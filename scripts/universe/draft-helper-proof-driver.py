"""UNEXECUTED literal private draft GET/staging + ONE reviewed small proof."""
import argparse
import datetime
import hashlib
import importlib.util
import json
import os
import pathlib
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

HERE = pathlib.Path(__file__).resolve().parent
API = 'https://api.github.com'
REPO = '/repos/bitcoinuniverseio/electrs'
REPO_ID = 1412614956
RELEASE_ID = 408752991
TAG = 'qualification-fuse-helper-20261010'
ASSETS = [
    {'id': 627257138, 'name': 'electrs-private-helper-package-data-aadc52.tar.gz', 'bytes': 674624,
     'sha256': '213d548c40f31d3b15c94f3468420a8cf6de4849bc6c3ecafe29f15e79bb224c'},
    {'id': 627257159, 'name': 'electrs-actual-helper-data-inspection-v2-20261010T060412Z.json', 'bytes': 11295,
     'sha256': '2dbeb838a6ed18480b1e634752f69d2351aeeba149846e771d8ec019a93d0c4e'},
    {'id': 627257177, 'name': 'electrs-aadc-actual-complete-host-helper-abi.json', 'bytes': 11640,
     'sha256': '40649fa2b524ccfecb7e09e468ffc4d86c24421370705c852e00ac49bba4d68b'}]


def load(name, file):
    spec = importlib.util.spec_from_file_location(name, HERE / file)
    value = importlib.util.module_from_spec(spec); spec.loader.exec_module(value)
    return value


class NoAutoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl): return None


class ApiFailure(ValueError):
    def __init__(self, code, status=None):
        self.code = code; self.status = status
        super().__init__(code)


def api_path_allowed(path):
    return path in [REPO, REPO + '/releases/' + str(RELEASE_ID)] + [REPO + '/releases/assets/' + str(asset['id']) for asset in ASSETS]


def valid_redirect(url):
    try:
        parsed = urllib.parse.urlsplit(url)
        return (parsed.scheme == 'https' and parsed.hostname == 'release-assets.githubusercontent.com'
                and parsed.port in [None, 443] and not parsed.username and not parsed.password
                and not parsed.fragment and len(url) <= 8192 and parsed.path.startswith('/'))
    except ValueError: return False


class Transport:
    def __init__(self, token):
        if not token or '\n' in token or '\r' in token: raise ValueError('ephemeral job credential unavailable')
        if any(os.environ.get(key) for key in ['SSLKEYLOGFILE', 'SSL_CERT_FILE', 'SSL_CERT_DIR']): raise ValueError('TLS trust/keylogging override forbidden')
        self.token = token; self.requests = 0; self.bytes = 0; self.started = time.monotonic()
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoAutoRedirect(), urllib.request.HTTPSHandler(context=ssl.create_default_context()))

    def request(self, url, authenticated, accept):
        if time.monotonic() - self.started > 45 or self.requests >= 8: raise ValueError('bounded draft transfer request/deadline exhausted')
        parsed = urllib.parse.urlsplit(url)
        if authenticated:
            if self.token is None: raise ValueError('credential deliberately forgotten; no further API requests')
            if parsed.scheme != 'https' or parsed.netloc != 'api.github.com' or parsed.query or not api_path_allowed(parsed.path): raise ValueError('literal authenticated API path required')
        elif not valid_redirect(url): raise ValueError('only exact approved unauthenticated asset domain permitted')
        headers = {'Accept': accept, 'User-Agent': 'UniversePrivateDraftQualification/1'}
        if authenticated: headers['Authorization'] = 'Bearer ' + self.token
        self.requests += 1
        return urllib.request.Request(url, headers=headers, method='GET')

    def body(self, response, maximum):
        length = response.headers.get('Content-Length')
        if length is not None and (not length.isdecimal() or int(length) > maximum): raise ValueError('draft transfer content length bound')
        chunks = []; count = 0
        while True:
            if time.monotonic() - self.started > 45: raise ValueError('draft transfer deadline exceeded')
            raw = response.read1(65536)
            if not raw: break
            count += len(raw); self.bytes += len(raw)
            if count > maximum or self.bytes > 1024 * 1024: raise ValueError('draft transfer per-response/aggregate byte bound')
            chunks.append(raw)
        return b''.join(chunks)

    def get(self, path, maximum, binary=False):
        request = self.request(API + path, True, 'application/octet-stream' if binary else 'application/vnd.github+json')
        try:
            with self.opener.open(request, timeout=8) as response:
                if response.status != 200: raise ValueError('approved API response status unavailable')
                return self.body(response, maximum)
        except urllib.error.HTTPError as error:
            if not binary or error.code != 302: raise ApiFailure('APPROVED_API_HTTP_FAILURE', error.code) from None
            # Keep signed Location only in local memory. Never serialize/log it.
            location = error.headers.get('Location', '')
            error.close()
            if not valid_redirect(location): raise ValueError('approved asset redirect unavailable') from None
            redirected = self.request(location, False, 'application/octet-stream')
            try:
                with self.opener.open(redirected, timeout=8) as response:
                    if response.status != 200: raise ValueError('approved asset response unavailable')
                    return self.body(response, maximum)
            except urllib.error.HTTPError as failure: raise ApiFailure('APPROVED_ASSET_HTTP_FAILURE', failure.code) from None
            except Exception: raise ApiFailure('APPROVED_ASSET_TRANSPORT_FAILURE_URL_WITHHELD') from None
        except Exception: raise ApiFailure('APPROVED_API_TRANSPORT_FAILURE_CREDENTIALS_WITHHELD') from None

    def forget(self): self.token = None


def verify_metadata(repository, release):
    if repository.get('id') != REPO_ID or repository.get('full_name') != 'bitcoinuniverseio/electrs': raise ValueError('exact owned repository metadata required')
    if release.get('id') != RELEASE_ID or release.get('tag_name') != TAG or release.get('draft') is not True or release.get('published_at') is not None: raise ValueError('exact unpublished draft release required')
    received = release.get('assets', [])
    if len(received) != 3 or {item.get('id') for item in received} != {item['id'] for item in ASSETS}: raise ValueError('exact three draft asset IDs required')
    for expected in ASSETS:
        actual = next(item for item in received if item['id'] == expected['id'])
        if actual.get('name') != expected['name'] or actual.get('size') != expected['bytes'] or actual.get('digest') != 'sha256:' + expected['sha256']: raise ValueError('draft asset name/size/digest mismatch')


def assets(transport, root):
    repository = json.loads(transport.get(REPO, 65536))
    release = json.loads(transport.get(REPO + '/releases/' + str(RELEASE_ID), 65536))
    verify_metadata(repository, release)
    records = []
    for asset in ASSETS:
        raw = transport.get(REPO + '/releases/assets/' + str(asset['id']), asset['bytes'], binary=True)
        if len(raw) != asset['bytes'] or hashlib.sha256(raw).hexdigest() != asset['sha256']: raise ValueError('exact received asset bytes/checksum mismatch')
        with (root / asset['name']).open('xb') as output: output.write(raw)
        records.append({**asset, 'verified': True})
    return records


def run():
    token = os.environ.pop('GITHUB_TOKEN', None)
    source = None; resources = None; phase = 'runtime-source-admission'
    try:
        guard = load('owned_draft_guard', 'locked-cache-readonly.py'); source = guard.runtime_guard()
        inventory = load('draft_git_guard', 'locked-source-inventory.py'); guard.source_guard(inventory, source)
        temp = pathlib.Path(os.environ['RUNNER_TEMP']); resources = guard.headroom_report(temp)
        phase = 'pressure-admission'
        load('draft_pressure', 'confinement-proof.py').headroom(resources)
    except Exception as error:
        token = None
        # Only fixed /proc memory/PSI and statvfs observations are eligible.
        # No original exception text, environment, credentials or URL is emitted.
        observed = None
        if isinstance(resources, dict):
            memory = resources.get('memoryKiB', {}).get('MemAvailable')
            free = resources.get('freeTempBytes')
            pressure = resources.get('pressure', {})
            if type(memory) is int and memory >= 0 and type(free) is int and free >= 0 and all(
                    isinstance(pressure.get(kind), str) and len(pressure[kind]) <= 4096 for kind in ['cpu', 'io']):
                observed = {'availableMemoryKiB': memory, 'freeTemporaryBytes': free,
                            'pressure': {kind: pressure[kind] for kind in ['cpu', 'io']}}
        return {'schema': 'universe-electrs-private-draft-small-proof-driver-v1', 'sourceSha': source,
                'observedAt': datetime.datetime.now(datetime.timezone.utc).isoformat(),
                'repositoryId': REPO_ID, 'releaseId': RELEASE_ID, 'draftVerified': False,
                'assets': [], 'requests': 0, 'networkBytes': 0, 'automaticRetries': 0,
                'result': None, 'failure': {'phase': phase, 'type': type(error).__name__,
                                          'reason': 'admission rejected; no transfer or scope started'},
                'observedResources': observed, 'driverReceipt': None,
                'credentialsOrSignedUrlsRecorded': False, 'sourceRustWipNotCompiled': True,
                'fullRustBuild': False, 'nativeIndexerActions': False}
    run_id = os.environ['GITHUB_RUN_ID']; attempt = os.environ['GITHUB_RUN_ATTEMPT']; nonce = os.urandom(8).hex()
    import re
    if not re.fullmatch('[0-9]{1,20}', run_id) or not re.fullmatch('[0-9]{1,3}', attempt): raise ValueError('exact owned run/attempt required')
    root = temp / ('universe-electrs-draft-transfer-' + run_id + '-' + attempt + '-' + nonce); root.mkdir(mode=0o700)
    transport = Transport(token); token = None
    phase = 'draft-download'; result = None; failure = None; records = []
    try:
        records = assets(transport, root)
        transport.forget()  # No credential survives into receiver/proof context.
        receiver = load('sealed_receiver', 'receive-helper-transfer.py')
        package_root = temp / ('universe-electrs-helper-data-' + run_id + '-' + attempt + '-' + nonce)
        phase = 'receive-verified-capsule'
        received = receiver.receive(root / ASSETS[0]['name'], package_root, temp)
        package = json.loads((root / ASSETS[1]['name']).read_bytes()); host = json.loads((root / ASSETS[2]['name']).read_bytes())
        guard.source_guard(inventory, source)
        phase = 'one-small-proof'
        result = load('reviewed_small_proof', 'small-fuse-image-proof.py').launch(package, host, package_root)
        if result['exitCode'] != 0: failure = {'phase': phase, 'type': 'SmallProofFailed', 'reason': 'own proof failure; bounded own diagnostics retained in proof result'}
    except Exception as error:
        # Exception messages are NOT persisted: a transport library might include
        # a credential-bearing Location. Preserve phase/type only, never URLs.
        failure = {'phase': phase, 'type': type(error).__name__, 'reason': 'controlled step failed; token/signed URL withheld'}
        if isinstance(error, ApiFailure): failure.update(safeCode=error.code, httpStatus=error.status)
    finally: transport.forget()
    receipt = {'schema': 'universe-electrs-private-draft-small-proof-driver-v1', 'sourceSha': source,
               'observedAt': datetime.datetime.now(datetime.timezone.utc).isoformat(), 'repositoryId': REPO_ID,
               'releaseId': RELEASE_ID, 'draftVerified': bool(records), 'assets': records,
               'requests': transport.requests, 'networkBytes': transport.bytes, 'automaticRetries': 0,
               'result': result, 'failure': failure, 'credentialsOrSignedUrlsRecorded': False,
               'sourceRustWipNotCompiled': True, 'fullRustBuild': False, 'nativeIndexerActions': False}
    with (root / 'driver-receipt.json').open('x') as output: json.dump(receipt, output, indent=2)
    return {'transferRoot': str(root), 'driverReceipt': str(root / 'driver-receipt.json'), **receipt}


def main():
    parser = argparse.ArgumentParser(description=__doc__); parser.add_argument('--run-one-small-proof', action='store_true')
    args = parser.parse_args()
    if not args.run_one_small_proof:
        print(json.dumps({'preparedOnly': True, 'assetsDownloaded': False, 'scopeCreated': False})); return
    result = run(); print(json.dumps(result))
    if result['failure']: raise SystemExit(1)


if __name__ == '__main__': main()
