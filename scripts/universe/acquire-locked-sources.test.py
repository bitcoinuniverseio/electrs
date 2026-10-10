"""Synthetic no-network acquisition controls; no Cargo, cache or native access."""
import hashlib
import gzip
import importlib.util
import io
import json
import pathlib
import subprocess
import tarfile
import tempfile
import unittest
from unittest.mock import Mock, patch

HERE = pathlib.Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('acquisition', HERE / 'acquire-locked-sources.py')
acquisition = importlib.util.module_from_spec(spec)
spec.loader.exec_module(acquisition)


class Response:
    def __init__(self, url, raw, headers=None):
        self.url = url; self.stream = io.BytesIO(raw); self.headers = headers or {}; self.status = 200

    def __enter__(self): return self
    def __exit__(self, *args): pass
    def geturl(self): return self.url
    def read1(self, size): return self.stream.read(size)


class AcquisitionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self.temp.name)

    def tearDown(self): self.temp.cleanup()

    def test_default_does_not_fetch_or_create(self):
        result = subprocess.run(['python', '-B', '-I', '-S', str(HERE / 'acquire-locked-sources.py')], capture_output=True, check=True)
        self.assertEqual(json.loads(result.stdout), {'preparedOnly': True, 'networkFetched': False, 'destinationCreated': False, 'cargoInvoked': False})

    def test_exact_actual_inventory_plan_and_full_denominator(self):
        raw = subprocess.check_output(['git', 'show', 'HEAD:Cargo.lock'], cwd=HERE.parents[1])
        packages = acquisition.load_inventory().parse_lock(raw)
        records = []
        complete = 0
        for package in packages:
            record = {key: package[key] for key in ['name', 'version', 'source']}
            if package['source'].startswith('git+'):
                record.update(state='locked-git-checkout-missing', complete=False)
            elif complete < 8:
                complete += 1; record.update(state='checksum-and-vendor-qualified', complete=True, path='/home/github-runner/.cargo/registry/cache/historical-only')
            else: record.update(state='archive-missing', complete=False)
            records.append(record)
        captured = {'runId': 38024510195, 'jobId': 114132367991, 'ciConclusion': 'success',
                    'report': {'lockSha256': acquisition.load_inventory().LOCK_SHA, 'packages': records}}
        inventory_raw = json.dumps(captured).encode()
        with patch.object(acquisition, 'INVENTORY_SHA', acquisition.sha(inventory_raw)):
            plan = acquisition.build_plan(raw, inventory_raw)
            self.assertEqual(len(plan['registryDownloads']), 195)
            self.assertEqual(len(plan['historicalQualifiedCacheReferences']), 8)
            self.assertFalse(plan['all204Materialized'])
            self.assertTrue(all(acquisition.url_allowed(record['url']) for record in plan['registryDownloads']))
            with self.assertRaisesRegex(ValueError, 'actual087c'):
                acquisition.build_plan(raw, inventory_raw + b'\n')

    def test_only_exact_official_unauthenticated_urls(self):
        self.assertTrue(acquisition.url_allowed('https://static.crates.io/crates/abc/abc-1.2.3.crate'))
        self.assertTrue(acquisition.url_allowed(acquisition.GITHUB + 'commits/' + acquisition.COMMIT))
        for url in ['http://static.crates.io/crates/a/a-1.crate', 'https://user:password@static.crates.io/crates/a/a-1.crate',
                    'https://static.crates.io.evil/crates/a/a-1.crate', 'https://api.github.com/repos/other/project/git/commits/' + acquisition.COMMIT,
                    'https://static.crates.io/crates/a/a-1.crate?auth=secret', 'https://localhost:18997/api/health']:
            with self.subTest(url=url): self.assertFalse(acquisition.url_allowed(url))
        with self.assertRaisesRegex(ValueError, 'redirects forbidden'):
            acquisition.NoRedirect().redirect_request(None, None, 302, '', {}, 'https://evil/')

    def download(self, raw, checksum=None, headers=None, maximum=1024):
        url = 'https://static.crates.io/crates/abc/abc-1.crate'
        opener = Mock(); opener.open.return_value = Response(url, raw, headers)
        with patch.object(acquisition.urllib.request, 'build_opener', return_value=opener), patch.object(acquisition.ssl, 'create_default_context'):
            return acquisition.download(url, self.root / 'abc.crate', acquisition.Budget(), maximum, checksum)

    def test_checksum_mismatch_retains_unparsed_part(self):
        with patch.object(tarfile, 'open', side_effect=AssertionError('must not parse')):
            with self.assertRaisesRegex(ValueError, 'Cargo.lock checksum mismatch'):
                self.download(b'untrusted', '0' * 64)
        self.assertEqual((self.root / 'abc.crate.part').read_bytes(), b'untrusted')
        self.assertFalse((self.root / 'abc.crate').exists())

    def test_verified_download_no_replace_and_no_extraction(self):
        result = self.download(b'abc', hashlib.sha256(b'abc').hexdigest())
        self.assertEqual(result['sha256'], hashlib.sha256(b'abc').hexdigest())
        self.assertEqual((self.root / 'abc.crate').read_bytes(), b'abc')
        self.assertFalse((self.root / 'abc.crate.part').exists())
        with self.assertRaisesRegex(ValueError, 'immutable target conflict'): self.download(b'abc', hashlib.sha256(b'abc').hexdigest())
        self.assertEqual((self.root / 'abc.crate').read_bytes(), b'abc')

    def test_request_total_per_file_and_declared_payload_bounds(self):
        for mode in ['length', 'body']:
            with self.subTest(mode=mode), self.assertRaisesRegex(ValueError, 'bound'):
                self.download(b'x' * 16, headers={'Content-Length': '16'} if mode == 'length' else None, maximum=8)
            (self.root / 'abc.crate.part').unlink()
        budget = acquisition.Budget()
        with patch.object(acquisition, 'MAX_REQUESTS', 0), self.assertRaisesRegex(ValueError, 'count'):
            budget.request()
        with patch.object(acquisition, 'MAX_TOTAL', 1), self.assertRaisesRegex(ValueError, 'aggregate'):
            budget.charge(2)
        with self.assertRaisesRegex(ValueError, 'declared payload'):
            budget.charge_unpacked(1024 * 1024**2 + 1)

    def test_actual_decoded_gzip_bound_before_tar_parser(self):
        target = self.root / 'compressed.gz'
        with gzip.open(target, 'wb') as output: output.write(b'x' * 1000)
        with patch.object(tarfile, 'open', side_effect=AssertionError('no tar parser admitted')):
            with self.assertRaisesRegex(ValueError, 'decoded archive stream'):
                acquisition.gzip_payload_fence(target, acquisition.Budget(), 100)

    def test_wrong_existing_or_shared_destination_rejected(self):
        for path in [self.root, self.root / 'outside', pathlib.Path('relative'), pathlib.Path('/home/github-runner/.cargo/deps')]:
            with self.subTest(path=path), self.assertRaises(ValueError): acquisition.safe_destination(path)

    def git_fixture(self):
        cargo = b'[package]\nname="fixture"\nversion="1.0.0"\n'
        rust = b'fn main() {}\n'
        cargo_sha = hashlib.sha1(b'blob ' + str(len(cargo)).encode() + b'\0' + cargo).hexdigest()
        rust_sha = hashlib.sha1(b'blob ' + str(len(rust)).encode() + b'\0' + rust).hexdigest()
        subtree = b'100644 lib.rs\0' + bytes.fromhex(rust_sha)
        sub_sha = hashlib.sha1(b'tree ' + str(len(subtree)).encode() + b'\0' + subtree).hexdigest()
        root_tree = b'100644 Cargo.toml\0' + bytes.fromhex(cargo_sha) + b'40000 src\0' + bytes.fromhex(sub_sha)
        root_sha = hashlib.sha1(b'tree ' + str(len(root_tree)).encode() + b'\0' + root_tree).hexdigest()
        records = [{'path': 'Cargo.toml', 'mode': '100644', 'type': 'blob', 'sha': cargo_sha},
                   {'path': 'src', 'mode': '040000', 'type': 'tree', 'sha': sub_sha},
                   {'path': 'src/lib.rs', 'mode': '100644', 'type': 'blob', 'sha': rust_sha}]
        target = self.root / 'git.tar.gz'
        with tarfile.open(target, 'w:gz') as archive:
            for name, raw in [('Cargo.toml', cargo), ('src/lib.rs', rust)]:
                member = tarfile.TarInfo('rust-electrum-client-' + acquisition.COMMIT + '/' + name)
                member.mode = 0o644; member.size = len(raw); archive.addfile(member, io.BytesIO(raw))
        return target, {'sha': acquisition.COMMIT, 'tree': {'sha': root_sha}}, {'sha': root_sha, 'truncated': False, 'tree': records}

    def test_git_full_blob_subtree_reconstruction_and_trust_label(self):
        path, commit, tree = self.git_fixture()
        result = acquisition.validate_git_archive(path, commit, tree, {'name': 'fixture', 'version': '1.0.0'})
        self.assertTrue(result['gitBlobAndTreeHashesVerified'])
        self.assertEqual(set(result['blobs']), {'Cargo.toml', 'src/lib.rs'})
        self.assertIn('raw commit object not reconstructed', result['commitToTreeTrust'])
        self.assertFalse(result['materialized'])
        with self.assertRaisesRegex(ValueError, 'exact locked package'):
            acquisition.validate_git_archive(path, commit, tree, {'name': 'fixture', 'version': '0.8.0'})

    def test_git_truncated_wrong_commit_blob_mode_and_root_fail_closed(self):
        import copy
        path, commit, tree = self.git_fixture()
        for kind in ['truncated', 'commit', 'blob', 'mode', 'root']:
            c = copy.deepcopy(commit); t = copy.deepcopy(tree)
            if kind == 'truncated': t['truncated'] = True
            elif kind == 'commit': c['sha'] = '0' * 40
            elif kind == 'blob': t['tree'][0]['sha'] = '0' * 40
            elif kind == 'mode': t['tree'][0]['mode'] = '120000'
            else: c['tree']['sha'] = t['sha'] = '0' * 40
            with self.subTest(kind=kind), self.assertRaises(ValueError): acquisition.validate_git_archive(path, c, t)

    def test_failure_stops_scheduling_and_never_fetches_git(self):
        packages = [{'name': 'p' + str(i), 'version': '1', 'url': 'https://static.crates.io/crates/p/p-1.crate', 'checksum': 'a' * 64} for i in range(195)]
        calls = []
        def fail(url, *args): calls.append(url); raise ValueError('controlled unavailable')
        with patch.object(acquisition, 'download', side_effect=fail):
            result = acquisition.acquire({'registryDownloads': packages}, self.root)
        self.assertTrue(result['errors'])
        self.assertLessEqual(len(calls), 2)
        self.assertTrue(all(url.startswith('https://static.crates.io/') for url in calls))
        self.assertTrue((self.root / 'acquisition-receipt.json').is_file())

    def test_watchdog_kills_only_stored_owned_child_and_preserves_failure(self):
        child = Mock(); child.pid = 123; child.communicate.side_effect = [subprocess.TimeoutExpired('owned', 660), (b'', b'')]
        with patch.object(acquisition, 'safe_destination', return_value=self.root / 'owned'), patch.object(acquisition.shutil, 'disk_usage', return_value=type('Usage', (), {'free': 1024 * 1024**2})()), patch.object(acquisition.subprocess, 'Popen', return_value=child):
            result = acquisition.launch_owned({'registryDownloads': []}, self.root / 'owned')
        child.kill.assert_called_once_with()
        self.assertTrue(result['watchdogExpired'])
        self.assertTrue((self.root / 'owned/watchdog-failure.json').is_file())


if __name__ == '__main__': unittest.main()
