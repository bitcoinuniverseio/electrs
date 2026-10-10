"""Controlled private draft transport tests; no credentials/assets/network/scope."""
import importlib.util
import io
import json
import pathlib
import subprocess
import tempfile
import unittest
import urllib.error
from unittest.mock import Mock, patch

HERE = pathlib.Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('draft', HERE / 'draft-helper-proof-driver.py')
draft = importlib.util.module_from_spec(spec); spec.loader.exec_module(draft)


class Response:
    status = 200
    headers = {}
    def __init__(self, raw): self.stream = io.BytesIO(raw)
    def __enter__(self): return self
    def __exit__(self, *args): pass
    def read1(self, size): return self.stream.read(size)


class DriverTests(unittest.TestCase):
    def transport(self):
        with patch.object(draft.urllib.request, 'build_opener', return_value=Mock()), patch.object(draft.ssl, 'create_default_context'):
            return draft.Transport('CONTROLLED_SYNTHETIC_TOKEN')

    def metadata(self):
        repo = {'id': draft.REPO_ID, 'full_name': 'bitcoinuniverseio/electrs'}
        release = {'id': draft.RELEASE_ID, 'tag_name': draft.TAG, 'draft': True, 'published_at': None,
                   'assets': [{'id': a['id'], 'name': a['name'], 'size': a['bytes'], 'digest': 'sha256:' + a['sha256']} for a in draft.ASSETS]}
        return repo, release

    def test_default_no_download_or_scope(self):
        result = subprocess.run(['python', '-B', '-I', '-S', str(HERE / 'draft-helper-proof-driver.py')], check=True, capture_output=True)
        self.assertEqual(json.loads(result.stdout), {'preparedOnly': True, 'assetsDownloaded': False, 'scopeCreated': False})

    def test_repo_release_draft_asset_identity_size_digest_guards(self):
        import copy
        repo, release = self.metadata(); draft.verify_metadata(repo, release)
        for kind in ['repo', 'draft', 'published', 'id', 'name', 'size', 'digest', 'extra']:
            r = copy.deepcopy(repo); value = copy.deepcopy(release)
            if kind == 'repo': r['id'] += 1
            elif kind == 'draft': value['draft'] = False
            elif kind == 'published': value['published_at'] = '2026-10-10'
            elif kind == 'id': value['id'] += 1
            elif kind == 'extra': value['assets'].append(copy.deepcopy(value['assets'][0]))
            elif kind == 'size': value['assets'][0]['size'] += 1
            else: value['assets'][0][kind] = 'wrong'
            with self.subTest(kind=kind), self.assertRaises(ValueError): draft.verify_metadata(r, value)

    def test_auth_only_exact_initial_api_no_query_or_other_endpoint(self):
        transport = self.transport()
        request = transport.request(draft.API + draft.REPO, True, 'json')
        self.assertEqual(request.get_method(), 'GET')
        self.assertEqual(request.get_header('Authorization'), 'Bearer CONTROLLED_SYNTHETIC_TOKEN')
        for url in ['https://api.github.com/user', 'https://api.github.com' + draft.REPO + '?token=bad', 'https://evil.example' + draft.REPO]:
            with self.subTest(url=url), self.assertRaises(ValueError): transport.request(url, True, 'json')

    def test_single_redirect_strips_auth_and_signed_url_never_error_logged(self):
        transport = self.transport(); path = draft.REPO + '/releases/assets/' + str(draft.ASSETS[0]['id'])
        signed = 'https://release-assets.githubusercontent.com/asset/path?signature=CONTROLLED_SIGNED_VALUE'
        redirect = urllib.error.HTTPError(draft.API + path, 302, 'redirect', {'Location': signed}, io.BytesIO())
        transport.opener.open.side_effect = [redirect, Response(b'abc')]
        self.assertEqual(transport.get(path, 3, binary=True), b'abc')
        initial, second = [call.args[0] for call in transport.opener.open.call_args_list]
        self.assertTrue(initial.has_header('Authorization')); self.assertFalse(second.has_header('Authorization'))
        self.assertEqual(second.get_method(), 'GET')
        transport = self.transport()
        redirect = urllib.error.HTTPError(draft.API + path, 302, 'redirect', {'Location': signed}, io.BytesIO())
        repeated = urllib.error.HTTPError(signed, 302, 'redirect-again', {'Location': signed}, io.BytesIO())
        transport.opener.open.side_effect = [redirect, repeated]
        with self.assertRaises(ValueError) as error: transport.get(path, 3, binary=True)
        self.assertNotIn('CONTROLLED_SIGNED_VALUE', str(error.exception))
        self.assertEqual(transport.opener.open.call_count, 2)

    def test_other_redirect_domains_or_credentials_rejected(self):
        for url in ['https://release-assets.githubusercontent.com.evil/path', 'http://release-assets.githubusercontent.com/path',
                    'https://u:p@release-assets.githubusercontent.com/path', 'https://release-assets.githubusercontent.com:444/path', 'https://api.github.com/path']:
            with self.subTest(url=url): self.assertFalse(draft.valid_redirect(url))

    def test_payload_deadline_request_and_total_budgets(self):
        transport = self.transport()
        with self.assertRaisesRegex(ValueError, 'byte bound'): transport.body(Response(b'abc'), 2)
        transport.bytes = 1024 * 1024
        with self.assertRaisesRegex(ValueError, 'byte bound'): transport.body(Response(b'x'), 2)
        transport.requests = 8
        with self.assertRaisesRegex(ValueError, 'exhausted'): transport.request(draft.API + draft.REPO, True, 'json')
        transport = self.transport(); transport.started -= 46
        with self.assertRaisesRegex(ValueError, 'exhausted'): transport.request(draft.API + draft.REPO, True, 'json')

    def test_token_forget_and_no_original_exception_message(self):
        transport = self.transport(); transport.forget(); self.assertIsNone(transport.token)
        with self.assertRaisesRegex(ValueError, 'forgotten'): transport.request(draft.API + draft.REPO, True, 'json')
        transport = self.transport()
        transport.opener.open.side_effect = RuntimeError('PRIVATE_SIGNED_OR_TOKEN_VALUE')
        with self.assertRaises(ValueError) as error: transport.get(draft.REPO, 32)
        self.assertNotIn('PRIVATE_SIGNED_OR_TOKEN_VALUE', str(error.exception))

    def test_integrated_driver_forgets_token_before_receiver_and_exact_one_scope(self):
        guard = Mock(); guard.runtime_guard.return_value = 'a' * 40
        transfer = Mock(requests=8, bytes=700000); transfer.token = 'CONTROLLED_SYNTHETIC_TOKEN'
        transfer.forget.side_effect = lambda: setattr(transfer, 'token', None)
        receiver = Mock(); proof = Mock(); proof.launch.return_value = {'exitCode': 0, 'nativeActions': False}
        calls = []
        receiver.receive.side_effect = lambda *args: calls.append('receive')
        def launch(*args):
            self.assertIsNone(transfer.token); self.assertNotIn('GITHUB_TOKEN', draft.os.environ)
            calls.append('proof'); return {'exitCode': 0, 'nativeActions': False}
        proof.launch.side_effect = launch
        def loaded(name, filename):
            if filename == 'locked-cache-readonly.py': return guard
            if filename == 'receive-helper-transfer.py': return receiver
            if filename == 'small-fuse-image-proof.py': return proof
            return Mock()
        def controlled_assets(transport, root):
            for asset in draft.ASSETS[1:]: (root / asset['name']).write_text('{}')
            return [dict(asset, verified=True) for asset in draft.ASSETS]
        with tempfile.TemporaryDirectory() as directory, patch.object(draft, 'load', side_effect=loaded), patch.object(draft, 'Transport', return_value=transfer), patch.object(draft, 'assets', side_effect=controlled_assets), patch.dict(draft.os.environ, {'RUNNER_TEMP': directory, 'GITHUB_RUN_ID': '123', 'GITHUB_RUN_ATTEMPT': '1', 'GITHUB_TOKEN': 'CONTROLLED_SYNTHETIC_TOKEN'}):
            result = draft.run()
            self.assertIsNone(result['failure'])
            self.assertNotIn('CONTROLLED_SYNTHETIC_TOKEN', json.dumps(result))
        self.assertEqual(calls, ['receive', 'proof']); proof.launch.assert_called_once()


if __name__ == '__main__': unittest.main()
