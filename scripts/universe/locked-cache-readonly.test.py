"""Controlled wrapper boundaries, never actual cache/unit/native access."""
import importlib.util
import json
import pathlib
import subprocess
import types
import unittest
from unittest.mock import Mock, patch

HERE = pathlib.Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('wrapper', HERE / 'locked-cache-readonly.py')
wrapper = importlib.util.module_from_spec(spec)
spec.loader.exec_module(wrapper)
pressure_spec = importlib.util.spec_from_file_location('pressure', HERE / 'confinement-proof.py')
pressure = importlib.util.module_from_spec(pressure_spec)
pressure_spec.loader.exec_module(pressure)


class WrapperTests(unittest.TestCase):
    def resources(self):
        return {'memoryKiB': {'MemAvailable': 1048576}, 'freeTempBytes': 1073741824,
                'pressure': {kind: 'some avg10=0.00 avg60=0.00 avg300=0.00 total=0\nfull avg10=0.00 avg60=0.00 avg300=0.00 total=0\n' for kind in ['cpu', 'io']}}

    def report(self):
        packages = [{'name': 'librocksdb-sys' if i == 0 else 'fixture-' + str(i), 'version': '1.0.0',
                     'source': 'registry+https://github.com/rust-lang/crates.io-index',
                     'state': 'archive-missing', 'complete': False} for i in range(203)]
        packages += [{'name': 'electrum-client', 'version': '0.8.0', 'source': 'git+locked-d379',
                      'state': 'locked-git-checkout-missing', 'complete': False}]
        return {'packages': packages, 'cargoInvoked': False, 'fullBuildAdmissionQualified': False}

    def test_default_no_source_or_cache_probe(self):
        result = subprocess.run(['python', str(HERE / 'locked-cache-readonly.py')], capture_output=True, check=True)
        self.assertEqual(json.loads(result.stdout), {'preparedOnly': True, 'cacheRead': False, 'cargoInvoked': False, 'unitCreated': False})

    def test_headroom_exact_bound_and_failure_before_cache(self):
        calls = []
        inventory = types.SimpleNamespace(parse_lock=Mock(return_value=[{}] * 204), inventory=Mock(side_effect=lambda *args: calls.append('cache') or self.report()))
        for kind in ['memory', 'disk', 'cpu', 'io', 'nan']:
            resources = self.resources()
            if kind == 'memory': resources['memoryKiB']['MemAvailable'] -= 1
            elif kind == 'disk': resources['freeTempBytes'] -= 1
            else: resources['pressure']['cpu' if kind == 'nan' else kind] = 'some avg10=' + ('NaN' if kind == 'nan' else '26' if kind == 'cpu' else '6') + ' avg60=0 avg300=0 total=0\nfull avg10=0 avg60=0 avg300=0 total=0'
            with self.subTest(kind=kind), patch.object(wrapper, 'runtime_guard', return_value='a' * 40), patch.object(wrapper, 'load_source', side_effect=[inventory, pressure]), patch.object(wrapper, 'source_guard'), patch.object(wrapper, 'headroom_report', return_value=resources):
                with self.assertRaises(ValueError): wrapper.observe()
        self.assertEqual(calls, [])
        self.assertFalse(pressure.headroom(self.resources())['longBuildHeadroomQualified'])

    def test_source_before_cache_and_end_fence(self):
        calls = []
        inventory = types.SimpleNamespace(parse_lock=Mock(return_value=[{}] * 204), inventory=Mock(side_effect=lambda *args: calls.append('cache') or self.report()))
        with patch.object(wrapper, 'runtime_guard', return_value='a' * 40), patch.object(wrapper, 'load_source', side_effect=[inventory, pressure]), patch.object(wrapper, 'source_guard', side_effect=lambda *args: calls.append('source')), patch.object(wrapper, 'headroom_report', return_value=self.resources()), patch.object(pathlib.Path, 'read_bytes', return_value=b'controlled lock fixture'):
            result = json.loads(wrapper.observe())
        self.assertEqual(calls, ['source', 'cache', 'source'])
        self.assertEqual(len(result['gates']['archiveMissing']), 203)
        self.assertFalse(result['gates']['fullBuildAdmissionQualified'])
        self.assertFalse(result['unitCreated'])
        self.assertEqual(result['observedResources']['availableMemoryKiB'], 1048576)

    def test_end_fence_failure_withholds_output(self):
        inventory = types.SimpleNamespace(parse_lock=Mock(return_value=[{}] * 204), inventory=Mock(return_value=self.report()))
        with patch.object(wrapper, 'runtime_guard', return_value='a' * 40), patch.object(wrapper, 'load_source', side_effect=[inventory, pressure]), patch.object(wrapper, 'source_guard', side_effect=[None, ValueError('source drift')]), patch.object(wrapper, 'headroom_report', return_value=self.resources()), patch.object(pathlib.Path, 'read_bytes', return_value=b'fixture'):
            with self.assertRaisesRegex(ValueError, 'source drift'): wrapper.observe()

    def test_wrong_package_denominator_and_payload_rejected(self):
        with self.assertRaisesRegex(ValueError, 'denominator'):
            wrapper.result_gates({'packages': []})
        inventory = types.SimpleNamespace(parse_lock=Mock(return_value=[{}] * 204), inventory=Mock(return_value=self.report()))
        with patch.object(wrapper, 'runtime_guard', return_value='a' * 40), patch.object(wrapper, 'load_source', side_effect=[inventory, pressure]), patch.object(wrapper, 'source_guard'), patch.object(wrapper, 'headroom_report', return_value=self.resources()), patch.object(pathlib.Path, 'read_bytes', return_value=b'fixture'), patch.object(wrapper, 'MAX_OUTPUT', 32):
            with self.assertRaisesRegex(ValueError, 'payload'): wrapper.observe()

    def test_missing_vendor_author_and_bad_archive_preserved_as_gates(self):
        report = self.report()
        report['packages'][0].update(state='archive-unqualified', reason='vendor/source completeness missing; implicit fetch forbidden')
        result = wrapper.result_gates(report)
        self.assertFalse(result['rocksdbVendorAuthorsAndSnappyQualified'])
        self.assertEqual(result['archiveUnqualified'][0]['reason'], report['packages'][0]['reason'])
        self.assertEqual(result['gitSource'][0]['state'], 'locked-git-checkout-missing')

    def test_runtime_wrong_owner_branch_and_python_effects(self):
        environment = {'GITHUB_REPOSITORY': 'bitcoinuniverseio/electrs', 'GITHUB_REF': 'refs/heads/codex/bounded-script-utxo-pages', 'GITHUB_SHA': 'a' * 40}
        with patch.object(wrapper.platform, 'system', return_value='Linux'), patch.object(wrapper.os, 'getuid', create=True, return_value=1001), patch.dict(wrapper.os.environ, environment):
            with patch.dict(wrapper.os.environ, {'GITHUB_REF': 'refs/heads/mempool'}):
                with self.assertRaisesRegex(ValueError, 'branch'): wrapper.runtime_guard()
            with patch.object(wrapper.sys, 'dont_write_bytecode', False):
                with self.assertRaisesRegex(ValueError, '-B -I -S'): wrapper.runtime_guard()

    def test_headroom_rejects_unknown_temp_before_proc_read(self):
        with patch.object(wrapper, 'bounded_read', side_effect=AssertionError('must not read')):
            with self.assertRaisesRegex(ValueError, 'temporary path'):
                wrapper.headroom_report('/var/lib/bitcoin')


if __name__ == '__main__':
    unittest.main()
