"""Controlled actual ELF-shape closure assertions, no execution/materialization."""
import copy
import importlib.util
import pathlib
import unittest

HERE = pathlib.Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('binding', HERE / 'helper-runtime-binding.py')
binding = importlib.util.module_from_spec(spec); spec.loader.exec_module(binding)


class BindingTests(unittest.TestCase):
    def fixture(self):
        libc = {'soname': 'libc.so.6', 'needed': [], 'interpreter': None, 'versionNeeds': [], 'versionDefinitions': ['GLIBC_2.38']}
        exe = {'soname': None, 'needed': ['libc.so.6'], 'interpreter': '/lib64/ld-linux-x86-64.so.2', 'versionNeeds': [{'library': 'libc.so.6', 'versions': ['GLIBC_2.38']}], 'versionDefinitions': []}
        package = {'packages': [{'files': {'usr/bin/fuse2fs': {'sha256': 'a' * 64, 'elf': exe}}}]}
        host = {'schema': 'universe-electrs-helper-runtime-leaf-metadata-v1', 'sourceSha': 'a' * 40, 'hostAbiVersionDefinitionsObserved': True,
                'libraries': [{'soname': 'libc.so.6', 'present': True, 'abiQualified': True, 'path': '/usr/lib/x86_64-linux-gnu/libc.so.6', 'sha256': 'b' * 64, 'elf': libc}],
                'mke2fs': {'path': '/usr/sbin/mke2fs', 'sha256': 'c' * 64, 'elf': copy.deepcopy(exe)},
                'fusermount3': {'path': '/usr/bin/fusermount3', 'sha256': 'd' * 64, 'elf': copy.deepcopy(exe), 'setuidObserved': True}}
        loader = copy.deepcopy(host['libraries'][0]); loader['soname'] = loader['elf']['soname'] = 'ld-linux-x86-64.so.2'
        host['libraries'].append(loader)
        return package, host

    def test_closed_metadata_does_not_approve_execution_or_storage(self):
        value = binding.bind(*self.fixture())
        self.assertTrue(value['metadataDependencyClosureVerified'])
        self.assertFalse(value['runtimeExecutionQualified']); self.assertFalse(value['hardStorageQualified'])

    def test_missing_library_default_fallback_and_wrong_versions_rejected(self):
        for kind in ['missing', 'version', 'hostFlag', 'duplicate']:
            package, host = self.fixture()
            if kind == 'missing': package['packages'][0]['files']['usr/bin/fuse2fs']['elf']['needed'].append('unknown.so')
            elif kind == 'version': host['libraries'][0]['elf']['versionDefinitions'] = ['GLIBC_2.34']
            elif kind == 'hostFlag': host['hostAbiVersionDefinitionsObserved'] = False
            else: host['libraries'].append(copy.deepcopy(host['libraries'][0]))
            with self.subTest(kind=kind), self.assertRaises(ValueError): binding.bind(package, host)

    def test_private_helper_and_original_host_mke_keep_distinct_version_providers(self):
        package, host = self.fixture()
        private = {'soname': 'library.so.1', 'needed': ['libc.so.6'], 'interpreter': None,
                   'versionNeeds': [], 'versionDefinitions': ['PRIVATE_1']}
        original = copy.deepcopy(private); original['versionDefinitions'] = ['HOST_1']
        package['packages'][0]['files']['usr/lib/library.so.1.2'] = {'sha256': 'e' * 64, 'elf': private}
        host['libraries'].append({'soname': 'library.so.1', 'present': True, 'abiQualified': True,
                                  'path': '/usr/lib/x86_64-linux-gnu/library.so.1', 'sha256': 'f' * 64, 'elf': original})
        exe = package['packages'][0]['files']['usr/bin/fuse2fs']['elf']
        exe['needed'].append('library.so.1'); exe['versionNeeds'].append({'library': 'library.so.1', 'versions': ['PRIVATE_1']})
        host['mke2fs']['elf']['needed'].append('library.so.1')
        host['mke2fs']['elf']['versionNeeds'].append({'library': 'library.so.1', 'versions': ['HOST_1']})
        result = binding.bind(package, host)
        self.assertEqual(result['executionGroups']['fuse2fs']['providers']['library.so.1']['origin'], 'isolated-package')
        self.assertEqual(result['executionGroups']['mke2fsAndExistingMountHelper']['providers']['library.so.1']['origin'], 'observed-host-leaf')


if __name__ == '__main__': unittest.main()
