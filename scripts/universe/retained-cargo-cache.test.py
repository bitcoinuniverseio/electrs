"""Pure cache-key/ownership controls; no old-unit probe or remount."""
import copy
import importlib.util
import pathlib
import unittest

spec = importlib.util.spec_from_file_location('retained', pathlib.Path(__file__).with_name('retained-cargo-cache.py'))
module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)


class Controls(unittest.TestCase):
    def fixture(self):
        root = '/opt/github-runners/runner-27/_work/_temp/universe-electrs-build-123-1-' + 'a' * 16
        context = {'taskRoot': root, 'vendorRoot': root + '/vendor', 'profile': 'unchanged-default', 'sourceSha': '1' * 40,
                   'cargoLockSha256': 'a' * 64, 'vendorManifestSha256': 'b' * 64, 'wrapperSourceSha256': 'c' * 64,
                   'wrapperBinarySha256': 'd' * 64, 'offlineConfigSha256': 'e' * 64, 'compilerEnvironment': {'RUSTC': '/exact/rustc'},
                   'toolAliases': {'rustc': '/exact/rustc'}}
        closure = {'leaves': [{'path': '/exact/rustc', 'bytes': 123, 'sha256': 'f' * 64}], 'trees': [],
                   'roles': {'rustc': {'requestedPath': '/known/rustc', 'resolvedPath': '/exact/rustc', 'sha256': 'f' * 64}}}
        receipt = {'schema': 'universe-electrs-retained-cargo-cache-v1', 'guardPolicy': 'full-cargo-v2', 'taskRoot': root,
                   'imagePath': root + '/aggregate8GiB.img', 'mountPath': root + '/work', 'cacheKeySha256': module.cache_key(context, closure),
                   'previousUnit': root.split('/')[-1], 'previousDaemonPid': 123, 'previousControlGroup': '/known/' + root.split('/')[-1] + '.service',
                   'settled': {'workerCleanupErrors': [], 'parentCleanupErrors': [], 'daemonExit': 0, 'mountAbsent': True, 'unitInactive': True},
                   'imageIdentity': {'device': 1, 'inode': 2, 'size': module.IMAGE_BYTES, 'mtimeNs': 3, 'ctimeNs': 4,
                                     'uid': 1001, 'gid': 1001, 'mode': 0o100600, 'nlink': 1},
                   'previousContextSha256': 'a' * 64, 'workerResultSha256': 'b' * 64, 'parentResultSha256': 'c' * 64}
        return context, closure, receipt

    def test_source_only_change_reuses_dependency_key(self):
        context, closure, receipt = self.fixture(); context['sourceSha'] = '2' * 40
        self.assertTrue(module.validate(receipt, context, closure)['cargoFingerprintValidationStillRequired'])

    def test_lock_vendor_tool_or_wrapper_change_rejects(self):
        for key in ['cargoLockSha256', 'vendorManifestSha256', 'wrapperBinarySha256']:
            context, closure, receipt = self.fixture(); context[key] = '0' * 64
            with self.assertRaises(ValueError): module.validate(receipt, context, closure)
        context, closure, receipt = self.fixture(); closure['leaves'][0]['sha256'] = '0' * 64
        with self.assertRaises(ValueError): module.validate(receipt, context, closure)

    def test_dependency_path_relocation_rejects(self):
        context, closure, receipt = self.fixture(); context['vendorRoot'] += '-relocated'
        with self.assertRaises(ValueError): module.validate(receipt, context, closure)

    def test_interruption_or_cleanup_failure_rejects(self):
        for key, value in [('mountAbsent', False), ('daemonExit', 1), ('workerCleanupErrors', ['failed'])]:
            context, closure, receipt = self.fixture(); receipt['settled'][key] = value
            with self.assertRaises(ValueError): module.validate(receipt, context, closure)

    def test_unknown_prior_unit_and_image_alias_reject(self):
        context, closure, receipt = self.fixture(); receipt['previousUnit'] = 'universe-bitcoin-mainnet-node'
        with self.assertRaises(ValueError): module.validate(receipt, context, closure)

    def test_persistent_namespace_is_narrow(self):
        root = module.PREFIX + '/' + 'a' * 16
        self.assertEqual(module.persistent_root(root), root)
        for path in ['/home/github-runner/.cargo/' + 'a' * 16, module.PREFIX + '/arbitrary', module.PREFIX + '/' + 'a' * 16 + '/nested']:
            with self.assertRaises(ValueError): module.persistent_root(path)
        context, closure, receipt = self.fixture(); receipt['imagePath'] = '/elsewhere/cache.img'
        with self.assertRaises(ValueError): module.validate(receipt, context, closure)


if __name__ == '__main__': unittest.main()
