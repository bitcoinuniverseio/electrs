"""Pure draft admission controls. No C compile, Cargo, units or cache reads."""
import copy
import importlib.util
import pathlib
import unittest

HERE = pathlib.Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('plan', HERE / 'confined-build-plan.py')
plan = importlib.util.module_from_spec(spec)
spec.loader.exec_module(plan)


class PlanTests(unittest.TestCase):
    def fixture(self):
        task = '/opt/github-runners/runner-10/_work/_temp/universe-electrs-build-38022672857-1-0123456789abcdef'
        value = {'schema': 'universe-electrs-confined-build-plan-v1', 'sourceSha': 'a' * 40,
                 'cargoLockSha256': plan.LOCK_SHA, 'profile': 'unchanged-default', 'operation': 'test-compile',
                 'taskRoot': task, 'workRoot': task + '/work', 'sourceRoot': task + '/source', 'vendorRoot': task + '/vendor',
                 'tools': {role: {'path': path, 'sha256': sha} for role, (path, sha) in plan.TOOL_PINS.items()},
                 'proposedResources': {'cpuMax': '200000 100000', 'memoryMax': str(4 * 1024**3), 'pidsMax': '128',
                                       'runtimeSeconds': 1800, 'targetByteLimit': 8 * 1024**3, 'jobs': 2}}
        for key in ['sourceManifestSha256', 'vendorManifestSha256', 'inventoryReceiptSha256',
                    'wrapperSourceSha256', 'wrapperBinarySha256', 'readRootsManifestSha256']:
            value[key] = 'b' * 64
        value['readRoots'] = [
            {'path': path, 'kind': 'tool-file', 'sha256': sha, 'executable': role != 'libclang'}
            for role, (path, sha) in plan.TOOL_PINS.items()]
        value['readRoots'] += [
            {'path': value['sourceRoot'], 'kind': 'source-tree', 'sha256': 'b' * 64, 'executable': False},
            {'path': value['vendorRoot'], 'kind': 'vendor-tree', 'sha256': 'b' * 64, 'executable': False}]
        return value

    def test_valid_source_plan_never_grants_build_admission(self):
        result = plan.validate(self.fixture())
        self.assertTrue(result['sourcePlanValidated'])
        self.assertFalse(result['buildAdmissionQualified'])
        self.assertFalse(result['cargoInvoked'])
        self.assertFalse(result['unitCreated'])

    def test_tiny_proof_or_claim_cannot_approve_larger_build(self):
        value = self.fixture()
        value['buildAdmissionQualified'] = True
        value['tinyProofPassed'] = True
        self.assertFalse(plan.validate(value)['buildAdmissionQualified'])
        value['proposedResources']['memoryMax'] = '67108864'
        with self.assertRaisesRegex(ValueError, 'resource'):
            plan.validate(value)

    def test_lock_tool_and_feature_drift(self):
        for change in ['lock', 'tool', 'feature', 'wrapper']:
            value = self.fixture()
            if change == 'lock': value['cargoLockSha256'] = 'c' * 64
            elif change == 'tool': value['tools']['rustc']['path'] = '/home/github-runner/.cargo/bin/rustc'
            elif change == 'feature': value['profile'] = 'all-features'
            else: value['wrapperBinarySha256'] = None
            with self.subTest(change=change), self.assertRaises(ValueError):
                plan.validate(value)

    def test_home_proc_native_and_credential_roots_rejected(self):
        for path in ['/home/github-runner', '/home/github-runner/.cargo', '/proc', '/etc', '/opt/universe-electrs/current', '/var/lib/bitcoin']:
            value = self.fixture()
            value['readRoots'].append({'path': path, 'kind': 'sdk-tree', 'sha256': 'b' * 64, 'executable': False})
            with self.subTest(path=path), self.assertRaisesRegex(ValueError, 'read leaf'):
                plan.validate(value)

    def test_source_vendor_must_not_be_under_writable_work(self):
        value = self.fixture()
        value['vendorRoot'] = value['workRoot'] + '/vendor'
        with self.assertRaisesRegex(ValueError, 'disjoint'):
            plan.validate(value)

    def test_paths_duplicates_and_missing_cargo_execution_grant(self):
        for change in ['escape', 'duplicate', 'no-execute']:
            value = self.fixture()
            if change == 'escape': value['readRoots'][0]['path'] = '/usr/bin/../secret'
            elif change == 'duplicate': value['readRoots'].append(copy.deepcopy(value['readRoots'][0]))
            else: value['readRoots'][1]['executable'] = False
            with self.subTest(change=change), self.assertRaises(ValueError):
                plan.validate(value)

    def test_c_boundary_reuses_proven_denials_without_changing_tiny_source(self):
        source = (HERE / 'confined-cargo.c').read_text()
        self.assertIn('#include "confinement-proof.c"', source)
        self.assertIn('restrict_syscalls();', source)
        self.assertIn('CLOSE_RANGE_UNSHARE', source)
        self.assertIn('"--offline", "--frozen", "--jobs", "2"', source)
        self.assertIn('"GIT_HASH", argv[7]', source)
        self.assertLess(source.index('SYS_landlock_restrict_self'), source.index('SYS_close_range'))
        self.assertIn('setenv("ELECTRS_SOURCE_REVISION", argv[7]', source)


if __name__ == '__main__':
    unittest.main()
