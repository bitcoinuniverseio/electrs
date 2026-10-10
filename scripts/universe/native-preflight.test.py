"""Local controlled metadata validation. Never invokes cargo or native tools."""
import importlib.util
import pathlib
import tempfile
import unittest
from unittest.mock import patch

PATH = pathlib.Path(__file__).with_name('native-preflight.py')
SPEC = importlib.util.spec_from_file_location('preflight', PATH)
PREFLIGHT = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PREFLIGHT)


class PreflightTests(unittest.TestCase):
    def test_exact_existing_version_and_host(self):
        PREFLIGHT.require_rust_version('rustc 1.89.0 (29483883e 2025-08-04)\nhost: x86_64-unknown-linux-gnu')
        for value in ['rustc 1.91.0 (aa 2025-01-01)\nhost: x86_64-unknown-linux-gnu',
                      'rustc 1.89.0 (aa 2025-01-01)\nhost: x86_64-pc-windows-msvc',
                      'rustc 1.89.0-nightly (aa 2025-01-01)\nhost: x86_64-unknown-linux-gnu']:
            with self.subTest(value=value), self.assertRaises(ValueError):
                PREFLIGHT.require_rust_version(value)

    def test_own_cgroup_path_cannot_escape(self):
        self.assertEqual(PREFLIGHT.cgroup_location('0::/user.slice/example'), pathlib.Path('/sys/fs/cgroup/user.slice/example'))
        for value in ['0::/../../etc', '0::relative', '0::/one\n0::/two', '1:cpu:/old']:
            with self.subTest(value=value), self.assertRaises(ValueError):
                PREFLIGHT.cgroup_location(value)

    def test_checkout_tool_and_oversized_metadata_rejected(self):
        with tempfile.TemporaryDirectory(prefix='native-preflight-test-') as folder:
            root = pathlib.Path(folder)
            path = root / 'tool'
            path.write_bytes(b'controlled tool')
            with self.assertRaises(ValueError):
                PREFLIGHT.file_pin(path, root)
            with self.assertRaises(ValueError):
                PREFLIGHT.read_small(path, 2)

    def test_wrong_repo_or_branch_before_any_tool_invocation(self):
        for env in [{'GITHUB_REPOSITORY': 'mempool/electrs'},
                    {'GITHUB_REPOSITORY': 'bitcoinuniverseio/electrs', 'GITHUB_REF': 'refs/heads/mempool'}]:
            with patch.object(PREFLIGHT.platform, 'system', return_value='Linux'), \
                    patch.object(PREFLIGHT.platform, 'machine', return_value='x86_64'), \
                    patch.dict(PREFLIGHT.os.environ, env, clear=True), \
                    patch.object(PREFLIGHT, 'run_metadata') as run:
                with self.assertRaises(ValueError):
                    PREFLIGHT.collect()
                run.assert_not_called()

    def test_partial_metadata_cannot_be_full_qualification_or_install(self):
        report = {'metadataToolsPresent': False, 'missing': ['rustc1.89.0'], 'compiled': False,
                  'installed': False, 'dependencyFetch': False, 'nativeActions': False}
        with patch.object(PREFLIGHT, 'collect', return_value=report), patch('builtins.print') as output:
            self.assertEqual(PREFLIGHT.main(), 2)
        self.assertIn('"compiled": false', output.call_args.args[0])

    def test_cargo_rustup_compilation_and_git_network_before_subprocess(self):
        root = pathlib.Path.cwd()
        for command in [[str(root / 'cargo'), '--version'], [str(root / 'rustup'), '--version'],
                        [str(root / 'rustc'), '--crate-name', 'fixture'], [str(root / 'git'), 'fetch'],
                        [str(root / 'installer'), '--version'],
                        ['rustc', '-Vv']]:
            with self.subTest(command=command), patch.object(PREFLIGHT.subprocess, 'run') as run:
                with self.assertRaises(ValueError):
                    PREFLIGHT.run_metadata(command)
                run.assert_not_called()

    def test_safe_version_callsite_cannot_bind_an_arbitrary_executable(self):
        path = pathlib.Path.cwd() / 'arbitrary'
        with patch.object(PREFLIGHT.subprocess, 'run') as run:
            for role in [None, 'installer', 'cc']:
                with self.subTest(role=role), self.assertRaises(ValueError):
                    PREFLIGHT.run_metadata([str(path), '--version'], version_tool=role)
            run.assert_not_called()

    def test_workflow_triggers_only_reviewed_branch_preflight_paths_and_no_build(self):
        workflow = PREFLIGHT.SOURCE / '.github/workflows/universe-native-preflight.yml'
        raw = workflow.read_text()
        self.assertIn('workflow_dispatch:', raw)
        self.assertNotIn('pull_request:', raw)
        self.assertIn('branches: [codex/bounded-script-utxo-pages]', raw)
        self.assertIn('      - scripts/universe/native-preflight.py', raw)
        self.assertIn('      - scripts/universe/native-preflight.test.py', raw)
        self.assertNotIn('branches: [mempool]', raw)
        self.assertNotIn('paths: [', raw)
        self.assertIn('runs-on: [self-hosted, universe-runners-1]', raw)
        self.assertIn('timeout-minutes: 5', raw)
        self.assertIn('persist-credentials: false', raw)
        for forbidden in ['rustup', 'install.sh', 'host-tools@', 'cargo ', 'secrets.', 'ubuntu-latest']:
            self.assertNotIn(forbidden, raw)

    def test_every_inherited_job_remains_upstream_only(self):
        for name, count in [('ci.yml', 5), ('on-tag.yml', 1), ('project-review-status.yml', 1)]:
            raw = (PREFLIGHT.SOURCE / '.github/workflows' / name).read_text()
            self.assertEqual(raw.count("if: github.repository == 'mempool/electrs'"), count)


if __name__ == '__main__':
    unittest.main()
