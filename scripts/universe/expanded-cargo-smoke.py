"""DRAFT distinct minimal offline Cargo confinement proof; default unexecuted."""
import argparse
import hashlib
import importlib.util
import json
import os
import pathlib
import re
import stat
import subprocess
import time

HERE = pathlib.Path(__file__).resolve().parent
READ_ELF = {'path': '/usr/bin/x86_64-linux-gnu-readelf', 'sha256': '64c58e15274bbbb5153f31078e455e9e77ee5f51489e709bba5bb788ce9df2b0'}
CARGO = '[package]\nname="universe-confined-cargo-smoke"\nversion="0.0.0"\nedition="2021"\n[dependencies]\n[profile.dev]\ndebug=0\n'
LOCK = 'version = 4\n[[package]]\nname = "universe-confined-cargo-smoke"\nversion = "0.0.0"\n'
LIB = '#[test]\nfn confinement_canaries_were_observed() { assert_eq!(include_str!(concat!(env!("OUT_DIR"), "/smoke-proof.json")), r#"{"fdClosed":true,"outsideWriteDenied":true,"privateWriteAllowed":true,"networkDenied":true,"uringDenied":true}"#); }\n'
BUILD = r'''use std::{env,ffi::CString,fs};
unsafe extern "C" { fn fcntl(fd:i32, cmd:i32, ...)->i32; fn open(path:*const i8, flags:i32, ...)->i32; fn close(fd:i32)->i32; fn socket(domain:i32, kind:i32, protocol:i32)->i32; fn syscall(number:i64, ...)->i64; fn __errno_location()->*mut i32; }
fn main() {
    unsafe {
        assert_eq!(fcntl(100,1),-1,"inherited canary FD survived"); assert_eq!(*__errno_location(),9);
        let outside=CString::new("__OUTSIDE__").unwrap();
        let fd=open(outside.as_ptr(),1|512,0o600); if fd>=0 { close(fd); panic!("outside write unexpectedly allowed"); }
        assert_eq!(*__errno_location(),13,"outside denial must be EACCES");
        for domain in [1,2] { assert_eq!(socket(domain,1,0),-1); assert_eq!(*__errno_location(),1); }
        assert_eq!(syscall(425,1i32,0usize),-1); assert_eq!(*__errno_location(),1);
    }
    let out=env::var("OUT_DIR").unwrap();
    fs::write(format!("{out}/private-canary"),b"owned-private-write").unwrap();
    fs::write(format!("{out}/smoke-proof.json"),br#"{"fdClosed":true,"outsideWriteDenied":true,"privateWriteAllowed":true,"networkDenied":true,"uringDenied":true}"#).unwrap();
    println!("cargo:rerun-if-changed=build.rs");
}
'''


def load(name, file):
    spec = importlib.util.spec_from_file_location(name, HERE / file)
    value = importlib.util.module_from_spec(spec); spec.loader.exec_module(value); return value


def project_bytes(outside):
    if not re.fullmatch(r'/opt/github-runners/runner-[0-9]{1,3}/_work/_temp/universe-electrs-cargo-smoke-[0-9]{1,20}-[0-9]{1,3}-[0-9a-f]{16}/source/outside-canary', outside):
        raise ValueError('literal owned outside canary path required')
    return {'Cargo.toml': CARGO.encode(), 'Cargo.lock': LOCK.encode(), 'src/lib.rs': LIB.encode(), 'build.rs': BUILD.replace('__OUTSIDE__', outside).encode()}


def actual_scope(root):
    reads = load('smoke_scope_reads', 'locked-cache-readonly.py')
    groups = [line[3:] for line in reads.bounded_read('/proc/self/cgroup', 4096).splitlines() if line.startswith('0::')]
    if len(groups) != 1 or not groups[0].endswith('/' + root.name + '.service'): raise ValueError('own smoke cgroup absent')
    path = pathlib.Path('/sys/fs/cgroup' + groups[0])
    expected = {'cpu.max': '100000 100000', 'memory.max': '536870912', 'pids.max': '32', 'io.weight': 'default 1'}
    if {key: reads.bounded_read(path / key, 4096).strip() for key in expected} != expected or os.getpriority(os.PRIO_PROCESS, 0) != 19:
        raise ValueError('smoke actual resource mismatch')
    status = reads.bounded_read('/proc/self/status', 32768)
    if re.findall(r'^NoNewPrivs:\s+([01])$', status, re.M) != ['1']: raise ValueError('smoke actual NNP absent')
    small = load('smoke_scope_properties', 'small-fuse-image-proof.py'); small.pin(small.CTL_TOOL)
    env = {'LANG': 'C', 'PATH': '/usr/bin:/bin', 'HOME': '/home/github-runner', 'XDG_RUNTIME_DIR': '/run/user/1001', 'DBUS_SESSION_BUS_ADDRESS': 'unix:path=/run/user/1001/bus'}
    response = subprocess.run([small.CTL_TOOL['path'], '--user', 'show', root.name + '.service', '--property=RuntimeMaxUSec', '--property=KillMode', '--property=TimeoutStopUSec'], env=env, capture_output=True, timeout=3, check=False)
    if response.returncode or len(response.stdout) > 4096 or len(response.stderr) > 4096: raise ValueError('smoke own-unit properties unavailable')
    properties = dict(line.split('=', 1) for line in response.stdout.decode('ascii').splitlines())
    if properties != {'RuntimeMaxUSec': '1min', 'KillMode': 'control-group', 'TimeoutStopUSec': '5s'}: raise ValueError('smoke lifetime/settlement mismatch')
    return {'controlGroup': groups[0], **expected, 'nice': 19, 'noNewPrivileges': True}


def worker(root, context):
    full = load('smoke_bounded_pins', 'full-cargo-scope.py')
    full.root_identity(root); resources = actual_scope(root)
    closure = full.read_json(root / 'closure.json', context['compilerClosureSha256'])
    # Parent already hashed tool material; this child checks continuity, not a
    # second full ELF/toolchain hash pass or a new source observation.
    for record in context['toolFences']:
        path = pathlib.Path(record['path'])
        if path.is_symlink() or list(full.file_identity(path.lstat())) != record['identity']: raise ValueError('smoke tool input changed after admission')
    full.validate_tool_roles(context, {leaf['path']: leaf for leaf in closure['leaves']}, closure['roles'])
    primary = load('smoke_primary', 'confined-build-plan.py').TOOL_PINS
    sources = {}
    for name in ['confined-cargo.c', 'confinement-proof.c']:
        path = root / 'wrapper-source' / name
        if full.file_hash(path) != context['wrapperSourceHashes'][name]: raise ValueError('smoke wrapper source drift')
        sources[name] = context['wrapperSourceHashes'][name]
    source_binding = hashlib.sha256(json.dumps(sources, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
    binary = root / 'expanded-wrapper'
    env = {'LANG': 'C', 'PATH': '/usr/bin:/bin', 'HOME': str(root), 'TMPDIR': str(root / 'work' / 'tmp')}
    failure = None; cargo_exit = None; observation = None
    try:
        with (root / 'compile.stdout').open('xb') as out, (root / 'compile.stderr').open('xb') as err:
            subprocess.run([primary['cc'][0], '-std=c11', '-O0', '-static', '-Wall', '-Wextra', '-Werror', str(root / 'wrapper-source' / 'confined-cargo.c'), '-o', str(binary)],
                           env=env, cwd=root, stdin=subprocess.DEVNULL, stdout=out, stderr=err, timeout=10, check=True)
        if full.file_hash(pathlib.Path(READ_ELF['path'])) != READ_ELF['sha256']: raise ValueError('smoke readelf pin drift')
        elf = subprocess.run([READ_ELF['path'], '-l', '-d', str(binary)], env=env, stdin=subprocess.DEVNULL, capture_output=True, timeout=2, check=True)
        if len(elf.stdout) > 16384 or b'INTERP' in elf.stdout or b'(NEEDED)' in elf.stdout: raise ValueError('smoke wrapper not static ELF')
        binary_sha = full.file_hash(binary)
        compiled = {'wrapperSourceSha256': source_binding, 'wrapperSourceHashes': sources, 'binarySha256': binary_sha,
                    'staticElf': True, 'compiledWrapper': True, 'readelf': READ_ELF, 'cc': primary['cc'], 'fullRustBuild': False}
        with (root / 'compiled-receipt.json').open('x') as output: json.dump(compiled, output)
        # Inherit one deliberately owned sentinel into the wrapper, which must
        # close it before Cargo. All other inherited descriptors are closed.
        sentinel = os.open(root / 'sentinel', os.O_RDONLY | os.O_NOFOLLOW)
        os.dup2(sentinel, 100); os.close(sentinel)
        command = [str(binary), str(root / 'work'), str(root / 'read-roots'), str(root / 'work' / 'environment'),
                   context['cargoPath'], str(root / 'source'), 'test', context['sourceSha']]
        try:
            with (root / 'setup.stdout').open('xb') as out, (root / 'setup.stderr').open('xb') as err:
                result = subprocess.run(command, env={'LANG': 'C'}, cwd=root, stdin=subprocess.DEVNULL, stdout=out, stderr=err, pass_fds=(100,), timeout=40, check=False)
                cargo_exit = result.returncode
        finally: os.close(100)
        if cargo_exit != 0: raise ValueError('smoke Cargo failed')
        if (root / 'source' / 'outside-canary').read_bytes() != b'owned-readable-canary': raise ValueError('outside canary changed')
        expected = {'fdClosed': True, 'outsideWriteDenied': True, 'privateWriteAllowed': True, 'networkDenied': True, 'uringDenied': True}
        proof_files = []; count = 0; total = 0; started = time.monotonic()
        for directory, dirs, files in os.walk(root / 'work', followlinks=False):
            count += 1 + len(dirs) + len(files)
            if count > 10000 or time.monotonic() - started > 3: raise ValueError('smoke output enumeration bound')
            for name in files:
                path = pathlib.Path(directory) / name
                if path.is_symlink(): raise ValueError('smoke output link')
                total += path.stat().st_size
                if total > 64 * 1024**2: raise ValueError('smoke aggregate output bound')
                if name == 'smoke-proof.json':
                    if len(path.read_bytes()) > 4096 or json.loads(path.read_bytes()) != expected: raise ValueError('smoke canary proof mismatch')
                    proof_files.append(str(path.relative_to(root)))
        if len(proof_files) != 1: raise ValueError('exact one actual build-script canary proof required')
        observation = {**compiled, 'controlledSmoke': True, 'outputBytes': total, 'proofFiles': proof_files,
                       'controls': {'landlock': True, 'networkDenied': True, 'uringDenied': True, 'inheritedFdsClosed': True,
                                    'outsideWriteDenied': True, 'privateWriteAllowed': True, 'directCargoCompatible': True}}
    except Exception as error: failure = type(error).__name__
    receipt = {'schema': 'universe-electrs-expanded-cargo-confinement-proof-v1', 'sourceSha': context['sourceSha'],
               'actualResources': resources, 'failureType': failure, 'cargoExit': cargo_exit,
               **(observation or {}), 'fullRustBuild': False, 'nativeActions': False}
    with (root / 'proof-receipt.json').open('x') as output: json.dump(receipt, output, indent=2)
    return 0 if failure is None else 1


def launch(closure_path, closure_sha, progress=None):
    progress = {} if progress is None else progress
    progress['phase'] = 'runtime-source-guard'
    full = load('smoke_parent_bounds', 'full-cargo-scope.py')
    guard = load('smoke_parent_runtime', 'locked-cache-readonly.py'); source = guard.runtime_guard()
    inventory = load('smoke_parent_git', 'locked-source-inventory.py'); guard.source_guard(inventory, source)
    temp = pathlib.Path(os.environ['RUNNER_TEMP'])
    observed = guard.headroom_report(temp)
    progress.update({'phase': 'headroom', 'sourceSha': source, 'observedResources': observed})
    load('smoke_parent_pressure', 'confinement-proof.py').headroom(observed)  # Before closure hashes or mkdir.
    closure = full.read_json(closure_path, closure_sha)
    progress['phase'] = 'closed-tool-sdk-verification'
    roles = closure['roles']; primary = load('smoke_parent_pins', 'confined-build-plan.py').TOOL_PINS
    environment = {'RUSTC': roles['rustc']['resolvedPath'], 'CC': roles['cc']['resolvedPath'], 'CXX': roles['cxx']['resolvedPath'],
                   'AR': closure['arPath'], 'LIBCLANG_PATH': str(pathlib.Path(roles['libclang']['resolvedPath']).parent),
                   'LD_LIBRARY_PATH': ':'.join(sorted({str(pathlib.Path(leaf['path']).parent) for leaf in closure['leaves'] if '.so' in pathlib.Path(leaf['path']).name}))}
    context = {'sourceSha': source, 'cargoPath': roles['cargo']['resolvedPath'], 'compilerEnvironment': environment,
               'toolAliases': closure['toolAliases'], 'compilerClosureReceiptSha256': closure['observationReceiptSha256']}
    full.validate_tools(context, closure)
    full.verify_sdk_trees(closure)
    tool_fences = sorted(full.VERIFIED_FENCES.values(), key=lambda record: record['path'])
    small = load('smoke_parent_unit', 'small-fuse-image-proof.py')
    for pin in [small.RUN_TOOL, small.CTL_TOOL, small.PYTHON]: small.pin(pin)
    unit = 'universe-electrs-cargo-smoke-' + os.environ['GITHUB_RUN_ID'] + '-' + os.environ['GITHUB_RUN_ATTEMPT'] + '-' + os.urandom(8).hex()
    if not re.fullmatch(r'universe-electrs-cargo-smoke-[0-9]{1,20}-[0-9]{1,3}-[0-9a-f]{16}', unit): raise ValueError('smoke owned run/unit')
    root = temp / unit
    if root.exists() or root.is_symlink(): raise ValueError('exclusive smoke task exists; no retry')
    root.mkdir(mode=0o700)
    progress.update({'phase': 'prepare-controlled-smoke', 'ownedRoot': str(root), 'ownedUnit': unit})
    with (root / 'closure.json').open('xb') as output: output.write(closure_path.read_bytes())
    for name in ['source', 'work', 'wrapper-source']: (root / name).mkdir(mode=0o700)
    (root / 'source' / 'src').mkdir(mode=0o700)
    for name, raw in project_bytes(str(root / 'source' / 'outside-canary')).items():
        with (root / 'source' / name).open('xb') as output: output.write(raw)
        (root / 'source' / name).chmod(0o400)
    with (root / 'source' / 'outside-canary').open('xb') as output: output.write(b'owned-readable-canary')
    (root / 'source' / 'outside-canary').chmod(0o600)  # DAC permits writes; Landlock must deny them.
    for name in ['tmp', 'cargo-home', 'target', 'home', 'bin']: (root / 'work' / name).mkdir(mode=0o700)
    (root / 'work' / 'cargo-home' / 'config.toml').write_text('[net]\noffline=true\n')
    for name, target in context['toolAliases'].items(): (root / 'work' / 'bin' / name).symlink_to(target)
    all_environment = {**environment, 'PATH': str(root / 'work' / 'bin'), 'HOME': str(root / 'work' / 'home'),
                       'CARGO_HOME': str(root / 'work' / 'cargo-home'), 'CARGO_TARGET_DIR': str(root / 'work' / 'target'), 'TMPDIR': str(root / 'work' / 'tmp')}
    (root / 'work' / 'environment').write_text(''.join(key + '=' + value + '\n' for key, value in sorted(all_environment.items())))
    (root / 'work' / 'environment').chmod(0o600)
    roots = [('R', str(root / 'source'))]
    for leaf in closure['leaves']: roots.append(('X' if leaf['executable'] else 'R', leaf['path']))
    allowed = {primary['rustc'][0].split('/bin/')[0] + '/lib', '/usr/include', '/usr/lib/gcc/x86_64-linux-gnu/13/include', '/usr/lib/gcc/x86_64-linux-gnu/13/include-fixed'}
    for tree in closure.get('reviewedReadOnlyTrees', []):
        if tree not in allowed: raise ValueError('smoke overbroad SDK read tree')
        roots.append(('R', tree))
    if len(roots) > 128: raise ValueError('smoke read leaf count')
    (root / 'read-roots').write_text(''.join(kind + ' ' + path + '\n' for kind, path in roots))
    (root / 'read-roots').chmod(0o400)
    source_hashes = {}
    for name in ['confined-cargo.c', 'confinement-proof.c']:
        raw = (HERE / name).read_bytes(); source_hashes[name] = hashlib.sha256(raw).hexdigest()
        with (root / 'wrapper-source' / name).open('xb') as output: output.write(raw)
        (root / 'wrapper-source' / name).chmod(0o400)
    with (root / 'sentinel').open('xb') as output: output.write(b'owned-fd-must-not-survive')
    context.update({'compilerClosureSha256': closure_sha, 'wrapperSourceHashes': source_hashes, 'headroom': observed,
                    'controllerSha256': full.file_hash(pathlib.Path(__file__)), 'toolFences': tool_fences})
    raw_context = json.dumps(context, sort_keys=True, separators=(',', ':')).encode()
    with (root / 'context.json').open('xb') as output: output.write(raw_context)
    reviewed = hashlib.sha256(raw_context).hexdigest()
    env = {'LANG': 'C', 'PATH': '/usr/bin:/bin', 'HOME': '/home/github-runner', 'XDG_RUNTIME_DIR': '/run/user/1001', 'DBUS_SESSION_BUS_ADDRESS': 'unix:path=/run/user/1001/bus'}
    command = [small.RUN_TOOL['path'], '--user', '--unit=' + unit, '--collect', '--wait', '--pipe', '--service-type=exec',
               '--property=CPUQuota=100%', '--property=CPUQuotaPeriodSec=100ms', '--property=MemoryMax=512M', '--property=TasksMax=32',
               '--property=RuntimeMaxSec=60s', '--property=TimeoutStopSec=5s', '--property=Nice=19', '--property=IOWeight=1', '--property=NoNewPrivileges=yes',
               '--property=KillMode=control-group', '--property=UnsetEnvironment=LD_PRELOAD LD_LIBRARY_PATH LD_AUDIT PYTHONPATH PYTHONHOME',
               '--', small.PYTHON['path'], '-B', '-I', '-S', str(pathlib.Path(__file__).resolve()), '--worker-root', str(root), '--reviewed-context-sha256', reviewed]
    errors = []; exit_code = 1; progress['phase'] = 'one-owned-smoke-unit'
    with (root / 'unit.stdout').open('xb') as out, (root / 'unit.stderr').open('xb') as err:
        child = subprocess.Popen(command, env=env, stdin=subprocess.DEVNULL, stdout=out, stderr=err)
        try: exit_code = child.wait(timeout=70)
        except subprocess.TimeoutExpired:
            try: subprocess.run([small.CTL_TOOL['path'], '--user', 'stop', unit], env=env, timeout=5, check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            except Exception as error: errors.append('own stop: ' + type(error).__name__)
            child.kill(); child.wait(timeout=5); errors.append('smoke owned watchdog timeout')
    receipt = {'schema': 'universe-electrs-expanded-cargo-smoke-parent-v1', 'root': str(root), 'unit': unit, 'sourceSha': source,
               'controllerSha256': context['controllerSha256'], 'contextSha256': reviewed, 'exitCode': exit_code, 'errors': errors,
               'fullRustBuild': False, 'nativeActions': False, 'artifactsPreserved': True}
    with (root / 'parent-receipt.json').open('x') as output: json.dump(receipt, output, indent=2)
    return 0 if exit_code == 0 and not errors else 1


def bounded_failure_files(root):
    records = []; remaining = 32768
    for name in ['compile.stderr', 'compile.stdout', 'setup.stderr', 'setup.stdout', 'unit.stderr', 'unit.stdout', 'work/cargo.stderr', 'work/cargo.stdout']:
        path = root / name
        try:
            if not path.exists() or path.is_symlink() or not path.is_file(): continue
            fd = os.open(path, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_NONBLOCK', 0))
            with os.fdopen(fd, 'rb') as incoming:
                info = os.fstat(incoming.fileno())
                if not stat.S_ISREG(info.st_mode) or info.st_uid != 1001 or info.st_nlink != 1: continue
                raw = incoming.read(min(4096, remaining))
            remaining -= len(raw)
            records.append({'file': name, 'bytesCaptured': len(raw), 'truncated': info.st_size > len(raw),
                            'sha256': hashlib.sha256(raw).hexdigest(), 'text': raw.decode('utf-8', errors='replace')})
        except Exception as error: records.append({'file': name, 'failureType': type(error).__name__})
    return records


def main():
    parser = argparse.ArgumentParser(description=__doc__); parser.add_argument('--worker-root', type=pathlib.Path); parser.add_argument('--reviewed-context-sha256')
    parser.add_argument('--run-reviewed-smoke', action='store_true'); parser.add_argument('--closure', type=pathlib.Path); parser.add_argument('--closure-sha256')
    args = parser.parse_args()
    if args.run_reviewed_smoke:
        if args.worker_root or args.closure is None or not re.fullmatch('[0-9a-f]{64}', args.closure_sha256 or ''): raise ValueError('one explicit reviewed smoke mode')
        progress = {'fullRustBuild': False, 'nativeActions': False}
        try: code = launch(args.closure, args.closure_sha256, progress)
        except Exception as error:
            print(json.dumps({**progress, 'failureType': type(error).__name__, 'automaticRetry': False}))
            code = 1
        if code and 'ownedRoot' in progress:
            print(json.dumps({'ownedRoot': progress['ownedRoot'], 'ownedUnit': progress['ownedUnit'], 'boundedOwnFailureFiles': bounded_failure_files(pathlib.Path(progress['ownedRoot']))}))
        raise SystemExit(code)
    if args.worker_root is None:
        print(json.dumps({'preparedOnly': True, 'unitCreated': False, 'cargoInvoked': False})); return
    root = args.worker_root
    if not re.fullmatch(r'/opt/github-runners/runner-[0-9]{1,3}/_work/_temp/universe-electrs-cargo-smoke-[0-9]{1,20}-[0-9]{1,3}-[0-9a-f]{16}', str(root)): raise ValueError('smoke owned root')
    full = load('smoke_context_reader', 'full-cargo-scope.py')
    context = full.read_json(root / 'context.json', args.reviewed_context_sha256, 2 * 1024**2)
    raise SystemExit(worker(root, context))


if __name__ == '__main__': main()
