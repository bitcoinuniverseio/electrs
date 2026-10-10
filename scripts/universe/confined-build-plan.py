"""Pure full-build admission/read-root validator. Never launches tools or units."""
import argparse
import hashlib
import json
import pathlib
import re

LOCK_SHA = 'a46b82fd06e8fe3858a1722ec0098d528bd2f4920bc3116c7e247ef473613236'
RUST_ROOT = '/home/github-runner/.rustup/toolchains/1.89.0-x86_64-unknown-linux-gnu'
TOOL_PINS = {
    'rustc': (RUST_ROOT + '/bin/rustc', 'c6ac0142c05a60b0f6c15e1a118bd5ac3bd04924cd6dc0c328f501c5f86e4142'),
    'cargo': (RUST_ROOT + '/bin/cargo', '5b32bd53b8a08d8e206daed51f3fce40cdc0729038ff96bd0ca845596a2c1019'),
    'cc': ('/usr/bin/x86_64-linux-gnu-gcc-13', '1b99826121ae6682a634e5efe09bd3e3df58ce58e0b28f849114ab5b89139c26'),
    'cxx': ('/usr/bin/x86_64-linux-gnu-g++-13', '1353e9bdd29a7295c7226bf6c63abccce056d8cac31f112e5cdbecc3f28c2769'),
    'clang': ('/home/github-runner/.local/universe-host-tools/prefix/usr/lib/llvm-18/bin/clang', '8ef402d453d1ba4902e4ee0f0f847f6cfa01400c95aa43c24e97818b9c0e3f45'),
    'libclang': ('/usr/lib/x86_64-linux-gnu/libclang-18.so.18', 'd7c54213dbeb95deb5bfee76cf3e32e425cbaf8ccbd2900345414fb57476458b'),
}


def full_sha(value):
    return isinstance(value, str) and re.fullmatch('[0-9a-f]{64}', value) is not None


def owned_root(path, task_root):
    path = pathlib.PurePosixPath(path)
    root = pathlib.PurePosixPath(task_root)
    if not path.is_absolute() or '..' in path.parts or path == root or root not in path.parents:
        raise ValueError('owned exclusive task child required')
    return str(path)


def validate(plan):
    if plan.get('schema') != 'universe-electrs-confined-build-plan-v1':
        raise ValueError('plan schema')
    if not re.fullmatch('[0-9a-f]{40}', plan.get('sourceSha', '')) or plan.get('cargoLockSha256') != LOCK_SHA:
        raise ValueError('source/lock binding')
    if plan.get('profile') != 'unchanged-default' or plan.get('operation') not in ['test-compile', 'test']:
        raise ValueError('unreviewed operation/features')
    task = plan.get('taskRoot', '')
    if not (re.fullmatch(r'/opt/github-runners/runner-[0-9]{1,3}/_work/_temp/universe-electrs-build-[0-9]{1,20}-[0-9]{1,3}-[0-9a-f]{16}', task) or re.fullmatch(r'/home/github-runner/.cache/universe-electrs-api-20261009/[0-9a-f]{16}', task)):
        raise ValueError('owned task root')
    paths = {key: owned_root(plan.get(key, ''), task) for key in ['workRoot', 'sourceRoot', 'vendorRoot']}
    if len(set(paths.values())) != 3 or any(pathlib.PurePosixPath(a) in pathlib.PurePosixPath(b).parents for a in paths.values() for b in paths.values() if a != b):
        raise ValueError('source/vendor/work roots must be disjoint')
    required = ['sourceManifestSha256', 'vendorManifestSha256', 'inventoryReceiptSha256',
                'wrapperSourceSha256', 'wrapperBinarySha256', 'readRootsManifestSha256']
    if any(not full_sha(plan.get(key)) for key in required):
        raise ValueError('immutable manifest bindings required')
    tools = plan.get('tools', {})
    if set(tools) != set(TOOL_PINS):
        raise ValueError('exact observed primary tools required')
    for role, (path, sha) in TOOL_PINS.items():
        if tools[role] != {'path': path, 'sha256': sha}:
            raise ValueError('observed tool path/hash drift: ' + role)
    roots = plan.get('readRoots', [])
    if not roots or len(roots) > 128:
        raise ValueError('read root bound')
    seen = set()
    for entry in roots:
        if set(entry) != {'path', 'kind', 'sha256', 'executable'} or not full_sha(entry['sha256']) or type(entry['executable']) is not bool:
            raise ValueError('read root exact shape')
        path = pathlib.PurePosixPath(entry['path'])
        if not path.is_absolute() or '..' in path.parts or str(path) in seen:
            raise ValueError('read root path/duplicate')
        seen.add(str(path))
        kind = entry['kind']
        allowed = False
        if kind == 'tool-file':
            allowed = any(str(path) == pair[0] and entry['sha256'] == pair[1] for pair in TOOL_PINS.values())
            allowed = allowed and entry['executable'] == (str(path) != TOOL_PINS['libclang'][0])
        elif kind == 'source-tree':
            allowed = str(path) == paths['sourceRoot'] and entry['sha256'] == plan['sourceManifestSha256'] and not entry['executable']
        elif kind == 'vendor-tree':
            allowed = str(path) == paths['vendorRoot'] and entry['sha256'] == plan['vendorManifestSha256'] and not entry['executable']
        elif kind == 'toolchain-tree':
            allowed = str(path) in [RUST_ROOT + '/lib', RUST_ROOT + '/lib/rustlib/x86_64-unknown-linux-gnu/lib']
        elif kind == 'sdk-tree':
            allowed = str(path) in ['/usr/include', '/usr/lib/gcc/x86_64-linux-gnu/13/include',
                                    '/usr/lib/gcc/x86_64-linux-gnu/13/include-fixed',
                                    '/usr/include/c++/13', '/usr/include/x86_64-linux-gnu/c++/13'] and not entry['executable']
        elif kind == 'linker-file':
            allowed = str(path).startswith(('/usr/bin/', '/usr/lib/gcc/x86_64-linux-gnu/13/', '/usr/lib/x86_64-linux-gnu/')) and path.name in ['as', 'ld', 'ld.bfd', 'ar', 'nm', 'ranlib', 'collect2', 'cc1', 'cc1plus', 'x86_64-linux-gnu-as', 'x86_64-linux-gnu-ld.bfd', 'x86_64-linux-gnu-ar', 'x86_64-linux-gnu-nm', 'x86_64-linux-gnu-ranlib']
        elif kind == 'loader-file':
            allowed = str(path) == '/etc/ld.so.cache' and not entry['executable']
        elif kind == 'shared-library-file':
            allowed = str(path).startswith(('/usr/lib/x86_64-linux-gnu/', '/usr/lib/gcc/x86_64-linux-gnu/13/')) and re.fullmatch(r'[A-Za-z0-9_+.-]{1,160}\.so(?:\.[0-9.]+)?', path.name) is not None
        if not allowed:
            raise ValueError('unreviewed/overbroad read leaf: ' + str(path))
    if not {paths['sourceRoot'], paths['vendorRoot'], TOOL_PINS['cargo'][0], TOOL_PINS['rustc'][0]} <= seen:
        raise ValueError('required read closure missing')
    expected = {'cpuMax': '200000 100000', 'memoryMax': str(4 * 1024**3), 'pidsMax': '128',
                'runtimeSeconds': 1800, 'targetByteLimit': 8 * 1024**3, 'jobs': 2}
    if plan.get('proposedResources') != expected:
        raise ValueError('fixed resource proposal drift')
    # Input claims are never converted into observed enforcement/admission.
    return {'schema': 'universe-electrs-confined-build-plan-review-v1', 'sourceSha': plan['sourceSha'],
            'cargoLockSha256': LOCK_SHA, 'readRoots': roots, 'proposedResources': expected,
            'sourcePlanValidated': True, 'buildAdmissionQualified': False,
            'remainingGates': ['Actual exact-lock source/vendor materialization with per-file checksum validation',
                               'Independent wrapper/read-leaf compile, isolation and Cargo compatibility proof',
                               'Fresh larger scope actual cgroup, resource headroom and 8GiB storage enforcement proof'],
            'cargoInvoked': False, 'unitCreated': False, 'nativeActions': False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--review-plan', type=pathlib.Path)
    args = parser.parse_args()
    if args.review_plan is None:
        print(json.dumps({'preparedOnly': True, 'cargoInvoked': False, 'unitCreated': False}))
        return
    path = args.review_plan
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 256 * 1024:
        raise ValueError('bounded regular plan file required')
    raw = path.read_bytes()
    result = validate(json.loads(raw))
    result['planSha256'] = hashlib.sha256(raw).hexdigest()
    print(json.dumps(result))


if __name__ == '__main__':
    main()
