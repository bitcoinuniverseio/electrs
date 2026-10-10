"""Bounded read-only existing compiler ELF/header/toolchain closure; no tool execution."""
import argparse
import hashlib
import importlib.util
import json
import mmap
import os
import pathlib
import stat
import time

HERE = pathlib.Path(__file__).resolve().parent
RUST = '/home/github-runner/.rustup/toolchains/1.89.0-x86_64-unknown-linux-gnu'
LLVM = '/home/github-runner/.local/universe-host-tools/prefix/usr/lib/llvm-18'
TOOLS = ['/usr/bin/x86_64-linux-gnu-as', '/usr/bin/x86_64-linux-gnu-ld.bfd', '/usr/bin/x86_64-linux-gnu-ar',
         '/usr/bin/x86_64-linux-gnu-nm', '/usr/bin/x86_64-linux-gnu-ranlib',
         '/usr/lib/gcc/x86_64-linux-gnu/13/cc1', '/usr/lib/gcc/x86_64-linux-gnu/13/cc1plus', '/usr/lib/gcc/x86_64-linux-gnu/13/collect2']
TREES = [RUST + '/lib', '/usr/include', '/usr/lib/gcc/x86_64-linux-gnu/13/include',
         '/usr/lib/gcc/x86_64-linux-gnu/13/include-fixed']
LIBRARY_ROOTS = [RUST + '/lib', LLVM + '/lib', '/usr/lib/llvm-18/lib', '/usr/lib/x86_64-linux-gnu', '/usr/lib/gcc/x86_64-linux-gnu/13']


def load(name, file):
    spec = importlib.util.spec_from_file_location(name, HERE / file); value = importlib.util.module_from_spec(spec); spec.loader.exec_module(value); return value


class Budget:
    def __init__(self):
        self.bytes = 0; self.files = 0; self.entries = 0; self.elf_bytes = 0; self.started = time.monotonic()
    def tick(self, entries=1):
        self.entries += entries
        if self.entries > 100000 or time.monotonic() - self.started > 90:
            raise ValueError('compiler directory/entry/time bound')
    def charge(self, size):
        self.tick()
        self.bytes += size; self.files += 1
        if self.bytes > 2 * 1024**3 or self.files > 50000 or time.monotonic() - self.started > 90: raise ValueError('compiler closure read/file/time bound')


def allowed_leaf(path):
    text = str(path)
    exact = {pair[0] for pair in load('allowed_primary_pins', 'confined-build-plan.py').TOOL_PINS.values()}
    if text in exact or text in TOOLS: return True
    return any(pathlib.Path(root) == path or pathlib.Path(root) in path.parents for root in LIBRARY_ROOTS + TREES)


def identity(value):
    return (value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns, value.st_ctime_ns, value.st_uid, value.st_nlink)


def pin_file(path, budget):
    resolved = pathlib.Path(path).resolve(strict=True)
    if not allowed_leaf(resolved): raise ValueError('compiler resolved leaf outside exact reviewed roots')
    before = resolved.lstat()
    if not stat.S_ISREG(before.st_mode) or before.st_uid not in [0, 1001] or before.st_nlink != 1 or before.st_size > 256 * 1024**2:
        raise ValueError('bounded regular compiler leaf ownership required')
    size = before.st_size; budget.charge(size); digest = hashlib.sha256()
    fd = os.open(resolved, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_NONBLOCK', 0))
    with os.fdopen(fd, 'rb') as source:
        if identity(os.fstat(source.fileno())) != identity(before): raise ValueError('compiler leaf changed before hash')
        remaining = size
        while remaining:
            budget.tick(0)
            block = source.read(min(65536, remaining))
            if not block: raise ValueError('compiler leaf truncated during hash')
            digest.update(block); remaining -= len(block)
        budget.tick(0)
        if source.read(1): raise ValueError('compiler leaf appended during hash')
        if identity(os.fstat(source.fileno())) != identity(before): raise ValueError('compiler leaf changed during hash')
    if identity(resolved.lstat()) != identity(before): raise ValueError('compiler leaf path changed after hash')
    return {'path': str(resolved), 'bytes': size, 'sha256': digest.hexdigest()}


def elf(path, parser, budget, expected):
    budget.tick()
    budget.elf_bytes += expected['bytes']
    if budget.elf_bytes > 1024**3: raise ValueError('cumulative compiler ELF read bound')
    fd = os.open(path, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_NONBLOCK', 0))
    with os.fdopen(fd, 'rb') as source:
        before = os.fstat(source.fileno())
        if not stat.S_ISREG(before.st_mode) or before.st_uid not in [0, 1001] or before.st_nlink != 1 or before.st_size != expected['bytes']:
            raise ValueError('ELF leaf changed after pinning')
        if before.st_size == 0: return None
        with mmap.mmap(source.fileno(), before.st_size, access=mmap.ACCESS_READ) as raw:
            digest = hashlib.sha256()
            for offset in range(0, before.st_size, 65536):
                budget.tick(0); digest.update(raw[offset:offset + 65536])
            if digest.hexdigest() != expected['sha256']: raise ValueError('ELF hash changed')
            result = parser.elf_metadata(raw, maximum_bytes=256 * 1024**2, allow_runpath=True) if raw[:4] == b'\x7fELF' else None
        if identity(os.fstat(source.fileno())) != identity(before) or identity(pathlib.Path(path).lstat()) != identity(before):
            raise ValueError('ELF leaf changed during parse')
        return result


def tree_pin(root, budget):
    root = pathlib.Path(root)
    if not root.is_dir() or root.is_symlink(): return {'path': str(root), 'present': False}
    files = []; links = []
    for directory, dirs, names in os.walk(root, followlinks=False):
        budget.tick(1 + len(dirs) + len(names))
        for name in list(dirs):
            path = pathlib.Path(directory) / name
            if path.is_symlink(): raise ValueError('linked compiler tree directory requires reviewed resolution')
        for name in names:
            path = pathlib.Path(directory) / name
            if path.is_symlink():
                target = path.resolve(strict=True)
                if root != target and root not in target.parents: raise ValueError('compiler tree link leaves exact read tree')
                links.append({'path': path.relative_to(root).as_posix(), 'target': target.relative_to(root).as_posix()}); continue
            record = pin_file(path, budget); record['relative'] = path.relative_to(root).as_posix(); files.append(record)
    raw = json.dumps({'files': sorted(files, key=lambda r: r['relative']), 'links': sorted(links, key=lambda r: r['path'])}, sort_keys=True, separators=(',', ':')).encode()
    return {'path': str(root), 'present': True, 'treeManifestSha256': hashlib.sha256(raw).hexdigest(), 'files': files, 'links': links}


def collect(progress=None):
    progress = {} if progress is None else progress
    progress['phase'] = 'runtime-source-guard'
    guard = load('closure_guard', 'locked-cache-readonly.py'); source = guard.runtime_guard()
    git = load('closure_git', 'locked-source-inventory.py'); guard.source_guard(git, source)
    progress['sourceSha'] = source
    progress['phase'] = 'read-only-headroom'
    resources = guard.headroom_report(pathlib.Path(os.environ['RUNNER_TEMP']))
    progress['observedResources'] = resources
    pressure = load('closure_pressure', 'confinement-proof.py')
    try:
        progress['headroom'] = pressure.headroom(resources)
        progress['smallProofHeadroomAvailable'] = True
    except ValueError:
        # Metadata is retained; expensive tree reads remain withheld on rejection.
        progress['smallProofHeadroomAvailable'] = False
        progress['compilerClosureReadWithheld'] = True
        return progress
    progress['phase'] = 'bounded-compiler-closure'
    known = load('primary_compiler_pins', 'confined-build-plan.py').TOOL_PINS
    parser = load('bounded_compiler_elf', 'inspect-fuse-packages.py'); budget = Budget(); records = {}; missing = []
    queue = []
    for role, (path, expected) in known.items():
        record = pin_file(path, budget)
        if record['sha256'] != expected: raise ValueError('observed primary compiler pin changed: ' + role)
        record['role'] = role; records[record['path']] = record; queue.append(record['path'])
    for path in TOOLS:
        if not pathlib.Path(path).is_file(): missing.append({'role': 'compiler-tool', 'path': path}); continue
        record = pin_file(path, budget); record['role'] = 'compiler-tool'; records[record['path']] = record; queue.append(record['path'])
    seen = set()
    while queue:
        path = queue.pop(0)
        if path in seen: continue
        if len(seen) >= 128: raise ValueError('bounded compiler ELF dependency count')
        seen.add(path); metadata = elf(path, parser, budget, records[path]); records[path]['elf'] = metadata
        if metadata is None: continue
        roots = list(LIBRARY_ROOTS)
        for runpath in metadata['runPaths']:
            for value in runpath.split(':'):
                resolved = pathlib.Path(value.replace('$ORIGIN', str(pathlib.Path(path).parent))).resolve(strict=True)
                if str(resolved) not in LIBRARY_ROOTS: raise ValueError('compiler RUNPATH outside reviewed library roots')
                roots.insert(0, str(resolved))
        dependencies = list(metadata['needed'])
        if metadata['interpreter']: dependencies.append('ld-linux-x86-64.so.2')
        for name in dependencies:
            candidates = {str((pathlib.Path(root) / name).resolve(strict=True)) for root in roots if (pathlib.Path(root) / name).is_file()}
            if len(candidates) != 1: missing.append({'role': 'unresolved-or-ambiguous-ELF', 'name': name, 'from': path}); continue
            target = next(iter(candidates))
            if target not in records: records[target] = pin_file(target, budget); records[target]['role'] = 'compiler-library'; queue.append(target)
    trees = [tree_pin(path, budget) for path in TREES]
    guard.source_guard(git, source)
    return {**progress, 'schema': 'universe-electrs-existing-compiler-closure-metadata-v1', 'sourceSha': source,
            'leaves': list(records.values()), 'trees': trees, 'missing': missing, 'readBytes': budget.bytes, 'readFiles': budget.files,
            'readEntries': budget.entries, 'elfReadBytes': budget.elf_bytes,
            'toolExecuted': False, 'cargoInvoked': False, 'installed': False, 'nativeActions': False,
            'compilerClosureQualified': False, 'expandedConfinementQualified': False}


def main():
    parser = argparse.ArgumentParser(description=__doc__); parser.add_argument('--observe-owned-compiler', action='store_true')
    args = parser.parse_args()
    if not args.observe_owned_compiler:
        print(json.dumps({'preparedOnly': True, 'metadataRead': False, 'toolExecuted': False})); return
    progress = {'schema': 'universe-electrs-existing-compiler-closure-metadata-v1',
                'cargoInvoked': False, 'unitCreated': False, 'toolExecuted': False,
                'nativeActions': False, 'compilerClosureQualified': False}
    try:
        result = collect(progress)
    except Exception as error:
        # Exception text may include private paths or environment data: type only.
        result = {**progress, 'observationComplete': False, 'failureType': type(error).__name__}
    raw = json.dumps(result, separators=(',', ':')).encode()
    if len(raw) > 8 * 1024**2: raise ValueError('compiler closure report bound')
    import sys
    sys.stdout.buffer.write(raw + b'\n')


if __name__ == '__main__': main()
