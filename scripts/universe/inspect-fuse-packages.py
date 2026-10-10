"""Bounded checksum-first Debian data/ELF inspection. Never executes package code."""
import argparse
import hashlib
import importlib.util
import io
import json
import os
import pathlib
import re
import struct
import subprocess
import tarfile

HERE = pathlib.Path(__file__).resolve().parent
NODE = {'path': 'C:/Program Files/nodejs/node.exe', 'sha256': '3602f2bb1a10f2cbab4c36886218a33c1ab3db87290e73b033c46c77147d0237'}
MAX_DATA = 8 * 1024**2
SONAME = re.compile(r'[A-Za-z0-9_+.-]{1,160}')


def helper():
    spec = importlib.util.spec_from_file_location('helper_capsule', HERE / 'acquire-fuse-helper.py')
    value = importlib.util.module_from_spec(spec); spec.loader.exec_module(value)
    return value


def ar_data(raw, expected):
    if len(raw) != expected['bytes'] or hashlib.sha256(raw).hexdigest() != expected['sha256']:
        raise ValueError('exact official package checksum/size required before ar parser')
    if not raw.startswith(b'!<arch>\n'): raise ValueError('Debian ar magic')
    offset = 8; members = {}
    while offset < len(raw):
        header = raw[offset:offset + 60]
        if len(header) != 60 or header[-2:] != b'`\n': raise ValueError('bounded Debian header invalid')
        name = header[:16].decode('ascii').strip().rstrip('/')
        size_text = header[48:58].decode('ascii').strip()
        if not size_text.isdecimal() or name not in ['debian-binary', 'control.tar.zst', 'data.tar.zst'] or name in members:
            raise ValueError('unknown/duplicate Debian member')
        size = int(size_text); start = offset + 60
        if size > 512 * 1024 or start + size > len(raw): raise ValueError('Debian member size bound')
        members[name] = raw[start:start + size]
        offset = start + size + size % 2
    if offset != len(raw) or set(members) != {'debian-binary', 'control.tar.zst', 'data.tar.zst'} or members['debian-binary'] != b'2.0\n':
        raise ValueError('exact Debian container layout required')
    # Control bytes are neither decompressed nor interpreted/executed.
    return members['data.tar.zst']


def decompress(data):
    path = pathlib.Path(NODE['path'])
    if os.name != 'nt' or not path.is_file() or path.is_symlink() or hashlib.sha256(path.read_bytes()).hexdigest() != NODE['sha256']:
        raise ValueError('exact existing Windows Node decoder required; no install/fallback')
    code = "const fs=require('node:fs'),z=require('node:zlib');fs.writeFileSync(1,z.zstdDecompressSync(fs.readFileSync(0),{maxOutputLength:8388608}));"
    result = subprocess.run([str(path), '-e', code], input=data, env={'SystemRoot': os.environ['SystemRoot']}, capture_output=True, timeout=5, check=True)
    if len(result.stdout) > MAX_DATA or len(result.stderr) > 4096: raise ValueError('decoder output bound')
    if hashlib.sha256(path.read_bytes()).hexdigest() != NODE['sha256']: raise ValueError('decoder tool drift')
    return result.stdout


def elf_metadata(raw, maximum_bytes=MAX_DATA, allow_runpath=False):
    if maximum_bytes > 256 * 1024**2 or len(raw) > maximum_bytes or len(raw) < 64 or raw[:7] != b'\x7fELF\x02\x01\x01': raise ValueError('Linux ELF64 little-endian required')
    header = struct.unpack_from('<HHIQQQIHHHHHH', raw, 16)
    kind, machine, version, _, phoff, _, _, _, phsize, phcount, *_ = header
    if kind not in [2, 3] or machine != 62 or version != 1 or phsize != 56 or phcount > 128 or phoff + phcount * 56 > len(raw): raise ValueError('bounded x86_64 ELF headers required')
    segments = [struct.unpack_from('<IIQQQQQQ', raw, phoff + i * 56) for i in range(phcount)]
    loads = []; dynamic = None; interpreter = None
    for ptype, flags, offset, address, _, size, _, _ in segments:
        if offset + size > len(raw): raise ValueError('ELF segment outside file')
        if ptype == 1:
            if flags & 3 == 3: raise ValueError('ELF writable executable segment')
            loads.append((offset, address, size))
        elif ptype == 2:
            if dynamic is not None or size % 16 or size > 65536: raise ValueError('dynamic segment invalid')
            dynamic = (offset, size)
        elif ptype == 3:
            if interpreter is not None or size > 256 or not raw[offset:offset + size].endswith(b'\0'): raise ValueError('ELF interpreter invalid')
            interpreter = raw[offset:offset + size - 1].decode('ascii')
            if interpreter != '/lib64/ld-linux-x86-64.so.2': raise ValueError('unreviewed ELF interpreter')
    if dynamic is None: raise ValueError('expected dynamic helper/library ELF')
    tags = {}
    for offset in range(dynamic[0], dynamic[0] + dynamic[1], 16):
        tag, value = struct.unpack_from('<qQ', raw, offset)
        if tag == 0: break
        tags.setdefault(tag, []).append(value)
    def mapped(address, size):
        matches = [offset + address - base for offset, base, length in loads if base <= address and address + size <= base + length]
        if len(matches) != 1: raise ValueError('ELF virtual address ambiguity')
        return matches[0]
    if len(tags.get(5, [])) != 1 or len(tags.get(10, [])) != 1 or tags[10][0] > 65536: raise ValueError('ELF string table bound')
    start = mapped(tags[5][0], tags[10][0]); strings = raw[start:start + tags[10][0]]
    def string(index):
        if index >= len(strings): raise ValueError('ELF string offset')
        end = strings.find(b'\0', index)
        if end < 0 or end - index > 160: raise ValueError('ELF string bound')
        value = strings[index:end].decode('ascii')
        if not SONAME.fullmatch(value): raise ValueError('ELF dependency/version spelling')
        return value
    needed = [string(value) for value in tags.get(1, [])]
    soname = string(tags[14][0]) if len(tags.get(14, [])) == 1 else None
    if len(tags.get(14, [])) > 1 or (not needed and soname != 'ld-linux-x86-64.so.2') or len(needed) > 32 or len(set(needed)) != len(needed): raise ValueError('ELF dependency count')
    runpaths = []
    if tags.get(15) or tags.get(29):
        if not allow_runpath: raise ValueError('unexpected ELF RPATH/RUNPATH')
        for index in tags.get(15, []) + tags.get(29, []):
            end = strings.find(b'\0', index)
            if index >= len(strings) or end < 0 or end - index > 1024: raise ValueError('bounded compiler runpath required')
            runpaths.append(strings[index:end].decode('ascii'))
    versions = []
    definitions = []
    if tags.get(0x6ffffffc):
        if len(tags[0x6ffffffc]) != 1 or len(tags.get(0x6ffffffd, [])) != 1 or tags[0x6ffffffd][0] > 128: raise ValueError('ELF version definitions bound')
        address = tags[0x6ffffffc][0]
        for i in range(tags[0x6ffffffd][0]):
            offset = mapped(address, 20); version, _, _, count, _, aux, following = struct.unpack_from('<HHHHIII', raw, offset)
            if version != 1 or not 1 <= count <= 16: raise ValueError('ELF version definition record')
            aux_address = address + aux
            for j in range(count):
                aux_offset = mapped(aux_address, 8); name, next_aux = struct.unpack_from('<II', raw, aux_offset)
                definitions.append(string(name))
                if j < count - 1 and next_aux == 0: raise ValueError('ELF definition auxiliary chain incomplete')
                aux_address += next_aux
            if i < tags[0x6ffffffd][0] - 1 and following == 0: raise ValueError('ELF definition chain incomplete')
            address += following
    if tags.get(0x6ffffffe):
        if len(tags[0x6ffffffe]) != 1 or len(tags.get(0x6fffffff, [])) != 1 or tags[0x6fffffff][0] > 32: raise ValueError('ELF version needs bound')
        address = tags[0x6ffffffe][0]
        for i in range(tags[0x6fffffff][0]):
            offset = mapped(address, 16); version, count, filename, aux, following = struct.unpack_from('<HHIII', raw, offset)
            if version != 1 or count > 128: raise ValueError('ELF version record')
            aux_address = address + aux; values = []
            for j in range(count):
                aux_offset = mapped(aux_address, 16); _, _, _, name, next_aux = struct.unpack_from('<IHHII', raw, aux_offset)
                values.append(string(name))
                if j < count - 1 and next_aux == 0: raise ValueError('ELF version chain incomplete')
                aux_address += next_aux
            versions.append({'library': string(filename), 'versions': values})
            if i < tags[0x6fffffff][0] - 1 and following == 0: raise ValueError('ELF needs chain incomplete')
            address += following
    return {'elfClass': 'ELF64_LE', 'machine': 'x86_64', 'type': kind, 'interpreter': interpreter,
            'needed': needed, 'soname': soname, 'versionNeeds': versions,
            'versionDefinitions': sorted(set(definitions)), 'runPaths': runpaths, 'executed': False}


def inspect_data(raw):
    files = {}; links = {}; excluded_docs = []; count = 0
    with tarfile.open(fileobj=io.BytesIO(raw), mode='r:') as archive:
        for member in archive:
            count += 1
            if count > 256 or len(member.name) > 512: raise ValueError('helper tar member bound')
            name = member.name.removeprefix('./'); path = pathlib.PurePosixPath(name)
            if name in ['', '.'] and member.isdir(): continue
            if not name or path.is_absolute() or '..' in path.parts or '\\' in name or ':' in name or name in files or name in links: raise ValueError('helper tar path/type duplicate')
            if member.isdir():
                if member.size: raise ValueError('helper directory payload')
                continue
            if member.issym():
                if name == 'usr/share/doc/fuse2fs/changelog.Debian.gz' and member.linkname == '../libcom-err2/changelog.Debian.gz':
                    excluded_docs.append({'path': name, 'target': member.linkname, 'reason': 'Cross-package documentation reference never materialized in isolated runtime'}); continue
                target = pathlib.PurePosixPath(member.linkname)
                if target.is_absolute() or len(target.parts) != 1 or target.name in ['', '.', '..']:
                    raise ValueError('only same-directory package library links allowed')
                links[name] = member.linkname; continue
            if not member.isfile() or member.size > 2 * 1024**2 or member.mode & 0o6000: raise ValueError('helper tar unsafe file/mode')
            content = archive.extractfile(member).read(member.size + 1)
            if len(content) != member.size: raise ValueError('helper payload length')
            value = {'bytes': len(content), 'sha256': hashlib.sha256(content).hexdigest(), 'mode': oct(member.mode & 0o777)}
            if content.startswith(b'\x7fELF'): value['elf'] = elf_metadata(content)
            files[name] = value
    for name, target in links.items():
        resolved = str(pathlib.PurePosixPath(name).parent / target)
        if resolved not in files: raise ValueError('package link target absent')
    return {'files': files, 'sameDirectoryLinks': links, 'excludedCrossPackageDocumentationLinks': excluded_docs, 'controlScriptsParsedOrExecuted': False,
            'materialized': False, 'packageCodeExecuted': False, 'runtimeQualified': False}


def main():
    parser = argparse.ArgumentParser(description=__doc__); parser.add_argument('--inspect-packages', type=pathlib.Path)
    args = parser.parse_args()
    if args.inspect_packages is None:
        print(json.dumps({'preparedOnly': True, 'packagesParsed': False, 'packageCodeExecuted': False})); return
    root = args.inspect_packages
    if not root.is_absolute() or root.is_symlink() or not root.is_dir(): raise ValueError('owned regular package root required')
    reports = []
    for package in helper().capsule()['packages']:
        path = root / package['filename']
        if path.is_symlink() or not path.is_file() or path.stat().st_size > 512 * 1024: raise ValueError('bounded package source required')
        data = decompress(ar_data(path.read_bytes(), package))
        reports.append({'name': package['name'], 'version': package['version'], 'packageSha256': package['sha256'], **inspect_data(data)})
    print(json.dumps({'schema': 'universe-electrs-isolated-helper-data-inspection-v1', 'packages': reports,
                      'decoder': NODE, 'extracted': False, 'helperExecuted': False, 'hostInstalled': False,
                      'mounted': False, 'nativeActions': False, 'runtimeQualified': False}))


if __name__ == '__main__': main()
