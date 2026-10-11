#!/usr/bin/env python3
"""Bounded local evidence restoration. Writes only a new auxiliary task store."""
import argparse
import contextlib
import hashlib
import json
import os
import pathlib
import sqlite3
import struct
import tempfile
import time

MAX_BODY = 4_000_000
MAX_BYTES = 8 * 1024 * 1024
MAX_VISITS = 500
MAX_WORK = 1_000_000
GENESIS = '00000008819873e925422c1ff0f99f7cc9bbb232af63a077a480a3633bee1ef6'


class InvalidProof(Exception):
    pass


class Window:
    def __init__(self):
        self.deadline = time.monotonic() + 10
        self.work = 0

    def charge(self, count=1):
        self.work += count
        if self.work > MAX_WORK or time.monotonic() > self.deadline:
            raise InvalidProof('Operation window exhausted; progress remains unqualified')


def double_hash(raw):
    return hashlib.sha256(hashlib.sha256(raw).digest()).digest()


def compact(value):
    if value < 253:
        return bytes([value])
    if value <= 65535:
        return b'\xfd' + struct.pack('<H', value)
    if value <= 4294967295:
        return b'\xfe' + struct.pack('<I', value)
    return b'\xff' + struct.pack('<Q', value)


class Reader:
    def __init__(self, body, budget):
        self.body = body
        self.offset = 0
        self.budget = budget

    def take(self, count):
        self.budget.charge()
        if count < 0 or self.offset + count > len(self.body):
            raise InvalidProof('Incomplete consensus body')
        result = self.body[self.offset:self.offset + count]
        self.offset += count
        return result

    def count(self):
        tag = self.take(1)[0]
        if tag < 253:
            return tag
        width = {253: 2, 254: 4, 255: 8}[tag]
        result = int.from_bytes(self.take(width), 'little')
        if result < {253: 253, 254: 65536, 255: 4294967296}[tag]:
            raise InvalidProof('Noncanonical compact size')
        return result

    def transaction(self):
        start = self.offset
        version = self.take(4)
        inputs = self.count()
        witness = False
        if inputs == 0:
            if self.take(1) != b'\x01':
                raise InvalidProof('Unsupported witness flags')
            witness = True
            inputs = self.count()
        if inputs < 1 or inputs > MAX_WORK:
            raise InvalidProof('Invalid input count')
        input_start = self.offset
        coinbase = False
        for index in range(inputs):
            self.budget.charge()
            previous = self.take(32)
            outpoint = self.take(4)
            is_null = previous == bytes(32) and outpoint == b'\xff' * 4
            if is_null:
                if inputs != 1 or index != 0:
                    raise InvalidProof('Invalid coinbase input')
                coinbase = True
            self.take(self.count())
            self.take(4)
        input_body = self.body[input_start:self.offset]
        outputs = self.count()
        if outputs < 1 or outputs > MAX_WORK:
            raise InvalidProof('Invalid output count')
        output_start = self.offset
        scripts = []
        total = 0
        for _ in range(outputs):
            self.budget.charge()
            value = int.from_bytes(self.take(8), 'little')
            total += value
            if value > 2_100_000_000_000_000 or total > 2_100_000_000_000_000:
                raise InvalidProof('Invalid output amount')
            scripts.append(self.take(self.count()))
        output_body = self.body[output_start:self.offset]
        stacks = []
        if witness:
            for _ in range(inputs):
                items = self.count()
                if items > MAX_WORK:
                    raise InvalidProof('Invalid witness count')
                stack = []
                for _ in range(items):
                    self.budget.charge()
                    stack.append(self.take(self.count()))
                stacks.append(stack)
            if not any(stacks):
                raise InvalidProof('Superfluous witness encoding')
        locktime = self.take(4)
        raw = self.body[start:self.offset]
        base = version + compact(inputs) + input_body + compact(outputs) + output_body + locktime
        return {'raw': raw, 'txid': double_hash(base), 'wtxid': double_hash(raw),
                'weight': len(base) * 3 + len(raw), 'coinbase': coinbase,
                'scripts': scripts, 'witness': stacks}


def merkle(values):
    if not values:
        raise InvalidProof('Empty Merkle tree')
    level = list(values)
    while len(level) > 1:
        if any(level[i] == level[i + 1] for i in range(0, len(level) - 1, 2)):
            raise InvalidProof('Mutated Merkle tree')
        if len(level) % 2:
            level.append(level[-1])
        level = [double_hash(level[i] + level[i + 1]) for i in range(0, len(level), 2)]
    return level[0]


def block_rows(body, expected_hash, budget):
    if len(body) < 81 or len(body) > MAX_BODY:
        raise InvalidProof('Invalid block byte bound')
    reader = Reader(body, budget)
    header = reader.take(80)
    block_hash = double_hash(header)
    if block_hash != expected_hash:
        raise InvalidProof('Block header identity changed')
    count = reader.count()
    if count < 1 or count > MAX_WORK:
        raise InvalidProof('Invalid transaction count')
    transactions = []
    ids = set()
    weight = (80 + len(compact(count))) * 4
    for index in range(count):
        budget.charge()
        tx = reader.transaction()
        if tx['coinbase'] != (index == 0) or tx['txid'] in ids:
            raise InvalidProof('Coinbase placement or transaction duplication failed')
        ids.add(tx['txid'])
        transactions.append(tx)
        weight += tx['weight']
    if reader.offset != len(body) or weight > 4_000_000:
        raise InvalidProof('Block EOF or weight failed')
    txids = [tx['txid'] for tx in transactions]
    if merkle(txids) != header[36:68]:
        raise InvalidProof('Block Merkle root failed')
    commitments = [s[6:38] for s in transactions[0]['scripts'] if len(s) >= 38 and s[:6] == bytes.fromhex('6a24aa21a9ed')]
    if commitments or any(tx['witness'] for tx in transactions):
        witness = transactions[0]['witness']
        if not commitments or len(witness) != 1 or len(witness[0]) != 1 or len(witness[0][0]) != 32:
            raise InvalidProof('Coinbase witness commitment is missing')
        root = merkle([bytes(32)] + [tx['wtxid'] for tx in transactions[1:]])
        if double_hash(root + witness[0][0]) != commitments[-1]:
            raise InvalidProof('Witness commitment failed')
    rows = [(b'T' + tx['txid'], tx['raw']) for tx in transactions]
    rows.append((b'X' + block_hash, struct.pack('<Q', count) + b''.join(txids)))
    rows.append((b'M' + block_hash, struct.pack('<III', count, len(body), weight)))
    return rows


def xor_bytes(raw, key, offset):
    return bytes(value ^ key[(offset + index) % 8] for index, value in enumerate(raw))


def regular(path):
    if path.is_symlink() or not path.is_file() or path.resolve() != path:
        raise InvalidProof('Source must be an explicit regular real path')
    return path.stat()


def source_file(profile, entry):
    path = pathlib.Path(profile['blocksDirectory']) / entry['name']
    if not entry['name'].startswith('blk') or len(entry['name']) != 12 or not entry['name'][3:8].isdigit() or entry['name'][8:] != '.dat':
        raise InvalidProof('Invalid block source filename')
    current = regular(path)
    if current.st_dev != entry['device'] or current.st_ino != entry['inode'] or current.st_uid != entry['uid']:
        raise InvalidProof('Block source owner or inode changed')
    if current.st_size < entry['bytes'] or (not entry['appendable'] and (current.st_size != entry['bytes'] or current.st_mtime_ns != entry['mtimeNs'])):
        raise InvalidProof('Block source prefix changed')
    return path


def atomic_bytes(path, raw):
    if path.exists():
        if regular(path).st_size != len(raw) or path.read_bytes() != raw:
            raise InvalidProof('Conflicting auxiliary output preserved')
        return
    fd, name = tempfile.mkstemp(prefix=path.name + '.', dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as out:
            out.write(raw)
            out.flush()
            os.fsync(out.fileno())
        os.link(name, path)
        os.unlink(name)
        if os.name != 'nt':
            directory = os.open(path.parent, os.O_RDONLY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
    except BaseException:
        # An incomplete task output is retained, never confused with a sealed chunk.
        raise


def emit_chunks(root, profile_digest, rows, index, rolling):
    pending = []
    size = 0
    count = 0
    for key, value in rows:
        record = key + struct.pack('<I', len(value)) + value
        if pending and (len(pending) == MAX_VISITS or size + len(record) > MAX_BYTES):
            payload = b''.join(pending)
            digest = hashlib.sha256(payload).digest()
            packet = b'UPRFROW1' + profile_digest + struct.pack('<QII', index, len(pending), len(payload)) + digest + payload
            atomic_bytes(root / 'chunks' / f'{index:08}.row', packet)
            rolling = hashlib.sha256(rolling + struct.pack('<Q', index) + digest).digest()
            count += len(pending)
            index += 1
            pending = []
            size = 0
        if len(key) != 33 or key[:1] not in (b'T', b'X', b'M') or len(value) > MAX_BODY:
            raise InvalidProof('Invalid auxiliary row shape')
        pending.append(record)
        size += len(record)
    if pending:
        payload = b''.join(pending)
        digest = hashlib.sha256(payload).digest()
        packet = b'UPRFROW1' + profile_digest + struct.pack('<QII', index, len(pending), len(payload)) + digest + payload
        atomic_bytes(root / 'chunks' / f'{index:08}.row', packet)
        rolling = hashlib.sha256(rolling + struct.pack('<Q', index) + digest).digest()
        count += len(pending)
        index += 1
    return index, rolling, count


@contextlib.contextmanager
def exclusive_task(root):
    path = root / 'restoration.lock'
    if path.exists():
        regular(path)
    descriptor = os.open(path, os.O_RDWR | os.O_CREAT | getattr(os, 'O_NOFOLLOW', 0), 0o600)
    try:
        if os.name == 'nt':
            import msvcrt
            if os.fstat(descriptor).st_size == 0:
                os.write(descriptor, b'0')
            os.lseek(descriptor, 0, os.SEEK_SET)
            msvcrt.locking(descriptor, msvcrt.LK_NBLCK, 1)
        else:
            import fcntl
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        yield
    finally:
        os.close(descriptor)


def advance(root):
    with exclusive_task(root):
        return advance_owned(root)


def advance_owned(root):
    manifest = root / 'proof-job.json'
    if regular(manifest).st_size > 65536:
        raise InvalidProof('Proof profile exceeds bound')
    raw = manifest.read_bytes()
    profile = json.loads(raw)
    if profile.get('schemaVersion') != 'universe-local-history-proof-job-v1' or profile.get('network') != 'signet' or profile.get('genesis') != GENESIS or profile.get('rowSchema') != 'electrs-TXM-v2':
        raise InvalidProof('Proof profile identity is unavailable')
    challenge = bytes.fromhex(profile.get('signetChallenge', ''))
    if not 1 <= len(challenge) <= 10000 or challenge.hex() != profile['signetChallenge'] or hashlib.sha256(challenge).hexdigest() != profile.get('signetChallengeSha256'):
        raise InvalidProof('Exact Signet challenge is unavailable')
    if profile.get('pruned') is not False or profile.get('initialBlockDownload') is not False or not isinstance(profile.get('targetHeight'), int) or profile['targetHeight'] < 0 or profile.get('coreHeaders') != profile['targetHeight']:
        raise InvalidProof('Complete synchronized source observation is unavailable')
    files = profile['files']
    if not 1 <= len(files) <= 1024 or any(entry['name'] != f'blk{index:05}.dat' for index, entry in enumerate(files)):
        raise InvalidProof('Source file inventory is incomplete')
    key_path = pathlib.Path(profile['blocksDirectory']) / 'xor.dat'
    if regular(key_path).st_size != 8:
        raise InvalidProof('Invalid XOR source')
    xor_key = key_path.read_bytes()
    if hashlib.sha256(xor_key).hexdigest() != profile['xorSha256']:
        raise InvalidProof('XOR source changed')
    profile_digest = hashlib.sha256(raw).digest()
    (root / 'chunks').mkdir(mode=0o700, exist_ok=True)
    if (root / 'chunks').resolve() != root / 'chunks':
        raise InvalidProof('Auxiliary chunk directory changed')
    locator_path = root / 'locator.sqlite'
    if locator_path.exists():
        regular(locator_path)
        with locator_path.open('rb') as source:
            header = source.read(100)
        if header and (len(header) != 100 or header[68:72] != b'PRF1'):
            raise InvalidProof('Refuse a non-auxiliary SQLite database before open')
    budget = Window()
    db = sqlite3.connect(locator_path)
    try:
        return advance_database(root, profile, profile_digest, files, xor_key, budget, db)
    finally:
        db.close()


def advance_database(root, profile, profile_digest, files, xor_key, budget, db):
    db.execute('PRAGMA application_id=1347569201')
    db.execute('PRAGMA synchronous=FULL')
    db.execute('PRAGMA journal_mode=WAL')
    db.executescript('CREATE TABLE IF NOT EXISTS locator(hash BLOB PRIMARY KEY, previous BLOB NOT NULL, file INTEGER NOT NULL, offset INTEGER NOT NULL, bytes INTEGER NOT NULL) WITHOUT ROWID; CREATE TABLE IF NOT EXISTS canonical(height INTEGER PRIMARY KEY, hash BLOB NOT NULL UNIQUE); CREATE TABLE IF NOT EXISTS progress(singleton INTEGER PRIMARY KEY CHECK(singleton=1), profile TEXT NOT NULL, state TEXT NOT NULL);')
    stored = db.execute('SELECT profile,state FROM progress WHERE singleton=1').fetchone()
    if stored is None:
        state = {'phase': 'scan', 'file': 0, 'offset': 0, 'height': profile['targetHeight'], 'hash': profile['targetHash'], 'bodyHeight': 0, 'bodyPrevious': bytes(32).hex(), 'chunks': 0, 'rows': 0, 'rolling': bytes(32).hex()}
    else:
        if stored[0] != profile_digest.hex():
            raise InvalidProof('Restoration progress profile changed')
        state = json.loads(stored[1])
    visits = 0
    read_bytes = 0
    rows = []
    try:
        while visits < MAX_VISITS and budget.work < MAX_WORK and time.monotonic() < budget.deadline:
            budget.charge()
            if state['phase'] == 'scan':
                if state['file'] == len(files):
                    state['phase'] = 'ancestry'
                    continue
                entry = files[state['file']]
                path = source_file(profile, entry)
                offset = state['offset']
                remaining = entry['bytes'] - offset
                if remaining < 8:
                    if remaining:
                        with path.open('rb') as source:
                            source.seek(offset)
                            tail = xor_bytes(source.read(remaining), xor_key, offset)
                        if any(tail) and not entry['appendable']:
                            raise InvalidProof('Incomplete immutable source framing')
                    state['file'] += 1
                    state['offset'] = 0
                    continue
                with path.open('rb') as source:
                    source.seek(offset)
                    frame = xor_bytes(source.read(8), xor_key, offset)
                    read_bytes += 8
                    if frame == bytes(8):
                        amount = min(remaining - 8, MAX_BYTES - read_bytes)
                        padding = xor_bytes(source.read(amount), xor_key, offset + 8)
                        if any(padding):
                            raise InvalidProof('Invalid source padding')
                        read_bytes += amount
                        state['offset'] += 8 + amount
                        if read_bytes >= MAX_BYTES:
                            break
                        continue
                    if frame[:4] != struct.pack('<I', profile['magic']):
                        raise InvalidProof('Block framing network magic failed')
                    size = struct.unpack('<I', frame[4:])[0]
                    if not 81 <= size <= MAX_BODY:
                        raise InvalidProof('Block framing size failed')
                    if size + 8 > remaining:
                        if not entry['appendable']:
                            raise InvalidProof('Incomplete immutable block record')
                        state['file'] += 1
                        state['offset'] = 0
                        continue
                    header = xor_bytes(source.read(80), xor_key, offset + 8)
                    if len(header) != 80:
                        raise InvalidProof('Source header changed or became incomplete')
                    read_bytes += 80
                block_hash = double_hash(header)
                previous = db.execute('SELECT previous FROM locator WHERE hash=?', (block_hash,)).fetchone()
                if previous and previous[0] != header[4:36]:
                    raise InvalidProof('Conflicting source header')
                db.execute('INSERT OR IGNORE INTO locator VALUES(?,?,?,?,?)', (block_hash, header[4:36], state['file'], offset + 8, size))
                state['offset'] += size + 8
                visits += 1
            elif state['phase'] == 'ancestry':
                block_hash = bytes.fromhex(state['hash'])[::-1]
                record = db.execute('SELECT previous FROM locator WHERE hash=?', (block_hash,)).fetchone()
                if record is None:
                    raise InvalidProof('Canonical source block is missing')
                db.execute('INSERT OR IGNORE INTO canonical VALUES(?,?)', (state['height'], block_hash))
                if db.execute('SELECT hash FROM canonical WHERE height=?', (state['height'],)).fetchone()[0] != block_hash:
                    raise InvalidProof('Canonical ancestry progress changed')
                if state['height'] == 0:
                    if state['hash'] != GENESIS or record[0] != bytes(32):
                        raise InvalidProof('Canonical genesis ancestry failed')
                    state['phase'] = 'bodies'
                else:
                    state['height'] -= 1
                    state['hash'] = record[0][::-1].hex()
                visits += 1
            elif state['phase'] == 'bodies':
                if state['bodyHeight'] > profile['targetHeight']:
                    state['phase'] = 'rows-complete'
                    break
                record = db.execute('SELECT c.hash,l.file,l.offset,l.bytes FROM canonical c JOIN locator l ON l.hash=c.hash WHERE c.height=?', (state['bodyHeight'],)).fetchone()
                if record is None:
                    raise InvalidProof('Canonical body locator is missing')
                if read_bytes + record[3] > MAX_BYTES:
                    break
                path = source_file(profile, files[record[1]])
                with path.open('rb') as source:
                    source.seek(record[2])
                    body = xor_bytes(source.read(record[3]), xor_key, record[2])
                if body[4:36].hex() != state['bodyPrevious']:
                    raise InvalidProof('Canonical body linkage changed')
                rows.extend(block_rows(body, record[0], budget))
                state['bodyPrevious'] = record[0].hex()
                read_bytes += record[3]
                state['bodyHeight'] += 1
                visits += 1
            elif state['phase'] == 'rows-complete':
                break
            else:
                raise InvalidProof('Unknown restoration phase')
        if rows:
            index, rolling, count = emit_chunks(root, profile_digest, rows, state['chunks'], bytes.fromhex(state['rolling']))
            state['chunks'] = index
            state['rolling'] = rolling.hex()
            state['rows'] += count
        db.execute('INSERT INTO progress VALUES(1,?,?) ON CONFLICT(singleton) DO UPDATE SET state=excluded.state', (profile_digest.hex(), json.dumps(state, separators=(',', ':'))))
        db.commit()
        if state['phase'] == 'rows-complete':
            for entry in files:
                source_file(profile, entry)
            if state['bodyPrevious'] != bytes.fromhex(profile['targetHash'])[::-1].hex():
                raise InvalidProof('Final canonical body anchor changed')
            completion = {'profileSha256': profile_digest.hex(), **state}
            atomic_bytes(root / 'generation-complete.json', json.dumps(completion, sort_keys=True).encode())
        return {'profileSha256': profile_digest.hex(), **state, 'visits': visits, 'bytesRead': read_bytes, 'work': budget.work, 'ready': False}
    except BaseException:
        db.rollback()
        raise


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('proof_directory', type=pathlib.Path)
    args = parser.parse_args()
    root = args.proof_directory
    if not root.is_absolute() or root.resolve() != root or not root.is_dir():
        raise InvalidProof('Proof directory must be an explicit real absolute path')
    print(json.dumps(advance(root)))


if __name__ == '__main__':
    main()
