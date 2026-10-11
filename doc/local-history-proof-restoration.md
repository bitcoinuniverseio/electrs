# Local historical evidence restoration

Existing light-mode databases omit historical T transaction bodies, X block
rosters and M metadata. A bounded read cannot treat that missing evidence as an
empty address. The original history, confirmation, output and coverage guards
remain authoritative.

An explicit auxiliary restoration can read the existing unpruned Core block
files without opening Core or canonical Electrs databases. Its private job
manifest records the actual synchronized Core observation, exact Signet challenge
and commitment, genesis, target header, network magic, XOR identity and bounded
regular-file descriptors. The task writes only its new locator database and row
chunks. It selects target-to-genesis ancestry independently of file order and
checks exact consensus EOF, transaction identity, coinbase placement, duplicate
and Merkle mutation, block weight and witness commitments before emitting T/X/M.

Run `scripts/universe/local-history-proof.py ABSOLUTE_TASK_DIRECTORY` for one
window. Each window admits at most500 block/ancestry visits, reads at most8MiB and
charges nested parsing against1,000,000 work units and a10-second cooperative
deadline. Actual source files remain untouched. Progress is independently tied
to the job digest, and overlapping task owners are rejected. An interrupted
window never publishes completion; exact existing chunks can be reused.

`history-proof-ingest TASK_DIRECTORY PROFILE_SHA256 CHUNK_NUMBER` ingests one
ordered, checksummed window with at most500 rows and8MiB. It verifies the exact
Bitcoin T transaction identity and X/M encoding, refuses canonical or unowned
storage before open, and commits rows plus progress in one synchronous batch.
Identical historical duplicate bodies are retained; a conflicting incarnation
fails closed rather than overwriting evidence. The original provider and primary
canonical records still determine valid occurrences.

After complete generation and sequential ingestion, use the same command with
`seal` instead of a chunk number. Sealing requires exact generator/importer count
and rolling-digest agreement, persists tables and WAL, closes the writer, and
records `readQualificationGranted:false`. A fresh Core target/ancestor readback,
immutable source fences, source/binary profile checks and the existing actual
baseline are required before activation. A seal alone never makes an address
ready. Preserve the old valid producer until those prerequisites are satisfied.

`--lightmode --retain-history-bodies` adds exact T/X/M for future blocks already
fetched by the existing sole writer, using the original write batch. The DB2/light
compatibility marker stays unchanged. The opt-in is part of the read profile; its
default preserves the previous profile bytes. Historical auxiliary evidence
supplies the past, and primary retained records supply future coverage. A sealed
read-only sidecar is never updated by a second follower or canonical producer.

`scripts/universe/check-local-proof-release.sh` runs the repository-required
checks, all-feature tests, default Bitcoin tests and both release builds using a
shared dependency cache. Python fixture results and a staged binary do not prove
native restoration, history completeness or full application acceptance.
