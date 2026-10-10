# Locked Linux build preparation (not build qualification)

The actual 8bec CI proof (run 38022672857, job 114126823667) qualified its static
tiny control under Landlock ABI4, network/io_uring denial and the observed
15-second/64MiB/16-task/CPU100 scope. Its source and binary hashes remain
historical evidence. The new Cargo wrapper includes that source unchanged, but
adds read roots, private artifact symlinks and direct tool execution. Those
changes have **not been compiled or exercised**. Tiny success does not approve
this larger policy or a Rust build.

## First next action: read-only inventory

The reviewed explicit entry point is
`/usr/bin/python3.12 -B -I -S scripts/universe/locked-cache-readonly.py --observe-owned-cache`.
Its default mode reads no cache. It permits only the known owned repository,
branch, UID1001, pinned Python and full clean dispatched source, and checks at
least1GiB available RAM/temp plus every CPU PSI average<=25% and IO PSI
average<=5% before cache access. It rechecks source after observation and emits
at most256KiB JSON including actual timestamps, exact204/203/1 counts and
separate missing-archive/checksum/vendor-AUTHORS/Git-tree gates. It creates no
directories/files, units or processes except bounded read-only Git plumbing.
The actual owned CI observation has not occurred yet; root must separately
review and activate one inventory-only workflow invocation.

`locked-source-inventory.py` defaults to preparation only. Its explicit
`--inspect-owned-cache` mode is restricted to the existing owned Linux UID1001,
exact clean dispatched Git SHA and original LF Cargo.lock SHA
`d70b0284f71409a27beb6e9f50b3e137c36463fc82aa987c225c8f4ced32a676`.
It reads only bounded registry archive/cache and the locked d379 Git checkout
paths; it does not read Cargo credentials/config, invoke Cargo, fetch, extract
or build. Archive checksums are checked against the lock before tar inspection,
with a second digest/stat fence. RocksDB's bundled AUTHORS and Snappy source
are mandatory, preventing its missing-vendor Git-update path from admission.
Git plumbing verifies exact commit/tree and clean checkout; presence does not
yet qualify a materialized Cargo vendor directory. Missing sources remain
blocked. Git package completeness deliberately stays false until that exact
tree has been materialized and independently bound.

Budgets: at most 512 packages, 32MiB per compressed archive, 256MiB aggregate
archive bytes, 256MiB declared unpacked payload per archive/1GiB aggregate,
30,000 entries per archive, bounded directory enumeration and a 60-second
between-package observation deadline. Archive digests require two full reads
in addition to tar streaming. These are logical/file bounds, not hard blocking
filesystem-I/O cancellation. Inventory itself still needs the reviewed owned
CI metadata step; this change adds no workflow invocation.

## Source-backed vendoring prerequisite

Cargo's [source replacement documentation](https://doc.rust-lang.org/cargo/reference/source-replacement.html)
requires replacement sources to preserve original source content. Its
[vendor documentation](https://doc.rust-lang.org/cargo/commands/cargo-vendor.html)
supports both registry and Git dependencies and emits their source replacement
configuration. A future separately reviewed offline/frozen vendoring operation
must use the exact available originals, checksum every registry archive before
safe extraction, bind every materialized file and exact Git tree, and preserve
the lock. `.cargo-checksum.json` alone is not an authenticity proof. No dependency
acquisition, extraction or Cargo operation is performed by this preparation.

## Larger builder boundary

`confined-build-plan.py` validates a bounded source plan and always reports
build admission false. It binds the known Rust1.89/Cargo/GCC/G++/clang/libclang
path/hash pins, full source SHA/lock, immutable source/vendor/wrapper/root
manifests and disjoint private work versus read-only source/vendor directories.
Read grants are individually scoped tool/library leaves or specifically named
toolchain/header trees, never the runner home, Cargo credential tree, native
DB/profile or whole /proc. Linker/loader/library closure pins have not yet been
observed; an arbitrary path/hash claim in a plan is not independent verification.

`confined-cargo.c` is an uncompiled draft executable boundary. It clears inherited
environment/descriptors, creates owned regular logs, applies Landlock and the
unchanged network/io_uring/ptrace/signal restrictions, and supports only fixed
`cargo test --offline --frozen --jobs 2` or its `--no-run` compile phase. It stamps
the full source SHA in GIT_HASH and ELECTRS_SOURCE_REVISION, uses direct binaries,
and allows no rustup/version fallback. A parent must construct and independently
verify the exact environment/root manifests and sealed source/vendor/tool bytes
before executing it. Existing Cargo/C++ compatibility with the strict syscall
policy remains unqualified, particularly ioctl/signalling and jobserver behavior.
The external unit owner must handle termination; denial cannot be weakened merely
to obtain a successful build.

Proposed larger limits remain jobs2, CPU200, 4GiB memory,128 tasks,30minutes and
8GiB target storage. No user-scope disk quota has been demonstrated: periodic
directory measurement is not an enforced 8GiB ceiling. Actual larger cgroup
limits, fresh RAM/storage/CPU/IO headroom, hard target-storage enforcement and
safe bounded own-child cleanup need independent proof before Cargo admission.
No controller, workflow, unit, full build or native activation is added here.
Default-feature compile/test success would not prove Liquid/discovery profiles,
existing-store/reorg completeness, REST lifecycle or live output parity.
