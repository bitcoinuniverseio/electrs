# Exact-lock dependency acquisition kit — unexecuted

`scripts/universe/acquire-locked-sources.py` defaults to preparation only. No
workflow or default build trigger is added. Root must review before running
its explicit `--acquire --source-sha FULL_COMMIT --inventory ORIGINAL_RECEIPT
--destination NEW_ABSOLUTE_DIRECTORY` operation.

The input is the exact saved actual087c inventory (run38024510195,
job114132367991), SHA256
`fef851f7a12c67f3d0807f669c03d853f9d2c91aa459a61edc0e2ef40f0a5c27`,
plus the original Git-blob Cargo.lock SHA256
`d70b0284f71409a27beb6e9f50b3e137c36463fc82aa987c225c8f4ced32a676`.
It selects exactly195 missing registry archives and the one d379 Git source.
The eight previously qualified cache references are carried separately and
are neither copied nor redownloaded. Thus acquisition success still does
**not** mean all204 sources have been materialized into a vendor directory.

Only a previously absent child named
`electrs-locked-acquisition-YYYYMMDDTHHMMSSZ-16hex` is admitted beneath the
existing Windows implementation audit directory or the known owned Linux
runner `_work/_temp`. Ancestor symlinks/junctions, existing destinations,
shared Cargo/source/native paths and insufficient1GiB temporary storage fail
before child admission. Source HEAD must match an explicit full SHA and be
clean; original lock bytes are obtained by bounded read-only Git plumbing.
Known direct Linux/Windows Git paths and observed hashes are used without
configuration changes or executable fallback.

Network downloads use HTTPS only, no credentials/proxies/netrc/cookies,
no retries and no redirects. Registry URLs are exact generated
`static.crates.io/crates/NAME/NAME-VERSION.crate` locations. Git source uses
only the public Blockstream rust-electrum-client commit/tree Git API and
the codeload archive for
`d3792352992a539afffbe11501d1aff9fd5b919d`. Unexpected TLS trust/keylogging
environment fails before admission; the worker receives a clean environment.
No Git remote fetch, Cargo, installer, dependency script, compilation or native
API request is run.

Bounds are two workers,195 registry requests plus three Git requests,
32MiB per archive,256MiB total network bytes,256MiB decoded registry stream
per archive and1GiB total decoded streams. Actual decoded gzip content is
bounded before tar parsing; tar members/path/types and RocksDB AUTHORS/Snappy
contents must pass the existing exact-lock parser. SHA256 matches the original
Cargo.lock **before** decoding or parsing registry archives. Downloads use
exclusive `.part` files and atomic no-replace publication; failures preserve
parts, stop new scheduling and never retry automatically. Per-archive qualified
receipts are retained as each worker succeeds.

The worker has a600-second logical observation budget and ten-second network
socket timeouts. The parent owns a separately spawned, source/hash-bound Python
child with a660-second outer watchdog; that bounds resolver/parser stalls too.
On timeout it kills only its stored child handle, preserves the new namespace,
and records an explicit failure. No indexer/native/service PID is targeted.
The child launches no subprocesses. It receives only LANG and the necessary
Windows SystemRoot rather than inheriting runner credentials/settings.

The Git archive is hashed before parsing, every blob SHA1 and executable mode
is checked against the complete nontruncated API tree, and every subtree/root
Git object hash is independently reconstructed. Unexpected links/submodules,
extra/missing blobs, ambiguous paths, oversized files or wrongcommit fail.
The commit-to-tree association is the primary public GitHub HTTPS response;
the raw commit object is **not** reconstructed or asserted to have a Cargo.lock
SHA256. That trust boundary is carried in its qualified tree receipt. Relevant
primary API contracts: [Git commits](https://docs.github.com/en/rest/git/commits)
and [Git trees](https://docs.github.com/en/rest/git/trees).

Remaining steps are independently binding/copying the eight historical cache
archives, exact source-preserving vendor materialization with checksum metadata,
full tool/read-root closure, expanded confinement compilation/compatibility,
larger cgroup/resource and hard8GiB target storage enforcement, and full Linux
adapter/REST/existing-store/reorg qualification. This kit changes no lock,
features, source implementation, shared cache, trust configuration or live
producer. No download has been executed by the preparing agent.
