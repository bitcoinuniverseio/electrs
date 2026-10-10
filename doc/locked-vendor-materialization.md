# Locked vendor materialization — review pending

Actual software acquisition now holds all203 registry archives in two new
owned namespaces. The first195 successful acquisition receipt SHA256 is
`33fe1c8776a4f7d255e2088bfcfadd9c91a2e61c3f88eddea931b374b8de77ff`.
The independently downloaded remaining8 receipt SHA256 is
`d5cfa46f578b8358e330c857796f924f5fe367eef301a40f6eecc83074495642`.
The latter made exactly8 official requests,7,134,473 network bytes and
113,859,072 decoded bytes, with no errors, shared-cache writes, Git request,
Cargo invocation or native action. Original Linux cache references remain
historical metadata. The existing d379 Git proof SHA256 is
`b80fc213b0fb1960e7f0b43adc69252995161405aa81423928333415b3263839`;
its root tree is `c689b79a06a393c6e93d06d4fe9808f5eefb3393`.

`materialize-locked-vendor.py` defaults to no extraction. After independent
review, its explicit operation requires both exact original receipts, a clean
full source SHA and a NEW absent `electrs-locked-vendor-DATE-16hex` directory
beneath the reviewed audit/owned temporary root. It verifies every203 archive
against the original lock before extracting any file, pins the Git proof and
all three Git object/archive input digests, rechecks all Git blobs/subtrees and
package identity, then safely materializes all204 packages. It preserves source
bytes and does not run Cargo/vendor/build scripts, fetch, install, access the
shared Cargo cache, or use native services.

Path/link/hardlink/duplicate/case-alias/Windows-device/checksum-injection guards
fail closed. Source file work<=200,000 files/members, payload<=1GiB, file<=32MiB,
package members<=30,000 and300s logical deadline are enforced. An owned Python
child has a360-second external watchdog, clean environment, source-module/plan
binding and parent PID check. Only that child is killed on timeout; partial
files and bounded original stdout/stderr remain. Each archive is rehashed after
extraction. Every completed source file and generated checksum metadata is
independently reopened and verified; partial/error receipts never assert
complete204 sources.

Each package receives the standard `.cargo-checksum.json` file map. Registry
package checksums remain exact lock checksums; the Git package checksum is null
with its separately preserved commit/tree proof. The separate offline Cargo
home config replaces crates.io and the exact Git URL/rev with the new immutable
directory source, `[net] offline=true`, and contains no `[patch]`, feature or
lock changes. This follows Cargo's
[source replacement](https://doc.rust-lang.org/cargo/reference/source-replacement.html)
and [directory vendor](https://doc.rust-lang.org/cargo/commands/cargo-vendor.html)
contracts. Configuration parsing tests are not actual offline Cargo resolution.
The current absolute directory is rendered for its materialization location;
future Linux transfer requires a newly bound local path/config, not reuse of a
Windows path. The Git commit-to-tree association remains public HTTPS GitHub
metadata, not a reconstructed raw commit object.

No materialization has run yet. Full offline resolution and native
adapter/REST/build/existing-store/reorg/output parity remain unqualified.

## Hard target storage boundary remains separate

The successful64MiB tiny proof does not establish an aggregate8GiB filesystem
ceiling. RLIMIT_FSIZE is per-file, and periodic directory measurement permits
overshoot. CPU/memory/pids cgroup limits do not impose disk quotas. A user unit's
TemporaryFileSystem requires actual mount/namespace capability, which has not
been observed; the earlier namespace failure remains evidence. Docker's socket
was absent. No existing FUSE device/helper or administrator-prepared quota-backed
private filesystem has been observed. A future read-only owned-runner metadata
step can inspect only the build-temp filesystem type/allowlisted size options,
exact existing FUSE device/helper presence and effective self capabilities.
None of those observations alone qualify mounting, enforcement or full build
admission; no quota/settings/mount/install is performed here. This gap does not
discard independently verified dependency acquisition/materialization progress.
