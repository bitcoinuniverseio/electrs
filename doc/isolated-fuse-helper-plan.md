# Existing-format helper route — package acquisition review pending

Actuala770 metadata observed `/dev/fuse` accessible and setuid fusermount3, with
`/usr/bin/fusermount` resolving to that same existing helper. Existing fuse2fs
and libfuse2 were absent; libfuse3 alone was present. This does not qualify
mounting and does not prove every privileged path is unavailable.

The smaller concrete route is three isolated official Ubuntu packages, without
host installation: fuse2fs and its exact matched libext2fs2t64
`1.47.0-2.4~exp1ubuntu4.1`, plus libfuse2t64 `2.9.9-8.1build1`. Their345,514
aggregate bytes and SHA256 checksums come from Canonical's public HTTPS pages:
[fuse2fs](https://packages.ubuntu.com/noble-updates/amd64/fuse2fs/download),
[matched ext2fs](https://packages.ubuntu.com/noble-updates/amd64/libext2fs2t64/download)
and [FUSE2](https://packages.ubuntu.com/noble/amd64/libfuse2t64/download).
The JSON capsule records this trust; no independently verified signed APT
release chain is claimed. No package or source version is changed on the host,
and Rust/Cargo/lock/features are untouched.

`acquire-fuse-helper.py` is default-unexecuted and supports only those three
literal checksum/size-pinned HTTPS archive URLs, no redirects/auth/proxies,
three sequential requests,1MiB total network bytes,45s logical/60s own-child
watchdog, immutable private files and partial/error preservation. It reuses the
reviewed source guard and downloader, specializes its policy only in its
isolated module instance, and creates only a previously absent owned audit/temp
namespace. It extracts nothing, runs no package/control/maintainer script,
changes no package database/trust/security, and executes no helper/native API.

After independent acquisition review, remaining exact gates are bounded .deb
data-only extraction and path/link/type manifest qualification, ELF/loader
closure and existing libc>=2.38, libblkid/libcom_err/libuuid ABI checks, actual
legacy-FUSE2 interaction with the existing fusermount3, and one separately
reviewed8MiB image proof. A future proof would use only a new fixed regular image,
existing pinned mke2fs and private helper/library paths, private mountpoint,
explicit no-allow_other behavior, actual own mount ID/PID checks and bounded
write-to-ENOSPC/readback/cleanup. No block device, rootfs, native database or host
quota/security settings would be targeted.

The FUSE daemon must retain the exclusively owned fixed image/mount lifetime;
an ENOSPC probe and actual image-size/statfs upper bound must prove aggregate
capacity, not periodic target-size measurement. Existing setuid mounting setup
must be reviewed separately from the final Cargo NoNewPrivileges confinement;
it cannot be assumed to work within that already-restricted scope. Full8GiB
resource limits, FUSE daemon resource/descriptor cleanup and read-only
compiler/library closure still need review and actual proof. Neither package
acquisition nor a successful small mount alone admits full Rust compilation.
