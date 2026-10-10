# Isolated helper data and actual host ABI prerequisite

All three acquired official packages were independently rehashed against the
capsule, total345,514bytes. Acquisition receipt SHA256 is
`62ad19b22ae2d5e72ac56083144a0c7e2bd1d3fc361e5b74a29ac1a748ecf2e5`.
They contain exact Debian2.0 ar members and Zstd data/control members. The local
inspection uses only existing Windows Node24.19.0, SHA256
`3602f2bb1a10f2cbab4c36886218a33c1ab3db87290e73b033c46c77147d0237`,
with its built-in8MiB-bounded Zstd decoder and a5-second timeout. No decoder
installation or package/control/helper execution occurred. Control members
are never decompressed or interpreted.

The pure parser bounds Debian member lengths, tar paths/file modes/link types,
ELF64/x86_64 segments, dependency string tables and version chains. Same-directory
library links must resolve to a present package file. One publisher-provided
documentation link crosses to libcom-err2's changelog; it is explicitly retained
as excluded provenance and will never be materialized. No runtime library link
or dependency is silently dropped. Local inspection receipt
`electrs-actual-helper-data-inspection-20261010T054840Z.json` is preserved; it
reports no extraction, execution, runtime qualification or mount. Later parser
version-definition support is separately source-tested rather than retroactively
included in that earlier receipt.

Actual helper ELF needs are libext2fs.so.2,libcom_err.so.2,libfuse.so.2,
libblkid.so.1,libuuid.so.1,libc.so.6, with the standard x86_64 loader. Both matched
private ext2fs and FUSE2 require GLIBC_2.38. FUSE versions2.5/2.6/2.8,BLKID_1.0,
UUID_1.0 and all transitive version needs must match, not simply SONAME presence.
The acquired paired ext2fs package also includes libe2p.so.2; that can support
the existing pinned mke2fs after its actual ELF closure is observed.

`helper-runtime-metadata.py` prepares only fixed, bounded actual host libc,
libcom_err,libblkid,libuuid and loader leaf/path/hash/ELF/version-definition
observations, plus the already observed readelf and mke2fs pins. It imports the
pure parser and executes neither ELF, loader, readelf nor mke2fs. Existing exact
owned-runner/source/Python guards and source end fence apply. Default mode reads
nothing. Metadata alone does not prove isolated package/host closure; runtime
execution remains withheld until copied/selected libraries and their complete
transitive versions/path/hash set are independently bound. No default-library
fallback, host installation, Cargo dependency change or native service action
is introduced.

Next reviewed steps are actual owned read-only host ABI observation; bounded
data-only extraction into a new private helper namespace preserving only safe
library aliases; verified private runtime closure; then one separately reviewed
8MiB regular-image creation/mount/ENOSPC/readback/cleanup proof. Existing mount
setup requires the existing setuid helper capability and cannot be assumed to
work after Cargo's NoNewPrivileges/all-network confinement has started. The
FUSE daemon, descriptor/resource boundaries and cleanup must be independently
owned and qualified. No such Linux helper execution or mount has occurred.
