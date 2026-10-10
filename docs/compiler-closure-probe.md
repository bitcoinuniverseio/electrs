# Read-only compiler closure probe

The next reviewed metadata payload can run `python3 -B -I -S
scripts/universe/compiler-closure-metadata.py --observe-owned-compiler`.
This command reads source identity, RAM/disk/PSI and exact existing compiler
leaves. It creates no unit, mount or process other than its own Python process;
it invokes no compiler, Cargo, installer or network operation.

CPU PSI maxima must remain at most 25%, IO maxima at most 5%, with at least
1 GiB available RAM and temporary disk. Rejected admission retains the actual
pressure readings and withholds compiler tree hashing. Exceptions emit only
their type and completed safe metadata, never raw error/environment text.

Hashing is bounded to 2 GiB, 50,000 files, 100,000 entries and 90 seconds;
ELF inspection separately accounts at most 1 GiB and 128 leaves. Resolved
paths are restricted to exact compiler/tool pins and known library/header
roots. Stable regular-file descriptor identity and fresh hashes fence changes.
Unresolved links, run paths or dependency providers stay unqualified.

The previous pressure-rejected small proof is preserved. This probe cannot
qualify FUSE, the larger resource scope, hard storage enforcement, or full Rust
compilation. The frozen old 204-package vendor remains bound to its old lock;
a merged lock requires a new reviewed closure, never a checksum substitution.
