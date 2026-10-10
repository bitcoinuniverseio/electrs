# Aggregate target-storage prerequisite — metadata only

The narrowly owned preflight now prepares one explicit storage metadata
observation on `universe-runners-1`. It does not repeat the completed cache
inventory or tiny confinement proof, fetch, run Cargo, create a unit, open a
device, mount a filesystem, change quota/security/privilege, or access native
services/DBs. Default script invocation does no metadata read. The existing
repository/branch/full-source/UID1001/direct-Python guards and source end fence
remain required. Existing workflow checkout pin, runner, read-only permissions
and5-minute timeout are retained.

The observation reads only bounded `/proc/self/mountinfo`, `/proc/self/status`,
memory/pressure/temp-space metrics, exact `/dev/fuse` device type/access metadata,
and fixed existing FUSE/mount/loop/format/quota/sudo tool paths and hashes. It
outputs only the mount covering the known owned temporary directory, filesystem
type and allowlisted quota/size flags; raw mount source and arbitrary options are
omitted. Effective self capability output is limited to SYS_ADMIN, SYS_RESOURCE
and DAC_OVERRIDE. Tool presence/setuid/executable metadata is availability, not
permission to exercise a privileged operation.

If existing sudo is executable, the only subprocess is `sudo -n -l`: a bounded
noninteractive policy listing, never a listed command. It uses a clean environment,
no input/password/authentication change, and a3-second timeout. Neither raw policy,
Defaults/environment values nor stderr is emitted. Only success and literal
unrestricted/NOPASSWD/storage-command mentions are summarized. Argument limits
remain unqualified; an unrecognized/absent mention does not prove denial. The
system may record its ordinary derived sudo audit entry; no policy/timestamp
files are written by this script and no privilege is granted.

`aggregate8GiBEnforcementQualified` is always false. Observed FUSE/helper access,
quota flags or existing sudo policy could justify a separately reviewed bounded
private filesystem proof. A quota-backed mount would require actual capacity,
ownership, target-path and cleanup proof; no mount or disk image is made here.
An existing shared tmpfs8GiB size alone does not reserve or enforce an8GiB ceiling
for this owned target. Per-file RLIMIT_FSIZE, memory cgroups and periodic directory
measurement do not independently enforce aggregate target storage. No conclusion
about current facilities is made before actual owned CI observation.
