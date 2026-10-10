# Root-selected Linux transfer mechanism — unexecuted

The reviewed local software capsule is
`electrs-private-helper-package-data-aadc52.tar.gz`, SHA256
`213d548c40f31d3b15c94f3468420a8cf6de4849bc6c3ecafe29f15e79bb224c`.
It has exactly22 regular payload files/aliases plus the exact sealed manifest
SHA256`ac5942baa44753d0e60a7193f8561d5c9489bdd101a7718902339e2cd85c46e8`
and original materialization receipt
SHA256`023dd8fb53cfa30eb4d15e57b412930183c8d093f37c0c4eb15d5eb1c2db02e7`.
No host library, installed helper, native profile or credential is carried.

Root can carry these fixed reviewed bytes and the two exact ABI/data metadata
receipts through the existing owned GitHub qualification branch/CI artifact
channel. A source-controlled qualification asset is also viable: the capsule
contains public Canonical package software, copyright files and provenance,
not operator runtime configuration. Root must explicitly choose/approve that
asset publication; this preparation performs no upload or repository asset
mutation. No new HTTP server, credential, SSH account or runner infrastructure
is needed. An alternate transfer is not a reason to weaken byte/path guards.

The owned job must first have the locally received archive under RUNNER_TEMP
and independently check its exact digest. `receive-helper-transfer.py` defaults
to no action; its reviewed `--receive-local --archive LOCAL --destination NEW`
operation admits only a new
`RUNNER_TEMP/universe-electrs-helper-data-RUN-ATTEMPT-16hex` directory owned by
UID1001. It checks the full capsule digest before tar parsing, regular types,
exact24-member/manifest path set, all bytes/modes and4MiB decoded aggregate
bound before the first write, then independently reopens every file. It creates
no links and executes no package code/helper/device/mount. The source capsule
stays unchanged and the new extracted root is the only write target.

The small controller separately checks explicit reviewed metadata receipt
hashes. Its package-data report is
`electrs-actual-helper-data-inspection-v2-20261010T060412Z.json`, SHA256
`2dbeb838a6ed18480b1e634752f69d2351aeeba149846e771d8ec019a93d0c4e`.
The actual complete host ABI file is
`electrs-aadc-actual-complete-host-helper-abi.json`, SHA256
`40649fa2b524ccfecb7e09e468ffc4d86c24421370705c852e00ac49bba4d68b`.
The receiver does not treat a received JSON's claims as authority: controller
arguments must include these separately reviewed hashes, then selected package
and host leaf bytes are freshly rehashed before staging/using. Metadata closure
alone still cannot approve a mount or full build.

Root's next review must include capsule/artifact publication choice, receiver
and controller source hashes, actual library/daemon/ownership/cgroup guards and
small-resource/setup NNPrivilege exception. Only then may Root activate one
bounded small-image job. No transfer, image formatting, device open, mount or
Linux helper execution has happened in this preparation.
