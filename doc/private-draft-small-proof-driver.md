# Private draft transfer and ONE small proof — root dispatch pending

Root created release408752991/tagqualification-fuse-helper-20261010 on owned
repository1412614956 (`bitcoinuniverseio/electrs`), draft=true and unpublished.
Three exact assets are capsule627257138 (674624bytes), package-report627257159
(11295bytes), and host-report627257177 (11640bytes). Source driver literals carry
their reviewed names and SHA256; Root's receipt is
`electrs-private-fuse-draft-transfer-root-receipt.json`. No public asset/source
commit, release publication or new credential is required.

The sole job remains the existing owned runner, exact checkout pin,5-minute
timeout and contents-read permission. Its one operational step uses the
ephemeral job token only for GET on the five literal api.github.com paths:
repository metadata, exact draft release and the three asset IDs. It validates
repository ID/name, release ID/tag/draft/published state and all asset IDs,
names, sizes and GitHub digest fields before download. No list/catalog endpoint
or release mutation is used.

Transport disallows automatic redirects. Binary asset requests may follow just
one HTTPS redirect to exact release-assets.githubusercontent.com, with NO
Authorization header. Another redirect/domain, userinfo, unreviewed API path,
content-size/digest mismatch or deadline fails without retry. Signed Location
and token stay only in memory; no raw HTTP exception, headers or URL are logged
or recorded. Inherited proxy/authentication handlers and TLS keylogging/trust
overrides are disabled/rejected. Bounds are8 total requests,1MiB aggregate,
exact asset sizes,45s logical transfer deadline and8s request timeouts under the
outer job deadline. Resolver stalls remain bounded by job timeout, not an
asserted cancellable Python resolver. Failure preserves phase/type and safe
diagnostics without credential-bearing remote messages.

Only a new owned RUNNER_TEMP transfer directory receives immutable validated
asset files. Token is removed from the process environment and forgotten before
receiver/proof launch. The reviewed receiver verifies the complete24-member
capsule and then stages to a new owned helper-data directory. Both metadata
files are checksum verified separately before binding; selected current host
and private bytes are rehashed again by the proof controller.

The driver invokes `small-fuse-image-proof.launch` exactly once. That controller
creates only the reviewed30s/128MiB/CPU100/tasks16 setup scope with existing
setuid mounting permitted, verifies actual guards, and tests the own fixed
8MiB image/real aggregate ENOSPC/readback/settlement. No Cargo, native producer,
host package install/settings change or8GiB/full-build qualification is done.
Rust WIP is neither compiled nor labeled frozen. Default driver invocation
performs no download or scope creation. The workflow/source is prepared locally;
Root must independently review and push/dispatch. No execution occurred here.
