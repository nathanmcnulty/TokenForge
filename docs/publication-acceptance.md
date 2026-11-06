# Premerge publication compatibility acceptance

The manual `ci.yml` publication probe uses only the checked-in public synthetic
candidate. It never loads a tenant credential, collector directory, permission
inventory or local operator receipt. The fixture preserves incomplete coverage:
one in-flight unknown cell, one unknown matrix, and no token/scope observations.

The probe is restricted to this repository and the reviewed
`codex/issue113-publication-acceptance` branch. Its default is off; the ordinary
PowerShell job is skipped when the probe is selected. There are no new automatic
triggers. The producer has read-only contents permission. The separate signing
job receives OIDC/attestation permission only after the producer succeeds and
validates the original service ZIP against independently reconstructed fixture
bytes. No candidate code is executed.

## Official stored ZIP profile

`GitHubStoredOriginalZipV2` supports the pinned official artifact uploader with
compression level zero, sorted seven-file membership, fixed ZIP-epoch timestamps
and regular `0600` files. It accounts for the uploader's stored entries and signed
data descriptors, including their CRCs/sizes and exact central-directory fields.
All headers, payloads, offsets and end records must match. Extra fields, comments,
trailing bytes, altered metadata, duplicates and reordered entries are refused.

Validation reconstructs expected bytes only for comparison. The downloaded
service archive is retained and hashed unchanged; that original digest is the
attestation subject. The uploader's API artifact ID, digest, size, repository,
source, run and attempt are checked independently. A rebuilt ZIP is never
substituted for the service object.

The existing `CanonicalStoredOriginalZipV1` default is unchanged. Selecting V2 is
explicit. This change does not activate the quarantined production sealer or emit
an operational publication policy.

## Signed proof

The signing job checks the entire public fixture archive, rejects an appended
marker, and attests only the validated original bytes. The existing hosted
GitHub CLI is copied and checked against its independently observed SHA-256.
The existing provisioned Sigstore root is pinned separately. There is no tool
installation or download fallback.

Verification runs with a cleared environment, no token/configuration/stdin and
an isolated network namespace. Existing runner `sudo` creates only that ephemeral
namespace; `runuser` drops back to the runner before the pinned verifier executes.
No sysctl, host policy or persistent permission is changed. Repository, source
digest/ref, signer workflow/digest, GitHub OIDC issuer and hosted-runner identity
are constrained. A positive verification and an expected exit-1 refusal for the
tampered archive are recorded separately.

## Scope of the result

This is real GitHub service compatibility with explicitly synthetic data on an
unmerged source branch. It is not production approval or authenticated collector
evidence. Public fixture proof may be retained in Actions; real VM evidence and
account/tenant data remain private and local.

The production adapter still requires current protected-main source and real
authenticated approval actors. A local agent review is useful independent code
review; it is not relabeled as those GitHub identities. No repository access,
branch protection, production data ref, merge or issue state is changed by the
artifact/signature probe.
