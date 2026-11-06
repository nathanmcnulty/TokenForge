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
compression level zero, a fixed seven-name set, fixed ZIP-epoch timestamps
and regular `0600` files. It accounts for the uploader's stored entries and signed
data descriptors, including their CRCs/sizes and exact central-directory fields.
All headers, payloads, offsets and end records must match. Extra fields, comments,
trailing bytes, altered metadata and duplicates are refused. The official uploader
can vary entry order. V2 accepts only a permutation of the seven fixed names and
reconstructs both local and central records in that same order. Inconsistent order
or offsets are refused, and the validated order is recorded. This permits at most
5,040 structural orders (about 12.3 bits of choice); it is not a claim of zero
covert-channel capacity or production privacy approval. V1 stays fixed-order.

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

## Disposable-ref transport test

The separate manual `publish` phase is deliberately limited to the previously
reviewed synthetic archive: producer source
`7b6e62223944d99edde3b648749125247578e559`, run `42166462125`, attempt `1`,
artifact `13479301224`, original SHA-256
`47e533aa04a2683affa3ba709bd03441c26081c172664d99e7e41b905b89be08`, candidate
`d43102cb46f2eb64ec43605c933f35e457b89ba14fbf587aea930a562b192568`.
It revalidates the actual API artifact, complete ZIP and genuine signed bundle
before writing. The newer transport driver's source is recorded separately from
the producer source. It cannot substitute an operational candidate or recollect.

This job has contents-write permission, Actions/attestation read permission and
no OIDC permission. It calls the existing writer's Git packet, advertisement,
acknowledgement and HTTP functions directly, without manufacturing a production
approval verdict. Only a new `tokenforge-publication-canary-<run-id>` ref is
created. Its tree retains main's existing files and adds the seven public fixture
members. Neither main nor the production data ref is updated. An existing ref
causes refusal; there is no force update, merge or deletion.

A stale ancestor as expected-old must produce a complete rejection and a fresh
GET must show the unchanged ref. Only then does a distinct transaction attempt
the correct expected-old with the identical candidate and proposed commit.
After a known accepted response, the driver explicitly simulates loss of its
local acknowledgement and uses GET-only observation to resolve `Unknown` to
`Applied`. This is not a real network failure, crash test or proof of production
journal durability. Any ambiguous POST stops the experiment without a resend.

The driver bounds metadata calls to 24, Git calls to two per transaction (four
total), response bytes to 8 MiB per context, its metadata phase to 120 seconds,
each Git transaction to 30 seconds and the entire job to five minutes. It never
installs or downloads a verifier. Its flushed test intent is separate from the
unchanged production private journal. Retained Actions results contain only
public synthetic metadata. Production approval remains false throughout.
