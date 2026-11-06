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
created. The proposal commit from the first stopped experiment is reused after
reading both complete trees and checking that every leaf matches main plus the
seven signed fixture members. Neither main nor the production data ref is updated. An existing ref
causes refusal; there is no force update, merge or deletion.

A stale ancestor as expected-old must produce a complete rejection and a fresh
GET must show the unchanged ref. Only then does a distinct transaction attempt
the correct expected-old with the identical candidate and proposed commit.
After a known accepted response, the driver explicitly simulates loss of its
local acknowledgement and uses GET-only observation to resolve `Unknown` to
`Applied`. This is not a real network failure, crash test or proof of production
journal durability. Any ambiguous POST stops the experiment without a resend.

The initial driver created seven blobs, one tree, one commit and one ref (ten
REST mutation attempts). Its wrong-old response failed strict parsing; it stopped
before the corrected transaction. The ref was observed unchanged. That attempt
is retained as unresolved acknowledgement evidence and is never resent.

The revised driver reuses the proposal and bounds total REST calls to 24,
including one REST mutation attempt to create a fresh ref. Two further mutation
attempts are the intentional Git POSTs, for three total. Git calls are two per transaction (four
total), response bytes to 8 MiB per context, its metadata phase to 120 seconds,
each Git transaction to 30 seconds and the entire job to five minutes. It never
installs or downloads a verifier. Its flushed test intent is separate from the
unchanged production private journal. Retained Actions results contain only
public synthetic metadata. Production approval remains false throughout.
The diagnostic phase performs only the wrong-old POST, saves its raw reply,
observes the ref using GET and stops with `Unknown`; it never proceeds to the
corrected transaction. The new ref is distinct from every previous attempt.
Both phases save raw Git replies before parsing. The experiment verifies the
proposal tree before writing and observes the final ref, but does not independently
read back the tree after writing or establish production candidate acceptance.

The diagnostic isolated the acknowledgement incompatibility: GitHub returned a
complete `unpack ok` plus wrong-old `ng` report, followed by **two** flush packets.
Local receive-pack emits one. The writer now permits exactly either form after
the two required status packets. Extra status data, three flushes, incomplete
framing and arbitrary suffix bytes remain refused. This changes transport
compatibility only; a negative report never authorizes a write or a retry.

## Accepted result and retained limitations

[The sanitized result record](publication-acceptance-results.json) distinguishes
producer source, executed code source, original artifact, payload hashes/sizes,
proposal commit and transport proof. It retains both actual failures and the
diagnostic outcome; this is not a new all-green full-suite run.

At code commit `ea4bd357edb4554356eeb57aaca28eaaec0c630e`, manual run
[42168365911](https://github.com/nathanmcnulty/TokenForge/actions/runs/42168365911)
passed. Its raw wrong-old report is `Rejected`; a fresh GET confirmed main's base
still held on the new canary ref. A distinct corrected transaction using the
same retained candidate/proposal received `Accepted`. Explicitly simulated local
acknowledgement loss was resolved by GET-only observation to `Applied`, with zero
recovery POSTs. Actual usage was nine REST requests (one ref creation) and four
Git requests (two POSTs). The previous failed and diagnostic refs were untouched.
CI was restored to `disabled_manually` after the tests. The final PR additionally
quarantines the write-capable transport job with an unconditional `if: false`;
another write experiment requires a new reviewed source change. Historical
manual phase names remain for traceability and cannot bypass this quarantine.

The affected protocol/writer/recovery checks passed 112/112 after the correction;
six certificate-binding unit methods passed separately. The 121 ZIP/sealer/policy
checks are reused from `7b6e622...`: their relevant source, tests, fixtures and
native inputs are unchanged. No native binary was rebuilt, no new runtime package
was produced, and no Windows/macOS or other architecture result is implied.

Independent review directly inspected the original service archive and retained
signed proof, verified every archive byte/payload against producer source, and
reviewed the verified certificate bindings. It independently replayed the actual
GitHub response through the fixed parser. This is reviewed genuine hosted crypto
evidence, not a second independent cryptographic verification execution.

Keep #113 and #115 open. The production writer still requires its real configured
reviewer/approval identities, protected-main binding and publication permission
acceptance. No such actors are fabricated, no agent review is relabeled as an
authenticated human approval, and quarantined production workflows stay disabled.
This PR establishes actual artifact/signature and synthetic Git transport
compatibility before merge; it does not establish operational publication,
production crash recovery, post-write tree readback or every #115 requirement.
Private VM evidence remains local. There is no operational-evidence publication,
merge, issue closure, permission change or scheduler activation.
