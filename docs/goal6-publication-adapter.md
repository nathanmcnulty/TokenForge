# Goal 6 trusted publication verification adapter

`scripts/TokenForgePublicationAdapter.ps1` implements the read-only verification and durable handoff boundary for an existing publication proposal. It has no remote writer, workflow dispatch or publication command. A successful result is `VerifiedForSeparateWriterReview`; `AuthorizationEstablished`, `PublishAllowed`, `RemoteMutationPerformed` and `HostedExecutionProof` remain false. Synthetic results also leave `ObservedAuthorityFromAuthenticatedApi` false.

This supplements the historical [offline release receipt](goal6-offline-readiness.md). It does not supersede its package acceptance results or complete Goal 6. The adapter is source-only and is not in that previously accepted package. The legacy discovery writer remains quarantined with `if: false`. Actions were not enabled or dispatched.

## Trust boundary and inputs

The adapter accepts an independently pinned, private policy file; a saved private candidate ZIP; and the IDs of one same-repository proposal PR and two approval comments. Synthetic mode requires explicit fixture callbacks and a fixture clock. Live mode instead requires an explicitly supplied `SecureString` access token, an absolute verifier path, a saved signed attestation bundle and a pinned trust-root file. The parameter sets cannot be combined. It never reads ambient GitHub credentials, downloads an artifact, checks out a proposal, runs candidate code, or invokes Git hooks/filters.

The policy and its SHA256 are trusted inputs, not values supplied by a producer. Provision them through a separately reviewed operator process. Policy bytes are read once under an exclusive handle, bounded to 16 KiB, then hashed and parsed from that same snapshot. Strict JSON parsing rejects duplicate fields. Unknown fields fail closed.

Policy schema version 1 contains exactly:

| Fields | Contract |
|---|---|
| `Repository`, `RepositoryId` | Exact owner/name and immutable numeric repository ID |
| `MainBranch`, `DataBranch` | Separate simple branch names; no slash, traversal or arbitrary ref |
| `WorkflowId`, `WorkflowPath`, `WorkflowSha256` | Audited manual producer identity and exact workflow bytes |
| `SealerPath`, `SealerCommit`, `SealerSha256` | Audited reusable sealer path, full commit and exact workflow bytes |
| `VerifierSha256`, `TrustRootSha256` | Exact approved executable and root file hashes |
| `ProducerIds`, `ReviewerIds`, `MaintainerIds`, `ReaderIds` | Distinct role allowlists of immutable numeric user IDs, 1–20 unique IDs each |
| `JournalRoot` | Explicit normalized absolute private custody directory |
| `SchemaVersion` | JSON integer `1` |

IDs in the policy are strings; hashes are full lowercase SHA256 or Git SHA1 as appropriate. Role lists may overlap, but each invocation enforces independent actors: reviewer and maintainer differ from each other, the reader, producer, triggering actor and proposer. Current repository permissions are fetched rather than inferred from allowlist membership. The reader and main maintainer need `maintain` or `admin`; the candidate reviewer needs `write`, `maintain` or `admin`.

The complete executable synthetic policy, approval and response generator is [AdapterFixture.ps1](../tests/fixtures/publication/AdapterFixture.ps1). Its IDs, hashes, workflows, certificates and actors are invented. It is test data, never an operational policy or cryptographic proof.

## Authenticated approval channel

Two unedited issue comments on the same open, non-draft, unmerged, same-repository PR carry byte-identical JSON bodies. The PR targets the configured data branch and its head equals the approved proposed commit. The API comment author establishes identity; a name or ID inside the body cannot establish identity. Bots are rejected. Both selected comments must appear in a complete, unpaginated stream of at most 100 comments. Any later comment by the same approving actor invalidates that actor's earlier approval. This deliberately conservative rule also treats an unrelated later comment as supersession.

The versioned approval has exactly these fields, all strings except integer `SchemaVersion`:

```text
SchemaVersion = 1
Kind = TokenForgePublicationApprovalV2
PolicySha256, RepositoryId
Ref = refs/heads/<configured data branch>
Mapping = CandidateDirectoryV1
CandidateHash, ArtifactId, ArtifactSha256
SourceCommit, ProducerRunId, ProducerAttempt
ExpectedParent, ProposedCommit
CreatedAt, ExpiresAt
Decision = Approved
```

`CandidateHash` is the SHA256 of the exact candidate `manifest.json`; `ArtifactSha256` binds the entire saved ZIP. Times use canonical round-trip UTC formatting, the window is at most 24 hours, and each comment must have been created within that window. The policy hash binds all role, workflow, verifier, root and custody choices. Edited, inconsistent, expired or superseded approvals cannot prepare publication. Expired approvals may still support read-only diagnosis of an already observed proposed commit.

## Producer, sealing and commit checks

The authenticated repository must have the expected immutable ID, full name and default branch and be neither archived nor disabled. The producer must be a successful, completed manual run of the pinned workflow, source and exact attempt in that repository. The artifact must have the exact approved ID, size, SHA256, run and source. Source must still equal the current protected main tip. Main protection must enforce administrators, dismiss stale reviews and require at least one approving review. The pinned sealer commit must be an ancestor of that tip. Both workflow files are checked against their audited byte hashes and Git blob IDs.

Artifact membership and a consistent candidate manifest are insufficient sealing evidence. Live mode runs a separately pinned `gh attestation verify` executable against a saved signed bundle and pinned custom root inside a Linux user/network namespace. The executable is copied into a private directory, hashed there and executed from that copy. Bundle, root and archive are also bounded private copies. The child has no network, inherited credentials/configuration or interactive stdin; its environment is cleared. Exact arguments constrain repository, signer workflow/commit, source commit/ref, GitHub OIDC issuer and hosted runners.

The verified output must contain exactly one SLSA v1 statement with the ZIP digest and a witnessed timestamp. The verified signing certificate must bind the immutable repository ID, repository URI, source commit/ref, reusable sealer path/commit, run/attempt invocation URI and GitHub-hosted runner identity. Caller-controlled predicate fields cannot substitute for these certificate fields. The future audited sealer must isolate OIDC authority from untrusted producer code and independently derive the sealed digest; merely signing a producer-supplied digest is insufficient.

The ZIP must contain exactly the seven candidate files as regular top-level entries: `manifest.json`, `coverage.json`, `flows.json`, `recipe.json`, `review.md`, `scopes.json`, `validation.json`. Duplicate/case-colliding entries, paths, links and excess expansion fail closed. Existing candidate reconstruction/privacy validation is reused. The manifest source/run/attempt must match the authenticated producer.

`CandidateDirectoryV1` is append-only: the proposed commit has exactly one parent, `ExpectedParent`, and adds the exact seven `100644` blobs at `candidates/<CandidateHash>/`. Complete old/new Git trees must preserve every unrelated path, mode, type and blob. Only necessary ancestor tree hashes may differ. Truncated trees, existing candidate destinations, unrelated changes, executable/link entries and extra directories fail. This versioned mapping does not replace the legacy discovery JSON files; a future consumer/writer must explicitly adopt it.

## Bounds and failure behavior

| Resource | Hard allowance |
|---|---|
| GitHub metadata | 32 GETs; 60 seconds aggregate after input staging; no retries |
| Each GET | At most 10 seconds, also bounded by remaining aggregate time |
| API response | 4 MiB each, 32 MiB aggregate; redirects and pagination refused |
| Candidate ZIP and expanded content | 8 MiB each; exactly seven files |
| Policy / bundle / trust root / verifier | 16 KiB / 4 MiB / 256 KiB / 128 MiB |
| Verifier stdout / stderr | 4 MiB / 64 KiB; aggregate verification deadline |
| Recursive Git tree | 10,000 entries each; complete response required |
| Journal | 100 records, 16 KiB on save; no automatic reset or garbage collection |

GET routes are constructed internally and restricted to `https://api.github.com`; response URLs and links are never followed. No token is passed to the verifier. Failures report only the stage and absence of remote writes, not API bodies, token contents or verifier stderr. Disk staging and atomic journal persistence are synchronous bounded-size local operations outside the HTTP/verifier deadline; this is not an end-to-end process termination guarantee.

The final pass repeats comment identity/content/supersession, reviewer/maintainer/reader permissions, main/protection, the full PR predicate, producer attempt/status and artifact metadata, then observes the data ref. This narrows ordinary races; it cannot make observations atomic with a future remote write or prove effective branch-ruleset push permission.

## Durable custody and recovery

The policy fixes `<JournalRoot>/<RepositoryId>-<DataBranch>/publication.json`. Private ownership/modes, unlinked paths, exclusive writer lock and the existing `VaultFileTransaction` flushed atomic replacement protect cooperating local processes. These reuse the reviewed compiled package primitives; they do not authenticate a store controlled by a hostile same-user process or protect against rollback of an entire custody directory. Keep the store, its `.initialized` marker and backups together. Missing canonical state after initialization fails closed. Do not delete/reset state to retry, move between roots, mix synthetic/live stores or silently compact records.

The transaction binds policy, exact approval body, both comment IDs and authenticated actor IDs. The approval body binds candidate, ZIP, source/run/attempt, destination mapping, expected parent and proposed commit. A durable prior prepared record plus observation of the exact proposed ref yields `AlreadyApplied`, even after expiry. A first observation already showing that ref yields `ObservedProposedWithoutPreparedState`, not invented prepared provenance. Once application has been observed and recorded, a rewind to the old parent yields `ConsumedApproval`. Another parent yields `StaleParent`; an expired preparation yields `Expired`.

This read-only journal cannot detect a publication and rewind that both occur between observations. A future writer needs a durable `DispatchStarted`/`Unknown`/`Applied` transition before sending, exact expected-old compare-and-swap, fresh verification immediately before dispatch and bounded remote recovery after a lost acknowledgement. A returned handoff object alone is never a bearer authorization. No writer should infer permission from `VerifiedForSeparateWriterReview`.

## Local acceptance and remaining gates

Run in a fresh PowerShell process using the unchanged trusted Linux package for its compiled private-file primitives:

```powershell
pwsh -NoProfile -File scripts/Invoke-TokenForgeLocalValidation.ps1 `
  -Preset Publication -NativeExecutable <trusted-package>/tokenforge `
  -ReportPath <new-report-path>
```

The preset includes adapter synthetic/process-boundary cases, existing recovery planning, candidate validation and manual-only workflow/quarantine policy checks. Use external network isolation (`unshare -Urn` on this VM) for additional assurance. It never builds, installs, authenticates or dispatches Actions. The verifier process cases execute harmless pinned shell fixtures, not a real attestation verifier. The [acceptance record](goal6-publication-adapter-validation.json) records exact results and source/package revisions.

The installed `/bin/gh` has no `attestation` subcommand. No dependency was installed or upgraded. Real CLI flag/output compatibility and signed-bundle/root verification remain unproven and fail closed. Before any hosted verification, provision and independently pin a compatible verifier, its required root/bundle and an audited reusable sealer; test real signed positive/negative bundles without authentication where possible. No actual GitHub permissions, approval-channel behavior, hosted race, effective push permissions or publication has been proved by the fixtures.

Separate approval is needed for authenticated read-only API verification, naming the account/repository, exact policy/tool/root/candidate/bundle and request/time envelope. Hosted execution needs separate explicit Actions authorization. A remote writer and its permission/API/race/lost-ack tests remain separate implementation and approval gates; publishing, PR creation and merge are not authorized. Fresh human administrator workflow and collector-recovery acceptance from the historical Goal 6 receipt also remain open. This checkpoint is offline-validated verification code, not full Goal 6 or publication readiness.

Primary protocol references: [GitHub artifact metadata](https://docs.github.com/en/rest/actions/artifacts?apiVersion=2022-11-28), [GitHub Git trees](https://docs.github.com/en/rest/git/trees?apiVersion=2022-11-28), [CLI attestation verification](https://cli.github.com/manual/gh_attestation_verify), [Sigstore verified certificate output](https://github.com/sigstore/sigstore-go/blob/main/docs/verification.md), [explicit expected-old Git leases](https://git-scm.com/docs/git-push).
