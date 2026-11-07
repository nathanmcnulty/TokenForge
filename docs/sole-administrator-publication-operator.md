# Sole-administrator publication (offline-qualified local mode)

The approved [trust decision](sole-administrator-publication-decision.md) permits implementation and offline testing. It grants no live access or data publication. Existing strict hosted publication gates remain unchanged. No workflow activation, credential acquisition, collection or tenant operation belongs to this procedure.

## Prepare from retained evidence

Use a fresh PowerShell 7.6.7 Linux x64 process and the independently reviewed extracted package. Preserve the complete package, its manifest, the runtime, original receipts and custody directory. Import `scripts/TokenForgeLocalPublication.ps1` from that package. Never combine scripts from one package with another module or credential assembly. Loaded-assembly verification requires a fresh process when identity cannot be established. There is no build, install or download fallback.

1. Inspect the original evidence and selection sidecar privately. Preserve original observation dates, initial failures, unknowns and exclusions. Evidence from the earlier Graph/ARM assessment belongs to its original source and compilation identities; exporting it with new scripts does not make it a new live test of the rebuilt binaries.
2. Use `New-TfDiscoveryCandidate -LocalOrigin` with the existing saved-evidence exporters. Local origin has exact keys `Kind=LocalSnapshotV1`, `ExportId` (lowercase UUID), `EvidenceManifestSha256`, `SelectionSha256`, `EvidenceSourceCommit`, `EvidencePackageManifestSha256`, `EvidenceCompilationSource`. The latter three describe original evidence, separately from the exporting `SourceCommit`. Verify those original source/package claims against the retained receipts during independent review. The exporter does not infer provenance from a hash or fabricate hosted run/artifact IDs.
3. The seven candidate files are `coverage.json`, `flows.json`, `manifest.json`, `recipe.json`, `review.md`, `scopes.json`, `validation.json`. A complete, nonempty assessed candidate is required: no pending, unknown, paused, request-blocked or transient cells. Structural exclusions remain explicit. Completeness is scoped to the selected recipe, not all platforms/accounts/resources.
4. Call `New-TokenForgeLocalPublicationRuntimeInventory -OutputPath <new-private-file>`. This snapshots all PowerShell installation files and the publisher package identity. The real packet and dispatcher validate actual package membership/hashes, complete runtime membership/hashes, the source revision and the approved executable/DLL pair and loaded DLL identity. Keep the runtime installation unchanged through publication. A synthetic policy is explicitly barred from live execution.
5. Freeze a policy JSON with exactly the following fields:

```text
SchemaVersion=1; Mode=LocalSoleAdministratorV1; Synthetic=false
Repository; RepositoryId; UserId; DataBranch; SourcePullRequest; SourceCommit
PackageManifestSha256; RuntimeInventorySha256
ExpectedPermission; CredentialSource; JournalRoot
MaxReads; MaxDispatches; MaxSeconds
```

`Repository` is owner/name. Numeric IDs are decimal strings. `DataBranch` is a simple named branch, not main. The source PR must remain open, unmerged and at the approved exact source head in the same private repository. `ExpectedPermission` is the exact observed write/maintain/admin role; `CredentialSource` identifies approved existing access without storing a secret. `JournalRoot` is a private absolute path. Limits are 20–96 charged HTTP operations, 1–2 Git dispatches and 10–600 seconds. The cumulative byte reservation ceiling is 32 MiB, including outbound packs; unknown requests retain their full reservation. No automatic retry exists. Live approval may narrow all limits.

A bounded read-only preflight needs separate approval before observing account/repository identity, visibility, permissions, source PR, expected parent and complete recursive base tree. Do not silently perform it to populate missing values. Confirm no target push activates hosted jobs. Creating a disposable private test ref, if needed, is a separately listed live operation, never implicit preparation.

6. With that retained base-tree JSON (`sha`, `truncated=false`, complete `tree`), call `New-TokenForgeLocalPublicationPacket` with `PolicyPath`, externally verified `PolicySha256`, `CandidatePath`, `CandidateHash`, `BaseTreePath`, `ExpectedParent`, `UnixSeconds`, `AuthorName`, `AuthorEmail`, `RuntimeInventoryPath`, original `EvidenceManifestPath`, original `SelectionPath`, and a new private `OutputPath`.

The builder copies the original evidence manifest and selection bytes into **private custody only**, checks their actual SHA-256 against the candidate origin, and retains them on every recovery. It does not turn arbitrary manifest labels into verified historical provenance: the independent reviewer examines the underlying receipts and source/package mappings. Receipt and selection JSON are bounded to 4 MiB each. They are never Git objects or extra exported files.

The packet freezes seven file hashes/sizes, a readable table of added observations and original dates, every new Git object, the exact minimal canonical pack and the proposed commit/parent/tree. Existing paths are preserved. Author/committer metadata is publication content too. The bounded pack contains no deltas, thin references, alternate commits, surplus objects or opaque trailer. The packet directory is immutable by convention and revalidated by hash on every invocation. Never edit it to repair a transaction.

## Review and Nathan's approval

An independently invoked agent examines the actual candidate, semantic diff, complete outbound pack, source/package/runtime identities and private original evidence/selection. Retain its invocation reference and accepted report. The exact report fields are enforced by `Assert-TfLocalIndependentReview`; `Findings` must be empty after corrections. A report or synthetic fixture is not Nathan's authority.

`New-TokenForgeLocalPublicationApprovalDraft` takes the packet identity, `ReviewPath`, UTC creation/expiry/recovery times, `MaxDispatches` and a unique nonce. It emits a body and SHA-256, **not approval**. Validity is at most fifteen minutes; GET-only recovery allowance is at most twenty-four hours. It binds the exact policy, source PR/head, package/runtime, original evidence and selection, candidate files, pack/object inventory, destination, parent, proposed tree/commit and independent report.

Before live use, show Nathan the actual proposed content and exact bounded envelope: destination/ref and private visibility, account and existing credential use, observed role, source/package/evidence identities, read/byte/time/dispatch limits, possible ref setup and recovery location. Nathan must post the **exact body himself** as an authenticated comment on the pinned source PR and explicitly instruct the executing session to proceed. The publisher has no comment-creation route. It cannot distinguish physical human presence behind an authenticated account; the approved host/account trust assumption remains necessary.

Approval checks authenticate the actual credential principal separately from the comment author, require the pinned numeric Nathan user ID, exact body bytes, consistent REST comment listings, null GraphQL `lastEditedAt`, current validity and source head. Any later Nathan comment supersedes the selected approval. Post approval last, after review and corrections. Any content, policy, source, parent or review change requires a new packet/review/approval; do not edit an old comment.

## Publish and reconcile

Only inside the separately approved live envelope, use `Invoke-TokenForgeLocalPublication -Live -AccessToken <in-memory SecureString>` with `PacketPath`, externally pinned `PacketSha256`, `ReviewPath`, exact `ApprovalBodyPath`, `ApprovedApprovalSha256` and `ApprovalCommentId`. The caller owns/disposes its access token; the publisher disposes its own copy. Do not save tokens in files, commands, logs or journal. No sign-in/refresh is performed.

The journal is repository/ref scoped under the frozen `JournalRoot`, with an exclusive local lock and initialization marker. It retains cumulative requests, byte reservations and dispatch intent **before** each operation. No reset, movement or deletion is a retry mechanism. Malformed, missing or inconsistent initialized custody refuses. Runtime verification and authority checks run before dispatch. Git receive-pack uses exact-old CAS, not REST fast-forward approximation. Ordinary competing advances reject the update; no rebase, force or replacement is attempted.

After every dispatch—even a negative ACK—the publisher reads the remote. `AppliedVerified` requires the expected immutable commit/parent/tree, complete seven-file membership and downloaded blob lengths/SHA-256, with unrelated entries checked and a stable final ref/private-visibility observation. `AppliedAdvanced` additionally verifies ancestry and exact candidate content at the observed later tip. These are observations at the receipt time, not permanence guarantees.

`Rejected` means the observed ref remains at the expected parent with a negative ACK. It does **not** mean uploaded objects were erased. `ObjectTransfer=Unknown` remains distinct from ref outcome until content is observed and verified. Lost ACK/readback failure is `Unknown` or `UnknownAtParent`; never label it success or retry automatically.

For recovery call `Get-TokenForgeLocalPublicationStatus -Live` with the same packet/hash and existing authorized access. It performs read-only reconciliation; no sign-in, collection or POST update. Expired approval blocks writes but the retained recovery allowance can permit reads. A repeated applied invocation performs verification without another dispatch. If access expires, preserve custody and stop; offline data cannot establish the current private remote.

A second identical attempt is possible only when the exact live approval allowed two dispatches, the first process is known terminal, read-only reconciliation completed, the same approval remains current and unedited, expected parent remains, and the operator explicitly invokes `-Retry`. A late first update is safe only under the accepted no-rewind assumption and identical-commit CAS. Both attempts remain charged. Exhaustion, conflict, rewind, content tampering, settings change, lost custody or ambiguous evidence stops publication; a new parent-bound proposal may reuse retained content after reconciliation, without recollection.

## Qualification limits and backlog

Local synthetic and bare-Git tests establish implementation behavior under injected faults, not private GitHub operational acceptance. The legacy strict hosted model remains NO-GO under its existing deployment decision. No synthetic signature or reviewer report grants authority. No operational evidence is published by source/draft-PR publication.

- #113: synthetic signing/artifact and Git transport compatibility are retained; this mode adds offline approval/content/recovery behavior. Production private GitHub read/write, actual approval metadata/permissions and final content verification still need an approved live transaction.
- #115: preserve the earlier live Graph/ARM assessment separately from #128's later rebuilt-binary offline qualification. Expiry, revocation, renewal, protected-provider, reboot and backup claims require their own exact receipt scope. This milestone does not prove protected unattended provider startup or credential backup, and closes nothing.
- #116: frozen selection bytes and their digest survive publication/recovery; candidate completeness is checked. Hosted worker transport and end-to-end production incremental publication remain separate acceptance criteria. Publication retry does not rerun discovery or collection.

### Retained acceptance credited without rerunning

The newer private acceptance summaries refine the older offline-only checkpoints. Credit these as historical, source-bound results; they are not tests run by this branch:

| Requirement | Retained result and limit |
| --- | --- |
| Declared expiry | Runner `SessionExpired`, exit 1, zero requests/issuances; the supervising harness exit 0 meant the refusal assertion passed. |
| Renewal/account binding | Same-account renewal and a different-account refusal before later stages were accepted separately. |
| Service revocation | One controlled held-cookie test returned `Paused` at authorization after revocation while the declared deadline was still future. No numeric provider code was returned. This is not immediate access-token/all-device invalidation or a literal service `SessionExpired` result. |
| Reboot | One approved reboot established after-login safe refusal, runner exit 1, zero counters and unchanged saved state. Temporary units were removed. This is the safe-stop alternative; it does not prove protected unattended provider loading, pre-login startup, screen visibility or remote reachability. |
| Backup | Three metadata SQLite stores plus saved export/reconstruction were restored and checked. No credential/token backup claim. |
| Graph/ARM | The earlier source/package completed two frozen pairs through lock exclusion, one durable stop/resume and fixed Graph/ARM GETs returning HTTP 200; final no-work selection preserved the journal. HTTP 200 does not establish subscription counts, roles, licensing or general API access. |
| Incremental plan | Missing-only follow-up and all-fresh no-work selection were observed live; stale/relevant-change selection was subsequently checked offline. Immutable selection transport through trusted publication remains open. |

The earlier live package source is `9c02b2af51b1c02cbb0ef62aeac55c15f2caf362`, compilation `6c053524510a3c4aaf9e372b927079c754db47f0`. The #128 rebuilt compilation is `121c2b4f45bb345ff0377e761d847ed60b0c5b5d`, package source `b1c43b88872b4227169d2d87b6c0e3137a8e9963`; its later qualification was offline only. The present source overlay reuses that rebuilt pair only after complete compilation-input and binary equivalence. No historical result is relabeled as a new run of this overlay.
