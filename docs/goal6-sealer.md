# Goal 6 reusable sealer and policy

Current checkpoint: [the canonical original-ZIP contract](goal6-canonical-zip.md) implements fail-closed container coverage and converts the prior unsafe characterizations into rejection regressions. Historical findings/receipts below remain unchanged; operational emission and hosted activation are still blocked.

Previous checkpoint status: [follow-up to Dot](goal6-sealer-followup.md) corrects temporary-directory ingress and confirms an unresolved complete-original-ZIP privacy blocker. Operational policy emission is now refused unconditionally. The earlier acceptance below covers structural checks, not every archive byte.

This milestone implements an offline-tested trusted sealer and policy planner. It does not complete Goal 6 or establish hosted provenance, publication authority or release readiness. Exact commits, package reuse and checks are recorded in [the validation receipt](goal6-sealer-validation.json). [Dot's review handoff](goal6-dot-review.md) describes the current review scope and remaining release gates.

## Trust boundary

The reusable workflow accepts one artifact ID. Repository, immutable repository ID, source SHA, caller run/attempt, ref, event and workflow reference come from GitHub execution context. A single isolated job loads only the implementation from an immutable commit and pinned official actions. No producer code, supplied digest/path, cache or inherited secrets enter that job. The downloaded files remain data: they are never imported, rendered or executed.

The validator uses at most seven metadata GETs plus two download GETs, a shared 60-second deadline and 16 MiB aggregate response budget. Individual metadata responses are limited to 4 MiB and the original ZIP to 8 MiB. The first download GET targets a fixed GitHub artifact route; one HTTPS redirect to an allowed GitHub artifact-storage hostname is permitted, with no GitHub Authorization header forwarded. There is no download retry or second redirect.

It compares the exact downloaded ZIP with the authenticated artifact size/digest, validates exactly seven regular top-level candidate files, reconstructs existing schema/hash/privacy checks and binds the manifest to the caller source/run/attempt. Final metadata reads reject changed origin, reruns, expiry, failed runs, advanced or unprotected main. It creates a new private destination, deletes only that newly created destination on failure, and retains a read-only candidate ZIP and a private receipt on success. Completed evidence is never overwritten.

The signing action receives one fixed `subject-path`; it computes its digest over those original ZIP bytes. A later upload wrapper is a distinct archive. Publication must continue referencing the original candidate artifact ID and digest, never the evidence wrapper's ID/digest. Structural sealing does not imply semantic approval. The job has signing permission but no repository contents-write permission; only reviewed code and pinned actions run within that boundary.

The checked-in workflow is deliberately quarantined with a literal false job guard. No producer calls it. Actions remain disabled. Offline tests cannot establish whether GitHub's service artifact digest always equals the exact REST-downloaded ZIP or prove the certified same-repository reusable-workflow identity. Both are explicit hosted acceptance gates.

## Immutable source and policy construction

Implementation commit A contains the code and exact workflow template. Workflow commit B pins A; a future separately approved producer commit C must pin B with a real `jobs.<id>.uses` call. This avoids a recursive workflow self-hash. Policy planning reads exact local Git blobs, disables replacement objects, lazy fetching, transports, prompts and credential-helper fallback, and has size/time bounds. It compares every sealer workflow byte with the template at A, allowing only the documented false guard or exact activation guard.

Caller validation uses isolated `/usr/bin/python3 -I` and existing PyYAML 6.0.2. It requires a manual producer, an exact immutable same-repository call, isolated signing permissions, one predecessor artifact output and no inherited secrets. Duplicate YAML keys, aliases, scalar spoofs, extra triggers and elevated active worker permissions fail closed. Python/PyYAML are offline policy-planning developer dependencies; the hosted signing job does not use them. No dependency was installed during this milestone. A clean-checkout smoke confirms the pinned PowerShell source can load its unchanged BCL-only credential core without a packaged DLL, SDK download or authentication; the normal focused suite reuses the trusted Linux package.

Review mode emits a distinctly typed non-operational plan. Even complete identity bindings produce only a runtime-rejected binding preview, never a nested runtime policy. Missing immutable repository/workflow IDs and independent producer/reviewer/maintainer/reader IDs remain missing; no real identity is guessed. The four role lists must be pairwise disjoint.

An explicit `-Operational` request refuses quarantined or unconnected source and incomplete bindings. Its synthetic positive fixture proves schema construction only. It is not an authority check: existing publication verification must still establish current main, permissions, certified origin, expiry and independent approvals at execution time. Operator policy custody and a protected journal remain required.

Example for review only, using exact reviewed local commits and a new absolute private custody path:

```powershell
. ./scripts/TokenForgeSealerPolicy.ps1
Get-TokenForgeSealerPolicyPlan -RepositoryPath <local-repository> `
  -SealerCommit <workflow-B> -ProducerCommit <producer-C> `
  -JournalRoot <absolute-private-custody-path>
```

Real bindings are a private JSON object with exactly `RepositoryId`, `WorkflowId`, `ProducerIds`, `ReviewerIds`, `MaintainerIds`, `ReaderIds`. IDs are positive decimal strings; each role is a nonempty array. Keep the file and its parent private. Establish these identities and current roles independently before approval. The tracked [review plan](../publication/sealer-policy-review-plan.json) intentionally lacks them and cannot be used by the writer.

## Local acceptance and limits

Run the narrow `Sealer` preset in fresh PowerShell with the existing trusted Linux executable. It performs no build, install, authentication or hosted execution. The receipt distinguishes the final gate from earlier diagnostic failures and historical unchanged package/verifier checks.

Independent review found and closed four issues: YAML scalar spoofing, runtime-valid nested preview output, lazy Git fetching and an incomplete workflow quarantine test. Regression fixtures cover each. Request/time/byte bounds, redirects, origin changes, malformed/wrapped candidates, privacy, no-overwrite, strict caller permissions and activation refusal are also tested. No other operating system or architecture was compiled or tested.

Goal 6 is now ready for an offline architecture/security review by Dot after the recorded gates pass. It remains a release candidate. Remaining work requires explicit decisions and authorization: activate and connect the reviewed workflow, establish real identity/custody bindings and current-main source; prove original ZIP/certificate behavior with approved hosted compute; prove actual publication permissions, expected-parent races and lost-ack recovery with approved remote mutations; and have a fresh operator complete all four supported admin workflows and collector recovery on an exact matching release package. No authentication, tenant permission change, push, publication, PR, merge or hosted run was performed here.
