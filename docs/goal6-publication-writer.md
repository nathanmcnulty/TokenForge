# Goal 6 remote writer: offline checkpoint

The source-only writer adds one exact-old Git ref update after fresh trusted verification, durable intent before dispatch, and independent read-only recovery. No real publication was performed. Actions remain disabled, the legacy workflow writer remains quarantined, and no workflow was connected to this implementation. Full Goal 6, hosted compatibility and publication readiness remain open.

The existing [verification contract](goal6-publication-adapter.md) still applies to a new publication: exact candidate/archive hashes, producer and sealing identity, two independent current approvers, strict expiry/current-main/protection, exact parent and complete proposed commit contents. The seven-file `CandidateDirectoryV1` mapping remains append-only. Existing policy and approval schemas are unchanged. New operational policies and approvals must pin the reviewed current policy/tool/root bytes; test policies are never operational approvals.

## Entry points and execution boundary

Dot-source `scripts/TokenForgePublicationWriter.ps1` to load the entry points. Import performs no dispatch.

| Entry point | Behavior |
|---|---|
| `Invoke-TokenForgePublicationVerification` | Existing read-only verification; cannot accept writer options or a mutation callback |
| `Invoke-TokenForgePublication` | Requires `ExecutePublication` and the exact independently approved `ApprovedTransaction` hash, then repeats full verification while holding private custody lock |
| `Get-TokenForgePublicationWriterStatus` | Requires pinned policy and a recorded transaction; authenticated GET-only observation and local reconciliation, with no publication option |

`ExecutePublication` is an execution guard, not a substitute for separate human authorization. The approved transaction comes from a reviewed verification result and binds the exact policy, approval body, comment IDs and authenticated approving actor IDs; its approval body binds the artifact/candidate, producer tuple, destination/ref/mapping and old/new commits. A caller-supplied matching hash alone does not establish authority. The writer rederives it from fresh verified inputs.

Publication takes the same inputs as verification, plus `ApprovedTransaction` and `ExecutePublication`. Live mode requires explicitly supplied `SecureString` credentials and pinned offline verifier/root/bundle; it accepts no callback transport. Synthetic mode instead requires the fixture clock and metadata, attestation and Git transport callbacks. The parameter sets cannot be combined, including by passing `Synthetic:$false`. Synthetic results always retain false authority/remote-mutation/hosted-proof claims. `RemoteMutationPerformed` is unknown (`null`) for live results; observed ref state does not prove which actor caused it.

The writer identity is the allowlisted authenticated reader identity. It must have the currently required repository role and differ from producer, triggering actor and proposer, as well as the two approvers. Workers and writer must have separately provisioned credentials and privileges. Future live use requires a repository-ID-restricted credential and separately verified branch/ruleset behavior; this implementation never changes permissions, provisions credentials or bypasses server restrictions.

## Exact-old transport

The REST ref-update API does not expose the required exact-old compare-and-swap. The writer instead uses a restricted Git smart-HTTP receive-pack exchange at the fixed `https://github.com/<policy owner>/<policy repo>.git` origin:

1. Bounded discovery GET, requiring the receive-pack service banner, complete packet framing, a unique target ref at `ExpectedParent`, `report-status` and SHA1 object format. Unsupported or ambiguous discovery fails before intent.
2. Rebind the repository URL to its immutable ID through the API, then perform the existing final authority, producer, artifact, PR/protection and data-ref checks. Discovery occurs **before** this final pass so an approval withdrawal during discovery is observed. The final data-ref GET is the last remote observation before intent.
3. Atomically persist `DispatchStarted`, then recheck expiry and elapsed budgets. POST exactly one `<ExpectedParent> <ProposedCommit> refs/heads/<DataBranch>` update requesting only `report-status`, followed by a flush and a correctly checksummed empty pack.
4. Parse a complete unpack/ref status response and independently observe the data ref. Never resend the POST.

The commit and all objects must already exist in the same repository, as verified through authenticated metadata and complete tree checks. No object upload, checkout, local Git configuration, credential helper, hook, child Git process or arbitrary URL is used in production. HTTP uses explicit credentials, TLS validation, HTTP/1.1, fresh clients with connection-close, no redirects, cookies, proxy, ambient credential lookup or application-level retry. The server checks the exact old object ID at ref update time; an ordinary fast-forward check is insufficient after a rewind.

The exact-old comparison closes the ref race. Separate metadata observations cannot atomically bind reviewer permission or repository naming to that ref update. Keep the expected immutable repository ID, fixed URL and repository-restricted credential together; actual GitHub permission/ruleset/rename/race behavior remains a separately authorized gate. There is no claim of an exactly-once distributed transaction.

## Durable custody and recovery

The existing private `.writer.lock` is held across verification, discovery, preparation, dispatch and reconciliation. Writer state is a separate `writer.json` beside the verification `publication.json`, using the same reviewed compiled `VaultFileTransaction` flushed atomic replacement. `.writer.initialized` makes missing canonical writer state fail closed. Private ownership/modes, unlinked paths, exclusive handles, strict JSON/fields/context and fixed policy root apply. State is bounded to 16 KiB and 100 records; it is never automatically compacted or reset.

Each record binds transaction, expected parent, proposed commit and tree, writer ID and preparation time, plus finite acknowledgement/outcome and last observed commit. The protected record pins the immutable content verified before dispatch. Recovery checks the repository ID, an authenticated allowlisted reader, exact saved commit/tree/parent and current ref. It needs no saved archive, open PR, current main, unexpired artifact or still-valid approval. It makes no authority decision for a new write. Repository access/authentication are still required in live mode; failed observation leaves custody intact and requires recovery again.

| State | Meaning and next behavior |
|---|---|
| `DispatchStarted` | Durable intent exists; POST may or may not have started. Only read-only recovery is allowed. |
| `Unknown` | Transport/status/observation was inconclusive, or success was followed by the old/another ref. Never infer failure from the old ref. |
| `Rejected` | Complete server rejection plus independent observation of the unchanged old ref. The transaction is still never resent. |
| `Applied` | Exact proposed ref was independently observed. This proves state, not which request/actor caused it. |
| `Consumed` | A known applied transaction was later observed at its old parent. It cannot become eligible again. |

Any `DispatchStarted`, `Unknown` or `Consumed` record blocks **all new transactions on that repository/ref**, including new comments and hashes. A prior `Applied` history permits a new publication only when its expected parent equals the last applied proposed commit. External history changes conservatively require separate audited reconciliation. No override, abandonment or reset command is provided. Moving the custody root, rolling back/deleting the whole directory or changing policy is not an approved way to clear uncertainty.

A crash before intent allows a new fully verified preparation. A crash after intent—even before POST—consumes the dispatch opportunity conservatively. If the server applies the ref but the acknowledgement or final journal commit is lost, GET-only recovery can record `Applied`. If application and rewind both occur between observations, recovery stays `Unknown`; the global barrier prevents a new approval from bypassing it. The store assumes cooperating processes and trusted same-user custody; it cannot authenticate a hostile same-user replacement or detect rollback of the entire custody directory. Retain all canonical files, markers and backups together. No power-failure durability claim is added beyond the existing transaction primitive.

## Bounded execution

| Phase | Allowance |
|---|---|
| Fresh verification | Existing 32 API GETs, 60 seconds, 4 MiB each/32 MiB aggregate |
| Writer | At most 2 Git HTTP requests (one discovery GET, one POST) plus 2 API GETs; 30-second clock starts before discovery and continues through the final verification pass, dispatch and reconciliation |
| Writer response sizes | Git 2 MiB each; API 4 MiB each; 8 MiB aggregate; each call at most 10 seconds or remaining phase time |
| Independent recovery | At most 4 API GETs, 30 seconds, 4 MiB each/8 MiB aggregate |
| Local intent/journal | 16 KiB, 100 records; existing private atomic storage primitive |

Clocks overlap and are never replenished after discovery. Both verification and writer allowances must still pass before dispatch. Input staging, synchronous bounded local validation and persistence are not a hard process-kill deadline. After durable intent, deadline/expiry failure is recovery-only even when the POST was never sent. Any failed post-write observation remains `Unknown`. Errors expose a stage and recovery instruction, not token contents, response bodies or raw server rejection text. `ObservedCommit` is the last successful observation and may precede dispatch when reconciliation failed.

## Offline evidence and remaining gates

Use a fresh process with the unchanged trusted Linux package:

```powershell
pwsh -NoProfile -File scripts/Invoke-TokenForgeLocalValidation.ps1 `
  -Preset Publication -NativeExecutable <trusted-package>/tokenforge `
  -ReportPath <new-report-path>
```

The preset includes verification, writer/recovery fixtures, real local bare-repository Git protocol cases, candidate/planner contracts and workflow policy checks. Tests use `unshare -Urn` external network isolation. Local Git fixtures create only synthetic repositories: existing-object success, a genuine fast-forward-but-wrong-old refusal, disappeared branch, missing object and rejecting server hook. These tests do not authenticate to GitHub or publish anything there. They prove wire/CAS behavior with the installed local Git, not GitHub support or permissions.

The [acceptance receipt](goal6-publication-writer-validation.json) records exact source/package revisions, hashes, final results and review corrections. No module/native/package-builder/workflow input changed; no rebuild, dependency installation or unchanged broad runtime gate was needed. This source-only writer is not included in the previously accepted package, and its existing acceptance receipt remains historical.

Before any real use, a compatible pinned attestation verifier and audited reusable sealer/policy must be provisioned and tested with real signed positive/negative bundles. Installed `gh` lacks the attestation command. Actual GitHub smart-HTTP existing-object publication, authenticated API identities/roles, ruleset rejection, stale-old CAS and lost-ack recovery require separately authorized bounded service tests with a repository-restricted writer credential and disposable approved ref. Wire compatibility may fail closed; offline fixtures do not resolve it.

Separate approval must name the account/repository, exact source/policy/tool/root/bundle/candidate/transaction, approved target ref, one POST maximum, discovery/API/time limits and recovery allowance. Authorization for read-only authentication does not authorize a publication POST. Hosted compute needs its own explicit Actions budget/approval. No publication, PR, merge, tenant change or Actions use is authorized by this checkpoint. Fresh human administrator workflow/collector-recovery acceptance and the other historical Goal 6 gates also remain open.

Protocol references: [Git smart HTTP](https://git-scm.com/docs/gitprotocol-http), [receive-pack update and report-status framing](https://git-scm.com/docs/gitprotocol-pack). The implementation deliberately supports only the documented SHA1, single-ref, existing-object subset.
