# Weekly research CI

The scheduled workflow refreshes public source metadata every six hours. It freezes a UTC ISO-week recipe containing **all published application IDs**, the public discovery snapshot, protocol bounds, and fixed chunk membership. It does not publish the tenant's eligible registration inventory. App IDs found only in private sign-in logs remain in the separate private maintenance catalog.

Four independently authenticated workers assess at most 100 published IDs each. Every selected ID must have an explicit fresh inventory record, including missing, disabled, or unverified entries. These structural results count as assessment coverage without token issuance. A successful token observation is a different measure: it describes what Entra issued for the tested account/session, not universal support or API authorization.

The coordinator chooses pending batches and failed batches with fewer than three attempts. Selection uses saved state, not GitHub run numbers. Failed or missing workers remain incomplete; an exhausted batch prevents a weekly complete claim. Manual `retry_exhausted` allows up to ten attempts. Each week starts a fresh shallow recipe and archives the prior aggregate report, including unfinished coverage. Late or repeated results cannot replace newer state: receipts bind the recipe, partition, and next attempt; publication checks the original data-branch parent and uses a normal fast-forward push.

After the shallow recipe completes, Auto mode spends a separate deep budget: at most 100 public candidates per week, 25 per batch, at most two workers, up to four callbacks, and all three implemented delegated protocols. New deep recipes freeze Graph and ARM as separate resource pairs, with at most 200 pairs across 100 selected apps; existing Graph-only recipes remain frozen unchanged. Changed published hints take priority, followed by never-selected apps and then the oldest deep selections. A public last-selected-week ledger is independent of shallow token success, so successful clients can still receive deeper exploration. Selection history records scheduling, not completed assessment; interrupted work retries within its frozen week. Existing recipes retain their membership and plan hash when the ledger is added. Changed hints retain priority, so sustained changes exceeding the weekly budget can delay unchanged apps; selection history does not guarantee completion after interrupted weeks. Deep work does not make the shallow report more complete. Explicit target IDs are allowed only for Deep and remain bounded by its budget. If public sources provide no usable deep selection, planning fails clearly rather than silently expanding the budget.

## State and reports

The `discovery-data` branch must already be initialized. The final branch-writing job is the only job with `contents: write`; workers and the report publisher have read access and do not receive the branch-writing credential. Source code with credential access runs only from `main`, with pinned actions. Nora's passkey values, expected account fingerprints, and checkpoint key are repository **secrets**.

Public outputs are:

- `applications.json`: the validated public-source ledger.
- `weekly-shallow.json` / `weekly-deep.json`: frozen public recipes and aggregate batch checkpoints; DeepSelectionHistory in the deep state records public app IDs and their last selected ISO weeks.
- `coverage-shallow.json` / `coverage-deep.json`: completion, assessment/success counts, oldest/latest assessment dates, pending age, median/p95 batch duration, and estimated remaining runner seconds.
- `reports/YYYY-Www-mode.json`: prior-week aggregate reports.
- `scopes/chunk-NNNN.json`: validated anonymous successful scope evidence. Earlier successes retain their original observation dates after a new failure; old evidence does not become fresh merely because a batch completed.

Coverage schemas v2 and v3 separate `SourceCatalogApplications` (the frozen source snapshot) from `SelectedApplications` (this week's recipe). `PublishedApplications` remains a compatibility alias for the selected count. `PublishedCallbackCandidates` counts source IDs with callback hints, not tenant eligibility. Deep reports also expose `DeepSelectionHistoryApplications` and `NeverDeepSelectedCallbackCandidates`; these are selection history, not completed flow coverage. Both are null for shallow reports or legacy deep state without a ledger. Schema v3 adds the frozen `ResourceIds`, `SelectedPairs`, `AssessedPairs`, and `SuccessfulPairs`. An app counts as assessed only when every requested resource pair is handled; an app with any successful pair counts once. Pair counts are separate from flow cells. Readers still accept archived schema v1/v2 reports. Assessment includes structural exclusions; successful token observations do not prove JWT signature validity or API authorization.

Median/p95 estimates use completed batches in the current recipe, not an assumed constant cost per app. Pending age measures time since the recipe was created. Successful evidence freshness comes from the anonymous observations' dates. A green workflow may still report incomplete coverage, exhausted retries, or zero successful tokens. Completion means every frozen member was assessed, including structural exclusions.

## Private checkpoints and artifacts

Do not upload plaintext tenant inventories, sign-in summaries, flow diagnostics, tokens, cookies, or passkeys as artifacts from this public repository. [GitHub permits signed-in users with repository read access to download artifacts](https://docs.github.com/en/actions/how-tos/manage-workflow-runs/download-workflow-artifacts); artifact access is not a private data boundary.

Workers keep scope/flow diagnostics in a private temporary directory. A random 256-bit repository secret, `TOKENFORGE_CHECKPOINT_KEY`, encrypts diagnostic checkpoints with AES-GCM. Associated data binds the tenant fingerprint, principal fingerprint, recipe ID, and chunk. Credentials are never included. Ciphertext is uploaded separately with eight-day retention; public receipts/exports have one-day retention. The local key backup is outside Git with current-user-only permissions. Losing or rotating the key means old checkpoints cannot be resumed; their public successful evidence remains available.

The worker checks for a previous matching main-branch artifact and verifies its encryption context before import. It checkpoints around issuance, encrypts progress at least when a checkpoint boundary is reached after ten seconds, and stops at a 40-minute work budget before the 50-minute job timeout. Recognizable HTTP 429/5xx and sanitized transport failures leave interrupted flow slots for a later batch attempt. Other terminal OAuth failures remain diagnostic observations. Fully completed flow slots resume without issuance, while changed inventory/redirect recipes receive new flow-plan hashes.

Hard cancellation or runner loss can still discard the encrypted progress that has not yet reached artifact upload. The next invocation resumes the last uploaded checkpoint and may repeat later attempts. There is no promise of exactly-once remote token issuance. Credential disposal and plaintext cleanup run even if receipt output fails.

The separate [private maintenance workflow](private-maintenance.md) uses this encrypted-artifact boundary for inventory, configured grants, and sign-in summaries, with 15-day recovery retention. Persistent authoritative history should live in a dedicated private store; artifacts are transport and recovery snapshots. Service-principal creation requires a separate explicit administrative stage and is never part of scheduled token research. The current weekly workflow neither registers apps nor grants consent.

## Artifact storage

Standard public runner execution is free, but [artifact storage has a separate plan allowance](https://docs.github.com/en/billing/concepts/product-billing/github-actions). Public transport artifacts use one-day retention and encrypted research recovery uses eight days. Native validation runs on all supported platforms, while binary artifacts publish only from main pushes with one-day retention, avoiding duplicate branch/PR package retention. Monitor aggregate artifact size when adding private snapshots; encryption does not reduce their storage cost.

## Manual controls

Use workflow dispatch to choose 1–4 workers, Auto/Shallow/Deep mode, a bounded comma-separated Deep selection, or exhausted retry handling. A source or tenant change does not reorder a frozen recipe. A new UTC ISO week starts the next shallow recipe. Run reports before interpreting successful evidence as current or comprehensive.

Authentication remains PowerShell-based. The scheduled matrix uses one account. Shallow remains Graph-only; new deep recipes assess Graph and ARM. Both-account/local bounded proofs and offline tests provide additional validation; they do not establish all-app/all-resource/all-protocol coverage.

## Bounded validation on 2026-10-07

The [sanitized report](weekly-ci-validation-2026-10-07.json) covers local worker execution with Nora and secadmin. Each assessed four clients across two chunks with deeper callback/protocol exploration, producing 33 terminal flow attempts and four scope rows. Nora had three successful client/resource observations; secadmin had four. Encrypted checkpoint resumes added no attempts or scope rows. Anonymous export validation passed; no credentials or consent were persisted. A public-source planning pass froze 5,454 IDs into 55 chunks. Hosted worker artifact transport and one-writer publication subsequently completed the full frozen catalog: 5,454 IDs, 55 batches, no retried or exhausted batches, and 252 successful client observations for the tested account. The recipe hash and complete public-source membership were independently verified. Completion is shallow Graph assessment coverage, including structural exclusions; it is not universal token issuance or all-protocol/API authorization coverage.

## Native build artifact retention

After a successful main-branch native matrix, an isolated cleanup job keeps Linux, Windows, and macOS packages from the newest coherent successful main build. Cleanup jobs serialize. The script verifies the originating workflow and exact package names, enumerates all artifact pages before deleting, and leaves unfinished runs and newer artifacts untouched. A missing current package stops cleanup. Research checkpoints and private maintenance snapshots are excluded. Native packages also expire after one day; they are CI outputs, not durable releases.

For a local preview, run `./scripts/Remove-TokenForgeNativeArtifacts.ps1 -Repository nathanmcnulty/TokenForge -WhatIf`. Omit `-WhatIf` to apply the bounded cleanup. `CurrentRunId` is reserved for CI after all native matrix jobs succeed.

## Measured full-catalog cycle

The first complete hosted shallow discovery cycle used **149.6 runner-minutes** across 85 jobs (excluding private maintenance and code-validation workflows): 107.2 worker minutes, 19.88 preparation minutes, and 22.52 publishing minutes. Fifteen dispatched workflow invocations contributed 78.28 minutes of execution wall time; the observed cycle took 105.2 minutes including manual dispatch gaps. The first invocation used two workers; subsequent full batches used four. Ordinary four-worker scheduling needs 14 invocations for 55 batches. At four scheduled invocations per day, that fits within approximately 3.5 days, leaving the remainder of the week for retries and bounded deep work. GitHub scheduling delays and service throttling can extend this estimate.

The median assessment batch was 87.859 seconds; the 95th percentile was 114.195 seconds. Actual worker job time includes login, downloads, and uploads in addition to assessment. The [full cycle report](weekly-catalog-cycle-2026-10-07.json) identifies the frozen public recipe and records source commits, successful runs, and measured stages. These are observed execution minutes, not a billing statement or a guarantee about other repositories' quotas. Standard public hosted runners remain the intended deployment.

The shallow cycle's 252 successful observations are separate from its 5,454 assessed IDs. Deep mode has its own 100-application weekly budget and coverage report. Keep weekly shallow coverage exhaustive and deepen selected applications rather than multiplying every callback and protocol across the entire catalog without measurements.

## Hosted deep validation

Auto mode selected its separate 100-application recipe after shallow completion. Two invocations with two workers each completed four 25-ID batches without retries. There were 46 successful client observations; 69 clients had planned protocol cells and 31 received structural assessment without token probing. Decrypting all four account-bound checkpoints verified **767 terminal cells**: 347 OAuth 2.0 v2 PKCE attempts (210 native and 137 SPA), 210 v2 implicit attempts, and 210 v1 implicit attempts. Every planned cell had terminal evidence. Of those cells, 138 succeeded and 629 failed for this account/session. Rejection is an observed result, not proof that the application universally lacks the flow.

The deep invocations used 18.57 runner-minutes and 13.22 summed workflow wall minutes. Their 100 selected IDs are a subset of the 5,454 source-catalog IDs; deep completion does not mean the entire catalog has deeper coverage. Checkpoints stored no credentials, authenticated to the expected account context, and respected the four-callback budget. These attempts establish no API authorization or JWT signature-validation claim. The full-cycle JSON and the existing sanitized validation report include the protocol/mode totals and public run references.

## Code validation scheduling

PowerShell and native validation run on pull requests, main-branch pushes, and tag pushes. Feature-branch pushes are validated through their pull request, avoiding duplicate three-platform matrices for the same update. Pull-request validation keeps synthetic credentials; authenticated research workflows remain main-only. Successful main builds still publish packages and run bounded artifact cleanup.

## Multi-resource deep recipes

New deep recipes freeze Graph and Azure Resource Manager as separate resource targets. The 100-application budget therefore contains 200 app/resource pairs. An application counts once in successful application coverage even when both resources succeed; successful pair counts show that difference. All requested pairs must have an active assessment summary before a worker can claim completion. Earlier plan summaries cannot fill missing pairs, and decrypted checkpoints must match the frozen account, application partition, resource set, and flow cohort.

The [sanitized validation report](weekly-ci-validation-2026-10-07.json) includes bounded local module proofs for both accounts: four applications and eight pairs per account, with two callbacks and all three delegated protocols. Each account completed 48 terminal flow cells. Nora had three successful Graph pairs and one ARM pair; secadmin had four Graph and two ARM pairs. Exact and authenticated-encrypted resumes added no attempts or summary rows, and a foreign encryption context was rejected. These results describe the tested sessions; they do not establish API authorization or JWT signature validity. Existing weekly recipes keep their original Graph-only resources and plan hashes. New multi-resource hosted execution will begin with the next deep recipe.

Actual local CI worker execution then assessed the same four applications in two chunks per account using the production four-callback recipe. Each account produced eight active scope summaries and 66 terminal flow attempts. Nora completed three successful applications and four successful resource pairs; secadmin completed four and six, respectively. Encrypted checkpoint resumes added no attempts or rows, and resumed receipts preserved completion and all counters. Each account's two local chunks reused one passkey-derived cookie; every worker still performed fresh identity and inventory bootstrap. Hosted workers authenticate independently. This local execution is separate from the earlier hosted Graph-only cycle.

The local publisher accepted both accounts' live receipts and anonymous exports, emitted valid schema v3 reports with eight assessed pairs each, and left no pending work. Successful pairs were four for Nora and six for secadmin. The complete public-data allowlist validation passed; only aggregate results from these private proofs are included in the repository.

## Inspect weekly progress offline

Use a local checkout of the public `discovery-data` branch:

```text
tokenforge research weekly --state-path /path/to/discovery-data
tokenforge research weekly --state-path /path/to/discovery-data --json
```

The PowerShell entry point is `./scripts/tokenforge.ps1 research weekly -StatePath /path/to/discovery-data -Json`. No profile or login is required. The command reads the two frozen weekly recipe files, validates their hashes and coverage, and recomputes reports rather than relying on cached report files. It writes no files. Unrelated checkout files are not inspected or endorsed by this command.

Reports distinguish source catalog, selected applications, successful applications, and app/resource pairs. They include remaining applications/pairs, pending/exhausted batches, observation dates, and next-step guidance. An older recipe is marked `CurrentWeek=false`; refresh the checkout and inspect scheduling before assuming the current week has run. Future-week recipes and creation times more than five minutes ahead are rejected. Assessment includes structural exclusions, and successful token observations do not establish universal support or API authorization. The packaged native command uses its PowerShell adapter, so PowerShell 7.4+ is required.

Validation on 2026-10-07 matched the published snapshot through both entry points: 5,454 shallow assessments with 252 successful pairs, and 100 deep assessments with 46 successful pairs. The final packaged native read took 21.98 seconds on this Linux machine; this is one observed runtime, not a platform guarantee. All ten packaged weekly CLI cases and 32 expanded native adapter cases passed. The stable full suite passed 340 tests with two platform skips. See the [sanitized report](weekly-ci-validation-2026-10-07.json).

## Isolated hosted validation

Workflow dispatch supports `validation_only=true` with Deep mode and one to four explicit published app IDs. Use two workers for three or four IDs; one worker suffices for one or two. The coordinator creates a fresh runner-local data directory, copies only the public application ledger, and freezes Graph/ARM pairs into two-app chunks. It refuses existing weekly state. A schema v2 publication request marks the isolated route; normal publication rejects that request, and isolated publication rejects normal requests.

Each worker signs in independently with the existing Nora repository secrets, assesses its partition, then restores its encrypted checkpoint and checks that receipt completion/counts and flow/summary counts remain unchanged. The validation report is produced only if all validation workers and their resume checks succeed. The branch-writing job is skipped entirely, so this mode does not replace or extend the real weekly recipe. The read-only publisher uploads a `validation-report-<run-attempt>` aggregate artifact for eight days; encrypted checkpoints retain their existing account/plan/partition binding and eight-day retention. This proof creates no registrations or consent grants.

Normal runs now pass validated public files through a one-day artifact to a separate branch writer. That writer revalidates public files, requires a normal publication request and matching plan, checks the original data parent, and performs a fast-forward push. The additional job adds runner overhead beyond the earlier measured cycle; its cost has not yet been measured in a complete new weekly cycle.

Validation reports use an attempt-specific name so a failed rerun cannot look like a newly successful proof by retaining an earlier aggregate. Normal validated-data artifacts keep a stable name with overwrite enabled, allowing a failed branch writer to retry without rerunning successful workers; the original parent check still rejects stale publication.

## Hosted isolated multi-resource proof on 2026-10-08

[Run 37706314330](https://github.com/nathanmcnulty/TokenForge/actions/runs/37706314330) exercised the production workers on four explicit public applications and eight Graph/ARM pairs, using two independent Nora passkey logins. All eight pairs completed; three apps had successful observations across four pairs. Encrypted checkpoints contained 66 terminal attempts: 22 authorization-code/PKCE, 22 OAuth v2 implicit, and 22 OAuth v1 implicit. Each worker then resumed its completed checkpoint and verified zero added attempts or scope rows.

Independent artifact verification checked the frozen recipe, account and partition context, receipt schema/attempts, terminal flow cells, and anonymous exports against successful private observations. The read-only publisher succeeded, the branch writer was skipped, and the public catalog branch remained at `869d082aa3d248599a7a8533e76a93c76bcafde3`. The attempt-specific aggregate is `validation-report-1`. This bounded proof does not refresh the normal weekly recipe or establish JWT signature validity, API authorization, or exhaustive multi-resource support. See the [sanitized report](weekly-ci-validation-2026-10-07.json).

[Normal Auto run 37707708903](https://github.com/nathanmcnulty/TokenForge/actions/runs/37707708903) then verified the split publication path with completed weekly work: token workers were skipped, the read-only publisher succeeded, and the separate writer succeeded. All 60 published files matched the validated artifact byte for byte. The data commit `1fe876f4955384e546d38918f3dfda0bb347de3d` directly descends from the expected frozen parent, and the existing Graph-only deep recipe and plan hash remained unchanged. The run used 2.817 runner-minutes and performed no new matrix token work. This is one no-work invocation, not a revised full-week cost measurement.

The first normal attempt exposed an artifact-transport edge case: an empty `reports` directory was omitted and fixed directory staging failed. [PR #31](https://github.com/nathanmcnulty/TokenForge/pull/31) stages existing validated public files instead; Git-based absent/empty/populated-directory regression cases and the actual 60-file artifact passed before the successful hosted run.

A 2026-10-08 Actions API snapshot reported 176 unexpired artifacts totaling 221.18 MiB: 93.52 MiB of native packages, 56.98 MiB of encrypted recovery, and 70.69 MiB of other transport/test artifacts. These reported sizes describe that snapshot, not billed storage accrual, the account's remaining allowance, or weekly growth. Continue monitoring retention as research depth increases.

## Full local Graph/ARM production recipe on 2026-10-08

A frozen production recipe assessed 100 published applications and 200 Graph/ARM pairs
in four sequential local workers, each with a fresh Nora passkey login. All pairs completed,
with 51 successful applications across 73 pairs and 1,534 terminal flow attempts: 694 PKCE,
420 v2 implicit, and 420 v1 implicit. Each encrypted checkpoint resumed with zero new attempts
or scope rows, and both publication rounds accepted the receipts and anonymous exports.

The proof used immutable source commit `43d0b2fa426b2938706764ee4e7944e621a6f984` and the
published legacy 100-app selection, frozen into a new two-resource recipe. It created no
consent grants, persisted no credentials, and updated no public branch. Total local elapsed
time was 3,745.717 seconds (62.43 minutes). This is local sequential execution, not hosted
runner consumption or an estimate for all 5,454 applications. It establishes no JWT signature
validity or API authorization. See the sanitized validation report for per-worker timing.

## Publication when no token workers are selected

For a normal request with zero worker indices, the preparation job now invokes the same
publication validator before uploading the validated public files. It sets a readiness marker
only after the publication and public-data checks succeed. The separate publisher job and
prepared-data upload are skipped. The sole branch writer still validates the artifact and
requires the original data parent before pushing. Metadata refreshes and report generation
continue even without token issuance; exhausted batches still report incomplete coverage.

Worker runs retain their existing receipt-merging publisher. Isolated validation cannot take
the inline normal route or write the catalog branch. A failed prepare/upload, absent readiness
marker, unexpected worker selection, or stale parent prevents the inline route from writing.

The local proof used the actual public data snapshot with a completed 100-app legacy deep
recipe. It validated 60 public files, preserved all 55 scope files byte for byte and retained the
frozen plan, without credentials, a local commit, or a public branch update. Preparation took
93.154 seconds and publication plus validation 83.671 seconds on this machine. These are local
timings. The hosted effect must be measured after deployment; this removes a job and artifact
transfer rather than skipping the required metadata refresh.

## Coordinator validation performance

Frozen membership validation now indexes published GUIDs with case-insensitive hash membership,
while keeping recipe hashes, sorting, uniqueness, shallow completeness, and publication checks.
Preparation computes its coverage report once for persistence and return. Sol approved the change.
Three alternating local comparisons on the same 5,454-ID snapshot measured median state-validation
time of 9.985 seconds before and 6.905 seconds after. These are local function timings, not
complete workflow savings. Production publication preserved the frozen recipe and all 55 scope
files; 35 weekly tests and 327 offline tests passed, with 34 platform/package skips.
See the [sanitized report](weekly-ci-validation-2026-10-07.json).

## Hosted no-worker publication measurements

The inline publication path passed runs [37715412744](https://github.com/nathanmcnulty/TokenForge/actions/runs/37715412744)
and [37716208626](https://github.com/nathanmcnulty/TokenForge/actions/runs/37716208626). In each,
workers and the separate publisher were skipped, the writer succeeded, all 60 published files
matched the validated artifact, and all 55 scope files and the frozen recipe stayed unchanged.
Each data commit directly descended from its requested parent.

Those runs used 3.93 and 3.83 runner-minutes, compared with 2.82 and 2.93 for earlier
separate-publisher runs. No saving has been demonstrated. The source commits and live data
differed, and preparation time increased in code unchanged by the routing change. Measure
matched source/data fixtures before attributing the difference or claiming a hosted improvement.
These runs did no token matrix work and do not measure a complete new weekly cycle.

After the indexed membership/report reuse change, [run 37718137655](https://github.com/nathanmcnulty/TokenForge/actions/runs/37718137655)
passed the same publication checks and used 3.48 runner-minutes (169 seconds preparation,
40 seconds writer). This is one uncontrolled no-worker sample; it is not a complete weekly
cost or a controlled comparison of publication routes.
