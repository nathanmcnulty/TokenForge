# Weekly research CI

The scheduled workflow refreshes public source metadata every six hours. It freezes a UTC ISO-week recipe containing **all published application IDs**, the public discovery snapshot, protocol bounds, and fixed chunk membership. It does not publish the tenant's eligible registration inventory. App IDs found only in private sign-in logs remain in the separate private maintenance catalog.

Four independently authenticated workers assess at most 100 published IDs each. Every selected ID must have an explicit fresh inventory record, including missing, disabled, or unverified entries. These structural results count as assessment coverage without token issuance. A successful token observation is a different measure: it describes what Entra issued for the tested account/session, not universal support or API authorization.

The coordinator chooses pending batches and failed batches with fewer than three attempts. Selection uses saved state, not GitHub run numbers. Failed or missing workers remain incomplete; an exhausted batch prevents a weekly complete claim. Manual `retry_exhausted` allows up to ten attempts. Each week starts a fresh shallow recipe and archives the prior aggregate report, including unfinished coverage. Late or repeated results cannot replace newer state: receipts bind the recipe, partition, and next attempt; publication checks the original data-branch parent and uses a normal fast-forward push.

After the shallow recipe completes, Auto mode spends a separate deep budget: at most 100 public candidates per week, 25 per batch, at most two workers, up to four callbacks, and all three implemented delegated protocols. Changed published hints take priority, followed by never-selected apps and then the oldest deep selections. A public last-selected-week ledger is independent of shallow token success, so successful clients can still receive deeper exploration. Selection history records scheduling, not completed assessment; interrupted work retries within its frozen week. Existing recipes retain their membership and plan hash when the ledger is added. Changed hints retain priority, so sustained changes exceeding the weekly budget can delay unchanged apps; selection history does not guarantee completion after interrupted weeks. Deep work does not make the shallow report more complete. Explicit target IDs are allowed only for Deep and remain bounded by its budget. If public sources provide no usable deep selection, planning fails clearly rather than silently expanding the budget.

## State and reports

The `discovery-data` branch must already be initialized. The publisher is the only job with `contents: write`; workers have read access and do not receive the publication credential. Source code with credential access runs only from `main`, with pinned actions. Nora's passkey values, expected account fingerprints, and checkpoint key are repository **secrets**.

Public outputs are:

- `applications.json`: the validated public-source ledger.
- `weekly-shallow.json` / `weekly-deep.json`: frozen public recipes and aggregate batch checkpoints; DeepSelectionHistory in the deep state records public app IDs and their last selected ISO weeks.
- `coverage-shallow.json` / `coverage-deep.json`: completion, assessment/success counts, oldest/latest assessment dates, pending age, median/p95 batch duration, and estimated remaining runner seconds.
- `reports/YYYY-Www-mode.json`: prior-week aggregate reports.
- `scopes/chunk-NNNN.json`: validated anonymous successful scope evidence. Earlier successes retain their original observation dates after a new failure; old evidence does not become fresh merely because a batch completed.

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

Authentication remains PowerShell-based. The scheduled matrix is Graph-only and uses one account. Both-account/local bounded proofs and offline tests provide additional validation; they do not establish all-app/all-resource/all-protocol coverage.

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
