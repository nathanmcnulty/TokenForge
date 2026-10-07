# Weekly research CI

The scheduled workflow refreshes public source metadata every six hours. It freezes a UTC ISO-week recipe containing **all published application IDs**, the public discovery snapshot, protocol bounds, and fixed chunk membership. It does not publish the tenant's eligible registration inventory. App IDs found only in private sign-in logs remain in the separate private maintenance catalog.

Four independently authenticated workers assess at most 100 published IDs each. Every selected ID must have an explicit fresh inventory record, including missing, disabled, or unverified entries. These structural results count as assessment coverage without token issuance. A successful token observation is a different measure: it describes what Entra issued for the tested account/session, not universal support or API authorization.

The coordinator chooses pending batches and failed batches with fewer than three attempts. Selection uses saved state, not GitHub run numbers. Failed or missing workers remain incomplete; an exhausted batch prevents a weekly complete claim. Manual `retry_exhausted` allows up to ten attempts. Each week starts a fresh shallow recipe and archives the prior aggregate report, including unfinished coverage. Late or repeated results cannot replace newer state: receipts bind the recipe, partition, and next attempt; publication checks the original data-branch parent and uses a normal fast-forward push.

After the shallow recipe completes, Auto mode spends a separate deep budget: at most 100 public candidates per week, 25 per batch, at most two workers, up to four callbacks, and all three implemented delegated protocols. Changed published hints take priority, followed by apps with no recent successful scope evidence. Stale selections rotate past the previous deep selection. Deep work does not make the shallow report more complete. Explicit target IDs are allowed only for Deep and remain bounded by its budget. If public sources provide no usable deep selection, planning fails clearly rather than silently expanding the budget.

## State and reports

The `discovery-data` branch must already be initialized. The publisher is the only job with `contents: write`; workers have read access and do not receive the publication credential. Source code with credential access runs only from `main`, with pinned actions. Nora's passkey values, expected account fingerprints, and checkpoint key are repository **secrets**.

Public outputs are:

- `applications.json`: the validated public-source ledger.
- `weekly-shallow.json` / `weekly-deep.json`: frozen public recipes and aggregate batch checkpoints.
- `coverage-shallow.json` / `coverage-deep.json`: completion, assessment/success counts, oldest/latest assessment dates, pending age, median/p95 batch duration, and estimated remaining runner seconds.
- `reports/YYYY-Www-mode.json`: prior-week aggregate reports.
- `scopes/chunk-NNNN.json`: validated anonymous successful scope evidence. Earlier successes retain their original observation dates after a new failure; old evidence does not become fresh merely because a batch completed.

Median/p95 estimates use completed batches in the current recipe, not an assumed constant cost per app. Pending age measures time since the recipe was created. Successful evidence freshness comes from the anonymous observations' dates. A green workflow may still report incomplete coverage, exhausted retries, or zero successful tokens. Completion means every frozen member was assessed, including structural exclusions.

## Private checkpoints and artifacts

Do not upload plaintext tenant inventories, sign-in summaries, flow diagnostics, tokens, cookies, or passkeys as artifacts from this public repository. [GitHub permits signed-in users with repository read access to download artifacts](https://docs.github.com/en/actions/how-tos/manage-workflow-runs/download-workflow-artifacts); artifact access is not a private data boundary.

Workers keep scope/flow diagnostics in a private temporary directory. A random 256-bit repository secret, `TOKENFORGE_CHECKPOINT_KEY`, encrypts diagnostic checkpoints with AES-GCM. Associated data binds the tenant fingerprint, principal fingerprint, recipe ID, and chunk. Credentials are never included. Ciphertext is uploaded separately with eight-day retention; public receipts/exports have one-day retention. The local key backup is outside Git with current-user-only permissions. Losing or rotating the key means old checkpoints cannot be resumed; their public successful evidence remains available.

The worker checks for a previous matching main-branch artifact and verifies its encryption context before import. It checkpoints around issuance, encrypts progress at least when a checkpoint boundary is reached after ten seconds, and stops at a 40-minute work budget before the 50-minute job timeout. Recognizable HTTP 429/5xx and sanitized transport failures leave interrupted flow slots for a later batch attempt. Other terminal OAuth failures remain diagnostic observations. Fully completed flow slots resume without issuance, while changed inventory/redirect recipes receive new flow-plan hashes.

Hard cancellation or runner loss can still discard the encrypted progress that has not yet reached artifact upload. The next invocation resumes the last uploaded checkpoint and may repeat later attempts. There is no promise of exactly-once remote token issuance. Credential disposal and plaintext cleanup run even if receipt output fails.

For a broader private maintenance workflow, use this same encrypted-artifact boundary for sanitized inventory/sign-in/registration metadata with short retention. Persistent authoritative history should live in a dedicated private store; artifacts are transport and recovery snapshots. Service-principal creation requires a separate explicit administrative stage and is never part of scheduled token research. The current weekly workflow neither registers apps nor grants consent.

## Manual controls

Use workflow dispatch to choose 1–4 workers, Auto/Shallow/Deep mode, a bounded comma-separated Deep selection, or exhausted retry handling. A source or tenant change does not reorder a frozen recipe. A new UTC ISO week starts the next shallow recipe. Run reports before interpreting successful evidence as current or comprehensive.

Authentication remains PowerShell-based. The scheduled matrix is Graph-only and uses one account. Both-account/local bounded proofs and offline tests provide additional validation; they do not establish all-app/all-resource/all-protocol coverage.

## Bounded validation on 2026-10-07

The [sanitized report](weekly-ci-validation-2026-10-07.json) covers local worker execution with Nora and secadmin. Each assessed four clients across two chunks with deeper callback/protocol exploration, producing 33 terminal flow attempts and four scope rows. Nora had three successful client/resource observations; secadmin had four. Encrypted checkpoint resumes added no attempts or scope rows. Anonymous export validation passed; no credentials or consent were persisted. A public-source planning pass froze 5,454 IDs into 55 chunks. This proof does not establish full-catalog completion or GitHub artifact transport; deployed workflow runs provide that next evidence level.
