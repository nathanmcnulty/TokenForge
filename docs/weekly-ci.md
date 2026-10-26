# Weekly research CI

GitHub Actions are disabled. All workflows are manual-only, and discovery accepts one Linux worker per invocation. Enabling or dispatching hosted work requires a new explicit instruction. Use [local discovery](discovery.md) to collect data without runner minutes or model quota; use [local validation](local-validation.md) for code checks. Windows, macOS, and additional architectures remain deferred. Native validation checks Linux x64 only; it does not upload packages or delete artifacts. Release publication remains a separate workflow.

“Weekly” describes the frozen research recipe, not an active schedule. Earlier schedules, worker counts, build matrices, and timing measurements are in the [history archive](history/weekly-ci.md). They do not describe the current execution policy or guarantee billing or throughput.

## How an approved run works

1. The coordinator reads the initialized `discovery-data` branch, refreshes public sources, and creates or resumes a UTC ISO-week recipe with fixed membership and protocol bounds.
2. It selects pending batches or failed batches with retry budget remaining. Selection uses saved state, not the GitHub run number.
3. The worker signs in independently, verifies account identity, collects fresh inventory, and assesses its partition. Missing, disabled, or ownership-unverified candidates receive structural assessment without token requests.
4. The publisher validates receipts, frozen membership, and anonymous successful observations. Workers and publishers have read-only repository access.
5. A separate writer with `contents: write` revalidates the public files, checks the original data-branch parent, and pushes a fast-forward update. A stale parent prevents publication.

Account-only sign-in discoveries belong to [private maintenance](private-maintenance.md), not the public recipe. Public sources can contain permission IDs or other GUIDs alongside app IDs. Recipe membership is candidate coverage, not proof of application identity or tenant eligibility. See the [identifier comparison](public-permissions.md#compare-identifiers-with-the-application-catalog).

## Modes and bounds

| Mode | Work |
| --- | --- |
| `Shallow` | Assess every candidate in the frozen public recipe for Graph, in batches of up to 100. |
| `Deep` | Assess up to 100 selected candidates per week, in batches of 25, with up to four callbacks and the three implemented delegated protocols. New recipes freeze Graph and ARM pairs. |
| `Auto` | Finish pending shallow work, then use the separate deep budget. |

Deep selection prefers changed published hints, then never-selected candidates, then older selections. Its public selection ledger records scheduling, not completed assessment. Existing recipes keep their membership, resource set, and hash. A source refresh does not silently reorder a frozen recipe. A new ISO week starts a new shallow recipe and archives the previous aggregate report, including unfinished coverage.

Manual controls select the mode, optional explicit published IDs for a new deep recipe, and `retry_exhausted`. The current workflow restricts `workers` to `1`. Normal batches allow three attempts; deliberate exhausted-retry handling raises the limit to ten. Exhausted or missing batches prevent a complete coverage claim.

`validation_only` is an isolated Deep proof without a data-branch update. With the current single-worker configuration, keep its explicit selection to one or two IDs. The underlying tooling also supports larger isolated proofs, but their prior multi-worker configuration is not enabled here.

## Read progress without authentication

Use a local checkout of `discovery-data`:

```text
tokenforge research weekly --state-path /path/to/discovery-data --json
```

The PowerShell entry point is:

```powershell
./scripts/tokenforge.ps1 research weekly -StatePath /path/to/discovery-data -Json
```

These commands require no Entra login or profile. They validate frozen recipe hashes and recompute reports without writing files. The native CLI runs without PowerShell; the script entry point requires PowerShell 7.6+. Old-week recipes report `CurrentWeek=false`. Future-week recipes and creation times more than five minutes ahead are rejected. The command does not inspect or endorse unrelated checkout files.

Public outputs distinguish:

- `applications.json`: the public-source metadata ledger.
- `weekly-shallow.json` and `weekly-deep.json`: frozen membership and aggregate batch checkpoints.
- `coverage-shallow.json` and `coverage-deep.json`: selected and assessed candidates/pairs, successes, pending or exhausted batches, observation dates, and timing estimates.
- `reports/`: archived weekly aggregate reports.
- `scopes/`: anonymous successful observations with their original dates.

A green workflow can still leave incomplete coverage or zero successful tokens. Completion means all frozen members were assessed, including structural exclusions. Success means observed issuance for the tested account and request; it does not establish universal support, JWT signature validation, or API authorization. Pair counts, unique candidate counts, and individual protocol cells measure different things.

## Recovery and privacy

Artifacts from this public repository are accessible to repository readers. Never upload plaintext tenant inventory, private flow diagnostics, sign-in summaries, cookies, tokens, passkeys, or encryption keys.

Nora's passkey values, expected account fingerprints, and `TOKENFORGE_CHECKPOINT_KEY` belong in repository **secrets**. Credential-bearing source executes only from `main`. Workers keep diagnostics in private temporary directories and upload only AES-GCM-encrypted checkpoints, bound to the tenant, principal, recipe, and chunk. Credentials are excluded.

Encrypted research checkpoints and public recipe bundles retain eight days; worker results and prepared/validated data bundles retain one day. Isolated validation reports retain eight days. Workers verify matching checkpoint context before import. A 40-minute work budget leaves time before the 50-minute worker timeout. Recognized transient identity failures retain pending work; completed flow cells resume without issuance. Changed inventory or callbacks can create new flow-plan hashes.

Runner loss can discard progress not yet uploaded, so later attempts may repeat work. There is no exactly-once issuance guarantee. Credential disposal and temporary plaintext cleanup run on normal failure paths. Keep a separate protected backup for durable history; artifact retention is not a database. Private maintenance uses a separate account-bound context and 15-day retention.

## Measure usage locally

The usage workflow is also manual-only. To read the same Actions metadata locally with an authenticated GitHub CLI:

```powershell
./scripts/Get-TokenForgeCiUsage.ps1 -WeekStart '2026-10-05T00:00:00Z' |
    ConvertTo-Json -Depth 10 | Set-Content discovery-usage.json
```

This reads run, job, and artifact metadata; it does not log in to Entra, download logs or artifact contents, or modify the catalog. It counts completed physical jobs once across all available attempts for runs created in the selected half-open UTC week. Failed and cancelled jobs contribute duration; queues, skipped jobs, and unfinished work do not. A current week or unfinished jobs make the observation incomplete.

Measured runner seconds are not invoice minutes. Current unexpired artifact bytes are not historical storage accrual, total repository storage, or a billing estimate. Deleted or expired history cannot be reconstructed. Use the report alongside actual account billing and catalog coverage; neither usage completion nor older timing samples prove that a weekly catalog cycle is complete.

## Validation evidence

The [weekly validation report](weekly-ci-validation-2026-10-07.json), [catalog cycle report](weekly-catalog-cycle-2026-10-13.json), and [usage observation](weekly-usage-observation-2026-10-13.json) record bounded historical evidence. Detailed run references and older measurements remain in the [history archive](history/weekly-ci.md). No historical result authorizes another hosted run.
