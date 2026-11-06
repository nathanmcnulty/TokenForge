# Public metadata health and workstation sync

This lane refreshes public application/resource candidates and imports their evidence into a workstation catalog. It does not sign in, inspect private tenant inventory, issue tokens, grant consent, or start account research. Public catalog claims do not prove ownership, consent, issuance or API acceptance. Goal 6's original-ZIP interoperability experiment remains parked behind its existing refusal gates.

The supported runtime is PowerShell 7.6.7 on Linux x64. Entry points verify the accepted native executable and core-library hashes; collection never builds or installs a replacement. Package source and compilation source are recorded separately. `New-TokenForgePublicHealthPackage.ps1 -AcceptedPackagePath` can refresh source over the accepted offline-v1 package only after verifying its pinned manifest, every payload, and both complete compilation-input inventories. No native rebuild is implied. This flow uses ordinary artifact transfer and local SQLite independently of the older publication research.

## Local loop

Use an unpacked, verified package and its own scripts. Select an unused exchange path for every collection. The manifest revision identifies the code actually executed; do not substitute an unrelated checkout's HEAD. Source-checkout use requires independently checking its executed files against that package.

```powershell
$package = (Resolve-Path ./linux-x64).Path # unpacked reviewed package
Set-Location $package
$native = Join-Path $package tokenforge
$revision = (Get-Content ./public-health-package.json -Raw | ConvertFrom-Json).sourceRevision
$state = Join-Path $HOME '.local/share/TokenForge/health-state'
$null = [IO.Directory]::CreateDirectory($state, [IO.UnixFileMode]448) # 0700
$exchangeRoot = Join-Path $state exchanges
$null = [IO.Directory]::CreateDirectory($exchangeRoot, [IO.UnixFileMode]448)
$exchange = Join-Path $exchangeRoot 'public-health-001'
```

Run the bounded collection after authorizing public network access, then import,
inspect status and look up saved applications. For offline source-checkout use,
add `-FixturePath tests/fixtures/public-health` to collection instead.

```powershell
pwsh -NoProfile scripts/tokenforge.ps1 health collect `
  -OutputPath $exchange -SourceRevision $revision -NativeExecutablePath $native -MaxSeconds 180 -Json

pwsh -NoProfile scripts/tokenforge.ps1 health sync `
  -ExchangePath $exchange -StatePath $state -NativeExecutablePath $native -Json

pwsh -NoProfile scripts/tokenforge.ps1 health status `
  -StatePath $state -NativeExecutablePath $native -Json

pwsh -NoProfile scripts/tokenforge.ps1 health lookup `
  -StatePath $state -NativeExecutablePath $native -Name 'Office' -Limit 20 -Json
```

For an authorized real public collection, omit `-FixturePath` and use a new output path. Add `-MaxSeconds 180` for a smaller cooperative deadline (maximum 600 seconds). Collection uses at most six anonymous HTTPS requests to the three fixed sources, with no account or GitHub credential inference. Pass `-PreviousExchangePath` with the preceding validated exchange to preserve public history and meaningful empty-snapshot transitions. Keep immutable exchanges locally; artifact retention is not a backup. Checked-in test fixtures are source-checkout examples and are not required for a real packaged run.

```powershell
# Run only when public network collection has been authorized.
pwsh -NoProfile scripts/tokenforge.ps1 health collect `
  -OutputPath ./public-health-exchange-002 -PreviousExchangePath $exchange `
  -SourceRevision $revision -NativeExecutablePath $native -Json
```

The producer returns collection completeness separately from exchange completion, import completion and operational publication. An incomplete collection can produce a valid exchange; inspect its health summary rather than treating file creation as complete collection.

## Sources, evidence and limits

Exactly three approved source URLs are supported; submitted metadata cannot add a URL or enlarge the request plan:

| Source | URL |
| --- | --- |
| ROADtools | `https://raw.githubusercontent.com/dirkjanm/ROADtools/master/roadtx/roadtools/roadtx/firstpartyscopes.json` |
| Microsoft applications | `https://raw.githubusercontent.com/merill/microsoft-info/main/_info/MicrosoftApps.json` |
| Resource candidates | `https://raw.githubusercontent.com/f-bader/entrascopes.com/main/resources.json` |

The narrow health HTTP helper streams capped bytes for both fixed public sources and the later binary artifact download. The general collector source helper currently buffers up to 128 MiB and returns text, so this lane keeps that account-collector path unchanged. It reuses the existing source projections, complete catalog policies and transactional importer, with the same reserve-before-dispatch/no-redirect budget rules; it adds no generic dispatcher or account collection envelope.

Collection permits at most six HTTP requests, at most two attempts per source, 30 seconds per request and a 600-second cooperative acceptance budget. The timer starts after runtime initialization and previous-exchange validation. Network waits are cancelled against the request and remaining budgets; synchronous source projection and validation are checked between steps and are not preempted mid-step. The proposed ten-minute job timeout is a separate outer limit. Retries consume that same allowance. There is no recursive URL discovery, redirect following, identity request or automatic extra source. Schema-invalid data does not receive a transient retry.

Each source document is limited to 8 MiB and 10,000 source records; the combined catalog is limited to 30,000 application IDs. The validated public ledger is limited to 64 MiB, health summary to 64 KiB and manifest to 16 KiB. Complete-input validation checks schema, IDs, source references, counts and public evidence structure before import. Published GUID case is accepted through the existing canonical projection; unknown owner hints remain unknown, and explicit zero-ID placeholders are excluded. Malformed ID suffixes, whitespace repairs and conflicting IDs after canonicalization are refused, not silently corrected or discarded. It rejects unexpected private fields; it does not prove upstream claims true or make arbitrary free text safe to publish.

The exchange contains exactly `manifest.json`, `health.json` and `metadata.json`. Manifest member hashes and byte counts must match. Hosted context includes repository, repository/workflow/run IDs, attempt, event, source SHA and branch; local fixture exchanges cannot claim hosted provenance. Source raw-response hashes remain retrieval evidence. Raw source responses are not retained in the exchange.

All three sources must succeed before producing a new combined catalog snapshot. On a partial or failed pass, the previous full `metadata.json` is retained byte for byte, including its original dates. Successful individual source retrievals still receive their own health dates/hashes; these do not freshen retained catalog facts. Without a previous exchange, partial collection carries a valid empty ledger and no invented complete date.

A complete empty pass with a previous ledger records explicit absence/tombstones in that public history. An initial empty exchange without a history chain cannot erase omitted records already in the workstation's destination. Ordinary imports merge incoming history; they do not infer destination-wide deletions from omissions.

## Private state and recovery

Standalone hosted snapshots have no previous exchange. Imports are additive: omissions in an unlinked complete snapshot do not create destination-wide tombstones. Linked complete history can represent absence. Older distinct payloads are retained as deduplicated history while newer current values and freshness stay current.

The workstation owns `applications.sqlite`, including its private origins/history. Public import validates the entire incoming public ledger before merging; it does not redact or apply the public-only validator to the mixed private destination. Existing frozen inventory, cohort, plan, scope and flow evidence remain in place. Public drift does not resume research or replace a plan. Compare saved cohort context before new deep work; using changed metadata requires explicitly selecting a new plan, while old checkpoints remain available for their original exact-plan resume.

Sync holds the state's `.writer.lock` and the catalog's `applications.sqlite.lock`. A competing writer causes a clean refusal. Native import uses its existing transaction and run-identity deduplication, preserving private namespaces and preventing older facts from replacing newer ones.

Validated exchange members are staged under `public-health-receipts/<manifest-sha256>/exchange/`, with an immutable import receipt beside them. `public-health-pending.json` records an import needing reconciliation. An interruption before commit preserves the prior SQLite state; an interruption after commit but before receipt completion is recovered by repeating the identical, idempotent import. Retry sync to reconcile pending evidence before accepting another exchange. Do not remove locks or pending evidence to force a retry around a running writer. Uncommitted partial staging can be repaired; completed receipts are reused.

Status reads bounded saved receipts without projecting the full SQLite history or fetching anything. It separates transfer, import and collection states, retains the original `lastCompleteAt`, reports stale collection after 48 hours, and flags a collection-history gap when complete observations are over 14 days apart. A gap remains visible; fetching a later snapshot does not invent the missing observations. `pendingDeepWork=Unassessed_ExistingPlansPreserved` is an explicit limit: the health loop does not calculate or run an account-specific research plan. Publication remains `NotRequested`.

Status also reports the latest exchange's three source statuses and last-success dates. These never advance the overall last-complete time. Legacy receipts have an empty `sources` list until a new exchange is imported. `catalog=Present_NotVerified` means only that the SQLite file exists; saved completion is not a fresh database integrity check. A deleted catalog reports `Missing`.

`health lookup` searches current saved Discovery records by literal, case-insensitive name or exact `-AppId`. It ignores Inventory-only records and never substitutes tenant names for Discovery names. Because ordinary local discovery shares that catalog namespace, output is explicitly `PrivateWorkstationOutput` / `SavedDiscoveryMetadata`, not certified public-health provenance or publishable evidence. Scope hints remain metadata with token availability `Unverified`. Name searches use the existing bounded full-current-catalog export (128 MiB/60-second native limit); `-Limit` caps returned rows at 1–100, while exact AppId uses the native selector. Lookup performs no authentication, token check or write. An initial incomplete exchange can legitimately return zero matches; it never invents a complete catalog from the successful sources alone.

Use existing SQLite-aware maintenance/backup commands for private backups. Do not copy a live database/WAL as an ordinary file or commit private state, receipts, profiles or downloaded diagnostics into this public repository.

## Named GitHub transfer, after approval

The normal artifact path is implemented and tested with fake transfers. It remains subject to explicit hosted/credential authorization. Supply a named trusted run and independently selected repository/workflow/source pins:

```powershell
# Example shape only: replace every placeholder with reviewed public run metadata.
pwsh -NoProfile scripts/tokenforge.ps1 health sync `
  -Repository 'OWNER/REPOSITORY' -RepositoryId 'REPOSITORY_ID' `
  -WorkflowId 'WORKFLOW_ID' -RunId 'RUN_ID' `
  -SourceRevision 'EXACT_40_CHARACTER_LOWERCASE_COMMIT_SHA' -SourceBranch 'TRUSTED_BRANCH' `
  -StatePath $state -NativeExecutablePath $native -Json
```

Sync independently checks completed/successful run metadata, same repository/head repository, workflow ID, `workflow_dispatch` or `schedule`, exact source SHA and branch. It requires exactly one unexpired artifact named `tokenforge-public-health`; paginated/ambiguous selection is refused. Only run attempt 1 is supported. Later attempts are refused because a manifest's attempt is not independent proof of the artifact's own attempt.

Transfer allows four GETs, no retries, 30 seconds per request and a 180-second cooperative transfer acceptance budget, including extraction/validation checks between synchronous steps; those steps are not preempted mid-step. The fourth request can follow one approved HTTPS artifact-service redirect; authorization is removed before following the capability URL. GitHub REST requests use a fixed User-Agent. Native local import retains the existing 60-second timeout per native call, separately from the transfer deadline.

The downloaded ZIP and expanded aggregate are each limited to 67,190,784 bytes (64 MiB plus the 64 KiB health and 16 KiB manifest allowances). Each member is also bounded; metadata cannot exceed 64 MiB. Exactly the three expected regular-file members are accepted, with no traversal, duplicate member, link or unexpected file. Downloaded members are never executed. This product verifies member bytes, hashes and schemas. It does not require the outer GitHub service ZIP to equal a producer-created archive; that is the separate parked Goal 6 contract. A service digest warning alone is not an acceptance gate.

Anonymous public requests are attempted by default. If GitHub requires authorization, sync reports `ExplicitReadAuthorizationRequired` rather than reading environment variables, running a login or obtaining a token. A future separately authorized caller may supply `-GitHubToken` as an explicit `SecureString`; do not place credentials in command history, files or logs. No credential is provisioned by this milestone. Failed transfer receipts contain a sanitized fixed reason, while bounded downloaded bytes remain private for diagnosis; they are never executed or accepted as successful imports.

## Metadata contributions

Contribution validation is a separate quarantine/report operation. It does not fetch submitted URLs, import a catalog, or authorize collection. The input is at most 1 MiB, containing one application ID and up to 32 existing source claims. For example:

```powershell
pwsh -NoProfile scripts/tokenforge.ps1 health contribution `
  -ContributionPath ./proposed-public-claims.json -ExchangePath $exchange `
  -NativeExecutablePath $native -Json
```

Use the existing `DiscoverySourceClaims` shape (`SourceName`, public `Location`, `Evidence`, and supported attributes). The report retains source references, conflicts and the input hash, labels the result `Quarantined`, and lists ownership, consent, issuance and API acceptance as proof still needed. An optional supplied exchange supports claim comparison; a match does not promote the contribution to tenant/account proof. Review tool changes and metadata claims before admitting them to trusted source.

## Dormant hosted workflow and separate approval

`.github/workflows/public-metadata-health.yml` is registered as workflow `395612174`; its only job remains unconditionally `if: false` and it has no schedule. PR #125 corrected its Bash/PowerShell shell syntax. Its existing delivery pins describe an older package and must be reconciled with the selected source before any new hosted execution. Its target is one Linux job, no matrix, 600 seconds total and 480 seconds for collection, pinned standard actions, normal artifact tooling, read-only repository permissions, explicit three-file upload and a 14-day artifact-retention request. There are no Entra secrets, identity-token permission, repository data writes, custom artifact-service adapter or settings controller in this lane.

Before a trial, review the exact source and matching package's public delivery, supported runner/runtime versions, default-branch/workflow registration change, permissions and relevant existing automation. Then obtain explicit approval for one bounded public-only hosted manual job and its public three-file output. Existing approval to push sanitized source does not authorize hosted execution, credentials, operational publication, workflow registration, merge or activation. Do not re-enable the old credentialed discovery workflow.

A proposed stop procedure is to cancel the named trial, disable its workflow, retain already downloaded private evidence and report incomplete work. No such setting change has been performed here. A daily schedule is a later decision after a successful approved trial; it is not enabled or guaranteed by offline acceptance.

The decision-ready manual-trial proposal is in `public-metadata-health-manual-trial.md`. Offline acceptance does not establish fresh upstream completeness, hosted artifact interoperability or Goal 6 production completion.
