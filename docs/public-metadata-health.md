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
$previous = $exchange
$exchange = Join-Path $exchangeRoot 'public-health-002'
pwsh -NoProfile scripts/tokenforge.ps1 health collect `
  -OutputPath $exchange -PreviousExchangePath $previous `
  -SourceRevision $revision -NativeExecutablePath $native -MaxSeconds 180 -Json
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

Each source document is limited to 8 MiB and 10,000 source records; the combined catalog is limited to 30,000 application IDs. The validated public ledger is limited to 64 MiB, health summary to 64 KiB and manifest to 16 KiB. Complete-input validation checks schema, IDs, source references, counts and public evidence structure before import. Published GUID case is accepted through the existing canonical projection; unknown owner hints remain unknown, and explicit zero-ID placeholders are excluded. Canonical candidates still reject malformed ID suffixes and conflicting IDs after canonicalization. The MicrosoftApps boundary adaptation below accounts explicitly for documentation-only exclusions before those unchanged checks. It rejects unexpected private fields; it does not prove upstream claims true or make arbitrary free text safe to publish.

### MicrosoftApps consumer adaptation

This consumer does not depend on upstream fixes. Health schema 2 adds `adaptation` to every source observation: null except for a successfully processed MicrosoftApps source. The manifest and metadata schemas remain unchanged. The reader accepts exact schema-1 exchanges for retained history; older readers cannot read schema 2, so refresh producer and workstation scripts together. Dormant hosted delivery pins still refer to the previously reviewed package and are not activated or updated by this change.

The `MicrosoftAppsEntraDocsV1` policy checks every raw row's exact fields, types, owner identity and public text, including rows that will be excluded. All AppId strings are bounded to 128 characters and pass the public-text guard. For exact `Source: EntraDocs` only, a strict hyphenated GUID after surrounding-whitespace removal is normalized to lowercase. Other source IDs retain the strict published spelling contract (case is normalized after validation). Braces, compact GUIDs and arbitrary character removal are not repair strategies. A malformed documentation ID is quarantined, never guessed into an application ID. Malformed non-documentation identities, unsafe text, invalid owners, schema drift and normalized duplicate AppId/Source identities reject the whole source without a schema retry.

Each successful report binds to the **raw response SHA-256** and satisfies:

`rawRecordCount = admittedRecordCount + zeroIdPlaceholderCount + quarantinedRecordCount`

`normalizedRecordCount` counts changed spellings among admitted rows only. Valid zero GUIDs remain explicit placeholders, not candidates; duplicates involving zero IDs are still refused. Each quarantine record contains only its zero-based source-array index, fixed `ApplicationIdentity` reason and `recordSha256`. That hash is SHA-256 over UTF-8, compact `ConvertTo-Json -Depth 5` of the original parsed row in its original property order, without a BOM or trailing newline. It is a **parsed-row JSON hash**, not a raw response byte-slice hash. The original source hash is authoritative for exact input bytes. The policy permits at most 128 quarantine records; a 129th rejects the source without truncation. Existing 8 MiB/10,000-row input and 64 KiB final health-file limits remain enforced.

Only admitted rows reach the unchanged canonical validator and actual source-claims projection. Successful source status means that the entire bounded document was processed and accounted for; it does not mean every upstream row is an admitted application. `complete` means all three sources were successfully processed into a complete snapshot of **admissible public candidates**, with exclusions visible in the report. It does not mean every Microsoft application is known or accessible, nor that every dictionary GUID is an app. Documentation SKU/AAGUID values remain descriptive `PublishedEntraDocs` candidates; existing tenant-resolution/proof requirements remain intact. No scopes, access or ownership are inferred from the adaptation.

Exclusions are not silently copied into metadata. If a previously admitted candidate becomes inadmissible and no other source retains it, a subsequent complete snapshot records ordinary absence from the admitted catalog, not tenant/application deletion. Failed source validation or projection retains the previous metadata bytes and complete date. Accounting from a rejected projection is cleared instead of being attached to the retained older source hash. Both original snapshots and quarantine receipts should be retained locally for investigation.

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

`.github/workflows/public-metadata-health.yml` is registered as workflow `395612174`; its only job remains unconditionally `if: false` and it has no schedule. PR #125 corrected its Bash/PowerShell shell syntax. The delivery pins now select the approved code-only `public-health-e2e-1d6617e` prerelease below; executed module/health source must still match checkout bytes before a future run. Its target is one Linux job, no matrix, 600 seconds total and 480 seconds for collection, pinned standard actions, normal artifact tooling, read-only repository permissions, explicit three-file upload and a 14-day artifact-retention request. There are no Entra secrets, identity-token permission, repository data writes, custom artifact-service adapter or settings controller in this lane.

Before a trial, review the exact source and matching package's public delivery, supported runner/runtime versions, default-branch/workflow registration change, permissions and relevant existing automation. Then obtain explicit approval for one bounded public-only hosted manual job and its public three-file output. Existing approval to push sanitized source does not authorize hosted execution, credentials, operational publication, workflow registration, merge or activation. Do not re-enable the old credentialed discovery workflow.

A proposed stop procedure is to cancel the named trial, disable its workflow, retain already downloaded private evidence and report incomplete work. No such setting change has been performed here. A daily schedule is a later decision after a successful approved trial; it is not enabled or guaranteed by offline acceptance.

The decision-ready manual-trial proposal is in `public-metadata-health-manual-trial.md`. Offline acceptance does not establish fresh upstream completeness, hosted artifact interoperability or Goal 6 production completion.

## Observed end-to-end result

The current reconciliation reused the accepted offline-v1 binaries after all 267
payloads, 265 source mappings and complete 100 CLI / 47 credential compilation
inputs were checked. Operator additions are source overlays, not native rebuilds.
The older hosted producer at `04e89350b74e1a600c233aa43572a80a6f3ea642` also
matches all 93 executed module/health source paths in its retained package from
`c7d0b255612280e05605eca2e9ccfb44d5d68e18`; all 166 old payloads were verified.

One fresh credential-free local collection used three requests in 48.71 seconds
(180-second/six-request ceiling): ROADtools and resources succeeded; MicrosoftApps
remained Invalid. A separate single-request current-input diagnostic reproduced
`ApplicationIdentity` at zero-based row 2230 of 4459: a valid GUID prefix plus two
extra characters including non-ASCII whitespace. It is the same malformed value
as the prior diagnostic, not proof of the historical hosted response's exact cause.
No trimming, repair or row dropping was performed. The resulting exchange is
valid but incomplete, with null last-complete date and zero catalog applications.

After anonymous artifact download was refused, Nathan explicitly approved one
read-only transfer using the existing GitHub sign-in. The normal named-run sync
validated run `40161542664`, attempt 1, workflow `395612174`, and artifact
`12586302492`. The retained original ZIP is 1472 bytes, SHA256
`944b5ac4d1632f72b423c7abde37c7d86e07e2855b8be01b5a06474774129618`, with exactly
the three public exchange members. The existing four-GET/180-second transfer cap
was enforced; the implementation does not persist the actual request count.
No new hosted job or package publication was needed.

Both real exchanges imported successfully into a private workstation. Local
repeat import left SQLite bytes unchanged and preserved the newer source dates.
Real lookup truthfully returns zero matches. A separate explicitly synthetic
packaged collect/import/name-lookup walkthrough returned three fixture matches;
those are not live catalog coverage. Focused import/recovery tests retain older
evidence, last-success, locks, pending-import replay, private origins and frozen
plans. Raw inputs, artifact ZIP, receipts and test reports remain local.

Fresh complete application results still require a valid MicrosoftApps source or
a previously accepted complete exchange. Any future hosted activation still
requires approval; the completed trial and code-package publication are recorded
below. #113, #115 and
#116 remain open; this practical flow does not satisfy their production acceptance
by implication.

## Fresh current-package runner-to-workstation trial

After explicit approval, the existing archive from package source
`1d6617e6f724fc27fc6e7e64b3ea3dbd407b7168` was published as the single asset in
[the code-only prerelease](https://github.com/nathanmcnulty/TokenForge/releases/tag/public-health-e2e-1d6617e).
`TokenForge-public-health-linux-x64.tar.gz` is 33,936,560 bytes, SHA256
`3e396f3486b9671ba5a71b6afd53a0e7a869fcb466e428beea30df596923446f`.
The uploaded asset API digest/size matched. No historical asset was replaced or
marked latest, no native binary was rebuilt, and no private evidence was released.

One manual [run 42266672386](https://github.com/nathanmcnulty/TokenForge/actions/runs/42266672386)
at workflow source `6ab34622928b500f068984f75153b17c5fc2a9d8`, attempt 1, passed.
The job verified PowerShell 7.6.7/Linux x64, the package source/hash and all 94
executed module/health source files against checkout. Its sole permission was
contents-read. Source GETs: three, 34.453 seconds. ROADtools (506 candidates) and
resources (1753) succeeded; MicrosoftApps was Invalid after one attempt. The
precise hosted refusal cause is not recorded; the earlier private current-input
diagnosis is separate evidence. Collection remains incomplete, with zero catalog
candidates and null last-complete date. Job/upload success does not change that.

The normal receiver transferred artifact `13526823949` from that named run:
1467 bytes, SHA256
`309876960dc29a1698b9117bb1257ee5648298fbffe8db421c061547c6cd3c64`, exactly
`manifest.json` (795 bytes), `health.json` (1304) and `metadata.json` (227).
It independently checked run/repository/workflow/source/attempt, all member
hashes/schema and exchange context, then imported into the private workstation.
The four-GET/180-second receiver cap applied with no retry; actual transfer request
count is not separately persisted. Authorization was supplied explicitly from the
approved existing GitHub sign-in, never to the artifact-service redirect.

For that named run, after explicitly authorizing an existing read credential:

```powershell
# $approvedReadToken is an explicitly supplied SecureString; never log/store it.
& ./scripts/tokenforge.ps1 health sync `
  -Repository nathanmcnulty/TokenForge -RepositoryId 1402673320 `
  -WorkflowId 395612174 -RunId 42266672386 `
  -SourceRevision 6ab34622928b500f068984f75153b17c5fc2a9d8 `
  -SourceBranch codex/public-health-current-trial `
  -StatePath $state -NativeExecutablePath $native -GitHubToken $approvedReadToken -Json
```

The imported files match the retained ZIP byte for byte. Local repeat import used
zero network requests and preserved SQLite SHA256 exactly. Status reports
transfer/import Complete, collection Incomplete, stale true, null lastCompleteAt
and the successful sources' new dates. Real name and AppId lookup each return
zero; three nonempty fixture matches remain separately labeled synthetic proof.
The artifact's requested retention is 14 days; local immutable receipts preserve
import evidence after service expiry.

Independent review directly inspected the API records, real ZIP, immutable
exchange, job log and repeat/status/lookup receipts. No repeated live operation
or local suite was needed. The trial branch was re-quarantined after completion;
default-branch job guards, repository settings, permissions, old credentialed
workflows and schedules were not changed. #113/#115/#116 remain open.
