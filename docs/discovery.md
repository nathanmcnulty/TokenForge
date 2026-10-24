For credential-free public metadata, start with [public health and workstation sync](public-metadata-health.md). The account-bound collection and exact-plan resume commands below remain private workstation operations; public health never starts them automatically. The old discovery workflow remains disabled.

# Run discovery locally

Discovery runs in PowerShell on your machine. It does not require Codex, an LLM API, or GitHub Actions. Authentication still requires an authorized account and an existing supported session or software passkey.

The runner downloads public application sources, confirms the signed-in account through Graph, collects tenant inventory, freezes a research cohort, and requests tokens for its pending client/resource pairs. It records scope and authentication-flow results as it goes. It never grants consent or registers applications automatically.

For the engineering backlog and proposed collection improvements, see the [discovery improvement plan](discovery-improvements.md).

## Requirements

- PowerShell 7.4+ and a trusted Linux TokenForge native package matching the source version.
- An explicitly supplied existing SecureString ESTS session. Obtain or renew it separately; the bounded runner does not sign in.
- A private state directory outside your Git checkout, with one directory per account.
- A private passkey file and containing directory. On Unix use mode 0600 for the file and 0700 for its directory; file permissions alone are insufficient.

```powershell
pwsh -NoProfile -File ./scripts/Invoke-TokenForgeDiscoveryRun.ps1 `
    -StatePath /private/tokenforge/nora `
    -NativeExecutablePath /path/to/linux-x64/tokenforge `
    -EstsAuth $operatorSession `
    -MaxMinutes 15
```

Rerun the same command to resume. Completed flow cells are checkpointed before the next request; a completed client is not requested again within that cohort. A run stops at its chunk, request or cooperative time budget, or when an error prevents progress. See the [Goal 1 offline contract](goal1-collector.md) for explicit ceilings, status, interruption and export recovery. Definite throttling and server errors leave the affected client pending. A transport timeout can hide remote issuance: its durable intent remains unknown and requires an explicit bounded recovery decision. The runner retries these failures up to three times per invocation, waiting 30, 60, then 120 seconds. Completed clients remain checkpointed and are skipped when automatic discovery retries a partly completed batch. Uncheckpointed clients still run evidence and metadata repair before completion. Use `-MaxTransientRetries 0` to disable retries or change the initial wait with `-RetryDelaySeconds` (subsequent waits double, capped at 300 seconds). Other failures stop immediately. Retries reuse the current session; they never sign in again or request consent. The bounded runner includes preflight in its timer, checks budgets before safe operations and bounds transport cancellation by the remaining deadline. Local work and an in-flight operation can overrun cooperatively; the receipt reports this. Smaller `-BatchSize` values give shorter stopping intervals. Failed chunk attempts count toward `-MaxChunks`; the runner also stops before a retry wait that would consume its remaining time budget. Results distinguish `ChunkAttempts`, successfully returned `ChunksExecuted`, and `TransientRetries`.

For an existing cohort with small stored batches, `-MaxPendingClients 25` processes up to 25 pending clients per processing batch, even across stored chunk boundaries. A discovery run can execute many such batches; this option does not cap the total clients in the entire run. Use `-MaxChunks` and `-MaxMinutes` for overall bounds. It keeps the same cohort and flow-plan identity, skips completed clients, and batches metadata projection before per-client completion checkpoints. This can reduce local database/process overhead; it does not parallelize requests. The default `0` keeps the original one-chunk execution behavior. It is a runtime cap, not a change to frozen membership or protocol bounds, and cannot be combined with an explicit `-ChunkIndex` repair request. `ChunkIndex` in a combined result is the first stored chunk selected; `SelectedClients` gives the actual count. `MaxChunks`, `ChunkAttempts`, and `ChunksExecuted` count invocation attempts/returns even when a call spans several stored chunks. Larger caps can extend stopping intervals and memory use; start small.

Check progress in another terminal without authentication:

```powershell
./scripts/Invoke-TokenForgeInventory.ps1 -Action CohortStatus `
    -StatePath /private/tokenforge/nora `
    -NativeExecutablePath /path/to/linux-x64/tokenforge -SummaryOnly |
    ConvertTo-Json -Compress
```

This reads the saved cohort even while discovery holds the writer lock. `Pending` means clients remain to be checkpointed; it does not mean a process is running. Completed clients include failed probes. Omit `-SummaryOnly` for the private recipe and pending membership. Use `-CohortId` to inspect a separately created or older cohort.

For a richer read-only summary of catalog categories and observed flow coverage:

```powershell
./scripts/Invoke-TokenForgeInventory.ps1 -Action Report `
    -StatePath /private/tokenforge/nora `
    -NativeExecutablePath /path/to/linux-x64/tokenforge `
    -InventoryAccount -SummaryOnly | ConvertTo-Json -Compress
```

`-InventoryAccount` selects the tenant/account fingerprints in the saved inventory. It reads no credentials and performs no authentication. Omit it for catalog-only reporting, or use the existing `-PrincipalFingerprint` option to select another observer in the inventory's tenant. These account selectors cannot be combined. Reports run while the writer lock is held and never create a state directory, lock file, or missing flow file. Missing explicit input files still fail. Inventory must already satisfy the private-path policy; reporting does not change its permissions.

A report reads metadata and flow snapshots separately, so counts can move while collection runs; it is not a transaction across both databases. The richer report validates the full catalog and flow history, so use cohort status for frequent checkpoint polling. Reported successes describe observed issuance; they do not infer a required authentication flow, consent, or API authorization.

The bootstrap requests `User.Read` and `Application.Read.All` through Microsoft Graph PowerShell and verifies the issued permissions and `/me` identity. These permissions must already be authorized; the runner stops when they are unavailable. Optional grant enumeration may be unavailable without its separate read permission.

A refreshed inventory replaces the saved snapshot only after metadata writes succeed. Failed writes retain the previous snapshot rather than advertising a successful refresh.

A fresh session may be needed between runs. Paused session continuation requires explicit `-ResumePaused` with an operator-renewed same-account session; an unknown request requires a separately reviewed `-RecoverUnknown` decision and budget. Neither flag signs in. Inventory older than 24 hours is refreshed. If application metadata changed, the frozen cohort refuses it; use `-NewRun` after reviewing the change. `-RefreshDiscovery` fetches updated public sources and refreshes inventory. `-GraphOnly` limits a new cohort to Graph; otherwise the planner uses known resource relationships. Use `-ExploreAllFlows:$false` on a new cohort to stop each pair after its first issuance; the default explores all three implemented protocols, with at most eight callbacks per client by default. The saved cohort retains its original exploration settings when resumed. These bounds do not prove support for every possible authentication method.

Missing, disabled, or ownership-unverified applications stay in metadata but are excluded from token requests. Use the separate [registration stage](inventory.md) if you intentionally want to register candidates. Unknown metadata or an excluded request is not a successful token observation.

## Storage and exports

The working databases are `applications.sqlite`, `scopes.sqlite`, and `flows.sqlite`. They update individual records transactionally rather than serializing all history after every request. Cohort probes read saved observations for the exact account, client, resource, and flow plan; they do not reload the account's full observation history for each chunk. `discovery.json` and `inventory.json` are private snapshots; `discovery-run.json` contains the resume identifier. No credential is saved by this runner.

Keep working databases private. Generate public observations separately with the existing `Export` and `ExportFlows` actions in `Invoke-TokenForgeInventory.ps1`; see [inventory](inventory.md) and [research cohorts](research-cohorts.md). Public source metadata, observed token scopes, and API permission definitions are separate kinds of evidence. Token scopes do not establish API acceptance or universal consent.

SQLite is the working format. JSON is the exchange format. Avoid publishing private history snapshots or repeating the full application ledger inside every observation. Public exports retain their current schema for compatibility. Generate a compact gzip copy with:

```powershell
./scripts/Export-TokenForgeCatalogDownload.ps1 `
    -InputPath /path/to/public/applications.json `
    -OutputPath /path/to/downloads/applications-2026-10-15.json.gz
```

The exporter validates the complete public catalog, including historical records, before creating output. It rejects tenant evidence and private source paths. It accepts JSON or a public-only SQLite ledger; SQLite input also requires `-NativeExecutablePath`. Existing output is never overwritten. Output uses UTF-8 without a BOM and preserves the complete document, dates, and field values. The summary contains application count, byte sizes, and a SHA-256 hash of the decompressed compact JSON. Gzip bytes may vary between runtime versions; the content hash identifies the JSON payload.

Create downloads in a directory you control and publish them after the command succeeds. Generation is offline and does not replace the readable catalog or update published assets automatically. Give snapshots a date or content hash so consumers can distinguish them. A compressed snapshot describes the catalog at export time; it does not establish that every application has been tested. Partitioned exports remain future work.

The schema-2 public snapshot inspected during this work contained 5,455 applications: 31,932,994 bytes as published, 19,699,256 bytes after compact UTF-8 serialization, and 1,770,783 bytes after export with the gzip command above. The complete read, public validation, and export took 158.7 seconds locally; an independent decompression check matched every source value. These are serialization measurements, not a completed discovery claim. Compression should be offered alongside the readable catalog so existing consumers keep working.

The final JSON contains aggregate counts or a bounded failure stage (`Configuration`, `Authentication`, `Authorization`, `Identity`, `PublicSources`, `Inventory`, `Discovery`, or `TransientIdentity` after retry exhaustion). A nonzero exit means work stopped; checkpoints are retained. No identity response body or raw exception is printed.

Use `-Verbose` to see fixed stage names while a run is active. These messages identify preparation versus token research without printing URLs, request bodies, scopes, or account identifiers. Normal output remains one JSON result. For automated runs, capture PowerShell verbose stream 4 separately from the JSON output.
