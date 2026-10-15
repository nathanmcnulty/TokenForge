# Run discovery locally

Discovery runs in PowerShell on your machine. It does not require Codex, an LLM API, or GitHub Actions. Authentication still requires an authorized account and an existing supported session or software passkey.

The runner downloads public application sources, confirms the signed-in account through Graph, collects tenant inventory, freezes a research cohort, and requests tokens for its pending client/resource pairs. It records scope and authentication-flow results as it goes. It never grants consent or registers applications automatically.

## Requirements

- PowerShell 7.4+ and a trusted Linux TokenForge native package matching the source version.
- An authorized software passkey and XDRInternals authentication module, or an existing SecureString ESTS session.
- A private state directory outside your Git checkout, with one directory per account.

```powershell
pwsh -NoProfile -File ./scripts/Invoke-TokenForgeDiscoveryRun.ps1 `
    -StatePath /private/tokenforge/nora `
    -NativeExecutablePath /path/to/linux-x64/tokenforge `
    -PasskeyPath /private/nora.passkey `
    -XdrModulePath /path/to/XDRInternals.psd1 `
    -MaxMinutes 60
```

Rerun the same command to resume. Completed flow cells are checkpointed before the next request; a completed client is not requested again within that cohort. A run stops at its chunk or time budget, or when an error prevents progress. The time budget is checked between chunks, so one chunk may extend beyond it. Smaller `-BatchSize` values give shorter stopping intervals.

The bootstrap requests `User.Read` and `Application.Read.All` through Microsoft Graph PowerShell and verifies the issued permissions and `/me` identity. These permissions must already be authorized; the runner stops when they are unavailable. Optional grant enumeration may be unavailable without its separate read permission.

A fresh session may be needed between runs. Inventory older than 24 hours is refreshed. If application metadata changed, the frozen cohort refuses it; use `-NewRun` after reviewing the change. `-RefreshDiscovery` fetches updated public sources and refreshes inventory. `-GraphOnly` limits a new cohort to Graph; otherwise the planner uses known resource relationships. Use `-ExploreAllFlows:$false` on a new cohort to stop each pair after its first issuance; the default explores all three implemented protocols, with at most eight callbacks per client by default. The saved cohort retains its original exploration settings when resumed. These bounds do not prove support for every possible authentication method.

Missing, disabled, or ownership-unverified applications stay in metadata but are excluded from token requests. Use the separate [registration stage](inventory.md) if you intentionally want to register candidates. Unknown metadata or an excluded request is not a successful token observation.

## Storage and exports

The working databases are `applications.sqlite`, `scopes.sqlite`, and `flows.sqlite`. They update individual records transactionally rather than serializing all history after every request. `discovery.json` and `inventory.json` are private snapshots; `discovery-run.json` contains the resume identifier. No credential is saved by this runner.

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

The final JSON contains aggregate counts or a bounded failure stage (`Configuration`, `Authentication`, `Authorization`, `Identity`, `PublicSources`, `Inventory`, or `Discovery`). A nonzero exit means work stopped; checkpoints are retained. No identity response body or raw exception is printed.

Use `-Verbose` to see fixed stage names while a run is active. These messages identify preparation versus token research without printing URLs, request bodies, scopes, or account identifiers. Normal output remains one JSON result. For automated runs, capture PowerShell verbose stream 4 separately from the JSON output.
