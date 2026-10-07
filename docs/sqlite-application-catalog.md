# SQLite application catalog

Version 0.14 adds a primary SQLite backend for the application ledger. JSON remains the portable import/export format and the public CI catalog. The existing metadata projection still controls what discovery, inventory, sign-in, registration, scope, and flow producers submit. SQLite stores the projected rows transactionally, without reading or rewriting their complete history on every update.

## Migrate and maintain

Keep a private assessment directory outside Git, and keep the complete native package together. Import the existing JSON ledger once:

```powershell
Import-TokenForgeApplicationMetadata -Path "$state/applications.sqlite" `
  -InputPath "$state/applications.json" -NativeExecutablePath $native

# The inventory runner now selects applications.sqlite when it exists.
./scripts/Invoke-TokenForgeInventory.ps1 -Action Discover -StatePath $state `
  -NativeExecutablePath $native

# A current view excludes previous attribute versions and old run history.
Get-TokenForgeApplicationMetadata "$state/applications.sqlite" `
  -CurrentOnly -NativeExecutablePath $native
```

Module updates accept either a JSON path or a `.sqlite` path. `Update-TokenForgeDiscovery` selects an existing sibling `applications.sqlite`, and otherwise retains its JSON default. Inventory runner actions pass the configured native executable through every metadata update, including registration checkpoints. Packaged module calls find their executable automatically; source checkouts need `-NativeExecutablePath`.

Research reports prefer an existing SQLite catalog and use its current view. The CLI accepts an explicit `--metadata-path` when needed:

```sh
tokenforge research report --state-path /private/lab --summary-only --json
tokenforge catalog import --database /private/lab/applications.sqlite --input /private/lab/applications.json
tokenforge catalog export --database /private/lab/applications.sqlite --app APPLICATION_GUID --current
```

A normal export includes all retained applications, records, versions, origin watermarks, and runs. `--app` selects one application's records and associated origins; `--current` excludes previous versions and retains only the runs referenced by current origin watermarks. Filtered exports are partial views. Importing them preserves existing omitted applications and history; it does not interpret omission as absence.

Native exports go to stdout and contain private diagnostic metadata. Protect redirected files. Public CI continues to use its bounded JSON ledger and existing publication guard. The module's `-PublicOnly` validation examines the complete ledger before applying any selection; it rejects private origins, runs, history, and unexpected public fields. Selecting one public-looking application does not make a mixed ledger publishable.

## What a transaction preserves

Current records, historical versions, application first/last dates, origin watermarks, snapshot presence, and the run record commit together. Malformed input rolls back the whole update or import. An empty complete discovery, inventory, or sign-in snapshot explicitly marks prior records absent for its origin. Scope, registration, and flow batches never mark omitted pairs absent.

Presence follows the newest origin snapshot independently of attribute observation dates. Older imports cannot restore an app removed by a newer snapshot. A newer absent snapshot can mark an app absent while retaining more recent attributes collected elsewhere. Equal-date row changes retain their input order. Repeated transitions such as A → B → A → B remain separate versions, including when their timestamps are equal.

Legacy content hashes are preserved. New updates carry the exact projected hash-input JSON, which the native store verifies against the submitted attributes, sources, and SHA-256. A separate canonical payload digest detects accidental current-record corruption without changing legacy hashes. Versions also have payload digests. These checks provide consistency, not cryptographic proof of origin or protection against a process that can rewrite the database.

Imports preserve run IDs and ordering, source snapshots, sign-in windows, and version occurrences. Repeated imports do not duplicate those runs or versions. Conflicting run IDs, duplicate dictionary keys, unknown fields, invalid context bindings, and indexed-column/payload disagreement are rejected. Historical app/resource/flow-slot context is checked as well as current context. Older ledgers with a scalar singleton `TenantRedirectUris` remain importable with their hashes intact; newly collected tenant callbacks are arrays.

## Security and limits

This store contains diagnostic metadata, never tokens, cookies, assertions, passkeys, or credential objects. Sign-in summaries retain bounded allowed categories, not raw authentication events. Catalog records do not authorize registration, choose trusted ownership, or bypass token validation. Those operations still consume independently verified tenant inputs.

Storage is unencrypted. Unix paths require a private parent and mode-0600 files; Windows requires a protected current-user ACL. Linked paths and foreign SQLite formats are rejected. WAL/SHM files stay inside the private directory. The shared adapter uses private temporary metadata files, argument lists, a timeout, cleanup, and suppressed child diagnostics. Disk encryption remains useful for confidential research.

History can grow in SQLite without whole-file checkpoint writes. Current reports avoid materializing version and full run history. JSON imports/exports remain limited to 128 MiB; use application/current selections for large exports. Very large current catalogs may still need partitioned reports. Version 0.15 also supports [primary SQLite scope/registration checkpoints](sqlite-scope-history.md); JSON remains portable. Authentication still uses PowerShell.

## Validation on 2026-10-07

The [sanitized migration report](sqlite-catalog-validation-2026-10-07.json) covers both complete private lab ledgers. Nora's 5,521 IDs, 5,538 records, 13 previous versions, and five runs survived; secadmin's 5,536 IDs, 5,780 records, 184 previous versions, and seven runs survived. Every metadata hash and observation date matched, version order was retained, and repeated imports added zero runs. Both packaged research reports found 12 terminal flow slots. A live public-source refresh collected 5,454 rows and updated each SQLite catalog while retaining absent IDs. No credentials were used or private metadata published.

Verification passed 254 PowerShell tests (two platform-specific skips), 88 native checks, seven catalog adapter checks, and independent Sol review. The fixture checks cover stale and empty snapshots, equal-date repeated transitions, namespaces, partial batches, rollback, run identity conflicts, publication guards, indexed corruption, and hash parity with non-ASCII/escaped text. Live migration ran on Linux; cross-platform CI exercises synthetic adapters separately. These timings are lab observations, not a general performance guarantee.
