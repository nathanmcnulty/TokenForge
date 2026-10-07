# SQLite scope and registration history

Version 0.15 connects the native evidence store to primary scope-probe and registration checkpoints. Application metadata, detailed flow evidence, and scope/registration evidence remain separate stores. JSON stays supported as a portable format; migration is explicit.

## Migrate a private state directory

Use a native package, or supply the executable path when calling PowerShell directly:

```powershell
Import-Module ./src/TokenForge/TokenForge.psd1
$native = './dist/native/linux-x64/tokenforge' # tokenforge.exe on Windows
$state = '/path/to/private/research'
Import-TokenForgeScopeDatabase -Path "$state/scopes.sqlite" `
  -InputPath "$state/scopes.json" -NativeExecutablePath $native
Get-TokenForgeScopeDatabase "$state/scopes.sqlite" -NativeExecutablePath $native
```

The import validates the entire input and commits observations and registration attempts in one transaction. Identical normalized records are deduplicated. Repeated imports do not add records. Imported source paths are retained privately; primary checkpoints use a stable source label rather than accumulating temporary filenames.

The inventory runner selects an existing `scopes.sqlite`, otherwise `scopes.json`. Its `-DatabasePath` parameter selects another path. Native CLI profiles also prefer an existing `scopes.sqlite`; their default remains JSON until migration. Do not run independent writers against the same state directory. Probe and registration operations share a private operation lock; SQLite transactions protect individual writes.

```powershell
./scripts/Invoke-TokenForgeInventory.ps1 -Action Probe -StatePath $state `
  -EstsAuth $cookie -DatabasePath "$state/scopes.sqlite" `
  -FlowPath "$state/flows.sqlite" -MetadataPath "$state/applications.sqlite" `
  -NativeExecutablePath $native -GraphOnly -MaxApplications 4
```

Cookies and access tokens remain in memory for this operation. The evidence database records only the established scope/registration whitelist, including app IDs, scope claims, outcomes, timestamps, and namespace fingerprints. It is diagnostic evidence, not a credential cache or proof that an API permits every claimed scope.

## Read current evidence

```powershell
Get-TokenForgeScopeDatabase "$state/scopes.sqlite" -NativeExecutablePath $native `
  -Latest -TenantFingerprint $tenantHash -PrincipalFingerprint $principalHash `
  -ResourceId '00000003-0000-0000-c000-000000000000'
```

`-Latest` selects the newest observation for each tenant/principal/client/resource pair, including failures. A failed newer probe supersedes an earlier success for coverage selection. Full history remains available without `-Latest`. Equal timestamps use insertion order. Profile status and targeted scope acquisition read selected current evidence; individual checkpoints do not rewrite the full history.

Registration reads are tenant-scoped. An unresolved `CleanupRequired` remains visible even if a later unrelated outcome is imported. Only a chronological `CleanupResolved` event clears it; missing candidates can then be retried. The same cleanup rules apply to JSON. A 401/403 registration failure is checkpointed before the run stops. Registration `-WhatIf` suppresses checkpoint and metadata writes; it may create the private operation-lock file.

Scope and registration resume can repair application metadata after an earlier metadata write failure. Scope resume supplies the persisted aggregate for each skipped completed pair; it does not issue another token or create another scope observation. Registration resume supplies the saved attempt for skipped candidates.

Native commands support the same selection:

```text
tokenforge evidence export --database /private/scopes.sqlite --latest --tenant HASH --principal HASH --resource APPID
tokenforge evidence update --database /private/scopes.sqlite --input /private/checkpoint.json
```

A checkpoint document has the existing scope database schema with only its new `Observations` or `RegistrationAttempts`. Updates are transactional. Native selected reads validate payload hashes and indexed identities. Principal-only selection is rejected. Full exports and imports are capped at 64 MiB; use selected/latest reads for operational work and partition oversized portable histories. Very large registration catalogs may need additional indices in a future schema migration.

## Sharing and security

Storage is unencrypted diagnostic metadata. Unix directories/files require private permissions; Windows uses a protected current-user ACL. Linked paths and foreign database formats are rejected. WAL/SHM and temporary input files remain inside the private directory. The native adapter removes its input file and suppresses child diagnostics.

For public sharing, use `Export-TokenForgeScopeDatabase` on the private document. It exports only successful observations with matched namespace/request evidence and removes private namespace fingerprints. Native `evidence export --public` is a lower-level diagnostic projection; it removes tenant/principal fingerprints but is not the anonymous public catalog schema. Do not publish private SQLite files.

The [sanitized live report](sqlite-scope-validation-2026-10-07.json) records both accounts: each imported 12 existing observations idempotently, added four fresh scope observations, retained 12 terminal flow slots, resumed without new observations or attempts, and exposed four saved rows for metadata repair. Nora had three successful aggregate observations; secadmin had four. Existing-app registration returned `AlreadyPresent` for both accounts. No service principal was created, no consent was granted, and no tokens were persisted. Linux supplied the live proof; cross-platform CI uses synthetic fixtures.
