# Supported runtime baseline

Issue #98 and PR #106 align the maintained module, script entry points and packages on **PowerShell 7.6 or later and .NET 10**. Tests use **Pester 6.2 or later**; reproducible repository runners and manual workflow setup select exactly **6.2.0**. Runtime summaries record the actual selected PowerShell, .NET and Pester versions. No execution-mode or parallelization change is included.

The SDK is exactly **10.0.401**, with roll-forward disabled. Its locked ILLink tooling is 10.0.12; automatically selecting a later SDK patch can request a different tooling package and fail locked restore. An SDK update requires deliberate lock reconciliation and local validation. Package versions, content hashes and existing RID lock coverage are preserved. Only Linux x64 is built and tested for this candidate.

Both shared libraries now target `net10.0`. The module loads the BCL-only credential assembly from `src/TokenForge/lib/net10.0/TokenForge.Credentials.dll`, separate from SQLite storage. A fresh process tests source compilation and the packaged DLL; existing-DLL identity failures never fall back to compiling source. Preserve the complete extracted package.

The integration candidate retains current main and the owning session's newer collector, saved-evidence reports, admin/refresh interfaces, SQLite snapshots, public-health packaging and diagnostic safeguards. Updating those package paths also requires independently reviewing the newly built binary hashes; an old package of the same module version is insufficient. No authentication, collection, artifact sync or hosted validation is part of this migration.

## Historical and deferred evidence

Dated receipts, historical run summaries, upstream fixtures and `docs/history/` retain the versions actually observed. The 0.3.0 package account in `customer-workflow-validation.md` is historical. Source comments about PowerShell 7.4/7.5 JSON date coercion explain retained compatibility logic, not a supported floor.

The original Goal 6 deployment lane remains inert and is not migrated or activated here. `New-TokenForgeSealerReviewKit.py`, `New-TokenForgeCanarySubject.ps1` and `TokenForgeCanaryAction.mjs` bind exact older `net8.0` DLL bytes, source/package hashes and synthetic producer inventories. Their path/hash pairs remain frozen review evidence, not an alternative supported runtime or a package fallback. They cannot consume the new package. Existing unconditional service/bootstrap gates, zero signer pin and disabled workflow/template guards remain. Reopening that lane requires separate scope, exact-source review and approval; changing a path alone would invalidate its evidence.

The disabled public-metadata-health workflow retains current main's previously reviewed delivery URLs and asset hashes. Those delivery pins are deferred evidence and require separate review and updating before the job can be enabled. Updating the maintained sealer's PowerShell guard also regenerates its current source-hash declaration; it changes no archive validation, operational gate or frozen runtime pin.

Local acceptance results and exact source/package identities are recorded separately after testing. Historical counts are not acceptance evidence for this candidate.
