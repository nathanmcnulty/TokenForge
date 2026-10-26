# Local validation

GitHub Actions remain disabled. Run the smallest relevant local preset in a fresh PowerShell process; use an existing trusted Linux package rather than rebuilding unchanged code. The runner needs PowerShell 7.6+ and Pester 6.2.0 already installed. It does not install dependencies, build packages, authenticate, or dispatch workflows. Both test entry points and the manual workflow setup use the exact Pester 6.2.0 pin. Historical validation receipts retain the versions actually used for those runs.

```powershell
pwsh -NoProfile -File ./scripts/Invoke-TokenForgeLocalValidation.ps1 -Preset ReleaseGuards
pwsh -NoProfile -File ./scripts/Invoke-TokenForgeLocalValidation.ps1 -Preset Weekly -NativeExecutable /path/to/linux-x64/tokenforge
pwsh -NoProfile -File ./scripts/Invoke-TokenForgeLocalValidation.ps1 -Preset Collector -NativeExecutable /path/to/linux-x64/tokenforge
pwsh -NoProfile -File ./scripts/Invoke-TokenForgeLocalValidation.ps1 -Preset Discovery -NativeExecutable /path/to/linux-x64/tokenforge
pwsh -NoProfile -File ./scripts/Invoke-TokenForgeLocalValidation.ps1 -Preset Native -NativeExecutable /path/to/linux-x64/tokenforge
```

Collector checks Goal 1 session/status, finite request budgets, native uncertainty recovery, saved-evidence export and actual process-kill boundaries using synthetic transports. Weekly checks reports, frozen recipes, native offline execution, and credential bootstrap. Discovery checks standalone orchestration, snapshot recovery, cached inventory equivalence, bounded observation reads, account boundaries, and resumable SQLite cohorts with synthetic data. The broader Native preset retains the SQLite backend regression suites. Native uses the fixed test selection in `native.yml` and is appropriate for broader package changes. ReleaseGuards checks source and asset validators with local fixtures. None of these presets refreshes the public catalog. A full Native run took about 17 minutes locally for version 0.47; routine report checks should use Weekly instead.

The final JSON summary records the preset, source version, actual PowerShell/.NET/Pester versions, counts, and a bounded status code. Exit zero means the selected checks passed and at least one test ran. Optional `-ReportPath` writes a new summary file into an existing directory and refuses overwrites. Raw exception text, credentials, and test output are excluded from the summary. Individual tests may still print progress or fixture messages.

Reuse passing results when the relevant source, test selection, package, and fixtures have not changed. A saved summary alone is not a cache-validity check. Use Maximum reasoning for Luna. Give Luna deterministic execution or read-only assessment tasks with explicit files, commands, and expected behavior. Keep production coding with the primary agent or Sol, and ask Sol to review security-sensitive changes or investigate unclear failures.

The [Pester 6.2 migration receipt](pester-6-validation.md) records the full Linux suite, native selection parity and entry-point validation for the current pin.

The `Changes` preset runs the synthetic typed change-report fixtures and native/PowerShell saved-evidence parity checks against a matching existing Linux package. It uses Pester 6.2.0, performs no live collection, and covers the Goal 2 report contract. See [Goal 2 change reports](goal2-change-reports.md).

The `Admin` preset runs the Goal 3 strict-policy, synthetic acquisition, evidence conversion, named-tool health, private packet, and native consumer parity checks. It needs a matching Linux package and Pester 6.2.0. Run `pwsh -NoProfile -File ./scripts/Invoke-TokenForgeLocalValidation.ps1 -Preset Admin -NativeExecutable /path/to/linux-x64/tokenforge`. All fixtures are offline; see [administrator workflows](goal3-admin-workflows.md).

### Offline release readiness

`-Preset ReleaseReadiness -NativeExecutable /absolute/matching/linux-x64/tokenforge` checks release-source mocks, exact archive receipts, offline publication recovery planning, manual-only workflow/quarantined-writer policy and native SQLite snapshot boundaries. It requires Pester 6.2.0 and an existing matching package; it does not build, install, authenticate or run Actions. `scripts/Test-TokenForgeOfflinePackage.ps1` is the separate Pester-free extracted-package synthetic operator walkthrough; run it in a fresh PowerShell process with a new private workspace. Neither proves live or hosted readiness.

### Canonical original-ZIP review

The `Sealer` preset requires Linux PowerShell 7.6 (tested 7.6.7), Pester 6.2.0 and existing PyYAML 6.0.2. It includes the canonical-container safety regressions and never enables operational output or hosted execution. `scripts/New-TokenForgeSealerReviewKit.py` creates an immutable-source review/test kit using the exact previously accepted Linux CLI/DLL; it refuses module-source drift, installs/builds nothing, and is not a release-package builder. See [the profile and package evidence](goal6-canonical-zip.md).

See [the supported runtime baseline](runtime-baseline.md) for .NET 10 package paths, SDK selection and explicitly frozen historical/deferred tool contracts.
