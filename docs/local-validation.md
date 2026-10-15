# Local validation

GitHub Actions remain disabled. Run the smallest relevant local preset in a fresh PowerShell process; use an existing trusted Linux package rather than rebuilding unchanged code. The runner needs PowerShell 7.4+ and Pester 5.7.1 already installed. It does not install dependencies, build packages, authenticate, or dispatch workflows.

```powershell
pwsh -NoProfile -File ./scripts/Invoke-TokenForgeLocalValidation.ps1 -Preset ReleaseGuards
pwsh -NoProfile -File ./scripts/Invoke-TokenForgeLocalValidation.ps1 -Preset Weekly -NativeExecutable /path/to/linux-x64/tokenforge
pwsh -NoProfile -File ./scripts/Invoke-TokenForgeLocalValidation.ps1 -Preset Discovery -NativeExecutable /path/to/linux-x64/tokenforge
pwsh -NoProfile -File ./scripts/Invoke-TokenForgeLocalValidation.ps1 -Preset Native -NativeExecutable /path/to/linux-x64/tokenforge
```

Weekly checks reports, frozen recipes, native offline execution, and credential bootstrap. Discovery checks standalone orchestration, account boundaries, resumable cohorts, and the three SQLite stores with synthetic data. Native uses the fixed test selection in `native.yml` and is appropriate for broader package changes. ReleaseGuards checks source and asset validators with local fixtures. None of these presets refreshes the public catalog. A full Native run took about 17 minutes locally for version 0.47; routine report checks should use Weekly instead.

The final JSON summary records the preset, source version, counts, and a bounded status code. Exit zero means the selected checks passed and at least one test ran. Optional `-ReportPath` writes a new summary file into an existing directory and refuses overwrites. Raw exception text, credentials, and test output are excluded from the summary. Individual tests may still print progress or fixture messages.

Reuse passing results when the relevant source, test selection, package, and fixtures have not changed. A saved summary alone is not a cache-validity check. Use Maximum reasoning for Luna. Give Luna deterministic execution or read-only assessment tasks with explicit files, commands, and expected behavior. Keep production coding with the primary agent or Sol, and ask Sol to review security-sensitive changes or investigate unclear failures.
