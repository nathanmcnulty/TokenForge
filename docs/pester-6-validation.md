# Pester 6.2 migration validation

TokenForge's active test entry points and manual workflow dependency setup now pin **Pester 6.2.0**. Both `scripts/Test-TokenForge.ps1` and `scripts/Invoke-TokenForgeLocalValidation.ps1` require that exact version. The two workflows install and import the same version; their triggers remain `workflow_dispatch` only. Historical Goal 1 receipts retain the versions actually used for those runs.

The migration follows Goal 1 checkpoint `68ae5749bbc609937290e2209a5cda89375d7313`. No runtime module, native source, protocol, credential handling or collector behavior changed. The prior milestone's explicit conditional-mock fallback already supports Pester 6; the full migration run required no additional fixture changes.

## Local Linux evidence

PowerShell **7.6.7**, Pester **6.2.0**, Linux x64:

| Check | Passed | Failed | Skipped |
| --- | ---: | ---: | ---: |
| Full `scripts/Test-TokenForge.ps1` suite, 64 test files | 961 | 0 | 4 |
| Existing native workflow's 21-file selection, included in the full run | 340 | 0 | 3 |
| Updated local runner, `ReleaseGuards` preset | 27 | 0 | 0 |

The full suite discovered 965 cases, had zero failed containers and completed in 469.64 seconds. All 64 `*.Tests.ps1` files contributed results; the initial file inventory's two additional entries were fixtures. Detailed per-file results were reconciled to the actual Pester summary. The native subset's expected 340 passes remains unchanged; it was derived from the same full run rather than rerun or counted as additional unique coverage.

The four full-suite skips are the Windows ACL cases in `NativeOAuth.Tests.ps1` and `Vault.Tests.ps1`, and the macOS-specific cases in `NativeProfiles.Tests.ps1` and `Profiles.Tests.ps1`. Native package prerequisites were present; native tests were not skipped for a missing executable. No Windows, macOS or additional architecture was compiled or tested.

The full entry point ran in a fresh `pwsh -NoProfile` process with `TOKENFORGE_TEST_NATIVE` set to the existing verified complete Linux x64 package. The packaged module was loaded first and removed before source tests, retaining its compatible compiled credential types. The package remains version **0.48.0**, source `f5df773c177cd11dcf3befc53b3e7507f08e2041`, with 133 payload files plus its manifest. Exact source/package verification passed again; unchanged runtime/native inputs justified reuse without rebuilding.

- Package manifest SHA-256: `6e203055aa9414d894ef7763f488479b2c1f8d19ca4cbfc17a5503f54d19aa15`
- Native executable SHA-256: `d65f1686542444dcfab9fe1bb38eb5989a815a2e743fc04a6276648fcf7de196`
- Native-input aggregate SHA-256: `e045aa00fe2cc1a2bfc3c9a9dca2098f45bd658610650d8ad51646bac4dd648c`

Both workflow diffs were checked against the baseline: only the Pester version substitutions changed. No hosted workflow was enabled, dispatched or run. No authentication, live discovery, dependency installation, publication, push, PR or tenant mutation occurred during this migration. Goal 2 remains untouched.

Independent review found no issues in the pins, workflow boundaries, compatibility approach or recorded results. The exact structured results and entry-point hashes are in [pester-6-validation.json](pester-6-validation.json). Local detailed logs and analysis helpers remain under `.cache/pester6/`.
