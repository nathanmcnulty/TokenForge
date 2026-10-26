# Runtime baseline offline acceptance

Issue #98 / draft PR #106 is ready for integration review on Linux x64. Exact tested and independently reviewed candidate: **`58203ecdcee47c4bdaaef0801d0b496d22daa35f`**. The containing checkpoint adds acceptance/handoff documentation only. See [the machine-readable receipt](runtime-baseline-validation.json) and [supported baseline and exceptions](runtime-baseline.md).

The candidate retains PR #106's `b35461a6`, current main `4c986518`, and the newer owning checkpoint `9f6b4f2`. It preserves the collector, changes/admin/refresh commands, SQLite snapshots, public-health packaging and strict diagnostic behavior. No stale draft or CI-only changes were substituted for that work.

All projects use .NET 10; maintained module/script floors are PowerShell 7.6. Reproducible test entry points select Pester 6.2.0. Actual local tools were SDK 10.0.401, PowerShell 7.6.7 on .NET 10.0.13 and Pester 6.2.0. Existing dependency versions/content hashes and RID coverage remain unchanged. SDK roll-forward is disabled to prevent an SDK patch silently selecting ILLink tooling inconsistent with the locks.

| Check | Result |
| --- | --- |
| Full applicable Pester suite, exact candidate | **1663 passed, 0 failed, 4 skipped**, zero inconclusive/not-run; exit 0; 663.66 s |
| Native core | **1157 checks passed**; implementation/test source and selected SDK unchanged through final candidate |
| Sealer declaration repair, exact candidate | **224 passed, 0 failed/skipped** |
| Extracted Linux package walkthrough | **33 synthetic checks passed**; final payload identical to tested extraction |
| Source and packaged credential bootstrap | Full-suite fresh subprocesses; .NET 10, corrupt-DLL refusal, no SQLite assembly references |
| PowerShell parser | 190 files, zero errors; final PowerShell inputs unchanged |
| Analyzer 1.25.0, Error severity | Nine existing findings in both baseline and candidate, exact same findings; zero new, no suppressions |
| Workflows/generated profile | Three changed workflows parse and remain manual-only; early native runtime check executed locally; both generated source hashes match |

The four full-suite skips are Windows ACL checks (two), moved OS-profile ciphertext on an unsupported platform, and unavailable macOS signed-helper behavior. They are platform exclusions, not missing-dependency skips. Existing pinned genuine-bundle attestation verification ran offline. Full Pester ran in an externally isolated network namespace with only loopback enabled and no test exclusions. Windows/macOS/other architectures, standalone Secret Service integration and hosted execution were not rerun.

Development found and corrected two integration problems without weakening assertions: full-suite startup now preloads the explicit package before source imports; package provenance now distinguishes compilation from a script overlay, requiring both complete file sets and every literal compilation input to match. The first completed full run had 1662 passes and one failure because a changed PowerShell guard left the generated sealer hash stale. Regenerating that single hash restored the unchanged positive assertion; operational refusal remains intact. Rejected/interrupted attempts are retained separately in the receipt and private logs.

## Exact local packages

Artifacts remain local and unpublished under `.cache/issue98/` in the implementation worktree. They are not GitHub release assets or downloaded hosted artifacts.

| Artifact | SHA-256 | Bytes |
| --- | --- | --- |
| `final-package-58203ec/TokenForge-public-health-linux-x64.tar.gz` | `975a8407cc0e7c90939fc630f48b7da2b92947ee2c8d11435944cc1c15e5ea7d` | 33629642 |
| `module-package-final/TokenForge-0.48.0.zip` | `b953287a8364cdead26391dc12175b8a8e99a82df5cacd6e69140967b903cd0f` | 861843 |

Linux archive: 167 members, all 166 payload hashes/sizes verified, all 87 current module source files preserved, 73 exports. Its native executable hash is `42773ca3e048d5d29dd3edf488ca33ace5116d47afdd4513fa8df95b24a3047e`; credential DLL hash is `a96664feb04f767cd48360a706292e2577e36472a1b27ac282c6e67899fa1a52`. Native compilation source is `c32cd7b27e98fdeac9f376807999205d99133a38`, with all 100 complete compilation/build inputs identical to final source. Overlay source is the exact tested candidate above.

Module ZIP: 237 members; its existing newly built .NET 10 DLL is preserved from `cbea33e`, with only the final baseline guide overlaid. All source-backed files were independently checked. Its DLL hash is `969c5ff5020b4be4e41b64a3a63c3602aa2d433b69cad853e42fe03ad801c2a4`; differing build-commit metadata is recorded rather than relabeling either assembly. Both assemblies have zero SQLite references. The native CLI is self-contained; the module and PowerShell adapters require an existing PowerShell 7.6+ installation. No runtime installation was performed or added to package use.

Independent Sol review cleared the exact source and final archives, including source-backed bytes, safe membership, binary pins, complete input inventories and preserved refusal gates. The reviewer did not rerun producer suites. The containing review checkpoint records final receipt inspection separately.

No Actions, authentication, live collection, artifact download/sync/import, dependency installation, package publication, release or merge occurred. The original Goal 6 deployment lane and prior hosted delivery pins remain deferred and disabled; historical receipts retain their actual versions. Source publication to the existing PR branch does not authorize operational activation. PR #106 remains a draft per issue #98; integration/merge and any live work require separate authorization.
