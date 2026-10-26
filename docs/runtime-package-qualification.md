# Merged runtime package qualification

**Recommendation: #98 is ready to close after this PR is reviewed and merged**, for the agreed .NET 10 / PowerShell 7.6 / Pester 6.2 baseline and Linux x64 offline acceptance scope. The merged baseline is usable as a local Linux package and a module ZIP on the installed Linux PowerShell runtime. No issue is closed by this recommendation. Windows/macOS/ARM distribution qualification and operational activation remain separate work.

Base: merged main **`ecf16f4fe98e2b29dc444e273fcc08d795a0d915`**, including PR #106's final budget-forwarding and ledger-reader corrections. Exact packaged source and packaging driver: **`a7694cb65d8cfadfe41ba7efbd6d20cdec4effa4`**. The later containing documentation commit records these results; it is not substituted as package source. [The sanitized summary](runtime-package-qualification.json) records archive, manifest, corrected-payload and raw-log digests. Historical receipts remain unchanged.

## Exact local artifacts

Archives/raw receipts remain under `.cache/qualification/` in the qualification worktree, unpublished. Preserve complete extractions. The native CLI is self-contained; module/adapters require existing PowerShell 7.6+. Both packages are 0.48.0; version alone is insufficient identity.

| Artifact in `packages-a7694cb/` | Bytes | SHA-256 |
| --- | ---: | --- |
| `TokenForge-linux-x64.tar.gz` | 33898204 | `df3be70e6f21b0360c701799c9ad03543e0b8cdfada53c0bf16de950762f77dc` |
| `TokenForge-module.zip` | 928514 | `4e3b69a6b1f3ffd8c44031bdabd88d1a489724f67b3d18829c9598bc16aa2be2` |

Linux has 263 regular payload files including `public-health-package.json`; manifest SHA-256 `3dc6c625b93e2669d21efd4d62e7d51c2eecfc7b179df53682b21e2e4b829076`. ZIP has 261 files including `runtime-package.json`; manifest SHA-256 `bffaa91377d2387ff037b18bcbc429de590596f2ea6f59676aa2691fbb464fee`. Each manifest enumerates every other payload's hash/size, source mapping and complete compilation-input Git blob inventory. Both include all 87 current module source files, corrected scripts, operator dependencies, Markdown guides and the complete offline administrator replay/fixtures. Linux preserves historical root documentation alongside `docs/` for guide links.

No compilation occurred. Linux native/DLL retain compilation source `c32cd7b27e98fdeac9f376807999205d99133a38`; module DLL retains `cbea33eca2dfde24f0c92b0385784876510e4ece`. All 100 compilation/build inputs match both original compilation and packaged source. Distinct assembly build-commit metadata/hashes are preserved:

| Payload | SHA-256 |
| --- | --- |
| Linux `tokenforge` | `42773ca3e048d5d29dd3edf488ca33ace5116d47afdd4513fa8df95b24a3047e` |
| Linux credential DLL | `a96664feb04f767cd48360a706292e2577e36472a1b27ac282c6e67899fa1a52` |
| Module credential DLL | `969c5ff5020b4be4e41b64a3a63c3602aa2d433b69cad853e42fe03ad801c2a4` |
| Both `scripts/Invoke-TokenForgeInventory.ps1` | `79a8305b0d917529e7bf1e3616a34a12a83e3181212da95fdb37011c7f9db52f` |
| Both `src/TokenForge/Private/OperationBudget.ps1` | `e8cd3278c6a481e2ec088c94a6ba3628dd385eca6aabf1b8a7f35509ee78243e` |

## Bounded packaging workflow

The existing public-health builder requires old source payloads already match HEAD and overlays only six scripts; the module builder always compiles. The [runtime repacker](../scripts/New-TokenForgeRuntimePackages.py) leaves these builders intact and uses only existing Python/Git to qualify unchanged binaries with current scripts. It accepts only the two independently pinned historical archives from [prior acceptance](runtime-baseline-validation.json), verifying their whole hashes before parsing, independent binary pins, every old source-backed member against exact `58203ecdcee47c4bdaaef0801d0b496d22daa35f` blobs, and complete compilation input sets/blobs. New source comes from Git blobs, not mutable working files. Changed/missing inputs, wrong source/driver, unpinned archives, invalid membership or existing output cause refusal. Output metadata is normalized; manifests bind complete source/payload inventories.

This is a bounded historical repacker, not a general archive import/release tool. Directory names and generic archive resource bounds are not an arbitrary-input security contract; only the pinned historical byte streams are parsed. It has no download/build/install fallback.

Reproduce at exact packaged source, supplying existing accepted local archives and new output under an existing private parent:

```sh
python3 -B scripts/New-TokenForgeRuntimePackages.py \
  --linux-archive /absolute/accepted/TokenForge-public-health-linux-x64.tar.gz \
  --module-archive /absolute/accepted/TokenForge-0.48.0.zip \
  --source-revision a7694cb65d8cfadfe41ba7efbd6d20cdec4effa4 \
  --output-directory /absolute/private-parent/new-packages
```

Source must be owning HEAD and driver bytes must match Git. An initial abbreviated source argument was rejected before output creation; the corrected full-identity invocation succeeded. No validation assertions were weakened.

## New validation

Actual tools: Linux x64, Python 3.13.5, PowerShell 7.6.7 on .NET 10.0.13, Pester 6.2.0. PowerShell checks and administrator replay ran under `unshare -Urn` without external interfaces. Replay also used `env -i`, private temporary/bundle directories and unchanged no-adapter PATH. No dependency installation occurred.

| New check | Actual result |
| --- | --- |
| `python3 -B tests/RuntimePackages.test.py` | 9 passed; path/link/duplicate/parent boundaries, pins, complete input/blob drift, deterministic output, overwrite refusal |
| Linux extracted payload, seven Pester files | 138 passed / 0 failed / 0 skipped / 0 inconclusive / 0 not-run; exit 0 |
| Module ZIP extracted payload, same seven files | 138 passed / 0 failed / 0 skipped / 0 inconclusive / 0 not-run; exit 0 |
| Linux packaged operator script | 33 synthetic checks passed; exit 0 |
| Linux packaged administrator replay/fixtures | 21/21 commands passed; exit 0; all seven expected health/uncertainty cases retained |
| Extraction and post-execution checks | All payload hashes/sizes/source maps matched; no payload changed during execution |

Seven files: CollectorSafety (44), OperationBudget (59), InventoryCheckpoint (4), ResearchChunkPending (12), ProbeReadBounds (3), DiscoveryBootstrap (9), CredentialBootstrap (7). Exact unchanged test files/fixtures were copied as test-only scaffolding beside each extraction; `native/` and `global.json` were copied only for bootstrap metadata assertions. Production `src/` and `scripts/` came from each archive, verified again after execution. Fresh PowerShell processes imported each packaged module and ran `Invoke-Pester` over these files with Pester 6.2.0 and fail-closed count/container checks. Setting a native executable while testing checkout scripts was not used as payload proof.

Coverage includes issuance/HTTP ceilings, refresh/resume behavior, uncertainty recovery, writer locks, ledger integrity/publication failure, orchestration and fresh-process packaged .NET 10 BCL loading with zero SQLite references and corrupt-DLL refusal. Acquisition/native persistence boundaries in correction regressions remain mocked. Linux execution alone does not prove Windows replacement semantics.

Operator execution used packaged `scripts/Test-TokenForgeOfflinePackage.ps1`, extracted CLI and a new private workspace. Administrator execution used packaged `examples/offline-admin/replay.py`, the source/manifest pins above and new private output, following [the guide](walkthroughs/offline-admin.md). Module ZIP users need a separate native package for CLI walkthroughs; the ZIP contains no native executable.

## Evidence reuse

- Historical full Linux **1663 passed / four platform skips** remains scoped to `58203ec`; it is not a newly run full-suite count. Only the inventory wrapper and operation-budget helper changed in production since that run. Both changed test files and related regression groups were executed above. Other source/test inputs are identical apart from separately tested new Python packaging code/test and documentation/examples. No combined historical/current full-suite count is claimed.
- Native **1157 checks** and Sealer **224 checks** were not repeated. Complete native/build inputs match; Sealer source/tests/policy/workflow inputs are unchanged. Historical full/native log and Sealer summary hashes matched preserved receipts.
- Prior Windows **131/0/0** source acceptance is retained from [PR #106 follow-up](pr106-review-followup.json). All eight recorded source/test hashes match current source and corrected payloads. Private Windows logs were unavailable for independent local inspection. This is prior Windows source execution, not a newly tested Windows package.
- Historical parser/analyzer/workflow evidence remains scoped: this PR changes no PowerShell/workflow files; nine existing analyzer findings remain, with no new suppression. No SDK build or hosted/cross-platform gate was repeated for another green result.

## Independent review and remaining limits

Independent `qualification_review` inspected the new driver/tests and actual final archives: whole-archive hashes, unique membership, every payload hash/size and source mapping, all 100 compilation inputs, all 87 module files, both corrections and walkthrough presence. No blocking findings remained; the reviewer did not rerun producer suites. Final completed-receipt/log audit is recorded in the JSON summary.

The local Linux distribution gap for #98 is satisfied. Remaining limits: no new Windows/macOS/ARM package execution, standalone Secret Service integration, signing/notarization, live authentication/API assurance, production or Goal 6 operational qualification. Frozen Goal 6 runtime/delivery pins remain deferred and inert. No Actions, authentication, live collection, installation, activation, binary publication, release, merge or issue closure occurred. The PR contains sanitized source/docs/validation summaries only; packages and raw receipts remain local for final review.
