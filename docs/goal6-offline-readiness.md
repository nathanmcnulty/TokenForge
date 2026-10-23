# Goal 6 offline release readiness

This is a local Linux x64 release candidate, not full Goal 6, live, publication or production completion. The assigned offline validation/readiness assessment is complete; the remaining product gates below are still open. The machine-readable [receipt](goal6-offline-validation.json) preserves exact artifacts, hashes, diagnostics and remaining gates. The [operator runbook](goal6-operator-runbook.md) is included in the tested package.

Subsequent source-only work: the [trusted publication verification adapter](goal6-publication-adapter.md) adds offline-tested authority/provenance verification and durable handoff. It supplies no remote writer or hosted proof and is not included in this historical package.

The separate [remote writer checkpoint](goal6-publication-writer.md) subsequently implements bounded dispatch and recovery with offline fixtures. It also remains outside this historical package and has no real publication/hosted proof.

## Exact checkpoints

- Goal 5 parent: `534520fd52a47b3cd80138efac5d2ce2081247cc`.
- Reviewed runtime, package builder and operator source: `0a1704d057417e58b92fd5eac8c546541d3f7ec2`.
- Reviewed final unbundled validator/test correction: `68dd61cb8dbd142ef06d28840e2f21d1bc17a0e6`.
- Preserved roadmap handoff: `19470aeba7a949e4204e4ecf5586a6ffb3171c69`, local tag `handoff/goal1-19470ae`.
- Branch: `codex/goal6-offline-release-readiness`; all work remains local and unmerged.

Package version is the existing `0.48.0`, with no release/version promotion. The complete archive is `.cache/goal6/TokenForge-0.48.0-goal6-accepted-linux-x64.tar.gz`, SHA256 `f95f8d926c4afd0ca761f3a659378b27706d796c0cb0c61388ddb70e599bfe6b`. Manifest SHA256 is `8295f2508bc95d67c1ce61904cd3a4bba5a7ccac0f8d30af8ef34066eff383c9`; executable SHA256 is `987c863bc92f29de27ff812ad360cd1be1a8bde0fda6080f465827dbb6eb99db`; compiled credential DLL SHA256 is `30d5d1268223c806e8c6d26fd138ef2f1db58dd23f067f59ac38387e2d7bad32`.

Archive extraction verified every byte/member against the manifest, all 87 complete module sources, 100 native inputs and 71 operator files against the source commit: 160 payload files plus the manifest. The manifest was sealed before validation; its `PendingAcceptance` label is superseded only by this external acceptance receipt, never by a self-assertion inside the package. Install by retaining the whole directory and independently trusting the expected hashes.

## Reviewed changes

`storage snapshot --database <existing> --output-path <new> --domain scopes|flows|applications --json` uses SQLite's backup API and a pinned read transaction. It includes committed WAL pages, validates supported logical histories/relationships and creates a new 0600 private file. Restore to a new path with the same command. It preserves old catalog format when read and supports a pre-migration recovery cut; binary-only downgrade remains unsafe.

Snapshots are sensitive whole-database copies, including auxiliary/freed bytes. They are not credential sanitization, account-wide atomic recovery or power-failure durability. Quiesce account writers and keep corresponding JSON/cohort/inventory/uncertainty/refresh journals and package receipts. Cancellation is cooperative; synchronous phases may delay observation.

Independent review found and corrected the `sqlite_%` wildcard schema bypass, dangling source/destination SQLite companion paths, orphan histories hidden by missing input foreign keys, omitted auxiliary row validation, overbroad privacy language, smoke freshness/DLL/packet assertions, duplicate release receipt fields and the PowerShell typed-loop runtime-label collision. The final source review reported no outstanding material finding within the declared offline scope.

The package now contains the missing collector/status/export scripts and dependencies, Goal 1/2/3/4 guides, operator runbook and a Pester-free synthetic walkthrough. The legacy discovery writer is quarantined with `if: false`; workflows remain manual-only and Actions were not enabled/dispatched. Source-only publication recovery planning tests exact digests/producer tuples, bounded validity, expected-old parents, tampering and lost acknowledgements. Every verdict explicitly leaves authorization, producer/reviewer identity, journal authenticity, commit contents and actual remote observation unverified. The model cannot publish or grant permission.

## Local gates

| Gate | Result |
|---|---|
| Matching compiled-package Pester suite, excluding only two historical exact-pin experiment cases | 1,286 passed, 0 failed, 4 platform skips; two historical cases excluded and separately replayed |
| Historical Goal 5 experiment cases, exact prior package/DLL in separate fresh process | 2 passed, 0 failed |
| ReleaseReadiness preset | 85 passed, 0 failed, 0 skipped |
| Final unbundled ReleaseGuards replay | 30 passed, 0 failed |
| Native core | 1,135 checks passed |
| New SQLite snapshot cases (included in core) | 44 passed |
| Catalog history/migration/rollback cases (included in core) | 35 passed |
| Extracted package walkthrough, no source checkout/Pester/SDK | 33 checks passed; four synthetic workflows, zero-session acquisition refused with zero attempts, zero-selected/one-reused refresh, pending cohort status, saved candidate seal/replay/verify, snapshot/restore/no-overwrite |
| Real Linux archive/receipt gate | Passed with scalar runtime and exact bytes/source hash |
| Cached locked NuGet dependencies | Eight lock-content hashes and archive content integrity checks passed; all 116 extracted files including normalized nuspecs matched; no unexpected cache files |

The final broad package run took 500.354 seconds. Its process preloads the exact packaged credential DLL, asserts its digest and uses a fresh PowerShell process. The four skips are two Windows ACL and two macOS-only cases outside the declared Linux support set. Historical experiment results use package source `8d625be62ef70a43a765e37faf29b3f4c9e780d4`, manifest `1cee964b74fe63c8ffffecec8d2ed4075963d217c28d9554e3da5196f3caceea`. They are reported separately; their aggregate is not one all-tests pass on the new package.

The initial source-compilation broad run had 1,286 passes, two deliberate historical package-pin refusals and four skips. First replay setup also failed because in-memory source types preceded the old DLL. Both diagnostics remain recorded; final replay loaded the required old DLL before tests. An isolated core run stalled with loopback down and was stopped without a pass claim; final native checks ran with only loopback enabled in an externally isolated namespace. A missing timing utility was replaced with Python stdlib measurement, and the archive guard correctly refused a hardlink alias before a regular byte-identical copy passed. No failed attempt is represented as green.

Tools: approved .NET SDK `10.0.401`, .NET runtime `10.0.12`, PowerShell `7.6.7`, Pester `6.2.0`, Microsoft.Data.Sqlite `10.0.12`, SQLitePCLRaw `2.1.12`, System.Memory `4.5.3`; lock-file digests are in the receipt. Restore used cached locked dependencies with all feeds cleared. NuGet signed-content hashes differ from raw ZIP hashes; the SDK's content-hash/integrity methods were used. No signer/certificate-chain/revocation assurance or hosted provenance is claimed. No dependencies were installed and no other OS/architecture was built or tested.

The extracted walkthrough took 18.923 seconds and 195,440 KiB peak child RSS on this VM, including local validation, process startup and storage work. It makes no production network/CPU savings claim. The scripted walkthrough deliberately leaves the never-dispatched collector Pending; it does not masquerade as live recovery. Existing termination/recovery gates run in the broad suite.

## Reproduce without authentication

Use `scripts/Invoke-TokenForgeLocalValidation.ps1 -Preset ReleaseReadiness -NativeExecutable <exact-new-package>/tokenforge` in fresh PowerShell. It builds/installs/authenticates nothing. To run the broad package gate, preload that package's module/DLL before importing Pester, retain `TOKENFORGE_TEST_NATIVE` for that executable, then `Invoke-Pester ./tests -ExcludeTag Experiment -PassThru`. The two closed Goal 5 cases must run in another fresh process preloading their exact old package DLL; do not loosen their study pin. Actual wrapper/verification scripts, input hashes, output summaries and artifact paths are pinned in the receipt.

For operator acceptance, run the packaged `scripts/Test-TokenForgeOfflinePackage.ps1 -NativeExecutable <extracted>/tokenforge -Workspace <new-private-directory>` from the extracted package. Use external network isolation and existing PowerShell. The script never supplies a session or discovers operational account state. The SDK and Pester are developer dependencies, not native operator prerequisites.

## Remaining gates and approvals

Full Goal 6 is not complete. A fresh human operator must still perform all four real administrator workflows and collector recovery from these instructions with this exact package and matching receipts. No Goal 6 authentication, protected credential access, live discovery or API request was performed. The dated Goal 4 canary is not fresh Goal 6 proof and still has two unattributed original-process HTTP events; offline tests do not resolve them.

The publication-capable trusted hosted adapter remains unconnected. Before publication it must be implemented/reviewed to bind the exact seven-file candidate digest, producer repository/workflow/source/run/attempt, independent reviewer/current-main permissions, expiry, expected-old parent, proposed commit contents/ancestry and trusted recovery journal. Then separately authorized hosted permission/API/race and lost-ack tests must establish actual behavior. Caller-supplied consistent documents do not establish authority. Worker and writer privileges must stay separate, and artifact retention is not backup. This release candidate is not declared publication-ready or fully Goal-6-offline-ready while that integration is absent.

The source is on a local branch, not an approved current-main release source. No push, PR, merge, tag, release, publication, hosted compute or Actions enablement was performed or authorized. Future live approval must identify the account, exact reviewed bootstrap/client/callback/scope route, selected Graph GET, at most two issuance attempts and 180 seconds inclusive of bootstrap, explicit recovery allowance and saved-evidence reuse; additional collector recovery needs its own approved aggregate envelope. Tenant permission changes remain excluded. Hosted authorization/API proof, Actions use and publication each need separate approval.
