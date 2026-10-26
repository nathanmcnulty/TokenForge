# Goal 1 offline acceptance receipt

Result: **offline-ready, live acceptance pending**. This is Goal 1 only. No live/production completion is claimed.

Implementation source is `3bf93cbcee318e8758005d12258808ec7184394f` on `codex/goal1-bounded-collector`, based on `1be12d75c7e2a63eac8e14c32d54e79cec4a23ef`. Handoff `19470aeba7a949e4204e4ecf5586a6ffb3171c69` is retained as `handoff/goal1-19470ae`. The final receipt commit changes documentation only. Draft reconciliation and operation instructions are in [the collector contract](goal1-collector.md); exact machine-readable inputs/results are in [the JSON receipt](goal1-offline-validation.json).

## Gates

| Gate | Final evidence |
| --- | --- |
| Collector preset, exact committed source and extracted Linux x64 package | 111 passed, 0 failed, 0 skipped |
| Native collector core / SQLite cohort policy | 46 checks passed |
| Discovery regression selection | 154 checks covered: 138 unchanged passing checks reused plus 16 affected checks passing after stale assertions were corrected |
| Final affected regression run | 28 passed: 7 ResearchCohort, 9 DiscoveryBootstrap, 12 FlowEvidence |
| Native SQLite flow integration | 4 passed, 0 skipped |
| Actual process-kill boundaries | All 4 passed, included in Collector |
| Complete archive extraction, all files, module import and version | Passed; 134 files verified |
| Independent source/security review | No open must-fix findings; reviewer inspected source/tests and did not independently rerun tests |

The original Discovery run had 152 passes and two stale outcome assertions failing. Both were resolved and the affected suites passed; unchanged passing evidence was reused. Final Collector was rerun after the last code/test changes against the exact committed source and extracted package. Synthetic results prove offline behavior only. Fixtures cover paused/expired/ambiguous interaction, request-scoped declines, mismatched account, throttling, cancellation/deadline/overrun, corrupt historical rows/plans/intent timestamps, private paths, locks, hash tampering, same-plan recovery and export privacy. Completed evidence retains its original dates; true process termination bypasses finally blocks.

## Package and export

A complete local Linux x64 package was built with existing SDK 10.0.401, .NET runtime 10.0.12 and locked cached dependencies with package sources disabled. PowerShell is 7.6.0; Pester is 5.7.1. No software/dependencies were installed. Native/core inputs did not change after the build; adapter files were synchronized to the committed source without rebuilding unchanged native code. This is local build provenance, not a downloaded release attestation. All package file/dependency hashes are retained in `.cache/goal1/package-provenance.json` and its identical archived manifest.

| Artifact | SHA-256 |
| --- | --- |
| Complete `TokenForge-0.48.0-goal1-linux-x64.tar.gz` | `6f0a78c13ac1473d5439bcfe4857e38a5ad3f1719c9d8d21f2b1f19f7860f005` |
| Full package manifest | `399b9eb03941b9512a06b21ab55dbd6b0891846cb8eecefe68453efe57ae2b82` |
| Native executable | `d65f1686542444dcfab9fe1bb38eb5989a815a2e743fc04a6276648fcf7de196` |
| Adjacent credential DLL | `13590ca58fc86b195525ac25507620366b86413d477040416398f10914a7f460` |
| Native build-input manifest | `e045aa00fe2cc1a2bfc3c9a9dca2098f45bd658610650d8ad51646bac4dd648c` |
| Saved synthetic export manifest | `2c3d77699f10181be3c05d4644b145c0d420b62443c4c604357d8884a8b9a1ec` |

The public synthetic example is at `.cache/goal1/synthetic-artifacts/kill-ExportBeforeMove-9735b8f286c24f2fb9d7aa1e0cdf4585`. It binds source `3bf93cbcee318e8758005d12258808ec7184394f`, producer run 1 / attempt 2, one selected pair and one exact terminal cell. It contains one scope observation and one flow observation, zero excluded/pending/paused/blocked/unknown cells, and retains review Pending. There was one simulated issuance, zero recovery/export issuances and zero live requests. The example was recovered after an actual export-stage process kill. It is an integrity/privacy-validated review candidate, not independent approval or publication.

## Remaining acceptance and approval

No required offline gate remains blocked. Live acceptance still needs separate authorization and account/session/service proof: verified account and inventory; bounded stop/restart; explicitly renewed same-account continuation; safe saved-evidence export; unchanged grants/registrations within checked visibility.

A specific canary approval must name one account and a frozen set of ten Graph-only client/resource pairs, one published callback per client, serial existing flows, a 15-minute cooperative deadline, at most 30 total issuance attempts including bootstrap/retries, bootstrap ceiling 1 per invocation / 20 HTTP exchanges, inventory 100 HTTP requests / 50 pages, sources 0 using reviewed saved sources, total HTTP 300, at most three recognized retries per operation and transport timeout 30 seconds. Allocate the **remaining aggregate allowance** across stop/restart/renewal invocations from durable receipts; a restart does not authorize another full canary. Review a new bootstrap/recovery allocation explicitly if needed. No registration/consent/permission changes are included. Do not send credentials through this chat.

No Actions, live discovery, protected credential access, publishing, push, PR or merge occurred. The existing checkout was not reset or cleaned. Goal 2 was not started.

## Copyable next-session status

```text
Goal 1 offline-ready; live acceptance pending. Stop before Goal 2.
Workspace: /home/nathan/GitHub/TokenForge-goal1-2rQ8rilR
Branch: codex/goal1-bounded-collector
Implementation source: 3bf93cbcee318e8758005d12258808ec7184394f
Read docs/goal1-offline-validation.json and docs/goal1-collector.md.
Use the verified complete Linux package under .cache/goal1/extracted/.
Native SHA256: d65f1686542444dcfab9fe1bb38eb5989a815a2e743fc04a6276648fcf7de196
All required offline gates passed; independent review has no open findings.
Do not authenticate, use protected credentials, run live discovery or hosted compute,
push, open PRs, publish or merge without separate explicit authorization.
A live canary needs the exact account/cohort/envelope approval described above.
```
