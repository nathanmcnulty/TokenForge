# Goal 4 offline acceptance

Goal 4 is **offline-ready** on `codex/goal4-bounded-refresh`. The required synthetic and local Linux gates passed. No Goal 4 live authentication or discovery was performed; this is not live or production completion. Goal 5 has not started.

## Exact revisions and package

- Runtime source: `8d625be62ef70a43a765e37faf29b3f4c9e780d4`.
- Validation source: `fdebd149a9e4184cb97af2467cc2b9a2b088ac52`. Its later changes cover CI scripts, tests and documentation; all runtime build inputs still match the runtime source exactly.
- Reviewed Goal 3 parent: `c3adeda2f1863c637da9190ffaff7452676a8fff`.
- Preserved roadmap handoff: `19470aeba7a949e4204e4ecf5586a6ffb3171c69`, tag `handoff/goal1-19470ae`.
- Unmerged draft #119: `e2aab00b2079dc1e99dc38aa1a994d4877b1bbf5`; #120: `360d0e04edbfca41f8001d4838ef8d67b5ef338e`. Their contracts were reconciled selectively; no draft or workflow was merged.
- Local package: `.cache/goal4/accepted-package/linux-x64`, version 0.48.0, 150 payload files plus manifest; all 87 module source files and 97 native inputs verified against committed blobs.
- Package manifest SHA-256: `1cee964b74fe63c8ffffecec8d2ed4075963d217c28d9554e3da5196f3caceea`.
- Executable SHA-256: `d45619f1238d858d918b8b36d1b3c551d06fee6bbb75a215e660bc4219757eaa`.
- Credentials DLL SHA-256: `d977e4ea04a015ed80a3c46ceaa23a0cb09af6e8628cd878cb673dbe5dbeba34`.
- Archive: `.cache/goal4/TokenForge-0.48.0-goal4-accepted-linux-x64.tar.gz`; SHA-256 `23656191835272d65cedbb6574e1527a44ff5fc44a7a97b1ae1f000f74550876`.
- Validation-input SHA-256: `18e4a40fea9b7907f00fff90f1bb68f4fce2df5c8b2f9c39ffe681530a5cc395`, covering 83 files.

Changed native source was built locally with .NET SDK 10.0.401, PowerShell 7.6.7, Pester 6.2.0 and locked cached dependencies with all NuGet feeds cleared. No dependency installation was needed. Independent review verified complete package/archive membership, exact hashes and source inputs. All seven workflow files are unchanged and manual-only; Actions were neither enabled nor dispatched.

## Local acceptance gates

| Gate | Passed | Failed | Skipped |
| --- | ---: | ---: | ---: |
| Full package-backed Pester 6.2.0 suite | 1217 | 0 | 4 |
| Final local runner `Refresh` preset | 97 | 0 | 0 |
| Native core harness | 1086 | 0 | 0 |

The full suite contains 1221 cases with zero failed containers. The four skips are existing Windows ACL/macOS cases; native prerequisites were present. Focused counts overlap the full suite and are not additional unique coverage. No other OS or architecture was built or tested. The full run used direct `Invoke-Pester ./tests` after loading the matching package in a fresh process, preserving a structured summary even on failure. The unchanged native harness result was reused; it was not rebuilt or rerun for the script-only validation delta.

Required behavior passed offline:

- All-fresh input yields no issuance plan. Relevant grant/definition/callback/policy changes invalidate compatibility; unrelated names, pairs and principals preserve eligible reuse.
- Immutable legacy pins and exact resume remain intact. History retains original source/record IDs, dates and phase-specific provenance; failures, contradictions and incomplete visibility remain explicit.
- Deterministic priority, bounded fairness, single-request priority, cooldown and retry ceilings pass. Selection reports budget deferrals and freshness misses without changing frozen policies.
- Every external operation reserves durable intent; unknown consumption stays charged. Four actual process-kill cases cover pre-request intent, remote result, durable terminal and projection boundaries. Recovery does not replay completed evidence or automatically retry issuance.
- The strict production adapter validates every synthetic issued token, account and scope ceiling. Declared API operations require separate `-OperationCheck`. Stable account-store identity prevents per-plan journal resets.
- Public immutable selection generations and atomic state survive replacement, removal and interrupted bundle handling. Existing transport/no-plan gates remain intact; public assessment never becomes private authorization.
- Native and PowerShell plan/validate consumers agree on tested JSON and exit behavior through protected file ingress; malformed input and duplicate flags fail closed. Native capture/status/project use the reviewed shared core, whose journal and projection behavior is tested; these three native command routes were not separately executed by this gate. Full malformed and credential-bearing core inputs fail closed.
- Independent implementation review and separate receipt/claim audit found no outstanding material finding after fixes. Final recorded gate results complete that audit.

## Frozen synthetic cost comparison

Both paths validate the same complete 156537-byte frozen input at the same evaluation time and produce the same plan identity. The baseline actually calls the shared strict acquisition code with synthetic token and identity adapters. Incremental reuse retains original references.

| Measure | Baseline | Refresh |
| --- | ---: | ---: |
| Retained useful context facts | 20 | 20 |
| Strict acquisition calls | 20 | 0 |
| Synthetic token acquisitions | 40 | 0 |
| Synthetic identity checks | 20 | 0 |
| Modeled HTTP exchanges | 100 | 0 |
| Actual external requests | 0 | 0 |
| Full validation/planning, ms | 361.088 | 319.217 |
| Projection, ms | 63.422 | 0.024 |
| Local elapsed, ms | 727.822 | 323.747 |
| Shared-process peak working set, bytes | 192102400 | 195756032 |

This is one fixed-order synthetic process measurement. Peak memory increased; no memory reduction or live/network speedup is claimed. Source collection, inventory fetch, database I/O, child processes, retries and retry waits are absent and explicitly zero. This measures request avoidance and local overhead, not performance of those absent stages. No concurrency was added.

Frozen input SHA-256: `eb5ee70b56bf9ff4968f243c35b87306529018906974404a7e83fb192695870c`.
Benchmark script SHA-256: `d14ced68ba0ddad807d01547538b1908a0546d26745ac45b51723bd0eb8383f9`.
The frozen input, full benchmark, logs, package and archive remain local under `.cache/goal4/`; the [structured receipt](goal4-offline-acceptance.json) pins their hashes.

## Remaining limits and separate live approval

No required offline gate is blocked. Public permission definitions remain explicitly `NotCollected`, with their 24-hour freshness target reported as unmet. Manual catalog collection does not guarantee daily freshness. Process termination was tested; power-loss directory durability was not. The canonical journal boundary requires the operator to keep one stable account directory; it is not an OS-wide registry. Caller pins are provenance assertions, not signatures; token inspection does not verify JWT signatures.

A small Goal 4 live canary needs new explicit approval. Proposed scope: authenticate as `secadmin@sharemylabs.com`, use only the previously reviewed ZTNA Network Access Client `038ddad9-5bbe-4f64-b0cd-12434d1e633b` for bootstrap and final issuance, callback `https://login.microsoftonline.com/common/oauth2/nativeclient`, explicit Graph `User.Read`, zero additional API scopes, at most two issuance attempts, cooperative 180-second deadline and separately selected Graph v1.0 `GET /me?$select=id`. Recheck the route and current inventory before execution; no fallback or tenant permission changes. Save the one dated observation, project/export it, then replan the same frozen cohort to verify reuse without another issuance. An unexpected prompt, scope, account, transport uncertainty or budget limit stops the run and preserves charged evidence.

This milestone performed no authentication, credential lookup, live discovery, tenant permission changes, hosted compute, publication, push, PR or merge. The historical Goal 3 canary is not Goal 4 live proof. See the [implementation and operator contract](goal4-bounded-refresh.md).
