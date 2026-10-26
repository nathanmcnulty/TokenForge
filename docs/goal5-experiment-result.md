# Goal 5: rejected callback-cap experiment

Goal 5 is **complete with a reviewed rejected experiment**. Reducing warm acquisition from two published callbacks to the previously observed callback alone saved attempts but lost six verified client/resource pairs in the frozen synthetic challenge set. The candidate is rejected; production policy and defaults remain unchanged. Goal 6 has not started.

## Result and decision

The [preregistered protocol](goal5-bounded-experiment.md) requires retaining every baseline success before considering at least 10% fewer logical issuance attempts. Both arms use the unchanged `ProfileScopeAcquisition.Acquire`, the same synthetic namespace and inputs, explicit `User.Read`, the core's existing `offline_access` request, one candidate client and zero additional API scopes. Only `maxRedirects` changes, from two to one. Responses depend on case, phase and concrete callback, never arm or attempt ordinal.

| Partition | Pairs per arm | Baseline successes | Candidate successes | Lost successes | Baseline attempts | Candidate attempts |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Discovery | 8 | 6 | 2 | 4 | 21 | 16 |
| Holdout | 4 | 3 | 1 | 2 | 10 | 8 |
| Total | 12 | 9 | 3 | 6 | 31 | 24 |

Attempts fell by **22.581%**, but success fell from 9/12 to 3/12, a paired difference of **−50 percentage points** with six losses and no new successes. Attempts per successful pair worsened from 3.444 to 8, including bootstrap. Lost successes in both partitions fail the primary gate, regardless of attempt savings.

This is a predeclared synthetic counterexample set, including working fallbacks after a rejected, excess-scope, opaque, throttled or wrong-principal primary. It is not a blind holdout or estimate of service prevalence. The finding rejects the general callback-cap proposal for this tested behavior; it does not estimate tenant coverage or claim other policies cannot improve discovery.

## Bounded execution and retained uncertainty

All **24 trials** completed, alternating baseline/candidate order by case, with **55 synthetic logical issuance attempts** against a 72-attempt ceiling. The trial phase took **423.368 ms**, below 60 seconds; the longest trial took 81.695 ms, below five seconds. Package and frozen-input validation precede that trial clock. No concurrency was added. Logical attempts are not measured HTTP request savings.

| Core result | Baseline | Candidate |
| --- | ---: | ---: |
| Verified scoped token | 9 | 3 |
| No verified token | 1 | 7 |
| Cancelled | 2 | 2 |

`NoVerifiedToken` retains uncertainty; it is not a claim of permanent denial. Each arm received one synthetic throttling scenario, one session-loss scenario and one prompt-required scenario. The latter two explicitly cancel the trial. These labels are injected challenges, not evidence of actual service status/prompt classification. No prompt was invoked and no retry wait occurred.

All 55 attempt charges reconcile with their retained traces. All 42 executor-created token owners were disposed; the 12 successful returned result owners were separately disposed in the harness. No extra API scope was accepted. The report retains every trial, concrete client/callback and requested API/OAuth scopes, core outcome, injected scenario, cancellation, disposal count, elapsed time and shared-process peak working set. Shared peak memory is not an isolated arm measurement; no timing, memory, HTTP or live performance improvement is claimed. Source/inventory network requests, database operations and child starts during trials are absent and explicitly zero.

Execution and local validation ran in a network-isolated `unshare -Urn` namespace with PowerShell/.NET telemetry disabled before startup. There was no authentication, real session, production credential/private-store read, tenant access or external request. Inputs use a clearly synthetic namespace; fresh synthetic timestamps are regenerated for replay without relabeling real observations.

## Exact source, package and validation

- Preregistration: `8bbe31edf07e499facc598ff14f10fa002c44254`, committed before comparison execution; fixture and hypothesis unchanged.
- Reviewed experiment source: `6e8479ad4a78999fce61c242759c0ef5b5d4f5d6`.
- Preserved roadmap handoff: `19470aeba7a949e4204e4ecf5586a6ffb3171c69`; Goal 4 parent `9476bb952e1d4fb0896781991eb794ad308a1b13`.
- Reused Linux 0.48.0 runtime source: `8d625be62ef70a43a765e37faf29b3f4c9e780d4`.
- Package manifest SHA-256: `1cee964b74fe63c8ffffecec8d2ed4075963d217c28d9554e3da5196f3caceea`.
- Cohort SHA-256: `36a2b88ae045959f41637f82ce000cfa9e64f2b5a8a5f07fa16ca3a7e3a25547`.
- Recorded input SHA-256: `c2529a6bc85be3cb480106b6e68c31ad71835ec024285b025babc991bd5d2c44`.
- Recorded report SHA-256: `155c6bcf968dbb48e64edd7e98dde53d7e973cd85e9db1c495902150a3179665`.

The Pester **6.2.0** local `Lab` preset passed **35 tests, zero failures, zero skips**: 13 laboratory cases plus 22 existing scope-candidate/native-planning cases. The lowered-budget fixture retains the charged active bootstrap and partial trace, reports zero completed trials/pairs, and returns `Stopped`/`Inconclusive`. Input-boundary tests reject credential/private-path/command fields, duplicate keys and identities, foreign scenarios and incomplete/mismatched cohorts. The full comparison fixture verifies actual core execution, original callback preference, callback-keyed responses, cancellation, scope checks, disposal and create-new reporting.

Independent reviews cleared the protocol, implementation and stop accounting, then reconciled all recorded inputs, outcomes, counters and hashes and approved the **rejected** disposition. Early validation failures exposed synthetic-array serialization, duplicate module loading and a PowerShell disposed-property probe issue; the harness was corrected and the logs retained. They were not counted as ordinary failed service pairs or evidence of cost savings. The lower-level runtime was unchanged.

All 150 package payload files, 87 module source files, 97 native build inputs and six relevant validation inputs were verified. No runtime build or dependency installation was needed. The earlier Goal 4 broad suite and core harness remain evidence for the unchanged runtime; they are not presented as a newly run Goal 5 full suite. Only laboratory scripts/tests/documentation and the focused validation preset changed. All seven workflow files remain unchanged and manual-only; Actions were neither enabled nor dispatched.

The [structured receipt](goal5-experiment-result.json) contains all 24 trial records, exact package and validation hashes, protocol/namespace/budgets and local artifact hashes. Raw reports, frozen inputs and logs remain under `.cache/goal5/`; generated reports are mode 0600. To reproduce from the repository root with the pinned package and a new output path:

```bash
POWERSHELL_TELEMETRY_OPTOUT=1 DOTNET_CLI_TELEMETRY_OPTOUT=1 unshare -Urn \
  pwsh -NoProfile -Command '. ./scripts/Invoke-TokenForgeCallbackExperiment.ps1; Invoke-TokenForgeCallbackExperiment -NativeExecutable ./.cache/goal4/accepted-package/linux-x64/tokenforge -OutputPath ./.cache/goal5/replay.json'
```

Counts and disposition should reproduce; synthetic time anchors, elapsed times and peak memory vary. There is no remaining blocker to closing this rejected experiment. No production policy version was created because nothing was promoted. Another proposal or any live experiment requires separate scope and authorization. No publication, push, PR, merge, tenant permission change, hosted compute or Goal 6 work occurred.
