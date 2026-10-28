# Linux x64 offline-v1 convergence

## Current correction and final acceptance

The earlier `dc6661f` qualification below is historical and is superseded for the current PR by corrected runtime/package source **`76efe6e878ed0a1c2d4c9dba36657c6677e8c2d7`** and [the correction receipt](pr123-correction-validation.json). The final PR acceptance comment pins the immutable whole head; its containing receipt commit changes documentation only.

Frozen cycles now preserve terminal `StructurallyExcluded` in returned JSON and `vm-cycle.json`. `Complete` and `StructurallyExcluded` explicitly exit0; unfinished/failed states exit1, with `InFlightUnknown` still taking precedence. All grant resource identities, including excluded current records and history, are validated before filtering/output. Metadata-only rows may still have no resource; anonymous observations remain separate and neither evidence type guarantees acquisition.

The corrected archive is local `.cache/pr123-correction/TokenForge-offline-v1-76efe6e-linux-x64.tar.gz`, **33,915,685 bytes**, SHA-256 **`29a84b5128fd5a885dc3ffdb298dd0eaf2e23b78264bcc4c0dfcb2976126c5f2`**. Its `public-health-package.json` SHA-256 is **`093fb116ad5c10575f27105e447419b1a13fb67c144f6b085a3b9a1b07e3189c`**. Counts stay268 regular members/267 payload entries/265 source maps: five existing payloads changed (three Markdown files and two corrected scripts), with no new package member. Actual archive bytes, safe membership, every hash/size/source mapping and compilation provenance were independently inspected.

No binary rebuild was needed for these script corrections. All100native inputs match compilation source `0eb5e60fe0ecbfc7312e681dc9ce60ffdd5906ea`, retaining CLI hash `aa1ad0d814970379376ee5da6ddf531ccb22b1b738ad65709599ee64c4a2f61b`; all 47 credential inputs match `c32cd7b27e98fdeac9f376807999205d99133a38`, retaining DLL hash `a96664feb04f767cd48360a706292e2577e36472a1b27ac282c6e67899fa1a52`.

Fresh affected checks passed **70/0/0** in source and **70/0/0** from the actual extracted payload: VmCycle27, DiscoveryBootstrap9, ApplicationEvidence15, ApplicationMetadata19. The same new regressions against old production reproduced six failures (including the old Complete script's unset explicit exit) and three passes, with 33 intentional filter exclusions; its original count guard expected five failures and rejected the additional failure. That diagnostic attempt is preserved. Current checks cover result/receipt/exit handling, genuine failure and uncertainty precedence, null/malformed/missing/empty resource identities in selected/excluded current/history records, and valid evidence separation.

Expiry proof now launches an actual separate PowerShell runner process, captures its script and process exits, stdout/stderr and private receipt, and checks every counter. **Runner exit1 / SessionExpired / all 13 counters at 0 / empty stderr** is an expected refusal, not successful runner execution. The independent asserting harness exits 0 only after verifying that refusal. The old receipt's ambiguous `exitCode:0` is corrected to historical harness0 with no captured runner exit; only the new proof establishes observed runner1.

The reviewer directly audited the original 436 distinct scoped cases, failed attempts/retries/exclusions, 33 operator checks and 1157 native-core reuse. These remain historical/input-equivalent evidence; they were not rerun or added to 70 to create a new all-green full-suite total. The operator script and exercised functions/CLI/DLL are unchanged and do not call either corrected entry point. Two production scripts do change, so blanket equivalence of all runtime files is not claimed. Raw logs, harnesses, before/after controls, archives and private synthetic receipts remain local and directly available to the reviewer.

The independent reviewer accepts the correction source/package and recommends, after owner approval and merge, retiring #100/#117/#118/#119/#120/#121 and closing #114 for accepted offline lookup/planning. Keep #113/#115/#116 open for the external gates below; keep #69/#74 parked. No merge/closures, authentication, credential access, tenant changes, enrollment retry, scheduling, hosted execution/settings or release/publication were performed.

## Historical integration acceptance map

Acceptance map against merged main `744cead6e54e236597cd5e9d6a71c586b0f49c92`. This is the consolidation acceptance map; final source/package identities and actual validation are recorded below and in the sanitized receipt. #106/#122 and issue #98 are accepted history, not repeated assignments.

| Backlog | Retained implementation / missing work | Required evidence and disposition |
| --- | --- | --- |
| #100 | Integrate its exact 23 immutable action-pin replacements into current workflows | Structural equivalence except action references; no trigger/permission/activation changes; retire draft after integration merge |
| #118 / #114 | Public metadata + anonymous observation lookup; custom resource GUID/no-history scope planning | Focused public/privacy/path tests and matching newly compiled Linux CLI; close #114 and retire draft only after final acceptance/merge |
| #117 / #115 | Retain newer bounded collector/uncertainty logic; add frozen operational-cycle mode at existing entry point | Offline session-deadline/stop/frozen input/package/receipt checks; retain live VM/reboot/provider/scheduling checklist; keep #115 open |
| #119 / #113 | Retain current seven-file candidate and newer trusted verification/writer/recovery layers | Existing privacy/hash/concurrency/offline provenance tests; no draft helper or hosted wiring import; keep #113 open for real reviewer/ACL/artifact/publication acceptance |
| #120 / #116 | Retain Goal4 deterministic missing/stale/changed queue, immutable selection snapshots and frozen resumes | Matching compiled Weekly/report package tests plus queue regressions; keep #116 open for live completed-assessment and real artifact transport/publication proof |
| #121 | Replace stale Goal1-only roadmap with actual Goal1–6 supported state and remaining gates | Current support/gate/closure map; no rerun of old Goal1 assignment; retire stale documentation draft after merge |
| #69 / #74 | Passkey worker/enrollment drafts explicitly parked outside offline-v1 | No import/retry/credential access; unresolved enrollment remains held; no closure proposed |

No merge, PR/issue closure, scheduler activation, hosted run/settings change, dependency installation, credential access, authentication, tenant mutation or operational publication is authorized. Binary packages/raw receipts stay local. One convergence branch will supply one integration PR for final review with dot.

## Ordered review, merge and cleanup proposal

1. Dot reviews this single convergence PR at its exact final head, source-bound Linux archive/manifest, affected packaged results and independent audit. The source snapshot and compiled snapshot are separately named; #122 binaries are not used as proof for changed native source. Merge only after Nathan approves. No merge/closure is executed by this work.
2. After the integration merge, close **#100** as superseded: its exact 23 reference changes were retained on newer workflows; all other lines were unchanged at the pin-only commit. The existing native 340-pass guard remains intact: discovery confirms 343 cases with three Linux platform exclusions; the scope tests expand existing cases without increasing their count.
3. Close **#118** as superseded by the integrated public lookup/planning implementation and close **#114** as satisfied after matching Linux compiled/payload acceptance. Evidence: separate provenance/freshness rows, full-ledger-before-output/private-field rejection, preserved legacy lookup, GUID/no-history planning, malformed/unsafe paths and profile/inventory refusal tests.
4. Close **#117** as superseded by `-FrozenCycle` on the current bounded runner, not a competing VM loop. Retain **#115 open** for the real VM/provider/reboot/scheduler/publication checklist. Offline evidence includes same locks/budgets/bootstrap verification, immutable input refusal, cancellation/deadline stops, durable receipt and uncertainty preservation.
5. Close **#119** as superseded by the current seven-file saved-cohort candidate and later Goal6 verifier/writer/recovery. Its similarly named weekly candidate helper is incompatible and intentionally not imported. Retain **#113 open**: actual trusted reviewer configuration, approval protections and publication ACLs, hosted artifact/source/run/attempt/sealer API behavior, real publication race/tamper rejection and lost-ack retry remain unproven. The legacy discovery-data writer stays quarantined; no fabricated reviewer or candidate approval is installed.
6. Close **#120** as superseded by the newer Goal4 completed-assessment queue, generation-bound selection snapshots, compatible native weekly reports and frozen resumes. Retain **#116 open** for a real bounded incremental cycle and actual selection-snapshot worker transport/reviewed-publication acceptance. Offline CI queue tests do not prove hosted transport; selection history/token success are not both-resource completion. Do not reactivate old discovery workflow wiring merely to transport a sidecar.
7. Close **#121** as superseded by the [supported-state roadmap](goals/01-trustworthy-bounded-collector.md). It replaces the stale Goal1-only prompt; historical Goal1–6 receipts are preserved. #106/#122 stay merged and #98 stays closed; no repeat closure/milestone is proposed.
8. Leave **#69 and #74 parked**, held drafts outside offline-v1. No enrollment retry, old passkey branch import, hosted worker activation or closure is proposed. Their future reconciliation must preserve current runtime floors and action pins.

## Remaining external acceptance, not current authority

- **#113 / Goal6 publication:** configure and authenticate a real independent reviewer under a reviewed trust contract; verify who may commit approvals on main and actual publisher/ref permissions; accept real artifact retrieval and producer tuple/sealing-job responses (including partial-worker artifacts); prove exact-parent publication, tamper/stale rejection, retained-candidate retry and unknown acknowledgements without recollection. This requires separate hosted/permission/operational authorization. New privileges/settings are not inferred from source access.
- **#115 VM:** separately authorize one small frozen cohort and aggregate request budget; verify real service expiry/revocation, explicitly renewed same-account context, interruption at intent/evidence/checkpoint/projection boundaries, private receipt/account isolation and measured cancellation/overrun. Protected session provider, reboot/timer and scheduling need independent approval. Publication/backup proof remains separate and depends on #113.
- **#116 incremental collection:** separately authorize missing/stale/changed and all-fresh real completed assessments for both Graph/ARM, exact resume despite elapsed time/new evidence, and real immutable selection-snapshot artifact transport/publication retry. Offline sidecar integrity does not establish actual hosted preservation.
- **Original Goal6 activation:** [the existing single NO-GO packet](goal6-canary-decision.md) still governs enforceable custody/conditional settings mutation, concrete controller/service authority, selected distribution/runner behavior, dynamic signed-plan delivery and signer provisioning. No signature, test result, path update or gate flip substitutes for those approvals/proofs.
- **Platform/integration:** Linux x64 offline qualification does not establish Windows/macOS/ARM packages, standalone Secret Service, signing/notarization, fresh operator live/API assurance or production readiness.


## Historical source, package and validation at dc6661f

Final runtime/package source is **`dc6661f09c995c128cfdaafbc337957814b19cf9`** on `codex/offline-v1-convergence`, above merged main `744cead6e54e236597cd5e9d6a71c586b0f49c92`. The containing evidence commit changes documentation only. [The sanitized machine receipt](offline-v1-convergence-validation.json) records exact payload/test/log hashes, failed attempts, equivalence and review. Binaries, private synthetic state, packaging recipe and raw receipts remain local under `.cache/convergence/` in the qualification worktree.

| Identity | Value |
| --- | --- |
| Local archive | `TokenForge-offline-v1-dc6661f-linux-x64.tar.gz` |
| Archive SHA-256 / bytes | `e9e2bdf5eda4251e2207ed1d5c39e635bfa798b9e598164fd91d7ed3f8b0ea48` / 33,912,816 |
| Complete manifest | `public-health-package.json`, SHA-256 `c97aa00880939cf92cfcf3995db155ee234d79b7c752453d306f3648e444c88b` |
| Payload | 268 regular files; all 267 declared payload hashes/sizes and 265 source mappings verified |
| New CLI compilation source | `0eb5e60fe0ecbfc7312e681dc9ce60ffdd5906ea`; all 100 compilation/build inputs identical through final source |
| New CLI SHA-256 | `aa1ad0d814970379376ee5da6ddf531ccb22b1b738ad65709599ee64c4a2f61b` |
| Reused external credential DLL | `a96664feb04f767cd48360a706292e2577e36472a1b27ac282c6e67899fa1a52`, compiled at `c32cd7b27e98fdeac9f376807999205d99133a38`; all 47 credential inputs identical |

The changed native CLI was actually published locally for Linux x64/net10.0 with installed SDK10.0.401, locked cached dependencies and all package feeds cleared, inside `unshare -Urn`. No dependency installation or other platform build occurred. It is not the #122 executable. The unchanged external BCL DLL retains its original identity; internal project compilation performed by `dotnet publish` is recorded in the local build log. The public-health helper now accepts the existing approved executable and this explicitly pinned new CLI with the same approved DLL; no caller-controlled generic trust fallback was added.

Focused final coverage is **436 distinct passing cases across 23 files**, assembled from completed scoped runs, not one new all-green full-suite run:

| Behavior | Distinct cases with passing evidence |
| --- | ---: |
| Public lookup, metadata, scope candidates, legacy lookup, actual native custom-resource/no-history/path/profile/inventory checks | 85 |
| Frozen cycle, budgets, original collector safety/native safety, actual kill boundaries and bootstrap | 146 |
| Completed-assessment queue/weekly CI plus actual new native Weekly/report compatibility | 86 |
| Fresh-process credential bootstrap | 7 |
| Preserved seven-file candidate plus actual native saved-candidate integration | 23 |
| Public-health pin/read/privacy/diagnostic/refusal paths | 89 |

The harness extracted the actual archive, checked its payload, then added exact tests/fixtures and source-only CI/diagnostic/build-metadata scaffolding beside it. No packaged production file was overwritten. CI orchestration and packaging-source tests use scaffolding rather than claiming those tools ship in the operator package. Runtime/module/wrapper tests load the extracted payload. Full histories, privacy assertions, mock invocation counts and negative controls were retained.

Initial wider execution reported 374 passed/62 failed and one failed container because source-only CI/diagnostic scaffolding was missing. After adding unchanged missing scripts, only the four affected files were rerun: 92 passed/one failed. The remaining old packaging refusal expected source custody before receipt access. Moving that check first fixes the order; its substituted-receipt companion now supplies actual HEAD so it still tests receipt rejection. Both affected cases passed; 12 cases intentionally filtered from that final two-case run already had passing evidence. Overlapping pass counts are not summed. The earlier review finding about partial public-ledger output was corrected before packaged testing: missing/null required fields and strict dates in current/excluded/history records now fail before filtering or output.

The native workflow's existing **340-pass guard** remains unchanged; discovery confirmed **343 cases and three Linux platform exclusions**. The first guard-discovery check assumed an extra case, but the expanded scope tests replace existing cases; the assumption was rejected and the original guard preserved. No assertions or skips were relaxed.

The new package passed the **33-check synthetic operator walkthrough**. Its real frozen-cycle preflight also verified the complete final package, refused an expired synthetic session, wrote a sanitized private receipt and reported **zero requests/issuance** without mocked package verification or credential access. Actual acquisition/persistence in collector regression tests remains mocked; this is not authenticated VM proof.

Initial tested payload source was `d2b417dbf29d8f97cb674ca439e6d3645778d2c5`. Rebinding to final source changed only two Markdown payloads and the manifest. Every executable, module and operator-script byte is identical; post-execution hashes still match. Successful runtime tests and operator checks were reused on that demonstrated equivalence. The final manifest/source pins were exercised once in the real zero-request expiry preflight. Development summary source labels predate some containing commits; the receipt separately binds executed file bytes to final blobs instead of relabeling those summaries.

The **1157 native core checks** were not repeated: all core test/implementation/credential/global inputs are unchanged and their preserved log hash matched. Historical full baseline1663/four platform skips remains historical, not a new full-suite result. Old Windows source checks do not qualify this changed budget helper on Windows. Existing nine analyzer findings remain historical; changed PowerShell files parse without errors. No all-platform, live/API, signing, standalone Secret Service or production acceptance is inferred.

Independent runtime/package review found no remaining source/package blocker, verifying actual archive membership, all payload/source maps and compilation/credential inputs; producer suites were not rerun by the reviewer. Final completed-evidence audit is recorded in the JSON receipt. #114 is satisfied for this offline scope after review/merge; #113/#115/#116 stay open for the named external gates. No merges, releases, issue/PR closures or operational activation were performed.
