# Merged runtime packages - local qualification

Read [the qualification and #98 recommendation](runtime-package-qualification.md) and [sanitized identities/results](runtime-package-qualification.json). Packages bind exact source `a7694cb65d8cfadfe41ba7efbd6d20cdec4effa4` above merged main `ecf16f4fe98e2b29dc444e273fcc08d795a0d915`. Both extracted payloads passed 138 focused checks; operator 33 and administrator 21 passed. Compiled inputs/binaries were reused after equivalence checks. Independent packaging/artifact review found no blocker. Packages/raw receipts remain local. Recommend closing #98 after final PR review/merge; no merge, release, closure, hosted/live work or activation was performed. Earlier handoffs below remain historical.

# Review corrections and source acceptance - PR #106

Read the [review follow-up](pr106-review-followup.md) and [exact-file receipt](pr106-review-followup.json). Two bounded runtime corrections now supersede the earlier documentation-only delta: inventory budget forwarding and Windows request-ledger replacement. Final related offline checks passed 131/131 with no skips. Historical Linux package/full-suite receipts below remain scoped to their original source and do not qualify the corrected scripts or a new distribution. Both review findings are resolved; the final review response pins the complete immutable candidate. No push, merge, hosted workflow, package release or operational activation was performed in this follow-up. Earlier handoffs below describe historical checkpoints.

---

# Final pre-merge review — PR #106

Read [the final review handoff for Dot](pr106-dot-final-review.md). The final reviewed walkthrough checkpoint is `7a0417dc17517880156f1dff26e1223b5c4210d5`; its 21-command replay passed against the exact reviewed runtime package from source `58203ecdcee47c4bdaaef0801d0b496d22daa35f`. The containing checkpoint adds handoff documentation only. Nathan authorized the source push and opening the existing PR for review on 2026-10-26; leave it unmerged pending Dot's final review and Nathan's merge authorization. Earlier draft/local-only statements below describe their historical checkpoints. Packages and raw receipts remain local; no hosted compute, authentication, live work, package publication or activation is authorized.

---

# Current runtime integration candidate — issue #98 / PR #106

Exact independently reviewed and full-suite tested candidate: **58203ecdcee47c4bdaaef0801d0b496d22daa35f**. Read [runtime baseline acceptance](runtime-baseline-validation.md), its [exact-source/package receipt](runtime-baseline-validation.json), and [supported baseline/exceptions](runtime-baseline.md). This checkpoint adds documentation only above that candidate; it retains current main `4c986518`, prior runtime draft `b35461a6`, and owning checkpoint `9f6b4f2` without discarding newer functionality.

Full Linux offline gate: **1663 Pester passes, zero failures, four platform skips**, on PowerShell 7.6.7 / Pester 6.2.0. Native core:1157 checks; repaired Sealer gate:224/0/0; extracted Linux package:33 checks. Packages remain local and unpublished; archive hashes, distinct native compilation/overlay identities, all100 matching compiled inputs and independent review limits are in the receipt. No Actions, live work or original Goal6 deployment was reopened. PR106 stays draft/unmerged; the original MicrosoftApps malformed-ID blocker remains unrelated and unchanged.

# Earlier MicrosoftApps diagnostic milestone — precise strict rejection

Read [the diagnostic guide](public-health-microsoftapps-diagnostic.md) and [exact-source receipt](public-health-microsoftapps-validation.json). This adopts the MicrosoftApps goal at `ebdaa42fd7021456071b4bd61dfffb785b449740`, with coordinated dependency guardrails at `b7831a35680b5dd917b4d07eaee25f947c2a2f59` through index `61b0536e4090b58fe610e04dcfe3aa6b83fc5b30`. Start from owning `4b95c76f3a7eccf4fafc67d9e76d7563a12e5c74`; exact reviewed/tested source is **03ec0774e2475a710c6b87dda4fae824f604e414** on `codex/goal6-reusable-sealer`. The containing checkpoint adds handoff/receipt only.

One anonymous, no-redirect/no-retry MicrosoftApps GET returned HTTP 200, 840,156 bytes, raw SHA256 `741ce7aa8c960e47fda87ca93bcf1b84c7681bef559571fea185f2a68abeda4c`. Raw bytes and acquisition facts remain private and immutable. Offline diagnostics identify **ApplicationIdentity** at zero-based record **2227** of **4449**, before projection. Independent PowerShell/.NET inspection confirmed the AppId has a valid 36-character nonzero GUID prefix followed by two extra characters; the suffix contains non-ASCII characters and whitespace. No raw identifier, name or arbitrary upstream string is published.

This is current-input reproduction of a strict published-ID refusal, **not proof of the historical trial response**. Dot's earlier artifact inspection localized MicrosoftApps Invalid but could not identify a detailed reason: the artifact contains no failed-source raw bytes/hash or detailed refusal code. The earlier receipt's implication that detailed reasons already existed there is corrected.

The malformed-ID rejection is intentionally preserved: no trimming, identifier repair, record dropping or source broadening. New fixed-code diagnostics are offline/private and repository-only; the public exchange schema and existing validator/projector remain unchanged. They produce no exchange, network request or import. Unexpected storage/programmer failures stay fatal. Synthetic cases preserve successful ROADtools/resources observations, one-attempt invalid status, the initial empty incomplete ledger, and exact previous bytes/dates and retained source facts.

Source review completed **before candidate execution**. Producer local results using the exact approved PowerShell 7.6.7/Linux x64 kit: **20 focused Pester 6.2.0 tests passed**, then **161 PublicHealth tests passed**, zero failures/skips, inside network-disabled namespaces. A separate reviewer inspected source and independently checked the bounded current-input facts; the entire suite was not independently rerun.

No production/build/test dependency was introduced or removed. No Python/Node/package-manager/parser package, runtime upgrade, native rebuild or replacement asset was added. All 100 native build inputs and 164 source-backed package files still match the existing kit under its documented layout. Native/package source remains `c7d0b255612280e05605eca2e9ccfb44d5d68e18`, archive SHA256 `2b92b0d0662809f3aeaf4992935cc38323c78d8223430b5f58eb9216156ef3e8`; the new diagnostic is not silently bundled into that release. The guide records pin/patching obligations and verified older-helper consumers; their retirement and original Goal 6 work remain deferred.

No additional hosted run, artifact download/sync/import, saved-evidence reuse, Entra authentication, tenant change, dependency installation, workflow/settings change, release asset, PR, merge or operational activation occurred. A complete fresh catalog and historical-byte cause are not claimed. The bounded milestone is complete; any new hosted or artifact-import work requires its own applicable authorization.

Earlier handoffs below are historical and apply to their stated exact revisions.

---

# Historical manual trial result — incomplete exchange uploaded successfully

The approved recovery dispatch completed successfully: [run 40161542664](https://github.com/nathanmcnulty/TokenForge/actions/runs/40161542664), workflow ID `395612174`, exact trial head `04e89350b74e1a600c233aa43572a80a6f3ea642`, branch `codex/public-health-manual-trial-20261025`, attempt 1. See [the sanitized result receipt](public-health-manual-trial-result.json).

Only the reviewed shell patch was applied above trial head `5893574`; product code/package bytes are unchanged. The one Linux x64 Ubuntu 24.04 job passed the pinned PowerShell 7.6.7/runtime, package/source checks and artifact upload. The collector made **3 requests in 33.429 seconds**, reporting **CollectionComplete=false, ExchangeComplete=true, CandidateCount=0**. This is useful proof of the hosted incomplete-result and upload path, not a complete fresh catalog. No second run or automatic retry followed.

Upload logs reported exactly three files. Artifact `tokenforge-public-health`, ID `12586302492`, is 1,472 bytes; platform digest is `944b5ac4d1632f72b423c7abde37c7d86e07e2855b8be01b5a06474774129618`, with requested 14-day retention and recorded expiry in the receipt. Only run/job/log/artifact metadata was read. **Artifact download, member inspection, sync/import and saved-evidence reuse remain blocked and unperformed.** Aggregate logs do not identify which source failed; no cause is inferred without the artifact evidence.

Main remains at registration `4c9865185977033e110e8eaaf71fb8f649ec18f2` with its job false. Repository Actions remains enabled under explicit approval; all eight legacy workflows remain individually disabled. No PR, merge, additional Actions setting change, Entra authentication, tenant permission change, schedule or Goal 6 operational activation occurred. The trial is Linux-only; no repository-wide macOS restriction was added.

No further hosted execution is authorized. A possible next bounded decision is download/local inspection of only artifact `12586302492` from this exact run; sync would still need separate approval. The two exact code/runtime assets remain published under `public-health-offline-20261024` with their approved hashes. Original strict Goal 6 custody/ZIP research remains deferred.

Earlier handoffs below are historical and apply to their stated exact revisions.

---

# Current manual trial handoff — dispatch rejected before a run

See [the approved trial receipt](public-health-manual-trial-receipt-20261025.json). Dot's branch correction at `401b247cd2ce7bac7c4097c4b78e09ed80c1a1fc` supersedes the historical default-branch dispatch proposal below. The exact two archives are published under `public-health-offline-20261024`, with matching remote SHA256 digests. Repository-wide Actions was enabled after separate explicit approval; all eight legacy workflows remain individually disabled.

Main registration is `4c9865185977033e110e8eaaf71fb8f649ec18f2`, adding only the new workflow with its job false. Trial branch `codex/public-health-manual-trial-20261025` is pinned to `589357448104ca6f5d0239138d0094dff57057db`, based directly on reviewed checkpoint `3c1e274af04c22c8ef6db651dd025c2ad6739217`; only its workflow was added with numeric ID `395612174` and job true. Product code was not promoted to main.

The single dispatch request received HTTP 422: GitHub rejects `runner.temp` in `steps.shell`. It created zero runs, executed no hosted collection and produced no new artifact. There was no retry. Artifact download/sync remains blocked; no Entra credentials, tenant changes, PR or merge occurred.

[The proposed shell correction](../publication/health/public-health-shell-fix.patch) is local/source-only and applies to the exact trial head above. It replaces the invalid shell expression with Bash, a quoted heredoc and the exact reviewed PowerShell invocation. The PowerShell body, hashes, action pins, permissions, budgets and output allowlist are unchanged. YAML/Bash/PowerShell syntax and independent diff/body review passed without executing the collector. No active workflow was changed by this correction.

**Next approval needed:** apply this exact patch to the trial branch, record/verify its resulting commit, and make one new dispatch under the same approved limits. Stop for any PR/merge/additional setting change. Artifact download/sync stays blocked. Main's job remains false. This is a concrete recovery proposal, not evidence of successful hosted collection or upload.

Earlier handoffs below are historical and apply to their stated exact revisions.

---

# Current finishing checkpoint for public metadata health

Start with [the finishing validation receipt](public-metadata-health-finishing-validation.json) and [the manual-trial decision packet](public-metadata-health-manual-trial.md). This checkpoint adopts Dot's goal at **cc52dde2f020656e559acd70907b3344e7bc6863** from owning **bee9ad1f0240965840b8aa93a6e5acae1dba82f2**, on `codex/goal6-reusable-sealer`. Tested source and rebuilt native source are **c7d0b255612280e05605eca2e9ccfb44d5d68e18**. The containing checkpoint adds receipt/handoff/proposal and dormant-template changes only.

Both findings are fixed: older distinct independent imports retain deduplicated SQLite history without regressing the current record, and source/projector contract failures emit an incomplete exchange preserving previous metadata bytes/dates. Unexpected storage/programmer failures still fail visibly. The new package verifies all 100 tracked native inputs against owning source; the old unchanged-native assertion is not reused.

Local Linux acceptance: **141 Pester 6.2.0 tests passed**, zero failures/skips, using the exact extracted rebuilt package and separately extracted approved PowerShell 7.6.7 runtime. Native synthetic harness: **1,157 checks passed**. Independent source, boundary, package/hash/inventory and decision-packet review found no outstanding material findings. The reviewer independently ran the combined-claims regression; the broader suite remains producer-run evidence. See the receipt for the frozen exact-package performance result and its memory/timing limits.

Package SHA256: `2b92b0d0662809f3aeaf4992935cc38323c78d8223430b5f58eb9216156ef3e8`. Runtime archive SHA256: `3da36d92808db25aa2466422b1b765da792adc159d890512fbae852e2b495d3b`. Both remain local and unpublished. Private receipts, raw responses and synthetic state remain outside Git. There was no external collection/transfer or credential access in this finishing task; only the expressly authorized sanitized Git source exchange is permitted.

The practical offline loop is review-ready. Standalone snapshots are additive, cooperative acceptance timers do not preempt synchronous steps, current upstream completeness and Ubuntu/hosted artifact interoperability remain unverified. The original Goal 6 custody/ZIP experiment and operational activation remain deferred. Active `.github/workflows` bytes are unchanged from `bee9ad1`; the dormant proposal remains outside that directory, literal false and pending a real workflow ID. Live work, package publication, Actions, PRs and merges remain blocked pending the separately reviewed bundled manual-trial authorization.

For Dot: review the containing checkpoint on `codex/goal6-reusable-sealer`, the finishing receipt, manual-trial proposal, M1/M2 implementation and new regressions. Source/package hashes and producer/independent evidence are separated in the receipt. Return focused findings or a decision on the concrete manual-trial proposal; do not infer approval to execute it.

The earlier handoffs below are historical and apply only to their stated exact revisions.

---

# Current public metadata / workstation handoff

Use owning branch `codex/goal6-reusable-sealer`. This milestone starts from **91f858f8b7b70722223f4baa225a6cfc2ac340b6** and adopts [the practical runner/workstation goal](tokenforge-runner-workstation-design.md) unchanged from **50bb94bc38531834a73c3b8e46e3bebfde9ee467**. The documentation branch's implementation was not adopted.

Start with the [operator guide](public-metadata-health.md) and [validation/canary packet](public-metadata-health-validation.json). The new product path collects only the three fixed public metadata sources, exchanges three validated public files, and imports them transactionally into private SQLite. `tokenforge.ps1 health status` reads saved status; existing discovery and deep exact-plan resume commands remain intact. The frozen realistic fixture and independent review cover local use; no hosted or live-service completion is claimed.

Local acceptance: **123 passed, zero failures/skips**, Pester 6.2.0, exact executable/package source **e93cdcc9764cf43347321b783f23c36526c60030**. The extracted package's full CLI fixture loop covered **5,502 candidates and 100,000 scope edges in 231.85 seconds**, including repeat import; saved status took **0.146 seconds**. Package SHA-256: `c1656f3a20135bc2665506b9678b097b39dbfceee5e36e2a0b6afd3934fd4283`. Independent review and package/evidence audit found no outstanding material issues. This containing checkpoint changes only documentation and the dormant package hash; tested executable bytes remain unchanged.

Anonymous public-source reading also occurred locally. Collected documents, source hashes/counts/statuses and diagnostics remain private; no complete current public refresh is claimed. Invalid upstream IDs are reported as source errors with prior facts preserved, rather than silently repaired or dropped. The approval packet distinguishes local engineering acceptance from source freshness and the unrun hosted trial.

The user adopted the simpler sole-trusted-administrator model for this separate lane. It does not require Goal 6's signed-plan, raw-service transport or competing-trusted-admin exclusion proof. That strict original-byte experiment remains parked with all refusal gates and historical receipts preserved. The two research defects in Dot's earlier review remain unfixed in that unused code; the new GitHub REST transport supplies its own required fixed User-Agent.

The dormant proposal is `publication/health/workflow.yml`, outside active `.github/workflows`, manual-only with a literal-false job. Its final registration ID and public package delivery must be explicitly reviewed/approved before activation. Actions, live credentials, operational publication, tenant changes, PRs and merges remain blocked. The authorized sanitized Git source push is distinct from publishing an operational artifact or package asset.

The earlier handoff below is historical and applies to its exact source/receipts only.

---

# TokenForge consolidated offline handoff

Use branch `codex/goal6-reusable-sealer`. Nathan adopted [Dot's review and consolidated milestone](goal6-dot-offline-transaction-review.md), authorizing one final sanitized source/test/documentation push on this branch. That authorization does not enable real HTTPS, runner credentials, an action entry point, workflow dispatch, hosted compute, operational emission, signing or publication. Actions have not been enabled or dispatched.

## Current checkpoint

The consolidated **offline protocol-boundary milestone is complete**. Start with [the outcome and boundaries](goal6-consolidated-offline.md), [the exact-source/package receipt](goal6-consolidated-validation.json), [the source-only provenance dossier](goal6-offline-provenance.json) and [component behavior](goal6-offline-transaction-core.md).

Exact tested source: `8dee359f9b1616d229ba802ea253d88afed09f8b`. Its parent is the local unchanged adoption of Dot's review; the receipt pins both the original review branch commit and adoption commit. The containing receipt/handoff checkpoint adds documentation only after that tested source. Use the containing Git revision as the consolidated review checkpoint.

M1 is closed: transaction and fake service clocks must share one exact timing domain, including the explicit default/default case, before any store or lock is created. The serialized flow now covers Twirp, raw Block bytes, Uncommitted-only commit and REST observation through a deny-by-default recording fake. All origins/capabilities are reserved dummy fixtures; no network dispatcher or runtime credential reader exists.

The immutable exact-source kit passed **237 Node tests and 224 Pester 6.2 sealer tests**, with zero failures/skips. Its 460 payload files include 458 literal Git blobs and the two reused runtime binaries. All 144 native/module/build inputs match the existing pinned runtime; no native build or dependency installation was needed. Independent source/test/docs review is clear; the receipt separates producer-run suites from independent static/hash review.

Original C is retained and compared byte for byte; no formatter, normalization or replacement route exists. Budgets are charged durably before serialization/dispatch, never refunded or reset, and mutation/observation unknown barriers remain conservative. Native parser errors are sanitized. Artifact provenance reports only observed repository ID/run ID/source; separate current-Run checks do not invent artifact-own attempt/workflow observations. All result authority/interoperability/privacy flags remain false.

Stale-lock refusal remains unchanged. Actual process exit preserves evidence but refuses automatic reopening. Journal v2 refuses v1 without migration or rewriting evidence. No killed-process takeover, cross-job recovery, power-loss or real wire/TLS proof is claimed.

## Review exchange

Copy this text to Dot:

> Review nathanmcnulty/TokenForge, branch codex/goal6-reusable-sealer, at the containing consolidated receipt checkpoint. Read docs/HANDOFF.md, docs/goal6-consolidated-offline.md, docs/goal6-consolidated-validation.json and docs/goal6-offline-provenance.json. Exact tested source: 8dee359f9b1616d229ba802ea253d88afed09f8b. Review scripts/offline/TokenForgeArtifactTransaction.mjs, TokenForgeArtifactProtocol.mjs, TokenForgeOfflineSchema.mjs and tests/ArtifactTransaction.test.mjs + ArtifactProtocol.test.mjs. M1 and follow-up deadline/provenance/parser/signed64 findings are addressed. The exact-source kit passed 237 Node and 224 Pester 6.2 tests. Reviewers audited source/hashes separately; they did not rerun producer suites. This is a narrow synthetic serialization profile, not service compatibility, runner/binary trust or operational approval. Return findings with file/line references, severity, reasoning and validation. Keep real HTTPS, runner credentials, action entry points, dispatch, Actions, tenant changes, operational emission, signing/publication, PRs and merges blocked.

## Preserved evidence and future prerequisites

[The original producer/service design](goal6-producer-zip-design.md) remains future integration context. [The prior fake-core receipt](goal6-offline-transaction-validation.json) and [canonical ZIP receipt](goal6-canonical-zip-validation.json) remain historical evidence for their exact revisions, not results for this new serialized profile. Canonical sealer implementation: `326cf8f1bc18a132b0401e994d9ea37ea253818a`; dormant workflow: `91e624733ff2e766be276ecb270a18638af5c1a5`. The roadmap handoff remains `19470aeba7a949e4204e4ecf5586a6ffb3171c69`.

The private kit and raw logs are not pushed. New public checkpoint content excludes private evidence, secrets, local account paths and raw archives. Earlier records and history are preserved. A source-only branch push is distinct from operational artifact publication or signing.

Real protocol/header variations, service raw-byte preservation, runtime/binary/credential provenance, real origins/versions, artifact-own attempt/content authority, wire replay/TLS behavior, hosted controller limits/ref exclusion/Actions restoration and activation remain separate reviews and authorization decisions. Offline acceptance does not establish live or production completion. No PR, merge or hosted execution is part of this handoff.
