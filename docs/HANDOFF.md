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
