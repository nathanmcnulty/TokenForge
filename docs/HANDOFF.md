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
