# TokenForge shared review handoff

Use branch `codex/goal6-reusable-sealer` for implementation checkpoints and handoffs between Codex and Dot. The user approved pushing this review branch. No PR, merge, release, tenant operation or hosted execution is authorized by that approval. Actions remain disabled.

## Current review

Start with [the canonical original-ZIP contract](goal6-canonical-zip.md) and [its exact-source/package receipt](goal6-canonical-zip-validation.json). The receipt is recorded after packaging and identifies the immutable source of the review kit; use that matching receipt with any extracted kit. [The broader Goal 6 handoff](goal6-dot-review.md) supplies historical context.

Implementation: `326cf8f1bc18a132b0401e994d9ea37ea253818a`; dormant workflow: `91e624733ff2e766be276ecb270a18638af5c1a5`. The complete container contract is now implemented as `CanonicalStoredOriginalZipV1`: the ORIGINAL archive must match a fixed stored-ZIP reconstruction byte for byte. Original identity is retained, not silently replaced. Former metadata/extra-byte unsafe acceptances are rejection regressions. The prior private-parent fix remains in place.

Operational emission and hosted activation remain blocked without override. Ordinary compressed/default GitHub artifact ZIP compatibility is not established. The next review should challenge the canonical construction, independent reference fixtures, pinned profile declaration and package provenance. Full-container coverage plus existing content/schema checks is not universal DLP or semantic approval. A distinct offline review/test kit reuses the hash-pinned unchanged native runtime; it is not a production release package.

Acceptance receipts describe conditions when recorded. Their historical local-only/unpublished flags remain intact after an approved branch push; they are not statements of the branch's current hosting status. The preserved roadmap handoff is `19470aeba7a949e4204e4ecf5586a6ffb3171c69`.

## Review exchange

Copy this text to Dot:

> Review repository nathanmcnulty/TokenForge, branch codex/goal6-reusable-sealer. Start with docs/HANDOFF.md and docs/goal6-canonical-zip.md; exact-source/package evidence is docs/goal6-canonical-zip-validation.json. Challenge the complete-container contract, pinned provenance and extracted-kit safety gates. Operational and hosted activation remain blocked. The reviewed implementation/workflow commits are pinned in those files. Review offline and return findings with file/line references, severity, reasoning and suggested validation. Do not authenticate, run Actions, change tenant permissions, publish, open PRs or merge.

Copy Dot's response back into this chat. Future review notes and dispositions can be committed here as scoped documentation, with an exact source commit for every review. Keep earlier evidence and pin subsequent fixes to new commits. Push ordinary reviewed checkpoints without force-pushing or rewriting the existing evidence history. Branch access does not grant access to ignored private working stores, credentials or local package caches.
