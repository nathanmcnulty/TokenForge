# Consolidated offline acceptance and next approval point

Review date: 2026-10-24 UTC

## Decision

Accept the consolidated offline milestone at checkpoint **46463c00ad61fbcf35447ee087a59bdd40bbd446**. M1 is closed. No new material defect was substantiated within the reviewed, deliberately narrow network-disabled scope.

This finishes the adopted offline goal. It does not establish live GitHub interoperability, credential authority, operational readiness or permission to activate anything. The remaining work is a real transport and execution-boundary decision, not another round of abstract fake layers.

## Exact source chain

The verified sequence on `codex/goal6-reusable-sealer` is:

1. Prior receipt checkpoint `8ef7f1a756f283cbfc37c33579e2abe820310321`.
2. Review adoption `d120d02c66adeb1704f42ba0ac4ea620ab6b1bc1`, adding only the unchanged review document from handoff commit `18a617f79f4968fbab27433a82e3c68ef6d38d62`.
3. Tested source `8dee359f9b1616d229ba802ea253d88afed09f8b`.
4. Documentation-only receipt/handoff checkpoint `46463c00ad61fbcf35447ee087a59bdd40bbd446`.

The branch head matched the last revision when checked. The adopted review's full text and Git blob `2d7aa77af734115caebe95569e7cb861a1a727ec` match the original handoff. All eight source SHA-256 values in the [consolidated receipt](https://github.com/nathanmcnulty/TokenForge/blob/46463c00ad61fbcf35447ee087a59bdd40bbd446/docs/goal6-consolidated-validation.json) independently match the retrieved Git files and remained unchanged after the reviewer test run. The comparison from the prior checkpoint contains only the expected source, tests and documentation; no production workflow, sealer, native source or module changes appear.

## Evidence independently established

### M1 is closed

The transaction now requires exact identity between its clock and the fake transport's clock, including the explicit default/default domain. Both prepare and open check this before creating a directory or lock. The new tests cover all three mismatched pairings at both entry points, valid default timing, shared request-time boundaries and accumulated expiry. See [clock binding and entry points](https://github.com/nathanmcnulty/TokenForge/blob/8dee359f9b1616d229ba802ea253d88afed09f8b/scripts/offline/TokenForgeArtifactTransaction.mjs#L178-L267) and [the M1 regression matrix](https://github.com/nathanmcnulty/TokenForge/blob/8dee359f9b1616d229ba802ea253d88afed09f8b/tests/ArtifactProtocol.test.mjs#L27-L49).

### Protocol suite independently passed

After inspecting the complete source closure, the reviewer ran the unchanged `tests/ArtifactProtocol.test.mjs` with existing Node **24.19.0** and system Python **3.13.5**, under a cleared environment and a 60-second outer limit.

Result: **108 passed, 0 failed, 0 skipped, 0 cancelled**, exit code 0.

This was the protocol suite only. It used synthetic files, a canonical fixture encoder and the recording fake, with no network-capable dispatcher, real credentials or artifact-service calls. The older ZIP-metadata mutation/leakage investigation was not run. No dependencies were installed and no native runtime was executed or rebuilt.

Reviewer Node SHA-256: `bc17c508ffeed0ec622934f9b7fa72f8e78da65350e63c3eceb56fa688aa5e12`.
Reviewer Python SHA-256: `889c603f0d17cb54060951bcf4c4f9b8c9ebd9e52b392c70209bbb9755d797d9`.
Reviewer protocol log SHA-256: `c97e7f3d07157132c0e6759433b233be3120b1eccf71898ff6f26f6fa06423f9`.

The producer's **237 Node + 224 Pester 6.2** exact-kit results remain separate producer-reported evidence. This reviewer did not rerun the combined suite or Pester gate, and did not independently obtain the private kit, raw producer logs or reused native binaries. The independent protocol run does not reproduce the producer's Node 24.18.1 toolchain or whole-kit audit.

### Source-only provenance checks passed

All five runner/Node source-file hashes in the [dossier](https://github.com/nathanmcnulty/TokenForge/blob/8dee359f9b1616d229ba802ea253d88afed09f8b/docs/goal6-offline-provenance.json) independently matched their pinned public Git files. The runner v2.329.0 tag resolves to `c76c59996c8fa32e989164a5a695efb12608ae5a`; the Node v24.18.1 annotated tag resolves to `9623d9ad85d37d2f0610ec4a82b48182cf2c6061`.

The source supports the documented conditional runtime-token/Results-URL injection, Node runtime selection, monotonic-clock interface and HTTPS agent/proxy considerations. This is not selected-runner inspection, binary provenance, token-scope proof, a reproducible-build audit or no-wire-replay evidence. The artifact package archive and its five generated reference-file hashes were not independently rehashed in this review.

## Reviewed boundaries

- **Original bytes:** the Block body remains C, not a wrapper or regenerated archive. The observer requires exact length, digest and full-byte equality, followed by structural checks and repeated metadata/run checks. No normalization or replacement route is introduced.
- **Origins and credentials:** request construction accepts only fixed reserved fixture origins and dummy capabilities. Method/path, query octets, credential role and placement are validated. The download capability never gains the read bearer slot. No real URL is followed and no runtime credential reader exists. These restrictions are visible in [the protocol module](https://github.com/nathanmcnulty/TokenForge/blob/8dee359f9b1616d229ba802ea253d88afed09f8b/scripts/offline/TokenForgeArtifactProtocol.mjs#L25-L89).
- **Unknown outcomes and budgets:** mutation intent and exact body reservations are persisted before serialization or exchange. Failures do not refund charges or add replay edges. Deadline checks cover persistence, serialization, the final recording boundary, response handling and parsing. Reconciliation remains single-use. See [the dispatch boundary](https://github.com/nathanmcnulty/TokenForge/blob/8dee359f9b1616d229ba802ea253d88afed09f8b/scripts/offline/TokenForgeArtifactTransaction.mjs#L298-L347).
- **Observed authority:** artifact metadata yields only repository ID, run ID and source. Separate Run reads do not become artifact-own attempt/workflow evidence. Result flags explicitly remain false for those unobserved properties and for interoperability, operational emission and privacy approval. This correct limitation is tested, not hidden by copying expected fields. See [artifact normalization](https://github.com/nathanmcnulty/TokenForge/blob/8dee359f9b1616d229ba802ea253d88afed09f8b/scripts/offline/TokenForgeArtifactProtocol.mjs#L102-L108) and [the provenance regression](https://github.com/nathanmcnulty/TokenForge/blob/8dee359f9b1616d229ba802ea253d88afed09f8b/tests/ArtifactProtocol.test.mjs#L129-L141).
- **Stale locks:** an unclean process exit still leaves a lock that refuses reopening. There is no takeover, cross-job recovery or power-loss claim. Journal v2 refuses v1 without migrating or rewriting old evidence.

The protocol profile deliberately rejects additional real-world headers/fields and uses only dummy origins. Its successful fake flow is therefore not a runnable service client, and failure against real responses would not justify silently relaxing the profile.

## One proposed next package

The next meaningful step is a **pre-live transport readiness package**, proposed for Nathan to adopt. Publishing this review is documentation-only and does not adopt the goal or authorize implementation. Work begins only after Nathan explicitly adopts this bounded goal.

Implementation must start from the reviewed owning checkpoint **46463c00ad61fbcf35447ee087a59bdd40bbd446** on `codex/goal6-reusable-sealer`, not from the older implementation contained on the documentation handoff branch. Read this review as the task specification; preserve the reviewed owning source and its evidence chain. If that owning branch has advanced, inspect and reconcile the intervening changes rather than resetting it or silently reviewing a different baseline.

Adoption should permit one bounded engineering package: implement the actual HTTPS adapter and dormant action/control entry points, but validate them only in a local controlled harness with dummy credentials and local TLS fixtures. No real runtime/read credentials may be accessed or used. External artifact-service HTTPS, Actions enablement/dispatch, hosted execution and operational signing/publication remain forbidden. Keep service-mode execution disabled throughout the milestone. Public source inspection and the final ordinary Git handoff using existing Git authentication remain distinct from runtime credential access and service execution.

The package should finish all of the following before returning:

1. Implement the exact transport boundary against the selected Node runtime: fixed method/path/origin policy, scoped credential slots, no inherited proxy/retry/redirect behavior, bounded headers/bodies/deadlines, one charged exchange per wire attempt, and original C unchanged throughout.
2. Exercise the actual adapter, rather than another abstract substitute, against local loopback TLS endpoints using dummy credentials. Cover connection failure, dropped acknowledgements, cancellation, oversized/partial responses, redirect rejection, credential separation, logging sanitization and unknown/no-replay behavior. Use per-test client trust for the local TLS fixture only; do not modify global trust stores, disable certificate verification or change system security settings. Use existing tools and dependencies; obtain separate approval for any installation instead of silently adding one.
3. Complete the real response/header/capability profile and action/runtime provenance preflight. Missing or unapproved context must fail before credential access or mutation. Distinguish source-supported facts from conditions that can only be checked on the eventually selected runner.
4. Prepare one exact synthetic-canary authorization packet: reviewed implementation and workflow revisions, repository/workflow IDs, exclusive source-ref procedure, real origin/version allowlists, credential scopes, retention, operation/body/time limits, no-redispatch reconciliation and concurrency-safe Actions restoration. State exactly which artifact provenance remains unobserved and prohibit turning the observation into operational approval.
5. Produce one reviewed source checkpoint, a validation receipt distinguishing producer and reviewer evidence, and the final canary decision request. Keep all live execution disabled. A later canary must require a separate explicit approval for its specific source, credentials, writes, compute and controller procedure.

If Nathan adopts this next goal, include one final sanitized source/test/docs checkpoint push to the existing public `nathanmcnulty/TokenForge` branch `codex/goal6-reusable-sealer`, using existing Git authentication/signing only. Verify and return the exact remote SHA with the consolidated outcome. Do not require a separate push microtask. Do not force-push, change permissions, publish private artifacts/logs, open a PR, merge or trigger hosted execution.

Completion means the real adapter has local transport evidence and a single decision-ready bounded canary packet exists. It does not mean the canary has run. Stop there rather than adding open-ended fake milestones or assuming live authority.

Publication of this review changes documentation only. The next package still requires Nathan's explicit adoption, and any live canary requires its own subsequent approval.
