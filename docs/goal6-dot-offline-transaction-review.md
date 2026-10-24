# Offline transaction review and next milestone

Review date: 2026-10-24 UTC

## Disposition

The checked-in shared-clock path supports the stated offline milestone. One medium-severity API/model-contract finding should be corrected in the next bundled milestone: the accepted configuration surface also permits the fake service and transaction to use different clocks, allowing simulated delays to escape the transaction's timeout checks.

This does not invalidate the producer's reported shared-clock test results or demonstrate a timeout failure in the checked-in caller. It limits any broader claim that every accepted fake configuration enforces the same timing model.

The remaining reviewed source supports the stated narrow milestone: a network-disabled, synthetic-capability transaction model with exact original-byte checks, conservative unknown outcomes and no operational authority. This review does not establish real transport behavior, service interoperability, runner credential injection or permission to execute a hosted test.

## Exact source and evidence

- Review checkpoint: [8ef7f1a756f283cbfc37c33579e2abe820310321](https://github.com/nathanmcnulty/TokenForge/commit/8ef7f1a756f283cbfc37c33579e2abe820310321).
- Tested source named by the receipt: [f5a4da91f90d9281c1118e09ac24b3e4a62fc06a](https://github.com/nathanmcnulty/TokenForge/commit/f5a4da91f90d9281c1118e09ac24b3e4a62fc06a).
- Source parent: b0588906b82f814c9cd9b7d50a3658dab13f8605.
- The branch head matched the review checkpoint when checked. The tested-source commit adds the core, tests and boundary documentation; its child adds only the validation receipt and handoff update. The changed-file comparison contains no production sealer, native runtime or production workflow changes.
- Independently computed SHA-256 values for the three Git-fetched files match the receipt. Their Git blob IDs also match GitHub's returned IDs.

| File | SHA-256 |
| --- | --- |
| scripts/offline/TokenForgeArtifactTransaction.mjs | d76a748637b26980b95a538a9e7488ec719e242717cdbbf3b21d7c166d3b53a1 |
| tests/ArtifactTransaction.test.mjs | 8c8f8314ee7476d5d9627aefad5ab9ccd9a94e46e0a21257af18a6139dffabe8 |
| docs/goal6-offline-transaction-core.md | 10dbb38021138915821f9e66a175747466eadbe1fad5ebffc4845a9a8252ccf7 |

The [receipt](https://github.com/nathanmcnulty/TokenForge/blob/8ef7f1a756f283cbfc37c33579e2abe820310321/docs/goal6-offline-transaction-validation.json) reports 129 Node and 224 Pester 6.2 passing tests, with no failures or skips. Those are producer-reported results, not reruns by this review. The private review-kit archive, extracted payload, complete test logs and toolchain binaries were not available through the reviewed Git files, so their recorded hashes and the prior audit statement were not independently re-established here.

This review used static source inspection and hashing of downloaded text. It executed no candidate modules or test suites, installed no dependencies and made no live artifact-service or runner calls.

## Finding M1 Bind the fake service and transaction to one clock

Severity: Medium. Scope: correctness of the offline timing model and its acceptance evidence.

The fake transport accepts and retains one clock, and advances that clock when a configured delay is applied. The transaction accepts a separate optional clock in prepare and open. Neither entry point checks that it is the transport's clock. Request timing then samples only the transaction clock.

Consequently, a valid fake transport configured with clock A and a delay at or above the ten-second request limit can be combined with a transaction using clock B, or the default local clock. The fake exchange advances A synchronously, while the transaction samples B or local time. The request can be treated as timely despite its configured delay. Larger repeated synthetic delays can similarly escape the intended total-time model. This is an incoherent dependency-injection configuration, but the public factories accept it and the documented optional-clock contract does not prohibit it. The existing fixture consistently supplies the same clock to both components, and default/default operation uses local time. Those coherent paths are not shown defective by this finding.

This is established by the source control flow; it was not executed as a reproduction. It does not expose a live timeout bypass because no live transport exists.

Relevant source:
- [Transport clock acceptance and storage, lines 93-103](https://github.com/nathanmcnulty/TokenForge/blob/f5a4da91f90d9281c1118e09ac24b3e4a62fc06a/scripts/offline/TokenForgeArtifactTransaction.mjs#L93-L103).
- [Delay advances the transport clock, line 114](https://github.com/nathanmcnulty/TokenForge/blob/f5a4da91f90d9281c1118e09ac24b3e4a62fc06a/scripts/offline/TokenForgeArtifactTransaction.mjs#L114).
- [Prepare and open accept the transaction clock, lines 211-228](https://github.com/nathanmcnulty/TokenForge/blob/f5a4da91f90d9281c1118e09ac24b3e4a62fc06a/scripts/offline/TokenForgeArtifactTransaction.mjs#L211-L228).
- [Request checks sample the transaction clock, lines 278-280](https://github.com/nathanmcnulty/TokenForge/blob/f5a4da91f90d9281c1118e09ac24b3e4a62fc06a/scripts/offline/TokenForgeArtifactTransaction.mjs#L278-L280).
- [Current fixture shares one clock, lines 23-25](https://github.com/nathanmcnulty/TokenForge/blob/f5a4da91f90d9281c1118e09ac24b3e4a62fc06a/tests/ArtifactTransaction.test.mjs#L23-L25).

Required correction: make the transport and transaction share one owned timing domain, or reject unequal clock identities in both prepare and open before creating a store or lock. Define and enforce the default/local-clock case explicitly.

Required validation:
1. Two distinct fake clock handles are rejected before any store creation, journal update or exchange.
2. Fake/default clock combinations cannot hide a configured delay.
3. Reopening checks the same binding before lock creation and preserves all evidence on refusal.
4. A request at the ten-second boundary and a transaction at the total deadline are charged conservatively and cannot dispatch or succeed as timely.
5. Existing rollback, boot identity, post-persistence expiry and no-budget-reset cases continue to pass.

## Reviewed properties that hold within the stated model

### Original identity

The transaction accepts an already-created canonical original, writes it unchanged, retains its own copy, and compares saved length, digest and full bytes before dispatch. The Block operation uses those original bytes. Observation independently reads fake metadata and download bytes, then requires exact original equality and canonical structural validation before checking metadata and run context again. A wrapper, altered header or changed payload cannot become an accepted substitute through a formatter path because the core has no such path.

The structural checker is not the existing business-schema or privacy decision. An Observed result explicitly remains fake-only and carries false interoperability, operational-emission and privacy-approval flags. See [core lines 53-79](https://github.com/nathanmcnulty/TokenForge/blob/f5a4da91f90d9281c1118e09ac24b3e4a62fc06a/scripts/offline/TokenForgeArtifactTransaction.mjs#L53-L79), [lines 256-259](https://github.com/nathanmcnulty/TokenForge/blob/f5a4da91f90d9281c1118e09ac24b3e4a62fc06a/scripts/offline/TokenForgeArtifactTransaction.mjs#L256-L259) and [lines 284-335](https://github.com/nathanmcnulty/TokenForge/blob/f5a4da91f90d9281c1118e09ac24b3e4a62fc06a/scripts/offline/TokenForgeArtifactTransaction.mjs#L284-L335).

### Unknown outcomes and budgets

Mutation intent is persisted before a durable dispatch charge. Each mutation has one allowed attempt. Reopening changes interrupted intents to unknown states and acknowledged mid-upload states to UploadUnknown; advance provides no unknown-to-mutation transition. One reconciliation is consumed before List dispatch, and interrupted observation cannot restart its read sequence. Maximum response allowances are reserved before dispatch without refunds. The normal path is four mutations plus seven reads; one reconciliation reaches twelve total attempts. M1 limits timing guarantees across all accepted configurations; it does not contradict shared-clock tests or these operation-count and reservation properties. See [journal validation, lines 166-205](https://github.com/nathanmcnulty/TokenForge/blob/f5a4da91f90d9281c1118e09ac24b3e4a62fc06a/scripts/offline/TokenForgeArtifactTransaction.mjs#L166-L205), [request accounting, lines 266-283](https://github.com/nathanmcnulty/TokenForge/blob/f5a4da91f90d9281c1118e09ac24b3e4a62fc06a/scripts/offline/TokenForgeArtifactTransaction.mjs#L266-L283) and [observation, lines 315-337](https://github.com/nathanmcnulty/TokenForge/blob/f5a4da91f90d9281c1118e09ac24b3e4a62fc06a/scripts/offline/TokenForgeArtifactTransaction.mjs#L315-L337).

### Synthetic credentials and network boundary

The module imports only filesystem, path and crypto primitives. Only WeakMap-branded fake transports are accepted. Capabilities are module-private opaque objects with fixed Runtime, Blob, Read and Download roles. No real token, URL, arbitrary transport callback, socket or runner-environment input is implemented. This supports message-level separation only, not future URL policy, credential injection, TLS or wire-replay claims.

### Stale locks and recovery

The exclusive lock sentinel intentionally blocks reopening after an unclean process exit. No stale-lock takeover, deletion or cross-job recovery is implemented. The test starts a child process, exits without close, checks original/journal preservation and verifies refusal with zero exchanges. It is evidence for that process-exit case, not SIGKILL-at-every-write, power-loss durability or automatic recovery. Clean-close reopening is the supported recovery model, and the documentation accurately says so. Keep this fail-closed boundary rather than expanding the next milestone into stale-lock takeover. See [core lines 224-244](https://github.com/nathanmcnulty/TokenForge/blob/f5a4da91f90d9281c1118e09ac24b3e4a62fc06a/scripts/offline/TokenForgeArtifactTransaction.mjs#L224-L244), [test lines 178-185](https://github.com/nathanmcnulty/TokenForge/blob/f5a4da91f90d9281c1118e09ac24b3e4a62fc06a/tests/ArtifactTransaction.test.mjs#L178-L185) and [boundary documentation, lines 23-31](https://github.com/nathanmcnulty/TokenForge/blob/f5a4da91f90d9281c1118e09ac24b3e4a62fc06a/docs/goal6-offline-transaction-core.md#L23-L31).

## Proposed next milestone

Complete one offline protocol-boundary readiness package, including the M1 correction, before the next external review. This is a proposed bounded work goal. It grants no present implementation or publication authority; the implementation and final source-checkpoint handoff below become authorized only if Nathan adopts this goal.

### Scope

1. Fix the shared-clock contract and add the complete mismatch/deadline regression matrix above.
2. Add pure request/response serialization and validation for the proposed Create, Block, Commit, Finalize and observer flow, using pinned public protocol references and synthetic data only. Keep request construction separate from dispatch and provide no network-capable dispatcher.
3. Exercise the complete original-byte path through those serialized messages, including strict integer identities, schema errors, one-hop download planning, method/path/origin policy, signed-query preservation using dummy values, fixed credential-role placement, bounded bodies and sanitized failures. Do not infer independent service authority from a submitted or echoed hash.
4. Connect this layer to the existing state machine through a deny-by-default recording fake. Demonstrate that serialization failures cannot replenish budgets, replay mutations, change C or convert an unknown outcome into approval. Treat wire-level replay and real TLS behavior as still unproven.
5. Prepare a source-only runner/action/Node provenance and environment-contract dossier. Record exact reviewed references, supported context and explicit unresolved facts; do not read real runtime credentials or claim a selected hosted runner has been verified.
6. Produce one immutable exact-source review kit and receipt, with independently reviewed changes, bounded local synthetic validation results, unchanged operational/workflow guards, and clearly separated producer-run versus reviewer-run evidence.

### Completion and handoff

The milestone is complete when M1 is closed, the entire network-disabled serialized flow and refusal matrix have one reviewed exact source, the recorded source/package evidence matches that source, and one consolidated Git handoff explains remaining live prerequisites. Internal implementation/review iterations should not require repeated manual user relays. Interrupt only for a material design decision, an authorization boundary or a blocker that cannot be resolved within the approved offline scope.

On Nathan's adoption, the goal includes ONE final sanitized source/test/documentation checkpoint pushed to the existing public repository nathanmcnulty/TokenForge, branch codex/goal6-reusable-sealer, after the bounded work and validation are complete. Include the review disposition, consolidated goal outcome and exact tested-source/receipt references. Verify the remote revision and return that exact pushed SHA with one consolidated outcome; do not stop to request a separate one-minute push handoff. Use only existing Git authentication and existing Git commit signing as needed for that bounded push. Do not create or extract credentials, grant new permissions, force-push, rewrite evidence history or publish unrelated changes. Public checkpoint contents must exclude private evidence, secrets, local account paths, raw artifact archives and private test logs.

This ordinary source-checkpoint push is distinct from operational artifact publication or signing. Retain the current stale-lock refusal. Real HTTPS, runtime-token access, a runner action entry point, workflow dispatch, new dependencies, operational artifact signing/publication, operational policy emission, a PR, merge and hosted execution remain outside the goal. Do not enable Actions or introduce automatic triggers. Real transport and any later hosted canary remain separate reviews and authorization decisions.

This review and proposed goal were prepared locally. They have not been committed or published.
