# Inert activation checkpoint review and feasibility decision

Review date: 2026-10-24 UTC

## Decision

Checkpoint **9bc717b16e4800270e5a49f3cc7c248d15b42d15** is a useful, source-verified **inert engineering handoff**, not a complete activation candidate. Maintain the packet's **NO-GO**. Both prior low findings are resolved, but one concrete service interoperability defect and one boundedness caveat remain below. Neither escapes the current refusal gates.

Do not turn the reported 416/224 passes into live-readiness evidence. The real controller HTTPS leaf, selected execution distribution, trusted dynamic-plan delivery and enforceable GitHub custody are still absent or unproved. These require an actual deployment/trust-model decision, not more abstract fake layers or a gate flip.

## Findings

### M1 — medium: required GitHub REST User-Agent is missing

The [REST request profile](https://github.com/nathanmcnulty/TokenForge/blob/eaec9e025e29de31c3d580a58e3e8b4a33a2fea0/scripts/offline/TokenForgeArtifactProtocol.mjs#L88-L97) supplies Accept, API version and Content-Length, but no User-Agent. The [HTTPS driver](https://github.com/nathanmcnulty/TokenForge/blob/eaec9e025e29de31c3d580a58e3e8b4a33a2fea0/scripts/transport/TokenForgeLocalTlsTransport.mjs#L101-L126) adds Host, Connection, Accept-Encoding and the scoped bearer, not User-Agent. The pinned [Node HTTP client](https://github.com/nodejs/node/blob/9623d9ad85d37d2f0610ec4a82b48182cf2c6061/lib/_http_client.js#L349-L381) does not supply that header automatically.

GitHub documents a valid User-Agent as required and says requests without it are rejected. This is a documented compatibility failure, not a live observation. If the preceding artifact mutations succeeded, the first REST observation would be expected to fail. The [independent fixture's header check](https://github.com/nathanmcnulty/TokenForge/blob/eaec9e025e29de31c3d580a58e3e8b4a33a2fea0/tests/fixtures/publication/LocalTlsFixture.mjs#L49-L51) does not require the header, so the green synthetic path cannot catch this defect. [GitHub requirement](https://docs.github.com/en/rest/using-the-rest-api/getting-started-with-the-rest-api#user-agent)

Before any real candidate, add one fixed non-sensitive application User-Agent to the closed REST profile and independent wire expectations, with missing/incorrect-header regressions. Apply the same requirement when the future real controller leaf is implemented. This does not require a live request or permission to broaden other headers/origins.

### L1 — low: producer timeout is not a guaranteed hard termination bound

The [producer invocation](https://github.com/nathanmcnulty/TokenForge/blob/eaec9e025e29de31c3d580a58e3e8b4a33a2fea0/scripts/transport/TokenForgeCanaryAction.mjs#L18-L27) uses spawnSync with a 20-second timeout but the default SIGTERM termination signal. The pinned Node documentation says spawnSync can continue waiting when the child handles SIGTERM without exiting. Therefore the readiness document's unqualified “20-second bound” is stronger than this API guarantees. [Pinned Node behavior](https://github.com/nodejs/node/blob/9623d9ad85d37d2f0610ec4a82b48182cf2c6061/doc/api/child_process.md#L1374-L1410)

No hang of the fixed producer was demonstrated. Expired approval is rechecked after the producer and before application credential reads, so this is not a late-authorization bypass. In the next real implementation package, define and validate bounded Linux child termination/custody, or narrow the claim to a timeout request and its known limits. Do not claim real-time guarantees that the OS cannot provide.

## Prior findings closed

- **Prior L1, header dictionary:** the driver now uses Object.create(null), rejects unknown/duplicate fields, and includes actual single/duplicate __proto__ TLS regression cases. [Driver](https://github.com/nathanmcnulty/TokenForge/blob/eaec9e025e29de31c3d580a58e3e8b4a33a2fea0/scripts/transport/TokenForgeLocalTlsTransport.mjs#L70-L89)
- **Prior L2, exact route oracle:** the independent fixture now matches complete method, Host and raw target for every operation, including List, Block ID and signed query octets. Forty malformed variants are covered in checked-in tests. [Oracle](https://github.com/nathanmcnulty/TokenForge/blob/eaec9e025e29de31c3d580a58e3e8b4a33a2fea0/tests/fixtures/publication/LocalTlsFixture.mjs#L14-L44)

These are independently source-verified corrections with regressions present, not newly executed reviewer TLS results.

## Exact chain and independently verified evidence

The verified sequence is:

1. Prior owning checkpoint `5a137f5a4bcac9560edada472b577ddd9ed8a41b`.
2. Review adoption `132820809675b2071b491e341976ed2310f8182e`, copying the review from `01c6b3c56470902791e22ce1b387ed17386ebd29` unchanged.
3. Implementation `441bf8020b11c9770115e896d73134c298dd9c1d`.
4. Exact tested source/template `eaec9e025e29de31c3d580a58e3e8b4a33a2fea0`, whose changes are confined to the dormant template and its test.
5. Receipt checkpoint `9bc717b16e4800270e5a49f3cc7c248d15b42d15`, adding the sanitized handoff/receipt and changing the decision document only.

The owning ref matched the final checkpoint when checked. All **16 source SHA-256 values** in the [receipt](https://github.com/nathanmcnulty/TokenForge/blob/9bc717b16e4800270e5a49f3cc7c248d15b42d15/docs/goal6-inert-activation-validation.json) match retrieved Git bytes. The adopted review matches SHA-256 `987e1c7d3193e770e133172b3a3e48532dfc73725aa3de2b90f56f12b5e0e48b`. The tested tree contains **484 Git blobs**.

All **144 native/module/build input paths, modes and blob identities** match reused-runtime source `0a1704d057417e58b92fd5eac8c546541d3f7ec2`. No active workflow file changed from the prior owning checkpoint. The template remains outside `.github/workflows`, is manual-only and literal-false, pins implementation `441bf802...`, and embeds the exact **11,922-byte** bootstrap, SHA-256 `0de0aa2976ba725a93ccef5d1f10c9abaa3eac7bff50eaa44d7217226ad741ab`.

Public source independently confirms:
- Pinned runner source selects **Node 24.10.0**, not the locally approved **24.18.1**. This is a source-version mismatch, not inspection of an actual selected hosted machine. [Runner distribution source](https://github.com/actions/runner/blob/c76c59996c8fa32e989164a5a695efb12608ae5a/src/Misc/externals.sh#L9-L10)
- The Node action handler injects the runtime credential before launching Node. The enforceable proposed application boundary is therefore “before application reads,” not “before platform token materialization.” [Handler](https://github.com/actions/runner/blob/c76c59996c8fa32e989164a5a695efb12608ae5a/src/Runner.Worker/Handlers/NodeScriptActionHandler.cs#L53-L76)
- Pinned main `1be12d75c7e2a63eac8e14c32d54e79cec4a23ef` contains the original manual validation workflow, blob `9132eee7c87fc91ae48f0ad9c5ba2b2dafe255f3`, with mutable checkout and Pester installation. It is not this canary. Current registration/settings were not queried or established. [Pinned main workflow](https://github.com/nathanmcnulty/TokenForge/blob/1be12d75c7e2a63eac8e14c32d54e79cec4a23ef/.github/workflows/ci.yml)

### Execution evidence boundary

**No candidate suite was executed in this review.** Existing reviewer Node remains **24.22.1**, SHA-256 `61ab14cd750fc24d5db53490ec5fc40f756e4b6e136b78cf7004265471d9bd1d`, not approved 24.18.1/hash `f3432a45b03b2da0d270095fdd8813dc34cbea73f5fc8b18c7a384b7cf9b333a`. The new fixture/control suites correctly check that pin before creating their fixtures. No pin was bypassed, no dependency installed and no candidate runtime substituted.

The producer's **416 Node + 224 Pester 6.2** passes, **486 payload-file** audit, private archive/log/binary hashes and the earlier independent review's **11 service/authority + 15 controller-recovery** passes remain separately reported evidence. This reviewer did not obtain the private kit or raw logs, rerun those suites or execute the native package. Development failures and corrections remain disclosed in the receipt.

Verification here used source reading, Git-tree comparisons and independent byte/hash extraction. No credentials, external adapter/bootstrap, controller/service calls, Actions, operational activation or denied ZIP experiment were used.

## What the implementation really establishes

- The action wrapper, service entry/factory, bootstrap entry/future fetch and controller entry retain separate unconditional refusals. The live signer pin is zero and no live plan is configured. Local service execution requires the private loopback brand and fixed dummy role slots.
- The service serializer now requests one-day retention from frozen transaction.created. The synthetic producer validates the complete original C and business/privacy structure before application role reads. C, uploaded Block bytes and downloaded R remain separate values that must match completely; no service-wrapper/member-byte substitution is introduced.
- Context is frozen into the transport before store/open/exchange. Authority wall/monotonic expiry is checked across producer, dispatch, completion and parsing. Original budgets, durable charges, no refund/replay, conservative unknown outcomes, stale-lock refusal and unobserved artifact-own attempt/workflow flags remain intact.
- The controller implements a durable bounded state machine, but only its WeakMap-branded recording backend can execute. It preserves six-write/30-attempt/480-second limits and phase reserves. Restored enablement is distinct from resolved run outcome; recoveryRequired can remain true. Fresh-process recovery, cross-job reconstruction and automatic stale-lock takeover are not claimed.
- The anonymous bootstrap has a source implementation, sterile child tool-home and literal-tree export checks. It has not executed an external fetch. Its source-output byte cap is not a remote-pack/network/disk cap. Full runner, Python/Git helpers/libraries, PowerShell/native provisioning and startup trust remain unproved.

These are meaningful inert capabilities, not substitutes for the documented missing real controller transport or independently enforced authority.

## One consolidated next decision, not another mock milestone

Do not adopt another broad “finish activation” coding goal without resolving the trust/deployment model. The current [NO-GO packet](https://github.com/nathanmcnulty/TokenForge/blob/9bc717b16e4800270e5a49f3cc7c248d15b42d15/docs/goal6-canary-decision.md) correctly makes the missing prerequisites explicit.

Nathan's genuine choices are:

1. **Retain the current strict model:** keep the canary blocked until a concrete mechanism establishes the selected distribution, dynamic signed-plan issuance/delivery and exclusion of all competing ref/settings/dispatch/rerun writers. A local boolean, workflow concurrency, signature or read-compare-write is not that mechanism.
2. **Authorize design of a narrower isolated experiment:** consider a dedicated synthetic-only repository and controlled ephemeral execution/provisioning model, with an explicitly reviewed custody/risk model. This may reduce exposure and avoid toggling the working repository's settings, but does not itself prove authority or solve dynamic backend-plan delivery. It changes scope and requires explicit approval before creating resources, permissions, keys or workflows.
3. **Park live integration:** preserve this inert checkpoint and its evidence if the platform-control/provisioning cost is not justified by the byte-preservation question.

Recommendation: if the interoperability question remains worth pursuing, decide between the first two models in **one bounded feasibility package**, with the isolated model as the candidate to evaluate rather than an assumed authorization. The package should name concrete infrastructure/operator responsibilities, the approved distribution and provisioning path, workflow registration strategy, trusted late plan delivery and how custody is enforced or explicitly revised. Stop with either an implementable decision or a precise unresolved blocker. Do not claim those facts by adding another recording fake.

Engineer-owned work should then be bundled, not sent back as microtasks: M1's header fix, L1's termination correction, real controller transport/response-profile implementation, full source/runtime/plan binding and one final exact-source validation packet for the chosen model. Current fixture response shapes must be reconciled with documented real API responses when building that leaf; passing recording tests is not a compatibility guarantee.

Any later implementation goal must start from reviewed owning checkpoint **9bc717b16e4800270e5a49f3cc7c248d15b42d15**, not the older documentation-branch code, and should include one final sanitized source/test/docs checkpoint push on adoption. Publication of this review alone authorizes neither that implementation nor any push.

All live credentials, external artifact/control transport, signer provisioning, settings changes, Actions/hosted runs, tenant operations, operational emission/signing/publication, PRs and merges remain blocked. A future canary needs separate specific approval for exact source, credentials/scopes, writes, compute, retention and named recovery.
