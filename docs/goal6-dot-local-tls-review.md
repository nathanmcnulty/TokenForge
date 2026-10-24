# Local TLS acceptance review and one proposed completion package

Review date: 2026-10-24 UTC

## Decision

Accept **5a137f5a4bcac9560edada472b577ddd9ed8a41b** as the completed **local-only transport milestone**, with the two low-severity follow-ups below carried into the next implementation package. No material defect was substantiated in original-byte identity, loopback confinement, transaction custody, deadline enforcement or mutation no-replay.

This is not acceptance of a runnable service client or permission for a hosted canary. The implementation remains deliberately inert for external service/action/controller execution. The remaining work is one concrete activation-candidate completion and authorization decision, not another abstract fake layer.

## Exact source and evidence

The verified owning-branch chain is:

1. Prior accepted checkpoint: `46463c00ad61fbcf35447ee087a59bdd40bbd446`.
2. Unchanged review adoption: `86747086760dfb4df773f613927e8873ddb2af49`, carrying the review from `c12befdb760777c0665af00140c372cf44de765b`.
3. Local TLS implementation: `546674afdbc36abcc775651d838d51c53bde5bb4`.
4. First template/tested source: `8e84e406544769331ca4b2d3b95127f760c8af43`, whose failed exact-kit result remains recorded.
5. Corrected implementation: `026ec9d0380eeacae9ecd7787c84996a0307814c`. Its only change restores the still-used `isFakeClock` import.
6. Exact accepted tested source: `733fe2865856fc577eae8ac626f0f2001a531971`, changing only the dormant template pin and its test.
7. Receipt checkpoint: `5a137f5a4bcac9560edada472b577ddd9ed8a41b`, adding the handoff/receipt and changing only the decision document.

The owning branch matched the receipt checkpoint when checked. All **17 source SHA-256 values** in the [receipt](https://github.com/nathanmcnulty/TokenForge/blob/5a137f5a4bcac9560edada472b577ddd9ed8a41b/docs/goal6-local-tls-validation.json) match independently retrieved Git files and remained unchanged after reviewer checks. Its tested tree contains **474 Git blobs**. All **144 native/module/build input paths, modes and Git blob identities** match runtime-source commit `0a1704d057417e58b92fd5eac8c546541d3f7ec2`. Active workflow files are unchanged from the prior accepted checkpoint.

The two pinned `actions/checkout` metadata hashes independently match commit `3d3c42e5aac5ba805825da76410c181273ba90b1`, preserving the original CRLF bytes of `action.yml`. This does not audit checkout's executable distribution or prove a selected hosted runner/runtime.

### Reviewer execution, separately stated

An unchanged preflight/template check was run with a cleared environment and a 30-second outer bound using existing Node **24.22.1**, SHA-256 `61ab14cd750fc24d5db53490ec5fc40f756e4b6e136b78cf7004265471d9bd1d`.

Actual outcome: **39 cases executed, 38 passed, 1 failed, 0 skipped/cancelled; exit 1**. The sole failure is the explicit runtime-pin assertion: current Node differs from approved **24.18.1**, SHA-256 `f3432a45b03b2da0d270095fdd8813dc34cbea73f5fc8b18c7a384b7cf9b333a`. This is a partial, non-green reviewer run, not a replacement for the producer gate. The attempted test-name exclusion did not exclude those cases; the actual TAP result above controls. Dormant refusal checks used only synthetic values and made no controller/service requests.

Reviewer log SHA-256: `385eab230d5d49ba320e4f825bbac697912253b4039a72c9ff22dc03ae3e0b3a`.

The **36-case actual TLS suite was source-reviewed but not run here**: it requires the approved executable. No runtime pin was weakened, alternate runtime installed, TLS listener started or real credential used. The suite's fixture trust is explicit per client and temporary suite-scoped, not a global trust-store change. Its helper starts a server before transport construction registers cleanup, so a runtime mismatch should be rejected before starting that suite.

Producer **312 Node + 224 Pester 6.2** passes, private kit/log hashes, 476 payload-file checks and reused binary hashes remain producer-reported evidence. The earlier independent review's **38 preflight + 3 TLS expiry/history** passes are also reported, not rerun by this reviewer. This review did not obtain the private kit, execute Pester/native binaries, repeat the combined suite or retry the earlier denied ZIP investigation. The receipt truthfully retains the superseded **184 passed / 128 failed** kit attempt rather than presenting it as accepted.

## Findings

### L1 — low: one header name evades the stated refusal profile

At [transport lines 38–52](https://github.com/nathanmcnulty/TokenForge/blob/733fe2865856fc577eae8ac626f0f2001a531971/scripts/transport/TokenForgeLocalTlsTransport.mjs#L38-L52), raw response headers are accumulated in `{}`. Assigning a string to `headers['__proto__']` invokes the inherited setter instead of creating an own property. That valid header name, including duplicates, consequently disappears before unknown-header/duplicate rejection.

This is a narrow profile-correctness issue, not prototype pollution through an object-valued response and not a loopback, credential, byte-cap or authority bypass. Use a null-prototype dictionary or Map and add a bounded single/duplicate-header regression when revising the actual adapter. This finding is source analysis, not a network reproduction.

### L2 — low: independent fixture evidence is narrower than its description

The fixture [classifies routes with suffix/substring matching](https://github.com/nathanmcnulty/TokenForge/blob/733fe2865856fc577eae8ac626f0f2001a531971/tests/fixtures/publication/LocalTlsFixture.mjs#L20-L46); the happy-path test [checks only a query prefix](https://github.com/nathanmcnulty/TokenForge/blob/733fe2865856fc577eae8ac626f0f2001a531971/tests/LocalTlsTransport.test.mjs#L30-L35). Thus “Host/path/query octets independently checked” overstates the complete exact-route oracle.

Production request construction and validation are still strict, and no incorrect emitted route was demonstrated. Add independent full method/Host/path/raw-query expectations for each operation in the next package, or narrow that evidence claim. Keep this bounded to the actual adapter contract, not an open-ended mock framework.

## Security boundaries confirmed in source

- **Transport refusal:** only branded local handles work; physical TCP destination is literal IPv4 loopback, SNI is fixed, the fixture CA is supplied explicitly, normal certificate/hostname checks and TLS 1.3 stay enabled. Fresh private agents avoid the global agent, inherited proxy selection, automatic redirects and retry paths. Only fixed dummy Runtime/Read bearer values are inserted. [Transport](https://github.com/nathanmcnulty/TokenForge/blob/733fe2865856fc577eae8ac626f0f2001a531971/scripts/transport/TokenForgeLocalTlsTransport.mjs#L21-L105)
- **Custody and time:** the transaction remains busy with its lock held until request and socket close. Cancellation destroys both. Durable reservation precedes dispatch; wall/monotonic exchange deadlines are fixed and checked again at completion, after parsing and before final observation. Stalled scheduling is not a real-time guarantee, but a late acknowledgement cannot become accepted evidence. [Core](https://github.com/nathanmcnulty/TokenForge/blob/733fe2865856fc577eae8ac626f0f2001a531971/scripts/offline/TokenForgeArtifactTransaction.mjs#L244-L377)
- **Identity and unknown outcomes:** original C is reread and checked by size, digest and bytes; upload uses C, and downloaded R must equal C in full before structural validation and repeated metadata/Run checks. There is no service-wrapper/member-byte substitution. Mutation intent and exact reservation survive failure without refunds/replay. Reconciliation is single-use; expired/partial observations do not restart.
- **Honest limits:** 12 exchanges/four mutations/eight reads, 64 KiB C, 180 seconds total, ten seconds per exchange and 2 MiB reserved entity bodies remain fixed. Headers have separate limits; an overflowing delivered chunk and TLS/TCP overhead are not falsely claimed to fit the entity reservation. Journal v3 binds engine/profile/runtime/fixture authority; stale locks refuse takeover, and no cross-job or power-loss recovery is claimed.
- **Provenance and expiry:** observed expiry is persisted and rechecked after final Run; completed expired evidence becomes historical without rewriting the journal. Missing expiry is explicitly unobserved. Artifact-own attempt/workflow identity, privacy approval, service interoperability and operational emission remain false. Public-context and capability validators confer no credential/service authority.
- **Dormancy:** service construction, action and controller execution refuse unconditionally. The workflow template is outside active workflows, manual-only and literal-false. The controller is a plan, not runtime-enforced restoration. Repository settings were not read or changed in this review. A public workflow-list read was rejected by the connector's endpoint allowlist; no alternate route was used. The receipt's eight-disabled-workflows observation remains historical reported evidence, not a freshly verified setting.

## One proposed next milestone: complete the inert activation candidate

This goal is **proposed for Nathan to adopt**, not authorized by publication of this review. Start from owning checkpoint **5a137f5a4bcac9560edada472b577ddd9ed8a41b** on `codex/goal6-reusable-sealer`, not the older implementation on the documentation handoff branch. Inspect any intervening commits rather than resetting or silently changing the baseline.

On adoption, complete one finite package containing the full service/action/controller execution closure and precise activation diff, while keeping every external execution route disabled. The work must finish these concrete items together:

1. Correct L1 and close L2's exact-wire evidence gap. Keep original-byte, clock/budget, teardown, no-replay, sanitized-output and stale-lock guarantees intact. Check the approved existing runtime before creating fixtures; do not silently change its pin or install dependencies.
2. Implement the actual service protocol path, explicit one-day retention bound to the frozen start, role-scoped capabilities and pre-credential public-context/runtime checks. Review the complete executing checkout/action/runtime closure, not only metadata. Separate source-supported facts from selected-runner/binary/token authority and identify exactly how those facts will be established before application credential access. Platform token availability must not be mislabeled proof of authorization.
3. Implement and locally exercise the bounded controller/restoration state machine, including lost enable/dispatch/restore acknowledgements, no redispatch, unique run discovery, fixed deadlines with restoration time reserved, durable unknown states and named operator recovery. Use dummy local TLS/control fixtures only. Preserve the packet's 30 attempts, six writes and 480-second outer budget unless a separately reviewed change explains otherwise.
4. Resolve the real approval prerequisites in one packet: exact executing source/template/activation hashes, existing workflow/default-branch behavior, accepted runtime distribution/pins, endpoint/API/response/capability profile, credential roles and least scopes, synthetic C/privacy checks, explicit retention, exclusive ref/settings custody, restoration owner and one bounded Linux job. A boolean custody claim is not enforcement. Do not claim undocumented compare-and-swap semantics. If any prerequisite cannot be established, name the concrete blocker and decision needed rather than silently relaxing it.
5. Finish source review and applicable local tests, retain failures honestly, produce one exact-source receipt, and return the single decision-ready execution request. The current packet is not executable authority. Do not run the canary as part of this package.

Public GitHub documentation supports separate repository Administration permissions for settings changes and Actions write permissions for workflow controls; dispatch targets a branch/tag and has default-branch workflow requirements. The future implementation must bind its chosen API version and verified behavior rather than infer stronger guarantees. See [repository Actions permissions](https://docs.github.com/en/rest/actions/permissions#set-github-actions-permissions-for-a-repository), [workflow control API](https://docs.github.com/en/rest/actions/workflows#create-a-workflow-dispatch-event) and [dispatch event requirements](https://docs.github.com/en/actions/reference/workflows-and-actions/events-that-trigger-workflows#workflow_dispatch).

If Nathan adopts this goal, include **one final sanitized source/test/docs checkpoint push** to existing public `nathanmcnulty/TokenForge` branch `codex/goal6-reusable-sealer`, using existing Git authentication/signing only, followed by exact remote verification and the consolidated outcome. Do not require a separate push microtask. Preserve prior files/history; no force-push, PR or merge.

Throughout this package: no real runtime/read/controller credentials, external artifact/control-service HTTPS, Actions enablement/dispatch, hosted execution, tenant changes, operational emission/signing/artifact publication, new credentials/permissions, global trust/security changes or unapproved installations. Local fixtures use dummy values and explicit fixture-only client trust. Any actual canary requires subsequent specific approval for its exact source, credentials/scopes, writes, compute, retention and recovery procedure.

Stop with that approval-ready candidate or a precise feasibility blocker. Do not replace the remaining real decisions with more abstract fake milestones.
