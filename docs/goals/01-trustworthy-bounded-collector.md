# Supported state after the bounded-collector handoff

The Goal1-only assignment in draft #121 is superseded by the merged Goal1–6 work. Do not restart that assignment. Use [offline-v1 convergence](../offline-v1-convergence.md) for exact backlog disposition and final acceptance, and the current contracts below for operation/review.

Supported qualification is **Linux x64 offline-v1, PowerShell 7.6+, .NET 10**, with Pester 6.2.0 for reproducible tests. Historical cross-platform implementations, live receipts and packages retain their original limits and versions. #106/#122 are merged and #98 is closed; they are retained baseline evidence, not a new task.

| Goal | Actual retained implementation | Acceptance and remaining gate |
| --- | --- | --- |
| 1 | [Bounded collector](../goal1-collector.md), durable intent/recovery, locks, offline status, [seven-file saved candidate](../goal1-export.md) | Offline tests and dated [canary](../goal1-live-canary-completion.md) exist; current VM/provider/reboot/scheduler acceptance stays separate. Explicit frozen cycle is documented in [VM cycle](../vm-operational-cycle.md). |
| 2 | [Typed saved-evidence change reports](../goal2-change-reports.md) | [Offline receipt](../goal2-validation.md); no root-cause, authorization or API assurance inferred. |
| 3 | [Strict profiles and administrator workflows](../goal3-admin-workflows.md) plus public application-evidence lookup | [Offline administrator walkthrough](../walkthroughs/offline-admin.md) and dated canaries; fresh operator/live assurance remains separate. |
| 4 | [Bounded refresh](../goal4-bounded-refresh.md), deterministic completed-assessment queues, immutable selection generations, frozen resumes | [Offline acceptance](../goal4-offline-acceptance.md) and dated canary; real incremental coverage/transport/reviewed-publication acceptance remains open under #116. |
| 5 | [One closed callback experiment](../goal5-experiment-result.md) | Candidate rejected because it lost successful pairs; production policy unchanged. No new experiment or promotion is implied. |
| 6 | [Linux offline package readiness](../goal6-offline-readiness.md), later verifier/writer/recovery and inert transport checkpoints | [Current runtime packages](../runtime-package-qualification.md) are accepted history. [Single NO-GO packet](../goal6-canary-decision.md) governs hosted custody/distribution/signer/controller/service blockers; no gate flips or activation are authorized. |

#113 stays open for an actual trusted reviewer integration, main approval protections/ACLs, real artifact producer/run/attempt API proof, publication race/tamper and lost-ack retry without recollection. Consistent caller documents, a Reviewer string and green offline tests do not establish authority. The current seven-file protocol and stronger Goal6 verification/recovery supersede #119's incompatible helper; do not import it.

#115 stays open for separately authorized real VM interruption/recovery, actual expiry/revocation and same-account renewal, protected session provider, measured cancellation/overrun, reboot/timer behavior and staged publication/backup. No scheduler is activated here.

#116 stays open for a small authorized real completed-assessment cycle covering both Graph/ARM, changed/missing/stale selection and all-fresh no-work, unchanged resume across time/evidence changes, real selection-snapshot artifact transport and reviewed publication retry. Token success and selection history are not completed assessment coverage.

#114 can close only after the final compiled Linux package and affected lookup/planning tests pass and this integration is reviewed/merged; the convergence receipt records that decision. Metadata hints and anonymous scope observations remain evidence without a token/consent/API guarantee.

#69 and #74 are explicitly parked outside this milestone. Preserve their immutable historical evidence and held drafts; unresolved passkey enrollment is not retried, imported, released or declared successful. Any later work needs its own scope/authority and must preserve action pins/runtime floors.

Merge and closures remain owner decisions after dot's review. Source publication for this integration grants no authentication, tenant mutation, scheduling, hosted settings/dispatch, release or operational publication authority.
