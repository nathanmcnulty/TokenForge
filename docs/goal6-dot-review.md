# Dot review handoff: Goal 6 release candidate

Start with [the fb6d260 follow-up](goal6-sealer-followup.md) and [its receipt](goal6-sealer-followup-validation.json): the temporary-parent fix is implemented, and complete-original-ZIP privacy is a confirmed open blocker. Operational policy emission remains blocked.

Ready for offline architecture and security review after the reusable-sealer receipt passes. This document is a handoff artifact; no message or invitation has been sent to Dot. The source is on the shared review branch and remains unmerged, Actions disabled, and no live credentials are needed to review it. See [the shared handoff index](HANDOFF.md) for the copyable review request and pinned checkpoints.

Use [goal6-sealer-validation.json](goal6-sealer-validation.json) for exact code/workflow commits and hashes. Repository: `/home/nathan/GitHub/TokenForge-goal1-2rQ8rilR`, branch `codex/goal6-reusable-sealer`. Preserve roadmap handoff `19470aeba7a949e4204e4ecf5586a6ffb3171c69`. The original checkout is separate and untouched.

Read these in order:

1. [Offline release readiness](goal6-offline-readiness.md) and [operator runbook](goal6-operator-runbook.md).
2. [Publication adapter](goal6-publication-adapter.md), [remote writer](goal6-publication-writer.md), and [offline signed-bundle verifier](goal6-attestation-verifier.md), including their historical receipts.
3. [Reusable sealer and policy](goal6-sealer.md), the exact workflow/template, the strict caller parser and [non-operational policy plan](../publication/sealer-policy-review-plan.json).

Review the original candidate ZIP versus later evidence-wrapper distinction; trusted origin and reusable-workflow certificate bindings; the single trusted OIDC job; artifact/run/attempt/current-main rechecks; expiry, request/time/byte limits; strict seven-file privacy checks; independent actors and policy custody; exact-parent writer dispatch, lost-ack classification and durable recovery. Challenge the source-A/workflow-B/producer-C pin model and the separation between a schema-valid policy and operational authority.

The narrow local replay is `scripts/Invoke-TokenForgeLocalValidation.ps1 -Preset Sealer -NativeExecutable .cache/goal6/accepted-package/linux-x64/tokenforge`, in a fresh PowerShell process and externally isolated network namespace. It uses Pester 6.2.0, the existing Linux x64 package and PyYAML 6.0.2; no install or native rebuild is needed. Reuse historical broad package, native and signed-bundle results where their exact inputs are unchanged. No synthetic result establishes hosted or live behavior.

Completion assessment: the bounded collector, comparisons, four admin workflows, refresh planning and closed experiment have prior milestone evidence; Goal 6 has offline release/package, publication adapter/writer and signed-bundle verifier checkpoints, now extended by the reusable sealer and policy. The remaining Goal 6 work is integration and acceptance proof, rather than another unbounded discovery sweep:

- Review and approve final release source/package, real identity/custody bindings and caller activation.
- Separately authorize limited hosted provenance and actual publication permission/race/recovery proof. Actions activation and any remote mutation require approval.
- Obtain fresh-operator receipts for all four supported workflows and collector recovery on that exact package. Any authentication needs a separately bounded account/client/callback/scope/API envelope; tenant permission changes remain excluded.

Do not declare Goal 6 complete, production-ready or publication-ready until those required gates pass. Dot can review offline now; live release acceptance is pending. See the receipt for the independent review disposition and local test count.
