# Goal 1 collector contract

This implementation follows documentation handoff `19470aeba7a949e4204e4ecf5586a6ffb3171c69`, retained as local tag `handoff/goal1-19470ae`. Implementation base is verified main `1be12d75c7e2a63eac8e14c32d54e79cec4a23ef`. The handoff is not merged runtime code. Goal 2 and later roadmap work remain deferred.

## Reconciled drafts

All fetched heads matched their handoff pins. None is merged or blindly cherry-picked:

| Draft | Verified source | Goal 1 disposition |
| --- | --- | --- |
| #117 | `079a0ab8a5f46116bfbd5e97faf28c8601c5e544` | Preserve exclusive writer locks, source/package pins and separate receipt concepts; no VM service, scheduler or supervisor introduced |
| #118 | `2153779f7a1d5748dc14046f9d60f3ce2fa18837` | Independent public lookup; deferred to Goal 3 |
| #119 | `e2aab00b2079dc1e99dc38aa1a994d4877b1bbf5` | Adapt immutable allowlisted candidate, content/producer/source/recipe binding and independent approval contract for private saved-cohort export; omit all workflow/writer changes |
| #120 | `360d0e04edbfca41f8001d4838ef8d67b5ef338e` | Stacked on #119, public Deep queue; deferred to Goal 4, including sidecar consistency and original-target validation |

## Start and safe continuation

Use the existing discovery wrapper with an operator-supplied SecureString session. It rejects passkey sign-in mode. It does not automatically renew, register applications, grant consent or change policy. Keep an account-specific private state directory outside Git. Existing private-path and exclusive writer checks remain required.

The wrapper defaults to a 15-minute cooperative deadline, 30 issuance attempts including bootstrap/retries, one bootstrap issuance, 20 bootstrap HTTP exchanges, 100 inventory HTTP requests, 50 inventory pages, three public-source requests, 300 total HTTP exchanges and at most three recognized transient retries. Each ceiling is independently configurable, including zero. These are finite ceilings, not permission to execute or a guarantee of service response time. Source redirects fail closed. Transport cancellation uses the smaller of 30 seconds (configurable downward) and the remaining deadline. Backoff respects cancellation/deadline. The monotonic timer starts before preflight; overrun is reported.

`OperationBudget` summaries count the current invocation including preflight. Each HTTP dispatch reserves its counter and durable private intent before transport. Fixed bootstrap intent and flow `Started` records retain remote uncertainty across interruption. Generic source/inventory recovery is conservative and explicit: one consumed uncertainty-recovery authorization remains sticky for that state directory. A later generic unknown requires external inspection/repair; the runner does not automatically reset this cap. Completed evidence never receives a new observation date. Projection or receipt failure cannot overwrite authoritative flow evidence. These are separate stores and validated snapshots, not a distributed transaction or exactly-once remote guarantee.

A definite HTTP throttle/server decline can receive bounded transient retries. Transport failure can hide success and stays unknown. Expired/invalid or ambiguous session context pauses. Allowlisted consent/assignment/policy numeric diagnostics record a request-scoped block; `interaction_required` alone pauses as ambiguous. A wrong issued account/request stops collection. None establishes application-wide capability or API access. Legacy terminal evidence is not reclassified or rewritten.

`-ResumePaused` records the operator's explicit continuation decision with an already renewed same-account session. `-RecoverUnknown` authorizes at most one uncertainty-recovery retry of an existing non-mutating operation within a finite budget. Both require a budget on direct probe/chunk entry points. A second interrupted recovery or failed recovery requires inspection, not another silent request. Bootstrap uncertainty requires explicitly allowing two bootstrap attempts in that invocation because the prior uncertain issuance is conservatively charged too. Do not remove intent files to bypass a stop.

The standalone wrapper always supplies a finite budget. Existing low-level APIs retain their compatibility behavior unless passed `-Bounded` or `-OperationBudget`; they must not be represented as the bounded Goal 1 entry point. No changes to legacy plan/cohort hash formulas are made. New flow outcomes extend the existing schema's vocabulary; use this exact source-compatible package to read them. Older readers should reject unfamiliar outcomes.

## Read status offline

```powershell
pwsh -NoProfile -File ./scripts/Get-TokenForgeCollectorStatus.ps1 `
  -StatePath /private/tokenforge/account -NativeExecutablePath /absolute/package/tokenforge
```

This command validates saved history without credentials, authentication, new directories or writer locks. JSON schema 1 reports selected pair counts separately from materialized exact cells. Unmaterialized pairs have unknown matrix sizes; first-success alternatives remain untested cells. Completed client checkpoints count processed work, not successful issuance. Concurrent status uses separate validated reads and labels that consistency limit.

Status exit codes: complete/structurally excluded 0, failed/invalid saved evidence 1, pending 2, paused 3, request-blocked 4, transient-exhausted 5, in-flight unknown 6, account mismatch 7. The collection wrapper returns nonzero for any unfinished/blocked/stopped result; its typed JSON supplies the detailed reason/stage. The existing `CohortStatus` contract is retained; `CollectorStatus` is also available through the inventory script and `Get-TokenForgeCollectorStatus` module command.

## Saved evidence export

See [saved candidate export](goal1-export.md). Export validates complete histories before selecting the frozen cohort, reconstructs missing aggregates from primary checkpoints and keeps original dates. It creates an immutable allowlisted candidate with hashes and a fixed review summary. Candidate integrity/privacy checks do not approve or publish it. Retry export from the same saved stores after interruption without authenticating or collecting.

Collection, projection, export, backup, semantic approval and publication are distinct operations. This goal creates no new backup format, publication writer, Actions trigger or schedule. Existing SQLite-aware backup operations remain separately invoked. Retain source/package and validation receipts alongside private state.

## Offline gates and live boundary

Run the Collector preset with the exact complete Linux x64 package plus affected Discovery/SQLite-flow regressions and focused native collector checks. The Collector preset uses synthetic transports and includes actual child-process kills at the intent, remote-result, primary-checkpoint and export-staging boundaries. No live transport is permitted in these fixtures.

After those gates and independent review pass, the result is **offline-ready, live acceptance pending**. It is not live or production completion. A separate canary approval must identify one authorized account, Graph only, ten frozen selected pairs, one published callback per client, serial existing flows, a 15-minute deadline, at most 30 total issuance attempts including retries/bootstrap and separately explicit bootstrap, inventory/page, source and total HTTP ceilings. A proposed initial envelope is bootstrap attempts 1, bootstrap HTTP 20, inventory HTTP 100, inventory pages 50, sources 0 using reviewed saved sources, total HTTP 300, retries at most 3, transport timeout 30 seconds. A reviewed plan may require tighter ceilings; no execution follows from this document. The wrapper budgets are per invocation. For the canary, the operator must allocate the remaining approved aggregate ceilings and deadline across stop/restart/renewal invocations using the durable receipts; restarting does not authorize a fresh canary allowance. Freeze the ten explicit client IDs through the existing NewCohort selection before execution; a processing batch limit is not a cohort-size limit.

Live gates remain account/inventory verification, stop/restart, operator-authorized same-account renewal, saved export and unchanged grants/registrations within checked visibility. Session material must stay outside agent inputs/reports. Live transport, credential use, hosted compute, publication, PRs and merging still need separate authorization. Stop before Goal 2.
