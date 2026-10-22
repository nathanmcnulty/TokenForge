# Goal 1: A trustworthy bounded collector

This is the portable first coding goal for the [canonical six-goal roadmap](../discovery-improvements.md). The preparation change is documentation only; no collector, flag, package or live canary is implemented or validated by this document. Implementation runs on a separately prepared dedicated Linux VM with Codex, without dependence on desktop paths, sessions, credentials or caches. Do not provision or connect to the VM during preparation.

## Outcome and boundaries

An operator can start one small approved run, interrupt it, inspect status without authentication, resume safely and create a reviewable export without recollecting. Implement and test the finite offline contract first, using synthetic fixtures and mocked transports. With required offline/package checks passing, stop at **offline-ready, live acceptance pending** when live authorization or protected session access is absent. If a required package/build check is unavailable, report implementation prepared with that gate blocked; do not label either state production-complete. No increase in cohort size or success count is required.

Keep shared .NET policy, PowerShell adapters, native Linux SQLite, frozen plans and existing formats. Reuse reviewed contracts rather than introduce another supervisor/service, database, broad authentication rewrite or automatic scheduler. Goal 2 comparison contracts may be designed alongside these tests; cross-plan compatible reuse, strict admin profiles, private freshness planning and broader flows belong to later goals.

## Verified source reconciliation

Public refs were refreshed on 2026-10-22. Existing draft implementations remain unmerged planning inputs:

| Source | Pinned revision | Parent and disposition |
| --- | --- | --- |
| main | `1be12d75c7e2a63eac8e14c32d54e79cec4a23ef` | Verified current main at preparation |
| #117 bounded VM cycle | `079a0ab8a5f46116bfbd5e97faf28c8601c5e544` | Direct child of main; reuse lock/pin/receipt/crash concepts, not a deployed unattended service |
| #118 public lookup | `2153779f7a1d5748dc14046f9d60f3ce2fa18837` | Direct child of main; independent Goal 3 usability candidate |
| #119 publication gate | `e2aab00b2079dc1e99dc38aa1a994d4877b1bbf5` | Direct child of main; reuse immutable candidate/independent approval contract, no publication authorization |
| #120 public Deep queue | `360d0e04edbfca41f8001d4838ef8d67b5ef338e` | Child of #119; Goal 4 candidate, not private account freshness |

At session start re-fetch main and these heads, record SHAs and inspect changes from the pins. Base a new branch on verified current main; if it advanced, reconcile the delta before editing. A moved/merged draft requires fresh review, not blind application. Do not merge to main or incorporate unrelated draft work. Necessary reviewed draft changes may be incorporated on the isolated Goal 1 implementation branch; record each source commit and the scope/review rationale. #120 already transports snapshots and gates no-plan work; its remaining sidecar/state crash-consistency and original-target package gates must not be confused with missing transport. Reconcile #119 before considering its stacked #120.

Read `AGENTS.md`, `docs/discovery.md`, `docs/discovery-improvements.md`, `docs/local-validation.md`, `docs/weekly-ci.md`, `docs/sqlite-flow-evidence.md` and `docs/sqlite-scope-history.md`. Inspect `src/TokenForge/Public/Probe.ps1`, `Public/DiscoveryRun.ps1`, `Private/DiscoveryRun.ps1`, `Private/FlowEvidence.ps1` under that same module, and `scripts/Invoke-TokenForgeDiscoveryRun.ps1`; trace actual credential and checkpoint boundaries. Draft docs `vm-operational-cycle.md` and `discovery-review-gate.md` live on #117/#119, not main. Preserve legacy exact hashes, immutable Started/terminal evidence, account isolation and full-history validation. Do not infer current behavior from older migration prose.

## Portable Linux setup and package evidence

Use any operator-selected workspace and a fresh isolated clone from `https://github.com/nathanmcnulty/TokenForge.git`. Never reset/clean an existing checkout. Retrieve the roadmap through its separately reviewed documentation branch/commit; record that commit and the implementation base independently. A documentation branch is a handoff, not merged runtime code. No ZIP, desktop cache or existing account session is required.

Check Linux x64, Git, existing PowerShell and Pester 5.7.1 availability, applicable guidance and clean branch status without installing or signing in. Main declares module/native 0.48.0 and SDK 10.0.401 with latest-patch roll-forward. The local runner requires PowerShell 7.4+; inspect exact test/runtime requirements because some paths may require a newer runtime. Codex installation proves none of these dependencies. Keep private live state outside Git; inspect existing protection without changing permissions under this goal. Synthetic test directories must use the project's established private-path fixtures.

Before native execution, verify an existing trusted **complete Linux x64 package**, not just an executable. Record source revision, version, archive digest against an independently trusted expected hash, package manifest/provenance, executable and dependency hashes. Follow [release verification](../native-releases.md); matching version or a hash calculated from untrusted bytes alone proves neither source identity nor adjacent-library integrity. Keep the entire package together and use an operator-selected absolute executable path in tests. This preparation verified no native package and ran none.

Reuse an older matching package only for unchanged native/core/build inputs after inspecting and recording that exact diff. An old binary cannot validate changed native source. A required local Linux x64 build of changed project source using an already available approved toolchain and dependencies is normal Goal 1 validation and needs no separate approval. Use locked dependencies, record exact source/artifact hashes and run affected checks. Do not rebuild unchanged code merely for another green result. Installing missing software/dependencies, live authentication, protected credential use, Actions, publication and consequential settings still require separate approval. If the required build/package cannot be produced within those boundaries, continue independent fixture/source work and report native validation blocked. Do not substitute source-only checks for an original-target package pass.

Use focused tests in fresh `pwsh -NoProfile` processes after inspecting test transports. The existing `scripts/Invoke-TokenForgeLocalValidation.ps1 -Preset Discovery -NativeExecutable <verified-path>` is a broader regression option when affected; it executes native packages and requires the verified package. Add focused synthetic tests for changed behavior first. Reuse passing evidence only with unchanged source, selection, fixtures and package hashes. No live transport, credential source or automatic catalog refresh is allowed in the offline suite.

## Finite implementation slices

1. **Status and failure classification:** stable versioned JSON/exit reasons for complete, structurally excluded, pending, paused, request-blocked, transient-exhausted, in-flight unknown and failed; report pairs and exact cells separately. Expired/invalid or ambiguous session context pauses affected pending work; account mismatch stops the run. Do not globally equate `interaction_required` with session expiry: well-evidenced client-specific consent, assignment or policy declines remain request-blocked evidence for that context. Ambiguous interaction/session failures pause as unknown. Neither category establishes app-wide incapability. Use allowlisted numeric diagnostics; never store raw identity bodies. Do not rewrite legacy terminal evidence to manufacture a different outcome.
2. **Budgets and durable resume:** explicit issuance/retry, bootstrap, inventory/page, source, total-request and wall-clock budgets with bounded transport timeouts and cancellation/deadline checks before each safe operation. Preflight is reported, not hidden outside the budget. Persist request intent before dispatch, terminal primary evidence before completion, and original observation times. Skip durably completed same-plan cells; repair projection without issuance. Crash after simulated issuance before durability remains unknown, conservatively consumes attempt budget and requires an explicit bounded recovery decision. No exactly-once external guarantee. If a non-mutating operation is explicitly retried in the next authorized run, allow at most one recorded uncertainty-recovery retry within its budget; do not automatically retry sign-in or mutations.
3. **Reviewable export and recovery:** independently reconstruct an allowlisted content-hashed candidate from saved evidence, bound to producer/source/recipe. Verify integrity/privacy before considering it reviewable. Interrupted projection/export retries do not authenticate or issue tokens. Preserve #119's independent approval/publication boundary; do not implement another writer or dispatch its workflow. Collection, projection, export, backup, approval and publication have separate receipts. Receipt-write failure cannot supersede authoritative checkpoints.

## Proposed live acceptance envelope, not execution permission

After offline review, request a separate explicit live scope: one authorized account, Graph only, ten frozen selected client/resource pairs, one published callback per client, serial implemented flows, no app registration/consent changes, 15-minute cooperative run deadline and at most 30 issuance attempts including retries. Before any execution declare bounded bootstrap/inventory/source/total request ceilings from the reviewed plan and authorized source set; do not hide setup requests or infer unlimited values. At most three recognized transient retries per operation must still fit global limits. Cancellation, retry waits and transport timeouts respect remaining budgets; report any in-flight overrun. These are proposed acceptance requirements, not claims current flags enforce them or service guarantees.

Live evidence must verify account/inventory, unchanged grants/registrations within checked visibility, bounded stop/restart, explicitly renewed same-account session continuation and safe export. Renewal is an operator-authorized action, never automatic reauthentication. No passkey/session/credential may enter agent inputs or reports. If authorization/protected session is absent, leave live acceptance pending without seeking credentials or broadening the goal. A canary cannot claim unattended reboot readiness; that needs separate scheduling/reboot/session-provider approval and proof.

## Ready-to-paste first goal

```text
/goal Complete only TokenForge Goal 1 from docs/goals/01-trustworthy-bounded-collector.md
Use the full six-goal roadmap in docs/discovery-improvements.md as context only.
Read AGENTS.md first. Use one /goal per milestone; stop before starting Goal 2.
Use a fresh isolated Linux x64 branch based on verified current main. Reconcile
and record the pinned main/#117/#118/#119/#120 revisions and dependency order;
incorporate only necessary reviewed draft changes, recording commits and rationale.

Deliver the three finite slices in that goal: typed safe status/session handling,
request/deadline budgets with durable same-plan resume, and reviewable saved-evidence
export. Reuse existing architecture, hashes, stores and contracts. Build synthetic
fixtures with mocked transports before wiring behavior; no live discovery. Keep
comparison/status fixture contracts bounded to Goal 1, not a collector rewrite.

Expired/invalid/ambiguous sessions pause; wrong account stops. Well-evidenced
client-specific consent/assignment/policy declines are request-blocked evidence,
not global session expiry. Neither proves app-wide incapability. Do not globally
classify interaction_required as expired. No automatic sign-in, consent or policy
change. Explicitly renewed same-account sessions are a later authorized live check.

Count preflight/bootstrap/inventory/source requests and issuance/retries against
explicit budgets, persist intent, skip durably completed cells and preserve dates.
Crash between remote result and durability stays unknown; no exactly-once claim.
Projection/export recovery must not issue tokens. Use one explicitly recorded
uncertainty retry only for an existing non-mutating operation in a later authorized
run within budget. Test before-request, remote-result-before-checkpoint,
checkpoint-before-projection and export-interruption boundaries plus locks, expiry,
interaction, account mismatch, throttle, cancellation, corrupt history/plans,
private-path refusal and export privacy. Stable JSON explains pair/cell denominators.

Inspect dependencies without auto-install/sign-in. Verify and reuse an existing
complete source-compatible Linux x64 package for relevant native tests; record
provenance/hashes. Never claim an old binary tests changed native source. A changed
native input requires a local original-target build with the available approved
toolchain and locked dependencies; no separate build approval. Run focused synthetic
checks in fresh pwsh -NoProfile processes; state exact source/package/test evidence.

Do not install software, provision/connect VMs, access credentials, sign in, execute
live discovery or identity/API requests, register apps, grant consent, change
permissions, enable/dispatch/rerun Actions or add triggers/schedules. Do not push,
open PRs, merge to main, publish, send Microsoft reports or alter unrelated behavior.
General repository instructions to push do not override these explicit limits.
After focused tests and review, checkpoint Goal 1 implementation in local commits on the isolated branch and preserve a reviewable diff and validation receipts. Publishing those commits, opening PRs, and merging still require separate authorization.

After required offline/package gates pass, stop at offline-ready, live acceptance
pending if live authorization/session/service proof is absent. Missing required
build/package checks mean implementation prepared with that gate blocked. Continue
independent fixture/source work. No larger cohort/new protocol is required. Finish
with base/head, changed files, tested boundaries, counts/skips, package/source hashes,
remaining acceptance gates and a copyable next-session status. Do not call offline
checks production completion or infer live permission from this roadmap.
End after Goal 1 offline work and its acceptance/blocker report; do not start Goal 2.
```

## Acceptance and stopping receipt

Record the immutable source/package/runtime/test inputs and outcome of each slice and boundary. Durably completed cells never replay; uncertain external requests remain uncertain; malformed/private evidence fails closed; no missing work is called successful coverage. List request budgets including retries, elapsed/overrun, selected pairs/cells, exclusions, pending/paused/blocked/unknown/failures and issuance separately. With synthetic data these are simulated counters, not live measurements. Include export hashes and projection/export recovery evidence without credentials.

Goal 1 reaches offline-ready after focused changed-source tests and required original-target package checks pass, reviewable export is proven, and scope is reviewed. If a required package gate is missing, report offline implementation prepared with that gate blocked, not offline-ready. Full operational completion additionally needs separately authorized live canary receipts; Goal 6 covers the broader release matrix. No provisioning, scheduling, live authentication, hosted execution, publishing or tenant mutation follows automatically from any receipt.
