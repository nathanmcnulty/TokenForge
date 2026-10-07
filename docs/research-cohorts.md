# Frozen research cohorts

Version 0.16 connects SQLite research plans to the inventory CLI. A cohort is one frozen research run: client/resource pairs, account namespace, application metadata hash, catalog hash, authority, protocol order, redirect bound, and exploration mode. Client IDs are sorted and assigned to fixed chunks. New IDs discovered later do not shift the current run's chunk membership.

Creating the same recipe again creates a new run because creation time participates in its identity. Resubmitting the exact cohort document through `evidence cohort` remains idempotent. Each cohort also has separate flow-plan fingerprints, so a new run performs new observations rather than inheriting a previous run's completed cells.

## Plan, inspect, and run

First collect a fresh inventory using the existing Discover/Inventory stages. Use a private directory outside Git. Migrate an existing scope ledger with [the scope-history instructions](sqlite-scope-history.md), or select a new SQLite path explicitly.

```powershell
$runner = './scripts/Invoke-TokenForgeInventory.ps1'
$database = "$state/scopes.sqlite"
$cohort = & $runner -Action NewCohort -StatePath $state -DatabasePath $database `
  -PrincipalFingerprint $principal -GraphOnly -BatchSize 25 -MaxRedirects 2 `
  -ExploreAllFlows -Tenant $tenant -NativeExecutablePath $native

& $runner -Action CohortStatus -StatePath $state -CohortId $cohort.PlanId `
  -NativeExecutablePath $native

# $cookie is an existing SecureString session; the runner does not log in or grant consent.
& $runner -Action ProbeChunk -StatePath $state -CohortId $cohort.PlanId `
  -EstsAuth $cookie -NativeExecutablePath $native
```

`ProbeChunk` chooses the lowest chunk containing pending clients. Repeat it between bounded credential sessions until status reports no pending clients. Use `-ChunkIndex 0` to resume or repair a particular chunk, including a completed chunk. The original authority, principal, pairs, protocols, and limits come from the stored recipe. `-ClientId` on NewCohort narrows membership; otherwise every eligible client/resource pair from the existing probe planner is frozen. Missing, disabled, and unverified applications remain in the application catalog but are excluded from active cohorts until eligible.

Cohort creation and execution support `-WhatIf`; it suppresses recipe/checkpoint writes and token requests. The runner may still create its private directory and operation lock.

The runner uses an existing `scopes.sqlite` automatically. For a new directory, explicitly supply `-DatabasePath` on NewCohort. Detailed cohort checkpoints default to `flows.sqlite`; subsequent Report and ExportFlows actions select that existing store automatically. Application metadata uses the existing SQLite catalog when present, otherwise its compatible JSON ledger. `-MetadataPath` and `-FlowPath` choose other private output paths.

## Resume and refresh

Execution requires the same application snapshot and catalog hash as the frozen recipe, the same tenant, and a fresh inventory capture (24 hours by default in the module command). Refreshing capture time without changing application metadata is allowed. If application metadata or public catalog content changes, create a new cohort. Existing runs remain available for historical comparison. Resource pairs remain frozen even if other planning hints change.

Each flow attempt is checkpointed before issuance and after its terminal outcome. Scope summaries retain their flow-plan fingerprint, so repairing an older cohort after a newer run uses the older run's saved summary rather than reconstructing duplicate timing records. A client is completed in the cohort only after every frozen resource pair has been handled and scope/flow application-metadata updates succeed.

If metadata projection fails, primary scope and flow checkpoints survive and cohort clients stay pending. The next execution repairs metadata without repeating completed issuance. Partial failures preserve completion for fully handled clients; remaining clients stay pending. Issued-token account/client/resource mismatches stop execution and leave affected clients pending. Failed tested cells are terminal observations, not evidence that a flow can never work. Create a new run after resolving assignment, policy, callback, or session issues.

A cohort lock serializes chunk execution, alongside the existing state-directory and probe locks. Use separate private stores for independent workers, then merge their portable evidence snapshots. The recipe binds membership and execution context; it does not grant permission or replace Graph-verified ownership or issued-token consistency checks.

## Native interfaces

```text
tokenforge evidence cohort --database /private/scopes.sqlite --input /private/recipe.json --batch-size 25
tokenforge evidence cohort-export --database /private/scopes.sqlite --plan HASH
tokenforge evidence pending --database /private/scopes.sqlite --plan HASH
```

The native store validates a finite recipe schema and hashes its normalized payload with the batch size. Older client-array plans remain readable by `pending` and `checkpoint`; `cohort-export` requires a contextual cohort. Stored plan and checkpoint corruption is rejected. Recipes contain no credentials, but namespace fingerprints, authority, and membership remain private metadata. Do not publish private SQLite files or cohort exports. Anonymous scope and flow exports omit cohort and plan fingerprints.

Recipes are bounded to 8 MiB and 100,000 resource pairs; split unusually large matrices by client selection. Freeze Graph-only cohorts for a first pass, then selected published/configured resource relationships. Source and sign-in inventories are not an exhaustive universe of Microsoft applications. Authentication still requires PowerShell, and only the three implemented delegated protocols are actively probed.

## Validation

The [sanitized live report](research-cohort-validation-2026-10-07.json) covers Nora and secadmin through the inventory CLI. Each froze four client/resource pairs into two chunks, produced 12 new terminal flow slots, and completed all four clients. An injected metadata failure left all clients pending; recovery added no token attempts or scope rows. Completed and explicit chunk resumes returned no new observations. Nora had three successful flow slots and secadmin four. Private reports and anonymous exports passed. No tokens were persisted or consent granted. Local regressions also cover older-cohort repair after a newer run, account isolation, changed/stale snapshots, mismatched issuance, WhatIf, corrupt plans, and legacy plan compatibility.
