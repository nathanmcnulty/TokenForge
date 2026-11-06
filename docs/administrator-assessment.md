# Private administrator assessment

Use the saved public catalog to select candidates, the existing frozen collector to observe scopes, and the existing named-tool refresh journal to perform approved checks. Public metadata, token issuance and API acceptance remain different evidence types. Roles, licensing and access to other endpoints remain unproven unless separately checked. Keep account bindings, inventories, databases, journals and receipts private.

Use a reviewed Linux x64 package and its own module/scripts. Record source, compilation, archive, executable and credential-library identities separately. New core operations require a matching compiled package; an older accepted binary is not proof of new behavior. Production publication, Actions and scheduling are separate milestones.

## Select and prepare

1. Use packaged `scripts/tokenforge.ps1 health lookup` against the saved public-health workstation. Inspect source status and the original collection date. A match does not establish tenant registration, consent or callback support.
2. Privately confirm the approved account/tenant and existing authentication provider. Verify client/resource registration, ownership, enabled state, definitions and callback in the private inventory. Reuse compatible evidence within its original freshness limit; explicitly authorize bounded inventory refresh when required. Preserve original dates.
3. Approve exact client/resource/protocol/callback/API targets, aggregate sign-in/issuance/HTTP limits across preparation and resume, one deadline, and stop/recovery behavior. Invocation limits do not create a new aggregate allowance: carry prior charges and uncertain reservations forward.

Prepare a new private directory with the selected discovery/inventory documents. The staged cohort API creates an exact pair subset and immutable runner binding without authentication or collection:

```powershell
Import-Module "$package/src/TokenForge/TokenForge.psd1"
$native = Join-Path $package tokenforge
$pairs = @(
    @{ ClientId = $approvedGraphClient; ResourceId = '00000003-0000-0000-c000-000000000000' },
    @{ ClientId = $approvedArmClient; ResourceId = '797f4846-ba00-4fd7-ba43-dac1f8f63013' }
)
$cohort = New-TokenForgeResearchCohort -Inventory $inventory `
    -DatabasePath "$newState/scopes.sqlite" -Plan $pairs `
    -RunManifestPath "$newState/discovery-run.json" -BatchSize 1 `
    -Protocols OAuth2V2Pkce -MaxRedirects 1 -Tenant $approvedTenant `
    -NativeExecutablePath $native
```

Every selected pair must already be eligible under the inventory and any client/Graph-only filters. Empty/null/oversized, malformed and ineligible selections refuse before native dispatch; duplicate pairs are deduplicated. Runner preparation uses the exact database filename `scopes.sqlite`; its sibling `discovery-run.json` is create-new. A manifest I/O failure can leave an unreferenced cohort in SQLite, but cannot start collection or overwrite a saved run.

## Collect, stop and resume

Use the existing [FrozenCycle procedure](vm-operational-cycle.md) with complete package pins, a supplied session and its declared deadline. The ordinary runner can proceed into collection, so use the staged API above for preparation. Cap the first supervised invocation to one chunk or request a cooperative stop. Inspect durable receipts/status, then resume the identical directory/cohort with only the remaining aggregate budget. Clear a stop marker deliberately before an approved resume.

Use `Get-TokenForgeCollectorStatus`, `Get-TokenForgeResearchCohort -SummaryOnly` and `Get-TokenForgeResearchCoverage` to inspect completed/pending/unknown work and original observation dates. Completed primary assessments are repaired/projected and skipped; a new cohort is an explicit new assessment. Collector completion does not establish selected-token API acceptance. Never copy state or rename files to reset uncertain requests.

Stop on consent/interaction, context mismatch, expired session/inventory, exhausted limits or uncertain consumption. Authentication is explicit and uncertain authentication is not automatically retried. Supported single read-only recovery requires review. Reuse accepted safety evidence when its executed inputs are equivalent; unsafe live interruptions, reboot and revocation are not routine refresh checks.

## Check useful operations and select due work

Use existing named-tool requirements and strict profiles for explicitly scoped checks. Optional proofs are `GraphMeV1` (Graph self-profile) and `ArmSubscriptionsV1` (ARM subscriptions with explicit `user_impersonation`). Both require operation approval. Keep additional-scope ceilings unchanged. The ordinary collector can retain extra pre-consented scopes as observations without admitting that token into a strict tool request.

The [refresh input/history contract](goal4-bounded-refresh.md#offline-commands-and-operator-boundary) binds approved profile/tools, current inventory, exact pins and typed saved evidence. Prepare and save the input and frozen plan privately before acquisition:

```powershell
$plan = Get-TokenForgeRefreshPlan -InputJson $inputJson -AsOf ([DateTimeOffset]::UtcNow)
$plan.Candidates | Select-Object ToolId, Reason, Selected, Deferral, ObservedAt, ReuseOrigins
# Execute only the approved saved plan within the shared remaining limits.
Invoke-TokenForgeRefresh -PlanJson $planJson -AccountStateDirectory $stableAccountState `
    -EstsAuth $existingSession -OperationCheck
$history = Export-TokenForgeRefreshHistory -PlanJson $planJson `
    -StatePath "$stableAccountState/refresh-run.json"
```

Selection prioritizes relevant changes, missing observations and overdue evidence, reports deferrals, and reuses original references/dates. A display-name-only change does not invalidate a compatible request. Stale inventory is a prerequisite, not permission to refresh silently. Time and metadata changes do not rewrite a frozen plan. A reviewed new plan advances the stable journal only after known terminal work and retention of prior history; unknown consumption blocks advance/reset.

Omitted history in capture/export inherits the validated frozen base; explicit empty/malformed JSON refuses. An all-fresh plan selects zero requests and acquires nothing. Issuance with API 403 or an unobserved response does not become successful API acceptance. An ARM 200, including an empty visible subscription set, proves that endpoint accepted the token only; the fixed proof emits status, not response bodies or subscription identifiers.

Keep #115/#116 open where full acceptance is incomplete. Record live Graph/ARM and incremental outcomes separately from synthetic failures and retained historical evidence. #115's reviewed operational publication/failure-retry category belongs to #113 and does not block private assessment. This flow enables no schedule, old workflow, consent/protection change or private-evidence publication.
