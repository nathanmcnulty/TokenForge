# Run an operator-owned sign-in sample

Use this process for a small private sample of retained Microsoft Entra user sign-ins. The operator runs the official Microsoft Graph PowerShell SDK command in the foreground. The TokenForge scripts prepare query arguments and aggregate a local in-memory snapshot. This process does not certify complete coverage of the requested time window.

## Prepare the session

Open a dedicated `pwsh -NoProfile` process in an approved environment where you can inspect private sign-in aggregates. Use a session without optional recording or tracing where organizational policy permits. Keep required auditing and other controls in place. If required recording would capture data that cannot be retained there, use an approved alternative before proceeding. Load trusted copies of `Microsoft.Graph.Authentication` and `Microsoft.Graph.Reports`.

Set `$TokenForge` to the reviewed source checkout, `$CatalogRepository` to the local data checkout, and `$CatalogCommit` to the full published data commit. Set `$TenantId` to the approved tenant GUID and choose `$Since` and `$Until` as explicit UTC date-time offsets within your tenant's retention period, no more than 24 hours apart.

### Optional operator sign-in

If the process does not already have the intended connection, the operator can explicitly sign in below. Use an approved account with a supported Entra role and existing delegated `AuditLog.Read.All` consent. Stop if Microsoft asks to approve new permissions. Keep the process attended because the SDK may prompt again during collection. Cancel an unexpected account, tenant, or permission request. [Connect-MgGraph](https://learn.microsoft.com/en-us/powershell/module/microsoft.graph.authentication/connect-mggraph?view=graph-powershell-1.0) · [List signIns v1.0](https://learn.microsoft.com/en-us/graph/api/signin-list?view=graph-rest-1.0)

```powershell
& {
    $PSDefaultParameterValues = @{ Disabled = $true }
    $ErrorActionPreference = 'Stop'
    $DebugPreference = 'SilentlyContinue'
    $VerbosePreference = 'SilentlyContinue'
    try {
        Microsoft.Graph.Authentication\Connect-MgGraph -TenantId $TenantId `
            -Scopes 'AuditLog.Read.All' -Environment Global -ContextScope Process `
            -NoWelcome -ErrorAction Stop -Debug:$false -Verbose:$false
    } catch { throw 'Could not establish the operator-selected SDK session.' }
}
```

## Run the bounded sample

The planner requires the exact tenant, existing delegated scope, process scope and built-in Global endpoints. The block uses the generated v1.0 Reports command with a date filter, a 1,000-row cap and a minimal property selection. It does not accept a URI, proxy, request headers, authentication material, or a custom request pipeline. Keep the resulting aggregate private.

```powershell
& {
    $PSDefaultParameterValues = @{ Disabled = $true }
    $ErrorActionPreference = 'Stop'
    $DebugPreference = 'SilentlyContinue'
    $VerbosePreference = 'SilentlyContinue'
    $ProgressPreference = 'SilentlyContinue'

    try {
        $context = Microsoft.Graph.Authentication\Get-MgContext -ErrorAction Stop
        $cloud = Microsoft.Graph.Authentication\Get-MgEnvironment -Name Global -ErrorAction Stop
    } catch { throw 'Could not inspect the existing SDK session.' }
    if ($null -eq $context -or $null -eq $cloud) { throw 'An existing Global SDK session is required.' }

    $plan = & (Join-Path $TokenForge 'scripts/New-TokenForgeSignInReadPlan.ps1') `
        -TenantId $TenantId -Context $context -Environment $cloud -Since $Since -Until $Until
    $rows = [System.Collections.Generic.List[object]]::new()
    try {
        try {
            Microsoft.Graph.Reports\Get-MgAuditLogSignIn -Filter $plan.Filter `
                -Property $plan.Properties -Top $plan.MaxRows -ErrorAction Stop `
                -Debug:$false -Verbose:$false -InformationAction Ignore -WarningAction SilentlyContinue |
                ForEach-Object {
                    if ($rows.Count -ge $plan.MaxRows) { throw 'Sign-in sample exceeded the row cap.' }
                    $rows.Add(@{
                        id = $_.Id
                        appId = $_.AppId
                        resourceId = $_.ResourceId
                        createdDateTime = $_.CreatedDateTime
                        isInteractive = $_.IsInteractive
                    })
                }
        } catch { throw 'Sign-in sample was incomplete. Partial records were discarded.' }

        & (Join-Path $TokenForge 'scripts/Find-TokenForgeSignInCatalogGaps.ps1') `
            -CatalogRepository $CatalogRepository -CatalogCommit $CatalogCommit `
            -Since $Since -Until $Until -SnapshotRows ($rows.ToArray())
    } finally { $rows.Clear() }
}
```

The Reports SDK command controls its HTTP authentication, redirect, retry and paging behavior. The planner and local tests do not prove those behaviors or guarantee that Graph honors its property selection. The foreground sample does not ask for all pages, read continuation URLs itself, or certify that the provider returned every record even below the cap. A successful `ReplayComplete` covers only the rows received and checked by the aggregator. `SourceWindowCoverage` remains `Unknown`, and any Graph error aborts the sample before reporting candidates. [Get-MgAuditLogSignIn](https://learn.microsoft.com/en-us/powershell/module/microsoft.graph.reports/get-mgauditlogsignin?view=graph-powershell-1.0)

The SDK streams rows through a five-field projection before the bounded aggregation. Event IDs are used in memory for deduplication. The result contains pending client AppIds and separately labeled Graph resource IDs, with counts and observation times. The JWT audience remains unknown. This procedure covers v1.0 user sign-ins only. The replay tool can separately analyze an already supplied beta-shaped snapshot. [Offline replay and fixtures](catalog-candidate-ingestion.md)


After the sample succeeds, fails, or is cancelled, close the dedicated PowerShell process. Leave SDK error history in that process without inspecting, copying, or exporting it.

## Proving full-window coverage later

A full-window collector needs a separate review of its provider and pagination behavior. Record the requested half-open interval, event categories, and retention limits. Prove that adjacent segments cover the interval, deduplicate boundary events, and reach the provider's last page in every segment. Verify endpoint and redirect constraints with a transport test. Any skipped segment, page limit, continuation failure, or provider error leaves coverage incomplete. Compare observed Graph resource IDs as separately labeled identifiers. A match does not establish a token audience or verify an application.

For multiple samples, keep only each aggregate and use disjoint UTC intervals. The [offline assembly procedure](catalog-candidate-ingestion.md#assemble-multiple-local-sign-in-gap-reports) identifies missing, partial, and conflicting intervals.
