# Run an operator-owned sign-in sample

Use this process for a small private sample of retained Microsoft Entra user sign-ins. The operator runs the official Microsoft Graph PowerShell SDK command in the foreground. The TokenForge scripts prepare query arguments and aggregate a local in-memory snapshot. This process does not certify complete coverage of the requested time window.

1. Open a dedicated `pwsh -NoProfile` process. Disable transcripts, session recording and HTTP tracing. Load trusted copies of `Microsoft.Graph.Authentication` and `Microsoft.Graph.Reports`. Set `$TokenForge` to the reviewed source checkout, `$CatalogRepository` to the local data checkout, and `$CatalogCommit` to the full published data commit. Set `$TenantId` to the approved tenant GUID and choose `$Since` and `$Until` as explicit UTC date-time offsets within your tenant's retention period, no more than 24 hours apart.
2. In that dedicated process, deliberately sign in through the official SDK with the existing delegated `AuditLog.Read.All` authorization and an approved account with a supported Entra role. With the selected tenant and pre-existing consent, the operator can enter `Connect-MgGraph -TenantId $TenantId -Scopes 'AuditLog.Read.All' -Environment Global -ContextScope Process -NoWelcome` explicitly. Stop if Microsoft asks to approve new permissions. The SDK owns the normal sign-in and token refresh. It may prompt again during collection, so keep the process attended and cancel if the account, tenant or permission request is unexpected. [Connect-MgGraph](https://learn.microsoft.com/en-us/powershell/module/microsoft.graph.authentication/connect-mggraph?view=graph-powershell-1.0) · [List signIns v1.0](https://learn.microsoft.com/en-us/graph/api/signin-list?view=graph-rest-1.0)
3. After sign-in, run the block below. The planner requires the exact tenant, existing delegated scope, process scope and built-in Global endpoints. The block uses the generated v1.0 Reports command with a date filter, a 1,000-row cap and a minimal property selection. It does not accept a URI, proxy, request headers, authentication material, or a custom request pipeline. Keep the resulting aggregate private.

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
