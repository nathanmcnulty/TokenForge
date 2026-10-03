function Get-TokenForgeProbePlan {
    <# .SYNOPSIS
    Build a deduplicated client/resource matrix from published edges, tenant grants, own-resource definitions, and Graph discovery.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Inventory, [switch]$GraphOnly, [guid[]]$ClientId)
    $graph = '00000003-0000-0000-c000-000000000000'
    foreach ($app in $Inventory.Applications) {
        if ($ClientId -and $app.AppId -notin @($ClientId | ForEach-Object ToString)) { continue }
        if ($app.Registration -ne 'Present' -or $app.Ownership -ne 'VerifiedMicrosoftOwner' -or -not $app.AccountEnabled) { continue }
        $resources = @{}
        $resources[$graph] = @('GraphDiscovery')
        if (-not $GraphOnly) {
            foreach ($grant in $app.PublishedGrants) {
                if (-not $resources.ContainsKey($grant.ResourceId)) { $resources[$grant.ResourceId] = @() }
                $resources[$grant.ResourceId] += 'PublishedScopeEdge'
            }
            foreach ($grant in @($Inventory.TenantGrants | Where-Object { $_.ClientId -eq $app.AppId -and $_.AppliesToCurrentPrincipal })) {
                if (-not $resources.ContainsKey($grant.ResourceId)) { $resources[$grant.ResourceId] = @() }
                $resources[$grant.ResourceId] += 'TenantGrantEdge'
            }
            if ($app.DelegatedScopeDefinitions.Count) {
                if (-not $resources.ContainsKey($app.AppId)) { $resources[$app.AppId] = @() }
                $resources[$app.AppId] += 'OwnResourceDiscovery'
            }
        }
        foreach ($resourceId in @($resources.Keys | Sort-Object)) {
            [pscustomobject]@{ ClientId = $app.AppId; ResourceId = $resourceId; Sources = @($resources[$resourceId] | Sort-Object -Unique) }
        }
    }
}
