function New-TokenForgeTenantRequest {
    <#
    .SYNOPSIS
    Request explicit delegated scopes using tenant-verified client/resource metadata.
    .DESCRIPTION
    Resource scope definitions establish valid permission names, not client consent. With
    Database, fresh matched observations supply scope evidence instead, including scopes
    absent from definitions. Entra still decides whether an explicit request can succeed.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Inventory,
        [Parameter(Mandatory)][guid]$ClientId,
        [Parameter(Mandatory)][guid]$ResourceId,
        [Parameter(Mandatory)][string[]]$Scope,
        [Parameter(Mandatory)][uri]$RedirectUri,
        [string]$Tenant = 'organizations',
        [switch]$Spa,
        [switch]$OfflineAccess,
        $Database,
        [ValidateRange(1,8760)][int]$MaxAgeHours = 24,
        [ValidatePattern('^[a-f0-9]{64}$')][string]$PrincipalFingerprint
    )
    $client = @($Inventory.Applications | Where-Object AppId -eq $ClientId.ToString())
    $resource = @($Inventory.Applications | Where-Object AppId -eq $ResourceId.ToString())
    if ($client.Count -ne 1 -or $resource.Count -ne 1 -or $client[0].Registration -ne 'Present' -or $resource[0].Registration -ne 'Present' -or $client[0].Ownership -ne 'VerifiedMicrosoftOwner' -or $resource[0].Ownership -ne 'VerifiedMicrosoftOwner') { throw 'Explicit tenant requests require registered, ownership-verified client and resource records.' }
    $definitions = @()
    $source = 'VerifiedTenantScopeDefinitions'
    $observed = $null
    if ($null -ne $Database) {
        $principal = if ($PrincipalFingerprint) { $PrincipalFingerprint } else { $Inventory.PrincipalFingerprint }
        $observed = Get-TokenForgeAssessmentCoverage -Database $Database -ResourceId $ResourceId -Scope $Scope -TenantFingerprint $Inventory.TenantFingerprint -PrincipalFingerprint $principal -MaxAgeHours $MaxAgeHours |
            Where-Object { $_.ClientId -eq $ClientId.ToString() -and $_.CoversAll } | Select-Object -First 1
        if (-not $observed) { throw 'No fresh, namespace- and request-matched observation covers the requested scopes for this client/resource.' }
        $definitions = @($Scope) + @($observed.AdditionalScopes)
        $source = 'VerifiedPrivateScopeObservation'
    } else { $definitions = @($resource[0].DelegatedScopeDefinitions | Where-Object Enabled | Select-Object -ExpandProperty Value) }
    $planningCatalog = [pscustomobject]@{
        Source = $source; ContentSha256 = if ($observed) { $null } else { $Inventory.DiscoveryCatalogHash }
        ResourceIdentifiers = @{}
        Applications = @([pscustomobject]@{
            ClientId = $ClientId.ToString(); Name = $client[0].Name; PublicClient = $client[0].PublicClient; Foci = $client[0].Foci
            RedirectUris = $client[0].RedirectUris; PreferredRedirectUri = $client[0].PreferredRedirectUri
            Grants = @([pscustomobject]@{ ResourceId = $ResourceId.ToString(); Scopes = $definitions })
        })
    }
    # Reuse the existing explicit-scope/URI validation without asserting a client grant.
    $plan = New-TokenForgeRequest -Catalog $planningCatalog -ClientId $ClientId -ResourceId $ResourceId -Scope $Scope -RedirectUri $RedirectUri -Tenant $Tenant -Spa:$Spa -OfflineAccess:$OfflineAccess
    if ($observed) {
        $plan.Evidence = 'MatchedObservedScpNotGuaranteedExplicitAuthorization'
        $plan | Add-Member -NotePropertyName ObservedAt -NotePropertyValue $observed.ObservedAt
    } else { $plan.Evidence = 'TenantResourceScopeDefinitionNotClientConsent' }
    $plan
}
