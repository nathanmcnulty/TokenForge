function New-TokenForgeTenantRequest {
    <#
    .SYNOPSIS
    Request explicit delegated scopes using tenant-verified client/resource metadata.
    .DESCRIPTION
    Resource scope definitions establish valid permission names, not client consent. Entra
    still decides whether this client/session can receive them without interaction.
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
        [switch]$OfflineAccess
    )
    $client = @($Inventory.Applications | Where-Object AppId -eq $ClientId.ToString())
    $resource = @($Inventory.Applications | Where-Object AppId -eq $ResourceId.ToString())
    if ($client.Count -ne 1 -or $resource.Count -ne 1 -or $client[0].Registration -ne 'Present' -or $resource[0].Registration -ne 'Present' -or $client[0].Ownership -ne 'VerifiedMicrosoftOwner' -or $resource[0].Ownership -ne 'VerifiedMicrosoftOwner') { throw 'Explicit tenant requests require registered, ownership-verified client and resource records.' }
    $definitions = @($resource[0].DelegatedScopeDefinitions | Where-Object Enabled | Select-Object -ExpandProperty Value)
    $planningCatalog = [pscustomobject]@{
        Source = 'VerifiedTenantScopeDefinitions'; ContentSha256 = $Inventory.DiscoveryCatalogHash
        ResourceIdentifiers = @{}
        Applications = @([pscustomobject]@{
            ClientId = $ClientId.ToString(); Name = $client[0].Name; PublicClient = $client[0].PublicClient; Foci = $client[0].Foci
            RedirectUris = $client[0].RedirectUris; PreferredRedirectUri = $client[0].PreferredRedirectUri
            Grants = @([pscustomobject]@{ ResourceId = $ResourceId.ToString(); Scopes = $definitions })
        })
    }
    # Reuse the existing explicit-scope/URI validation without asserting a client grant.
    $plan = New-TokenForgeRequest -Catalog $planningCatalog -ClientId $ClientId -ResourceId $ResourceId -Scope $Scope -RedirectUri $RedirectUri -Tenant $Tenant -Spa:$Spa -OfflineAccess:$OfflineAccess
    $plan.Evidence = 'TenantResourceScopeDefinitionNotClientConsent'
    $plan
}
