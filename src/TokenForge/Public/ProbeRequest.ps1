function New-TokenForgeDiscoveryRequest {
    <#
    .SYNOPSIS
    Request a resource's .default scopes for an ownership-verified, registered Microsoft client.
    .DESCRIPTION
    Discovery deliberately observes the full delegated scope set Entra issues. It is distinct
    from an explicit assessment request and never grants new consent.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Application,
        [Parameter(Mandatory)][guid]$ResourceId,
        [Parameter(Mandatory)][uri]$RedirectUri,
        [string]$Tenant = 'organizations',
        [switch]$Spa,
        [ValidateSet('OAuth2V2Pkce','OAuth2V2Implicit','OAuth2V1Implicit')][string]$Protocol = 'OAuth2V2Pkce'
    )
    if ($Application.Registration -ne 'Present' -or $Application.Ownership -ne 'VerifiedMicrosoftOwner') { throw 'Discovery requires a registered client with Graph-verified Microsoft ownership.' }
    if ($Tenant -notmatch '^(organizations|common|consumers|[a-zA-Z0-9][a-zA-Z0-9.-]{0,252})$') { throw 'Invalid tenant authority.' }
    if (-not $RedirectUri.IsAbsoluteUri -or $RedirectUri.UserInfo -or $RedirectUri.Query -or $RedirectUri.Fragment) { throw 'Invalid discovery redirect URI.' }
    if ($Application.RedirectUris -cnotcontains $RedirectUri.OriginalString) { throw 'Redirect URI is not present in client metadata.' }
    if ($Spa -and $RedirectUri.Scheme -ne 'https') { throw 'SPA discovery requires an HTTPS redirect URI.' }
    [pscustomobject]@{
        PSTypeName = 'TokenForge.Request'; Discovery = $true; Protocol = $Protocol
        ClientId = $Application.AppId; ResourceId = $ResourceId.ToString(); ResourceUri = $ResourceId.ToString()
        Scopes = @(); OAuthScopes = @("$ResourceId/.default",'offline_access')
        RedirectUri = $RedirectUri.OriginalString; Tenant = $Tenant; Spa = [bool]$Spa
        Evidence = 'TenantServicePrincipal'; Source = 'VerifiedTenantInventory'; ContentSha256 = $null
    }
}
