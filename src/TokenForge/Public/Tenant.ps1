function Get-TokenForgeTenantInventory {
    <#
    .SYNOPSIS
    Enumerate tenant Microsoft-owned service principals and configured delegated grants.
    .DESCRIPTION
    Returns public app IDs and tenant/user fingerprints, never raw object or principal IDs.
    Published owner information is kept separate from ownership verified through Graph.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][securestring]$GraphToken, [Parameter(Mandatory)]$Discovery, [switch]$SkipGrants)
    $payload = ConvertFrom-TokenForgeJwtPayload -AccessToken $GraphToken
    if (-not $payload -or -not $payload['tid']) { throw 'A readable Graph token with a tenant claim is required to namespace tenant evidence.' }
    $tenantFingerprint = Get-TokenForgeFingerprint -Value ([string]$payload['tid'])
    $principal = [string]$payload['oid']
    $principalFingerprint = if ($principal) { Get-TokenForgeFingerprint -Value "$($payload['tid'])/$principal" } else { $null }
    $select = 'id,appId,appOwnerOrganizationId,accountEnabled,replyUrls,oauth2PermissionScopes,appRoles,servicePrincipalNames,appRoleAssignmentRequired,signInAudience,preferredSingleSignOnMode'
    $all = Get-TokenForgeGraphCollection -AccessToken $GraphToken -Uri "https://graph.microsoft.com/v1.0/servicePrincipals?`$select=$select&`$top=999"
    $objects = @{}; $byApp = @{}
    foreach ($sp in $all) { $objects[[string]$sp['id']] = $sp; $byApp[[string]$sp['appId']] = $sp }
    $grants = @(); $grantStatus = 'Skipped'
    if (-not $SkipGrants) {
        try {
            $rawGrants = Get-TokenForgeGraphCollection -AccessToken $GraphToken -Uri 'https://graph.microsoft.com/v1.0/oauth2PermissionGrants?$select=clientId,resourceId,scope,consentType,principalId&$top=999'
            $grants = @(foreach ($grant in $rawGrants) {
                $client = $objects[[string]$grant['clientId']]; $resource = $objects[[string]$grant['resourceId']]
                if (-not $client -or -not $resource -or $client['appOwnerOrganizationId'] -notin $script:MicrosoftOwnerTenants -or $resource['appOwnerOrganizationId'] -notin $script:MicrosoftOwnerTenants) { continue }
                [pscustomobject]@{
                    ClientId = [string]$client['appId']; ResourceId = [string]$resource['appId']
                    Scopes = @(([string]$grant['scope']) -split '\s+' | Where-Object { $_ } | Sort-Object -Unique)
                    ConsentType = [string]$grant['consentType']
                    AppliesToCurrentPrincipal = $grant['consentType'] -eq 'AllPrincipals' -or ($principal -and $grant['principalId'] -eq $principal)
                    Evidence = 'TenantConfiguredGrant'
                }
            })
            $grantStatus = 'Complete'
        } catch {
            # Retain no exception body. Absence of readable grants is not proof of no grants.
            $grantStatus = if ($_.Exception.Message -match 'HTTP 403') { 'Forbidden' } else { 'Failed' }
        }
    }
    $candidates = @{}; foreach ($app in $Discovery.Applications) { $candidates[$app.AppId] = $app }
    foreach ($sp in $all) {
        if ($sp['appOwnerOrganizationId'] -in $script:MicrosoftOwnerTenants -and -not $candidates.ContainsKey([string]$sp['appId'])) {
            $id = [string]$sp['appId']
            $candidates[$id] = [pscustomobject]@{ AppId = $id; Name = $id; Sources = @([pscustomobject]@{ Name = 'TenantDiscovery'; Evidence = 'VerifiedMicrosoftOwner' }); PublicClient = $null; Foci = $null; RedirectUris = @(); PreferredRedirectUri = ''; Grants = @(); OwnerTenantId = [string]$sp['appOwnerOrganizationId']; Ownership = 'VerifiedMicrosoftOwner'; IsResourceCandidate = $false; IdentifierUris = @() }
        }
    }
    $apps = foreach ($id in $candidates.Keys) {
        $candidate = $candidates[$id]; $sp = $byApp[$id]
        $verified = $sp -and $sp['appOwnerOrganizationId'] -in $script:MicrosoftOwnerTenants
        $redirects = @($candidate.RedirectUris)
        if ($verified) { $redirects = @(@($sp['replyUrls']) + $redirects | Where-Object { $_ -is [string] -and $_ } | Sort-Object -Unique) }
        $definitions = @()
        if ($verified) {
            $definitions = @(foreach ($scope in @($sp['oauth2PermissionScopes'])) {
                if ($scope['value']) { [pscustomobject]@{ Value = [string]$scope['value']; Enabled = $scope['isEnabled'] -eq $true; ConsentType = [string]$scope['type'] } }
            })
        }
        [pscustomobject]@{
            AppId = $id; Name = $candidate.Name; Sources = $candidate.Sources
            Registration = if (-not $sp) { 'Missing' } elseif ($verified) { 'Present' } else { 'OwnerMismatch' }
            Ownership = if ($verified) { 'VerifiedMicrosoftOwner' } else { $candidate.Ownership }
            OwnerTenantId = if ($verified) { [string]$sp['appOwnerOrganizationId'] } else { $candidate.OwnerTenantId }
            AccountEnabled = if ($sp) { $sp['accountEnabled'] -eq $true } else { $null }
            AssignmentRequired = if ($sp) { $sp['appRoleAssignmentRequired'] -eq $true } else { $null }
            SignInAudience = if ($verified) { [string]$sp['signInAudience'] } else { $null }
            PublicClient = $candidate.PublicClient; Foci = $candidate.Foci
            RedirectUris = $redirects; TenantRedirectUris = if ($verified) { @($sp['replyUrls']) } else { @() }; PreferredRedirectUri = $candidate.PreferredRedirectUri
            PublishedGrants = $candidate.Grants; DelegatedScopeDefinitions = $definitions
            IdentifierUris = @($candidate.IdentifierUris)
            IsResourceCandidate = $candidate.IsResourceCandidate -or $definitions.Count -gt 0
        }
    }
    [pscustomobject]@{
        SchemaVersion = 1; CapturedAt = [DateTimeOffset]::UtcNow.ToString('o')
        TenantFingerprint = $tenantFingerprint; PrincipalFingerprint = $principalFingerprint
        TotalTenantServicePrincipalCount = @($all).Count
        VerifiedMicrosoftServicePrincipalCount = @($all | Where-Object { $_['appOwnerOrganizationId'] -in $script:MicrosoftOwnerTenants }).Count
        GrantEnumeration = $grantStatus; Applications = @($apps | Sort-Object AppId); TenantGrants = $grants
        DiscoveryCatalogHash = $Discovery.CatalogContentSha256
    }
}

function Register-TokenForgeApplication {
    <#
    .SYNOPSIS
    Ensure a discovered Microsoft application has a tenant service principal; do not grant permissions.
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'Medium')]
    param([Parameter(Mandatory)][securestring]$GraphToken, [Parameter(Mandatory)]$Application, [switch]$ResolvePublishedCandidate)
    $id = [guid]::Empty
    if (-not [guid]::TryParse([string]$Application.AppId,[ref]$id)) { throw 'Invalid application ID.' }
    $uri = "https://graph.microsoft.com/v1.0/servicePrincipals(appId='$id')"
    $existing = Invoke-TokenForgeGraph -AccessToken $GraphToken -Uri $uri -AllowNotFound
    if ($existing) {
        if ($existing['appOwnerOrganizationId'] -notin $script:MicrosoftOwnerTenants) { throw 'Existing service principal is not verified as Microsoft-owned.' }
        return [pscustomobject]@{ AppId = $id.ToString(); Outcome = 'AlreadyPresent'; Ownership = 'VerifiedMicrosoftOwner' }
    }
    # A caller-provided display name is never sufficient evidence to create an application.
    $publishedOwner = $Application.OwnerTenantId -in $script:MicrosoftOwnerTenants -and $Application.Ownership -in @('PublishedMicrosoftOwner','VerifiedMicrosoftOwner')
    $publishedCandidate = $ResolvePublishedCandidate -and $Application.PSObject.Properties['Sources'] -and @($Application.Sources | Where-Object { $_.Evidence -in @('PublishedMetadata','PublishedGraph','PublishedEntraDocs','PublishedLearn','PublishedGitHub') }).Count -gt 0
    if (-not $publishedOwner -and -not $publishedCandidate) { throw 'Creation requires published Microsoft ownership evidence, or explicit resolution of a published candidate.' }
    if (-not $PSCmdlet.ShouldProcess($id.ToString(), 'Create Microsoft application service principal without granting consent')) {
        return [pscustomobject]@{ AppId = $id.ToString(); Outcome = 'NotCreated'; Ownership = $Application.Ownership }
    }
    try { $created = Invoke-TokenForgeGraph -AccessToken $GraphToken -Uri 'https://graph.microsoft.com/v1.0/servicePrincipals' -Method POST -Body @{ appId = $id.ToString() } }
    catch {
        $failureStatus = [regex]::Match($_.Exception.Message,'\bHTTP ([0-9]{3})\b').Groups[1].Value
        # Concurrent creation may race; only verified existing state can turn failure into success.
        $existing = Invoke-TokenForgeGraph -AccessToken $GraphToken -Uri $uri -AllowNotFound
        if ($existing -and $existing['appOwnerOrganizationId'] -in $script:MicrosoftOwnerTenants) { return [pscustomobject]@{ AppId = $id.ToString(); Outcome = 'AlreadyPresent'; Ownership = 'VerifiedMicrosoftOwner' } }
        if ($failureStatus) { throw "Service principal creation failed (HTTP $failureStatus); no consent was granted." }
        throw 'Service principal creation failed; no consent was granted.'
    }
    if ($created['appId'] -ne $id.ToString()) { throw 'Creation response did not identify the requested application; no other principal was modified.' }
    if ($created['appOwnerOrganizationId'] -notin $script:MicrosoftOwnerTenants) {
        if ($created['id']) { $null = Invoke-TokenForgeGraph -AccessToken $GraphToken -Uri "https://graph.microsoft.com/v1.0/servicePrincipals/$($created['id'])" -Method DELETE }
        throw 'Created service principal failed ownership verification and was removed.'
    }
    [pscustomobject]@{ AppId = $id.ToString(); Outcome = 'Created'; Ownership = 'VerifiedMicrosoftOwner' }
}
