Set-StrictMode -Version Latest
$script:ModuleRoot=$PSScriptRoot
if(-not ('TokenForge.Core.V0100.TokenPolicy' -as [type])){Add-Type -Path (Join-Path $PSScriptRoot 'Core/TokenPolicy.cs')}

if(-not ('TokenForge.Core.V0110.PlatformVaultKey' -as [type])){Add-Type -Path (Join-Path $PSScriptRoot 'Core/PlatformVaultKey.cs')}

if(-not ('TokenForge.Core.V0180.OAuthTransport' -as [type])){Add-Type -Path (Join-Path $PSScriptRoot 'Core/OAuthTransport.cs')}

$script:CatalogUrl = 'https://raw.githubusercontent.com/dirkjanm/ROADtools/master/roadtx/roadtools/roadtx/firstpartyscopes.json'
$script:CatalogPath = if ($IsWindows) { Join-Path $env:LOCALAPPDATA 'TokenForge/catalog.json' } else { Join-Path $HOME '.cache/TokenForge/catalog.json' }

function Get-TokenForgeCatalog {
    <# .SYNOPSIS
    Read a ROADtools/EntraScopes-compatible JSON catalog or a TokenForge snapshot.
    #>
    [CmdletBinding()]
    param([string]$Path = $script:CatalogPath)
    $text = Get-Content -LiteralPath $Path -Raw -ErrorAction Stop
    $document = ConvertFrom-Json -InputObject $text -AsHashtable -ErrorAction Stop
    $source = (Resolve-Path -LiteralPath $Path).Path
    $fetchedAt = $null
    $data = $document
    if ($document.ContainsKey('SchemaVersion')) {
        if ($document.SchemaVersion -ne 1) { throw 'Unsupported catalog snapshot version.' }
        $data = $document.Data
        $source = $document.Source
        $fetchedAt = $document.FetchedAt
    }
    if ($data -isnot [System.Collections.IDictionary] -or $data.apps -isnot [System.Collections.IDictionary]) {
        throw 'Catalog must contain an apps object.'
    }
    $applications = foreach ($id in $data.apps.Keys) {
        $app = $data.apps[$id]
        $guid = [guid]::Empty
        if (-not [guid]::TryParse($id, [ref]$guid) -or $app -isnot [System.Collections.IDictionary] -or $app.scopes -isnot [System.Collections.IDictionary]) {
            throw 'Catalog contains an invalid application record.'
        }
        $grants = foreach ($resourceId in $app.scopes.Keys) {
            $resourceGuid = [guid]::Empty
            if (-not [guid]::TryParse($resourceId, [ref]$resourceGuid)) { throw 'Catalog contains an invalid resource ID.' }
            $scopes = $app.scopes[$resourceId]
            if ($scopes -isnot [array] -or @($scopes | Where-Object { $_ -isnot [string] -or $_ -notmatch '^[A-Za-z0-9_.-]+$' }).Count) {
                throw 'Catalog contains invalid scope names.'
            }
            [pscustomobject]@{ ResourceId = $resourceId; Scopes = @($scopes | Sort-Object -Unique) }
        }
        [pscustomobject]@{
            ClientId = $id
            Name = [string]$app.name
            PublicClient = $app.public_client -eq $true
            Foci = $app.foci -eq $true
            RedirectUris = @($app.redirect_uris)
            PreferredRedirectUri = [string]$app.preferred_noninteractive_redirurl
            Grants = @($grants)
        }
    }
    $hash = [Convert]::ToHexString([System.Security.Cryptography.SHA256]::HashData([Text.Encoding]::UTF8.GetBytes($text))).ToLowerInvariant()
    [pscustomobject]@{
        PSTypeName = 'TokenForge.Catalog'
        Source = $source; FetchedAt = $fetchedAt; ContentSha256 = $hash
        Applications = @($applications | Sort-Object Name, ClientId)
        ResourceIdentifiers = if ($data.ContainsKey('resourceidentifiers')) { $data.resourceidentifiers } else { @{} }
    }
}

function Update-TokenForgeCatalog {
    <# .SYNOPSIS
    Download published metadata; store no credentials. URLs can be pinned to an upstream commit.
    #>
    [CmdletBinding()]
    param([uri]$SourceUri = $script:CatalogUrl, [string]$Path = $script:CatalogPath)
    if ($SourceUri.Scheme -ne 'https' -or $SourceUri.UserInfo) { throw 'Catalog source must be HTTPS without user information.' }
    $data = Invoke-RestMethod -Uri $SourceUri -TimeoutSec 30 -ErrorAction Stop
    $snapshot = @{ SchemaVersion = 1; Source = $SourceUri.AbsoluteUri; FetchedAt = [DateTimeOffset]::UtcNow.ToString('o'); Data = $data }
    $fullPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Path)
    $directory = Split-Path $fullPath -Parent
    $null = New-Item -ItemType Directory -Path $directory -Force
    $temporary = Join-Path $directory ([guid]::NewGuid().ToString() + '.tmp')
    try {
        $snapshot | ConvertTo-Json -Depth 100 | Set-Content -LiteralPath $temporary -Encoding utf8
        $catalog = Get-TokenForgeCatalog -Path $temporary
        Move-Item -LiteralPath $temporary -Destination $fullPath -Force
        $catalog
    } finally { if (Test-Path -LiteralPath $temporary) { Remove-Item -LiteralPath $temporary } }
}

function Find-TokenForgeApplication {
    <# .SYNOPSIS
    Find applications publishing every requested delegated scope for one resource ID.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Catalog,
        [Parameter(Mandatory)][guid]$ResourceId,
        [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string[]]$Scope,
        [string]$Name,
        [switch]$PublicClientOnly
    )
    foreach ($app in $Catalog.Applications) {
        if ($Name -and $app.Name.IndexOf($Name, [StringComparison]::OrdinalIgnoreCase) -lt 0) { continue }
        if ($PublicClientOnly -and -not $app.PublicClient) { continue }
        $grant = @($app.Grants | Where-Object { $_.ResourceId -eq $ResourceId.ToString() })
        if ($grant.Count -ne 1) { continue }
        if (@($Scope | Where-Object { $grant[0].Scopes -cnotcontains $_ }).Count) { continue }
        [pscustomobject]@{
            ClientId = $app.ClientId; Name = $app.Name; ResourceId = $ResourceId.ToString()
            RequestedScopes = $Scope; PublishedScopes = $grant[0].Scopes
            PublicClient = $app.PublicClient; Foci = $app.Foci
            RedirectUris = $app.RedirectUris; PreferredRedirectUri = $app.PreferredRedirectUri
            Evidence = 'PublishedMetadata'; Source = $Catalog.Source; ContentSha256 = $Catalog.ContentSha256
        }
    }
}

function New-TokenForgeRequest {
    <# .SYNOPSIS
    Build a credential-free plan for one explicitly selected client and resource.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Catalog,
        [Parameter(Mandatory)][guid]$ClientId,
        [Parameter(Mandatory)][guid]$ResourceId,
        [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string[]]$Scope,
        [Parameter(Mandatory)][uri]$RedirectUri,
        [string]$Tenant = 'organizations',
        [string]$ResourceUri,
        [switch]$OfflineAccess,
        [switch]$Spa
    )
    if ($Tenant -notmatch '^(organizations|common|consumers|[a-zA-Z0-9][a-zA-Z0-9.-]{0,252})$') { throw 'Invalid tenant authority.' }
    if (-not $RedirectUri.IsAbsoluteUri -or $RedirectUri.UserInfo -or $RedirectUri.Query -or $RedirectUri.Fragment) {
        throw 'Redirect URI must be absolute without user information, query, or fragment.'
    }
    if ($Spa -and $RedirectUri.Scheme -ne 'https') { throw 'SPA requests require an HTTPS redirect URI.' }
    $scopes = @($Scope | Sort-Object -Unique)
    if (@($scopes | Where-Object { $_ -notmatch '^[A-Za-z0-9_-][A-Za-z0-9_.-]*$' -or $_ -eq '.default' -or $_ -cin @('openid','profile','email','offline_access') }).Count) {
        throw 'Supply explicit delegated API scope names, without resource prefixes, .default, or OIDC scopes.'
    }
    $match = @(Find-TokenForgeApplication -Catalog $Catalog -ResourceId $ResourceId -Scope $scopes | Where-Object { $_.ClientId -eq $ClientId.ToString() })
    if ($match.Count -ne 1) { throw 'Selected client does not publish every requested scope for this resource in the catalog.' }
    if ($match[0].RedirectUris -cnotcontains $RedirectUri.OriginalString) { throw 'Redirect URI is not published for the selected client.' }
    if (-not $ResourceUri) { $ResourceUri = $ResourceId.ToString() }
    $mappedId = $Catalog.ResourceIdentifiers[$ResourceUri]
    if ($ResourceUri -ne $ResourceId.ToString() -and $mappedId -ne $ResourceId.ToString()) {
        throw 'Resource URI must map to the selected resource in the catalog. Omit it to use the resource application ID.'
    }
    $oauthScopes = @($scopes | ForEach-Object { "$($ResourceUri.TrimEnd('/'))/$_" })
    if ($OfflineAccess) { $oauthScopes += 'offline_access' }
    [pscustomobject]@{
        PSTypeName = 'TokenForge.Request'
        ClientId = $ClientId.ToString(); ResourceId = $ResourceId.ToString(); ResourceUri = $ResourceUri
        Scopes = $scopes; OAuthScopes = $oauthScopes; RedirectUri = $RedirectUri.OriginalString
        Tenant = $Tenant; Spa = [bool]$Spa
        Evidence = 'PublishedMetadata'; Source = $Catalog.Source; ContentSha256 = $Catalog.ContentSha256
    }
}

# One transport boundary keeps protocol tests offline and prevents automatic redirect handling.
function Invoke-TokenForgeHttp {
    param([System.Net.Http.HttpClient]$Client, [uri]$Uri, [hashtable]$Form, [string]$Origin)
    $pairs = $null
    if ($null -ne $Form) {
        $pairs = [System.Collections.Generic.Dictionary[string,string]]::new()
        foreach ($key in $Form.Keys) { $pairs.Add($key, [string]$Form[$key]) }
    }
    try { [TokenForge.Core.V0180.OAuthTransport]::Send($Client, $Uri, $pairs, $(if ($Origin) { $Origin } else { $null }), [Threading.CancellationToken]::None) }
    finally { if ($null -ne $pairs) { $pairs.Clear() } }
}

# Authorization HTML and token JSON both need bounded, credential-free failure details.
function Get-TokenForgeIdentityFailure {
    param([string]$Content, [string]$Fallback)
    $codes = @([regex]::Matches($Content, '\bAADSTS([0-9]{4,9})\b') | ForEach-Object { $_.Groups[1].Value } | Sort-Object -Unique | Select-Object -First 5)
    if ($codes.Count -eq 0) { return $Fallback }
    $suffix = ($codes | ForEach-Object { "AADSTS$_" }) -join ', '
    if ($codes -contains '50011') {
        return "Identity request failed ($suffix). Entra rejected the redirect URI; published metadata may differ from the current app registration. Response details suppressed."
    }
    return "$Fallback Identity error codes: $suffix."
}

function Get-TokenForgeToken {
    <# .SYNOPSIS
    Request tokens using an ESTSAUTH session, system-browser code + PKCE, or a refresh token.
    .DESCRIPTION
    Secrets are SecureString inputs/outputs. Cookie and refresh flows cannot satisfy interactive policy.
    Browser mode permits account selection and MFA; NoConsent requires an existing session without interaction.
    #>
    [CmdletBinding(DefaultParameterSetName = 'Cookie')]
    param(
        [Parameter(Mandatory)]$Request,
        [Parameter(Mandatory, ParameterSetName = 'Cookie')][securestring]$EstsAuth,
        [Parameter(ParameterSetName = 'Cookie')][ValidateSet('ESTSAUTH','ESTSAUTHPERSISTENT')][string]$CookieName = 'ESTSAUTH',
        [Parameter(Mandatory, ParameterSetName = 'Refresh')][securestring]$RefreshToken,
        [Parameter(Mandatory, ParameterSetName = 'Browser')][switch]$Browser,
        [Parameter(ParameterSetName = 'Browser')][string]$LoginHint,
        [Parameter(ParameterSetName = 'Browser')][switch]$NoConsent,
        [Parameter(ParameterSetName = 'Browser')][ValidateRange(30,900)][int]$TimeoutSeconds = 300
    )
    # The same typed boundary and transport serve PowerShell and native callers.
    $plan = [TokenForge.Core.V0180.OAuthRequest]::new()
    foreach ($field in @('ClientId','ResourceId','ResourceUri','Tenant','RedirectUri')) { $plan.$field = [string]$Request.$field }
    $plan.Scopes = [string[]]@($Request.Scopes)
    $plan.OAuthScopes = [string[]]@($Request.OAuthScopes)
    $plan.Spa = [bool]$Request.Spa
    if ($Request.PSObject.Properties['Discovery']) { $plan.Discovery = $Request.Discovery -eq $true }
    if ($Request.PSObject.Properties['Protocol']) { $plan.Protocol = [string]$Request.Protocol }
    [TokenForge.Core.V0180.OAuthTransport]::ValidateRequest($plan)
    if ($plan.Protocol -ne 'OAuth2V2Pkce' -and $PSCmdlet.ParameterSetName -ne 'Cookie') { throw 'Implicit discovery does not redeem refresh tokens; use a PKCE request plan.' }
    # Synchronous per-call bridge preserves the module's HTTP mock seam without global callbacks.
    $adapter = [Func[System.Net.Http.HttpClient,uri,System.Collections.Generic.Dictionary[string,string],string,TokenForge.Core.V0180.OAuthHttpResponse]] {
        param($client, $uri, $fields, $origin)
        $form = $null
        if ($null -ne $fields) { $form = @{}; foreach ($key in $fields.Keys) { $form[$key] = $fields[$key] } }
        try {
            $response = Invoke-TokenForgeHttp -Client $client -Uri $uri -Form $form -Origin $origin
            $location = if ($response -is [System.Collections.IDictionary]) { $response['Location'] } elseif ($response.PSObject.Properties['Location']) { $response.Location } else { $null }
            [TokenForge.Core.V0180.OAuthHttpResponse]::new([int]$response.Status, $location, [string]$response.Content)
        } finally { if ($null -ne $form) { $form.Clear() } }
    }
    $authorization = $null
    $result = $null
    $access = $null
    $refresh = $null
    try {
        $mode = $PSCmdlet.ParameterSetName
        $credential = if ($mode -eq 'Refresh') { $RefreshToken } else { $EstsAuth }
        $verifier = $null; $redirect = $null
        if ($mode -eq 'Browser') {
            $authority = "https://login.microsoftonline.com/$($plan.Tenant)/oauth2/v2.0"
            $authorization = Invoke-TokenForgeBrowserAuthorization -Request $Request -Authority $authority -LoginHint $LoginHint -TimeoutSeconds $TimeoutSeconds -NoConsent:$NoConsent
            $mode = 'Code'; $credential = $authorization.Code; $verifier = $authorization.Verifier; $redirect = $authorization.RedirectUri
        }
        $result = [TokenForge.Core.V0180.OAuthTransport]::AcquireForAdapter($plan, $mode, $credential, $verifier, $redirect, $CookieName, $adapter)
        if ($result.ScopeEvidence -eq 'Unverified') { Write-Warning 'Token response omitted scope; requested scopes are unverified. Check the intended API before relying on this token.' }
        if (-not $result.Discovery -and $result.AdditionalScopes.Count) { Write-Warning "Entra returned $($result.AdditionalScopes.Count) additional API scopes beyond the request. Review GrantedScopes before using this token." }
        $access = $result.AccessToken.Copy()
        if ($null -ne $result.RefreshToken) { $refresh = $result.RefreshToken.Copy() }
        $token = [pscustomobject]@{
            PSTypeName = 'TokenForge.Token'
            ClientId = $result.ClientId; ResourceId = $result.ResourceId
            RequestedScopes = $result.RequestedScopes; GrantedScopes = $result.GrantedScopes; AdditionalScopes = $result.AdditionalScopes; ScopeEvidence = $result.ScopeEvidence
            ExpiresAt = $result.ExpiresAt; TokenType = $result.TokenType
            AccessToken = $access; RefreshToken = $refresh; TokenClaims = $result.TokenClaims | Select-Object Readable,Scopes,HasDelegatedScopeClaim,Audience,ClientId,TenantFingerprint,PrincipalFingerprint,ExpiresAt,SignatureValidated,Evidence
            Discovery = $result.Discovery; Protocol = $result.Protocol
        }
        $access = $null; $refresh = $null
        $token
    } finally {
        if ($null -ne $access) { $access.Dispose() }
        if ($null -ne $refresh) { $refresh.Dispose() }
        if ($null -ne $result) { $result.Dispose() }
        if ($null -ne $authorization) { $authorization.Code.Dispose(); $authorization.Verifier.Dispose() }
    }
}

foreach ($file in Get-ChildItem -LiteralPath (Join-Path $PSScriptRoot 'Private') -Filter '*.ps1' | Sort-Object Name) { . $file.FullName }
foreach ($file in Get-ChildItem -LiteralPath (Join-Path $PSScriptRoot 'Public') -Filter '*.ps1' | Sort-Object Name) { . $file.FullName }
Export-ModuleMember -Function Import-TokenForgeFlowEvidence, Get-TokenForgeFlowEvidence, Export-TokenForgeFlowEvidence, New-TokenForgeResearchCohort, Get-TokenForgeResearchCohort, Invoke-TokenForgeResearchChunk, Get-TokenForgeResearchCoverage, Remove-TokenForgeProfileKey, Connect-TokenForgeGraph, Disconnect-TokenForgeGraph, Find-TokenForgeGraphPermission, Get-TokenForgeProfileToken, New-TokenForgeProfile, Get-TokenForgeProfile, Get-TokenForgeProfileStatus, Test-TokenForgeProfile, Connect-TokenForgeProfile, Disconnect-TokenForgeProfile, Get-TokenForgeApplicationMetadata, Update-TokenForgeApplicationMetadata, Import-TokenForgeApplicationMetadata, Update-TokenForgeCatalog, Get-TokenForgeCatalog, Find-TokenForgeApplication, New-TokenForgeRequest, Get-TokenForgeToken, Get-TokenForgeTokenClaims, Get-TokenForgeDiscovery, Update-TokenForgeDiscovery, Get-TokenForgeSignInApplications, Get-TokenForgeTenantInventory, Register-TokenForgeApplication, New-TokenForgeDiscoveryRequest, Merge-TokenForgeScopeDatabase, Import-TokenForgeScopeDatabase, New-TokenForgeScopeDatabase, Get-TokenForgeScopeDatabase, Add-TokenForgeScopeObservation, Compare-TokenForgeScopeDatabase, Export-TokenForgeScopeDatabase, Get-TokenForgeAssessmentCoverage, Invoke-TokenForgeScopeProbe, Sync-TokenForgeApplicationRegistration, Get-TokenForgeProbePlan, New-TokenForgeVault, Get-TokenForgeVault, Get-TokenForgeVaultToken, Remove-TokenForgeVaultEntry, Export-TokenForgeVaultView, Get-TokenForgeScopedToken, Get-TokenForgeScopeCandidates, Get-TokenForgeEstsCookie, Test-TokenForgeTokenAccess, New-TokenForgeTenantRequest, Get-TokenForgeAssessmentPlan, Get-TokenForgeMaintenanceReport

$ExecutionContext.SessionState.Module.OnRemove = { if($script:GraphConnection){try{if([object]::ReferenceEquals((Get-MgContext),$script:GraphConnection.Context)){$null=Disconnect-MgGraph -ErrorAction Stop}}catch{}finally{$script:GraphConnection.Secret.Dispose();$script:GraphConnection=$null}}; foreach($key in @($script:ProfileContexts.Keys)){Clear-TokenForgeProfileContext $key} }
