Set-StrictMode -Version Latest
if(-not ('TokenForge.Core.V0100.TokenPolicy' -as [type])){Add-Type -Path (Join-Path $PSScriptRoot 'Core/TokenPolicy.cs')}

if(-not ('TokenForge.Core.V0110.PlatformVaultKey' -as [type])){Add-Type -Path (Join-Path $PSScriptRoot 'Core/PlatformVaultKey.cs')}

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
    $request = [System.Net.Http.HttpRequestMessage]::new()
    $response = $null
    try {
        $request.RequestUri = $Uri
        $request.Method = if ($Form) { [System.Net.Http.HttpMethod]::Post } else { [System.Net.Http.HttpMethod]::Get }
        if ($Form) {
            $pairs = [System.Collections.Generic.Dictionary[string,string]]::new()
            foreach ($key in $Form.Keys) { $pairs.Add($key, [string]$Form[$key]) }
            $request.Content = [System.Net.Http.FormUrlEncodedContent]::new($pairs)
        }
        if ($Origin) { $null = $request.Headers.TryAddWithoutValidation('Origin', $Origin) }
        try {
            $response = $Client.SendAsync($request).GetAwaiter().GetResult()
            $content = $response.Content.ReadAsStringAsync().GetAwaiter().GetResult()
        } catch { throw 'Identity transport failed or timed out. Request and response details suppressed.' }
        [pscustomobject]@{
            Status = [int]$response.StatusCode
            Location = if ($response.Headers.Location) { $response.Headers.Location.OriginalString } else { $null }
            Content = $content
        }
    } finally {
        if ($null -ne $response) { $response.Dispose() }
        $request.Dispose()
    }
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
    # Plans may be saved as JSON. Validate the network-relevant fields again at the boundary.
    $clientGuid = [guid]::Empty
    if (-not [guid]::TryParse([string]$Request.ClientId, [ref]$clientGuid) -or $Request.Tenant -notmatch '^(organizations|common|consumers|[a-zA-Z0-9][a-zA-Z0-9.-]{0,252})$') { throw 'Invalid request client or tenant.' }
    $redirect = [uri]$Request.RedirectUri
    if (-not $redirect.IsAbsoluteUri -or $redirect.UserInfo -or $redirect.Query -or $redirect.Fragment) { throw 'Invalid request redirect URI.' }
    if ($Request.Spa -and $redirect.Scheme -ne 'https') { throw 'SPA requests require HTTPS.' }
    $isDiscovery = $Request.PSObject.Properties['Discovery'] -and $Request.Discovery -eq $true
    if (-not $isDiscovery -and (@($Request.Scopes).Count -eq 0 -or @($Request.Scopes | Where-Object { $_ -notmatch '^[A-Za-z0-9_-][A-Za-z0-9_.-]*$' -or $_ -cin @('openid','profile','email','offline_access') }).Count)) { throw 'Invalid request scope names.' }
    $expected = if ($isDiscovery) { @("$($Request.ResourceId)/.default") } else { @($Request.Scopes | ForEach-Object { "$($Request.ResourceUri.TrimEnd('/'))/$_" }) }
    if ($isDiscovery -and (@($Request.Scopes).Count -gt 0 -or $Request.ResourceUri -ne $Request.ResourceId)) { throw 'Discovery requests must use one resource application ID and no asserted API scopes.' }
    if (@($Request.OAuthScopes).Count -eq 0 -or @($Request.OAuthScopes | Where-Object { $_ -cne 'offline_access' -and $expected -cnotcontains $_ }).Count -or @($expected | Where-Object { $Request.OAuthScopes -cnotcontains $_ }).Count) { throw 'Request OAuth scopes do not match the plan.' }
    $protocol = if ($Request.PSObject.Properties['Protocol']) { [string]$Request.Protocol } else { 'OAuth2V2Pkce' }
    if ($protocol -notin @('OAuth2V2Pkce','OAuth2V2Implicit','OAuth2V1Implicit') -or ($protocol -ne 'OAuth2V2Pkce' -and -not $isDiscovery)) { throw 'Implicit protocols are available only for explicit discovery plans.' }
    $implicitFlow = $protocol -ne 'OAuth2V2Pkce'
    if ($implicitFlow -and $PSCmdlet.ParameterSetName -ne 'Cookie') { throw 'Implicit discovery does not redeem refresh tokens; use a PKCE request plan.' }
    $implicitTokens = $null
    $handler = [System.Net.Http.HttpClientHandler]::new()
    $handler.AllowAutoRedirect = $false
    $handler.CookieContainer = [System.Net.CookieContainer]::new()
    $client = [System.Net.Http.HttpClient]::new($handler)
    $client.Timeout = [TimeSpan]::FromSeconds(30)
    $authority = if ($protocol -eq 'OAuth2V1Implicit') { "https://login.microsoftonline.com/$($Request.Tenant)/oauth2" } else { "https://login.microsoftonline.com/$($Request.Tenant)/oauth2/v2.0" }
    $origin = if ($Request.Spa) { $redirect.GetLeftPart([UriPartial]::Authority) } else { $null }
    $form = @{ client_id = $Request.ClientId; scope = ($Request.OAuthScopes -join ' ') }
    try {
        if ($PSCmdlet.ParameterSetName -eq 'Refresh') {
            if ($RefreshToken.Length -eq 0) { throw 'Refresh token is empty.' }
            $form.grant_type = 'refresh_token'
            $form.refresh_token = [System.Net.NetworkCredential]::new('', $RefreshToken).Password
        } elseif ($PSCmdlet.ParameterSetName -eq 'Browser') {
            $authorization = Invoke-TokenForgeBrowserAuthorization -Request $Request -Authority $authority -LoginHint $LoginHint -TimeoutSeconds $TimeoutSeconds -NoConsent:$NoConsent
            try {
                $form.grant_type = 'authorization_code'
                $form.code = [System.Net.NetworkCredential]::new('', $authorization.Code).Password
                $form.code_verifier = [System.Net.NetworkCredential]::new('', $authorization.Verifier).Password
                $form.redirect_uri = $authorization.RedirectUri
            } finally { $authorization.Code.Dispose(); $authorization.Verifier.Dispose() }
        } else {
            if ($EstsAuth.Length -eq 0) { throw 'ESTSAUTH cookie is empty.' }
            try {
                $cookie = [System.Net.Cookie]::new($CookieName, [System.Net.NetworkCredential]::new('', $EstsAuth).Password, '/', 'login.microsoftonline.com')
                $cookie.Secure = $true; $cookie.HttpOnly = $true
                $handler.CookieContainer.Add($cookie)
            } catch { throw 'Invalid cookie value. Supply only the cookie value as SecureString.' }
            $verifier = [Convert]::ToBase64String([System.Security.Cryptography.RandomNumberGenerator]::GetBytes(32)).TrimEnd('=').Replace('+','-').Replace('/','_')
            $challenge = [Convert]::ToBase64String([System.Security.Cryptography.SHA256]::HashData([Text.Encoding]::ASCII.GetBytes($verifier))).TrimEnd('=').Replace('+','-').Replace('/','_')
            $state = [Convert]::ToHexString([System.Security.Cryptography.RandomNumberGenerator]::GetBytes(32))
            $query = @{
                client_id = $Request.ClientId; redirect_uri = $Request.RedirectUri; scope = $form.scope
                response_type = 'code'; response_mode = 'query'; prompt = 'none'
                code_challenge = $challenge; code_challenge_method = 'S256'; state = $state
            }
            if ($implicitFlow) {
                $query.response_type = 'token'; $query.response_mode = 'fragment'
                $query.Remove('code_challenge'); $query.Remove('code_challenge_method')
                $query.scope = "$($Request.ResourceId)/.default"
                if ($protocol -eq 'OAuth2V1Implicit') { $query.Remove('scope'); $query.resource = $Request.ResourceId }
            }
            $encoded = ($query.Keys | ForEach-Object { "$([uri]::EscapeDataString($_))=$([uri]::EscapeDataString([string]$query[$_]))" }) -join '&'
            $url = [uri]"$authority/authorize?$encoded"
            $code = $null
            for ($step = 0; $step -lt 10; $step++) {
                $response = Invoke-TokenForgeHttp -Client $client -Uri $url
                if ($response.Status -notin @(301,302,303,307,308) -or -not $response.Location) {
                    throw (Get-TokenForgeIdentityFailure -Content $response.Content -Fallback 'Silent authorization did not return a redirect. Sign-in, consent, MFA, a policy interrupt, or an unsupported HTML flow may require browser interaction.')
                }
                try { $next = [uri]::new($url, [string]$response.Location) } catch { throw 'Authorization returned an invalid redirect.' }
                # Capture the callback without contacting it, even for native/custom schemes.
                if ($next.GetLeftPart([UriPartial]::Path) -ceq $redirect.GetLeftPart([UriPartial]::Path)) {
                    $values = [System.Web.HttpUtility]::ParseQueryString($(if ($implicitFlow) { $next.Fragment.TrimStart('#') } else { $next.Query }))
                    if (@($values.GetValues('state')).Count -ne 1 -or $values['state'] -cne $state) { throw 'Authorization state mismatch.' }
                    if ($values['error']) { throw (Get-TokenForgeIdentityFailure -Content $values['error_description'] -Fallback 'Silent authorization was declined. Interactive sign-in, consent, or tenant policy may be required.') }
                    if ($implicitFlow) {
                        if (@($values.GetValues('access_token')).Count -ne 1 -or [string]::IsNullOrWhiteSpace($values['access_token']) -or $next.Query) { throw 'Implicit authorization callback is missing a valid token.' }
                        $implicitTokens = @{ access_token = $values['access_token']; token_type = $values['token_type']; expires_in = $values['expires_in']; scope = $values['scope'] }
                        break
                    }
                    if (@($values.GetValues('code')).Count -ne 1 -or [string]::IsNullOrWhiteSpace($values['code']) -or $next.Fragment) { throw 'Authorization callback is missing a valid code.' }
                    $code = $values['code']
                    break
                }
                if ($next.Scheme -ne 'https' -or $next.Host -ne 'login.microsoftonline.com' -or $next.Port -ne 443 -or $next.UserInfo -or $next.Fragment) {
                    throw 'Authorization redirected outside the supported identity host. Browser interaction may be required.'
                }
                $url = $next
            }
            if (-not $code -and -not $implicitTokens) { throw 'Authorization exceeded the redirect limit.' }
            if (-not $implicitFlow) {
                $form.grant_type = 'authorization_code'; $form.code = $code
                $form.code_verifier = $verifier; $form.redirect_uri = $Request.RedirectUri
            }
        }
        if ($implicitTokens) { $tokens = $implicitTokens }
        else {
            $response = Invoke-TokenForgeHttp -Client $client -Uri "$authority/token" -Form $form -Origin $origin
            if ($response.Status -ne 200) { throw (Get-TokenForgeIdentityFailure -Content $response.Content -Fallback "Token request failed (HTTP $($response.Status)). Identity response details suppressed; verify session, client flow, consent, and tenant policy.") }
            try { $tokens = ConvertFrom-Json -InputObject $response.Content -AsHashtable -ErrorAction Stop } catch { throw 'Token endpoint returned invalid JSON.' }
        }
        if (-not $tokens['access_token'] -or $tokens['token_type'] -ine 'Bearer') { throw 'Token endpoint returned no usable bearer token.' }
        # Use the documented token response scope field; do not assume Microsoft tokens are readable JWTs.
        $granted = @()
        if ($tokens['scope']) { $granted = @(([string]$tokens['scope'] -split ' ') | Where-Object { $_ }) }
        $missing = @($Request.Scopes | Where-Object { $granted -cnotcontains $_ -and $granted -cnotcontains "$($Request.ResourceUri.TrimEnd('/'))/$_" })
        $verified = $granted.Count -gt 0
        if ($verified -and $missing.Count) { throw 'Token response is missing one or more requested API scopes. No token returned.' }
        if (-not $verified) { Write-Warning 'Token response omitted scope; requested scopes are unverified. Check the intended API before relying on this token.' }
        $additional = @($granted | Where-Object {
            $_ -cnotin @('openid','profile','email','offline_access') -and
            $Request.Scopes -cnotcontains $_ -and $expected -cnotcontains $_
        })
        if (-not $isDiscovery -and $additional.Count) { Write-Warning "Entra returned $($additional.Count) additional API scopes beyond the request. Review GrantedScopes before using this token." }
        $expiresAt = $null
        $seconds = [double]0
        if ($tokens['expires_in'] -and [double]::TryParse([string]$tokens['expires_in'], [Globalization.NumberStyles]::Float, [Globalization.CultureInfo]::InvariantCulture, [ref]$seconds) -and [double]::IsFinite($seconds) -and $seconds -ge 0 -and $seconds -le 604800) { $expiresAt = [DateTimeOffset]::UtcNow.AddSeconds($seconds) }
        $secureAccess = ConvertTo-SecureString ([string]$tokens['access_token']) -AsPlainText -Force
        $claims = Get-TokenForgeTokenClaims -AccessToken $secureAccess
        if ($claims.HasDelegatedScopeClaim -and @($Request.Scopes | Where-Object { $claims.Scopes -cnotcontains $_ }).Count) {
            $secureAccess.Dispose()
            throw 'Decoded scp is missing one or more requested API scopes. No token returned.'
        }
        [pscustomobject]@{
            PSTypeName = 'TokenForge.Token'
            ClientId = $Request.ClientId; ResourceId = $Request.ResourceId
            RequestedScopes = $Request.Scopes; GrantedScopes = $granted; AdditionalScopes = $additional; ScopeEvidence = if ($verified) { 'TokenResponse' } else { 'Unverified' }
            ExpiresAt = $expiresAt
            TokenType = [string]$tokens['token_type']
            AccessToken = $secureAccess
            TokenClaims = $claims; Discovery = [bool]$isDiscovery; Protocol = $protocol
            RefreshToken = if ($tokens['refresh_token']) { ConvertTo-SecureString ([string]$tokens['refresh_token']) -AsPlainText -Force } else { $null }
        }
    } finally {
        $form.Clear()
        $client.Dispose()
        $handler.Dispose()
    }
}

foreach ($file in Get-ChildItem -LiteralPath (Join-Path $PSScriptRoot 'Private') -Filter '*.ps1' | Sort-Object Name) { . $file.FullName }
foreach ($file in Get-ChildItem -LiteralPath (Join-Path $PSScriptRoot 'Public') -Filter '*.ps1' | Sort-Object Name) { . $file.FullName }
Export-ModuleMember -Function Get-TokenForgeFlowEvidence, Export-TokenForgeFlowEvidence, Get-TokenForgeResearchCoverage, Remove-TokenForgeProfileKey, Connect-TokenForgeGraph, Disconnect-TokenForgeGraph, Find-TokenForgeGraphPermission, Get-TokenForgeProfileToken, New-TokenForgeProfile, Get-TokenForgeProfile, Get-TokenForgeProfileStatus, Test-TokenForgeProfile, Connect-TokenForgeProfile, Disconnect-TokenForgeProfile, Get-TokenForgeApplicationMetadata, Update-TokenForgeApplicationMetadata, Update-TokenForgeCatalog, Get-TokenForgeCatalog, Find-TokenForgeApplication, New-TokenForgeRequest, Get-TokenForgeToken, Get-TokenForgeTokenClaims, Get-TokenForgeDiscovery, Update-TokenForgeDiscovery, Get-TokenForgeSignInApplications, Get-TokenForgeTenantInventory, Register-TokenForgeApplication, New-TokenForgeDiscoveryRequest, Merge-TokenForgeScopeDatabase, New-TokenForgeScopeDatabase, Get-TokenForgeScopeDatabase, Add-TokenForgeScopeObservation, Compare-TokenForgeScopeDatabase, Export-TokenForgeScopeDatabase, Get-TokenForgeAssessmentCoverage, Invoke-TokenForgeScopeProbe, Sync-TokenForgeApplicationRegistration, Get-TokenForgeProbePlan, New-TokenForgeVault, Get-TokenForgeVault, Get-TokenForgeVaultToken, Remove-TokenForgeVaultEntry, Export-TokenForgeVaultView, Get-TokenForgeScopedToken, Get-TokenForgeScopeCandidates, Get-TokenForgeEstsCookie, Test-TokenForgeTokenAccess, New-TokenForgeTenantRequest, Get-TokenForgeAssessmentPlan, Get-TokenForgeMaintenanceReport

$ExecutionContext.SessionState.Module.OnRemove = { if($script:GraphConnection){try{if([object]::ReferenceEquals((Get-MgContext),$script:GraphConnection.Context)){$null=Disconnect-MgGraph -ErrorAction Stop}}catch{}finally{$script:GraphConnection.Secret.Dispose();$script:GraphConnection=$null}}; foreach($key in @($script:ProfileContexts.Keys)){Clear-TokenForgeProfileContext $key} }
