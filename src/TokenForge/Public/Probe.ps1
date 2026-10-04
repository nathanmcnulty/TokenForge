function Invoke-TokenForgeScopeProbe {
    <#
    .SYNOPSIS
    Resumable, bounded delegated-scope discovery for registered Microsoft clients.
    .DESCRIPTION
    Uses existing cookies only. Does not grant consent, process policy pages, or persist tokens.
    The database checkpoints every terminal app/resource observation.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Inventory,
        [Parameter(Mandatory)][securestring]$EstsAuth,
        [guid[]]$ResourceId,
        [object[]]$Plan,
        [ValidateSet('OAuth2V2Pkce','OAuth2V2Implicit','OAuth2V1Implicit')][string[]]$Protocols = @('OAuth2V2Pkce','OAuth2V2Implicit','OAuth2V1Implicit'),
        [Parameter(Mandatory)][string]$DatabasePath,
        [guid[]]$ClientId,
        [ValidatePattern('^[a-f0-9]{64}$')][string]$PrincipalFingerprint,
        [ValidateRange(1,100000)][int]$MaxApplications = 100000,
        [ValidateRange(1,1000)][int]$MaxRedirects = 8,
        [ValidateRange(0,60000)][int]$DelayMilliseconds = 250,
        [switch]$Refresh,
        [string]$Tenant = 'organizations'
    )
    $probePrincipal = if ($PrincipalFingerprint) { $PrincipalFingerprint } else { $Inventory.PrincipalFingerprint }
    if (-not $probePrincipal) { throw 'A probe principal fingerprint is required.' }
    if (-not $ResourceId -and -not $Plan) { throw 'Provide ResourceId or a probe Plan.' }
    $matrix = @{}
    foreach ($edge in @($Plan)) {
        if ($null -eq $edge) { continue }
        $client = [guid]$edge.ClientId; $resource = [guid]$edge.ResourceId
        if (-not $matrix.ContainsKey($client.ToString())) { $matrix[$client.ToString()] = @() }
        $matrix[$client.ToString()] += $resource
    }
    $database = Get-TokenForgeScopeDatabase -Path $DatabasePath
    $completed = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    foreach ($observation in $database.Observations) {
        if ($observation.TenantFingerprint -eq $Inventory.TenantFingerprint -and $observation.PrincipalFingerprint -eq $probePrincipal) { $null = $completed.Add("$($observation.ClientId)/$($observation.ResourceId)") }
    }
    $apps = @($Inventory.Applications | Where-Object { -not $ClientId -or $_.AppId -in @($ClientId | ForEach-Object ToString) } | Sort-Object AppId)
    $processedApplications = 0
    foreach ($app in $apps) {
        $resources = @($ResourceId)
        if ($Plan) { $resources = @($matrix[$app.AppId] | Where-Object { $_ } | Sort-Object -Unique) }
        $pending = @($resources | Where-Object { $Refresh -or -not $completed.Contains("$($app.AppId)/$_") })
        if (-not $pending.Count) { continue }
        if ($processedApplications -ge $MaxApplications) { break }
        $processedApplications++
        foreach ($resource in $pending) {
            $key = "$($app.AppId)/$resource"
            if (-not $Refresh -and $completed.Contains($key)) { continue }
            $watch = [Diagnostics.Stopwatch]::StartNew()
            $observation = [pscustomobject]@{
                ClientId = $app.AppId; ResourceId = $resource.ToString()
                TenantFingerprint = $Inventory.TenantFingerprint; PrincipalFingerprint = $probePrincipal
                ObservedAt = [DateTimeOffset]::UtcNow.ToString('o'); Outcome = 'Failed'
                Protocol = 'OAuth2V2Pkce'; Spa = $false; RequestedScopes = @('.default')
                ResponseScopes = @(); ScpScopes = @(); ClaimsReadable = $false; HasScpClaim = $false
                SignatureValidated = $false; NamespaceVerification = 'Unverifiable'; RequestVerification = 'Unverifiable'; ErrorCodes = @(); AttemptCount = 0; ElapsedSeconds = 0
                CatalogHash = $Inventory.DiscoveryCatalogHash
            }
            if ($app.Registration -eq 'Missing') { $observation.Outcome = 'MissingRegistration' }
            elseif ($app.Registration -eq 'OwnerMismatch' -or $app.Ownership -ne 'VerifiedMicrosoftOwner') { $observation.Outcome = 'OwnerMismatch' }
            elseif (-not $app.AccountEnabled) { $observation.Outcome = 'Disabled' }
            else {
                $redirects = @($app.RedirectUris | Where-Object { $_ -is [string] -and $_ -notmatch '^(brk-|ms-appx-web:)' } | Sort-Object @{ Expression = { if ($_ -eq $app.PreferredRedirectUri) { 0 } elseif ($_ -match 'nativeclient|localhost|^urn:') { 1 } else { 2 } } }, @{ Expression = { $_ } } | Select-Object -First $MaxRedirects)
                if (-not $redirects.Count) { $observation.Outcome = if ($app.RedirectUris.Count) { 'BrokerRequired' } else { 'NoRedirect' } }
                foreach ($redirect in $redirects) {
                    $uri = $null
                    if (-not [uri]::TryCreate($redirect,[UriKind]::Absolute,[ref]$uri) -or $uri.Query -or $uri.Fragment -or $uri.UserInfo) { continue }
                    $attempts = @(foreach ($protocol in $Protocols) {
                        $modes = if ($protocol -eq 'OAuth2V2Pkce' -and $uri.Scheme -eq 'https' -and $uri.Host -ne 'login.microsoftonline.com') { @($false,$true) } else { @($false) }
                        foreach ($mode in $modes) { [pscustomobject]@{ Protocol = $protocol; Spa = $mode } }
                    })
                    foreach ($attempt in $attempts) {
                        $spa = $attempt.Spa
                        $token = $null
                        $observation.AttemptCount++
                        $observation.Protocol = $attempt.Protocol
                        $observation.Spa = $spa
                        try {
                            $request = New-TokenForgeDiscoveryRequest -Application $app -ResourceId $resource -RedirectUri $redirect -Tenant $Tenant -Spa:$spa -Protocol $attempt.Protocol
                            $token = Get-TokenForgeToken -Request $request -EstsAuth $EstsAuth -WarningAction SilentlyContinue
                            $claims = $token.TokenClaims
                            if ($claims.PSObject.Properties['TenantFingerprint'] -and $claims.PSObject.Properties['PrincipalFingerprint']) {
                                if (($claims.TenantFingerprint -and $claims.TenantFingerprint -ne $Inventory.TenantFingerprint) -or ($claims.PrincipalFingerprint -and $claims.PrincipalFingerprint -ne $probePrincipal)) {
                                    $observation.Outcome = 'ContextMismatch'
                                    $observation.NamespaceVerification = 'Mismatch'
                                    break
                                }
                                if ($claims.TenantFingerprint -and $claims.PrincipalFingerprint) { $observation.NamespaceVerification = 'Matched' }
                            }
                            $aliases = @($resource.ToString()) + @($Inventory.Applications | Where-Object AppId -eq $resource.ToString() | ForEach-Object { $_.IdentifierUris })
                            if ($resource.ToString() -eq '00000003-0000-0000-c000-000000000000') { $aliases += 'https://graph.microsoft.com' }
                            if ($resource.ToString() -eq '797f4846-ba00-4fd7-ba43-dac1f8f63013') { $aliases += @('https://management.azure.com','https://management.core.windows.net') }
                            $audience = if ($claims.PSObject.Properties['Audience']) { [string]$claims.Audience } else { '' }
                            $issuedClient = if ($claims.PSObject.Properties['ClientId']) { [string]$claims.ClientId } else { '' }
                            $audienceMatched = $audience -and $audience.TrimEnd('/') -in @($aliases | ForEach-Object { ([string]$_).TrimEnd('/') })
                            if (($issuedClient -and $issuedClient -ne $app.AppId) -or ($audience -and -not $audienceMatched)) {
                                $observation.Outcome = 'ContextMismatch'
                                $observation.RequestVerification = 'Mismatch'
                                break
                            }
                            if ($issuedClient -and $audienceMatched) { $observation.RequestVerification = 'Matched' }
                            $observation.ResponseScopes = @($token.GrantedScopes)
                            $observation.ClaimsReadable = $token.TokenClaims.Readable
                            $observation.HasScpClaim = $token.TokenClaims.HasDelegatedScopeClaim
                            $observation.ScpScopes = @($token.TokenClaims.Scopes)
                            $observation.Spa = $spa
                            $observation.Protocol = $attempt.Protocol
                            $observation | Add-Member -NotePropertyName RedirectFingerprint -NotePropertyValue (Get-TokenForgeFingerprint -Value $redirect) -Force
                            $observation.Outcome = if (-not $token.TokenClaims.Readable) { 'OpaqueToken' } elseif (-not $token.TokenClaims.HasDelegatedScopeClaim -or -not $observation.ScpScopes.Count) { 'NoDelegatedScp' } else { 'Succeeded' }
                            break
                        } catch {
                            $observation.ErrorCodes = @(@($observation.ErrorCodes) + @([regex]::Matches($_.Exception.Message,'\bAADSTS([0-9]{4,9})\b') | ForEach-Object { $_.Groups[1].Value }) | Sort-Object -Unique)
                        } finally {
                            if ($token) { $token.AccessToken.Dispose(); if ($token.RefreshToken) { $token.RefreshToken.Dispose() } }
                            $token = $null
                        }
                        if ($DelayMilliseconds) { Start-Sleep -Milliseconds $DelayMilliseconds }
                    }
                    if ($observation.Outcome -in @('Succeeded','OpaqueToken','NoDelegatedScp','ContextMismatch')) { break }
                }
            }
            $observation.ElapsedSeconds = [math]::Round($watch.Elapsed.TotalSeconds,3)
            $database = Add-TokenForgeScopeObservation -Database $database -Observation $observation -Path $DatabasePath
            $observation
            if ($DelayMilliseconds) { Start-Sleep -Milliseconds $DelayMilliseconds }
        }
    }
}

function Sync-TokenForgeApplicationRegistration {
    <# .SYNOPSIS
    Ensure verified/published Microsoft candidates are registered; checkpoint results without granting consent.
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'Medium')]
    param(
        [Parameter(Mandatory)]$Inventory,
        [Parameter(Mandatory)][securestring]$GraphToken,
        [Parameter(Mandatory)][string]$DatabasePath,
        [guid[]]$ClientId,
        [ValidateRange(1,100000)][int]$MaxApplications = 100000,
        [ValidateRange(0,60000)][int]$DelayMilliseconds = 250,
        [switch]$RetryFailures,
        [switch]$ResolvePublishedCandidates,
        [switch]$ResolveSignInCandidates
    )
    $context = Get-TokenForgeTokenClaims -AccessToken $GraphToken
    if (-not $context.TenantFingerprint -or $context.TenantFingerprint -ne $Inventory.TenantFingerprint) { throw 'Graph token tenant does not match registration inventory.' }
    $database = Get-TokenForgeScopeDatabase -Path $DatabasePath
    $completed = @{}
    foreach ($attempt in $database.RegistrationAttempts) {
        if ($attempt.TenantFingerprint -eq $Inventory.TenantFingerprint) { $completed[$attempt.AppId] = $attempt.Outcome }
    }
    if (@($completed.Values | Where-Object { $_ -eq 'CleanupRequired' }).Count) { throw 'Registration stopped by an unresolved ownership-cleanup checkpoint. Verify cleanup and append a CleanupResolved record before resuming.' }
    $apps = @($Inventory.Applications | Where-Object { $_.Registration -eq 'Missing' -and ($_.Ownership -eq 'PublishedMicrosoftOwner' -or ($ResolvePublishedCandidates -and @($_.Sources | Where-Object { $_.Evidence -in @('PublishedMetadata','PublishedResource','PublishedGraph','PublishedEntraDocs','PublishedLearn','PublishedGitHub') }).Count -gt 0) -or ($ResolveSignInCandidates -and @($_.Sources|Where-Object Evidence -eq 'ObservedSignInNotOwnership').Count -gt 0)) -and (-not $ClientId -or $_.AppId -in @($ClientId | ForEach-Object ToString)) } | Sort-Object AppId)
    $processedApplications = 0
    foreach ($app in $apps) {
        if ($completed.ContainsKey($app.AppId) -and (-not $RetryFailures -or $completed[$app.AppId] -ne 'Failed')) { continue }
        if ($processedApplications -ge $MaxApplications) { break }
        $processedApplications++
        if (-not $PSCmdlet.ShouldProcess($app.AppId,'Register Microsoft-owned candidate without granting consent')) { continue }
        $httpStatus = $null
        try { $result = Register-TokenForgeApplication -GraphToken $GraphToken -Application $app -ResolvePublishedCandidate:$ResolvePublishedCandidates -ResolveSignInCandidate:$ResolveSignInCandidates -Confirm:$false; $outcome = $result.Outcome }
        catch { $outcome = 'Failed'; if ($_.Exception.Data['TokenForgeOutcome'] -in @('OwnerRejected','CleanupRequired')) { $outcome = [string]$_.Exception.Data['TokenForgeOutcome'] }; $match = [regex]::Match($_.Exception.Message,'\bHTTP ([0-9]{3})\b'); if ($match.Success) { $httpStatus = [int]$match.Groups[1].Value }; if ($httpStatus -in @(401,403)) { throw "Registration stopped (HTTP $httpStatus); renew the Graph session or verify authorization before resuming." } }
        $attempt = [pscustomobject]@{ AppId = $app.AppId; TenantFingerprint = $Inventory.TenantFingerprint; AttemptedAt = [DateTimeOffset]::UtcNow.ToString('o'); Outcome = $outcome; HttpStatus = $httpStatus }
        $database.RegistrationAttempts += $attempt
        $database.UpdatedAt = [DateTimeOffset]::UtcNow.ToString('o')
        Save-TokenForgeDocument -Document $database -Path $DatabasePath
        $attempt
        if ($outcome -eq 'CleanupRequired') { throw 'Registration stopped because ownership cleanup is required; inspect the last application ID in RegistrationAttempts.' }
        if ($DelayMilliseconds) { Start-Sleep -Milliseconds $DelayMilliseconds }
    }
}
