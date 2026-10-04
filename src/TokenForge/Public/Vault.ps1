function New-TokenForgeVault {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path,[Parameter(Mandatory)][securestring]$Password)
    Invoke-TokenForgeVaultTransaction -Path $Path -Password $Password -Mode Create
    [pscustomobject]@{Created=$true;Format='TokenForgeVault';Version=1;Protection='Passphrase-AES-256-GCM'}
}

function Get-TokenForgeVault {
    <# .SYNOPSIS
    Unlock a vault and return only whitelisted session/token metadata, never credentials.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path,[Parameter(Mandatory)][securestring]$Password)
    $document=Invoke-TokenForgeVaultTransaction -Path $Path -Password $Password
    try{
        $now=[DateTimeOffset]::UtcNow
        $sessions=foreach($name in @($document.Sessions.Keys|Sort-Object)){
            $session=$document.Sessions[$name]
            [pscustomobject]@{
                Name=$name;TenantFingerprint=$session.TenantFingerprint;PrincipalFingerprint=$session.PrincipalFingerprint
                CookieName=$session.CookieName;HasCookie=[bool]$session.Cookie;CreatedAt=$session.CreatedAt
                LastConfirmedAt=$session.LastConfirmedAt;RetainUntil=$session.RetainUntil
                RetentionExpired=[DateTimeOffset]::Parse($session.RetainUntil) -le $now
                Tokens=@(foreach($entry in @($session.Tokens.Values|Sort-Object ClientId,ResourceId,Id)){
                    [pscustomobject]@{
                        Id=$entry.Id;ClientId=$entry.ClientId;ResourceId=$entry.ResourceId;Audience=$entry.Audience
                        RequestedScopes=@($entry.Scopes);IssuedScopes=@($entry.IssuedScopes);AdditionalScopeCount=$entry.AdditionalScopeCount
                        AcquiredAt=$entry.AcquiredAt;ExpiresAt=$entry.ExpiresAt;HasRefreshToken=[bool]$entry.RefreshToken
                        ExpiryStatus=if(-not $entry.ExpiresAt){'Unknown'}elseif([DateTimeOffset]::Parse($entry.ExpiresAt) -le $now.AddMinutes(2)){'ExpiredOrNearExpiry'}else{'WithinReportedLifetime'}
                        Protocol=$entry.Protocol;ConsentEvidence=$entry.ConsentEvidence;SignatureValidated=$false
                    }
                })
            }
        }
        [pscustomobject]@{SchemaVersion=1;GeneratedAt=$now.ToString('o');Protection='Passphrase-AES-256-GCM';Sessions=@($sessions);Evidence='StoredMetadataNotNewIssuanceOrApiAuthorization'}
    }finally{$document=$null}
}

function Remove-TokenForgeVaultEntry {
    <# .SYNOPSIS
    Remove a named session (and its tokens), or one token. This is local deletion, not revocation.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,[Parameter(Mandatory)][securestring]$Password,
        [Parameter(Mandatory)][ValidatePattern('^[a-z][a-z0-9_-]{0,63}$')][string]$SessionName,
        [ValidatePattern('^[a-f0-9]{64}$')][string]$TokenId
    )
    Invoke-TokenForgeVaultTransaction -Path $Path -Password $Password -Mode Update -Update {
        param($document)
        if(-not $document.Sessions.Contains($SessionName)){throw 'Session not found.'}
        if($TokenId){
            if(-not $document.Sessions[$SessionName].Tokens.Contains($TokenId)){throw 'Token not found.'}
            $null=$document.Sessions[$SessionName].Tokens.Remove($TokenId)
            $document.Sessions[$SessionName].Revision=[guid]::NewGuid().ToString()
        }else{$null=$document.Sessions.Remove($SessionName)}
    }
    [pscustomobject]@{Removed=$true;Evidence='LocalRemovalNotServerRevocation'}
}

function Get-TokenForgeVaultToken {
    <# .SYNOPSIS
    Explicitly retrieve one saved credential into SecureString objects; normal vault listing is metadata-only.
    .DESCRIPTION
    Cached access requires known expiry and actual requested-scope coverage. RefreshOnly returns no access token.
    No network request is made; caller owns secrets and must verify any later refresh result.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,[Parameter(Mandatory)][securestring]$Password,
        [Parameter(Mandatory)][ValidatePattern('^[a-z][a-z0-9_-]{0,63}$')][string]$SessionName,
        [Parameter(Mandatory)][ValidatePattern('^[a-f0-9]{64}$')][string]$TokenId,
        [ValidateRange(0,2147483647)][int]$MaxAdditionalScopes=2147483647,[switch]$RefreshOnly
    )
    $document=Invoke-TokenForgeVaultTransaction -Path $Path -Password $Password
    $access=$null;$refresh=$null;$returned=$false
    try{
        $session=$document.Sessions[$SessionName]
        if(-not $session -or [DateTimeOffset]::Parse($session.RetainUntil) -le [DateTimeOffset]::UtcNow){throw 'Saved session is absent or its local retention deadline passed.'}
        $entry=$session.Tokens[$TokenId]
        if(-not $entry){throw 'Saved token not found.'}
        if($RefreshOnly){if(-not $entry.RefreshToken){throw 'Saved token has no refresh token.'}}
        else{
            if(-not $entry.ExpiresAt -or [DateTimeOffset]::Parse($entry.ExpiresAt) -le [DateTimeOffset]::UtcNow.AddMinutes(2)){throw 'Saved access token is expired, near expiry, or has unknown expiry; acquire a new token.'}
            $access=ConvertTo-SecureString $entry.AccessToken -AsPlainText -Force
            $claims=Get-TokenForgeTokenClaims -AccessToken $access
            if($claims.ExpiresAt -and $claims.ExpiresAt -le [DateTimeOffset]::UtcNow.AddMinutes(2)){throw 'Saved access token JWT lifetime has elapsed.'}
            if($claims.TenantFingerprint -ne $session.TenantFingerprint -or $claims.PrincipalFingerprint -ne $session.PrincipalFingerprint -or $claims.ClientId -ne $entry.ClientId -or $claims.Audience -cne $entry.Audience -or -not $claims.HasDelegatedScopeClaim -or @($entry.Scopes|Where-Object {$claims.Scopes -cnotcontains $_}).Count){throw 'Saved access token context or scope mismatch.'}
            $extra=@($claims.Scopes|Where-Object {$_ -cnotin @('openid','profile','email','offline_access') -and $entry.Scopes -cnotcontains $_})
            if($extra.Count -gt $MaxAdditionalScopes){throw 'Saved access token exceeds the additional-scope limit.'}
        }
        if($entry.RefreshToken){$refresh=ConvertTo-SecureString $entry.RefreshToken -AsPlainText -Force}
        $request=[pscustomobject]@{ClientId=$entry.ClientId;ResourceId=$entry.ResourceId;ResourceUri=$entry.ResourceId;Tenant=$entry.Tenant;Scopes=@($entry.Scopes);OAuthScopes=@($entry.Scopes|ForEach-Object {"$($entry.ResourceId)/$_"})+@(if($entry.OfflineAccess){'offline_access'});RedirectUri=$entry.RedirectUri;Spa=[bool]$entry.Spa;Protocol=$entry.Protocol}
        $returned=$true
        [pscustomobject]@{ClientId=$entry.ClientId;ResourceId=$entry.ResourceId;RequestedScopes=@($entry.Scopes);AccessToken=$access;RefreshToken=$refresh;Request=$request;Evidence='ExplicitSavedCredentialRetrievalNotNewIssuance';ExpectedTenantFingerprint=$session.TenantFingerprint;ExpectedPrincipalFingerprint=$session.PrincipalFingerprint}
    }finally{
        $document=$null
        if(-not $returned){if($access){$access.Dispose()};if($refresh){$refresh.Dispose()}}
    }
}
