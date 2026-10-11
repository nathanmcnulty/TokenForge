function Get-TokenForgeProfileToken {
    <# .SYNOPSIS
    Request explicit scopes through a named profile, reusing or renewing only matching credentials.
    .DESCRIPTION
    Caller owns returned SecureStrings. Cache hits are not new issuance. Refresh is bound to the
    saved client and request. Local retention is never extended by token acquisition or renewal.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][ValidatePattern('^[a-z][a-z0-9_-]{0,63}$')][string]$Name,
        [string]$Root,[securestring]$VaultPassword,[ValidateLength(0,320)][string]$LoginHint,
        [ValidateSet('graph','arm')][string]$Resource='graph',
        [guid]$ResourceId,
        [Parameter(Mandatory)][ValidateCount(1,64)][string[]]$Scope,
        [uri]$ApiUri,
        [ValidateRange(1,100)][int]$MaxCandidates=8,
        [ValidateRange(1,8)][int]$MaxRedirects=2
    )
    if(@($Scope|Where-Object {$_ -notmatch '^[A-Za-z0-9_-][A-Za-z0-9_.-]*$' -or $_ -cin @('openid','profile','email','offline_access')}).Count){throw 'Provide explicit API scope names.'}
    $Scope=@($Scope|Sort-Object -Unique)
    if(-not $PSBoundParameters.ContainsKey('ResourceId')){$ResourceId=if($Resource -eq 'graph'){'00000003-0000-0000-c000-000000000000'}else{'797f4846-ba00-4fd7-ba43-dac1f8f63013'}}
    if($ApiUri){
        $hostName=switch($ResourceId.ToString()){'00000003-0000-0000-c000-000000000000'{'graph.microsoft.com'} '797f4846-ba00-4fd7-ba43-dac1f8f63013'{'management.azure.com'} default {throw 'No API host mapping is defined for this resource.'}}
        if(-not $ApiUri.IsAbsoluteUri -or $ApiUri.Scheme -ne 'https' -or $ApiUri.Host -ne $hostName -or $ApiUri.Port -ne 443 -or $ApiUri.UserInfo -or $ApiUri.Fragment){throw 'API URI is outside the resource boundary.'}
    }
    $record=Read-TokenForgeProfile $Name $Root;$p=$record.Configuration
    if(-not $p.ExpectedTenantFingerprint -or -not $p.ExpectedPrincipalFingerprint){throw 'Log in to bind the profile account before requesting tokens.'}
    if($p.Storage -ne 'Memory'){
        if($p.Storage -eq 'OperatingSystem' -and $VaultPassword){throw 'OS-backed profiles do not accept a vault passphrase.'}
        $context=$script:ProfileContexts[$record.ContextKey]
        $password=if($VaultPassword){$VaultPassword}elseif($context){$context.Password}else{$null}
        $token=$null;$returned=$false
        try{
            $token=Get-TokenForgePersistedProfileToken -Record $record -Name $Name -Root $Root -Password $password -LoginHint $LoginHint -ResourceId $ResourceId -Scope $Scope -MaxCandidates $MaxCandidates -MaxRedirects $MaxRedirects
            $token|Add-Member ApiCheck $(if($ApiUri){try{Test-TokenForgeTokenAccess -Token $token -Uri $ApiUri}catch{[pscustomobject]@{Status=$null;Accepted=$false;Evidence='TransportFailureDetailsSuppressed'}}}else{$null}) -Force
            $returned=$true;return $token
        }finally{if($token -and -not $returned){$token.AccessToken.Dispose();if($token.RefreshToken){$token.RefreshToken.Dispose()}}}
    }
    $lock=Open-TokenForgeProfileOperation $record.Directory
    $token=$null;$savedToken=$null;$ownedCookie=$null;$returned=$false;$session=$null
    try{
        $context=$script:ProfileContexts[$record.ContextKey]
        $key=Get-TokenForgeFingerprint -Value ($ResourceId.ToString()+'|'+($Scope -join ' '))
        if($context -and $context.Revision -eq $p.Revision){
            $session=$context.Session
            if($context.Tokens[$key]){$savedToken=Copy-TokenForgeCredentialResult $context.Tokens[$key] 'InternalCredentialCopy'}
            if($context.Cookie){$ownedCookie=$context.Cookie.Copy()}
        }
        if(-not $session -or ([DateTimeOffset]$session.RetainUntil) -le [DateTimeOffset]::UtcNow){throw 'Profile session is missing or retention expired; log in explicitly.'}
        if($session.TenantFingerprint -ne $p.ExpectedTenantFingerprint -or $session.PrincipalFingerprint -ne $p.ExpectedPrincipalFingerprint){throw 'Saved session does not match the profile identity.'}
        $sessionRevision=$session.Revision;$cookieName=if($session.Contains('CookieName')){$session.CookieName}elseif($context){$context.CookieName}else{'ESTSAUTH'}
        if($savedToken){
            $r=$savedToken.Request
            if($r.Tenant -cne $p.Tenant -or $r.ResourceId -ne $ResourceId.ToString() -or $r.Protocol -ne 'OAuth2V2Pkce' -or (@($r.Scopes|Sort-Object -Unique) -join ' ') -cne ($Scope -join ' ') -or @($r.OAuthScopes|Where-Object {$_ -ceq '.default' -or $_ -clike '*/.default'}).Count){throw 'Saved request does not match the canonical profile authority, resource, explicit scopes, or protocol.'}
            # Invalid cached context must fail closed, rather than allowing its refresh credential to be redeemed.
            $claims=Get-TokenForgeTokenClaims $savedToken.AccessToken
            if($claims.TenantFingerprint -ne $p.ExpectedTenantFingerprint -or $claims.PrincipalFingerprint -ne $p.ExpectedPrincipalFingerprint -or $claims.ClientId -ne $savedToken.Request.ClientId -or -not $claims.HasDelegatedScopeClaim){throw 'Saved token identity or client context is invalid.'}
            $null=Assert-TokenForgeProfileToken $savedToken $p $Scope $savedToken.Request.ClientId $ResourceId.ToString() $p.MaxAdditionalScopes -AllowExpired
            $isFresh=$savedToken.ExpiresAt -and ([DateTimeOffset]$savedToken.ExpiresAt) -gt [DateTimeOffset]::UtcNow.AddMinutes(2) -and $claims.ExpiresAt -and $claims.ExpiresAt -gt [DateTimeOffset]::UtcNow.AddMinutes(2)
            if($isFresh){
                $null=Assert-TokenForgeProfileToken $savedToken $p $Scope $savedToken.Request.ClientId $ResourceId.ToString() $p.MaxAdditionalScopes
                $token=Copy-TokenForgeCredentialResult $savedToken 'CachedVerifiedContextNotNewIssuance'
            }elseif($savedToken.RefreshToken){
                try{$token=Get-TokenForgeToken -Request $savedToken.Request -RefreshToken $savedToken.RefreshToken}catch{throw 'Same-client renewal failed; log in explicitly. No alternate-client or consent fallback was attempted.'}
                $token|Add-Member Request $savedToken.Request -Force
                $token|Add-Member Evidence 'SameClientRefreshMatchedIssuedContext' -Force
                # Some providers omit a replacement refresh token. Preserve only this same-client record.
                if(-not $token.RefreshToken){$token.RefreshToken=$savedToken.RefreshToken.Copy()}
            }
        }
        if(-not $token){
            $auth=if($ownedCookie){@{EstsAuth=$ownedCookie;CookieName=$cookieName}}else{@{Browser=$true;NoConsent=$true;LoginHint=$LoginHint}}
            $token=Request-TokenForgeProfileScope -Profile $p -ResourceId $ResourceId -Scope $Scope -Authentication $auth -MaxCandidates $MaxCandidates -MaxRedirects $MaxRedirects
        }
        $token.Request|Add-Member Protocol $token.Protocol -Force
        $claims=Assert-TokenForgeProfileToken $token $p $Scope $token.Request.ClientId $ResourceId.ToString() $p.MaxAdditionalScopes
        $token|Add-Member TokenClaims $claims -Force
        $current=Read-TokenForgeProfile $Name $Root
        if((ConvertTo-Json $current.Configuration -Depth 4 -Compress) -cne (ConvertTo-Json $p -Depth 4 -Compress)){throw 'Profile changed during token acquisition; result discarded.'}
        if($token.Evidence -ne 'CachedVerifiedContextNotNewIssuance'){
            if(-not [object]::ReferenceEquals($script:ProfileContexts[$record.ContextKey],$context) -or ([DateTimeOffset]$context.Session.RetainUntil) -le [DateTimeOffset]::UtcNow -or $context.Revision -ne $p.Revision -or $context.Session.Revision -ne $sessionRevision){throw 'Session changed during token acquisition.'}
            if($context.Tokens[$key]){foreach($secret in @($context.Tokens[$key].AccessToken,$context.Tokens[$key].RefreshToken)){if($secret){$secret.Dispose()}}}
            $context.Tokens[$key]=Copy-TokenForgeCredentialResult $token $token.Evidence
            $context.Session.Revision=[guid]::NewGuid().ToString()
        }
        $token|Add-Member ApiCheck $(if($ApiUri){try{Test-TokenForgeTokenAccess -Token $token -Uri $ApiUri}catch{[pscustomobject]@{Status=$null;Accepted=$false;Evidence='TransportFailureDetailsSuppressed'}}}else{$null}) -Force
        $returned=$true
        $token
    }finally{
        if($savedToken){foreach($secret in @($savedToken.AccessToken,$savedToken.RefreshToken)){if($secret){$secret.Dispose()}}}
        if($token -and -not $returned){foreach($secret in @($token.AccessToken,$token.RefreshToken)){if($secret){$secret.Dispose()}}}
        if($ownedCookie){$ownedCookie.Dispose()}
        $session=$null;$lock.Dispose()
    }
}
