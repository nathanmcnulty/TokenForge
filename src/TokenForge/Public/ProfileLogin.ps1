function Connect-TokenForgeProfile {
    <# .SYNOPSIS
    Confirm the profile's account through Graph and create a memory or explicit encrypted session.
    .DESCRIPTION
    Login needs verified inventory but does not need prior target-scope observations. Browser login
    is silent by default; Interactive permits user-directed browser sign-in, not automatic consent approval.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][ValidatePattern('^[a-z][a-z0-9_-]{0,63}$')][string]$Name,
        [string]$Root,[securestring]$VaultPassword,[securestring]$EstsAuth,
        [ValidateSet('ESTSAUTH','ESTSAUTHPERSISTENT')][string]$CookieName='ESTSAUTH',
        [switch]$Browser,[switch]$Interactive,[string]$LoginHint,
        [ValidateRange(30,900)][int]$TimeoutSeconds=300
    )
    $record=Read-TokenForgeProfile $Name $Root;$p=$record.Configuration
    if($Browser -and $EstsAuth){throw 'Choose browser or ESTS authentication.'}
    if($Interactive -and -not $Browser){throw 'Interactive sign-in requires Browser.'}
    if($p.Storage -eq 'Passphrase' -and -not $VaultPassword){throw 'Provide a vault passphrase for the persisted profile.'}
    $lock=Open-TokenForgeProfileOperation $record.Directory
    $cookie=$null;$token=$null;$passwordCopy=$null
    try{
        $initialSessionRevision=$null
        if($p.Storage -eq 'Passphrase' -and (Test-Path $record.VaultPath)){
            $initialVault=Invoke-TokenForgeVaultTransaction $record.VaultPath $VaultPassword
            $initialSession=$initialVault.Sessions[$Name]
            if($initialSession){$initialSessionRevision=$initialSession.Revision}
            $initialSession=$null;$initialVault=$null
        }
        $inventoryPath=Resolve-TokenForgeVaultPath (Join-Path $p.StatePath 'inventory.json')
        $inventory=Get-Content -LiteralPath $inventoryPath -Raw|ConvertFrom-Json
        if(([DateTimeOffset]$inventory.CapturedAt) -lt [DateTimeOffset]::UtcNow.AddHours(-$p.MaxAgeHours) -or ([DateTimeOffset]$inventory.CapturedAt) -gt [DateTimeOffset]::UtcNow.AddMinutes(5)){throw 'Inventory is stale; refresh the profile inventory before login.'}
        $client=@($inventory.Applications|Where-Object {$_.AppId -eq $p.BootstrapClientId -and $_.Registration -eq 'Present' -and $_.Ownership -eq 'VerifiedMicrosoftOwner' -and $_.AccountEnabled})
        if($client.Count -ne 1){throw 'The profile bootstrap client is not enabled and ownership-verified in this tenant.'}
        $graph=@($inventory.Applications|Where-Object {$_.AppId -eq '00000003-0000-0000-c000-000000000000' -and $_.Registration -eq 'Present' -and $_.Ownership -eq 'VerifiedMicrosoftOwner' -and $_.AccountEnabled})
        if($graph.Count -ne 1){throw 'Enabled, ownership-verified Graph resource required.'}
        $useBrowser=$Browser -or (-not $EstsAuth -and -not $p.PasskeyPath)
        $redirect=@($client[0].RedirectUris|Where-Object {
            $uri=$null
            [uri]::TryCreate($_,[UriKind]::Absolute,[ref]$uri) -and -not $uri.Query -and -not $uri.Fragment -and -not $uri.UserInfo -and
            $(if($useBrowser){$uri.Scheme -eq 'http' -and $uri.Host -eq 'localhost' -and $uri.AbsolutePath -eq '/'}else{$_ -ceq 'https://login.microsoftonline.com/common/oauth2/nativeclient'})
        }|Select-Object -First 1)
        if(-not $redirect.Count){throw 'The bootstrap client has no supported callback for this login method; configure a suitable verified client.'}
        if($EstsAuth){$cookie=$EstsAuth.Copy()}
        elseif(-not $useBrowser){$cookie=Get-TokenForgeEstsCookie -PasskeyPath $p.PasskeyPath -XdrModulePath $p.XdrModulePath}
        $request=New-TokenForgeTenantRequest -Inventory $inventory -ClientId $p.BootstrapClientId -ResourceId 00000003-0000-0000-c000-000000000000 -Scope User.Read -RedirectUri $redirect[0] -Tenant $p.Tenant -OfflineAccess
        $auth=if($useBrowser){@{Browser=$true;NoConsent=(-not $Interactive);LoginHint=$LoginHint;TimeoutSeconds=$TimeoutSeconds}}else{@{EstsAuth=$cookie;CookieName=$CookieName}}
        $token=Get-TokenForgeToken -Request $request @auth
        $claims=$token.TokenClaims;$payload=ConvertFrom-TokenForgeJwtPayload $token.AccessToken
        if($claims.TenantFingerprint -ne $inventory.TenantFingerprint -or -not $claims.PrincipalFingerprint -or $claims.ClientId -ne $p.BootstrapClientId -or
           $claims.Audience -notin @($request.ResourceId,'https://graph.microsoft.com','https://graph.microsoft.com/') -or -not $claims.HasDelegatedScopeClaim -or $claims.Scopes -cnotcontains 'User.Read'){throw 'Login token context does not match the verified tenant/client/resource.'}
        if(($p.ExpectedTenantFingerprint -and $p.ExpectedTenantFingerprint -ne $claims.TenantFingerprint) -or ($p.ExpectedPrincipalFingerprint -and $p.ExpectedPrincipalFingerprint -ne $claims.PrincipalFingerprint)){throw 'This profile is bound to another account or tenant; use a separate profile.'}
        if(-not $claims.ExpiresAt -or $claims.ExpiresAt -le [DateTimeOffset]::UtcNow.AddMinutes(2) -or -not $token.ExpiresAt -or $token.ExpiresAt -le [DateTimeOffset]::UtcNow.AddMinutes(2)){throw 'Login token has unknown or insufficient remaining lifetime.'}
        $tid=[guid]::Empty;$oid=[guid]::Empty
        if(-not [guid]::TryParse([string]$payload['tid'],[ref]$tid) -or -not [guid]::TryParse([string]$payload['oid'],[ref]$oid)){throw 'Login requires readable tenant and account IDs.'}
        $extra=@($claims.Scopes|Where-Object {$_ -cnotin @('User.Read','openid','profile','email','offline_access')})
        if($extra.Count -gt $p.MaxBootstrapAdditionalScopes -or @($token.AdditionalScopes).Count -gt $p.MaxBootstrapAdditionalScopes){throw 'Login token exceeds the bootstrap scope policy; choose a narrower bootstrap client or explicitly create a broader policy profile.'}
        $me=Invoke-TokenForgeGraph -AccessToken $token.AccessToken -Uri 'https://graph.microsoft.com/v1.0/me?$select=id'
        if(-not $payload['oid'] -or [string]$me['id'] -ine [string]$payload['oid']){throw 'Graph identity does not match the login token.'}
        $current=Read-TokenForgeProfile $Name $Root
        if((Get-TokenForgeFingerprint (ConvertTo-Json $current.Configuration -Depth 4 -Compress)) -ne (Get-TokenForgeFingerprint (ConvertTo-Json $p -Depth 4 -Compress))){throw 'Profile changed during login; retry with its current configuration.'}
        $p.Tenant=$tid.ToString();$p.ExpectedTenantFingerprint=$claims.TenantFingerprint;$p.ExpectedPrincipalFingerprint=$claims.PrincipalFingerprint
        $p.Revision=[guid]::NewGuid().ToString();$p.UpdatedAt=[DateTimeOffset]::UtcNow.ToString('o')
        $now=[DateTimeOffset]::UtcNow
        $token|Add-Member Request $request -Force
        $token|Add-Member ConsentEvidence 'ProfileLoginGraphIdentityConfirmed' -Force
        $token|Add-Member ObservedAdditionalScopeCount $extra.Count -Force
        $session=@{TenantFingerprint=$claims.TenantFingerprint;PrincipalFingerprint=$claims.PrincipalFingerprint;RetainUntil=$now.AddHours($p.SessionRetentionHours).ToString('o');LastConfirmedAt=$now.ToString('o');Tokens=@{};Revision=[guid]::NewGuid().ToString()}
        if($p.Storage -eq 'Passphrase'){
            if(-not (Test-Path $record.VaultPath)){$null=New-TokenForgeVault $record.VaultPath $VaultPassword}
            # Explicit login renews local retention. Existing different identities still cannot replace this name.
            Invoke-TokenForgeVaultTransaction $record.VaultPath $VaultPassword -Mode Update -Update {
                param($vault)
                $old=$vault.Sessions[$Name]
                if(($initialSessionRevision -and (-not $old -or $old.Revision -ne $initialSessionRevision)) -or (-not $initialSessionRevision -and $old)){throw 'Session changed during login.'}
                if($old -and ($old.TenantFingerprint -ne $claims.TenantFingerprint -or $old.PrincipalFingerprint -ne $claims.PrincipalFingerprint)){throw 'Existing vault identity mismatch.'}
                $session.CreatedAt=if($old){$old.CreatedAt}else{$now.ToString('o')}
                $session.Cookie=if($cookie){[Net.NetworkCredential]::new('', $cookie).Password}else{$null}
                $session.CookieName=$CookieName
                # A deliberate new login must not keep an expired/revoked refresh record that would block recovery.
                $session.Tokens=@{}
                $vault.Sessions[$Name]=$session
            }
            $passwordCopy=$VaultPassword.Copy()
        }
        Save-TokenForgeDocument -Document $p -Path $record.Path
        Clear-TokenForgeProfileContext $record.ContextKey
        $script:ProfileContexts[$record.ContextKey]=@{Cookie=$cookie;Password=$passwordCopy;Session=@{TenantFingerprint=$session.TenantFingerprint;PrincipalFingerprint=$session.PrincipalFingerprint;RetainUntil=$session.RetainUntil;LastConfirmedAt=$session.LastConfirmedAt;Revision=$session.Revision;Tokens=@{}};Tokens=@{};CookieName=$CookieName;Revision=$p.Revision;Browser=$useBrowser}
        $cookie=$null;$passwordCopy=$null
        [pscustomobject]@{Profile=$Name;Tenant=$p.Tenant;Storage=$p.Storage;SessionState='Available';RetainUntil=$session.RetainUntil;
            BootstrapClientId=$p.BootstrapClientId;BootstrapAdditionalScopeCount=$extra.Count;Evidence='ProfileLoginGraphIdentityConfirmed'}
    }finally{
        if($token){$token.AccessToken.Dispose();if($token.RefreshToken){$token.RefreshToken.Dispose()}}
        if($cookie){$cookie.Dispose()};if($passwordCopy){$passwordCopy.Dispose()};$payload=$null;$me=$null;$session=$null;$lock.Dispose()
    }
}
