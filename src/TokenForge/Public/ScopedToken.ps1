function Get-TokenForgeScopedToken {
    <#
    .SYNOPSIS
    Authenticate, select fresh observer-specific coverage, and request explicit scopes in one command.
    .DESCRIPTION
    Graph User.Read bootstraps API-confirmed observer context; its token is disposed before return.
    Candidates use fresh private observations, published redirects and explicit PKCE requests.
    The optional GET API result is separate from token success. Caller owns returned token secrets.
    #>
    [CmdletBinding(DefaultParameterSetName='Vault')]
    param(
        [Parameter(Mandatory)]$Inventory,
        [Parameter(Mandatory)]$Database,
        [Parameter(Mandatory)][guid]$ResourceId,
        [Parameter(Mandatory)][ValidateCount(1,64)][string[]]$Scope,
        [Parameter(Mandatory,ParameterSetName='Cookie')][securestring]$EstsAuth,
        [Parameter(ParameterSetName='Cookie')][ValidateSet('ESTSAUTH','ESTSAUTHPERSISTENT')][string]$CookieName='ESTSAUTH',
        [Parameter(Mandatory,ParameterSetName='Passkey')][string]$PasskeyPath,
        [Parameter(Mandatory,ParameterSetName='Passkey')][string]$XdrModulePath,
        [Parameter(Mandatory,ParameterSetName='Browser')][switch]$Browser,
        [Parameter(ParameterSetName='Browser')][string]$LoginHint,
        [Parameter(Mandatory,ParameterSetName='Vault')][Parameter(ParameterSetName='Cookie')][Parameter(ParameterSetName='Passkey')][Parameter(ParameterSetName='Browser')][string]$VaultPath,
        [Parameter(Mandatory,ParameterSetName='Vault')][Parameter(ParameterSetName='Cookie')][Parameter(ParameterSetName='Passkey')][Parameter(ParameterSetName='Browser')][securestring]$VaultPassword,
        [Parameter(Mandatory,ParameterSetName='Vault')][Parameter(ParameterSetName='Cookie')][Parameter(ParameterSetName='Passkey')][Parameter(ParameterSetName='Browser')][ValidatePattern('^[a-z][a-z0-9_-]{0,63}$')][string]$SessionName,
        [ValidateRange(1,168)][int]$SessionRetentionHours=8,
        [ValidateRange(30,900)][int]$TimeoutSeconds=300,
        [string]$Tenant='organizations',
        [guid]$BootstrapClientId='14d82eec-204b-4c2f-b7e8-296a70dab67e',
        [ValidateRange(0,2147483647)][int]$MaxBootstrapAdditionalScopes=2147483647,
        [ValidateRange(1,8760)][int]$MaxAgeHours=24,
        [ValidateRange(1,100)][int]$MaxCandidates=8,
        [ValidateRange(1,8)][int]$MaxRedirects=2,
        [ValidateRange(0,2147483647)][int]$MaxAdditionalScopes=2147483647,
        [switch]$OfflineAccess,
        [uri]$ApiUri
    )
    if(@($Scope|Where-Object {$_ -notmatch '^[A-Za-z0-9_-][A-Za-z0-9_.-]*$' -or $_ -cin @('openid','profile','email','offline_access')}).Count){throw 'Provide explicit API scope names.'}
    if(($VaultPath -or $VaultPassword -or $SessionName) -and (-not $VaultPath -or -not $VaultPassword -or -not $SessionName)){throw 'Vault persistence requires VaultPath, VaultPassword, and an explicit SessionName.'}
    $now=[DateTimeOffset]::UtcNow
    $captured=[DateTimeOffset]::Parse($Inventory.CapturedAt)
    if($captured -lt $now.AddHours(-$MaxAgeHours) -or $captured -gt $now.AddMinutes(5)){throw 'Inventory is stale or future-dated; refresh it before requesting tokens.'}
    if($ApiUri){
        $hostName=switch($ResourceId.ToString()){'00000003-0000-0000-c000-000000000000'{'graph.microsoft.com'} '797f4846-ba00-4fd7-ba43-dac1f8f63013'{'management.azure.com'} default {throw 'No API host mapping is defined for this resource.'}}
        if(-not $ApiUri.IsAbsoluteUri -or $ApiUri.Scheme -ne 'https' -or $ApiUri.Host -ne $hostName -or $ApiUri.Port -ne 443 -or $ApiUri.UserInfo -or $ApiUri.Fragment){throw 'API URI is outside the resource boundary.'}
    }
    $graphId='00000003-0000-0000-c000-000000000000'
    $bootstrapApp=@($Inventory.Applications|Where-Object {$_.AppId -eq $BootstrapClientId.ToString() -and $_.Registration -eq 'Present' -and $_.Ownership -eq 'VerifiedMicrosoftOwner' -and $_.AccountEnabled})
    $resource=@($Inventory.Applications|Where-Object {$_.AppId -eq $ResourceId.ToString() -and $_.Registration -eq 'Present' -and $_.Ownership -eq 'VerifiedMicrosoftOwner' -and $_.AccountEnabled})
    $graph=@($Inventory.Applications|Where-Object {$_.AppId -eq $graphId -and $_.Registration -eq 'Present' -and $_.Ownership -eq 'VerifiedMicrosoftOwner' -and $_.AccountEnabled})
    if($bootstrapApp.Count -ne 1 -or $resource.Count -ne 1 -or $graph.Count -ne 1){throw 'Enabled, ownership-verified bootstrap client, Graph, and resource records are required.'}
    $bootstrapRedirect=@($bootstrapApp[0].RedirectUris|Where-Object {
        $u=$null
        [uri]::TryCreate($_,[UriKind]::Absolute,[ref]$u) -and -not $u.UserInfo -and -not $u.Query -and -not $u.Fragment -and
        $(if($Browser){$u.Scheme -eq 'http' -and $u.Host -eq 'localhost' -and $u.AbsolutePath -eq '/'}else{$u.Scheme -eq 'https' -and $u.AbsolutePath -match '/nativeclient$'})
    }|Select-Object -First 1)
    if(-not $bootstrapRedirect.Count){throw 'Bootstrap client has no supported published redirect for this authentication method.'}
    $ownedCookie=$null;$bootstrap=$null;$selected=$null;$returned=$false;$vaultContext=$null
    $attempts=[Collections.Generic.List[object]]::new()
    try{
        if($VaultPath){
            $vault=Invoke-TokenForgeVaultTransaction -Path $VaultPath -Password $VaultPassword
            $saved=$vault.Sessions[$SessionName]
            if($saved){$vaultContext=@{TenantFingerprint=$saved.TenantFingerprint;PrincipalFingerprint=$saved.PrincipalFingerprint;Revision=$saved.Revision}}
            if($PSCmdlet.ParameterSetName -eq 'Vault'){
                if(-not $saved -or -not $saved.Cookie -or [DateTimeOffset]::Parse($saved.RetainUntil) -le [DateTimeOffset]::UtcNow){throw 'Selected vault session has no reusable cookie or its local retention deadline passed; authenticate explicitly.'}
                if($saved.CookieName -notin @('ESTSAUTH','ESTSAUTHPERSISTENT')){throw 'Unsupported saved session cookie name.'}
                $ownedCookie=ConvertTo-SecureString $saved.Cookie -AsPlainText -Force;$EstsAuth=$ownedCookie;$CookieName=$saved.CookieName
            }
            $saved=$null;$vault=$null
        }
        if($PSCmdlet.ParameterSetName -eq 'Passkey'){$ownedCookie=Get-TokenForgeEstsCookie -PasskeyPath $PasskeyPath -XdrModulePath $XdrModulePath;$EstsAuth=$ownedCookie}
        $authentication=if($Browser){@{Browser=$true;LoginHint=$LoginHint;TimeoutSeconds=$TimeoutSeconds;NoConsent=$true}}else{@{EstsAuth=$EstsAuth;CookieName=$CookieName}}
        $request=New-TokenForgeTenantRequest -Inventory $Inventory -ClientId $BootstrapClientId -ResourceId $graphId -Scope User.Read -RedirectUri $bootstrapRedirect[0] -Tenant $Tenant
        try{$bootstrap=Get-TokenForgeToken -Request $request @authentication}catch{
            $codes=@([regex]::Matches($_.Exception.Message,'\bAADSTS[0-9]{4,9}\b')|ForEach-Object Value|Sort-Object -Unique)
            throw "Observer bootstrap failed; details suppressed. $($codes -join ',')"
        }
        $claims=$bootstrap.TokenClaims
        $payload=ConvertFrom-TokenForgeJwtPayload -AccessToken $bootstrap.AccessToken
        $tid=[guid]::Empty;$oid=[guid]::Empty
        if(-not $payload -or -not [guid]::TryParse([string]$payload['tid'],[ref]$tid) -or -not [guid]::TryParse([string]$payload['oid'],[ref]$oid) -or
           $claims.TenantFingerprint -ne $Inventory.TenantFingerprint -or -not $claims.PrincipalFingerprint -or
           $claims.ClientId -ne $BootstrapClientId.ToString() -or $claims.Audience -notin @($graphId,'https://graph.microsoft.com','https://graph.microsoft.com/')){throw 'Observer bootstrap context does not match the verified inventory/client/resource.'}
        if(-not $claims.HasDelegatedScopeClaim -or $claims.Scopes -cnotcontains 'User.Read'){throw 'Observer bootstrap requires a readable delegated User.Read scope.'}
        $bootstrapExtras=@($claims.Scopes|Where-Object {$_ -cnotin @('User.Read','openid','profile','email','offline_access')})
        if($bootstrapExtras.Count -gt $MaxBootstrapAdditionalScopes -or @($bootstrap.AdditionalScopes).Count -gt $MaxBootstrapAdditionalScopes){throw 'Observer bootstrap exceeds the additional-scope limit; choose a narrower BootstrapClientId.'}
        $me=Invoke-TokenForgeGraph -AccessToken $bootstrap.AccessToken -Uri 'https://graph.microsoft.com/v1.0/me?$select=id'
        if([string]$me['id'] -ine $oid.ToString()){throw 'Graph identity does not match the bootstrap token context.'}
        if($vaultContext -and ($vaultContext.TenantFingerprint -ne $claims.TenantFingerprint -or $vaultContext.PrincipalFingerprint -ne $claims.PrincipalFingerprint)){throw 'Confirmed observer does not match the selected vault session.'}
        $principal=$claims.PrincipalFingerprint;$tenantFingerprint=$claims.TenantFingerprint
        $bootstrap.AccessToken.Dispose();if($bootstrap.RefreshToken){$bootstrap.RefreshToken.Dispose()};$bootstrap=$null;$payload=$null;$me=$null
        $candidates=@(Get-TokenForgeAssessmentCoverage -Database $Database -ResourceId $ResourceId -Scope $Scope -TenantFingerprint $tenantFingerprint -PrincipalFingerprint $principal -MaxAgeHours $MaxAgeHours|Where-Object CoversAll)
        if(-not $candidates.Count){throw 'No fresh coverage for the authenticated observer; run scope discovery for this account.'}
        $candidateCount=0
        foreach($candidate in $candidates){
            if($candidateCount -ge $MaxCandidates){break}
            $app=@($Inventory.Applications|Where-Object {$_.AppId -eq $candidate.ClientId -and $_.Registration -eq 'Present' -and $_.Ownership -eq 'VerifiedMicrosoftOwner' -and $_.AccountEnabled})
            if($app.Count -ne 1){continue}
            $redirects=@($app[0].RedirectUris|Where-Object {
                $u=$null
                [uri]::TryCreate($_,[UriKind]::Absolute,[ref]$u) -and -not $u.UserInfo -and -not $u.Query -and -not $u.Fragment -and
                $(if($Browser){$u.Scheme -eq 'http' -and $u.Host -eq 'localhost' -and $u.AbsolutePath -eq '/'}else{($u.Scheme -eq 'https') -or ($u.Scheme -eq 'http' -and $u.Host -eq 'localhost') -or ($u.Scheme -eq 'urn')})
            }|Sort-Object @{Expression={if($candidate.RedirectFingerprint -and (Get-TokenForgeFingerprint -Value $_) -eq $candidate.RedirectFingerprint){0}else{1}}},@{Expression={$_}}|Select-Object -First $MaxRedirects)
            if(-not $redirects.Count){continue}
            $candidateCount++
            foreach($redirect in $redirects){
                try{
                    $spa= -not $Browser -and [bool]$candidate.Spa -and ([uri]$redirect).Scheme -eq 'https'
                    $request=New-TokenForgeTenantRequest -Inventory $Inventory -Database $Database -PrincipalFingerprint $principal -ClientId $candidate.ClientId -ResourceId $ResourceId -Scope $Scope -RedirectUri $redirect -Tenant $tid.ToString() -Spa:$spa -OfflineAccess:$OfflineAccess -MaxAgeHours $MaxAgeHours
                    $selected=Get-TokenForgeToken -Request $request @authentication
                    $actual=$selected.TokenClaims
                    $audiences=@($ResourceId.ToString())+@($resource[0].IdentifierUris)
                    if($ResourceId.ToString() -eq $graphId){$audiences+=@('https://graph.microsoft.com')}
                    if($ResourceId.ToString() -eq '797f4846-ba00-4fd7-ba43-dac1f8f63013'){$audiences+=@('https://management.azure.com','https://management.core.windows.net')}
                    if($actual.TenantFingerprint -ne $tenantFingerprint -or $actual.PrincipalFingerprint -ne $principal -or $actual.ClientId -ne $candidate.ClientId -or -not $actual.Audience -or $actual.Audience.TrimEnd('/') -notin @($audiences|ForEach-Object {([string]$_).TrimEnd('/')}) -or
                       -not $actual.HasDelegatedScopeClaim -or @($Scope|Where-Object {$actual.Scopes -cnotcontains $_}).Count){throw 'Issued token context or scope mismatch.'}
                    $extra=@($actual.Scopes|Where-Object {$_ -cnotin @('openid','profile','email','offline_access') -and $Scope -cnotcontains $_})
                    if($extra.Count -gt $MaxAdditionalScopes -or @($selected.AdditionalScopes).Count -gt $MaxAdditionalScopes){throw 'Issued token exceeds the additional-scope limit.'}
                    $selected|Add-Member Request $request
                    $selected|Add-Member SelectionEvidence 'FreshObserverScopeCoverageWithMatchedIssuedContext'
                    $selected|Add-Member ConsentEvidence 'SilentAuthorizationSucceededForThisRequest'
                    $selected|Add-Member BootstrapEvidence ([pscustomobject]@{ClientId=$BootstrapClientId.ToString();AdditionalScopeCount=$bootstrapExtras.Count;IdentityConfirmedByGraph=$true})
                    $selected|Add-Member ObservedAdditionalScopeCount $extra.Count
                    $selected|Add-Member AttemptSummary @($attempts.ToArray())
                    $selected|Add-Member ApiCheck $(if($ApiUri){try{Test-TokenForgeTokenAccess -Token $selected -Uri $ApiUri}catch{[pscustomobject]@{Status=$null;Accepted=$false;Evidence='TransportFailureDetailsSuppressed'}}}else{$null})
                    if($VaultPath){
                        try{
                            $tokenId=Save-TokenForgeScopedCredential -Path $VaultPath -Password $VaultPassword -SessionName $SessionName -Cookie $(if($Browser){$null}else{$EstsAuth}) -CookieName $CookieName -Token $selected -RetentionHours $SessionRetentionHours -ExpectedRevision $(if($vaultContext){$vaultContext.Revision}else{$null}) -ReuseSession:($PSCmdlet.ParameterSetName -eq 'Vault')
                            $selected|Add-Member VaultTokenId $tokenId
                        }catch{
                            $failure=[InvalidOperationException]::new('Token was acquired but vault persistence failed; token discarded. Details suppressed.')
                            $failure.Data['TokenForgeVaultPersistence']=$true;throw $failure
                        }
                    }
                    $returned=$true
                    return $selected
                }catch{
                    if($_.Exception.Data['TokenForgeVaultPersistence']){throw}
                    $attempts.Add([pscustomobject]@{ClientId=$candidate.ClientId;Outcome='RequestRejectedOrContextMismatch';EntraCodes=@([regex]::Matches($_.Exception.Message,'\bAADSTS[0-9]{4,9}\b')|ForEach-Object Value|Sort-Object -Unique)})
                    if($selected){$selected.AccessToken.Dispose();if($selected.RefreshToken){$selected.RefreshToken.Dispose()};$selected=$null}
                }
            }
        }
        $failure=[InvalidOperationException]::new('No candidate completed an explicit scoped request with matching issued context; no token returned.')
        $failure.Data['TokenForgeAttempts']=$attempts.ToArray()
        throw $failure
    }finally{
        $saved=$null;$vault=$null;$vaultContext=$null
        if($ownedCookie){$ownedCookie.Dispose()}
        if($bootstrap){$bootstrap.AccessToken.Dispose();if($bootstrap.RefreshToken){$bootstrap.RefreshToken.Dispose()}}
        if($selected -and -not $returned){$selected.AccessToken.Dispose();if($selected.RefreshToken){$selected.RefreshToken.Dispose()}}
    }
}
