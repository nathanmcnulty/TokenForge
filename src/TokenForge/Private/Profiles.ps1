# Profiles contain configuration only. Credentials live in a process context or an explicit vault.
$script:ProfileContexts=@{}
function Resolve-TokenForgeProfileRoot {
    param([string]$Root)
    if(-not $Root){$Root=Join-Path ([Environment]::GetFolderPath('LocalApplicationData')) 'TokenForge/profiles'}
    $marker=Resolve-TokenForgeVaultPath -Path (Join-Path $Root '.profiles') -CreateDirectory
    Split-Path $marker -Parent
}
function Open-TokenForgeProfileOperation {
    param([string]$Directory,[ValidateSet('.operation.lock','.writer.lock')][string]$Leaf='.operation.lock')
    $path=Resolve-TokenForgeVaultPath -Path (Join-Path $Directory $Leaf)
    if(-not (Test-Path -LiteralPath $path)){
        try{return Open-TokenForgeVaultFile -Path $path -Create}catch [IO.IOException]{}
    }
    try{Open-TokenForgeVaultFile -Path $path}catch{throw 'Profile is in use by another operation; retry after it completes.'}
}
function Read-TokenForgeProfile {
    param([string]$Name,[string]$Root)
    $rootPath=Resolve-TokenForgeProfileRoot $Root
    $path=Resolve-TokenForgeVaultPath -Path (Join-Path $rootPath "$Name/profile.json")
    try{
        if((Get-Item -LiteralPath $path).Length -gt 32768){throw 'Oversized profile.'}
        $p=Get-Content -LiteralPath $path -Raw|ConvertFrom-Json -AsHashtable -Depth 4
        $keys=@('Format','SchemaVersion','Name','Tenant','StatePath','Storage','BootstrapClientId','MaxAdditionalScopes','MaxBootstrapAdditionalScopes','MaxAgeHours','SessionRetentionHours','PasskeyPath','XdrModulePath','ExpectedTenantFingerprint','ExpectedPrincipalFingerprint','Revision','CreatedAt','UpdatedAt')
        if($p.Keys.Count -ne $keys.Count -or @($p.Keys|Where-Object {$_ -cnotin $keys}).Count -or $p.Format -cne 'TokenForgeProfile' -or $p.SchemaVersion -ne 1 -or $p.Name -cne $Name){throw 'Invalid profile schema.'}
        if($p.Tenant -isnot [string] -or $p.Tenant -notmatch '^[a-zA-Z0-9][a-zA-Z0-9.-]{0,252}$' -or $p.Tenant -in @('common','organizations','consumers') -or $p.Storage -cnotin @('Memory','Passphrase')){throw 'Invalid profile policy.'}
        foreach($key in @('StatePath','PasskeyPath','XdrModulePath')){if($p[$key] -isnot [string] -or $p[$key].Length -gt 4096){throw 'Invalid profile paths.'}}
        $id=[guid]::Empty
        foreach($key in @('BootstrapClientId','Revision')){if(-not [guid]::TryParse([string]$p[$key],[ref]$id) -or $id -eq [guid]::Empty){throw 'Invalid profile ID.'}}
        foreach($key in @('ExpectedTenantFingerprint','ExpectedPrincipalFingerprint')){if($null -ne $p[$key] -and ($p[$key] -isnot [string] -or $p[$key] -cnotmatch '^[a-f0-9]{64}$')){throw 'Invalid profile namespace.'}}
        foreach($key in @('MaxAdditionalScopes','MaxBootstrapAdditionalScopes','MaxAgeHours','SessionRetentionHours')){if($p[$key] -isnot [long] -and $p[$key] -isnot [int] -or $p[$key] -lt 0 -or $p[$key] -gt 8760){throw 'Invalid profile limit.'}}
        if($p.MaxAgeHours -lt 1 -or $p.SessionRetentionHours -lt 1 -or $p.SessionRetentionHours -gt 168){throw 'Invalid profile lifetime.'}
        foreach($key in @('CreatedAt','UpdatedAt')){if($p[$key] -is [datetime]){$p[$key]=$p[$key].ToUniversalTime().ToString('o')};$date=[DateTimeOffset]::MinValue;if($p[$key] -isnot [string] -or -not [DateTimeOffset]::TryParse($p[$key],[ref]$date)){throw 'Invalid profile timestamp.'}}
        if([bool]$p.PasskeyPath -ne [bool]$p.XdrModulePath){throw 'Incomplete passkey configuration.'}
        [pscustomobject]@{Configuration=$p;Path=$path;Directory=(Split-Path $path -Parent);VaultPath=(Join-Path (Split-Path $path -Parent) 'session.tfvault');ContextKey=$path}
    }catch{throw 'Profile cannot be read; check its name, private path, format, and policy. Details suppressed.'}
}
function Clear-TokenForgeProfileContext {
    param([string]$Key)
    $context=$script:ProfileContexts[$Key]
    if($context){
        foreach($secret in @($context.Cookie,$context.Password)){if($secret){$secret.Dispose()}}
        foreach($token in $context.Tokens.Values){foreach($secret in @($token.AccessToken,$token.RefreshToken)){if($secret){$secret.Dispose()}}}
        $null=$script:ProfileContexts.Remove($Key)
    }
}
function Copy-TokenForgeCredentialResult {
    param($Token,[string]$Evidence)
    # Never give callers the cache's owned SecureString instances.
    $copy=[ordered]@{}
    foreach($property in $Token.PSObject.Properties){if($property.Name -notin @('AccessToken','RefreshToken','Evidence')){$copy[$property.Name]=if($null -eq $property.Value){$null}else{ConvertFrom-Json -InputObject (ConvertTo-Json -InputObject $property.Value -Depth 15 -Compress) -Depth 15 -NoEnumerate}}}
    $copy.AccessToken=if($Token.AccessToken){$Token.AccessToken.Copy()}else{$null}
    $copy.RefreshToken=if($Token.RefreshToken){$Token.RefreshToken.Copy()}else{$null}
    $copy.Evidence=$Evidence
    [pscustomobject]$copy
}
function Assert-TokenForgeProfileToken {
    param($Token,$Profile,[string[]]$Scope,[string]$ClientId,[string]$ResourceId,[int]$MaxAdditionalScopes,[switch]$AllowExpired)
    $claims=Get-TokenForgeTokenClaims -AccessToken $Token.AccessToken
    $audiences=@($ResourceId)
    if($ResourceId -eq '00000003-0000-0000-c000-000000000000'){$audiences+=@('https://graph.microsoft.com')}
    if($ResourceId -eq '797f4846-ba00-4fd7-ba43-dac1f8f63013'){$audiences+=@('https://management.azure.com','https://management.core.windows.net')}
    if($claims.TenantFingerprint -ne $Profile.ExpectedTenantFingerprint -or $claims.PrincipalFingerprint -ne $Profile.ExpectedPrincipalFingerprint -or
       $claims.ClientId -ne $ClientId -or -not $claims.Audience -or $claims.Audience.TrimEnd('/') -notin $audiences -or -not $claims.HasDelegatedScopeClaim -or
       @($Scope|Where-Object {$claims.Scopes -cnotcontains $_}).Count){throw 'Token does not match the profile account, tenant, client, resource, or scopes.'}
    if(-not $claims.ExpiresAt -or -not $Token.ExpiresAt -or (-not $AllowExpired -and ($claims.ExpiresAt -le [DateTimeOffset]::UtcNow.AddMinutes(2) -or ([DateTimeOffset]$Token.ExpiresAt) -le [DateTimeOffset]::UtcNow.AddMinutes(2)))){throw 'Token has unknown or insufficient remaining lifetime.'}
    $extra=@($claims.Scopes|Where-Object {$_ -cnotin @('openid','profile','email','offline_access') -and $Scope -cnotcontains $_})
    if($extra.Count -gt $MaxAdditionalScopes -or ($Token.PSObject.Properties['AdditionalScopes'] -and @($Token.AdditionalScopes).Count -gt $MaxAdditionalScopes)){throw 'Token exceeds the profile additional-scope policy.'}
    $claims
}
function Save-TokenForgeProfileToken {
    param($Record,[securestring]$Password,[string]$SessionName,[string]$ExpectedRevision,$Token,[string]$ReplaceTokenId)
    $request=$Token.Request;$claims=$Token.TokenClaims;$now=[DateTimeOffset]::UtcNow
    $id=Get-TokenForgeFingerprint -Value ($request.ClientId+'|'+$request.ResourceId+'|'+(@($request.Scopes|Sort-Object -Unique) -join ' ')+'|'+$request.RedirectUri+'|'+[string]$request.Spa)
    Invoke-TokenForgeVaultTransaction $Record.VaultPath $Password -Mode Update -Update {
        param($vault)
        $session=$vault.Sessions[$SessionName]
        if(-not $session -or $session.Revision -ne $ExpectedRevision -or ([DateTimeOffset]$session.RetainUntil) -le $now -or $session.TenantFingerprint -ne $claims.TenantFingerprint -or $session.PrincipalFingerprint -ne $claims.PrincipalFingerprint){throw 'Session changed or expired during acquisition.'}
        $expiry=@([DateTimeOffset]$Token.ExpiresAt,[DateTimeOffset]$claims.ExpiresAt)|Sort-Object|Select-Object -First 1
        $session.Tokens[$id]=@{Id=$id;ClientId=$request.ClientId;ResourceId=$request.ResourceId;Tenant=$request.Tenant;Audience=$claims.Audience;
            Scopes=@($request.Scopes);IssuedScopes=@($claims.Scopes);AdditionalScopeCount=@($claims.Scopes|Where-Object {$_ -cnotin $request.Scopes -and $_ -cnotin @('openid','profile','email','offline_access')}).Count;
            RedirectUri=$request.RedirectUri;Spa=[bool]$request.Spa;OfflineAccess=@($request.OAuthScopes) -ccontains 'offline_access';Protocol=$Token.Protocol;
            AcquiredAt=$now.ToString('o');ExpiresAt=$expiry.ToString('o');AccessToken=[Net.NetworkCredential]::new('', $Token.AccessToken).Password;
            RefreshToken=$(if($Token.RefreshToken){[Net.NetworkCredential]::new('', $Token.RefreshToken).Password}else{$null});ConsentEvidence=$Token.Evidence}
        if($ReplaceTokenId -and $ReplaceTokenId -ne $id){$null=$session.Tokens.Remove($ReplaceTokenId)}
        # Do not update Cookie, RetainUntil, or LastConfirmedAt: renewal is not a new login.
        $session.Revision=[guid]::NewGuid().ToString()
    }
    $id
}
function Request-TokenForgeProfileScope {
    param($Profile,$Inventory,$Database,[string]$DatabasePath,[guid]$ResourceId,[string[]]$Scope,$Authentication,[int]$MaxCandidates,[int]$MaxRedirects)
    if($Inventory.TenantFingerprint -ne $Profile.ExpectedTenantFingerprint -or ([DateTimeOffset]$Inventory.CapturedAt) -lt [DateTimeOffset]::UtcNow.AddHours(-$Profile.MaxAgeHours) -or ([DateTimeOffset]$Inventory.CapturedAt) -gt [DateTimeOffset]::UtcNow.AddMinutes(5)){throw 'Inventory must be fresh and match the profile tenant.'}
    $resource=@($Inventory.Applications|Where-Object {$_.AppId -eq $ResourceId.ToString() -and $_.Registration -eq 'Present' -and $_.Ownership -eq 'VerifiedMicrosoftOwner' -and $_.AccountEnabled})
    if($resource.Count -ne 1){throw 'Enabled ownership-verified target resource required.'}
    $candidates=@(Get-TokenForgeScopeCandidates -Inventory $Inventory -Database $Database -ResourceId $ResourceId -Scope $Scope -PrincipalFingerprint $Profile.ExpectedPrincipalFingerprint -MaxAgeHours $Profile.MaxAgeHours|Where-Object CandidateRank -LE 2)
    $attempted=0
    foreach($candidate in $candidates){
        $app=@($Inventory.Applications|Where-Object AppId -eq $candidate.ClientId)[0]
        $redirects=@($app.RedirectUris|Where-Object {
            $uri=$null
            [uri]::TryCreate($_,[UriKind]::Absolute,[ref]$uri) -and -not $uri.UserInfo -and -not $uri.Query -and -not $uri.Fragment -and
            $(if($Authentication.ContainsKey('Browser') -and $Authentication.Browser){$uri.Scheme -eq 'http' -and $uri.Host -eq 'localhost' -and $uri.AbsolutePath -eq '/'}else{$_ -ceq 'https://login.microsoftonline.com/common/oauth2/nativeclient'})
        }|Select-Object -First $MaxRedirects)
        if(-not $redirects.Count){continue}
        if($attempted -ge $MaxCandidates){break}
        $attempted++
        foreach($redirect in $redirects){
            $token=$null;$success=$false
            try{
                $request=New-TokenForgeTenantRequest -Inventory $Inventory -ClientId $candidate.ClientId -ResourceId $ResourceId -Scope $Scope -RedirectUri $redirect -Tenant $Profile.Tenant -OfflineAccess
                $token=Get-TokenForgeToken -Request $request @Authentication
                $claims=Assert-TokenForgeProfileToken $token $Profile $Scope $candidate.ClientId $ResourceId.ToString() $Profile.MaxAdditionalScopes
                $token|Add-Member Request $request -Force
                $token|Add-Member TokenClaims $claims -Force
                $token|Add-Member Evidence 'BoundedTargetedSilentExplicitScopeAcquisition' -Force
                $observation=[pscustomobject]@{ClientId=$candidate.ClientId;ResourceId=$ResourceId.ToString();Outcome='Succeeded';TenantFingerprint=$claims.TenantFingerprint;PrincipalFingerprint=$claims.PrincipalFingerprint;ObservedAt=[DateTimeOffset]::UtcNow.ToString('o');Protocol='OAuth2V2Pkce';Spa=$false;RedirectFingerprint=(Get-TokenForgeFingerprint $redirect);RequestedScopes=$Scope;ScpScopes=@($claims.Scopes);ClaimsReadable=$true;HasScpClaim=$true;NamespaceVerification='Matched';RequestVerification='Matched';SignatureValidated=$false}
                $stateLock=$null
                try{
                    $stateLock=Open-TokenForgeProfileOperation -Directory (Split-Path $DatabasePath -Parent) -Leaf '.writer.lock'
                    $latest=Get-TokenForgeScopeDatabase $DatabasePath
                    $null=Add-TokenForgeScopeObservation -Database $latest -Observation $observation -Path $DatabasePath
                }catch{
                    $failure=[InvalidOperationException]::new('Scope acquisition succeeded but its checkpoint could not be saved; token discarded. Details suppressed.')
                    $failure.Data['TokenForgeCheckpointFailure']=$true;throw $failure
                }finally{if($stateLock){$stateLock.Dispose()};$latest=$null}
                $success=$true
                return $token
            }catch{
                if($_.Exception.Data['TokenForgeCheckpointFailure']){throw}
                # Only bounded candidate attempts; no .default, registration, or consent fallback.
            }finally{if($token -and -not $success){$token.AccessToken.Dispose();if($token.RefreshToken){$token.RefreshToken.Dispose()}}}
        }
    }
    throw 'No bounded candidate completed a matching explicit scope request. Inspect scope hints or run explicit discovery; no broad fallback was attempted.'
}
