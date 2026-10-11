# Profiles contain configuration only. Credentials live in a process context or an explicit vault.
$script:ProfileContexts=@{}
function Resolve-TokenForgeProfileRoot {
    param([string]$Root)
    if(-not $Root){$Root=Join-Path ([Environment]::GetFolderPath('LocalApplicationData')) 'TokenForge/profiles'}
    $marker=Resolve-TokenForgeVaultPath -Path (Join-Path $Root '.profiles') -CreateDirectory
    Split-Path $marker -Parent
}
function Open-TokenForgeProfileOperation {
    param([string]$Directory,[ValidateSet('.operation.lock','.writer.lock','session.tfvault.lock')][string]$Leaf='.operation.lock')
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
        $json=Get-Content -LiteralPath $path -Raw
        [TokenForge.Core.V0200.ProfilePolicy]::Validate($json,$Name)
        $p=$json|ConvertFrom-Json -AsHashtable -Depth 4
        # Keep the PowerShell configuration projection's historical UTC date strings.
        foreach($key in @('CreatedAt','UpdatedAt')){if($p[$key] -is [datetime]){$p[$key]=$p[$key].ToUniversalTime().ToString('o')}}
        [pscustomobject]@{Configuration=$p;ConfigurationJson=$json;Path=$path;Directory=(Split-Path $path -Parent);VaultPath=(Join-Path (Split-Path $path -Parent) 'session.tfvault');ContextKey=$path}
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
    $responseExtras=if($Token.PSObject.Properties['AdditionalScopes']){@($Token.AdditionalScopes).Count}else{0}
    $jwtExpiry=if($claims.ExpiresAt){[Nullable[DateTimeOffset]]$claims.ExpiresAt}else{$null}
    $responseExpiry=if($Token.ExpiresAt){[Nullable[DateTimeOffset]]$Token.ExpiresAt}else{$null}
    try{
        $null=[TokenForge.Core.V0100.TokenPolicy]::Validate($claims.TenantFingerprint,$claims.PrincipalFingerprint,$claims.ClientId,$claims.Audience,
            $Profile.ExpectedTenantFingerprint,$Profile.ExpectedPrincipalFingerprint,$ClientId,$ResourceId,[string[]]$claims.Scopes,[string[]]$Scope,
            $claims.HasDelegatedScopeClaim,$jwtExpiry,$responseExpiry,$MaxAdditionalScopes,$responseExtras,[bool]$AllowExpired,[DateTimeOffset]::UtcNow)
    }catch{throw 'Token does not satisfy the profile identity, client, resource, scope, or lifetime policy.'}
    $claims
}
function Request-TokenForgeProfileScope {
    param($Profile,$Inventory,$Database,[string]$DatabasePath,[guid]$ResourceId,[string[]]$Scope,$Authentication,[int]$MaxCandidates,[int]$MaxRedirects)
    if(-not $Inventory){$Inventory=Get-Content -LiteralPath (Resolve-TokenForgeVaultPath (Join-Path $Profile.StatePath 'inventory.json')) -Raw|ConvertFrom-Json}
    if(-not $DatabasePath){$DatabasePath=Join-Path $Profile.StatePath $(if(Test-Path (Join-Path $Profile.StatePath 'scopes.sqlite')){'scopes.sqlite'}else{'scopes.json'})}
    if(-not $Database){$Database=Get-TokenForgeScopeDatabase -Path (Resolve-TokenForgeVaultPath $DatabasePath) -Latest -TenantFingerprint $Profile.ExpectedTenantFingerprint -PrincipalFingerprint $Profile.ExpectedPrincipalFingerprint -ResourceId $ResourceId}
    $coverage=@(Get-TokenForgeAssessmentCoverage -Database $Database -ResourceId $ResourceId -Scope $Scope -TenantFingerprint $Profile.ExpectedTenantFingerprint -PrincipalFingerprint $Profile.ExpectedPrincipalFingerprint -MaxAgeHours $Profile.MaxAgeHours|Where-Object CoversAll)
    if($coverage.Count){
        $Authentication.Remove('NoConsent')
        $token=Get-TokenForgeScopedToken -Inventory $Inventory -Database $Database -ResourceId $ResourceId -Scope $Scope @Authentication -Tenant $Profile.Tenant -BootstrapClientId $Profile.BootstrapClientId -MaxBootstrapAdditionalScopes $Profile.MaxBootstrapAdditionalScopes -MaxAdditionalScopes $Profile.MaxAdditionalScopes -MaxAgeHours $Profile.MaxAgeHours -MaxCandidates $MaxCandidates -MaxRedirects $MaxRedirects -OfflineAccess
        $token|Add-Member Evidence 'SilentExplicitScopeAcquisition' -Force
        return $token
    }
    if($Inventory.TenantFingerprint -ne $Profile.ExpectedTenantFingerprint -or ([DateTimeOffset]$Inventory.CapturedAt) -lt [DateTimeOffset]::UtcNow.AddHours(-$Profile.MaxAgeHours) -or ([DateTimeOffset]$Inventory.CapturedAt) -gt [DateTimeOffset]::UtcNow.AddMinutes(5)){throw 'Inventory must be fresh and match the profile tenant.'}
    $resource=@($Inventory.Applications|Where-Object {$_.AppId -eq $ResourceId.ToString() -and $_.Registration -eq 'Present' -and $_.Ownership -eq 'VerifiedMicrosoftOwner' -and $_.AccountEnabled})
    if($resource.Count -ne 1){throw 'Enabled ownership-verified target resource required.'}
    if($DatabasePath.EndsWith('.sqlite',[StringComparison]::OrdinalIgnoreCase)){$null=Invoke-TokenForgeNativeEvidence $DatabasePath update -Document (New-TokenForgeScopeDatabase) -Domain evidence}
    $plans=@(New-TokenForgePlannedScopeRequests -Inventory $Inventory -Database $Database -ResourceId $ResourceId -Scope $Scope -PrincipalFingerprint $Profile.ExpectedPrincipalFingerprint -Tenant $Profile.Tenant -Warm $false -Browser ($Authentication.ContainsKey('Browser') -and [bool]$Authentication.Browser) -OfflineAccess $true -MaxCandidates $MaxCandidates -MaxRedirects $MaxRedirects -MaxAgeHours $Profile.MaxAgeHours)
    foreach($request in $plans){
        $redirect=$request.RedirectUri
        $token=$null;$success=$false
        try{
            $instant=[DateTimeOffset]::UtcNow;$date=[TokenForge.Core.V0240.TimestampPolicy]::Parse($Inventory.CapturedAt)
            if($date -lt $instant.AddHours(-$Profile.MaxAgeHours) -or $date -gt $instant.AddMinutes(5)){throw 'Inventory expired during acquisition.'}
            $token=Get-TokenForgeToken -Request $request @Authentication
            $claims=Assert-TokenForgeProfileToken $token $Profile $Scope $request.ClientId $ResourceId.ToString() $Profile.MaxAdditionalScopes
            $token|Add-Member Request $request -Force
            $token|Add-Member TokenClaims $claims -Force
            $token|Add-Member Evidence 'BoundedTargetedSilentExplicitScopeAcquisition' -Force
            $observation=[pscustomobject]@{ClientId=$request.ClientId;ResourceId=$ResourceId.ToString();Outcome='Succeeded';TenantFingerprint=$claims.TenantFingerprint;PrincipalFingerprint=$claims.PrincipalFingerprint;ObservedAt=[DateTimeOffset]::UtcNow.ToString('o');Protocol='OAuth2V2Pkce';Spa=$false;RedirectFingerprint=(Get-TokenForgeFingerprint $redirect);RequestedScopes=$Scope;ScpScopes=@($claims.Scopes);ClaimsReadable=$true;HasScpClaim=$true;NamespaceVerification='Matched';RequestVerification='Matched';SignatureValidated=$false}
            $stateLock=$null
            try{
                $stateLock=Open-TokenForgeProfileOperation -Directory (Split-Path $DatabasePath -Parent) -Leaf '.writer.lock'
                $latest=if($DatabasePath.EndsWith('.sqlite',[StringComparison]::OrdinalIgnoreCase)){$Database}else{Get-TokenForgeScopeDatabase $DatabasePath}
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
    throw 'No bounded candidate completed a matching explicit scope request. Inspect scope hints or run explicit discovery; no broad fallback was attempted.'
}

function Get-TokenForgeProfileKeyHandle {
    param($Record)
    # A moved profile is not an automatic key migration.
    [TokenForge.Core.V0230.ProfileKeyIdentity]::Compute($Record.Directory,$Record.Configuration.KeyId)
}
function Open-TokenForgeProfilePlatformKey {
    param($Record,[switch]$Create)
    [TokenForge.Core.V0110.PlatformVaultKey]::Open((Get-TokenForgeProfileKeyHandle $Record), ($Create -and -not (Test-Path -LiteralPath $Record.VaultPath)))
}
function Remove-TokenForgeProfilePlatformKey {
    param($Record)
    [TokenForge.Core.V0110.PlatformVaultKey]::Delete((Get-TokenForgeProfileKeyHandle $Record))
}
