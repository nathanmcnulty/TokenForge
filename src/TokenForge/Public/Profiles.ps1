function New-TokenForgeProfile {
    <# .SYNOPSIS
    Create a named credential-free profile with explicit memory, passphrase, or OS-key storage.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][ValidatePattern('^[a-z][a-z0-9_-]{0,63}$')][string]$Name,
        [Parameter(Mandatory)][ValidatePattern('^[a-zA-Z0-9][a-zA-Z0-9.-]{0,252}$')][string]$Tenant,
        [string]$Root,[string]$StatePath,
        [ValidateSet('Memory','Passphrase','OperatingSystem')][string]$Storage='Memory',
        [guid]$BootstrapClientId='038ddad9-5bbe-4f64-b0cd-12434d1e633b',
        [ValidateRange(0,8760)][int]$MaxAdditionalScopes=0,
        [ValidateRange(0,8760)][int]$MaxBootstrapAdditionalScopes=0,
        [ValidateRange(1,8760)][int]$MaxAgeHours=24,
        [ValidateRange(1,168)][int]$SessionRetentionHours=8,
        [string]$PasskeyPath='', [string]$XdrModulePath=''
    )
    if($Tenant -in @('common','organizations','consumers') -or $BootstrapClientId -eq [guid]::Empty){throw 'Use a specific tenant and nonempty bootstrap client ID.'}
    if([bool]$PasskeyPath -ne [bool]$XdrModulePath){throw 'PasskeyPath and XdrModulePath must be configured together.'}
    $rootPath=Resolve-TokenForgeProfileRoot $Root
    $path=Resolve-TokenForgeVaultPath -Path (Join-Path $rootPath "$Name/profile.json") -CreateDirectory
    $lock=Open-TokenForgeProfileOperation -Directory (Split-Path $path -Parent)
    try{
        if(Test-Path -LiteralPath $path){throw 'Profile already exists; choose another name.'}
        if(-not $StatePath){$StatePath=Join-Path (Split-Path $path -Parent) 'state'}
        $stateMarker=Resolve-TokenForgeVaultPath -Path (Join-Path $StatePath '.state') -CreateDirectory
        $now=[DateTimeOffset]::UtcNow.ToString('o')
        $p=[ordered]@{Format='TokenForgeProfile';SchemaVersion=1;Name=$Name;Tenant=$Tenant;StatePath=(Split-Path $stateMarker -Parent);Storage=$Storage;
            BootstrapClientId=$BootstrapClientId.ToString();MaxAdditionalScopes=$MaxAdditionalScopes;MaxBootstrapAdditionalScopes=$MaxBootstrapAdditionalScopes;
            MaxAgeHours=$MaxAgeHours;SessionRetentionHours=$SessionRetentionHours;PasskeyPath=$PasskeyPath;XdrModulePath=$XdrModulePath;
            ExpectedTenantFingerprint=$null;ExpectedPrincipalFingerprint=$null;Revision=[guid]::NewGuid().ToString();CreatedAt=$now;UpdatedAt=$now}
        if($Storage -eq 'OperatingSystem'){
            if([TokenForge.Core.V0110.PlatformVaultKey]::Backend -eq 'Unsupported'){throw 'OS-backed profiles are currently supported on Windows and Linux; create a Passphrase profile on this platform.'}
            $p.SchemaVersion=2;$p.KeyId=[guid]::NewGuid().ToString('N')
        }
        Save-TokenForgeDocument -Document $p -Path $path
        [pscustomobject]$p
    }finally{$lock.Dispose()}
}
function Get-TokenForgeProfile {
    [CmdletBinding()]
    param([Parameter(Mandatory)][ValidatePattern('^[a-z][a-z0-9_-]{0,63}$')][string]$Name,[string]$Root)
    [pscustomobject](Read-TokenForgeProfile $Name $Root).Configuration
}
function Get-TokenForgeProfileStatus {
    <# .SYNOPSIS
    Report profile/session state without login, network calls, or credential output.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][ValidatePattern('^[a-z][a-z0-9_-]{0,63}$')][string]$Name,[string]$Root,[securestring]$VaultPassword)
    $record=Read-TokenForgeProfile $Name $Root;$p=$record.Configuration;$context=$script:ProfileContexts[$record.ContextKey]
    if($p.Storage -eq 'OperatingSystem' -and $VaultPassword){throw 'OS-backed profiles do not accept a vault passphrase.'}
    $session=$null
    if($p.Storage -eq 'Passphrase' -and (Test-Path $record.VaultPath)){
        $password=if($VaultPassword){$VaultPassword}elseif($context){$context.Password}else{$null}
        if($password){$session=@((Get-TokenForgeVault $record.VaultPath $password).Sessions|Where-Object Name -eq $Name)|Select-Object -First 1}
    }elseif($context -and $context.Revision -eq $p.Revision){$session=$context.Session}
    [pscustomobject]@{Profile=$Name;Tenant=$p.Tenant;Storage=$p.Storage;IdentityBound=[bool]$p.ExpectedPrincipalFingerprint;
        SessionState=if($session){if(([DateTimeOffset]$session.RetainUntil) -le [DateTimeOffset]::UtcNow){'RetentionExpired'}else{'Available'}}elseif($p.Storage -ne 'Memory' -and (Test-Path $record.VaultPath)){'Locked'}else{'LoginRequired'};
        RetainUntil=if($session){$session.RetainUntil}else{$null};CachedTokenCount=if($p.Storage -eq 'Memory' -and $context){$context.Tokens.Count}elseif($session){$session.Tokens.Count}else{0};
        MaxAdditionalScopes=$p.MaxAdditionalScopes;MaxBootstrapAdditionalScopes=$p.MaxBootstrapAdditionalScopes;
        StatePath=$p.StatePath;CredentialSource=if(-not $session){if($p.Storage -ne 'Memory' -and (Test-Path $record.VaultPath)){'UnknownUntilUnlocked'}else{'NoneUntilLogin'}}elseif($p.Storage -eq 'OperatingSystem'){'OsProtectedVault'}elseif($p.Storage -eq 'Passphrase'){if($session.HasCookie){'EncryptedEstsCookie'}else{'BrowserSsoRequiredForNewClients'}}elseif($context -and $context.Cookie){'ProcessEstsCookie'}else{'BrowserSsoRequiredForNewClients'};Evidence='LocalSessionMetadataNotServerValidity'}
}
function Test-TokenForgeProfile {
    [CmdletBinding()]
    param([Parameter(Mandatory)][ValidatePattern('^[a-z][a-z0-9_-]{0,63}$')][string]$Name,[string]$Root,[securestring]$VaultPassword)
    $p=Get-TokenForgeProfile $Name $Root
    $status=Get-TokenForgeProfileStatus $Name $Root -VaultPassword $VaultPassword
    $checks=@([pscustomobject]@{Check='Session';State=$status.SessionState;NextStep=if($status.SessionState -eq 'Available'){'Request a token.'}elseif($status.SessionState -eq 'Locked'){'Unlock the configured credential store through login or token acquisition.'}else{'Log in to this profile.'}})
    $inventoryState='Missing';$scopeState='Missing'
    try{
        $file=Resolve-TokenForgeVaultPath (Join-Path $p.StatePath 'inventory.json')
        if(Test-Path $file){
            $inventory=Get-Content -LiteralPath $file -Raw|ConvertFrom-Json
            $inventoryState=if($p.ExpectedTenantFingerprint -and $inventory.TenantFingerprint -ne $p.ExpectedTenantFingerprint){'WrongTenant'}elseif(([DateTimeOffset]$inventory.CapturedAt) -lt [DateTimeOffset]::UtcNow.AddHours(-$p.MaxAgeHours)){'Stale'}elseif(([DateTimeOffset]$inventory.CapturedAt) -gt [DateTimeOffset]::UtcNow.AddMinutes(5)){'FutureDated'}else{'Fresh'}
        }
    }catch{$inventoryState='InvalidOrUnsafePath'}
    try{
        $file=Resolve-TokenForgeVaultPath (Join-Path $p.StatePath $(if(Test-Path (Join-Path $p.StatePath 'scopes.sqlite')){'scopes.sqlite'}else{'scopes.json'}))
        if(Test-Path $file){
            $database=Get-TokenForgeScopeDatabase $file -Latest -TenantFingerprint $p.ExpectedTenantFingerprint -PrincipalFingerprint $p.ExpectedPrincipalFingerprint
            $matching=@($database.Observations|Where-Object {$_.TenantFingerprint -eq $p.ExpectedTenantFingerprint -and $_.PrincipalFingerprint -eq $p.ExpectedPrincipalFingerprint -and $_.Outcome -eq 'Succeeded' -and $_.NamespaceVerification -eq 'Matched' -and $_.RequestVerification -eq 'Matched' -and ([DateTimeOffset]$_.ObservedAt) -ge [DateTimeOffset]::UtcNow.AddHours(-$p.MaxAgeHours) -and ([DateTimeOffset]$_.ObservedAt) -le [DateTimeOffset]::UtcNow.AddMinutes(5)})
            $scopeState=if($matching.Count){'FreshAccountObservations'}else{'NoFreshAccountObservations'}
        }
    }catch{$scopeState='InvalidOrUnsafePath'}
    $checks+=[pscustomobject]@{Check='Inventory';State=$inventoryState;NextStep=if($inventoryState -eq 'Fresh'){'Available for request validation.'}else{'Import or collect a fresh tenant-verified inventory.'}}
    $checks+=[pscustomobject]@{Check='ScopeObservations';State=$scopeState;NextStep=if($scopeState -eq 'FreshAccountObservations'){'Explain requested scopes to inspect current coverage.'}else{'Token requests can try bounded published or configured candidates; use explicit discovery for broader assessment.'}}
    [pscustomobject]@{Profile=$p.Name;Checks=$checks;Evidence='LocalChecksNoNetworkOrConsent'}
}
function Disconnect-TokenForgeProfile {
    [CmdletBinding(SupportsShouldProcess)]
    param([Parameter(Mandatory)][ValidatePattern('^[a-z][a-z0-9_-]{0,63}$')][string]$Name,[string]$Root,[securestring]$VaultPassword)
    $record=Read-TokenForgeProfile $Name $Root
    if(-not $PSCmdlet.ShouldProcess($Name,'Remove the local session and cached tokens')){return}
    $lock=Open-TokenForgeProfileOperation $record.Directory
    $ownedPassword=$null
    try{
        if($record.Configuration.Storage -eq 'OperatingSystem' -and $VaultPassword){throw 'OS-backed profiles do not accept a vault passphrase.'}
        if($record.Configuration.Storage -ne 'Memory' -and (Test-Path $record.VaultPath)){
            $context=$script:ProfileContexts[$record.ContextKey]
            $password=if($VaultPassword){$VaultPassword}elseif($context){$context.Password}else{$null}
            if($record.Configuration.Storage -eq 'OperatingSystem'){$ownedPassword=Open-TokenForgeProfilePlatformKey $record;$password=$ownedPassword}
            if(-not $password){throw 'Unlock the configured credential store to remove the persisted session.'}
            $view=Get-TokenForgeVault $record.VaultPath $password
            if(@($view.Sessions|Where-Object Name -eq $Name).Count){$null=Remove-TokenForgeVaultEntry $record.VaultPath $password -SessionName $Name}
        }
        Clear-TokenForgeProfileContext $record.ContextKey
        [pscustomobject]@{Profile=$Name;Removed=$true;Evidence='LocalLogoutNotServerRevocation'}
    }finally{if($ownedPassword){$ownedPassword.Dispose()};$lock.Dispose()}
}

function Remove-TokenForgeProfileKey {
    <# .SYNOPSIS
    Forget an OS-backed local session: delete its encrypted vault before deleting its platform key.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param([Parameter(Mandatory)][ValidatePattern('^[a-z][a-z0-9_-]{0,63}$')][string]$Name,[string]$Root)
    $record=Read-TokenForgeProfile $Name $Root
    if($record.Configuration.Storage -ne 'OperatingSystem'){throw 'This operation requires an OS-backed profile.'}
    if(-not $PSCmdlet.ShouldProcess($Name,'Delete the local encrypted vault and its OS key')){return}
    $lock=Open-TokenForgeProfileOperation $record.Directory
    $vaultLock=$null
    try{
        $vaultLock=Open-TokenForgeProfileOperation $record.Directory -Leaf 'session.tfvault.lock'
        Clear-TokenForgeProfileContext $record.ContextKey
        $vaultPath=Resolve-TokenForgeVaultPath $record.VaultPath
        if(Test-Path -LiteralPath $vaultPath){Remove-Item -LiteralPath $vaultPath -ErrorAction Stop}
        $keyRemoved=$true
        try{Remove-TokenForgeProfilePlatformKey $record}catch{$keyRemoved=$false}
        [pscustomobject]@{Profile=$Name;VaultRemoved=$true;KeyRemoved=$keyRemoved;NextStep=if($keyRemoved){'Log in explicitly to create a new local session.'}else{'Vault removed; retry this operation to delete the remaining OS key.'};Evidence='LocalDeletionNotServerRevocation'}
    }finally{if($vaultLock){$vaultLock.Dispose()};$lock.Dispose()}
}
