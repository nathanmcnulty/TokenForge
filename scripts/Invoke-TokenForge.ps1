#Requires -Version 7.4
[CmdletBinding()]
param(
 [Parameter(Mandatory)][ValidateSet('Connect','Token','Candidates','Plan','Maintain','VaultCreate','VaultList','VaultToken','VaultRemove','VaultView')][string]$Action,
 [string]$RequestPath,
 [string]$LoginHint,
 [ValidateRange(30,900)][int]$TimeoutSeconds=300,
 [string]$ManifestPath,
 [string]$StatePath,
 [ValidatePattern('^[a-f0-9]{64}$')][string]$PrincipalFingerprint,
 [ValidateRange(1,8760)][int]$MaxAgeHours=24,
 [switch]$RefreshDiscovery,
 [string]$BeforeDatabasePath,
 [string]$DatabasePath,
 [guid]$ResourceId,
 [string[]]$Scope,
 [securestring]$EstsAuth,
 [ValidateSet('ESTSAUTH','ESTSAUTHPERSISTENT')][string]$CookieName='ESTSAUTH',
 [string]$PasskeyPath,
 [string]$XdrModulePath,
 [switch]$Browser,
 [switch]$NoConsent,
 [string]$Tenant='organizations',
 [guid]$BootstrapClientId='14d82eec-204b-4c2f-b7e8-296a70dab67e',
 [ValidateRange(0,2147483647)][int]$MaxBootstrapAdditionalScopes=2147483647,
 [ValidateRange(0,2147483647)][int]$MaxAdditionalScopes=2147483647,
 [switch]$OfflineAccess,
 [uri]$ApiUri,
 [string]$CheckId,
 [string]$VaultPath,
 [securestring]$VaultPassword,
 [ValidatePattern('^[a-z][a-z0-9_-]{0,63}$')][string]$SessionName,
 [ValidateRange(1,168)][int]$SessionRetentionHours=8,
 [ValidatePattern('^[a-f0-9]{64}$')][string]$TokenId,
 [switch]$RefreshOnly,
 [string]$OutputPath
)
$ErrorActionPreference='Stop'
Import-Module (Join-Path $PSScriptRoot '../src/TokenForge/TokenForge.psd1') -Force
$ownedVaultPassword=$null
try {
if($VaultPath -and -not $VaultPassword){$ownedVaultPassword=Read-Host 'Vault passphrase' -AsSecureString;$VaultPassword=$ownedVaultPassword}
if($Action -like 'Vault*'){
 if(-not $VaultPath){throw 'Vault actions require VaultPath.'}
 switch($Action){
  'VaultCreate' {New-TokenForgeVault -Path $VaultPath -Password $VaultPassword}
  'VaultList' {Get-TokenForgeVault -Path $VaultPath -Password $VaultPassword}
  'VaultToken' {
   if(-not $SessionName -or -not $TokenId){throw 'VaultToken requires SessionName and TokenId.'}
   Get-TokenForgeVaultToken -Path $VaultPath -Password $VaultPassword -SessionName $SessionName -TokenId $TokenId -MaxAdditionalScopes $MaxAdditionalScopes -RefreshOnly:$RefreshOnly
  }
  'VaultRemove' {
   if(-not $SessionName){throw 'VaultRemove requires SessionName.'}
   $remove=@{Path=$VaultPath;Password=$VaultPassword;SessionName=$SessionName};if($TokenId){$remove.TokenId=$TokenId}
   Remove-TokenForgeVaultEntry @remove
  }
  'VaultView' {
   if(-not $OutputPath){throw 'VaultView requires OutputPath.'}
   Export-TokenForgeVaultView -Path $VaultPath -Password $VaultPassword -OutputPath $OutputPath
  }
 }
 return
}
if($Action -eq 'Connect') {
 if(-not $RequestPath){throw 'Connect requires a credential-free RequestPath.'}
 $request=Get-Content -LiteralPath $RequestPath -Raw|ConvertFrom-Json
 Get-TokenForgeToken -Request $request -Browser -LoginHint $LoginHint -TimeoutSeconds $TimeoutSeconds -NoConsent:$NoConsent
 return
}
if($Action -eq 'Token') {
 if(-not $StatePath){throw 'Token requires private StatePath.'}
 if(@($EstsAuth,$PasskeyPath,$Browser|Where-Object {$_}).Count -gt 1){throw 'Choose one authentication method.'}
 $inventory=Get-Content -LiteralPath (Join-Path $StatePath 'inventory.json') -Raw|ConvertFrom-Json
 if(-not $DatabasePath){$DatabasePath=Join-Path $StatePath 'scopes.json'}
 $database=Get-TokenForgeScopeDatabase -Path $DatabasePath
 if($ManifestPath){
  if(-not $CheckId -or $Scope -or $ResourceId -ne [guid]::Empty -or $ApiUri){throw 'Use ManifestPath and CheckId instead of ResourceId, Scope, and ApiUri.'}
  $plan=Get-TokenForgeAssessmentPlan -ManifestPath $ManifestPath -Database $database -TenantFingerprint $inventory.TenantFingerprint -PrincipalFingerprint $inventory.PrincipalFingerprint -MaxAgeHours $MaxAgeHours
  $check=@($plan.Checks|Where-Object Id -eq $CheckId)
  if($check.Count -ne 1){throw 'CheckId is not in the validated manifest.'}
  $ResourceId=$check[0].ResourceId;$Scope=$check[0].RequiredScopes;$ApiUri=$check[0].ApiUri
 }elseif($CheckId){throw 'CheckId requires ManifestPath.'}
 if($ResourceId -eq [guid]::Empty -or -not $Scope){throw 'Token requires ResourceId and Scope, or ManifestPath and CheckId.'}
 $options=@{Inventory=$inventory;Database=$database;ResourceId=$ResourceId;Scope=$Scope;Tenant=$Tenant;BootstrapClientId=$BootstrapClientId;MaxBootstrapAdditionalScopes=$MaxBootstrapAdditionalScopes;MaxAgeHours=$MaxAgeHours;MaxAdditionalScopes=$MaxAdditionalScopes;OfflineAccess=$OfflineAccess;TimeoutSeconds=$TimeoutSeconds}
 if($VaultPath){if(-not $SessionName){throw 'Vault persistence requires an explicit SessionName.'};$options.VaultPath=$VaultPath;$options.VaultPassword=$VaultPassword;$options.SessionName=$SessionName;$options.SessionRetentionHours=$SessionRetentionHours}
 if($ApiUri){$options.ApiUri=$ApiUri}
 if($PasskeyPath){if(-not $XdrModulePath){throw 'Passkey authentication requires XdrModulePath.'};$options.PasskeyPath=$PasskeyPath;$options.XdrModulePath=$XdrModulePath}
 elseif($EstsAuth){$options.EstsAuth=$EstsAuth;$options.CookieName=$CookieName}
 elseif($Browser -or -not $VaultPath){if($XdrModulePath){throw 'XdrModulePath requires PasskeyPath.'};$options.Browser=$true;$options.LoginHint=$LoginHint}
 elseif($XdrModulePath){throw 'XdrModulePath requires PasskeyPath.'}
 Get-TokenForgeScopedToken @options
 return
}
if(-not $StatePath -or -not $PrincipalFingerprint){throw 'Candidates, Plan and Maintain require private StatePath and PrincipalFingerprint.'}
$inventory=Get-Content -LiteralPath (Join-Path $StatePath 'inventory.json') -Raw|ConvertFrom-Json
if(-not $DatabasePath){$DatabasePath=Join-Path $StatePath 'scopes.json'}
$database=Get-TokenForgeScopeDatabase -Path $DatabasePath
if($Action -eq 'Candidates'){
 if($ResourceId -eq [guid]::Empty -or -not $Scope){throw 'Candidates requires ResourceId and Scope.'}
 Get-TokenForgeScopeCandidates -Inventory $inventory -Database $database -ResourceId $ResourceId -Scope $Scope -PrincipalFingerprint $PrincipalFingerprint -MaxAgeHours $MaxAgeHours
 return
}
if($Action -eq 'Plan') {
 if(-not $ManifestPath){throw 'Plan requires ManifestPath.'}
 Get-TokenForgeAssessmentPlan -ManifestPath $ManifestPath -Database $database -TenantFingerprint $inventory.TenantFingerprint -PrincipalFingerprint $PrincipalFingerprint -MaxAgeHours $MaxAgeHours
 return
}
$discoveryPath=Join-Path $StatePath 'discovery.json'
$drift=@()
if($RefreshDiscovery) {
 # The same lock as the inventory CLI prevents replacing discovery during another stage.
 $lock=$null
 try {
  try{$lock=[IO.File]::Open((Join-Path $StatePath '.writer.lock'),[IO.FileMode]::OpenOrCreate,[IO.FileAccess]::ReadWrite,[IO.FileShare]::None)}catch{throw 'State directory is already in use by another writer.'}
  if(-not $IsWindows){[IO.File]::SetUnixFileMode((Join-Path $StatePath '.writer.lock'),384)}
  $before=Get-Content -LiteralPath $discoveryPath -Raw|ConvertFrom-Json
  $after=Update-TokenForgeDiscovery -Path $discoveryPath
  foreach($source in $after.SourceSnapshots) {
   $old=@($before.SourceSnapshots|Where-Object {$_.Location -eq $source.Location -and $_.HashKind -eq $source.HashKind})
   if($old.Count -ne 1 -or $old[0].Sha256 -ne $source.Sha256){$drift+=[pscustomobject]@{Location=$source.Location;HashKind=$source.HashKind;Changed=$true}}
  }
 } finally {if($lock){$lock.Dispose()}}
}
$report=Get-TokenForgeMaintenanceReport -Inventory $inventory -Database $database -PrincipalFingerprint $PrincipalFingerprint -MaxAgeHours $MaxAgeHours
$discovery=Get-Content -LiteralPath $discoveryPath -Raw|ConvertFrom-Json
$report|Add-Member SourceDrift @($drift)
$report|Add-Member DiscoveryRefreshRequired ([DateTimeOffset]::Parse($discovery.FetchedAt) -lt [DateTimeOffset]::UtcNow.AddHours(-$MaxAgeHours) -or [DateTimeOffset]::Parse($discovery.FetchedAt) -gt [DateTimeOffset]::UtcNow.AddMinutes(5))
$report|Add-Member InventoryDiscoveryMismatch ($inventory.DiscoveryCatalogHash -ne $discovery.CatalogContentSha256)
$report|Add-Member ObservationDrift @(if($BeforeDatabasePath){Compare-TokenForgeScopeDatabase -Before (Get-TokenForgeScopeDatabase -Path $BeforeDatabasePath) -After $database})
$report

} finally {if($ownedVaultPassword){$ownedVaultPassword.Dispose()}}
