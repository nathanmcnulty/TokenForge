#Requires -Version 7.4
[CmdletBinding()]
param(
 [Parameter(Mandatory)][ValidateSet('Connect','Plan','Maintain')][string]$Action,
 [string]$RequestPath,
 [string]$LoginHint,
 [ValidateRange(30,900)][int]$TimeoutSeconds=300,
 [string]$ManifestPath,
 [string]$StatePath,
 [ValidatePattern('^[a-f0-9]{64}$')][string]$PrincipalFingerprint,
 [ValidateRange(1,8760)][int]$MaxAgeHours=24,
 [switch]$RefreshDiscovery,
 [string]$BeforeDatabasePath
)
$ErrorActionPreference='Stop'
Import-Module (Join-Path $PSScriptRoot '../src/TokenForge/TokenForge.psd1') -Force
if($Action -eq 'Connect') {
 if(-not $RequestPath){throw 'Connect requires a credential-free RequestPath.'}
 $request=Get-Content -LiteralPath $RequestPath -Raw|ConvertFrom-Json
 Get-TokenForgeToken -Request $request -Browser -LoginHint $LoginHint -TimeoutSeconds $TimeoutSeconds
 return
}
if(-not $StatePath -or -not $PrincipalFingerprint){throw 'Plan and Maintain require private StatePath and PrincipalFingerprint.'}
$inventory=Get-Content -LiteralPath (Join-Path $StatePath 'inventory.json') -Raw|ConvertFrom-Json
$database=Get-TokenForgeScopeDatabase -Path (Join-Path $StatePath 'scopes.json')
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
