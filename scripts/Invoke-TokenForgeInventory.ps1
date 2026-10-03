#Requires -Version 7.4
<#
.SYNOPSIS
Run one resumable discovery, registration, or scope-observation stage.
.DESCRIPTION
Pass SecureString credentials from the current PowerShell session. No credential is serialized.
StatePath is private assessment metadata. Only one writer may use a state directory at a time.
Registration changes the tenant but does not grant permissions. ResolvePublishedCandidates
also resolves published candidates whose owner is unknown, rolling back newly created
non-Microsoft principals. Probe uses existing consent and stops at interactive policy pages.
#>
[CmdletBinding(SupportsShouldProcess)]
param(
 [Parameter(Mandatory)][ValidateSet('Discover','Inventory','Register','Probe','Export')][string]$Action,
 [Parameter(Mandatory)][string]$StatePath,
 [securestring]$GraphToken,
 [securestring]$EstsAuth,
 [guid[]]$ClientId,
 [ValidateRange(1,100000)][int]$MaxApplications=100000,
 [ValidateRange(1,1000)][int]$MaxRedirects=8,
 [switch]$GraphOnly,
 [switch]$ResolvePublishedCandidates,
 [switch]$Refresh,
 [switch]$RetryFailures,
 [string]$ExportPath
)
$ErrorActionPreference='Stop'
Import-Module (Join-Path $PSScriptRoot '../src/TokenForge/TokenForge.psd1') -Force
$null=New-Item -ItemType Directory -Path $StatePath -Force
if (-not $IsWindows) { [IO.File]::SetUnixFileMode($StatePath, ([IO.UnixFileMode]::UserRead -bor [IO.UnixFileMode]::UserWrite -bor [IO.UnixFileMode]::UserExecute)) }
$discoveryPath=Join-Path $StatePath 'discovery.json'
$inventoryPath=Join-Path $StatePath 'inventory.json'
$databasePath=Join-Path $StatePath 'scopes.json'
# Prevent checkpoint loss from overlapping writers, including a second CLI process.
$lock=$null
try {
 try {$lock=[IO.File]::Open((Join-Path $StatePath '.writer.lock'),[IO.FileMode]::OpenOrCreate,[IO.FileAccess]::ReadWrite,[IO.FileShare]::None)}
 catch {throw 'State directory is already in use by another writer.'}
 switch ($Action) {
  'Discover' {Update-TokenForgeDiscovery -Path $discoveryPath}
  'Inventory' {
   if(-not $GraphToken){throw 'Inventory requires GraphToken.'}
   $discovery=Get-Content -LiteralPath $discoveryPath -Raw|ConvertFrom-Json
   $inventory=Get-TokenForgeTenantInventory -GraphToken $GraphToken -Discovery $discovery
   $inventory|ConvertTo-Json -Depth 100|Set-Content -LiteralPath $inventoryPath -Encoding utf8
   $inventory
  }
  'Register' {
   if(-not $GraphToken){throw 'Register requires GraphToken.'}
   $inventory=Get-Content -LiteralPath $inventoryPath -Raw|ConvertFrom-Json
   Sync-TokenForgeApplicationRegistration -Inventory $inventory -GraphToken $GraphToken -DatabasePath $databasePath -ClientId $ClientId -MaxApplications $MaxApplications -ResolvePublishedCandidates:$ResolvePublishedCandidates -RetryFailures:$RetryFailures -WhatIf:$WhatIfPreference
  }
  'Probe' {
   if(-not $EstsAuth){throw 'Probe requires EstsAuth.'}
   $inventory=Get-Content -LiteralPath $inventoryPath -Raw|ConvertFrom-Json
   $plan=Get-TokenForgeProbePlan -Inventory $inventory -ClientId $ClientId -GraphOnly:$GraphOnly
   Invoke-TokenForgeScopeProbe -Inventory $inventory -EstsAuth $EstsAuth -Plan $plan -DatabasePath $databasePath -ClientId $ClientId -MaxApplications $MaxApplications -MaxRedirects $MaxRedirects -Refresh:$Refresh
  }
  'Export' {
   if(-not $ExportPath){throw 'Export requires ExportPath.'}
   Export-TokenForgeScopeDatabase -Database (Get-TokenForgeScopeDatabase -Path $databasePath) -Path $ExportPath
  }
 }
} finally {if($lock){$lock.Dispose()}}
