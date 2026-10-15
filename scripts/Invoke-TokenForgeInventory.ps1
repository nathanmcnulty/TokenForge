#Requires -Version 7.6
<#
.SYNOPSIS
Run one resumable discovery, registration, or scope-observation stage.
.DESCRIPTION
Pass SecureString credentials from the current PowerShell session. No credential is serialized.
StatePath is private assessment metadata. Only one writer may use a state directory at a time.
Registration changes the tenant but does not grant permissions. ResolvePublishedCandidates
also resolves app-source candidates whose owner is unknown. Documentation-only GUIDs
require ResolveDocumentationCandidates. Registration rolls back newly created
non-Microsoft principals. Probe uses existing consent and stops at interactive policy pages.
#>
[CmdletBinding(SupportsShouldProcess)]
param(
 [Parameter(Mandatory)][ValidateSet('Discover','SignIns','Inventory','Register','Probe','Merge','Export','Report','ExportFlows','NewCohort','ProbeChunk','CohortStatus')][string]$Action,
 [Parameter(Mandatory)][string]$StatePath,
 [string]$MetadataPath,[string]$DatabasePath,[string]$FlowPath,[string]$NativeExecutablePath,[switch]$ExploreAllFlows,[switch]$SummaryOnly,[switch]$InventoryAccount,
 [securestring]$GraphToken,
 [securestring]$EstsAuth,
 [ValidateSet('ESTSAUTH','ESTSAUTHPERSISTENT')][string]$CookieName='ESTSAUTH',
 [guid[]]$ClientId,
 [ValidatePattern('^[a-f0-9]{64}$')][string]$PrincipalFingerprint,
 [string]$Tenant='organizations',
 [ValidateRange(1,100000)][int]$MaxApplications=100000,
 [ValidateRange(1,1000)][int]$MaxRedirects=8,
 [switch]$GraphOnly,
 [switch]$ResolvePublishedCandidates,
 [switch]$ResolveDocumentationCandidates,
 [switch]$ResolveSignInCandidates,
 [DateTimeOffset]$Since=[DateTimeOffset]::UtcNow.AddDays(-7),
 [DateTimeOffset]$Until=[DateTimeOffset]::UtcNow,
 [ValidateSet('interactiveUser','nonInteractiveUser','servicePrincipal','managedIdentity')][string[]]$EventTypes=@('interactiveUser','nonInteractiveUser','servicePrincipal','managedIdentity'),
 [ValidateRange(1,10000)][int]$MaxPages=1000,
 [switch]$Refresh,
 [switch]$RetryFailures,
 [string[]]$InputDatabasePath,
 [string]$ExportPath,
 [ValidatePattern('^[a-f0-9]{64}$')][string]$CohortId,
 [ValidateRange(-1,100000)][int]$ChunkIndex=-1,[ValidateRange(1,1000)][int]$BatchSize=25,
 [ValidateRange(0,1000)][int]$MaxPendingClients=0
)
$ErrorActionPreference='Stop'
Import-Module (Join-Path $PSScriptRoot '../src/TokenForge/TokenForge.psd1') -Force
if($InventoryAccount -and ($Action -ne 'Report' -or $PrincipalFingerprint)){throw 'InventoryAccount requires Report without PrincipalFingerprint.'}
# Reports inspect existing files without creating directories, changing modes, or taking the writer lock.
if($Action -eq 'Report'){
 if(-not $MetadataPath){$MetadataPath=Join-Path $StatePath $(if(Test-Path (Join-Path $StatePath 'applications.sqlite')){'applications.sqlite'}else{'applications.json'})}
 if(-not $FlowPath){
  $candidate=Join-Path $StatePath $(if(Test-Path (Join-Path $StatePath 'flows.sqlite')){'flows.sqlite'}else{'flows.json'})
  if(Test-Path -LiteralPath $candidate -PathType Leaf){$FlowPath=$candidate}
 }
 $options=@{MetadataPath=$MetadataPath;SummaryOnly=$SummaryOnly;NativeExecutablePath=$NativeExecutablePath}
 if($FlowPath){$options.FlowPath=$FlowPath}
 if($InventoryAccount -or $PrincipalFingerprint){
  $stream=$null
  try{
   $path=[TokenForge.Core.V0220.PrivateFiles]::Resolve((Join-Path $StatePath 'inventory.json'),$false)
   $stream=[IO.File]::OpenRead($path)
   if($stream.Length -lt 1 -or $stream.Length -gt 134217728){throw 'Invalid inventory size.'}
   $bytes=[byte[]]::new([int]$stream.Length);$stream.ReadExactly($bytes)
   if($stream.ReadByte() -ne -1){throw 'Inventory changed during reading.'}
   $inventory=[TokenForge.Core.DiscoverySourceClaims]::ReadMetadataJson([Text.UTF8Encoding]::new($false,$true).GetString($bytes))
   if($inventory -isnot [Collections.IDictionary]){throw 'Invalid inventory object.'}
   $reportTenant=$inventory.TenantFingerprint;$reportPrincipal=if($InventoryAccount){$inventory.PrincipalFingerprint}else{$PrincipalFingerprint}
   foreach($fingerprint in @($reportTenant,$reportPrincipal)){if($fingerprint -isnot [string] -or $fingerprint -cnotmatch '\A[a-f0-9]{64}\z'){throw 'Invalid inventory account.'}}
   $options.TenantFingerprint=$reportTenant;$options.PrincipalFingerprint=$reportPrincipal
  }catch{throw 'Cannot select a valid account from the saved inventory.'}finally{if($stream){$stream.Dispose()}}
 }
 Get-TokenForgeResearchCoverage @options
 return
}
# Status is read-only and remains available while a discovery writer holds its lock.
if($Action -eq 'CohortStatus'){
 if(-not $DatabasePath){$DatabasePath=Join-Path $StatePath 'scopes.sqlite'}
 if(-not (Test-Path -LiteralPath $DatabasePath -PathType Leaf)){throw 'Cohort status requires an existing scope database.'}
 if(-not $CohortId){$CohortId=& (Get-Module TokenForge) {param($p) Get-TokenForgeDiscoveryRunId $p} (Join-Path $StatePath 'discovery-run.json')}
 Get-TokenForgeResearchCohort $DatabasePath $CohortId -NativeExecutablePath $NativeExecutablePath -SummaryOnly:$SummaryOnly
 return
}
$null=New-Item -ItemType Directory -Path $StatePath -Force
if (-not $IsWindows) { [IO.File]::SetUnixFileMode($StatePath, ([IO.UnixFileMode]::UserRead -bor [IO.UnixFileMode]::UserWrite -bor [IO.UnixFileMode]::UserExecute)) }
$discoveryPath=Join-Path $StatePath 'discovery.json'
$inventoryPath=Join-Path $StatePath 'inventory.json'
if(-not $DatabasePath){$DatabasePath=Join-Path $StatePath $(if(Test-Path (Join-Path $StatePath 'scopes.sqlite')){'scopes.sqlite'}else{'scopes.json'})}
if(-not $FlowPath){$FlowPath=Join-Path $StatePath $(if($Action -eq 'ProbeChunk' -or (Test-Path (Join-Path $StatePath 'flows.sqlite'))){'flows.sqlite'}else{'flows.json'})}
if(-not $MetadataPath){$MetadataPath=Join-Path $StatePath $(if(Test-Path (Join-Path $StatePath 'applications.sqlite')){'applications.sqlite'}else{'applications.json'})}
$principalOptions=@{}
if ($PrincipalFingerprint) { $principalOptions.PrincipalFingerprint=$PrincipalFingerprint }
# Prevent checkpoint loss from overlapping writers, including a second CLI process.
$lock=$null
try {
 try {$lock=[IO.File]::Open((Join-Path $StatePath '.writer.lock'),[IO.FileMode]::OpenOrCreate,[IO.FileAccess]::ReadWrite,[IO.FileShare]::None)}
 catch {throw 'State directory is already in use by another writer.'}
 if (-not $IsWindows) { [IO.File]::SetUnixFileMode((Join-Path $StatePath '.writer.lock'), ([IO.UnixFileMode]::UserRead -bor [IO.UnixFileMode]::UserWrite)) }
 switch ($Action) {
  'NewCohort' {
   $inventory=Get-Content -LiteralPath $inventoryPath -Raw|ConvertFrom-Json
   New-TokenForgeResearchCohort -Inventory $inventory -DatabasePath $DatabasePath -GraphOnly:$GraphOnly -ClientId $ClientId @principalOptions -BatchSize $BatchSize -MaxRedirects $MaxRedirects -ExploreAllFlows:$ExploreAllFlows -Tenant $Tenant -NativeExecutablePath $NativeExecutablePath -WhatIf:$WhatIfPreference -Confirm:$false
  }
  'ProbeChunk' {
   if(-not $CohortId -or -not $EstsAuth){throw 'ProbeChunk requires CohortId and EstsAuth.'}
   $inventory=Get-Content -LiteralPath $inventoryPath -Raw|ConvertFrom-Json
   if($PrincipalFingerprint){$cohort=Get-TokenForgeResearchCohort $DatabasePath $CohortId -NativeExecutablePath $NativeExecutablePath;if($PrincipalFingerprint -ne $cohort.Cohort.PrincipalFingerprint){throw 'Principal selection differs from the frozen cohort.'}}
   Invoke-TokenForgeResearchChunk -Inventory $inventory -EstsAuth $EstsAuth -CookieName $CookieName -DatabasePath $DatabasePath -CohortId $CohortId -ChunkIndex $ChunkIndex -MaxPendingClients $MaxPendingClients -FlowDatabasePath $FlowPath -MetadataPath $MetadataPath -NativeExecutablePath $NativeExecutablePath -WhatIf:$WhatIfPreference -Confirm:$false
  }
  'Discover' {Update-TokenForgeDiscovery -Path $discoveryPath -MetadataPath $MetadataPath -NativeExecutablePath $NativeExecutablePath}
  'SignIns' {
   if(-not $GraphToken){throw 'SignIns requires GraphToken.'}
   $inventory=Get-Content -LiteralPath $inventoryPath -Raw|ConvertFrom-Json
   $report=Get-TokenForgeSignInApplications -GraphToken $GraphToken -Inventory $inventory -Since $Since -Until $Until -EventTypes $EventTypes -MaxPages $MaxPages -Verbose:($VerbosePreference -eq 'Continue')
   $discovery=Get-Content -LiteralPath $discoveryPath -Raw|ConvertFrom-Json
   $map=@{};foreach($app in $discovery.Applications){$map[$app.AppId]=$app}
   foreach($row in $report.Applications){
    if(-not $map.ContainsKey($row.AppId)){$map[$row.AppId]=[pscustomobject]@{AppId=$row.AppId;Name=$row.AppId;OwnerTenantId=$null;Ownership='Unverified';Sources=@();PublicClient=$null;Foci=$null;RedirectUris=@();PreferredRedirectUri='';Grants=@();IsResourceCandidate=$false;IdentifierUris=@()}}
    $app=$map[$row.AppId]
    if(-not @($app.Sources|Where-Object Evidence -eq 'ObservedSignInNotOwnership').Count){$app.Sources+= [pscustomobject]@{Name='SignInLogs';Location='https://graph.microsoft.com/beta/auditLogs/signIns';Evidence='ObservedSignInNotOwnership'}}
   }
   $discovery.Applications=@($map.Values|Sort-Object AppId)
   & (Get-Module TokenForge) {
    param($report,$discovery,$reportPath,$discoveryPath)
    Save-TokenForgeDocument -Document $report -Path $reportPath
    Save-TokenForgeDocument -Document $discovery -Path $discoveryPath
   } $report $discovery (Join-Path $StatePath 'signin-applications.json') $discoveryPath
   $null=Update-TokenForgeApplicationMetadata -Path $MetadataPath -Document $report -Kind SignIns -NativeExecutablePath $NativeExecutablePath
   $report
  }
  'Inventory' {
   if(-not $GraphToken){throw 'Inventory requires GraphToken.'}
   $discovery=Get-Content -LiteralPath $discoveryPath -Raw|ConvertFrom-Json
   $inventory=Get-TokenForgeTenantInventory -GraphToken $GraphToken -Discovery $discovery
   $null=Update-TokenForgeApplicationMetadata -Path $MetadataPath -Document $inventory -Kind Inventory -NativeExecutablePath $NativeExecutablePath
   & (Get-Module TokenForge) {param($document,$path) Save-TokenForgeDocument -Document $document -Path $path} $inventory $inventoryPath
   $inventory
  }
  'Register' {
   if(-not $GraphToken){throw 'Register requires GraphToken.'}
   $inventory=Get-Content -LiteralPath $inventoryPath -Raw|ConvertFrom-Json
   Sync-TokenForgeApplicationRegistration -Inventory $inventory -GraphToken $GraphToken -DatabasePath $databasePath -ClientId $ClientId -MaxApplications $MaxApplications -ResolvePublishedCandidates:$ResolvePublishedCandidates -ResolveDocumentationCandidates:$ResolveDocumentationCandidates -ResolveSignInCandidates:$ResolveSignInCandidates -RetryFailures:$RetryFailures -MetadataPath $MetadataPath -NativeExecutablePath $NativeExecutablePath -WhatIf:$WhatIfPreference
  }
  'Probe' {
   if(-not $EstsAuth){throw 'Probe requires EstsAuth.'}
   $inventory=Get-Content -LiteralPath $inventoryPath -Raw|ConvertFrom-Json
   $plan=Get-TokenForgeProbePlan -Inventory $inventory -ClientId $ClientId -GraphOnly:$GraphOnly @principalOptions
   $flowChanges=@{Plans=@{};Attempts=@{}};$scopeChanges=@{}
   try{Invoke-TokenForgeScopeProbe -Inventory $inventory -EstsAuth $EstsAuth -CookieName $CookieName -Plan $plan -DatabasePath $databasePath -ClientId $ClientId @principalOptions -Tenant $Tenant -MaxApplications $MaxApplications -MaxRedirects $MaxRedirects -Refresh:$Refresh -FlowDatabasePath $FlowPath -ExploreAllFlows:$ExploreAllFlows -NativeExecutablePath $NativeExecutablePath -FlowChanges $flowChanges -ScopeChanges $scopeChanges}finally{
   if($scopeChanges.Count){$null=Update-TokenForgeApplicationMetadata -Path $MetadataPath -Document @{SchemaVersion=1;UpdatedAt=[DateTimeOffset]::UtcNow.ToString('o');Observations=@($scopeChanges.Values)} -Kind ScopeObservations -NativeExecutablePath $NativeExecutablePath}
   if($flowChanges.Plans.Count){$changed=@{Format='TokenForgeFlowEvidence';SchemaVersion=1;UpdatedAt=[DateTimeOffset]::UtcNow.ToString('o');Plans=$flowChanges.Plans;Attempts=@($flowChanges.Attempts.Values)};$null=Update-TokenForgeApplicationMetadata -Path $MetadataPath -Document $changed -Kind FlowAttempts -NativeExecutablePath $NativeExecutablePath}
   }
  }
  'Merge' {
   if (-not $InputDatabasePath) { throw 'Merge requires InputDatabasePath.' }
   foreach ($inputPath in $InputDatabasePath) { if (-not (Test-Path -LiteralPath $inputPath -PathType Leaf)) { throw 'A merge input file is missing.' } }
   $sources=@($InputDatabasePath | ForEach-Object { Get-TokenForgeScopeDatabase -Path $_ -NativeExecutablePath $NativeExecutablePath })
   $merged=Merge-TokenForgeScopeDatabase -Database $sources -Path $databasePath -NativeExecutablePath $NativeExecutablePath
   $null=Update-TokenForgeApplicationMetadata -Path $MetadataPath -Document $merged -Kind ScopeObservations -NativeExecutablePath $NativeExecutablePath
   $null=Update-TokenForgeApplicationMetadata -Path $MetadataPath -Document $merged -Kind RegistrationAttempts -NativeExecutablePath $NativeExecutablePath
   $merged
  }
  'ExportFlows' {if(-not $ExportPath){throw 'ExportFlows requires ExportPath.'};Export-TokenForgeFlowEvidence $FlowPath -OutputPath $ExportPath -NativeExecutablePath $NativeExecutablePath}
  'Export' {
   if(-not $ExportPath){throw 'Export requires ExportPath.'}
   Export-TokenForgeScopeDatabase -Database (Get-TokenForgeScopeDatabase -Path $databasePath -NativeExecutablePath $NativeExecutablePath) -Path $ExportPath
  }
 }
} finally {if($lock){$lock.Dispose()}}
