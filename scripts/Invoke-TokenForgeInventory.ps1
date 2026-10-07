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
 [Parameter(Mandatory)][ValidateSet('Discover','SignIns','Inventory','Register','Probe','Merge','Export','Report','ExportFlows','NewCohort','ProbeChunk','CohortStatus')][string]$Action,
 [Parameter(Mandatory)][string]$StatePath,
 [string]$MetadataPath,[string]$DatabasePath,[string]$FlowPath,[string]$NativeExecutablePath,[switch]$ExploreAllFlows,[switch]$SummaryOnly,
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
 [ValidateRange(-1,100000)][int]$ChunkIndex=-1,[ValidateRange(1,1000)][int]$BatchSize=25
)
$ErrorActionPreference='Stop'
Import-Module (Join-Path $PSScriptRoot '../src/TokenForge/TokenForge.psd1') -Force
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
  'CohortStatus' {
   if(-not $CohortId){throw 'CohortStatus requires CohortId.'}
   Get-TokenForgeResearchCohort $DatabasePath $CohortId -NativeExecutablePath $NativeExecutablePath
  }
  'ProbeChunk' {
   if(-not $CohortId -or -not $EstsAuth){throw 'ProbeChunk requires CohortId and EstsAuth.'}
   $inventory=Get-Content -LiteralPath $inventoryPath -Raw|ConvertFrom-Json
   if($PrincipalFingerprint){$cohort=Get-TokenForgeResearchCohort $DatabasePath $CohortId -NativeExecutablePath $NativeExecutablePath;if($PrincipalFingerprint -ne $cohort.Cohort.PrincipalFingerprint){throw 'Principal selection differs from the frozen cohort.'}}
   Invoke-TokenForgeResearchChunk -Inventory $inventory -EstsAuth $EstsAuth -CookieName $CookieName -DatabasePath $DatabasePath -CohortId $CohortId -ChunkIndex $ChunkIndex -FlowDatabasePath $FlowPath -MetadataPath $MetadataPath -NativeExecutablePath $NativeExecutablePath -WhatIf:$WhatIfPreference -Confirm:$false
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
   $inventory|ConvertTo-Json -Depth 100|Set-Content -LiteralPath $inventoryPath -Encoding utf8
   if (-not $IsWindows) { [IO.File]::SetUnixFileMode($inventoryPath, ([IO.UnixFileMode]::UserRead -bor [IO.UnixFileMode]::UserWrite)) }
   $null=Update-TokenForgeApplicationMetadata -Path $MetadataPath -Document $inventory -Kind Inventory -NativeExecutablePath $NativeExecutablePath
   $inventory
  }
  'Register' {
   if(-not $GraphToken){throw 'Register requires GraphToken.'}
   $inventory=Get-Content -LiteralPath $inventoryPath -Raw|ConvertFrom-Json
   Sync-TokenForgeApplicationRegistration -Inventory $inventory -GraphToken $GraphToken -DatabasePath $databasePath -ClientId $ClientId -MaxApplications $MaxApplications -ResolvePublishedCandidates:$ResolvePublishedCandidates -ResolveSignInCandidates:$ResolveSignInCandidates -RetryFailures:$RetryFailures -MetadataPath $MetadataPath -NativeExecutablePath $NativeExecutablePath -WhatIf:$WhatIfPreference
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
  'Report' {
   $options=@{MetadataPath=$MetadataPath;FlowPath=$FlowPath;SummaryOnly=$SummaryOnly;NativeExecutablePath=$NativeExecutablePath}
   if($PrincipalFingerprint){$inventory=Get-Content $inventoryPath -Raw|ConvertFrom-Json;$options.TenantFingerprint=$inventory.TenantFingerprint;$options.PrincipalFingerprint=$PrincipalFingerprint}
   Get-TokenForgeResearchCoverage @options
  }
  'ExportFlows' {if(-not $ExportPath){throw 'ExportFlows requires ExportPath.'};Export-TokenForgeFlowEvidence $FlowPath -OutputPath $ExportPath -NativeExecutablePath $NativeExecutablePath}
  'Export' {
   if(-not $ExportPath){throw 'Export requires ExportPath.'}
   Export-TokenForgeScopeDatabase -Database (Get-TokenForgeScopeDatabase -Path $databasePath -NativeExecutablePath $NativeExecutablePath) -Path $ExportPath
  }
 }
} finally {if($lock){$lock.Dispose()}}
