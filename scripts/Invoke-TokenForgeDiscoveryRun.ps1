#Requires -Version 7.6
<# .SYNOPSIS
Run local application discovery without an agent or hosted runner.
#>
[CmdletBinding()]
param(
 [Parameter(Mandatory)][string]$StatePath,
 [Parameter(Mandatory)][string]$NativeExecutablePath,
 [securestring]$EstsAuth,
 [string]$PasskeyPath,[string]$XdrModulePath,
 [switch]$NewRun,[switch]$RefreshDiscovery,[switch]$RefreshInventory,[switch]$GraphOnly,
 [switch]$FrozenCycle,
 [Nullable[DateTimeOffset]]$SessionExpiresAt,
 [string]$PackageManifestPath,
 [ValidatePattern('^[a-f0-9]{64}$')][string]$PackageManifestSha256,
 [ValidatePattern('^[a-f0-9]{40}$')][string]$PackageSourceRevision,
 [switch]$ExploreAllFlows=$true,
 [ValidateRange(1,1000)][int]$BatchSize=25,
 [ValidateRange(1,1000)][int]$MaxRedirects=8,
 [ValidateRange(1,100000)][int]$MaxChunks=100000,
 [ValidateRange(1,10080)][int]$MaxMinutes=15,
 [ValidateRange(0,3)][int]$MaxTransientRetries=3,
 [ValidateRange(1,300)][int]$RetryDelaySeconds=30,
 [ValidateRange(0,1000)][int]$MaxPendingClients=0,
 [switch]$RecoverUnknown,[switch]$ResumePaused,
 [ValidateRange(0,1000000)][int]$MaxIssuanceAttempts=30,
 [ValidateRange(0,1000000)][int]$MaxBootstrapAttempts=1,
 [ValidateRange(0,1000000)][int]$MaxBootstrapRequests=20,
 [ValidateRange(0,1000000)][int]$MaxInventoryRequests=100,
 [ValidateRange(0,1000000)][int]$MaxInventoryPages=50,
 [ValidateRange(0,1000000)][int]$MaxSourceRequests=3,
 [ValidateRange(0,1000000)][int]$MaxTotalRequests=300,
 [ValidateRange(0.001,30)][double]$TransportTimeoutSeconds=30,
 [Threading.CancellationToken]$CancellationToken=[Threading.CancellationToken]::None
)
$ErrorActionPreference='Stop'
$cookie=$null;$graph=$null;$runLock=$null;$budget=$null;$failure='Configuration'
$invocationStarted=[DateTimeOffset]::UtcNow.ToString('o');$invocationTimer=[Diagnostics.Stopwatch]::StartNew()
$cycle=$null;$cyclePath=$null
# The external manifest digest is the trust anchor. This verifies the complete local payload,
# including the running wrapper/module, rather than trusting an executable hash alone.
function Assert-TfFrozenCyclePackage {
 if(-not $PackageManifestPath -or -not $PackageManifestSha256 -or -not $PackageSourceRevision){throw 'Frozen cycle requires reviewed package pins.'}
 $packageRoot=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
 $manifest=[IO.Path]::GetFullPath($PackageManifestPath)
 if((Split-Path $manifest -Parent) -cne $packageRoot -or [IO.Path]::GetFullPath($NativeExecutablePath) -cne (Join-Path $packageRoot 'tokenforge')){throw 'Run the wrapper and executable from the reviewed complete package.'}
 for($cursor=$packageRoot;$cursor;$cursor=[IO.Path]::GetDirectoryName($cursor)){if((Get-Item -LiteralPath $cursor -Force).LinkType){throw 'Linked package path.'}}
 if((Get-Item -LiteralPath $manifest -Force).LinkType -or (Get-FileHash -LiteralPath $manifest -Algorithm SHA256).Hash.ToLowerInvariant() -cne $PackageManifestSha256){throw 'Package manifest pin mismatch.'}
 $document=ConvertFrom-Json -InputObject ([IO.File]::ReadAllText($manifest)) -AsHashtable -DateKind String -Depth 100
 if($document.schemaVersion -ne 1 -or $document.sourceRevision -cne $PackageSourceRevision -or $document.files -isnot [Collections.IDictionary] -or $document.files.Count -lt 4 -or $document.files.Count -gt 4096){throw 'Invalid package source or payload inventory.'}
 foreach($required in @('tokenforge','scripts/Invoke-TokenForgeDiscoveryRun.ps1','src/TokenForge/TokenForge.psd1','src/TokenForge/TokenForge.psm1')){if(-not $document.files.Contains($required)){throw 'Incomplete package.'}}
 $payload=@(Get-ChildItem -LiteralPath $packageRoot -Recurse -Force)
 if(@($payload|Where-Object LinkType).Count -or @($payload|Where-Object {-not $_.PSIsContainer}).Count -ne $document.files.Count+1){throw 'Unexpected package member.'}
 $seen=[Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
 foreach($name in $document.files.Keys){
  if($name -isnot [string] -or $name.Contains('\') -or @($name.ToCharArray()|Where-Object {[int]$_ -lt 32 -or [int]$_ -eq 127}).Count -or $name.StartsWith('/') -or @($name.Split('/')|Where-Object {$_ -in @('','.','..')}).Count -or -not $seen.Add($name)){throw 'Invalid package payload path.'}
  $file=Get-Item -LiteralPath (Join-Path $packageRoot $name) -Force
  $expected=$document.files[$name]
  if($file.PSIsContainer -or $file.LinkType -or $expected.sha256 -cnotmatch '^[a-f0-9]{64}$' -or ($expected.bytes -isnot [int] -and $expected.bytes -isnot [long]) -or $expected.bytes -ne $file.Length -or (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash.ToLowerInvariant() -cne $expected.sha256){throw 'Package payload mismatch.'}
 }
 foreach($file in $payload|Where-Object {-not $_.PSIsContainer}){if($file.FullName -cne $manifest -and -not $seen.Contains([IO.Path]::GetRelativePath($packageRoot,$file.FullName))){throw 'Unexpected package member.'}}
}
function Save-TfFrozenCycleReceipt($Summary) {
 if(-not $cycle){return}
 # Use only closed vocabulary/numeric fields from the collector. Never copy exception text.
 $allowed=@('Running','Complete','StructurallyExcluded','BudgetReached','SessionExpired','Cancelled','Paused','RequestBlocked','TransientExhausted','InFlightUnknown','AccountMismatch','Failed','Pending','InventoryStale','Configuration','Busy')
 if($Summary){
  $status=[string]$Summary.Status
  if($status -cnotin $allowed){throw 'Invalid cycle summary status.'}
  $cycle.Status=$status
  $cycle.Reason=if($Summary.PSObject.Properties['Reason'] -and [string]$Summary.Reason -cin $allowed){[string]$Summary.Reason}else{$status}
  if($budget.StopReason -cin @('SessionExpired','Cancelled') -and -not $budget.PendingRequest){$cycle.Status=$budget.StopReason;$cycle.Reason=$budget.StopReason}
  if($budget.PendingRequest -or ($budget.BootstrapIntent -and $budget.BootstrapIntent.State -ceq 'Started')){$cycle.Status='InFlightUnknown';$cycle.Reason='InFlightUnknown'}
  foreach($key in @('Clients','CompletedClients','PendingClients')){
   if($Summary.PSObject.Properties[$key]){if(($Summary.$key -isnot [int] -and $Summary.$key -isnot [long]) -or $Summary.$key -lt 0){throw 'Invalid cycle count.'};$cycle[$key]=$Summary.$key}
  }
  if($null -ne $cycle.Clients -and ($cycle.CompletedClients+$cycle.PendingClients -ne $cycle.Clients)){throw 'Invalid cycle counts.'}
 }
 $cycle.UpdatedAt=[DateTimeOffset]::UtcNow.ToString('o')
 $cycle.OperationBudget=& (Get-Module TokenForge) {param($b) Get-TokenForgeOperationBudgetSummary $b} $budget
 & (Get-Module TokenForge) {param($p,$d) Save-TokenForgeDocument -Path $p -Document $d} $cyclePath $cycle
}
$budgetOptions=@{MaxSeconds=($MaxMinutes*60);MaxIssuanceAttempts=$MaxIssuanceAttempts;MaxBootstrapAttempts=$MaxBootstrapAttempts;MaxBootstrapRequests=$MaxBootstrapRequests;MaxInventoryRequests=$MaxInventoryRequests;MaxInventoryPages=$MaxInventoryPages;MaxSourceRequests=$MaxSourceRequests;MaxTotalRequests=$MaxTotalRequests;MaxTransientRetries=$MaxTransientRetries;TransportTimeoutSeconds=$TransportTimeoutSeconds;CancellationToken=$CancellationToken}
try{
 Write-Verbose 'Discovery stage: Configuration'
 if($FrozenCycle -and (-not $IsLinux -or -not $SessionExpiresAt -or $NewRun -or $RefreshDiscovery -or $RefreshInventory)){throw 'Frozen cycle requires Linux, a declared session deadline and unchanged saved inputs.'}
 if(-not $FrozenCycle -and ($SessionExpiresAt -or $PackageManifestPath -or $PackageManifestSha256 -or $PackageSourceRevision)){throw 'Cycle options require FrozenCycle.'}
 if($FrozenCycle){Assert-TfFrozenCyclePackage}
 Import-Module (Join-Path $PSScriptRoot '../src/TokenForge/TokenForge.psd1') -Force -Verbose:$false
 $budget=& (Get-Module TokenForge) {param($options) $script:OperationBudget=New-TokenForgeOperationBudget @options;$script:OperationBudget} $budgetOptions
 $budget.Timer=$invocationTimer;$budget.StartedAt=$invocationStarted
 if(-not $EstsAuth -or $PasskeyPath -or $XdrModulePath){throw 'Bounded discovery requires an explicitly supplied existing SecureString session; obtain or renew it separately.'}
 & (Get-Module TokenForge) {param($budget) Assert-TokenForgeOperationBudget $budget} $budget
 $root=Split-Path ([TokenForge.Core.V0220.PrivateFiles]::Resolve((Join-Path $StatePath '.state'),(-not $FrozenCycle))) -Parent
 $lockPath=[TokenForge.Core.V0220.PrivateFiles]::Resolve((Join-Path $root '.discovery.lock'),$true)
 $runLock=[TokenForge.Core.V0220.PrivateFiles]::Open($lockPath,(-not (Test-Path -LiteralPath $lockPath)))
 $budget.LedgerPath=Join-Path $root ('budget-intent-'+[guid]::NewGuid().ToString('N')+'.json')
 & (Get-Module TokenForge) {param($budget) Save-TokenForgeBudgetLedger $budget} $budget
 $inventoryPath=Join-Path $root 'inventory.json'
 $old=$null
 if($FrozenCycle){
  $budget.SessionExpiresAt=$SessionExpiresAt;$budget.StopFilePath=Join-Path $root 'stop.requested'
  $cohortId=& (Get-Module TokenForge) {param($p) Get-TokenForgeDiscoveryRunId $p} (Join-Path $root 'discovery-run.json')
  $cyclePath=Join-Path $root 'vm-cycle.json'
  $cycle=[ordered]@{SchemaVersion=1;Kind='TokenForgeFrozenCycle';CycleId=[guid]::NewGuid().ToString('N');CohortId=$cohortId;PackageSourceRevision=$PackageSourceRevision;PackageManifestSha256=$PackageManifestSha256;StartedAt=[DateTimeOffset]::UtcNow.ToString('o');UpdatedAt=$null;Status='Running';Reason='Running';Clients=$null;CompletedClients=$null;PendingClients=$null;CheckpointsRetained=$true;Publication='NotAttempted';CredentialOutput=$false;OperationBudget=$null}
  Save-TfFrozenCycleReceipt
 }
 if(Test-Path -LiteralPath $inventoryPath){
  $path=[TokenForge.Core.V0220.PrivateFiles]::Resolve($inventoryPath,$false)
  $file=Get-Item -LiteralPath $path
  if($file.Length -gt 134217728){throw 'Oversized saved inventory.'}
  $old=[TokenForge.Core.DiscoverySourceClaims]::ReadMetadataJson((Get-Content -LiteralPath $path -Raw))
 }
 if($FrozenCycle){
  $failure='InventoryStale'
  if(-not $old){throw 'Frozen inventory is required.'}
  $captured=[TokenForge.Core.V0240.TimestampPolicy]::Parse($old.CapturedAt)
  if($captured -lt [DateTimeOffset]::UtcNow.AddHours(-24) -or $captured -gt [DateTimeOffset]::UtcNow.AddMinutes(5)){throw 'Frozen inventory needs reviewed recovery.'}
  if(-not (Test-Path -LiteralPath (Join-Path $root 'discovery.json') -PathType Leaf)){throw 'Frozen discovery input is required.'}
  $failure='Configuration'
  & (Get-Module TokenForge) {param($b) Assert-TokenForgeOperationBudget $b} $budget
 }
 & (Get-Module TokenForge) {param($root,$budget,$recover) Assert-TokenForgePendingRequestRecovery -StatePath $root -Budget $budget -RecoverUnknown:$recover} $root $budget ([bool]$RecoverUnknown)
 $failure='Authentication'
 Write-Verbose 'Discovery stage: Authentication'
 $cookie=$EstsAuth.Copy()
 $request=[pscustomobject]@{ClientId='14d82eec-204b-4c2f-b7e8-296a70dab67e';ResourceId='00000003-0000-0000-c000-000000000000';ResourceUri='00000003-0000-0000-c000-000000000000';Scopes=@('User.Read','Application.Read.All');OAuthScopes=@('00000003-0000-0000-c000-000000000000/User.Read','00000003-0000-0000-c000-000000000000/Application.Read.All');RedirectUri='https://login.microsoftonline.com/common/oauth2/nativeclient';Tenant='organizations';Spa=$false;Discovery=$false}
 $failure='Authorization'
 Write-Verbose 'Discovery stage: Authorization'
 & (Get-Module TokenForge) {param($root,$budget,$recover,$resume) Start-TokenForgeBootstrapIntent -Path (Join-Path $root 'bootstrap-intent.json') -Budget $budget -RecoverUnknown:$recover -ResumePaused:$resume} $root $budget ([bool]$RecoverUnknown) ([bool]$ResumePaused)
 try{
  $graph=Get-TokenForgeToken -Request $request -EstsAuth $cookie -OperationBudget $budget -WarningAction SilentlyContinue -Verbose:$false
 }catch{
  & (Get-Module TokenForge) {param($budget,$errorRecord) $classification=Get-TokenForgeProbeFailure $errorRecord;if($classification.Status -notin @('BudgetReached','InFlightUnknown')){Complete-TokenForgeBootstrapIntent -Budget $budget -State $classification.Status}} $budget $_
  throw
 }finally{$budget.IdentityCategory='Identity'}
 $claims=$graph.TokenClaims
 if(-not $claims -or $claims.TenantFingerprint -cnotmatch '^[a-f0-9]{64}$' -or $claims.PrincipalFingerprint -cnotmatch '^[a-f0-9]{64}$' -or $claims.ClientId -cne $request.ClientId -or $claims.Audience -notin @($request.ResourceId,'https://graph.microsoft.com','https://graph.microsoft.com/')){& (Get-Module TokenForge) {param($budget) Complete-TokenForgeBootstrapIntent -Budget $budget -State AccountMismatch;Throw-TokenForgeCollectorState AccountMismatch} $budget}
 if(-not @($claims.Scopes|Where-Object {$_ -cin @('Application.Read.All','Application.ReadWrite.All','Directory.Read.All','Directory.ReadWrite.All')}).Count){& (Get-Module TokenForge) {param($budget) Complete-TokenForgeBootstrapIntent -Budget $budget -State RequestBlocked;Throw-TokenForgeCollectorState RequestBlocked} $budget}
 if($old -and ($old.TenantFingerprint -cne $claims.TenantFingerprint -or $old.PrincipalFingerprint -cne $claims.PrincipalFingerprint)){& (Get-Module TokenForge) {param($budget) Complete-TokenForgeBootstrapIntent -Budget $budget -State AccountMismatch;Throw-TokenForgeCollectorState AccountMismatch} $budget}
 & (Get-Module TokenForge) {param($budget) Complete-TokenForgeBootstrapIntent $budget} $budget
 $failure='Identity'
 Write-Verbose 'Discovery stage: Identity'
 & (Get-Module TokenForge) {
  param($token)
  $VerbosePreference='SilentlyContinue'
  $payload=ConvertFrom-TokenForgeJwtPayload -AccessToken $token
  $me=Invoke-TokenForgeGraph -AccessToken $token -Uri 'https://graph.microsoft.com/v1.0/me?$select=id'
  if(-not $payload['oid'] -or [string]$me['id'] -ine [string]$payload['oid']){Throw-TokenForgeCollectorState AccountMismatch}
 } $graph.AccessToken
 $stage=Join-Path $PSScriptRoot 'Invoke-TokenForgeInventory.ps1'
 $common=@{StatePath=$root;NativeExecutablePath=$NativeExecutablePath;MetadataPath=(Join-Path $root 'applications.sqlite');DatabasePath=(Join-Path $root 'scopes.sqlite');FlowPath=(Join-Path $root 'flows.sqlite');OperationBudget=$budget}
 $failure='PublicSources'
 Write-Verbose 'Discovery stage: PublicSources'
 if($RefreshDiscovery -or -not (Test-Path (Join-Path $root 'discovery.json'))){$null=& $stage -Action Discover @common -Verbose:$false}
 $expired=-not $old -or [TokenForge.Core.V0240.TimestampPolicy]::Parse($old.CapturedAt) -lt [DateTimeOffset]::UtcNow.AddHours(-24)
 $failure='Inventory'
 Write-Verbose 'Discovery stage: Inventory'
 if(-not $FrozenCycle -and ($RefreshInventory -or $RefreshDiscovery -or $expired)){$inventory=& $stage -Action Inventory -GraphToken $graph.AccessToken @common -Verbose:$false}else{$inventory=$old}
 if($inventory.TenantFingerprint -cne $claims.TenantFingerprint -or $inventory.PrincipalFingerprint -cne $claims.PrincipalFingerprint){& (Get-Module TokenForge) {Throw-TokenForgeCollectorState AccountMismatch}}
 $failure='Discovery'
 Write-Verbose 'Discovery stage: Discovery'
 $result=Invoke-TokenForgeDiscoveryRun -Inventory $inventory -EstsAuth $cookie -StatePath $root -NativeExecutablePath $NativeExecutablePath -NewRun:$NewRun -GraphOnly:$GraphOnly -BatchSize $BatchSize -MaxPendingClients $MaxPendingClients -MaxRedirects $MaxRedirects -MaxChunks $MaxChunks -MaxMinutes $MaxMinutes -MaxTransientRetries $MaxTransientRetries -RetryDelaySeconds $RetryDelaySeconds -ExploreAllFlows:$ExploreAllFlows -OperationBudget $budget -RecoverUnknown:$RecoverUnknown -ResumePaused:$ResumePaused -Verbose:$false
 Write-Verbose 'Discovery stage: Finished'
 Save-TfFrozenCycleReceipt $result
 if($cycle -and $cycle.Status -cne $result.Status){$result.Status=$cycle.Status;if($result.PSObject.Properties['Reason']){$result.Reason=$cycle.Reason}}
 $result|ConvertTo-Json -Depth 8 -Compress
 # Both terminal states leave no selected work pending. Uncertainty and all
 # unfinished/failed states still stop nonzero after receipt precedence applies.
 if($result.Status -cin @('Complete','StructurallyExcluded')){exit 0}
 exit 1
}catch{
 $summary=if($budget){& (Get-Module TokenForge) {param($errorRecord,$stage,$budget) Get-TokenForgeCollectorStopSummary -ErrorRecord $errorRecord -Stage $stage -Budget $budget} $_ $failure $budget}else{[pscustomobject]@{SchemaVersion=1;Status='Failed';Reason='Configuration';Stage='Configuration';CheckpointsRetained=$true;CredentialOutput=$false;Publication='NotAttempted'}}
 if($cycle){
  if($failure -eq 'InventoryStale'){$summary.Status='InventoryStale';$summary.Reason='InventoryStale'}
  try{Save-TfFrozenCycleReceipt $summary;$summary.Status=$cycle.Status;$summary.Reason=$cycle.Reason}catch{
   # The old receipt and authoritative journals remain intact; a receipt error is never success.
   $summary=[pscustomobject]@{SchemaVersion=1;Status='Failed';Reason='ReceiptWriteFailed';CheckpointsRetained=$true;CredentialOutput=$false;Publication='NotAttempted'}
  }
 }
 $summary|ConvertTo-Json -Depth 8 -Compress
 exit 1
}finally{
 if($budget){& (Get-Module TokenForge) {$script:OperationBudget=$null}}
 if($runLock){$runLock.Dispose()}
 if($cookie){$cookie.Dispose()}
 if($graph){foreach($name in @('AccessToken','RefreshToken')){if($graph.PSObject.Properties[$name] -and $graph.$name){$graph.$name.Dispose()}}}
}
