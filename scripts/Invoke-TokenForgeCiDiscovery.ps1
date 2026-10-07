#Requires -Version 7.4
<# .SYNOPSIS
Assess a rotating legacy batch or a frozen weekly batch using an action-provided cookie.
.DESCRIPTION
DataPath contains ONLY public discovery and anonymous exports. Private state is temporary.
No registration, consent, sign-in log collection, or token persistence is performed.
Weekly mode can save only authenticated-encrypted diagnostic checkpoints outside DataPath.
#>
[CmdletBinding()]
param(
 [Parameter(Mandatory)][string]$DataPath,
 [ValidateRange(1,200)][int]$ChunkSize=100,
 [ValidateRange(-1,100000)][int]$ChunkIndex=-1,
 [ValidateRange(1,2147483647)][int]$RunNumber=1,
 [switch]$PublicOnly,
 [string]$WeeklyStatePath,[string]$ReceiptPath,[string]$CheckpointPath,[string]$CheckpointInputPath,
 [ValidateRange(1,60)][int]$CheckpointIntervalSeconds=10
)
$ErrorActionPreference='Stop'
Import-Module (Join-Path $PSScriptRoot '../src/TokenForge/TokenForge.psd1') -Force
function Assert-PublicScopeExports {
 param([string]$Path)
 foreach($file in @(Get-ChildItem -LiteralPath (Join-Path $Path 'scopes') -Force -Recurse -ErrorAction SilentlyContinue)){
  if($file.PSIsContainer -or ($file.Attributes -band [IO.FileAttributes]::ReparsePoint) -or $file.Name -notmatch '^chunk-[0-9]{4,6}\.json$'){throw 'Unexpected scope export path.'}
  $doc=Get-Content $file.FullName -Raw|ConvertFrom-Json -AsHashtable
  if($doc.SchemaVersion -ne 1 -or @($doc.Keys|Where-Object {$_ -cnotin @('SchemaVersion','Observations','Disclaimer')}).Count -or $doc.Disclaimer -cne 'Observed scopes are session/tenant dependent, not universal consent or guaranteed API access.'){throw 'Invalid public scope export.'}
  if($doc.Observations -isnot [array]){throw 'Invalid export observations array.'}
  foreach($row in $doc.Observations){
   if(@($row.Keys|Where-Object {$_ -cnotin @('ClientId','ResourceId','ObservedAt','Scopes','Evidence','SignatureValidated')}).Count -or $row.Evidence -cne 'AnonymousTenantTokenObservation' -or $row.SignatureValidated -ne $false){throw 'Private or invalid export fields.'}
   $date=[DateTimeOffset]::MinValue
   if($row.ObservedAt -isnot [string] -and $row.ObservedAt -isnot [datetime] -or -not [DateTimeOffset]::TryParse([string]$row.ObservedAt,[ref]$date) -or $row.Scopes -isnot [array] -or $row.SignatureValidated -isnot [bool]){throw 'Invalid anonymous scope value types.'}
   $client=[guid]::Empty;$resource=[guid]::Empty
   if($row.ClientId -isnot [string] -or $row.ResourceId -isnot [string] -or -not [guid]::TryParse($row.ClientId,[ref]$client) -or -not [guid]::TryParse($row.ResourceId,[ref]$resource) -or @($row.Scopes|Where-Object {$_ -isnot [string] -or $_ -notmatch '^[A-Za-z0-9_.-]{1,256}$'}).Count){throw 'Invalid public scope attributes.'}
  }
 }
}
$tempRoot=[IO.Path]::GetTempPath()
# macOS exposes its system temporary path through /var -> /private/var.
# Use the canonical system path; arbitrary linked private paths remain rejected.
if($IsMacOS -and $tempRoot.StartsWith('/var/',[StringComparison]::Ordinal)){$tempRoot='/private'+$tempRoot}
$state=Join-Path $tempRoot ('TokenForge-ci-'+[guid]::NewGuid())
$cookie=$null;$graph=$null;$weekly=$null;$checkpointWatch=[Diagnostics.Stopwatch]::StartNew();$timer=[Diagnostics.Stopwatch]::StartNew()
if($WeeklyStatePath){. (Join-Path $PSScriptRoot 'TokenForgeCiState.ps1');$weekly=Get-Content -LiteralPath $WeeklyStatePath -Raw|ConvertFrom-Json -AsHashtable;Assert-TfCiState $weekly;if($ChunkIndex -lt 0){throw 'A frozen worker requires ChunkIndex.'};$selected=@(Get-TfCiMembers $weekly $ChunkIndex);$receipt=[ordered]@{SchemaVersion=1;PlanId=$weekly.PlanId;Index=$ChunkIndex;Attempt=($weekly.Batches[$ChunkIndex].Attempts+1);Status='Failed';Assessed=0;Successful=0;DurationSeconds=0;ObservedAt=[DateTimeOffset]::UtcNow.ToString('o')}}
try {
 $null=New-Item -ItemType Directory -Path $state
 if(-not $IsWindows){[IO.File]::SetUnixFileMode($state,[IO.UnixFileMode]448)}
 $null=New-Item -ItemType Directory -Path $DataPath -Force
 Assert-PublicScopeExports $DataPath
 $metadata=Join-Path $DataPath 'applications.json'
 if(Test-Path $metadata){$null=Get-TokenForgeApplicationMetadata $metadata -PublicOnly}
 $discovery=if($weekly){$weekly.Recipe.Discovery|ConvertTo-Json -Depth 100|ConvertFrom-Json}else{Update-TokenForgeDiscovery -Path (Join-Path $state 'discovery.json') -MetadataPath $metadata}
 if(-not $weekly){$null=Get-TokenForgeApplicationMetadata $metadata -PublicOnly}
 if($PublicOnly){return [pscustomobject]@{Applications=$discovery.Applications.Count;Stage='PublicDiscovery'}}
 if(-not $env:TOKENFORGE_ESTS_COOKIE){throw 'The passkey action must supply an ESTS cookie.'}
 $cookie=ConvertTo-SecureString $env:TOKENFORGE_ESTS_COOKIE -AsPlainText -Force
 $env:TOKENFORGE_ESTS_COOKIE=$null
 . (Join-Path $PSScriptRoot 'TokenForgeCiAuthentication.ps1')
 $graph=Get-TfCiGraphSession -EstsAuth $cookie
 $inventory=Get-TokenForgeTenantInventory -GraphToken $graph.AccessToken -Discovery $discovery -SkipGrants
 $ids=@($inventory.Applications|Where-Object {$_.Registration -eq 'Present' -and $_.Ownership -eq 'VerifiedMicrosoftOwner' -and $_.AccountEnabled}|Sort-Object AppId|Select-Object -ExpandProperty AppId)
 if(-not $weekly -and -not $ids.Count){throw 'No enabled Microsoft-owned applications were found.'}
 if($weekly){
  $index=$ChunkIndex;$chunkCount=$weekly.Batches.Count
  # Every published member must have an explicit inventory record, including Missing.
  if(@($inventory.Applications|Where-Object {$_.AppId -in $selected}).Count -ne $selected.Count){throw 'Frozen inventory membership is incomplete.'}
 }else{
  $chunkCount=[int][Math]::Ceiling($ids.Count/$ChunkSize)
  $index=if($ChunkIndex -lt 0){($RunNumber-1)%$chunkCount}else{$ChunkIndex}
  if($index -ge $chunkCount){throw 'ChunkIndex exceeds the current inventory.'}
  $selected=@($ids|Select-Object -Skip ($index*$ChunkSize) -First $ChunkSize)
 }
 $databasePath=Join-Path $state 'scopes.json';$flowPath=Join-Path $state 'flows.json'
 if($weekly -and $CheckpointInputPath -and (Test-Path -LiteralPath $CheckpointInputPath)){
  $context="$($env:TOKENFORGE_TENANT_FINGERPRINT)/$($env:TOKENFORGE_PRINCIPAL_FINGERPRINT)/$($weekly.PlanId)/$index"
  $bytes=Unprotect-TfCiCheckpoint ([IO.File]::ReadAllBytes($CheckpointInputPath)) $env:TOKENFORGE_CHECKPOINT_KEY $context
  try{$saved=[Text.Encoding]::UTF8.GetString($bytes)|ConvertFrom-Json -AsHashtable;Assert-TfCiKeys $saved @('Scopes','Flows');$saved.Scopes|ConvertTo-Json -Depth 100|Set-Content $databasePath;$saved.Flows|ConvertTo-Json -Depth 100|Set-Content $flowPath}
  finally{[Security.Cryptography.CryptographicOperations]::ZeroMemory($bytes)}
  if(-not $IsWindows){[IO.File]::SetUnixFileMode($databasePath,[IO.UnixFileMode]384);[IO.File]::SetUnixFileMode($flowPath,[IO.UnixFileMode]384)}
  $null=Get-TokenForgeScopeDatabase $databasePath;$null=Get-TokenForgeFlowEvidence $flowPath
 }
 function Save-WorkerCheckpoint {
  if(-not $CheckpointPath){return}
  $scope=Get-TokenForgeScopeDatabase $databasePath;$flows=Get-TokenForgeFlowEvidence $flowPath
  $json=@{Scopes=$scope;Flows=$flows}|ConvertTo-Json -Depth 100 -Compress
  $bytes=[Text.Encoding]::UTF8.GetBytes($json)
  try{$context="$($env:TOKENFORGE_TENANT_FINGERPRINT)/$($env:TOKENFORGE_PRINCIPAL_FINGERPRINT)/$($weekly.PlanId)/$ChunkIndex";$blob=Protect-TfCiCheckpoint $bytes $env:TOKENFORGE_CHECKPOINT_KEY $context;$temp=$CheckpointPath+'.tmp';[IO.File]::WriteAllBytes($temp,$blob);Move-Item -LiteralPath $temp -Destination $CheckpointPath -Force}
  finally{[Security.Cryptography.CryptographicOperations]::ZeroMemory($bytes)}
  $checkpointWatch.Restart()
 }
 $options=@{Inventory=$inventory;EstsAuth=$cookie;CookieName=$env:TOKENFORGE_COOKIE_NAME;DatabasePath=$databasePath;ClientId=$selected;Tenant='organizations';MaxApplications=$selected.Count;MaxRedirects=2}
 if($weekly){$options.ResourceId=[guid]'00000003-0000-0000-c000-000000000000';$options.FlowDatabasePath=$flowPath;$options.CohortFingerprint=$weekly.PlanId;$options.MaxRedirects=$weekly.Recipe.MaxRedirects;$options.ExploreAllFlows=$weekly.Recipe.Mode -eq 'Deep';$options.StopOnTransientFailure=$true;$options.CheckpointAction={if($checkpointWatch.Elapsed.TotalSeconds -ge $CheckpointIntervalSeconds){Save-WorkerCheckpoint};if($timer.Elapsed.TotalSeconds -ge 2400){Save-WorkerCheckpoint;throw 'Worker time budget reached; resume encrypted checkpoints.'}}}
 else{$options.Plan=Get-TokenForgeProbePlan -Inventory $inventory -ClientId $selected -GraphOnly}
 $outcomes=@{}
 Invoke-TokenForgeScopeProbe @options|ForEach-Object {
  if($_.Outcome -eq 'ContextMismatch'){throw 'Issuance context mismatch.'}
  if($weekly -and $checkpointWatch.Elapsed.TotalSeconds -ge $CheckpointIntervalSeconds){Save-WorkerCheckpoint}
  if(-not $outcomes.ContainsKey($_.Outcome)){$outcomes[$_.Outcome]=0};$outcomes[$_.Outcome]++
 }
 if($weekly){
  $current=Get-TokenForgeScopeDatabase $databasePath -Latest -TenantFingerprint $env:TOKENFORGE_TENANT_FINGERPRINT -PrincipalFingerprint $env:TOKENFORGE_PRINCIPAL_FINGERPRINT
  $rows=@($current.Observations|Where-Object {$_.ClientId -in $selected -and $_.ResourceId -eq '00000003-0000-0000-c000-000000000000'})
  if($rows.Count -ne $selected.Count -or @($rows|Where-Object Outcome -eq ContextMismatch).Count){throw 'Frozen assessment coverage is incomplete.'}
  $receipt.Status='Complete';$receipt.Assessed=$rows.Count;$receipt.Successful=@($rows|Where-Object Outcome -eq Succeeded).Count
 }
 $exportDirectory=Join-Path $DataPath 'scopes'
 $null=New-Item -ItemType Directory -Path $exportDirectory -Force
 $exportPath=Join-Path $exportDirectory ('chunk-{0:D4}.json' -f $index)
 $freshPath=Join-Path $state 'anonymous-scopes.json'
 if($weekly){$current.Observations=$rows}
 $exportDatabase=if($weekly){$current}else{Get-TokenForgeScopeDatabase $databasePath}
 Export-TokenForgeScopeDatabase -Database $exportDatabase -Path $freshPath
 $public=Get-Content $freshPath -Raw|ConvertFrom-Json
 $previous=if(Test-Path $exportPath){@((Get-Content $exportPath -Raw|ConvertFrom-Json).Observations)}else{@()}
 $latest=@{}
 foreach($row in @(@($previous)+@($public.Observations)|Sort-Object {([DateTimeOffset]$_.ObservedAt)})){$row.ObservedAt=([DateTimeOffset]$row.ObservedAt).ToUniversalTime().ToString('o');$latest["$($row.ClientId)/$($row.ResourceId)"]=$row}
 $public.Observations=@($latest.Values|Sort-Object ClientId,ResourceId)
 & (Get-Module TokenForge) {param($document,$path) Save-TokenForgeDocument -Document $document -Path $path} $public $exportPath
 Assert-PublicScopeExports $DataPath
 if(-not $weekly){$null=Get-TokenForgeApplicationMetadata $metadata -PublicOnly}
 [pscustomobject]@{Applications=$discovery.Applications.Count;EligibleApplications=$ids.Count;ChunkIndex=$index;ChunkCount=$chunkCount;Selected=$selected.Count;Outcomes=$outcomes}
} catch {
 if($weekly){$receipt.Status='Failed';$receipt.Assessed=0;$receipt.Successful=0}
 # Do not allow external action/identity response bodies into the runner log.
 throw 'CI discovery failed. No private state is published; inspect bounded action status and rerun.'
 } finally {
 try{
 if($weekly){
  $receipt.DurationSeconds=[Math]::Round($timer.Elapsed.TotalSeconds,3);$receipt.ObservedAt=[DateTimeOffset]::UtcNow.ToString('o')
  if($CheckpointPath -and (Test-Path (Join-Path $state 'flows.json'))){
   try{Save-WorkerCheckpoint}catch{$receipt.Status='Failed';$receipt.Assessed=0;$receipt.Successful=0}
  }
  if($ReceiptPath){$receipt|ConvertTo-Json -Depth 20|Set-Content -LiteralPath $ReceiptPath}
 }
 }finally{
 if($graph){foreach($name in @('AccessToken','RefreshToken')){if($graph.PSObject.Properties[$name] -and $graph.$name){$graph.$name.Dispose()}}}
 if($cookie){$cookie.Dispose()};$env:TOKENFORGE_ESTS_COOKIE=$null
 if(Test-Path $state){Remove-Item -LiteralPath $state -Recurse -Force}
 }
}
