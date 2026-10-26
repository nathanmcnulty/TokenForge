# Workstation public exchange import. No identity or account operations.
Set-StrictMode -Version Latest
function Initialize-TokenForgeHealthSyncModule {
 param([string]$NativeExecutablePath)
 Initialize-TokenForgeHealthRuntime -NativeExecutablePath $NativeExecutablePath
}
function Resolve-TokenForgeHealthPrivateFile {
 param([string]$Path,[switch]$CreateDirectory)
 [TokenForge.Core.V0220.PrivateFiles]::Resolve([IO.Path]::GetFullPath($Path),[bool]$CreateDirectory)
}
function New-TokenForgeHealthSyncPrivateDirectory {
 param([string]$Path)
 $full=[IO.Path]::GetFullPath($Path)
 if(-not [IO.Directory]::Exists($full)){
  $parent=Split-Path $full -Parent
  if(-not [IO.Directory]::Exists($parent)){New-TokenForgeHealthSyncPrivateDirectory $parent}
  $null=[IO.Directory]::CreateDirectory($full,[IO.UnixFileMode]448)
 }
 $null=Resolve-TokenForgeHealthPrivateFile (Join-Path $full '.private')
}
function Write-TokenForgeHealthPrivateJson {
 param([string]$Path,$Value,[switch]$Immutable)
 $path=Resolve-TokenForgeHealthPrivateFile $Path -CreateDirectory
 $bytes=[Text.Encoding]::UTF8.GetBytes(($Value|ConvertTo-Json -Depth 32 -Compress))
 $temp=$path+'.'+[guid]::NewGuid().ToString('N')+'.tmp'
 $file=[TokenForge.Core.V0220.PrivateFiles]::Open($temp,$true)
 try{$file.Write($bytes);$file.Flush($true)}finally{$file.Dispose()}
 try{[IO.File]::Move($temp,$path,(-not $Immutable))}finally{if([IO.File]::Exists($temp)){[IO.File]::Delete($temp)}}
}
function Get-TokenForgePublicHealthStatus {
 param([Parameter(Mandatory)][string]$StatePath,[DateTimeOffset]$Now=[DateTimeOffset]::UtcNow)
 $root=[IO.Path]::GetFullPath($StatePath);$index=Join-Path $root 'public-health-status.json'
 if(-not [IO.File]::Exists($index)){$state=[ordered]@{schemaVersion=1;transfer='NotStarted';import=$(if([IO.File]::Exists((Join-Path $root 'public-health-pending.json'))){'RecoveryRequired'}else{'NotStarted'});collection='Unknown';lastCollectedAt=$null;lastCompleteAt=$null;stale=$true;collectionHistoryGap=$false;pendingDeepWork='Unassessed';publication='NotRequested'}}else{
 # Cheap status reads one bounded receipt, never a SQLite history projection.
 $index=Resolve-TokenForgeHealthPrivateFile $index
 if(([IO.FileInfo]$index).Length -gt 32768){throw 'Health status receipt exceeds limit.'}
 $state=Get-Content -LiteralPath $index -Raw|ConvertFrom-Json -DateKind String -AsHashtable
 }
 $state.stale=($null -eq $state.lastCompleteAt -or ($Now-[DateTimeOffset]::Parse($state.lastCompleteAt)).TotalHours -gt 48)
 $transfer=Join-Path $root 'public-health-transfer.json'
 if([IO.File]::Exists($transfer)){
  $transfer=Resolve-TokenForgeHealthPrivateFile $transfer
  if(([IO.FileInfo]$transfer).Length -gt 4096){throw 'Transfer receipt exceeds limit.'}
  $saved=Get-Content -LiteralPath $transfer -Raw|ConvertFrom-Json -DateKind String -AsHashtable
  $state.transfer=$saved.state
 }
 $pending=Join-Path $root 'public-health-pending.json'
 if([IO.File]::Exists($pending)){$state.import='RecoveryRequired'}
 return $state
}
function Import-TokenForgePublicHealthExchange {
 [CmdletBinding()]
 param([Parameter(Mandatory)][string]$ExchangePath,[Parameter(Mandatory)][string]$StatePath,[Parameter(Mandatory)][string]$NativeExecutablePath)
 Initialize-TokenForgeHealthSyncModule $NativeExecutablePath
 # Validate before any private-state mutation. Revalidate immutable staging before import.
 $validated=Read-TokenForgeHealthExchange -Path $ExchangePath
 $root=Split-Path (Resolve-TokenForgeHealthPrivateFile (Join-Path $StatePath '.state') -CreateDirectory) -Parent
 $lockPath=Resolve-TokenForgeHealthPrivateFile (Join-Path $root '.writer.lock')
 $lock=$null
 try{
  try{$lock=[TokenForge.Core.V0220.PrivateFiles]::Open($lockPath,(-not [IO.File]::Exists($lockPath)))}catch{throw 'Workstation state is in use by another writer.'}
  $pendingPath=Join-Path $root 'public-health-pending.json'
  # Pending evidence is authoritative after interruption: finish it before accepting new input.
  if([IO.File]::Exists($pendingPath)){
   $pendingPath=Resolve-TokenForgeHealthPrivateFile $pendingPath
   if(([IO.FileInfo]$pendingPath).Length -gt 16384){throw 'Invalid pending health receipt.'}
   $pending=Get-Content -LiteralPath $pendingPath -Raw|ConvertFrom-Json -DateKind String -AsHashtable
   if($pending.Keys.Count -ne 2 -or $pending.schemaVersion -ne 1 -or $pending.exchangeId -cnotmatch '^[a-f0-9]{64}$'){throw 'Invalid pending health receipt.'}
   Complete-TokenForgeHealthPending -Root $root -ExchangeId $pending.exchangeId -NativeExecutablePath $NativeExecutablePath
  }
  $id=(Get-FileHash -LiteralPath (Join-Path $ExchangePath manifest.json) -Algorithm SHA256).Hash.ToLowerInvariant()
  $stage=Join-Path $root ('public-health-receipts/'+$id+'/exchange')
  $receipt=Join-Path (Split-Path $stage -Parent) 'import.json'
  if([IO.File]::Exists($receipt)){
   Write-TokenForgeHealthPrivateJson (Join-Path $root 'public-health-transfer.json') @{schemaVersion=1;state='Complete';source='SavedExchange'}
   return Get-TokenForgePublicHealthStatus $root
  }
  New-TokenForgeHealthSyncPrivateDirectory $stage
  foreach($name in @('manifest.json','health.json','metadata.json')){
   $source=Join-Path $ExchangePath $name;$dest=Join-Path $stage $name
   if([IO.File]::Exists($dest) -and (Get-FileHash -LiteralPath $source).Hash -ceq (Get-FileHash -LiteralPath $dest).Hash){continue}
   $dest=Resolve-TokenForgeHealthPrivateFile $dest
   $temp=Resolve-TokenForgeHealthPrivateFile (Join-Path (Split-Path $stage -Parent) ($name+'.'+[guid]::NewGuid().ToString('N')+'.tmp'))
   $out=[TokenForge.Core.V0220.PrivateFiles]::Open($temp,$true)
   try{
    $input=[IO.FileStream]::new($source,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
    try{if($input.Length -gt 67108864){throw 'Exchange member exceeds transfer limit.'};$buffer=[byte[]]::new(65536);$copied=0L;while(($n=$input.Read($buffer,0,$buffer.Length)) -gt 0){$copied+=$n;if($copied -gt 67108864){throw 'Exchange member exceeds transfer limit.'};$out.Write($buffer,0,$n)};$out.Flush($true)}finally{$input.Dispose()}
   }finally{$out.Dispose()}
   # Only uncommitted staging may be repaired. Completed receipts returned above;
   # pending imports were reconciled before this point. Rename avoids partial members.
   [IO.File]::Move($temp,$dest,$true)
  }
  $null=Read-TokenForgeHealthExchange -Path $stage
  Write-TokenForgeHealthPrivateJson $pendingPath @{schemaVersion=1;exchangeId=$id} -Immutable
  Complete-TokenForgeHealthPending -Root $root -ExchangeId $id -NativeExecutablePath $NativeExecutablePath
  Get-TokenForgePublicHealthStatus $root
 }finally{if($lock){$lock.Dispose()}}
}
function Complete-TokenForgeHealthPending {
 param([string]$Root,[string]$ExchangeId,[string]$NativeExecutablePath)
 $stage=Join-Path $Root ('public-health-receipts/'+$ExchangeId+'/exchange')
 $exchange=Read-TokenForgeHealthExchange -Path $stage
 if((Get-FileHash -LiteralPath (Join-Path $stage manifest.json)).Hash.ToLowerInvariant() -cne $ExchangeId){throw 'Pending evidence identity mismatch.'}
 # Native catalog import commits transactionally and deduplicates run identities. An interruption
 # between this commit and receipt publication is reconciled by repeating the same import.
 $catalog=Join-Path $Root applications.sqlite
 $catalogLockPath=Resolve-TokenForgeHealthPrivateFile ($catalog+'.lock')
 $catalogLock=$null
 try{
  try{$catalogLock=[TokenForge.Core.V0220.PrivateFiles]::Open($catalogLockPath,(-not [IO.File]::Exists($catalogLockPath)))}catch{throw 'Catalog is in use by another writer.'}
  $result=Import-TokenForgeApplicationMetadata -Path $catalog -InputPath $exchange.MetadataPath -NativeExecutablePath $NativeExecutablePath
 }finally{if($catalogLock){$catalogLock.Dispose()}}
 $old=Get-TokenForgePublicHealthStatus $Root
 $health=$exchange.Health;$date=[DateTimeOffset]::Parse($health.collectedAt)
 $isLatest=($null -eq $old.lastCollectedAt -or $date -ge [DateTimeOffset]::Parse($old.lastCollectedAt))
 $complete=$old.lastCompleteAt
 $gap=[bool]$old.collectionHistoryGap
 if($health.lastCompleteAt -and ($null -eq $complete -or [DateTimeOffset]::Parse($health.lastCompleteAt) -gt [DateTimeOffset]::Parse($complete))){
  if($complete -and ([DateTimeOffset]::Parse($health.lastCompleteAt)-[DateTimeOffset]::Parse($complete)).TotalDays -gt 14){$gap=$true}
  $complete=$health.lastCompleteAt
 }
 $receipt=[ordered]@{schemaVersion=1;exchangeId=$ExchangeId;collectedAt=$health.collectedAt;importedAt=[DateTimeOffset]::UtcNow.ToString('o');complete=$health.complete;importedRuns=$result.ImportedRuns}
 $receiptPath=Join-Path (Split-Path $stage -Parent) import.json
 if(-not [IO.File]::Exists($receiptPath)){Write-TokenForgeHealthPrivateJson $receiptPath $receipt -Immutable}
 if($isLatest){
  $status=[ordered]@{schemaVersion=1;transfer='Complete';import='Complete';collection=$(if($health.complete){'Complete'}else{'Incomplete'});lastCollectedAt=$health.collectedAt;lastCompleteAt=$complete;stale=$false;collectionHistoryGap=$gap;candidateCount=$health.candidateCount;conflictCount=$health.conflictCount;pendingDeepWork='Unassessed_ExistingPlansPreserved';publication='NotRequested';exchangeId=$ExchangeId}
  Write-TokenForgeHealthPrivateJson (Join-Path $Root public-health-status.json) $status
 }elseif($complete -cne $old.lastCompleteAt -or $gap -ne $old.collectionHistoryGap){
  $old.lastCompleteAt=$complete;$old.collectionHistoryGap=$gap;$old.import='Complete'
  Write-TokenForgeHealthPrivateJson (Join-Path $Root public-health-status.json) $old
 }
 [IO.File]::Delete((Join-Path $Root public-health-pending.json))
}
function Receive-TokenForgePublicHealthRun {
 [CmdletBinding()]
 param([Parameter(Mandatory)][ValidatePattern('^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$')][string]$Repository,
  [Parameter(Mandatory)][ValidatePattern('^[1-9][0-9]{0,18}$')][string]$RepositoryId,
  [Parameter(Mandatory)][ValidatePattern('^[1-9][0-9]{0,18}$')][string]$WorkflowId,
  [Parameter(Mandatory)][ValidatePattern('^[1-9][0-9]{0,18}$')][string]$RunId,
  [Parameter(Mandatory)][ValidatePattern('^[a-f0-9]{40}$')][string]$SourceRevision,
  [Parameter(Mandatory)][ValidatePattern('^[A-Za-z0-9_./-]{1,200}$')][string]$SourceBranch,
  [Parameter(Mandatory)][string]$StatePath,[Parameter(Mandatory)][string]$NativeExecutablePath,
  [securestring]$GitHubToken)
 Initialize-TokenForgeHealthSyncModule $NativeExecutablePath
 $root=Split-Path (Resolve-TokenForgeHealthPrivateFile (Join-Path $StatePath '.state') -CreateDirectory) -Parent
 $temporary=Join-Path $root ('public-health-transfer-'+[guid]::NewGuid().ToString('N'))
 $null=Resolve-TokenForgeHealthPrivateFile (Join-Path $temporary 'archive.zip') -CreateDirectory
 $budget=New-TokenForgeHealthBudget -MaxSeconds 180 -MaxRequests 4
 $failureCode='RunArtifactOrExchangeValidationFailed';$transferComplete=$false
 Write-TokenForgeHealthPrivateJson (Join-Path $root 'public-health-transfer.json') @{schemaVersion=1;state='InterruptedOrInProgress';runId=$RunId}
 $headers=@{'Accept'='application/vnd.github+json';'X-GitHub-Api-Version'='2022-11-28'}
 if($GitHubToken){$headers.Authorization='Bearer '+[Net.NetworkCredential]::new('',$GitHubToken).Password}
 try{
  $base='https://api.github.com/repos/'+$Repository
  $runResponse=Invoke-TokenForgeHealthGet -Uri "$base/actions/runs/$RunId" -MaxBytes 262144 -TimeoutSeconds 30 -Headers $headers -Budget $budget -AllowedHosts @('api.github.com')
  if($runResponse.StatusCode -in @(401,403)){$failureCode='ExplicitReadAuthorizationRequired';throw 'GitHub public health transfer requires separately supplied explicit read authorization.'}
  if($runResponse.StatusCode -ne 200){throw 'Named GitHub health run is unavailable.'}
  $run=Read-TokenForgeHealthJson $runResponse.Bytes
  if([string]$run.id -cne $RunId -or [string]$run.repository.id -cne $RepositoryId -or $run.repository.full_name -cne $Repository -or $run.head_repository.full_name -cne $Repository -or [string]$run.head_repository.id -cne $RepositoryId -or [string]$run.workflow_id -cne $WorkflowId -or $run.event -cnotin @('workflow_dispatch','schedule') -or $run.head_sha -cne $SourceRevision -or $run.head_branch -cne $SourceBranch -or $run.status -cne 'completed' -or $run.conclusion -cne 'success'){throw 'GitHub run identity or trust context mismatch.'}
  # Run-level artifact APIs cannot prove an artifact belongs to a later attempt. Refuse
  # reruns until an independent artifact-own attempt proof is available.
  if($run.run_attempt -ne 1){throw 'Artifact attempt association is ambiguous for a rerun; transfer refused.'}
  $response=Invoke-TokenForgeHealthGet -Uri "$base/actions/runs/$RunId/artifacts?per_page=100" -MaxBytes 1048576 -TimeoutSeconds 30 -Headers $headers -Budget $budget -AllowedHosts @('api.github.com')
  if($response.StatusCode -ne 200){throw 'GitHub health artifacts are unavailable.'}
  $listing=Read-TokenForgeHealthJson $response.Bytes
  if($listing.total_count -gt 100 -or $listing.total_count -ne @($listing.artifacts).Count){throw 'Ambiguous paginated artifact selection refused.'}
  $artifacts=@($listing.artifacts|Where-Object name -CEQ 'tokenforge-public-health')
  if($artifacts.Count -ne 1){throw 'Expected exactly one named public health artifact.'}
  $artifact=$artifacts[0]
  if($artifact.expired -or $artifact.size_in_bytes -lt 1 -or $artifact.size_in_bytes -gt 67190784 -or [string]$artifact.workflow_run.id -cne $RunId -or [string]$artifact.workflow_run.repository_id -cne $RepositoryId -or [string]$artifact.workflow_run.head_repository_id -cne $RepositoryId -or $artifact.workflow_run.head_sha -cne $SourceRevision -or $artifact.workflow_run.head_branch -cne $SourceBranch -or [string]$artifact.id -cnotmatch '^[1-9][0-9]{0,18}$'){throw 'Artifact provenance or bounds mismatch.'}
  $download=Invoke-TokenForgeHealthGet -Uri "$base/actions/artifacts/$($artifact.id)/zip" -MaxBytes 8192 -TimeoutSeconds 30 -Headers $headers -Budget $budget -AllowedHosts @('api.github.com')
  if($download.StatusCode -in @(401,403)){$failureCode='ExplicitReadAuthorizationRequired';throw 'GitHub artifact download requires separately supplied explicit read authorization.'}
  if($download.StatusCode -eq 302){
   $next=[uri]$download.Headers.Location
   if($next.Scheme -cne 'https' -or $next.UserInfo -or $next.Fragment -or $next.Port -ne 443 -or $next.Host -cnotmatch '^(?:[a-z0-9]{3,24}\.blob\.core\.windows\.net|[a-z0-9.-]+\.actions\.githubusercontent\.com)$'){throw 'Artifact download redirect is outside the approved service boundary.'}
   $download=Invoke-TokenForgeHealthGet -Uri $next -MaxBytes 67190784 -TimeoutSeconds 30 -Headers @{} -Budget $budget -AllowedHosts @($next.Host)
  }
  if($download.StatusCode -ne 200){throw 'GitHub artifact download failed within the transfer budget.'}
  Assert-TokenForgeHealthBudget $budget
  $archive=Join-Path $temporary archive.zip
  $file=[TokenForge.Core.V0220.PrivateFiles]::Open($archive,$true)
  try{$file.Write([byte[]]$download.Bytes);$file.Flush($true)}finally{$file.Dispose()}
  $exchange=Join-Path $temporary exchange
  $null=Resolve-TokenForgeHealthPrivateFile (Join-Path $exchange manifest.json) -CreateDirectory
  $zip=[IO.Compression.ZipFile]::OpenRead($archive)
  try{
   if($zip.Entries.Count -ne 3){throw 'Unexpected artifact member count.'}
   $seen=[Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal);$total=0L
   foreach($entry in $zip.Entries){
    Assert-TokenForgeHealthBudget $budget
    if($entry.FullName -cnotin @('manifest.json','health.json','metadata.json') -or -not $seen.Add($entry.FullName) -or $entry.Length -gt 67190784 -or $entry.Length -lt 1 -or (($entry.ExternalAttributes -shr 16) -band 61440) -notin @(0,32768)){throw 'Unexpected, duplicate, oversized or nonregular artifact member.'}
    $total+=$entry.Length;if($total -gt 67190784){throw 'Artifact expansion limit exceeded.'}
    $dest=Resolve-TokenForgeHealthPrivateFile (Join-Path $exchange $entry.FullName)
    $out=[TokenForge.Core.V0220.PrivateFiles]::Open($dest,$true);$input=$entry.Open()
    try{
     $buffer=[byte[]]::new(65536);$written=0L
     while(($n=$input.Read($buffer,0,$buffer.Length)) -gt 0){Assert-TokenForgeHealthBudget $budget;$written+=$n;if($written -gt $entry.Length){throw 'Artifact expansion mismatch.'};$out.Write($buffer,0,$n)}
     if($written -ne $entry.Length){throw 'Truncated artifact member.'};$out.Flush($true)
    }finally{$input.Dispose();$out.Dispose()}
   }
  }finally{$zip.Dispose()}
  $validated=Read-TokenForgeHealthExchange $exchange
  Assert-TokenForgeHealthBudget $budget
  $context=$validated.Manifest.context
  if($null -eq $context -or $context.repository -cne $Repository -or [string]$context.repositoryId -cne $RepositoryId -or [string]$context.workflowId -cne $WorkflowId -or [string]$context.runId -cne $RunId -or $context.attempt -ne 1 -or $context.event -cne $run.event -or $context.headSha -cne $SourceRevision -or $context.headBranch -cne $SourceBranch -or $validated.Manifest.sourceRevision -cne $SourceRevision){throw 'Exchange manifest does not match independently verified GitHub run.'}
  $result=Import-TokenForgePublicHealthExchange -ExchangePath $exchange -StatePath $root -NativeExecutablePath $NativeExecutablePath
  $transferComplete=$true
  Write-TokenForgeHealthPrivateJson (Join-Path $root 'public-health-transfer.json') @{schemaVersion=1;state='Complete';runId=$RunId}
  $result.transfer='Complete';$result
 }catch{
  # No provider error body, redirect capability or Authorization value in diagnostics.
  Write-TokenForgeHealthPrivateJson (Join-Path $root 'public-health-transfer.json') @{schemaVersion=1;state='RefusedOrInterrupted';runId=$RunId;reason=$failureCode}
  throw ('Public health transfer refused: '+$failureCode+'. Existing evidence is preserved.')
 }finally{
  $null=$headers.Remove('Authorization')
  # Keep bounded downloaded bytes private for diagnosis/retry; never execute them or
  # promote transfer leftovers into an immutable successful-import receipt.
 }
}
