#Requires -Version 7.4
[CmdletBinding(SupportsShouldProcess)]
param([Parameter(Mandatory)][ValidatePattern('^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$')][string]$Repository, [ValidateRange(0,9223372036854775807)][long]$CurrentRunId=0)
$ErrorActionPreference='Stop'
function Select-TfSupersededNativeArtifacts($Artifacts,[long]$WorkflowId,[hashtable]$Runs,[long]$CurrentRunId=0) {
 $names=@('tokenforge-linux-x64','tokenforge-win-x64','tokenforge-osx-arm64')
 $native=@($Artifacts|Where-Object {$_.name -cin $names -and $Runs[[string]$_.workflow_run.id].WorkflowId -eq $WorkflowId -and -not $_.expired})
 $candidates=@($native|Where-Object {
  $run=$Runs[[string]$_.workflow_run.id]
  $_.workflow_run.head_branch -ceq 'main' -and
   (($CurrentRunId -gt 0 -and $_.workflow_run.id -eq $CurrentRunId) -or
    ($run.Status -ceq 'completed' -and $run.Conclusion -ceq 'success'))
 }|Sort-Object {([DateTimeOffset]$_.created_at)},id -Descending)
 if($CurrentRunId -gt 0){
  $current=@($candidates|Where-Object {$_.workflow_run.id -eq $CurrentRunId})
  if(@($names|Where-Object {$_ -cnotin $current.name}).Count){throw 'Current main packages are incomplete; no artifacts will be removed.'}
 }
 $keep=@{};$boundary=$null
 foreach($candidate in $candidates){
  $build=@($candidates|Where-Object {$_.workflow_run.id -eq $candidate.workflow_run.id})
  if(@($names|Where-Object {$_ -cnotin $build.name}).Count){continue}
  foreach($name in $names){$item=$build|Where-Object name -CEQ $name|Select-Object -First 1;$keep[[string]$item.id]=$true}
  $boundary=($build|ForEach-Object {[DateTimeOffset]$_.created_at}|Sort-Object|Select-Object -First 1)
  break
 }
 if($keep.Count -ne 3){throw 'Successful main packages are incomplete; no artifacts will be removed.'}
 # Leave unfinished runs untouched, including packages uploaded during enumeration.
 @($native|Where-Object {-not $keep.ContainsKey([string]$_.id) -and $Runs[[string]$_.workflow_run.id].Status -ceq 'completed' -and ([DateTimeOffset]$_.created_at) -lt $boundary})
}

try{
 $workflow=gh api "repos/$Repository/actions/workflows/native.yml"|ConvertFrom-Json
 if($LASTEXITCODE -ne 0 -or $workflow.id -le 0){throw 'Native workflow lookup failed.'}
 $items=@{};$page=1
 do{
  $response=gh api "repos/$Repository/actions/artifacts?per_page=100&page=$page"|ConvertFrom-Json
  if($LASTEXITCODE -ne 0 -or $response.artifacts -isnot [array]){throw 'Artifact enumeration failed.'}
  foreach($artifact in $response.artifacts){if($artifact.id -le 0){throw 'Invalid artifact identity.'};$items[[string]$artifact.id]=$artifact}
  if($page -ge 100 -and $response.artifacts.Count -eq 100){throw 'Artifact enumeration bound reached; no deletion performed.'}
  $page++
 }while($response.artifacts.Count -eq 100)
 $runWorkflows=@{}
 foreach($artifact in @($items.Values|Where-Object {$_.name -cin @('tokenforge-linux-x64','tokenforge-win-x64','tokenforge-osx-arm64')})){
  $runId=[string]$artifact.workflow_run.id
  if($runId -notmatch '^[1-9][0-9]*$'){throw 'Invalid artifact run identity.'}
  if($runWorkflows.ContainsKey($runId)){continue}
  $run=gh api "repos/$Repository/actions/runs/$runId"|ConvertFrom-Json
  if($LASTEXITCODE -ne 0 -or $run.workflow_id -le 0){throw 'Artifact workflow provenance lookup failed.'}
  $runWorkflows[$runId]=@{WorkflowId=[long]$run.workflow_id;Status=$run.status;Conclusion=$run.conclusion}
 }
 $obsolete=@(Select-TfSupersededNativeArtifacts $items.Values $workflow.id $runWorkflows $CurrentRunId)
 $removed=0;$bytes=0L
 foreach($artifact in $obsolete){
  if($PSCmdlet.ShouldProcess("Generated native artifact $($artifact.id)",'Remove superseded package')){
   gh api "repos/$Repository/actions/artifacts/$($artifact.id)" --method DELETE --silent
   if($LASTEXITCODE -ne 0){throw 'Artifact deletion failed.'}
   $removed++;$bytes+=[long]$artifact.size_in_bytes
  }
 }
 [pscustomobject]@{RemovedNativePackages=$removed;BytesRemoved=$bytes;LatestMainPackagesPreserved=3}
}catch{throw 'Native artifact maintenance failed; details suppressed. Research and maintenance snapshots are excluded.'}
