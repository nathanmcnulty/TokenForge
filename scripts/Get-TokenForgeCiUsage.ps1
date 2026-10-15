#Requires -Version 7.6
[CmdletBinding()]
param(
 [ValidatePattern('^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$')][string]$Repository='nathanmcnulty/TokenForge',
 [ValidatePattern('^[A-Za-z0-9_-]+\.ya?ml$')][string]$Workflow='discovery.yml',
 [DateTimeOffset]$WeekStart,
 [DateTimeOffset]$Now=[DateTimeOffset]::UtcNow
)
$ErrorActionPreference='Stop'
# Read Actions metadata only. Never download artifacts, job logs, or authentication state.
function Get-TfUsageApi([string]$Endpoint){
 try{
  $json=& gh api $Endpoint 2>$null
  if($LASTEXITCODE -ne 0){throw 'API failed.'}
  $json -join "`n" | ConvertFrom-Json -AsHashtable -Depth 32 -ErrorAction Stop
 }catch{throw 'Actions usage metadata could not be read. Details suppressed.'}
}
function Get-TfUsagePages([string]$Endpoint,[string]$Collection){
 $items=[Collections.Generic.List[object]]::new();$page=1;$expected=$null;$ids=[Collections.Generic.HashSet[long]]::new()
 do{
  $separator=if($Endpoint.Contains('?')){'&'}else{'?'}
  $response=Get-TfUsageApi ($Endpoint+$separator+"per_page=100&page=$page")
  if($response[$Collection] -isnot [array] -or $response.total_count -isnot [long] -and $response.total_count -isnot [int]){throw 'Invalid Actions usage page.'}
  if($response.total_count -lt 0 -or $response.total_count -gt 1000){throw 'Actions usage page exceeds the supported bound; narrow the collection window.'}
  if($null -eq $expected){$expected=$response.total_count}elseif($expected -ne $response.total_count){throw 'Actions usage collection changed; retry the report.'}
  foreach($item in $response[$Collection]){if([long]$item.id -le 0 -or -not $ids.Add([long]$item.id)){throw 'Duplicate or invalid Actions usage item ID.'};$items.Add($item)}
  if($items.Count -gt $expected){throw 'Invalid Actions usage count.'}
  if($items.Count -eq $expected){break}
  if($response[$Collection].Count -eq 0){throw 'Actions usage pagination ended early.'}
  $page++
 }while($page -le 10)
 if($items.Count -ne $expected){throw 'Actions usage pagination is incomplete.'}
 $items.ToArray()
}
$Now=$Now.ToUniversalTime()
if(-not $PSBoundParameters.ContainsKey('WeekStart')){
 $days=(([int]$Now.DayOfWeek+6)%7)
 $WeekStart=[DateTimeOffset]::new($Now.UtcDateTime.Date.AddDays(-$days-7),[TimeSpan]::Zero)
}
$WeekStart=$WeekStart.ToUniversalTime()
if($WeekStart.DayOfWeek -ne [DayOfWeek]::Monday -or $WeekStart.TimeOfDay -ne [TimeSpan]::Zero -or $WeekStart -gt $Now){throw 'WeekStart must be a Monday at UTC midnight no later than now.'}
$end=$WeekStart.AddDays(7);$observedEnd=if($end -gt $Now){$Now}else{$end}
$runs=[Collections.Generic.Dictionary[long,object]]::new()
# Split into UTC days to avoid GitHub's filtered-run search cap silently truncating a week.
for($day=$WeekStart;$day -lt $observedEnd;$day=$day.AddDays(1)){
 $queryEnd=if($day.AddDays(1) -gt $observedEnd){$observedEnd}else{$day.AddDays(1)}
 $range=[uri]::EscapeDataString($day.ToString('yyyy-MM-ddTHH:mm:ssZ')+'..'+$queryEnd.ToString('yyyy-MM-ddTHH:mm:ssZ'))
 foreach($run in @(Get-TfUsagePages "repos/$Repository/actions/workflows/$Workflow/runs?created=$range" workflow_runs)){
  $id=[long]$run.id;$created=[DateTimeOffset]$run.created_at
  if($id -le 0 -or $run.path -cne ".github/workflows/$Workflow" -or $run.head_sha -cnotmatch '^[a-f0-9]{40}$' -or $run.run_attempt -lt 1 -or $run.run_attempt -gt 100){throw 'Invalid Actions usage run.'}
  # Cast parsed DateTime values directly to preserve their UTC Kind; stringifying loses it.
  # GitHub's search range is inclusive. Keep exact half-open membership and deduplicate midnight.
  if($created -ge $WeekStart -and $created -lt $observedEnd){$runs[$id]=$run}
 }
}
$jobSnapshots=[Collections.Generic.Dictionary[long,string]]::new()
$jobs=[Collections.Generic.Dictionary[long,object]]::new();$rows=[Collections.Generic.List[object]]::new()
$artifactIds=[Collections.Generic.HashSet[long]]::new();$artifactBytes=0L;$artifactCount=0;$expiredArtifacts=0
$incompleteRuns=0;$attemptCount=0
foreach($run in @($runs.Values|Sort-Object id)){
 if($run.status -cne 'completed'){$incompleteRuns++}
 for($attempt=1;$attempt -le $run.run_attempt;$attempt++){
  $attemptCount++
  foreach($job in @(Get-TfUsagePages "repos/$Repository/actions/runs/$($run.id)/attempts/$attempt/jobs" jobs)){
   $id=[long]$job.id
   if($id -le 0){throw 'Invalid Actions usage job.'}
   # Reruns can reference unchanged jobs. Count each physical job ID once.
   $snapshot=@($run.id,$job.name,$job.status,$job.conclusion,$job.started_at,$job.completed_at) -join '|'
   if($jobs.ContainsKey($id)){if($jobSnapshots[$id] -cne $snapshot){throw 'Actions job changed between attempts; retry the report.'};continue}
   $jobSnapshots.Add($id,$snapshot)
   $stage=switch -Regex ([string]$job.name){'^worker(?:\s|$)'{'Worker';break};'^prepare$'{'Prepare';break};'^publish$'{'Publish';break};'^push$'{'Push';break};default{'Other'}}
   $seconds=$null
   if($job.status -ceq 'completed' -and $job.conclusion -cne 'skipped'){
    if(-not $job.started_at -or -not $job.completed_at){throw 'Completed Actions job has no timing.'}
    $start=[DateTimeOffset]$job.started_at;$finish=[DateTimeOffset]$job.completed_at
    if($finish -lt $start -or $finish -gt $Now.AddMinutes(5)){throw 'Invalid Actions usage timing.'}
    $seconds=($finish-$start).TotalSeconds
   }
   if($job.status -cnotin @('queued','in_progress','completed','waiting','pending','requested')){throw 'Invalid Actions job status.'}
   $status=$job.status
   $conclusion=if($job.conclusion -cin @('success','failure','cancelled','skipped','timed_out','action_required','neutral','stale','startup_failure')){$job.conclusion}else{$null}
   if($status -ceq 'completed' -and -not $conclusion){throw 'Completed Actions job has no recognized conclusion.'}
   $row=[pscustomobject]@{RunId=[long]$run.id;JobId=$id;Attempt=$attempt;Stage=$stage;Status=$status;Conclusion=$conclusion;RunnerSeconds=$seconds}
   $jobs.Add($id,$row)
  }
 }
 foreach($artifact in @(Get-TfUsagePages "repos/$Repository/actions/runs/$($run.id)/artifacts" artifacts)){
  $id=[long]$artifact.id
  if($id -le 0 -or $artifact.size_in_bytes -lt 0 -or $artifact.expired -isnot [bool]){throw 'Invalid Actions artifact metadata.'}
  if(-not $artifactIds.Add($id)){throw 'Duplicate Actions artifact ID.'}
  if($artifact.expired){$expiredArtifacts++}else{$artifactBytes+=[long]$artifact.size_in_bytes;$artifactCount++}
 }
 $latest=Get-TfUsageApi "repos/$Repository/actions/runs/$($run.id)"
 if($latest.id -ne $run.id -or $latest.run_attempt -ne $run.run_attempt -or $latest.status -cne $run.status -or $latest.head_sha -cne $run.head_sha){throw 'Actions run changed during observation; retry the report.'}
 $rows.Add([pscustomobject]@{RunId=[long]$run.id;SourceCommit=$run.head_sha;Attempts=[int]$run.run_attempt;Completed=($run.status -ceq 'completed');Url="https://github.com/$Repository/actions/runs/$($run.id)"})
}
$jobRows=@($jobs.Values|Sort-Object RunId,JobId)
$pending=@($jobRows|Where-Object Status -NE completed).Count
$timed=@($jobRows|Where-Object {$null -ne $_.RunnerSeconds})
$seconds=($timed|Measure-Object RunnerSeconds -Sum).Sum
if($null -eq $seconds){$seconds=0}
$stages=@(foreach($stage in @('Prepare','Worker','Publish','Push','Other')){
 $selected=@($timed|Where-Object Stage -EQ $stage)
 [pscustomobject]@{Stage=$stage;Jobs=$selected.Count;RunnerMinutes=[Math]::Round(($selected|Measure-Object RunnerSeconds -Sum).Sum/60,3)}
})
[pscustomobject]@{
 SchemaVersion=1;GeneratedAt=$Now.ToString('o');Repository=$Repository;Workflow=$Workflow
 WeekStart=$WeekStart.ToString('o');WeekEnd=$end.ToString('o');ObservedThrough=$observedEnd.ToString('o')
 Scope='AllAttemptsOfWorkflowRunsCreatedInUtcWeek';WeekElapsed=($end -le $Now)
 ObservationComplete=($end -le $Now -and $incompleteRuns -eq 0 -and $pending -eq 0)
 CatalogCompletionVerified=$false;RunCount=$runs.Count;AttemptCount=$attemptCount;IncompleteRuns=$incompleteRuns;IncompleteJobs=$pending
 TimedJobs=$timed.Count;NonSuccessfulTimedJobs=@($timed|Where-Object Conclusion -NE success).Count
 TotalRunnerMinutes=[Math]::Round($seconds/60,3);RunnerMinutesByStage=$stages
 ArtifactSnapshot=[pscustomobject]@{UnexpiredCount=$artifactCount;UnexpiredBytes=$artifactBytes;ExpiredCount=$expiredArtifacts;Scope='SelectedRunsAtObservationTimeNotRepositoryStorageOrBilledUsage'}
 TimingMethod='Sum distinct completed non-skipped job durations, including failures and reruns; includes setup, excludes queues and unfinished jobs. Attempts may execute outside the selected creation week. Not invoice minutes or elapsed cycle time.'
 Runs=$rows.ToArray();Jobs=$jobRows
}
