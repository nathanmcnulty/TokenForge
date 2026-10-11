BeforeAll {
 $runner="$PSScriptRoot/../scripts/Get-TokenForgeCiUsage.ps1"
 function global:gh {param([string]$Command,[string]$Endpoint) throw 'Unmocked GitHub request.'}
}
AfterAll {Remove-Item Function:\global:gh -ErrorAction SilentlyContinue}
Describe 'Read-only weekly Actions usage' {
 BeforeEach {
  $week=[DateTimeOffset]'2026-10-05T00:00:00Z';$now=[DateTimeOffset]'2026-10-12T12:00:00Z'
  $run=@{id=101L;created_at='2026-10-06T00:00:00Z';path='.github/workflows/discovery.yml';head_sha='a'*40;run_attempt=2;status='completed'}
  $jobs1=@(
   @{id=1L;name='prepare';status='completed';conclusion='success';started_at='2026-10-06T00:00:00Z';completed_at='2026-10-06T00:01:00Z'},
   @{id=2L;name='worker (1)';status='completed';conclusion='failure';started_at='2026-10-06T00:01:00Z';completed_at='2026-10-06T00:03:00Z'},
   @{id=3L;name='publish';status='completed';conclusion='skipped';started_at=$null;completed_at=$null}
  )
  $jobs2=@($jobs1[0],@{id=4L;name='worker (1)';status='completed';conclusion='success';started_at='2026-10-07T00:00:00Z';completed_at='2026-10-07T00:03:00Z'})
  $artifacts=@(@{id=10L;size_in_bytes=1024L;expired=$false},@{id=11L;size_in_bytes=4096L;expired=$true})
  Mock gh {
   param($Command,$Endpoint)
   $global:LASTEXITCODE=0
   $response=switch -Regex ($Endpoint) {
    '/workflows/discovery.yml/runs\?' {@{total_count=1;workflow_runs=@($run)};break}
    '/attempts/1/jobs' {@{total_count=$jobs1.Count;jobs=$jobs1};break}
    '/attempts/2/jobs' {@{total_count=$jobs2.Count;jobs=$jobs2};break}
    '/artifacts\?' {@{total_count=$artifacts.Count;artifacts=$artifacts};break}
    '/runs/101$' {$run;break}
    default {throw "Unexpected endpoint: $Endpoint"}
   }
   ConvertTo-Json $response -Depth 10 -Compress
  }
 }
 It 'includes failed attempts and counts reused physical jobs only once' {
  $report=& $runner -WeekStart $week -Now $now
  $report.TotalRunnerMinutes|Should -Be 6
  $report.RunCount|Should -Be 1
  $report.AttemptCount|Should -Be 2
  $report.Jobs.Count|Should -Be 4
  $report.TimedJobs|Should -Be 3
  $report.NonSuccessfulTimedJobs|Should -Be 1
  $report.ObservationComplete|Should -BeTrue
  $report.CatalogCompletionVerified|Should -BeFalse
  ($report.RunnerMinutesByStage|Where-Object Stage -EQ Worker).RunnerMinutes|Should -Be 5
  Should -Invoke gh -Times 11 -Exactly
 }
 It 'reports artifact snapshots separately and excludes expired bytes' {
  $report=& $runner -WeekStart $week -Now $now
  $report.ArtifactSnapshot.UnexpiredCount|Should -Be 1
  $report.ArtifactSnapshot.UnexpiredBytes|Should -Be 1024
  $report.ArtifactSnapshot.ExpiredCount|Should -Be 1
  ($report|ConvertTo-Json -Depth 10)|Should -Not -Match 'size_in_bytes|created_at|started_at'
 }
 It 'uses the previous complete UTC week by default' {
  $report=& $runner -Now $now
  ([DateTimeOffset]$report.WeekStart)|Should -Be $week
  ([DateTimeOffset]$report.WeekEnd)|Should -Be $week.AddDays(7)
 }
 It 'marks a partial week and unfinished jobs as incomplete' {
  $run.status='in_progress';$run.run_attempt=1
  $jobs1[1].status='in_progress';$jobs1[1].conclusion=$null;$jobs1[1].completed_at=$null
  $report=& $runner -WeekStart $week -Now ([DateTimeOffset]'2026-10-07T12:00:00Z')
  $report.ObservationComplete|Should -BeFalse
  $report.WeekElapsed|Should -BeFalse
  $report.IncompleteRuns|Should -Be 1
  $report.IncompleteJobs|Should -Be 1
  $report.TotalRunnerMinutes|Should -Be 1
 }
 It 'enforces half-open UTC week membership despite inclusive search responses' {
  $run.created_at=$week.AddDays(7).ToString('o')
  $report=& $runner -WeekStart $week -Now $now
  $report.RunCount|Should -Be 0
  $report.TotalRunnerMinutes|Should -Be 0
  $report.ObservationComplete|Should -BeTrue
  Should -Invoke gh -Times 7 -Exactly
 }
 It 'refuses a truncated GitHub search rather than claiming complete coverage' {
  Mock gh {$global:LASTEXITCODE=0;' {"total_count":1001,"workflow_runs":[]} '}
  {& $runner -WeekStart $week -Now $now}|Should -Throw '*bound*'
 }
 It 'fails safely without exposing an API error response' {
  Mock gh {$global:LASTEXITCODE=1;'synthetic-secret'}
  {& $runner -WeekStart $week -Now $now}|Should -Throw '*Details suppressed*'
 }
 It 'refuses completed jobs with missing or reversed timestamps' {
  $jobs1[0].completed_at=$null
  {& $runner -WeekStart $week -Now $now}|Should -Throw '*no timing*'
  $jobs1[0].completed_at='2026-10-05T23:00:00Z'
  {& $runner -WeekStart $week -Now $now}|Should -Throw '*timing*'
 }
 It 'rejects a mismatched workflow and invalid week boundaries' {
  $run.path='.github/workflows/maintenance.yml'
  {& $runner -WeekStart $week -Now $now}|Should -Throw '*run*'
  {& $runner -WeekStart $week.AddDays(1) -Now $now}|Should -Throw '*Monday*'
  {& $runner -WeekStart $week.AddMinutes(1) -Now $now}|Should -Throw '*midnight*'
 }
 It 'never requests logs, artifact contents, or writes' {
  $null=& $runner -WeekStart $week -Now $now
  Should -Invoke gh -Times 0 -ParameterFilter {$Command -ne 'api' -or $Endpoint -match '/logs|/zip|/delete|/dispatches'}
 }
 It 'refuses a rerun started during observation' {
  Mock gh { $global:LASTEXITCODE=0; $changed=$run.Clone();$changed.run_attempt=3;ConvertTo-Json $changed -Compress } -ParameterFilter {$Endpoint -match '/runs/101$'}
  {& $runner -WeekStart $week -Now $now}|Should -Throw '*changed during observation*'
 }
 It 'refuses conflicting snapshots of reused jobs' {
  $jobs2[0]=$jobs1[0].Clone();$jobs2[0].completed_at='2026-10-06T00:02:00Z'
  {& $runner -WeekStart $week -Now $now}|Should -Throw '*changed between attempts*'
 }
 It 'follows job pagination without losing the last page' {
  $run.run_attempt=1
  $many=@(1..101|ForEach-Object { $item=$jobs1[0].Clone();$item.id=$_;$item })
  Mock gh {
   $global:LASTEXITCODE=0
   $selected=@(if($Endpoint -match 'page=1$'){$many[0..99]}else{$many[100]})
   @{total_count=101;jobs=$selected}|ConvertTo-Json -Depth 10 -Compress
  } -ParameterFilter {$Endpoint -match '/attempts/1/jobs'}
  $report=& $runner -WeekStart $week -Now $now
  $report.TimedJobs|Should -Be 101
  $report.TotalRunnerMinutes|Should -Be 101
  Should -Invoke gh -Times 1 -Exactly -ParameterFilter {$Endpoint -match '/attempts/1/jobs.*page=2$'}
 }
 It 'refuses page-count changes and early empty pages' {
  Mock gh {
   $global:LASTEXITCODE=0
   if($Endpoint -match 'page=1$'){@{total_count=2;jobs=@($jobs1[0])}|ConvertTo-Json -Depth 10 -Compress}
   else{@{total_count=3;jobs=@()}|ConvertTo-Json -Depth 10 -Compress}
  } -ParameterFilter {$Endpoint -match '/attempts/1/jobs'}
  {& $runner -WeekStart $week -Now $now}|Should -Throw '*collection changed*'
  Mock gh { $global:LASTEXITCODE=0;' {"total_count":2,"jobs":[]} ' } -ParameterFilter {$Endpoint -match '/attempts/1/jobs'}
  {& $runner -WeekStart $week -Now $now}|Should -Throw '*ended early*'
 }

 It 'rejects repeated IDs within a paginated collection' {
  Mock gh {
   $global:LASTEXITCODE=0
   @{total_count=2;jobs=@($jobs1[0],$jobs1[0])}|ConvertTo-Json -Depth 10 -Compress
  } -ParameterFilter {$Endpoint -match '/attempts/1/jobs'}
  {& $runner -WeekStart $week -Now $now}|Should -Throw '*Duplicate*'
 }

 It 'does not mark unknown completed-job outcomes as complete' {
  $jobs1[0].conclusion=$null
  {& $runner -WeekStart $week -Now $now}|Should -Throw '*recognized conclusion*'
 }

 It 'preserves week membership and recent job times outside UTC' -Skip:($IsWindows) {
  $child=Join-Path $TestDrive 'usage-timezone.ps1'
  @'
param([string]$Runner)
function global:gh {
 param([string]$Command,[string]$Endpoint)
 $global:LASTEXITCODE=0
 $runs=@(
  @{id=101L;created_at='2026-10-05T00:30:00Z';path='.github/workflows/discovery.yml';head_sha='a'*40;run_attempt=1;status='completed'},
  @{id=102L;created_at='2026-10-11T23:30:00Z';path='.github/workflows/discovery.yml';head_sha='a'*40;run_attempt=1;status='completed'}
 )
 $response=switch -Regex ($Endpoint) {
  '/workflows/discovery.yml/runs\?' {@{total_count=2;workflow_runs=$runs};break}
  '/runs/(101|102)/attempts/1/jobs' {
   $run=$runs|Where-Object id -EQ ([long]$Matches[1])
   $finish=([DateTimeOffset]$run.created_at).AddMinutes(1).ToString('o')
   @{total_count=1;jobs=@(@{id=([long]$run.id+1000);name='prepare';status='completed';conclusion='success';started_at=$run.created_at;completed_at=$finish})};break
  }
  '/artifacts\?' {@{total_count=0;artifacts=@()};break}
  '/runs/(101|102)$' {$runs|Where-Object id -EQ ([long]$Matches[1]);break}
  default {throw 'Unexpected fixture endpoint.'}
 }
 ConvertTo-Json $response -Depth 10 -Compress
}
& $Runner -WeekStart '2026-10-05T00:00:00Z' -Now '2026-10-12T00:00:00Z'|ConvertTo-Json -Depth 10 -Compress
'@|Set-Content $child
  foreach($zone in @('America/Anchorage','Asia/Tokyo')){
   $start=[Diagnostics.ProcessStartInfo]::new((Get-Process -Id $PID).Path)
   $start.UseShellExecute=$false;$start.RedirectStandardOutput=$true;$start.RedirectStandardError=$true
   $start.Environment['TZ']=$zone
   foreach($arg in @('-NoProfile','-File',$child,$runner)){$start.ArgumentList.Add($arg)}
   $process=[Diagnostics.Process]::Start($start)
   try{
    $stdout=$process.StandardOutput.ReadToEndAsync();$stderr=$process.StandardError.ReadToEndAsync()
    if(-not $process.WaitForExit(30000)){$process.Kill($true);throw 'Timezone fixture timed out.'}
    $process.ExitCode|Should -Be 0 -Because $stderr.GetAwaiter().GetResult()
    $report=$stdout.GetAwaiter().GetResult()|ConvertFrom-Json
    $report.RunCount|Should -Be 2 -Because $zone
    $report.TimedJobs|Should -Be 2 -Because $zone
    $report.TotalRunnerMinutes|Should -Be 2 -Because $zone
    $report.ObservationComplete|Should -BeTrue -Because $zone
   }finally{$process.Dispose()}
  }
 }

}
