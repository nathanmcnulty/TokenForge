BeforeDiscovery {
 $nativeAvailable=[bool]($IsLinux -and $env:TOKENFORGE_TEST_NATIVE -and (Test-Path -LiteralPath $env:TOKENFORGE_TEST_NATIVE -PathType Leaf))
}
BeforeAll {
 . "$PSScriptRoot/../scripts/TokenForgeDiscoveryCandidate.ps1"
 $native=$env:TOKENFORGE_TEST_NATIVE
 $repository=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
 $sourceCommit=([string](git -C $repository rev-parse HEAD)).Trim()
 if($LASTEXITCODE -ne 0 -or $sourceCommit -cnotmatch '^[a-f0-9]{40}$'){throw 'Cannot identify the tested source revision.'}
 function Stop-TfSyntheticCollector([string]$Boundary,[string]$Root) {
  $start=[Diagnostics.ProcessStartInfo]::new();$start.FileName=(Get-Process -Id $PID).Path
  $start.UseShellExecute=$false;$start.RedirectStandardOutput=$true;$start.RedirectStandardError=$true
  foreach($arg in @('-NoProfile','-File',(Join-Path $PSScriptRoot 'fixtures/collector/InterruptedCollector.ps1'),'-Boundary',$Boundary,'-Root',$Root,'-NativeExecutablePath',$native,'-SourceCommit',$sourceCommit)){$start.ArgumentList.Add($arg)}
  $process=[Diagnostics.Process]::Start($start)
  $stdout=$process.StandardOutput.ReadToEndAsync();$stderr=$process.StandardError.ReadToEndAsync()
  try{
   $timer=[Diagnostics.Stopwatch]::StartNew();$ready=Join-Path $Root ready.json
   while(-not(Test-Path -LiteralPath $ready) -and -not $process.HasExited -and $timer.Elapsed.TotalSeconds -lt 30){[Threading.Thread]::Sleep(50)}
   if(-not(Test-Path -LiteralPath $ready)){
    if(-not $process.HasExited){$process.Kill($true);$null=$process.WaitForExit(5000)}
    $details=$stderr.GetAwaiter().GetResult()
    if($details.Length -gt 2000){$details=$details.Substring($details.Length-2000)}
    throw "Synthetic collector did not reach $Boundary within 30 seconds. $details"
   }
   $marker=Read-TfCandidateJson $ready
   if($marker.Boundary -cne $Boundary){throw 'Synthetic crash marker mismatch.'}
   $process.HasExited|Should -BeFalse
   # Actual process termination bypasses PowerShell finally blocks and disposal.
   $process.Kill($true)
   $process.WaitForExit(5000)|Should -BeTrue
   $process.ExitCode|Should -Not -Be 0
   $null=$stdout.GetAwaiter().GetResult();$null=$stderr.GetAwaiter().GetResult()
   $marker
  }finally{if(-not $process.HasExited){$process.Kill($true);$null=$process.WaitForExit(5000)};$process.Dispose()}
 }
 function Save-TfSyntheticKillReceipt([string]$Boundary,[string]$CandidatePath,[string]$Hash) {
  if(-not $env:TOKENFORGE_TEST_RECEIPT_DIR){return}
  $destination=[IO.Path]::GetFullPath($env:TOKENFORGE_TEST_RECEIPT_DIR)
  $cache=[IO.Path]::GetFullPath((Join-Path $repository '.cache'))+[IO.Path]::DirectorySeparatorChar
  if(-not $destination.StartsWith($cache,[StringComparison]::Ordinal)){throw 'Synthetic receipts must remain under this repository .cache directory.'}
  Assert-TfCandidateUnlinked $destination
  $null=[IO.Directory]::CreateDirectory($destination,[IO.UnixFileMode]448)
  $name='kill-'+$Boundary+'-'+[guid]::NewGuid().ToString('N')
  Copy-Item -LiteralPath $CandidatePath -Destination (Join-Path $destination $name) -Recurse
  Write-TfCandidateJson ([ordered]@{SchemaVersion=1;Boundary=$Boundary;Evidence='SyntheticProcessKillWithMockedIssuance';SourceCommit=$sourceCommit;Candidate=$name;CandidateHash=$Hash;NativeExecutableSha256=(Get-TfCandidateFileHash $native)}) (Join-Path $destination ($name+'.receipt.json'))
 }
}
Describe 'Linux process-kill boundaries preserve native collector evidence' -Skip:(-not $nativeAvailable) {
 BeforeEach {
  $root=Join-Path $TestDrive ([guid]::NewGuid().ToString())
  $null=[IO.Directory]::CreateDirectory($root,[IO.UnixFileMode]448)
  $scopePath=Join-Path $root scopes.sqlite;$flowPath=Join-Path $root flows.sqlite
  Mock Get-TokenForgeToken -ModuleName TokenForge {throw 'Recovery and export must never issue a token.'}
 }
 It 'retains unknown native intent after actual kill at <Boundary>' -ForEach @(
  @{Boundary='BeforeRequest';SimulatedCalls=0},
  @{Boundary='RemoteResult';SimulatedCalls=1}
 ) {
  $marker=Stop-TfSyntheticCollector $Boundary $root
  $flows=Get-TokenForgeFlowEvidence $flowPath -NativeExecutablePath $native
  $flows.Attempts.Count|Should -Be 1;$flows.Attempts[0].Outcome|Should -Be Started
  (Get-TokenForgeScopeDatabase $scopePath -NativeExecutablePath $native).Observations.Count|Should -Be 0
  $calls=Join-Path $root token-calls.txt
  if($SimulatedCalls){[int](Get-Content $calls)|Should -Be $SimulatedCalls;Test-Path (Join-Path $root simulated-result.json)|Should -BeTrue}else{Test-Path $calls|Should -BeFalse}
  $inventory=Get-Content (Join-Path $root inventory.json) -Raw|ConvertFrom-Json
  $secret=ConvertTo-SecureString synthetic-cookie -AsPlainText -Force
  try{
   $cohort=Get-TokenForgeResearchCohort $scopePath $marker.CohortId -NativeExecutablePath $native
   {Invoke-TokenForgeScopeProbe -Inventory $inventory -EstsAuth $secret -Plan @($cohort.Cohort.Pairs) -DatabasePath $scopePath -FlowDatabasePath $flowPath -CohortFingerprint $marker.CohortId -Protocols OAuth2V2Pkce -MaxRedirects 1 -ExploreAllFlows -DelayMilliseconds 0 -NativeExecutablePath $native}|Should -Throw '*unknown*'
  }finally{$secret.Dispose()}
  (Get-TokenForgeFlowEvidence $flowPath -NativeExecutablePath $native).Attempts.Count|Should -Be 1
  $candidate=Join-Path $root candidate
  $hash=New-TfDiscoveryCandidate -ScopePath $scopePath -FlowPath $flowPath -CohortId $marker.CohortId -OutputPath $candidate -SourceCommit $sourceCommit -ProducerRunId 1 -ProducerAttempt 1 -NativeExecutablePath $native
  $null=Assert-TfDiscoveryCandidate $candidate $hash
  $v=Read-TfCandidateJson (Join-Path $candidate validation.json)
  $v.InFlightUnknownCells|Should -Be 1;$v.TerminalCells|Should -Be 0;$v.ScopeObservations|Should -Be 0
  Save-TfSyntheticKillReceipt $Boundary $candidate $hash
  Should -Invoke Get-TokenForgeToken -ModuleName TokenForge -Times 0 -Exactly
 }
 It 'repairs projection without issuance after killing a durable terminal checkpoint' {
  $boundary='TerminalBeforeProjection';$marker=Stop-TfSyntheticCollector $boundary $root
  $before=Get-TokenForgeFlowEvidence $flowPath -NativeExecutablePath $native
  $before.Attempts.Count|Should -Be 1;$before.Attempts[0].Outcome|Should -Be Succeeded
  [int](Get-Content (Join-Path $root token-calls.txt))|Should -Be 1
  (Get-TokenForgeScopeDatabase $scopePath -NativeExecutablePath $native).Observations.Count|Should -Be 0
  $inventory=Get-Content (Join-Path $root inventory.json) -Raw|ConvertFrom-Json
  $secret=ConvertTo-SecureString synthetic-cookie -AsPlainText -Force
  try{
   $cohort=Get-TokenForgeResearchCohort $scopePath $marker.CohortId -NativeExecutablePath $native
   $result=Invoke-TokenForgeScopeProbe -Inventory $inventory -EstsAuth $secret -Plan @($cohort.Cohort.Pairs) -DatabasePath $scopePath -FlowDatabasePath $flowPath -CohortFingerprint $marker.CohortId -Protocols OAuth2V2Pkce -MaxRedirects 1 -ExploreAllFlows -DelayMilliseconds 0 -NativeExecutablePath $native
   [DateTimeOffset]$result.ObservedAt|Should -Be ([DateTimeOffset]$before.Attempts[0].ObservedAt)
  }finally{$secret.Dispose()}
  (Get-TokenForgeScopeDatabase $scopePath -NativeExecutablePath $native).Observations.Count|Should -Be 1
  $after=Get-TokenForgeFlowEvidence $flowPath -NativeExecutablePath $native
  $after.Attempts.Count|Should -Be 1;$after.Attempts[0].AttemptId|Should -BeExactly $before.Attempts[0].AttemptId
  $candidate=Join-Path $root candidate
  $hash=New-TfDiscoveryCandidate -ScopePath $scopePath -FlowPath $flowPath -CohortId $marker.CohortId -OutputPath $candidate -SourceCommit $sourceCommit -ProducerRunId 1 -ProducerAttempt 1 -NativeExecutablePath $native
  $null=Assert-TfDiscoveryCandidate $candidate $hash
  $scopeExport=Read-TfCandidateJson (Join-Path $candidate scopes.json)
  [DateTimeOffset]$scopeExport.Observations[0].ObservedAt|Should -Be ([DateTimeOffset]$before.Attempts[0].ObservedAt)
  Save-TfSyntheticKillReceipt $boundary $candidate $hash
  Should -Invoke Get-TokenForgeToken -ModuleName TokenForge -Times 0 -Exactly
 }
 It 'keeps interrupted export staging private and retries saved evidence after actual kill' {
  $boundary='ExportBeforeMove';$marker=Stop-TfSyntheticCollector $boundary $root
  $candidate=Join-Path $root candidate
  Test-Path $candidate|Should -BeFalse
  $staging=@(Get-ChildItem -LiteralPath $root -Directory -Force|Where-Object Name -like '.candidate.partial-*')
  $staging.Count|Should -Be 1
  ([int][IO.File]::GetUnixFileMode($staging[0].FullName) -band 63)|Should -Be 0
  Test-Path (Join-Path $staging[0].FullName filtered-private.json)|Should -BeFalse
  Test-Path (Join-Path $staging[0].FullName manifest.json)|Should -BeTrue
  $before=Get-TokenForgeFlowEvidence $flowPath -NativeExecutablePath $native
  $hash=New-TfDiscoveryCandidate -ScopePath $scopePath -FlowPath $flowPath -CohortId $marker.CohortId -OutputPath $candidate -SourceCommit $sourceCommit -ProducerRunId 1 -ProducerAttempt 2 -NativeExecutablePath $native
  $null=Assert-TfDiscoveryCandidate $candidate $hash
  Test-Path $candidate|Should -BeTrue
  $after=Get-TokenForgeFlowEvidence $flowPath -NativeExecutablePath $native
  $after.Attempts.Count|Should -Be $before.Attempts.Count;$after.Attempts[0].AttemptId|Should -BeExactly $before.Attempts[0].AttemptId
  [int](Get-Content (Join-Path $root token-calls.txt))|Should -Be 1
  Save-TfSyntheticKillReceipt $boundary $candidate $hash
  Should -Invoke Get-TokenForgeToken -ModuleName TokenForge -Times 0 -Exactly
 }
}
