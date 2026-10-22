BeforeAll {
 Import-Module "$PSScriptRoot/../src/TokenForge/TokenForge.psd1" -Force
 . "$PSScriptRoot/../scripts/Invoke-TokenForgeCallbackExperiment.ps1"
 $fixtureText=[IO.File]::ReadAllText("$PSScriptRoot/fixtures/lab/callback-cap-v1.json")
 function Copy-Cases { $fixtureText|ConvertFrom-Json -AsHashtable }
}
Describe 'Goal 5 synthetic laboratory boundary' {
 It 'accepts only the complete allowlisted synthetic cohort' {
  $v=ConvertFrom-TokenForgeCallbackCases $fixtureText
  $v.Cases.Count|Should -Be 12
  @($v.Cases|Where-Object Partition -CEQ Holdout).Count|Should -Be 4
 }
 It 'rejects unexpected, credential-bearing or private-path fields without echoing them' -ForEach @(@{Field='AccessToken'},@{Field='PrivateStore'},@{Field='PasskeyPath'}) {
  $v=Copy-Cases;$v[$Field]='synthetic-sensitive-sentinel'
  {ConvertFrom-TokenForgeCallbackCases ($v|ConvertTo-Json -Depth 8)}|Should -Throw '*invalid; no experiment executed*'
 }
 It 'rejects a foreign scenario in the last holdout row' {
  $v=Copy-Cases;$v.Cases[-1].Secondary='RunCommand'
  {ConvertFrom-TokenForgeCallbackCases ($v|ConvertTo-Json -Depth 8)}|Should -Throw '*invalid; no experiment executed*'
 }
 It 'rejects duplicate case identities, mismatched partitions and incomplete cohorts' -ForEach @(@{Kind='Duplicate'},@{Kind='Partition'},@{Kind='Missing'}) {
  $v=Copy-Cases
  switch($Kind){Duplicate {$v.Cases[-1].Id=$v.Cases[0].Id} Partition {$v.Cases[-1].Partition='Discovery'} Missing {$v.Cases=@($v.Cases|Select-Object -First 11)}}
  {ConvertFrom-TokenForgeCallbackCases ($v|ConvertTo-Json -Depth 8)}|Should -Throw '*invalid; no experiment executed*'
 }
 It 'rejects duplicate JSON keys and unknown row fields before a study' {
  $bad=$fixtureText.Replace('"Primary": "Success"','"Primary": "Success", "Primary": "Rejected"')
  {ConvertFrom-TokenForgeCallbackCases $bad}|Should -Throw '*invalid; no experiment executed*'
  $v=Copy-Cases;$v.Cases[-1].Command='synthetic-no-execution'
  {ConvertFrom-TokenForgeCallbackCases ($v|ConvertTo-Json -Depth 8)}|Should -Throw '*invalid; no experiment executed*'
 }
 It 'does not reinterpret a budget or harness stop as an ordinary negative result' {
  $pairs=@(@{Baseline=@{Success=$true;IssuanceAttempts=3};Candidate=@{Success=$false;IssuanceAttempts=1}})
  Get-TokenForgeCallbackDisposition -Pairs $pairs -Complete $false|Should -Be Inconclusive
  Get-TokenForgeCallbackDisposition -Pairs $pairs -Complete $true|Should -Be Rejected
 }
 It 'never promotes a favorable synthetic result on its own' {
  $pairs=@(1..12|ForEach-Object {@{Baseline=@{Success=$true;IssuanceAttempts=3};Candidate=@{Success=$true;IssuanceAttempts=2}}})
  Get-TokenForgeCallbackDisposition -Pairs $pairs -Complete $true|Should -Be Inconclusive
 }
}
Describe 'Goal 5 actual core callback experiment' -Tag Experiment {
 It 'retains the charged active trial and its partial trace on a reduced-budget stop' {
  if(-not $env:TOKENFORGE_TEST_NATIVE){throw 'The matching package is required.'}
  $r=Invoke-TokenForgeCallbackExperiment -NativeExecutable $env:TOKENFORGE_TEST_NATIVE -OutputPath (Join-Path $TestDrive stopped.json) -MaxSyntheticIssuanceAttempts 1
  $r.RunStatus|Should -Be Stopped
  $r.Disposition|Should -Be Inconclusive
  $r.CompletedTrials|Should -Be 0
  $r.AttemptedTrials|Should -Be 1
  $r.SyntheticIssuanceAttempts|Should -Be 1
  $r.Trials[0].TrialStatus|Should -Be Stopped
  $r.Trials[0].IssuanceAttempts|Should -Be 1
  $r.Trials[0].Trace.Count|Should -Be 1
  $r.Trials[0].Trace[0].Phase|Should -Be Bootstrap
  ($r.Trials|ForEach-Object IssuanceAttempts|Measure-Object -Sum).Sum|Should -Be $r.SyntheticIssuanceAttempts
  ($r.Partitions|ForEach-Object Pairs|Measure-Object -Sum).Sum|Should -Be 0
 }

 It 'runs both counterbalanced arms, retains all failures and rejects lost verified pairs' {
  $native=$env:TOKENFORGE_TEST_NATIVE
  if(-not $native){throw 'A verified matching native package is required; this gate cannot skip.'}
  $out=Join-Path $TestDrive result.json
  $r=Invoke-TokenForgeCallbackExperiment -NativeExecutable $native -OutputPath $out
  $r.RunStatus|Should -Be Complete
  $r.CompletedTrials|Should -Be 24
  $r.Disposition|Should -Be Rejected
  $r.ProductionPromotion|Should -BeFalse
  $r.PolicyChanged|Should -BeFalse
  $r.SyntheticIssuanceAttempts|Should -BeLessOrEqual 72
  $r.ExternalRequests|Should -Be 0
  $r.AuthenticationAttempts|Should -Be 0
  $r.PromptInvocations|Should -Be 0
  $r.Trials.Count|Should -Be 24
  @($r.Trials|Where-Object AcceptedExtraScopes -GT 0).Count|Should -Be 0
  @($r.Trials|Where-Object {$_.TokenObjectsCreated -ne $_.TokenObjectsDisposed}).Count|Should -Be 0
  @($r.Trials|Where-Object ObservedCoreOutcome -CEQ Cancelled).Count|Should -Be 4
  $r.Partitions[0].LostBaselineSuccesses|Should -BeGreaterThan 0
  $r.Partitions[1].LostBaselineSuccesses|Should -BeGreaterThan 0
  $r.Recipe.OAuthAdditionalRequestNames|Should -Be @('offline_access')
  $frozen=[IO.File]::ReadAllText($out+'.inputs.json')|ConvertFrom-Json -AsHashtable
  foreach($row in $frozen.Cases){
   $row.Requests.'1'.Count|Should -Be 1
   $row.Requests.'1'[0].RedirectUri|Should -Be $r.Recipe.ObservedCallback
   $row.Requests.'2'.Count|Should -Be 2
   $row.Requests.'2'[1].RedirectUri|Should -Be $r.Recipe.FallbackCallback
  }
  foreach($case in $frozen.Cases){
   $rows=@($r.Trials|Where-Object CaseId -CEQ $case.Case.Id)
   $rows.Count|Should -Be 2
   foreach($row in $rows){foreach($trace in $row.Trace){if($trace.Phase -ceq 'Final'){$expected=if($trace.Callback -ceq $r.Recipe.ObservedCallback){$case.Case.Primary}else{$case.Case.Secondary};$trace.InjectedScenario|Should -Be $expected}}}
  }
  $raw=[IO.File]::ReadAllText($out)
  $raw|Should -Not -Match 'synthetic-goal5-not-a-session|eyJ[A-Za-z0-9_-]+\.|"AccessToken"|"RefreshToken"'
  if(-not $IsWindows){[int][IO.File]::GetUnixFileMode($out)|Should -Be 384}
  $before=(Get-FileHash $out).Hash
  {Invoke-TokenForgeCallbackExperiment -NativeExecutable $native -OutputPath $out}|Should -Throw '*create-new only*'
  (Get-FileHash $out).Hash|Should -Be $before
  @(Get-Command Invoke-TokenForgeCallbackExperiment -Module TokenForge -ErrorAction SilentlyContinue).Count|Should -Be 0
 }
}
