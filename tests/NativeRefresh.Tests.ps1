BeforeDiscovery {$hasNative=[bool]($env:TOKENFORGE_TEST_NATIVE -and (Test-Path -LiteralPath $env:TOKENFORGE_TEST_NATIVE))}
BeforeAll { . "$PSScriptRoot/fixtures/refresh/RefreshFixture.ps1" }
Describe 'Goal 4 native and PowerShell offline contracts' -Skip:(-not $hasNative) {
 BeforeEach {$root=Join-Path $TestDrive ([guid]::NewGuid().ToString('N'));$null=[IO.Directory]::CreateDirectory($root,[IO.UnixFileMode]448)}
 It 'agrees on complete fresh and missing-evidence plans and exit codes' -ForEach @(@{Warm=$false;Exit=3},@{Warm=$true;Exit=0}) {
  $i=if($Warm){New-WarmRefreshInput}else{New-RefreshInput};$inputPath=Join-Path $root input.json;$inputJson=$i|ConvertTo-Json -Depth 100 -Compress;[IO.File]::WriteAllText($inputPath,$inputJson);[IO.File]::SetUnixFileMode($inputPath,[IO.UnixFileMode]384)
  $ps=Get-TokenForgeRefreshPlan -InputJson $inputJson -AsOf $script:rfNow
  $output=& $env:TOKENFORGE_TEST_NATIVE refresh plan --input-path $inputPath --as-of $script:rfNow.ToString('o') --json
  $LASTEXITCODE|Should -Be $Exit;$native=Read-RefreshJson ($output -join "`n");$native.PlanId|Should -Be $ps.PlanId;$native.SelectedCount|Should -Be $ps.SelectedCount;$native.ReusedCount|Should -Be $ps.ReusedCount
  $planPath=Join-Path $root plan.json;[IO.File]::WriteAllText($planPath,($ps|ConvertTo-Json -Depth 100 -Compress));[IO.File]::SetUnixFileMode($planPath,[IO.UnixFileMode]384)
  $null=& $env:TOKENFORGE_TEST_NATIVE refresh validate --plan-path $planPath --json;$LASTEXITCODE|Should -Be $Exit
 }
 It 'fails safely for malformed inputs and unknown/duplicate flags' {
  $bad=Join-Path $root bad.json;[IO.File]::WriteAllText($bad,'{"Cookie":"synthetic-secret"}');[IO.File]::SetUnixFileMode($bad,[IO.UnixFileMode]384)
  $out=& $env:TOKENFORGE_TEST_NATIVE refresh plan --input-path $bad --json 2>&1;$LASTEXITCODE|Should -Be 1;($out -join "`n")|Should -Not -Match 'synthetic-secret'
  $null=& $env:TOKENFORGE_TEST_NATIVE refresh plan --input-path $bad --input-path $bad --json 2>&1;$LASTEXITCODE|Should -Be 1
 }
 It 'validates history for a native zero-terminal projection (<Case>)' -ForEach @(
  @{Case='Malformed';Valid=$false},@{Case='Wrong schema';Valid=$false},@{Case='Empty valid';Valid=$true},@{Case='Saved valid';Valid=$true}
 ) {
  $i=New-WarmRefreshInput;$plan=Plan-Refresh $i;$json=$plan|ConvertTo-Json -Depth 100 -Compress
  $planPath=Join-Path $root plan.json;$statePath=Join-Path $root run.json;$historyPath=Join-Path $root history.json
  [IO.File]::WriteAllText($planPath,$json);[IO.File]::SetUnixFileMode($planPath,[IO.UnixFileMode]384)
  $run=[TokenForge.Core.AdminWorkflows]::OpenRefreshRun($json,$statePath);$run.Dispose()
  $history=switch($Case){'Malformed'{'not-json'};'Wrong schema'{'{}'};'Empty valid'{[TokenForge.Core.AdminWorkflows]::CreateRefreshHistory()};'Saved valid'{$i.History|ConvertTo-Json -Depth 100 -Compress}}
  [IO.File]::WriteAllText($historyPath,$history);[IO.File]::SetUnixFileMode($historyPath,[IO.UnixFileMode]384)
  $before=(Get-FileHash $statePath).Hash
  $out=& $env:TOKENFORGE_TEST_NATIVE refresh project --plan-path $planPath --state-path $statePath --history-path $historyPath --json 2>&1
  if($Valid){$LASTEXITCODE|Should -Be 0;[TokenForge.Core.ChangeReports]::FingerprintJson(($out -join "`n"))|Should -BeExactly ([TokenForge.Core.ChangeReports]::FingerprintJson($history))}
  else{$LASTEXITCODE|Should -Be 1;($out -join "`n")|Should -Match 'OperationFailed'}
  (Get-FileHash $statePath).Hash|Should -BeExactly $before
 }
}
