BeforeDiscovery {$hasNative=[bool]($env:TOKENFORGE_TEST_NATIVE -and (Test-Path -LiteralPath $env:TOKENFORGE_TEST_NATIVE))}
BeforeAll { . "$PSScriptRoot/fixtures/refresh/RefreshFixture.ps1" }
Describe 'Goal 4 native and PowerShell offline contracts' -Skip:(-not $hasNative) {
 It 'agrees on complete fresh and missing-evidence plans and exit codes' -ForEach @(@{Warm=$false;Exit=3},@{Warm=$true;Exit=0}) {
  $i=if($Warm){New-WarmRefreshInput}else{New-RefreshInput};$inputPath=Join-Path $TestDrive input.json;$inputJson=$i|ConvertTo-Json -Depth 100 -Compress;[IO.File]::WriteAllText($inputPath,$inputJson)
  $ps=Get-TokenForgeRefreshPlan -InputJson $inputJson -AsOf $script:rfNow
  $output=& $env:TOKENFORGE_TEST_NATIVE refresh plan --input-path $inputPath --as-of $script:rfNow.ToString('o') --json
  $LASTEXITCODE|Should -Be $Exit;$native=Read-RefreshJson ($output -join "`n");$native.PlanId|Should -Be $ps.PlanId;$native.SelectedCount|Should -Be $ps.SelectedCount;$native.ReusedCount|Should -Be $ps.ReusedCount
  $planPath=Join-Path $TestDrive plan.json;[IO.File]::WriteAllText($planPath,($ps|ConvertTo-Json -Depth 100 -Compress))
  $null=& $env:TOKENFORGE_TEST_NATIVE refresh validate --plan-path $planPath --json;$LASTEXITCODE|Should -Be $Exit
 }
 It 'fails safely for malformed inputs and unknown/duplicate flags' {
  $bad=Join-Path $TestDrive bad.json;[IO.File]::WriteAllText($bad,'{"Cookie":"synthetic-secret"}')
  $out=& $env:TOKENFORGE_TEST_NATIVE refresh plan --input-path $bad --json 2>&1;$LASTEXITCODE|Should -Be 2;($out -join "`n")|Should -Not -Match 'synthetic-secret'
  $null=& $env:TOKENFORGE_TEST_NATIVE refresh plan --input-path $bad --input-path $bad --json 2>&1;$LASTEXITCODE|Should -Be 2
 }
}
