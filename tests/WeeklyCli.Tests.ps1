BeforeAll {
 . "$PSScriptRoot/../scripts/TokenForgeCiState.ps1"
 Import-Module "$PSScriptRoot/../src/TokenForge/TokenForge.psd1" -Force
 $discovery=Get-TokenForgeDiscovery -Catalog (Get-TokenForgeCatalog -Path "$PSScriptRoot/fixtures/catalog.json")|ConvertTo-Json -Depth 100|ConvertFrom-Json -AsHashtable
 $cli="$PSScriptRoot/../scripts/tokenforge.ps1"
}
Describe 'Offline weekly CLI coverage' {
 BeforeEach {
  $root=Join-Path $TestDrive ([guid]::NewGuid().ToString())
  $null=New-Item -ItemType Directory $root
  $state=New-TfCiState $discovery -Mode Deep -ResourceId @('00000003-0000-0000-c000-000000000000','797f4846-ba00-4fd7-ba43-dac1f8f63013')
  $state|ConvertTo-Json -Depth 100|Set-Content "$root/weekly-deep.json"
 }
 It 'reads frozen pairs without a profile and changes no files' {
  $before=(Get-FileHash "$root/weekly-deep.json").Hash
  $profileRoot=Join-Path $root missing-profiles
  $result=(& $cli research weekly -StatePath $root -Root $profileRoot -Json)|ConvertFrom-Json
  $LASTEXITCODE|Should -Be 0
  $result.Reports.Count|Should -Be 1
  $r=$result.Reports[0]
  $r.SelectedPairs|Should -Be ($state.Recipe.AppIds.Count*2)
  $r.RemainingPairs|Should -Be $r.SelectedPairs
  $r.CurrentWeek|Should -BeTrue
  $r.NextAction|Should -Match 'Pending batches'
  $result.CredentialOutput|Should -BeFalse
  (Get-FileHash "$root/weekly-deep.json").Hash|Should -Be $before
  Test-Path $profileRoot|Should -BeFalse
 }
 It 'distinguishes successful apps and pairs in complete reports and human output' {
  $count=$state.Recipe.AppIds.Count
  Merge-TfCiReceipt $state @{SchemaVersion=2;PlanId=$state.PlanId;Index=0;Attempt=1;Status='Complete';Assessed=$count;Successful=1;AssessedPairs=$count*2;SuccessfulPairs=2;DurationSeconds=1;ObservedAt=[DateTimeOffset]::UtcNow.ToString('o')}
  $state|ConvertTo-Json -Depth 100|Set-Content "$root/weekly-deep.json"
  $r=((& $cli research weekly -StatePath $root -Json)|ConvertFrom-Json).Reports[0]
  $r.Complete|Should -BeTrue
  $r.RemainingPairs|Should -Be 0
  $r.SuccessfulApplications|Should -Be 1
  $r.SuccessfulPairs|Should -Be 2
  $text=(& $cli research weekly -StatePath $root)|Out-String
  $text|Should -Match '1 apps / 2 pairs succeeded'
  $text|Should -Match 'structural exclusions'
 }
 It 'shows exhausted-batch guidance without retrying anything' {
  $state.Batches[0].Attempts=3;$state.Batches[0].Status='Failed'
  $state|ConvertTo-Json -Depth 100|Set-Content "$root/weekly-deep.json"
  $r=((& $cli research weekly -StatePath $root -Json)|ConvertFrom-Json).Reports[0]
  $r.ExhaustedBatches|Should -Be 1
  $r.NextAction|Should -Match 'retry_exhausted'
 }
 It 'labels an older complete recipe as outside the current week' {
  $old=New-TfCiState $discovery -Mode Shallow -Now ([DateTimeOffset]::UtcNow.AddDays(-14))
  Merge-TfCiReceipt $old @{SchemaVersion=1;PlanId=$old.PlanId;Index=0;Attempt=1;Status='Complete';Assessed=$old.Recipe.AppIds.Count;Successful=0;DurationSeconds=1;ObservedAt=[DateTimeOffset]::UtcNow.ToString('o')}
  $old|ConvertTo-Json -Depth 100|Set-Content "$root/weekly-shallow.json"
  $r=((& $cli research weekly -StatePath $root -Json)|ConvertFrom-Json).Reports[0]
  $r.Mode|Should -Be 'Shallow'
  $r.CurrentWeek|Should -BeFalse
  $r.NextAction|Should -Match 'Refresh the checkout'
 }
 It 'rejects a completed future recipe instead of treating it as an old snapshot' {
  $future=New-TfCiState $discovery -Mode Shallow -Now ([DateTimeOffset]::UtcNow.AddDays(14))
  $future.Batches[0].Status='Complete';$future.Batches[0].Attempts=1;$future.Batches[0].Assessed=$future.Recipe.AppIds.Count;$future.Batches[0].ObservedAt=$future.Recipe.CreatedAt
  Assert-TfCiState $future
  $future|ConvertTo-Json -Depth 100|Set-Content "$root/weekly-shallow.json"
  $r=(. $cli research weekly -StatePath $root -Json)|ConvertFrom-Json
  $LASTEXITCODE|Should -Be 1
  $r.Code|Should -Be 'OperationFailed'
 }
 It 'rejects authentication prompts before prompting' {
  Mock Read-Host {throw 'Unexpected prompt.'}
  $r=(. $cli research weekly -StatePath $root -PromptPassphrase -Json)|ConvertFrom-Json
  $LASTEXITCODE|Should -Be 1
  $r.Code|Should -Be 'OperationFailed'
  Should -Invoke Read-Host -Exactly -Times 0
 }
 It 'rejects a mislabeled frozen recipe without echoing its contents' {
  Move-Item "$root/weekly-deep.json" "$root/weekly-shallow.json"
  $r=(. $cli research weekly -StatePath $root -Json)|ConvertFrom-Json
  $LASTEXITCODE|Should -Be 1
  $r.Code|Should -Be 'OperationFailed'
 }
 It 'rejects a linked recipe before reading it' -Skip:($IsWindows) {
  Move-Item "$root/weekly-deep.json" "$root/source.json"
  $null=New-Item -ItemType SymbolicLink -Path "$root/weekly-deep.json" -Target "$root/source.json"
  $r=(. $cli research weekly -StatePath $root -Json)|ConvertFrom-Json
  $LASTEXITCODE|Should -Be 1
  $r.Code|Should -Be 'OperationFailed'
 }
 It 'reads the same frozen report through the packaged native adapter' -Skip:(-not $env:TOKENFORGE_TEST_NATIVE) {
  $nativeResult=(& $env:TOKENFORGE_TEST_NATIVE research weekly --state-path $root --json)|ConvertFrom-Json
  $LASTEXITCODE|Should -Be 0
  $nativeResult.Reports[0].PlanId|Should -Be $state.PlanId
  $nativeResult.Reports[0].SelectedPairs|Should -Be ($state.Recipe.AppIds.Count*2)
  $nativeResult.CredentialOutput|Should -BeFalse
 }
 It 'rejects unexpected private fields' {
  $state.Recipe.AccessToken='synthetic-private'
  $state|ConvertTo-Json -Depth 100|Set-Content "$root/weekly-deep.json"
  $outputText=. $cli research weekly -StatePath $root -Json
  $LASTEXITCODE|Should -Be 1
  $outputText|Should -Not -Match 'synthetic-private'
 }
}
