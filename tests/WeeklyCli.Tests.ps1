BeforeAll {
 . "$PSScriptRoot/../scripts/TokenForgeCiState.ps1"
 Import-Module "$PSScriptRoot/../src/TokenForge/TokenForge.psd1" -Force
 $catalog=Get-TokenForgeCatalog -Path "$PSScriptRoot/fixtures/catalog.json"
 $catalog.Source='https://raw.githubusercontent.com/example/public/main/scopes.json'
 $discovery=Get-TokenForgeDiscovery -Catalog $catalog|ConvertTo-Json -Depth 100|ConvertFrom-Json -AsHashtable
 $cli="$PSScriptRoot/../scripts/tokenforge.ps1"
}
Describe 'Offline weekly CLI coverage' {
 BeforeEach {
  $root=Join-Path $TestDrive ([guid]::NewGuid().ToString())
  $null=New-Item -ItemType Directory $root
  $state=New-TfCiState $discovery -Mode Deep -ResourceId @('00000003-0000-0000-c000-000000000000','797f4846-ba00-4fd7-ba43-dac1f8f63013')
  $state|ConvertTo-Json -Depth 100|Set-Content "$root/weekly-deep.json"
 }
 It 'preserves literal date-looking claim text when reading frozen reports' {
  $literal=[TokenForge.Core.DiscoverySourceClaims]::ReadMetadataJson((ConvertTo-Json -InputObject $discovery -Depth 100))
  $app=@($literal.Applications|Where-Object AppId -eq '11111111-1111-1111-1111-111111111111')[0]
  $app.SourceClaims[0].Name='2026-01-01T00:00:00+02:00'
  $claims=[TokenForge.Core.DiscoverySourceClaims]::NormalizeMetadata((ConvertTo-Json -InputObject $app.SourceClaims -Depth 32 -Compress),$app.AppId)
  $app.SourceClaims=$claims.SourceClaims;$app.MetadataConflicts=$claims.MetadataConflicts
  $frozen=New-TfCiState $literal -Mode Deep -ResourceId @('00000003-0000-0000-c000-000000000000','797f4846-ba00-4fd7-ba43-dac1f8f63013')
  ConvertTo-Json -InputObject $frozen -Depth 100|Set-Content "$root/weekly-deep.json"
  $before=(Get-FileHash "$root/weekly-deep.json").Hash
  $result=(& $cli research weekly -StatePath $root -Json)|ConvertFrom-Json
  $LASTEXITCODE|Should -Be 0
  $result.Reports[0].PlanId|Should -BeExactly $frozen.PlanId
  if($env:TOKENFORGE_TEST_NATIVE){
   $nativeResult=(& $env:TOKENFORGE_TEST_NATIVE research weekly --state-path $root --json)|ConvertFrom-Json
   $LASTEXITCODE|Should -Be 0
   $nativeResult.Reports[0].PlanId|Should -BeExactly $frozen.PlanId
  }
  (Get-FileHash "$root/weekly-deep.json").Hash|Should -BeExactly $before
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
  $r.NextAction|Should -Match 'explicitly approved manual run'
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
 It 'preserves legacy Unicode and control-character hash bytes' {
  $texts=@([string][char]0xa0,[string][char]0x80+[char]0x93,[string][char]0x85,[string][char]0x2028,[string][char]0x2029,"quote`" slash\ newline`n")
  foreach($text in $texts){
   $value=[ordered]@{SchemaVersion=1;CreatedAt='2026-01-01T00:00:00+00:00';Name=$text}
   [TokenForge.Core.WeeklyRecipeHash]::Compute((ConvertTo-Json -InputObject $value -Depth 100 -Compress))|Should -BeExactly (Get-TfCiHash $value)
  }
 }
 It 'keeps legacy date-looking text beyond parser precision literal' {
  foreach($text in @('0001-01-01T00:00:00+01:00','9999-12-31T23:59:59-01:00','2026-01-01T00:00:00z','2026-01-01T24:00:00Z','2026-01-01T00:00:00+15:00','2026-01-01T00:00:00+14:01','2026-01-01T00:00:00+01:60','2026-01-01T00:00:00+99','2026-01-01T00:00:00.12345678Z','2026-01-01T00:00:00Z ','2026-01-01T00:00:00 +00:00',"2026-01-01T00:00:00Z`n")){
   $value=[ordered]@{SchemaVersion=1;CreatedAt='2026-01-01T00:00:00+00:00';Name=$text}
   [TokenForge.Core.WeeklyRecipeHash]::Compute((ConvertTo-Json -InputObject $value -Depth 100 -Compress))|Should -BeExactly (Get-TfCiHash $value)
  }
 }
 It 'preserves case-insensitive selected IDs with exact historical selection keys' {
  $mixed=[TokenForge.Core.DiscoverySourceClaims]::ReadMetadataJson((ConvertTo-Json -InputObject $discovery -Depth 100))
  $mixed.SchemaVersion=1
  foreach($app in $mixed.Applications){$app.Remove('SourceClaims');$app.Remove('MetadataConflicts')}
  $mixed.Applications[0].AppId='abcdefab-cdef-abcd-efab-cdefabcdefab'
  $selected=$mixed.Applications[0].AppId
  $frozen=New-TfCiState $mixed -Mode Deep -AppId @($selected)
  $frozen.Recipe.AppIds=@($selected.ToUpperInvariant())
  $frozen.DeepSelectionHistory=@{$selected=$frozen.Recipe.Week}
  $frozen.PlanId=Get-TfCiHash $frozen.Recipe
  Assert-TfCiState $frozen
  $report=[TokenForge.Core.WeeklyResearchReport]::Create((ConvertTo-Json -InputObject $frozen -Depth 100),'Deep',[DateTimeOffset]::UtcNow)|ConvertFrom-Json
  $report.SelectedApplications|Should -Be 1
  $report.DeepSelectionHistoryApplications|Should -Be 1
 }
 It 'matches the existing report fields for partial and complete batches' {
  $state=New-TfCiState $discovery -Mode Shallow -ChunkSize 1
  $first=@(Get-TfCiMembers $state 0).Count
  Merge-TfCiReceipt $state @{SchemaVersion=1;PlanId=$state.PlanId;Index=0;Attempt=1;Status='Complete';Assessed=$first;Successful=0;DurationSeconds=12;ObservedAt=[DateTimeOffset]::UtcNow.ToString('o')}
  $now=[DateTimeOffset]::UtcNow
  $old=Get-TfCiReport $state $now
  $new=[TokenForge.Core.DiscoverySourceClaims]::ReadMetadataJson([TokenForge.Core.WeeklyResearchReport]::Create((ConvertTo-Json -InputObject $state -Depth 100),'Shallow',$now))
  foreach($field in $old.Keys){
   if($old[$field] -is [ValueType] -and $old[$field] -isnot [bool]){
    [decimal]$new[$field]|Should -Be ([decimal]$old[$field])
   }else{
    (ConvertTo-Json -InputObject $new[$field] -Depth 20 -Compress)|Should -BeExactly (ConvertTo-Json -InputObject $old[$field] -Depth 20 -Compress)
   }
  }
 }
 It 'rejects impossible completed checkpoints: <Case>' -ForEach @(@{Case='NoAttempt'},@{Case='Duration'},@{Case='ZoneLess'}) {
  $state.Batches[0].Status='Complete';$state.Batches[0].Attempts=1
  $state.Batches[0].Assessed=$state.Recipe.AppIds.Count
  $state.Batches[0].AssessedPairs=$state.Recipe.AppIds.Count*2
  $state.Batches[0].ObservedAt=[DateTimeOffset]::UtcNow.ToString('o')
  switch($Case){
   NoAttempt {$state.Batches[0].Attempts=0}
   Duration {$state.Batches[0].DurationSeconds=3601}
   ZoneLess {$state.Batches[0].ObservedAt='2026-10-13T01:02:03'}
  }
  { [TokenForge.Core.WeeklyResearchReport]::Create((ConvertTo-Json -InputObject $state -Depth 100),'Deep',[DateTimeOffset]::UtcNow) }|Should -Throw
 }
 It 'rejects completed batches with missing observation dates' {
  $state.Batches[0].Status='Complete';$state.Batches[0].Attempts=1
  $state.Batches[0].Assessed=$state.Recipe.AppIds.Count
  $state.Batches[0].AssessedPairs=$state.Recipe.AppIds.Count*2
  $state.Batches[0].ObservedAt=$null
  $state|ConvertTo-Json -Depth 100|Set-Content "$root/weekly-deep.json"
  $result=(. $cli research weekly -StatePath $root -Json)|ConvertFrom-Json
  $LASTEXITCODE|Should -Be 1
  $result.Code|Should -Be 'OperationFailed'
 }
 It 'rejects changed recipes and duplicate keys without emitting their contents' {
  $raw=Get-Content "$root/weekly-deep.json" -Raw
  $raw=$raw.Replace('"PlanId":', '"PlanId":"synthetic-private", "PlanId":')
  $raw|Set-Content "$root/weekly-deep.json"
  $result=. $cli research weekly -StatePath $root -Json
  $LASTEXITCODE|Should -Be 1
  $result|Should -Not -Match 'synthetic-private'
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
