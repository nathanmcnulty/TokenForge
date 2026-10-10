BeforeAll {
 . "$PSScriptRoot/../scripts/TokenForgeCiState.ps1"
 Import-Module "$PSScriptRoot/../src/TokenForge/TokenForge.psd1" -Force
 $runner="$PSScriptRoot/../scripts/Test-TokenForgeCiIdle.ps1"
 $now=[DateTimeOffset]'2026-10-07T12:00:00Z'
 $catalog=Get-TokenForgeCatalog -Path "$PSScriptRoot/fixtures/catalog.json"
 $discovery=Get-TokenForgeDiscovery -Catalog $catalog|ConvertTo-Json -Depth 100|ConvertFrom-Json -AsHashtable
 $discovery.FetchedAt=$now.AddMinutes(-10).ToString('o')
 foreach($app in $discovery.Applications){foreach($source in $app.Sources){$source.Location='https://raw.githubusercontent.com/example/public/main/scopes.json'}}
}
Describe 'Scheduled idle refresh boundary' {
 BeforeEach {
  $data=Join-Path $TestDrive ([guid]::NewGuid().ToString())
  $null=New-Item -ItemType Directory $data
  foreach($mode in @('Shallow','Deep')){
   $state=New-TfCiState $discovery -Mode $mode -Now $now.AddHours(-1)
   foreach($batch in $state.Batches){
    $batch.Status='Complete';$batch.Attempts=1
    $batch.Assessed=@(Get-TfCiMembers $state $batch.Index).Count
    $batch.ObservedAt=$now.AddMinutes(-20).ToString('o')
   }
   $state|ConvertTo-Json -Depth 100|Set-Content (Join-Path $data ('weekly-'+$mode.ToLowerInvariant()+'.json'))
  }
  $metadata=Join-Path $data applications.json
  $null=Update-TokenForgeApplicationMetadata -Path $metadata -Document $discovery -Kind Discovery
 }
 It 'idles only with both complete recipes and a source observation today' {
  (& $runner -DataPath $data -EventName schedule -Now $now)|Should -BeTrue
  $before=@(Get-ChildItem $data -File|ForEach-Object {(Get-FileHash $_.FullName).Hash})
  $null=& $runner -DataPath $data -EventName schedule -Now $now
  (@(Get-ChildItem $data -File|ForEach-Object {(Get-FileHash $_.FullName).Hash}) -join ',')|Should -Be ($before -join ',')
 }
 It 'always allows manual dispatch without reading invalid state' {
  'invalid'|Set-Content (Join-Path $data weekly-shallow.json)
  (& $runner -DataPath $data -EventName workflow_dispatch -Now $now)|Should -BeFalse
 }
 It 'refreshes when either recipe or the metadata is missing' {
  foreach($name in @('weekly-shallow.json','weekly-deep.json','applications.json')){
   $path=Join-Path $data $name;$bytes=[IO.File]::ReadAllBytes($path)
   Remove-Item $path
   (& $runner -DataPath $data -EventName schedule -Now $now)|Should -BeFalse
   [IO.File]::WriteAllBytes($path,$bytes)
  }
 }
 It 'does not treat exhausted work as completed' {
  $path=Join-Path $data weekly-deep.json;$state=Get-Content $path -Raw|ConvertFrom-Json -AsHashtable
  $state.Batches[0].Status='Failed';$state.Batches[0].Attempts=3;$state.Batches[0].Assessed=0
  $state|ConvertTo-Json -Depth 100|Set-Content $path
  (& $runner -DataPath $data -EventName schedule -Now $now)|Should -BeFalse
 }
 It 'refreshes at UTC midnight independently of the caller offset' {
  (& $runner -DataPath $data -EventName schedule -Now ([DateTimeOffset]'2026-10-07T16:00:00-08:00'))|Should -BeFalse
  (& $runner -DataPath $data -EventName schedule -Now ([DateTimeOffset]'2026-10-07T05:00:00-07:00'))|Should -BeTrue
 }
 It 'refreshes on the next week and ISO year rollover' {
  foreach($later in @('2026-10-12T00:00:00Z','2027-01-04T00:00:00Z')){
   (& $runner -DataPath $data -EventName schedule -Now ([DateTimeOffset]$later))|Should -BeFalse
  }
 }
 It 'rejects corrupted recipes' {
  $path=Join-Path $data weekly-deep.json;$state=Get-Content $path -Raw|ConvertFrom-Json -AsHashtable
  $state.PlanId='a'*64;$state|ConvertTo-Json -Depth 100|Set-Content $path
  {& $runner -DataPath $data -EventName schedule -Now $now}|Should -Throw
 }
 It 'rejects a valid shallow recipe stored under the deep filename' {
  Copy-Item (Join-Path $data weekly-shallow.json) (Join-Path $data weekly-deep.json) -Force
  {& $runner -DataPath $data -EventName schedule -Now $now}|Should -Throw '*mode mismatch*'
 }
 It 'rejects a rehashed recipe created too far in the future' {
  $path=Join-Path $data weekly-deep.json;$state=Get-Content $path -Raw|ConvertFrom-Json -AsHashtable
  $state.Recipe.CreatedAt=$now.AddMinutes(10).ToString('o');$state.PlanId=Get-TfCiHash $state.Recipe
  $state|ConvertTo-Json -Depth 100|Set-Content $path
  {& $runner -DataPath $data -EventName schedule -Now $now}|Should -Throw '*recipe date*'
 }
 It 'refreshes a yesterday observation even when imported today' {
  $document=Get-Content $metadata -Raw|ConvertFrom-Json -AsHashtable
  $document.Origins['Discovery///'].LastObservedAt=$now.AddDays(-1).ToString('o')
  $document.Runs[0].ObservedAt=$now.AddDays(-1).ToString('o');$document.Runs[0].RecordedAt=$now.ToString('o')
  $document|ConvertTo-Json -Depth 100|Set-Content $metadata
  (& $runner -DataPath $data -EventName schedule -Now $now)|Should -BeFalse
 }
 It 'rejects private metadata rather than hiding it in idle status' {
  $document=Get-Content $metadata -Raw|ConvertFrom-Json -AsHashtable
  $document.AccessToken='synthetic-secret';$document|ConvertTo-Json -Depth 100|Set-Content $metadata
  {& $runner -DataPath $data -EventName schedule -Now $now}|Should -Throw
 }
 It 'rejects future or mismatched discovery evidence' {
  $document=Get-Content $metadata -Raw|ConvertFrom-Json -AsHashtable
  $document.Origins['Discovery///'].LastObservedAt=$now.AddMinutes(1).ToString('o')
  $document.Runs[0].ObservedAt=$now.AddMinutes(1).ToString('o')
  $document|ConvertTo-Json -Depth 100|Set-Content $metadata
  {& $runner -DataPath $data -EventName schedule -Now $now}|Should -Throw '*discovery date*'
  $document.Runs[0].ObservedAt=$now.AddMinutes(-5).ToString('o')
  $document|ConvertTo-Json -Depth 100|Set-Content $metadata
  {& $runner -DataPath $data -EventName schedule -Now $now}|Should -Throw '*discovery date*'
 }
 It 'requires the origin to reference exactly one recorded Discovery run' {
  $document=Get-Content $metadata -Raw|ConvertFrom-Json -AsHashtable
  $document.Origins['Discovery///'].LastRunId=[guid]::NewGuid().ToString()
  $document|ConvertTo-Json -Depth 100|Set-Content $metadata
  {& $runner -DataPath $data -EventName schedule -Now $now}|Should -Throw '*run mismatch*'
 }
}
