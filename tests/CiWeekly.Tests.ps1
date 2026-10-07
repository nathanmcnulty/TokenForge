BeforeAll {
 . "$PSScriptRoot/../scripts/TokenForgeCiState.ps1"
 Import-Module "$PSScriptRoot/../src/TokenForge/TokenForge.psd1" -Force
 $catalog=Get-TokenForgeCatalog -Path "$PSScriptRoot/fixtures/catalog.json"
 $discovery=Get-TokenForgeDiscovery -Catalog $catalog|ConvertTo-Json -Depth 100|ConvertFrom-Json -AsHashtable
}
Describe 'Frozen CI recipes and receipt completeness' {
 It 'freezes public membership and round trips the plan hash' {
  $state=New-TfCiState $discovery -ChunkSize 1
  Assert-TfCiState $state
  $round=$state|ConvertTo-Json -Depth 100|ConvertFrom-Json -AsHashtable
  Assert-TfCiState $round
  @(Get-TfCiWork $round 4).Count|Should -Be ([Math]::Min(4,$state.Batches.Count))
  $round.Recipe.AppIds[0]='ffffffff-ffff-ffff-ffff-ffffffffffff'
  {Assert-TfCiState $round}|Should -Throw
 }
 It 'retries failed work independently of run numbers and never counts it complete' {
  $state=New-TfCiState $discovery -ChunkSize 1
  $receipt=[ordered]@{SchemaVersion=1;PlanId=$state.PlanId;Index=0;Attempt=1;Status='Failed';Assessed=0;Successful=0;DurationSeconds=20;ObservedAt=[DateTimeOffset]::UtcNow.ToString('o')}
  Merge-TfCiReceipt $state $receipt
  (Get-TfCiReport $state).CompletedBatches|Should -Be 0
  $receipt.Attempt=2;$receipt.Status='Complete';$receipt.Assessed=1
  Merge-TfCiReceipt $state $receipt
  (Get-TfCiReport $state).AssessedApplications|Should -Be 1
  @(Get-TfCiWork $state)|Should -Not -Contain 0
  {Merge-TfCiReceipt $state $receipt}|Should -Throw
 }
 It 'rejects foreign receipts, incomplete completion, secrets, and invalid bounds' {
  $state=New-TfCiState $discovery -ChunkSize 1
  $receipt=[ordered]@{SchemaVersion=1;PlanId=('a'*64);Index=0;Attempt=1;Status='Complete';Assessed=1;Successful=0;DurationSeconds=20;ObservedAt=[DateTimeOffset]::UtcNow.ToString('o')}
  {Merge-TfCiReceipt $state $receipt}|Should -Throw
  $receipt.PlanId=$state.PlanId;$receipt.Assessed=0
  {Merge-TfCiReceipt $state $receipt}|Should -Throw
  $receipt.Assessed=1;$receipt.AccessToken='private'
  {Merge-TfCiReceipt $state $receipt}|Should -Throw
  {New-TfCiState $discovery -ChunkSize 0}|Should -Throw
 }
 It 'uses the ISO year at a calendar boundary' {
  Get-TfCiWeek ([DateTimeOffset]'2027-01-01T00:00:00Z')|Should -Be '2026-W53'
 }
}
Describe 'Encrypted private checkpoints' {
 It 'authenticates data and account/plan/partition context' {
  $key=[Convert]::ToBase64String([Security.Cryptography.RandomNumberGenerator]::GetBytes(32))
  $bytes=[Text.Encoding]::UTF8.GetBytes('private diagnostic evidence')
  $blob=Protect-TfCiCheckpoint $bytes $key 'tenant/account/plan/0'
  [Text.Encoding]::UTF8.GetString((Unprotect-TfCiCheckpoint $blob $key 'tenant/account/plan/0'))|Should -Be 'private diagnostic evidence'
  {Unprotect-TfCiCheckpoint $blob $key 'another-account'}|Should -Throw
  $blob[-1]=$blob[-1] -bxor 1
  {Unprotect-TfCiCheckpoint $blob $key 'tenant/account/plan/0'}|Should -Throw
  {Protect-TfCiCheckpoint $bytes 'bad' 'context'}|Should -Throw
 }
}
Describe 'Weekly publisher integration' {
 BeforeEach {
  Mock Import-Module {}
  Mock Update-TokenForgeDiscovery {$discovery}
  Mock Get-TokenForgeApplicationMetadata {}
  $data=Join-Path $TestDrive ([guid]::NewGuid().ToString());$bundle=Join-Path $TestDrive ([guid]::NewGuid().ToString())
  $null=New-Item -ItemType Directory $data
  git -C $data init --quiet
  git -C $data -c user.name=Test -c user.email=test@example.invalid commit --allow-empty --quiet -m seed
  $runner="$PSScriptRoot/../scripts/Invoke-TokenForgeWeeklyCi.ps1"
 }
 It 'publishes complete structural coverage, retains successful evidence, and resumes without selecting completed work' {
  $null=& $runner -Action Prepare -DataPath $data -BundlePath $bundle -Mode Shallow
  $state=Get-Content "$bundle/state.json" -Raw|ConvertFrom-Json -AsHashtable
  $request=Get-Content "$bundle/request.json" -Raw|ConvertFrom-Json -AsHashtable
  $request.Indices.Count|Should -Be 1
  $out=Join-Path $bundle result-0;$null=New-Item -ItemType Directory $out
  @{SchemaVersion=1;PlanId=$state.PlanId;Index=0;Attempt=1;Status='Complete';Assessed=$state.Recipe.AppIds.Count;Successful=1;DurationSeconds=10;ObservedAt=[DateTimeOffset]::UtcNow.ToString('o')}|ConvertTo-Json|Set-Content "$out/receipt.json"
  @{SchemaVersion=1;Observations=@(@{ClientId=$state.Recipe.AppIds[0];ResourceId='00000003-0000-0000-c000-000000000000';ObservedAt=[DateTimeOffset]::UtcNow.ToString('o');Scopes=@('User.Read');Evidence='AnonymousTenantTokenObservation';SignatureValidated=$false});Disclaimer='Observed scopes are session/tenant dependent, not universal consent or guaranteed API access.'}|ConvertTo-Json -Depth 10|Set-Content "$out/scopes.json"
  $report=& $runner -Action Publish -DataPath $data -BundlePath $bundle
  $report.Complete|Should -BeTrue
  $report.AssessedApplications|Should -Be $state.Recipe.AppIds.Count
  $null=& $runner -Action Prepare -DataPath $data -BundlePath $bundle -Mode Shallow
  @((Get-Content "$bundle/request.json" -Raw|ConvertFrom-Json).Indices).Count|Should -Be 0
  @((Get-Content "$data/scopes/chunk-0000.json" -Raw|ConvertFrom-Json).Observations).Count|Should -Be 1
 }
 It 'automatically starts a separately bounded deep recipe only after shallow completion' {
  $null=& $runner -Action Prepare -DataPath $data -BundlePath $bundle -Mode Shallow
  $state=Get-Content "$data/weekly-shallow.json" -Raw|ConvertFrom-Json -AsHashtable
  foreach($batch in $state.Batches){$batch.Status='Complete';$batch.Assessed=@(Get-TfCiMembers $state $batch.Index).Count;$batch.Attempts=1;$batch.ObservedAt=[DateTimeOffset]::UtcNow.ToString('o')}
  $state|ConvertTo-Json -Depth 100|Set-Content "$data/weekly-shallow.json"
  $report=& $runner -Action Prepare -DataPath $data -BundlePath $bundle -Mode Auto -DeepMaxApplications 1
  $report.Mode|Should -Be Deep
  $deep=Get-Content "$data/weekly-deep.json" -Raw|ConvertFrom-Json -AsHashtable
  $deep.Recipe.AppIds.Count|Should -Be 1
  $deep.Recipe.ChunkSize|Should -Be 25
  $deep.Recipe.MaxRedirects|Should -Be 4
 }
 It 'rejects targeted shallow coverage and never expands an empty deep selection' {
  {& $runner -Action Prepare -DataPath $data -BundlePath $bundle -Mode Shallow -AppId $discovery.Applications[0].AppId}|Should -Throw '*only for Deep*'
  $noCallbacks=$discovery|ConvertTo-Json -Depth 100|ConvertFrom-Json -AsHashtable
  foreach($app in $noCallbacks.Applications){$app.RedirectUris=@()}
  Mock Update-TokenForgeDiscovery {$noCallbacks}
  {& $runner -Action Prepare -DataPath $data -BundlePath $bundle -Mode Deep}|Should -Throw '*bounded deep selection*'
  Test-Path "$data/weekly-deep.json"|Should -BeFalse
 }
 It 'records missing worker artifacts as failed work instead of claiming completion' {
  $null=& $runner -Action Prepare -DataPath $data -BundlePath $bundle -Mode Shallow
  $report=& $runner -Action Publish -DataPath $data -BundlePath $bundle
  $report.Complete|Should -BeFalse
  $state=Get-Content "$data/weekly-shallow.json" -Raw|ConvertFrom-Json -AsHashtable
  $state.Batches[0].Status|Should -Be Failed
  $state.Batches[0].Attempts|Should -Be 1
 }
}
