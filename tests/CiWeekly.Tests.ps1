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
 It 'orders newly created and restored batches by attempts and numeric index' {
  $many=$discovery|ConvertTo-Json -Depth 100|ConvertFrom-Json -AsHashtable
  $many.Applications=@(1..55|ForEach-Object {$app=$discovery.Applications[0]|ConvertTo-Json -Depth 100|ConvertFrom-Json -AsHashtable;$app.AppId=('f0000000-0000-0000-0000-{0:D12}' -f $_);$app})
  $state=New-TfCiState $many -ChunkSize 1
  (@(Get-TfCiWork $state 4) -join ',')|Should -Be '0,1,2,3'
  $round=$state|ConvertTo-Json -Depth 100|ConvertFrom-Json -AsHashtable
  (@(Get-TfCiWork $round 4) -join ',')|Should -Be '0,1,2,3'
 }
 It 'hashes UTC instants independently of parsed host-local DateTime values' {
  $value=[ordered]@{SchemaVersion=1;CreatedAt='2026-10-07T20:09:09.9021780+00:00';Nested=@{FetchedAt='2026-10-07T20:08:00+00:00'}}
  $round=$value|ConvertTo-Json -Compress|ConvertFrom-Json -AsHashtable
  (Get-TfCiHash $round)|Should -Be (Get-TfCiHash $value)
  # Same representation produced by the original algorithm on a UTC runner.
  $normalized='{"SchemaVersion":1,"CreatedAt":"2026-10-07T20:09:09.902178+00:00","Nested":{"FetchedAt":"2026-10-07T20:08:00+00:00"}}'
  $expected=[Convert]::ToHexString([Security.Cryptography.SHA256]::HashData([Text.Encoding]::UTF8.GetBytes($normalized))).ToLowerInvariant()
  (Get-TfCiHash $value)|Should -Be $expected
 }
 It 'rejects private, malformed, future, and shallow selection history' {
  $state=New-TfCiState $discovery -Mode Deep
  $state.DeepSelectionHistory=@{}
  foreach($id in $state.Recipe.AppIds){$state.DeepSelectionHistory[$id]=$state.Recipe.Week}
  Assert-TfCiState $state
  $state.DeepSelectionHistory['ffffffff-ffff-ffff-ffff-ffffffffffff']=$state.Recipe.Week
  {Assert-TfCiState $state}|Should -Throw
  $state.DeepSelectionHistory.Remove('ffffffff-ffff-ffff-ffff-ffffffffffff')
  $id=$state.Recipe.AppIds[0]
  foreach($week in @('2026-W00','2026-W54','9999-W01','tenant/account',@{AccessToken='secret'})){$state.DeepSelectionHistory[$id]=$week;{Assert-TfCiState $state}|Should -Throw}
  $shallow=New-TfCiState $discovery;$shallow.DeepSelectionHistory=@{}
  {Assert-TfCiState $shallow}|Should -Throw
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
 It 'prioritizes never-selected flows even when shallow successes are fresh' {
  $prior=New-TfCiState $discovery -Mode Deep -AppId @($discovery.Applications[0].AppId) -Now ([DateTimeOffset]::UtcNow.AddDays(-7))
  $prior|ConvertTo-Json -Depth 100|Set-Content "$data/weekly-deep.json"
  $null=New-Item -ItemType Directory "$data/scopes"
  @{SchemaVersion=1;Observations=@($discovery.Applications|ForEach-Object {@{ClientId=$_.AppId;ResourceId='00000003-0000-0000-c000-000000000000';ObservedAt=[DateTimeOffset]::UtcNow.ToString('o');Scopes=@('User.Read');Evidence='AnonymousTenantTokenObservation';SignatureValidated=$false}});Disclaimer='Observed scopes are session/tenant dependent, not universal consent or guaranteed API access.'}|ConvertTo-Json -Depth 10|Set-Content "$data/scopes/chunk-0000.json"
  $null=& $runner -Action Prepare -DataPath $data -BundlePath $bundle -Mode Deep -DeepMaxApplications 1
  $deep=Get-Content "$data/weekly-deep.json" -Raw|ConvertFrom-Json -AsHashtable
  $deep.Recipe.AppIds[0]|Should -Not -Be $prior.Recipe.AppIds[0]
  $deep.DeepSelectionHistory[$prior.Recipe.AppIds[0]]|Should -Be $prior.Recipe.Week
  $deep.DeepSelectionHistory[$deep.Recipe.AppIds[0]]|Should -Be $deep.Recipe.Week
 }
 It 'migrates a current frozen selection without changing its hash or issuing more work' {
  $prior=New-TfCiState $discovery -Mode Deep -AppId @($discovery.Applications[0].AppId)
  foreach($batch in $prior.Batches){$batch.Status='Complete';$batch.Assessed=1;$batch.Attempts=1;$batch.ObservedAt=[DateTimeOffset]::UtcNow.ToString('o')}
  $prior|ConvertTo-Json -Depth 100|Set-Content "$data/weekly-deep.json"
  $null=& $runner -Action Prepare -DataPath $data -BundlePath $bundle -Mode Deep
  $deep=Get-Content "$data/weekly-deep.json" -Raw|ConvertFrom-Json -AsHashtable
  $deep.PlanId|Should -Be $prior.PlanId
  ($deep.Recipe.AppIds -join ',')|Should -Be ($prior.Recipe.AppIds -join ',')
  @((Get-Content "$bundle/request.json" -Raw|ConvertFrom-Json).Indices).Count|Should -Be 0
  $deep.DeepSelectionHistory[$deep.Recipe.AppIds[0]]|Should -Be $deep.Recipe.Week
 }
 It 'selects oldest deep history after every candidate has been selected' {
  $prior=New-TfCiState $discovery -Mode Deep -AppId @($discovery.Applications[0].AppId) -Now ([DateTimeOffset]::UtcNow.AddDays(-7))
  $prior.DeepSelectionHistory=@{}
  foreach($app in $discovery.Applications){$prior.DeepSelectionHistory[$app.AppId]=Get-TfCiWeek ([DateTimeOffset]::UtcNow.AddDays(-14))}
  $prior.DeepSelectionHistory[$prior.Recipe.AppIds[0]]=$prior.Recipe.Week
  $prior|ConvertTo-Json -Depth 100|Set-Content "$data/weekly-deep.json"
  $null=& $runner -Action Prepare -DataPath $data -BundlePath $bundle -Mode Deep -DeepMaxApplications 1
  $deep=Get-Content "$data/weekly-deep.json" -Raw|ConvertFrom-Json -AsHashtable
  $deep.Recipe.AppIds[0]|Should -Not -Be $prior.Recipe.AppIds[0]
  $deep.DeepSelectionHistory.Count|Should -Be $discovery.Applications.Count
 }
 It 'prunes removed public IDs while preserving history of remaining apps' {
  $prior=New-TfCiState $discovery -Mode Deep -Now ([DateTimeOffset]::UtcNow.AddDays(-7))
  $prior.DeepSelectionHistory=@{}
  foreach($id in $prior.Recipe.AppIds){$prior.DeepSelectionHistory[$id]=$prior.Recipe.Week}
  $prior|ConvertTo-Json -Depth 100|Set-Content "$data/weekly-deep.json"
  $reduced=$discovery|ConvertTo-Json -Depth 100|ConvertFrom-Json -AsHashtable
  $removed=$reduced.Applications[-1].AppId
  $reduced.Applications=@($reduced.Applications|Where-Object AppId -ne $removed)
  Mock Update-TokenForgeDiscovery {$reduced}
  $null=& $runner -Action Prepare -DataPath $data -BundlePath $bundle -Mode Deep -DeepMaxApplications 1
  $deep=Get-Content "$data/weekly-deep.json" -Raw|ConvertFrom-Json -AsHashtable
  $deep.DeepSelectionHistory.Contains($removed)|Should -BeFalse
  $deep.DeepSelectionHistory.Count|Should -Be $reduced.Applications.Count
 }
 It 'keeps changed hints ahead of oldest history without using a GUID cursor' {
  $prior=New-TfCiState $discovery -Mode Deep -AppId @($discovery.Applications[0].AppId) -Now ([DateTimeOffset]::UtcNow.AddDays(-7))
  $prior.DeepSelectionHistory=@{}
  foreach($app in $discovery.Applications){$prior.DeepSelectionHistory[$app.AppId]=$prior.Recipe.Week}
  $prior|ConvertTo-Json -Depth 100|Set-Content "$data/weekly-deep.json"
  $changed=$discovery|ConvertTo-Json -Depth 100|ConvertFrom-Json -AsHashtable
  $changed.Applications[-1].Name+=' changed'
  Mock Update-TokenForgeDiscovery {$changed}
  $null=& $runner -Action Prepare -DataPath $data -BundlePath $bundle -Mode Deep -DeepMaxApplications 1
  $deep=Get-Content "$data/weekly-deep.json" -Raw|ConvertFrom-Json -AsHashtable
  $deep.Recipe.AppIds[0]|Should -Be $changed.Applications[-1].AppId
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
