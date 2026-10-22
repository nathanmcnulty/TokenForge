BeforeAll {
 . "$PSScriptRoot/../scripts/TokenForgeCiEvidenceQueue.ps1"
 Import-Module "$PSScriptRoot/../src/TokenForge/TokenForge.psd1" -Force
 $catalog=Get-TokenForgeCatalog -Path "$PSScriptRoot/fixtures/catalog.json"
 $catalog.Source='https://raw.githubusercontent.com/example/public/main/scopes.json'
 $discovery=Get-TokenForgeDiscovery -Catalog $catalog|ConvertTo-Json -Depth 100|ConvertFrom-Json -AsHashtable
 $now=[DateTimeOffset]'2026-10-16T12:00:00Z'
 $resources=@('00000003-0000-0000-c000-000000000000','797f4846-ba00-4fd7-ba43-dac1f8f63013')
 function New-QueueState([DateTimeOffset]$ObservedAt) {
  $s=New-TfCiState $discovery -Mode Deep -ResourceId $resources -ChunkSize 1 -Now $now.AddDays(-14)
  foreach($b in $s.Batches){$b.Status='Complete';$b.Attempts=1;$b.Assessed=1;$b.AssessedPairs=2;$b.ObservedAt=$ObservedAt.ToString('o')}
  $s
 }
}
Describe 'Incremental completed-assessment evidence queue' {
 It 'selects bounded missing evidence deterministically and records explicit policy' {
  $q=Get-TfCiEvidenceQueue $discovery -Now $now -MaxApplications 1
  $q.Items.Count|Should -Be 1
  $q.Items[0].Reason|Should -Be MissingEvidence
  $q.Items[0].EvidenceType|Should -Be CompletedDeepAssessment
  $q.Items[0].ObservedAt|Should -BeNullOrEmpty
  $q.Items[0].ResourceIds.Count|Should -Be 2
  $q.EvaluatedAt|Should -Be $now.ToString('o')
  $q.DeferredCount|Should -Be ($q.PendingCount-1)
  $shuffled=[TokenForge.Core.DiscoverySourceClaims]::ReadMetadataJson(($discovery|ConvertTo-Json -Depth 100))
  [array]::Reverse($shuffled.Applications)
  (Get-TfCiEvidenceQueue $shuffled -Now $now -MaxApplications 1).Items[0].AppId|Should -Be $q.Items[0].AppId
 }
 It 'excludes fresh complete two-resource assessments regardless of token success' {
  $s=New-QueueState $now.AddHours(-12)
  $q=Get-TfCiEvidenceQueue $discovery $s -Now $now
  $q.PendingCount|Should -Be 0
  $q.Items.Count|Should -Be 0
  $q.FreshCount|Should -Be $q.CandidateCount
 }
 It 'treats exact expiry as stale and records observation and expiry' {
  $s=New-QueueState $now.AddDays(-1)
  $q=Get-TfCiEvidenceQueue $discovery $s -Now $now
  $q.Items[0].Reason|Should -Be StaleEvidence
  $q.Items[0].ObservedAt|Should -Be $now.AddDays(-1).ToString('o')
  $q.Items[0].FreshUntil|Should -Be $now.ToString('o')
 }
 It 'does not treat missing resource, failed, pending, or shallow evidence as fresh' {
  $s=New-QueueState $now.AddHours(-12)
  $callbacks=@($discovery.Applications|Where-Object {$_.RedirectUris.Count})
  foreach($b in $s.Batches){if(@(Get-TfCiMembers $s $b.Index)[0] -in $callbacks.AppId){$b.Status='Failed'}}
  $q=Get-TfCiEvidenceQueue $discovery $s -Now $now
  @($q.Items|Where-Object Reason -eq MissingEvidence).Count|Should -Be 2
  foreach($mode in @('Deep','Shallow')){
   $legacy=New-TfCiState $discovery -Mode $mode -Now $now.AddHours(-12)
   $legacy.Batches[0].Status='Complete';$legacy.Batches[0].Attempts=1;$legacy.Batches[0].Assessed=$legacy.Recipe.AppIds.Count;$legacy.Batches[0].ObservedAt=$now.ToString('o')
   $q=Get-TfCiEvidenceQueue $discovery $legacy -Now $now
   $q.FreshCount|Should -Be 0
   $q.PendingCount|Should -Be $q.CandidateCount
  }
 }
 It 'prioritizes changed hints then missing evidence then stale evidence' {
  $s=New-QueueState $now.AddDays(-1)
  $first=@($discovery.Applications|Where-Object {$_.RedirectUris.Count})[0].AppId
  foreach($b in $s.Batches){if(@(Get-TfCiMembers $s $b.Index)[0] -eq $first){$b.Status='Failed'}}
  $changed=[TokenForge.Core.DiscoverySourceClaims]::ReadMetadataJson(($discovery|ConvertTo-Json -Depth 100))
  $changed.Applications[-1].RedirectUris+=@('https://login.microsoftonline.com/organizations/oauth2/nativeclient')
  $q=Get-TfCiEvidenceQueue $changed $s -Now $now
  $q.Items[0].Reason|Should -Be ChangedPublicHints
  $q.Items[1].Reason|Should -Be MissingEvidence
 }
 It 'rejects future, malformed, pre-recipe and unattempted completed observations' {
  foreach($time in @($now.AddSeconds(1).ToString('o'),'not-a-timestamp',$now.AddDays(-15).ToString('o'))){
   $s=New-QueueState $now.AddHours(-12);$s.Batches[0].ObservedAt=$time
   {Get-TfCiEvidenceQueue $discovery $s -Now $now}|Should -Throw
  }
  $s=New-QueueState $now.AddHours(-12);$s.Batches[0].Attempts=0
  {Get-TfCiEvidenceQueue $discovery $s -Now $now}|Should -Throw
 }
 It 'never mutates a resumed frozen plan when evidence ages or discovery changes' {
  $s=New-QueueState $now.AddHours(-12)
  $before=ConvertTo-Json -InputObject $s -Depth 100 -Compress
  $changed=[TokenForge.Core.DiscoverySourceClaims]::ReadMetadataJson(($discovery|ConvertTo-Json -Depth 100));$changed.Applications[-1].RedirectUris+=@('https://login.microsoftonline.com/organizations/oauth2/nativeclient')
  $null=Get-TfCiEvidenceQueue $changed $s -Now $now.AddDays(30)
  (ConvertTo-Json -InputObject $s -Depth 100 -Compress)|Should -BeExactly $before
  Assert-TfCiState $s
 }
}
Describe 'Frozen queue integration' {
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
 It 'keeps policy, budget, reasons and exact plan on resume despite changed hints' {
  $null=& $runner -Action Prepare -DataPath $data -BundlePath $bundle -Mode Deep -DeepMaxApplications 1
  $stateBefore=Get-Content "$data/weekly-deep.json" -Raw
  $snapshotBefore=Get-Content (Get-TfCiEvidenceSelectionPath $data ([TokenForge.Core.DiscoverySourceClaims]::ReadMetadataJson([IO.File]::ReadAllText("$data/weekly-deep.json"))).EvidenceSelectionSha256) -Raw
  $changed=[TokenForge.Core.DiscoverySourceClaims]::ReadMetadataJson(($discovery|ConvertTo-Json -Depth 100));$changed.Applications[-1].RedirectUris+=@('https://login.microsoftonline.com/organizations/oauth2/nativeclient')
  Mock Update-TokenForgeDiscovery {$changed}
  $null=& $runner -Action Prepare -DataPath $data -BundlePath $bundle -Mode Deep -DeepMaxApplications 99
  (Get-Content "$data/weekly-deep.json" -Raw)|Should -BeExactly $stateBefore
  (Get-Content (Get-TfCiEvidenceSelectionPath $data ([TokenForge.Core.DiscoverySourceClaims]::ReadMetadataJson([IO.File]::ReadAllText("$data/weekly-deep.json"))).EvidenceSelectionSha256) -Raw)|Should -BeExactly $snapshotBefore
  (Get-Content "$bundle/selection-deep.json" -Raw)|Should -BeExactly $snapshotBefore
  @(Get-TfCiPublicStagePaths $data)|Should -Contain ([IO.Path]::GetFileName((Get-TfCiEvidenceSelectionPath $data ([TokenForge.Core.DiscoverySourceClaims]::ReadMetadataJson([IO.File]::ReadAllText("$data/weekly-deep.json"))).EvidenceSelectionSha256)))
 }
 It 'fails closed for missing or tampered snapshots on resume and public validation' {
  $null=& $runner -Action Prepare -DataPath $data -BundlePath $bundle -Mode Deep -DeepMaxApplications 1
  $snapshot=Get-Content (Get-TfCiEvidenceSelectionPath $data ([TokenForge.Core.DiscoverySourceClaims]::ReadMetadataJson([IO.File]::ReadAllText("$data/weekly-deep.json"))).EvidenceSelectionSha256) -Raw
  Remove-Item (Get-TfCiEvidenceSelectionPath $data ([TokenForge.Core.DiscoverySourceClaims]::ReadMetadataJson([IO.File]::ReadAllText("$data/weekly-deep.json"))).EvidenceSelectionSha256)
  {& $runner -Action Prepare -DataPath $data -BundlePath $bundle -Mode Deep}|Should -Throw '*Missing frozen*'
  $snapshot.Replace('MissingEvidence','StaleEvidence')|Set-Content (Get-TfCiEvidenceSelectionPath $data ([TokenForge.Core.DiscoverySourceClaims]::ReadMetadataJson([IO.File]::ReadAllText("$data/weekly-deep.json"))).EvidenceSelectionSha256)
  {Assert-TfCiPublicData $data}|Should -Throw '*binding*'
 }
 It 'rejects canonical membership and order mismatch even if a snapshot digest is recomputed' {
  $null=& $runner -Action Prepare -DataPath $data -BundlePath $bundle -Mode Deep
  $s=[TokenForge.Core.DiscoverySourceClaims]::ReadMetadataJson((Get-Content "$data/weekly-deep.json" -Raw))
  $snapshot=[TokenForge.Core.DiscoverySourceClaims]::ReadMetadataJson((Get-Content (Get-TfCiEvidenceSelectionPath $data ([TokenForge.Core.DiscoverySourceClaims]::ReadMetadataJson([IO.File]::ReadAllText("$data/weekly-deep.json"))).EvidenceSelectionSha256) -Raw))
  [array]::Reverse($snapshot.SelectedAppIds);$s.EvidenceSelectionSha256=Get-TfCiHash $snapshot
  {Assert-TfCiEvidenceSelection $s $snapshot}|Should -Throw '*binding*'
 }
 It 'produces no work for fresh previous-week assessments and removes stale bundle requests' {
  $s=New-TfCiState $discovery -Mode Deep -ResourceId $resources -Now ([DateTimeOffset]::UtcNow.AddDays(-14))
  foreach($b in $s.Batches){$b.Status='Complete';$b.Attempts=1;$b.Assessed=$s.Recipe.AppIds.Count;$b.AssessedPairs=$s.Recipe.AppIds.Count*2;$b.ObservedAt=[DateTimeOffset]::UtcNow.AddHours(-12).ToString('o')}
  $s|ConvertTo-Json -Depth 100|Set-Content "$data/weekly-deep.json"
  $before=Get-Content "$data/weekly-deep.json" -Raw
  $null=New-Item -ItemType Directory $bundle;Set-Content "$bundle/request.json" '{}'
  $savedOutput=$env:GITHUB_OUTPUT
  try{
   $env:GITHUB_OUTPUT=Join-Path $TestDrive github-output.txt
   $q=& $runner -Action Prepare -DataPath $data -BundlePath $bundle -Mode Deep
   $outputs=Get-Content $env:GITHUB_OUTPUT
   $outputs|Should -Contain 'has_plan=False'
   $outputs|Should -Contain 'has_work=False'
   $outputs|Should -Contain 'matrix={"include":[]}'
  }finally{$env:GITHUB_OUTPUT=$savedOutput}
  $q.PendingCount|Should -Be 0
  Test-Path "$bundle/request.json"|Should -BeFalse
  (Get-Content "$data/weekly-deep.json" -Raw)|Should -BeExactly $before
 }
 It 'emits a usable-plan flag for normal and legacy completed resume paths' {
  $savedOutput=$env:GITHUB_OUTPUT
  try{
   $env:GITHUB_OUTPUT=Join-Path $TestDrive plan-output.txt
   $null=& $runner -Action Prepare -DataPath $data -BundlePath $bundle -Mode Deep
   @(Get-Content $env:GITHUB_OUTPUT)|Should -Contain 'has_plan=True'
   Test-Path "$bundle/state.json"|Should -BeTrue
   Test-Path "$bundle/request.json"|Should -BeTrue
   $legacy=New-TfCiState $discovery -Mode Shallow
   foreach($b in $legacy.Batches){$b.Status='Complete';$b.Attempts=1;$b.Assessed=$legacy.Recipe.AppIds.Count;$b.ObservedAt=[DateTimeOffset]::UtcNow.ToString('o')}
   $legacy|ConvertTo-Json -Depth 100|Set-Content "$data/weekly-shallow.json"
   Clear-Content $env:GITHUB_OUTPUT
   $null=& $runner -Action Prepare -DataPath $data -BundlePath $bundle -Mode Shallow
   @(Get-Content $env:GITHUB_OUTPUT)|Should -Contain 'has_plan=True'
   @(Get-Content $env:GITHUB_OUTPUT)|Should -Contain 'has_work=False'
   Test-Path "$bundle/state.json"|Should -BeTrue
   Test-Path "$bundle/request.json"|Should -BeTrue
  }finally{$env:GITHUB_OUTPUT=$savedOutput}
 }
 It 'rejects orphan snapshots and stops workers before authentication if a snapshot is missing' {
  Set-Content "$data/selection-deep.json" '{"private":"not allowed"}'
  {Assert-TfCiPublicData $data}|Should -Throw '*Unbound*'
  Remove-Item "$data/selection-deep.json"
  $null=& $runner -Action Prepare -DataPath $data -BundlePath $bundle -Mode Deep
  Remove-Item "$bundle/selection-deep.json"
  {& "$PSScriptRoot/../scripts/Invoke-TokenForgeCiDiscovery.ps1" -DataPath $data -WeeklyStatePath "$bundle/state.json" -ChunkIndex 0 -PublicOnly}|Should -Throw '*Missing frozen evidence*'
 }
 It 'keeps native report compatibility while rejecting invalid selection markers' {
  $null=& $runner -Action Prepare -DataPath $data -BundlePath $bundle -Mode Deep
  $s=[TokenForge.Core.DiscoverySourceClaims]::ReadMetadataJson((Get-Content "$data/weekly-deep.json" -Raw))
  { [TokenForge.Core.WeeklyResearchReport]::Create(($s|ConvertTo-Json -Depth 100),'Deep',[DateTimeOffset]::UtcNow) }|Should -Not -Throw
  $s.EvidenceSelectionSha256='invalid'
  { [TokenForge.Core.WeeklyResearchReport]::Create(($s|ConvertTo-Json -Depth 100),'Deep',[DateTimeOffset]::UtcNow) }|Should -Throw
 }
}
Describe 'Goal 4 immutable public generation crash boundaries' {
 BeforeEach {
  $dir=Join-Path $TestDrive ([guid]::NewGuid().ToString('N'));$null=New-Item -ItemType Directory $dir
  $q=Get-TfCiEvidenceQueue $discovery -Now $now
  $s=New-TfCiState $discovery -Mode Deep -ResourceId $resources -AppId @($q.Items.AppId) -Now $now
  $snap=[TokenForge.Core.DiscoverySourceClaims]::ReadMetadataJson((@{SchemaVersion=1;PlanId=$s.PlanId;SelectedAppIds=$s.Recipe.AppIds;Queue=$q}|ConvertTo-Json -Depth 100))
  $s.EvidenceSelectionSha256=Get-TfCiHash $snap;$statePath=Join-Path $dir weekly-deep.json
  Save-TfCiEvidenceState $s $statePath $snap
 }
 It 'retains old state after a new generation is durable but before state replacement' {
  $newDiscovery=[TokenForge.Core.DiscoverySourceClaims]::ReadMetadataJson(($discovery|ConvertTo-Json -Depth 100));$newDiscovery.Applications[-1].Name+=' new exact recipe'
  $next=New-TfCiState $newDiscovery -Mode Deep -ResourceId $resources -AppId $s.Recipe.AppIds -Now $now.AddSeconds(1)
  $nextSnap=[TokenForge.Core.DiscoverySourceClaims]::ReadMetadataJson(($snap|ConvertTo-Json -Depth 100));$nextSnap.PlanId=$next.PlanId;$next.EvidenceSelectionSha256=Get-TfCiHash $nextSnap
  {Save-TfCiEvidenceState $next $statePath $nextSnap -Boundary {param($boundary)if($boundary -eq 'SelectionDurable'){throw 'synthetic interruption'}}}|Should -Throw '*interruption*'
  $old=[TokenForge.Core.DiscoverySourceClaims]::ReadMetadataJson([IO.File]::ReadAllText($statePath));$old.PlanId|Should -Be $s.PlanId
  (Read-TfCiEvidenceSelection $old $dir).PlanId|Should -Be $s.PlanId
  Test-Path (Get-TfCiEvidenceSelectionPath $dir $next.EvidenceSelectionSha256)|Should -BeTrue
  Save-TfCiEvidenceState $next $statePath $nextSnap
  (Read-TfCiEvidenceSelection $next $dir).PlanId|Should -Be $next.PlanId
 }
 It 'promotes a legacy alias before interruption or selection-marker removal' {
  Move-Item (Get-TfCiEvidenceSelectionPath $dir $s.EvidenceSelectionSha256) (Join-Path $dir selection-deep.json)
  $plain=New-TfCiState $discovery -Mode Deep -ResourceId $resources -AppId $s.Recipe.AppIds -Now $now.AddSeconds(1)
  {Save-TfCiEvidenceState $plain $statePath $null -Boundary {throw 'synthetic interruption'}}|Should -Throw
  (Read-TfCiEvidenceSelection $s $dir).PlanId|Should -Be $s.PlanId
  Save-TfCiEvidenceState $plain $statePath $null
  ([TokenForge.Core.DiscoverySourceClaims]::ReadMetadataJson([IO.File]::ReadAllText($statePath))).Contains('EvidenceSelectionSha256')|Should -BeFalse
  Test-Path (Get-TfCiEvidenceSelectionPath $dir $s.EvidenceSelectionSha256)|Should -BeTrue
 }
 It 'rejects a poisoned alias even when a valid immutable generation exists' {
  [IO.File]::WriteAllText((Join-Path $dir selection-deep.json),'{"credential":"synthetic-disallowed"}')
  {Read-TfCiEvidenceSelection $s $dir}|Should -Throw
 }
 It 'rejects a sidecar bound to the wrong actual recipe resources' {
  $wrong=New-TfCiState $discovery -Mode Deep -ResourceId @($resources[0]) -AppId $s.Recipe.AppIds -Now $now
  $changed=[TokenForge.Core.DiscoverySourceClaims]::ReadMetadataJson(($snap|ConvertTo-Json -Depth 100));$changed.PlanId=$wrong.PlanId;$wrong.EvidenceSelectionSha256=Get-TfCiHash $changed
  {Assert-TfCiEvidenceSelection $wrong $changed}|Should -Throw '*resource mismatch*'
 }
 It 'preserves the compatibility key across display name edits and exact legacy hash changes' {
  $changed=[TokenForge.Core.DiscoverySourceClaims]::ReadMetadataJson(($discovery|ConvertTo-Json -Depth 100));$changed.Applications[-1].Name+=' renamed'
  (Get-TfCiHash $changed.Applications[-1])|Should -Not -Be (Get-TfCiHash $discovery.Applications[-1])
  (Get-TfCiPublicCompatibilityKey $changed.Applications[-1])|Should -Be (Get-TfCiPublicCompatibilityKey $discovery.Applications[-1])
 }
}
