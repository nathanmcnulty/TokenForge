BeforeDiscovery {$nativeAvailable=[bool]($env:TOKENFORGE_TEST_NATIVE -and (Test-Path $env:TOKENFORGE_TEST_NATIVE))}
BeforeAll {Import-Module "$PSScriptRoot/../src/TokenForge/TokenForge.psd1" -Force;$native=$env:TOKENFORGE_TEST_NATIVE}
Describe 'Frozen namespace-bound research cohorts' -Skip:(-not $nativeAvailable) {
 BeforeEach {
  $root=Join-Path ($TestDrive -replace '^/var/','/private/var/') ([guid]::NewGuid().ToString());$path=Join-Path $root scopes.sqlite;$metadata=Join-Path $root applications.sqlite
  $null=Get-TokenForgeFlowEvidence (Join-Path $root missing.json)
  $graph='00000003-0000-0000-c000-000000000000';$clients=@('11111111-1111-1111-1111-111111111111','22222222-2222-2222-2222-222222222222')
  $inventory=[pscustomobject]@{CapturedAt=[DateTimeOffset]::UtcNow.ToString('o');TenantFingerprint=('a'*64);PrincipalFingerprint=('b'*64);DiscoveryCatalogHash=('c'*64);TenantGrants=@();Applications=@($clients|ForEach-Object {[pscustomobject]@{AppId=$_;Registration='Present';Ownership='VerifiedMicrosoftOwner';AccountEnabled=$true;RedirectUris=@('https://login.microsoftonline.com/common/oauth2/nativeclient');PreferredRedirectUri='https://login.microsoftonline.com/common/oauth2/nativeclient';IdentifierUris=@();PublishedGrants=@();DelegatedScopeDefinitions=@()}})}
  $secret=ConvertTo-SecureString synthetic -AsPlainText -Force
  Mock Get-TokenForgeToken -ModuleName TokenForge {param($Request) [pscustomobject]@{AccessToken=ConvertTo-SecureString private-access -AsPlainText -Force;RefreshToken=$null;GrantedScopes=@('User.Read');TokenClaims=[pscustomobject]@{Readable=$true;HasDelegatedScopeClaim=$true;Scopes=@('User.Read');TenantFingerprint=('a'*64);PrincipalFingerprint=('b'*64);ClientId=$Request.ClientId;Audience=$Request.ResourceId}}}
  $create=@{Inventory=$inventory;DatabasePath=$path;GraphOnly=$true;Protocols=@('OAuth2V2Pkce');BatchSize=1;MaxRedirects=1;NativeExecutablePath=$native}
 }
 AfterEach {$secret.Dispose()}
 It 'prepares only selected eligible pairs and creates an immutable runner binding without issuing' {
  $arm='797f4846-ba00-4fd7-ba43-dac1f8f63013'
  $inventory.Applications[0].PublishedGrants=@(@{ResourceId=$arm;Scopes=@('user_impersonation')})
  $create.GraphOnly=$false
  $selection=@(@{ClientId=$clients[0];ResourceId=$arm},@{ClientId=$clients[1];ResourceId=$graph},@{ClientId=$clients[0];ResourceId=$arm})
  $manifest=Join-Path $root discovery-run.json
  $cohort=New-TokenForgeResearchCohort @create -Plan $selection -RunManifestPath $manifest
  $cohort.PairCount|Should -Be 2
  $cohort.Cohort.Pairs[0].ResourceId|Should -Be $arm
  (& (Get-Module TokenForge) {param($p) Get-TokenForgeDiscoveryRunId $p} $manifest)|Should -Be $cohort.PlanId
  $before=(Get-FileHash $manifest).Hash
  {New-TokenForgeResearchCohort @create -Plan $selection -RunManifestPath $manifest}|Should -Throw '*cannot be replaced*'
  (Get-FileHash $manifest).Hash|Should -BeExactly $before
  Should -Invoke Get-TokenForgeToken -ModuleName TokenForge -Times 0
  $run=@{Inventory=$inventory;EstsAuth=$secret;DatabasePath=$path;CohortId=$cohort.PlanId;MetadataPath=$metadata;NativeExecutablePath=$native;DelayMilliseconds=0}
  (Invoke-TokenForgeResearchChunk @run).PendingClients|Should -Be 1
  (Invoke-TokenForgeResearchChunk @run).Complete|Should -BeTrue
  (Invoke-TokenForgeResearchChunk @run).NewObservations|Should -Be 0
  Should -Invoke Get-TokenForgeToken -ModuleName TokenForge -Times 2
  $observed=(Get-TokenForgeScopeDatabase $path -NativeExecutablePath $native).Observations
  @($observed|Where-Object {$_.ClientId -eq $clients[0] -and $_.ResourceId -eq $graph}).Count|Should -Be 0
 }
 It 'rejects empty, malformed and unapproved pair selection before native dispatch (<Case>)' -ForEach @(
  @{Case='null'},@{Case='empty'},@{Case='malformed'},@{Case='resource'},@{Case='client'},@{Case='overflow'}
 ) {
  $selection=switch($Case){
   null {$null}
   empty {,@()}
   malformed {,@(@{ClientId='bad';ResourceId=$graph})}
   resource {,@(@{ClientId=$clients[0];ResourceId='797f4846-ba00-4fd7-ba43-dac1f8f63013'})}
   client {,@(@{ClientId='33333333-3333-3333-3333-333333333333';ResourceId=$graph})}
   overflow {,[object[]]::new(1001)}
  }
  Mock Invoke-TokenForgeNativeEvidence -ModuleName TokenForge {throw 'Unexpected native dispatch.'}
  {New-TokenForgeResearchCohort @create -Plan $selection}|Should -Throw
  Should -Invoke Invoke-TokenForgeNativeEvidence -ModuleName TokenForge -Times 0
  Test-Path $path|Should -BeFalse
 }
 It 'binds relative database and manifest paths to the PowerShell location (<AbsoluteDatabase>)' -ForEach @(@{AbsoluteDatabase=$false},@{AbsoluteDatabase=$true}) {
  $null=[IO.Directory]::CreateDirectory($root,[IO.UnixFileMode]448)
  $old=Get-Location
  try{
   Set-Location $root
   $create.DatabasePath=if($AbsoluteDatabase){$path}else{'scopes.sqlite'}
   $manifest=if($AbsoluteDatabase){'discovery-run.json'}else{Join-Path $root discovery-run.json}
   $cohort=New-TokenForgeResearchCohort @create -Plan @(@{ClientId=$clients[0];ResourceId=$graph}) -RunManifestPath $manifest
   Test-Path $path|Should -BeTrue
   (Get-Content (Join-Path $root discovery-run.json) -Raw|ConvertFrom-Json).CohortId|Should -Be $cohort.PlanId
  }finally{Set-Location $old}
 }
 It 'refuses a non-sibling manifest before native state creation after Set-Location' {
  $null=[IO.Directory]::CreateDirectory($root,[IO.UnixFileMode]448)
  $old=Get-Location
  Mock Invoke-TokenForgeNativeEvidence -ModuleName TokenForge {throw 'Unexpected native dispatch.'}
  try{
   Set-Location $root;$create.DatabasePath='scopes.sqlite'
   {New-TokenForgeResearchCohort @create -Plan @(@{ClientId=$clients[0];ResourceId=$graph}) -RunManifestPath (Join-Path $TestDrive discovery-run.json)}|Should -Throw '*beside*'
   Should -Invoke Invoke-TokenForgeNativeEvidence -ModuleName TokenForge -Times 0
   Test-Path $path|Should -BeFalse
  }finally{Set-Location $old}
 }
 It 'refuses a differently named database when preparing the fixed runner manifest' {
  $create.DatabasePath=Join-Path $root other.sqlite
  Mock Invoke-TokenForgeNativeEvidence -ModuleName TokenForge {throw 'Unexpected native dispatch.'}
  {New-TokenForgeResearchCohort @create -RunManifestPath (Join-Path $root discovery-run.json)}|Should -Throw '*beside*'
  Should -Invoke Invoke-TokenForgeNativeEvidence -ModuleName TokenForge -Times 0
  Test-Path $create.DatabasePath|Should -BeFalse
 }
 It 'freezes account-bound membership and executes deterministic chunks with an issuance-free resume' {
  $cohort=New-TokenForgeResearchCohort @create
  $cohort.ClientCount|Should -Be 2;$cohort.ChunkCount|Should -Be 2
  $other=New-TokenForgeResearchCohort @create -PrincipalFingerprint ('d'*64)
  $other.PlanId|Should -Not -Be $cohort.PlanId
  $run=@{Inventory=$inventory;EstsAuth=$secret;DatabasePath=$path;CohortId=$cohort.PlanId;MetadataPath=$metadata;NativeExecutablePath=$native;DelayMilliseconds=0}
  (Invoke-TokenForgeResearchChunk @run).PendingClients|Should -Be 1
  (Invoke-TokenForgeResearchChunk @run).Complete|Should -BeTrue
  (Invoke-TokenForgeResearchChunk @run).NewObservations|Should -Be 0
  (Invoke-TokenForgeResearchChunk @run -ChunkIndex 0).NewObservations|Should -Be 0
  Should -Invoke Get-TokenForgeToken -ModuleName TokenForge -Times 2
  (Get-TokenForgeResearchCohort $path $other.PlanId -NativeExecutablePath $native).Pending.Count|Should -Be 2
  (Get-TokenForgeScopeDatabase $path -NativeExecutablePath $native).Observations.Count|Should -Be 2
  $newRun=New-TokenForgeResearchCohort @create
  (Invoke-TokenForgeResearchChunk $inventory $secret $path $newRun.PlanId -MetadataPath $metadata -NativeExecutablePath $native -DelayMilliseconds 0).NewObservations|Should -Be 1
  Should -Invoke Get-TokenForgeToken -ModuleName TokenForge -Times 3
  (Invoke-TokenForgeResearchChunk @run -ChunkIndex 0).NewObservations|Should -Be 0
  (Get-TokenForgeScopeDatabase $path -NativeExecutablePath $native).Observations.Count|Should -Be 3
  Should -Invoke Get-TokenForgeToken -ModuleName TokenForge -Times 3
 }
 It 'leaves cohort membership pending after a metadata failure and repairs it without issuing another token' {
  $cohort=New-TokenForgeResearchCohort @create
  $bad=Join-Path $root foreign.sqlite;[IO.File]::WriteAllText($bad,'not a SQLite database');if(-not $IsWindows){[IO.File]::SetUnixFileMode($bad,[IO.UnixFileMode]384)}
  $run=@{Inventory=$inventory;EstsAuth=$secret;DatabasePath=$path;CohortId=$cohort.PlanId;NativeExecutablePath=$native;DelayMilliseconds=0;ChunkIndex=0}
  {Invoke-TokenForgeResearchChunk @run -MetadataPath $bad}|Should -Throw
  (Get-TokenForgeResearchCohort $path $cohort.PlanId -NativeExecutablePath $native).Pending.Count|Should -Be 2
  (Invoke-TokenForgeResearchChunk @run -MetadataPath $metadata).PendingClients|Should -Be 1
  Should -Invoke Get-TokenForgeToken -ModuleName TokenForge -Times 1
 }
 It 'leaves throttled work pending and skips completed members on resume' {
  $create.BatchSize=2
  $cohort=New-TokenForgeResearchCohort @create
  $script:partialCalls=0
  Mock Get-TokenForgeToken -ModuleName TokenForge {param($Request)
   $script:partialCalls++
   if($script:partialCalls -eq 2){throw 'Identity request failed (HTTP 429); details suppressed.'}
   [pscustomobject]@{AccessToken=ConvertTo-SecureString private-access -AsPlainText -Force;RefreshToken=$null;GrantedScopes=@('User.Read');TokenClaims=[pscustomobject]@{Readable=$true;HasDelegatedScopeClaim=$true;Scopes=@('User.Read');TenantFingerprint=('a'*64);PrincipalFingerprint=('b'*64);ClientId=$Request.ClientId;Audience=$Request.ResourceId}}
  }
  $run=@{Inventory=$inventory;EstsAuth=$secret;DatabasePath=$path;CohortId=$cohort.PlanId;MetadataPath=$metadata;NativeExecutablePath=$native;DelayMilliseconds=0}
  $caught=$null
  try {Invoke-TokenForgeResearchChunk @run} catch {$caught=$_}
  $caught|Should -Not -BeNullOrEmpty
  $caught.FullyQualifiedErrorId.Split(',')[0]|Should -BeExactly 'TokenForge.TransientIdentity'
  $caught.CategoryInfo.Category|Should -Be ([Management.Automation.ErrorCategory]::ResourceUnavailable)
  (Get-TokenForgeResearchCohort $path $cohort.PlanId -NativeExecutablePath $native).Pending.Count|Should -Be 1
  (Get-TokenForgeScopeDatabase $path -NativeExecutablePath $native).Observations.Count|Should -Be 1
  $flow=Get-TokenForgeFlowEvidence (Join-Path $root flows.sqlite) -NativeExecutablePath $native
  @($flow.Attempts|Where-Object Outcome -eq TransientFailure).Count|Should -Be 1
  $resumed=Invoke-TokenForgeResearchChunk @run
  $resumed.SelectedClients|Should -Be 1
  $resumed.PendingClients|Should -Be 0
  $resumed.CompletedClients|Should -Be 2
  Should -Invoke Get-TokenForgeToken -ModuleName TokenForge -Times 1 -Exactly -ParameterFilter {$Request.ClientId -eq $clients[0]}
  Should -Invoke Get-TokenForgeToken -ModuleName TokenForge -Times 2 -Exactly -ParameterFilter {$Request.ClientId -eq $clients[1]}
  $completed=Invoke-TokenForgeResearchChunk @run -ChunkIndex 0
  $completed.SelectedClients|Should -Be 2
  $completed.Complete|Should -BeTrue
  Should -Invoke Get-TokenForgeToken -ModuleName TokenForge -Times 3 -Exactly
 }
 It 'rejects changed, stale, or mismatched inventory before token issuance' {
  $cohort=New-TokenForgeResearchCohort @create
  $run=@{Inventory=$inventory;EstsAuth=$secret;DatabasePath=$path;CohortId=$cohort.PlanId;MetadataPath=$metadata;NativeExecutablePath=$native;DelayMilliseconds=0}
  $inventory.Applications[0].AccountEnabled=$false
  {Invoke-TokenForgeResearchChunk @run}|Should -Throw '*differs*'
  $inventory.Applications[0].AccountEnabled=$true;$inventory.CapturedAt=[DateTimeOffset]::UtcNow.AddDays(-2).ToString('o')
  {Invoke-TokenForgeResearchChunk @run}|Should -Throw '*fresh*'
  Should -Invoke Get-TokenForgeToken -ModuleName TokenForge -Times 0
 }
 It 'keeps mismatched issuance pending and stops the cohort' {
  $cohort=New-TokenForgeResearchCohort @create -PrincipalFingerprint ('d'*64)
  {Invoke-TokenForgeResearchChunk $inventory $secret $path $cohort.PlanId -MetadataPath $metadata -NativeExecutablePath $native -DelayMilliseconds 0}|Should -Throw '*mismatch*'
  (Get-TokenForgeResearchCohort $path $cohort.PlanId -NativeExecutablePath $native).Pending.Count|Should -Be 2
  Should -Invoke Get-TokenForgeToken -ModuleName TokenForge -Times 1
 }
 It 'suppresses cohort writes and issuance under WhatIf' {
  $null=New-TokenForgeResearchCohort @create -WhatIf
  Test-Path $path|Should -BeFalse
  $null=Invoke-TokenForgeResearchChunk $inventory $secret $path ('e'*64) -NativeExecutablePath $native -WhatIf
  Test-Path $path|Should -BeFalse
  Should -Invoke Get-TokenForgeToken -ModuleName TokenForge -Times 0
 }
 It 'runs cohort creation and status and reads SQLite evidence through default CLI report and export' {
  $observed=New-TokenForgeResearchCohort @create
  $null=Invoke-TokenForgeResearchChunk $inventory $secret $path $observed.PlanId -MetadataPath $metadata -NativeExecutablePath $native -DelayMilliseconds 0
  $inventory|ConvertTo-Json -Depth 24|Set-Content (Join-Path $root inventory.json)
  if(-not $IsWindows){[IO.File]::SetUnixFileMode((Join-Path $root inventory.json),[IO.UnixFileMode]384)}
  $cohort=& "$PSScriptRoot/../scripts/Invoke-TokenForgeInventory.ps1" -Action NewCohort -StatePath $root -DatabasePath $path -GraphOnly -BatchSize 1 -NativeExecutablePath $native
  $status=& "$PSScriptRoot/../scripts/Invoke-TokenForgeInventory.ps1" -Action CohortStatus -StatePath $root -CohortId $cohort.PlanId -NativeExecutablePath $native
  $status.Pending.Count|Should -Be 2
  $report=& "$PSScriptRoot/../scripts/Invoke-TokenForgeInventory.ps1" -Action Report -StatePath $root -PrincipalFingerprint ('b'*64) -NativeExecutablePath $native
  $report.TerminalSlots|Should -Be 1
  $report.ApplicationsWithObservedSuccess|Should -Be 1
  $export=Join-Path $root anonymous-flows.json
  $null=& "$PSScriptRoot/../scripts/Invoke-TokenForgeInventory.ps1" -Action ExportFlows -StatePath $root -ExportPath $export -NativeExecutablePath $native
  @((Get-Content $export -Raw|ConvertFrom-Json).Observations).Count|Should -Be 1
 }
}
