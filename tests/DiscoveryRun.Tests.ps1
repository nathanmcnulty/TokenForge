BeforeDiscovery {$nativeAvailable=[bool]($env:TOKENFORGE_TEST_NATIVE -and (Test-Path $env:TOKENFORGE_TEST_NATIVE))}
BeforeAll {
 Import-Module "$PSScriptRoot/../src/TokenForge/TokenForge.psd1" -Force
}
Describe 'Bounded local discovery orchestration' {
 BeforeEach {
  $state=Join-Path $TestDrive ([guid]::NewGuid().ToString())
  $counter=Join-Path $TestDrive ([guid]::NewGuid().ToString()+'.txt')
  Set-Content $counter 3
  $inventory=[pscustomobject]@{TenantFingerprint=('a'*64);PrincipalFingerprint=('b'*64);DiscoveryCatalogHash=('d'*64);Applications=@()}
  $cookie=ConvertTo-SecureString synthetic -AsPlainText -Force
  $options=@{Inventory=$inventory;EstsAuth=$cookie;StatePath=$state;NativeExecutablePath='/synthetic/tokenforge'}
  $recipe=@{TenantFingerprint=$inventory.TenantFingerprint;PrincipalFingerprint=$inventory.PrincipalFingerprint;CatalogHash=$inventory.DiscoveryCatalogHash;InventoryHash=(& (Get-Module TokenForge) {Get-TokenForgeFingerprint '[]'})}
  Mock New-TokenForgeResearchCohort -ModuleName TokenForge {
   [pscustomobject]@{PlanId=('c'*64);Cohort=$recipe;ClientCount=3;CompletedClients=0;Pending=@(1,2,3)}
  }
  Mock Get-TokenForgeResearchCohort -ModuleName TokenForge {
   $n=[int](Get-Content $counter)
   [pscustomobject]@{PlanId=('c'*64);Cohort=$recipe;ClientCount=3;CompletedClients=(3-$n);Pending=@(1..$n|Where-Object {$n -gt 0})}
  }
  Mock Invoke-TokenForgeResearchChunk -ModuleName TokenForge {
   $n=[int](Get-Content $counter);Set-Content $counter ($n-1)
  }
 }
 AfterEach {$cookie.Dispose()}
 It 'runs all pending chunks and uses SQLite for every working ledger' {
  $r=Invoke-TokenForgeDiscoveryRun @options
  $r.Status|Should -Be Complete
  $r.CompletedClients|Should -Be 3
  $r.ChunksExecuted|Should -Be 3
  $r.CredentialOutput|Should -BeFalse
  Should -Invoke Invoke-TokenForgeResearchChunk -ModuleName TokenForge -Times 3 -Exactly -ParameterFilter {$DatabasePath.EndsWith('scopes.sqlite') -and $FlowDatabasePath.EndsWith('flows.sqlite') -and $MetadataPath.EndsWith('applications.sqlite')}
 }
 It 'stops at a chunk budget and resumes the saved cohort without creating another' {
  $r=Invoke-TokenForgeDiscoveryRun @options -MaxChunks 1
  $r.Status|Should -Be BudgetReached
  $r.PendingClients|Should -Be 2
  $r=Invoke-TokenForgeDiscoveryRun @options
  $r.Status|Should -Be Complete
  Should -Invoke New-TokenForgeResearchCohort -ModuleName TokenForge -Times 1 -Exactly
 }
 It 'does not request tokens when a saved run is complete' {
  $null=Invoke-TokenForgeDiscoveryRun @options
  Mock Invoke-TokenForgeResearchChunk -ModuleName TokenForge {throw 'Unexpected token work.'}
  $r=Invoke-TokenForgeDiscoveryRun @options
  $r.ChunksExecuted|Should -Be 0
 }
 It 'rejects changed identity even when the saved cohort is complete' {
  $null=Invoke-TokenForgeDiscoveryRun @options
  $inventory.PrincipalFingerprint='e'*64
  {Invoke-TokenForgeDiscoveryRun @options}|Should -Throw '*frozen cohort*'
 }
 It 'rejects changed inventory even when no requests remain' {
  $null=Invoke-TokenForgeDiscoveryRun @options
  $inventory.Applications=@(@{AppId='changed'})
  {Invoke-TokenForgeDiscoveryRun @options}|Should -Throw '*frozen cohort*'
 }
 It 'stops instead of looping when no checkpoints advance' {
  Mock Invoke-TokenForgeResearchChunk -ModuleName TokenForge {}
  {Invoke-TokenForgeDiscoveryRun @options}|Should -Throw '*no checkpoint progress*'
  Test-Path (Join-Path $state 'discovery-run.json')|Should -BeTrue
 }
 It 'releases the workspace lock on failure' {
  Mock Invoke-TokenForgeResearchChunk -ModuleName TokenForge {throw 'synthetic failure'}
  {Invoke-TokenForgeDiscoveryRun @options}|Should -Throw
  Mock Invoke-TokenForgeResearchChunk -ModuleName TokenForge {Set-Content $counter 0}
  (Invoke-TokenForgeDiscoveryRun @options).Status|Should -Be Complete
 }
 It 'rejects a changed manifest before requesting tokens' {
  $null=Invoke-TokenForgeDiscoveryRun @options -MaxChunks 1
  Set-Content (Join-Path $state 'discovery-run.json') '{"SchemaVersion":1,"CohortId":"invalid","AccessToken":"synthetic"}'
  {Invoke-TokenForgeDiscoveryRun @options}|Should -Throw '*manifest*'
  Should -Invoke Invoke-TokenForgeResearchChunk -ModuleName TokenForge -Times 1 -Exactly
 }
 It 'honors WhatIf without writing or requesting tokens' {
  $null=Invoke-TokenForgeDiscoveryRun @options -WhatIf
  Test-Path $state|Should -BeFalse
  Should -Invoke New-TokenForgeResearchCohort -ModuleName TokenForge -Times 0 -Exactly
 }
}

Describe 'Standalone run against native SQLite checkpoints' -Skip:(-not $nativeAvailable) {
 It 'stops after a real chunk, resumes, and performs no issuance on a completed run' {
  $native=$env:TOKENFORGE_TEST_NATIVE
  $root=Join-Path $TestDrive ([guid]::NewGuid().ToString())
  $clients=@('11111111-1111-1111-1111-111111111111','22222222-2222-2222-2222-222222222222')
  $inventory=[pscustomobject]@{CapturedAt=[DateTimeOffset]::UtcNow.ToString('o');TenantFingerprint=('a'*64);PrincipalFingerprint=('b'*64);DiscoveryCatalogHash=('c'*64);TenantGrants=@();Applications=@($clients|ForEach-Object {[pscustomobject]@{AppId=$_;Registration='Present';Ownership='VerifiedMicrosoftOwner';AccountEnabled=$true;RedirectUris=@('https://login.microsoftonline.com/common/oauth2/nativeclient');PreferredRedirectUri='https://login.microsoftonline.com/common/oauth2/nativeclient';IdentifierUris=@();PublishedGrants=@();DelegatedScopeDefinitions=@()}})}
  Mock Get-TokenForgeToken -ModuleName TokenForge {param($Request) [pscustomobject]@{AccessToken=ConvertTo-SecureString synthetic -AsPlainText -Force;RefreshToken=$null;GrantedScopes=@('User.Read');TokenClaims=[pscustomobject]@{Readable=$true;HasDelegatedScopeClaim=$true;Scopes=@('User.Read');TenantFingerprint=('a'*64);PrincipalFingerprint=('b'*64);ClientId=$Request.ClientId;Audience=$Request.ResourceId}}}
  $secret=ConvertTo-SecureString synthetic -AsPlainText -Force
  try{
   $options=@{Inventory=$inventory;EstsAuth=$secret;StatePath=$root;NativeExecutablePath=$native;GraphOnly=$true;BatchSize=1;MaxRedirects=1}
   $first=Invoke-TokenForgeDiscoveryRun @options -MaxChunks 1
   $first.Status|Should -Be BudgetReached
   $first.CompletedClients|Should -Be 1
   $second=Invoke-TokenForgeDiscoveryRun @options
   $second.Status|Should -Be Complete
   $second.CompletedClients|Should -Be 2
   Mock Get-TokenForgeToken -ModuleName TokenForge {throw 'Unexpected completed-run issuance.'}
   (Invoke-TokenForgeDiscoveryRun @options).ChunksExecuted|Should -Be 0
   foreach($name in @('applications.sqlite','scopes.sqlite','flows.sqlite')){Test-Path (Join-Path $root $name)|Should -BeTrue}
  }finally{$secret.Dispose()}
 }
}
