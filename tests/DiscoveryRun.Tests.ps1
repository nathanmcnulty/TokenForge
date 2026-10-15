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
  $options=@{Inventory=$inventory;EstsAuth=$cookie;StatePath=$state;NativeExecutablePath='/synthetic/tokenforge';RetryDelaySeconds=1}
  $recipe=@{TenantFingerprint=$inventory.TenantFingerprint;PrincipalFingerprint=$inventory.PrincipalFingerprint;CatalogHash=$inventory.DiscoveryCatalogHash;InventoryHash=(& (Get-Module TokenForge) {Get-TokenForgeFingerprint '[]'})}
  Mock Start-Sleep -ModuleName TokenForge {}
  Mock New-TokenForgeResearchCohort -ModuleName TokenForge {
   [pscustomobject]@{PlanId=('c'*64);Cohort=$recipe;ClientCount=3;CompletedClients=0;Pending=@(1,2,3)}
  }
  Mock Get-TokenForgeResearchCohort -ModuleName TokenForge {
   $n=[int](Get-Content $counter)
   [pscustomobject]@{PlanId=('c'*64);Cohort=$recipe;ClientCount=3;CompletedClients=(3-$n);Pending=@(1..$n|Where-Object {$n -gt 0})}
  }
  Mock Invoke-TokenForgeResearchChunk -ModuleName TokenForge {
   $n=[int](Get-Content $counter);Set-Content $counter ($n-1)
   [pscustomobject]@{PlanId=('c'*64);PendingClients=($n-1)}
  }
 }
 AfterEach {$cookie.Dispose()}
 It 'runs all pending chunks and uses SQLite for every working ledger' {
  $r=Invoke-TokenForgeDiscoveryRun @options
  $r.Status|Should -Be Complete
  $r.CompletedClients|Should -Be 3
  $r.ChunksExecuted|Should -Be 3
  $r.CredentialOutput|Should -BeFalse
  Should -Invoke Get-TokenForgeResearchCohort -ModuleName TokenForge -Times 0 -Exactly
  Should -Invoke Invoke-TokenForgeResearchChunk -ModuleName TokenForge -Times 3 -Exactly -ParameterFilter {$DatabasePath.EndsWith('scopes.sqlite') -and $FlowDatabasePath.EndsWith('flows.sqlite') -and $MetadataPath.EndsWith('applications.sqlite')}
 }
 It 'stops at a chunk budget and resumes the saved cohort without creating another' {
  $r=Invoke-TokenForgeDiscoveryRun @options -MaxChunks 1
  $r.Status|Should -Be BudgetReached
  $r.PendingClients|Should -Be 2
  $r=Invoke-TokenForgeDiscoveryRun @options
  $r.Status|Should -Be Complete
  Should -Invoke Get-TokenForgeResearchCohort -ModuleName TokenForge -Times 1 -Exactly
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
 It 'resumes the same frozen inventory after a literal JSON dictionary round trip' {
  $inventory.Applications=@(
   [pscustomobject]@{AppId='33333333-3333-3333-3333-333333333333';Name='three'},
   [pscustomobject]@{AppId='11111111-1111-1111-1111-111111111111';Name='2026-01-01T00:00:00Z'},
   [pscustomobject]@{AppId='22222222-2222-2222-2222-222222222222';Name='two'}
  )
  $recipe.InventoryHash=& (Get-Module TokenForge) {param($i) Get-TokenForgeFingerprint (ConvertTo-Json -InputObject @($i.Applications|Sort-Object AppId) -Depth 32 -Compress)} $inventory
  $null=Invoke-TokenForgeDiscoveryRun @options -MaxChunks 1
  $options.Inventory=[TokenForge.Core.DiscoverySourceClaims]::ReadMetadataJson((ConvertTo-Json -InputObject $inventory -Depth 100))
  (Invoke-TokenForgeDiscoveryRun @options).Status|Should -Be Complete
  Should -Invoke New-TokenForgeResearchCohort -ModuleName TokenForge -Times 1 -Exactly
 }
 It 'stops instead of looping when no checkpoints advance' {
  Mock Invoke-TokenForgeResearchChunk -ModuleName TokenForge {[pscustomobject]@{PlanId=('c'*64);PendingClients=3}}
  {Invoke-TokenForgeDiscoveryRun @options}|Should -Throw '*no checkpoint progress*'
  Test-Path (Join-Path $state 'discovery-run.json')|Should -BeTrue
 }
 It 'rejects an invalid chunk summary (<Case>) and retains the run manifest' -ForEach @(
  @{Case='missing result';Summary=$null},
  @{Case='missing cohort';Summary=@{PendingClients=0}},
  @{Case='wrong cohort';Summary=@{PlanId=('e'*64);PendingClients=0}},
  @{Case='missing pending count';Summary=@{PlanId=('c'*64)}},
  @{Case='string count';Summary=@{PlanId=('c'*64);PendingClients='0'}},
  @{Case='fractional count';Summary=@{PlanId=('c'*64);PendingClients=0.5}},
  @{Case='negative count';Summary=@{PlanId=('c'*64);PendingClients=-1}},
  @{Case='count above membership';Summary=@{PlanId=('c'*64);PendingClients=4}}
 ) {
  Mock Invoke-TokenForgeResearchChunk -ModuleName TokenForge {if($null -ne $Summary){[pscustomobject]$Summary}}
  {Invoke-TokenForgeDiscoveryRun @options}|Should -Throw '*chunk summary*'
  Test-Path (Join-Path $state 'discovery-run.json')|Should -BeTrue
  Should -Invoke Get-TokenForgeResearchCohort -ModuleName TokenForge -Times 0 -Exactly
 }
 It 'releases the workspace lock on failure' {
  Mock Invoke-TokenForgeResearchChunk -ModuleName TokenForge {throw 'synthetic failure'}
  {Invoke-TokenForgeDiscoveryRun @options}|Should -Throw
  Mock Invoke-TokenForgeResearchChunk -ModuleName TokenForge {Set-Content $counter 0;[pscustomobject]@{PlanId=('c'*64);PendingClients=0}}
  (Invoke-TokenForgeDiscoveryRun @options).Status|Should -Be Complete
 }
 It 'retries only typed temporary failures and counts partial checkpoint progress' {
  Mock Invoke-TokenForgeResearchChunk -ModuleName TokenForge {
   $n=[int](Get-Content $counter);Set-Content $counter ($n-1)
   if($n -eq 3){throw [Management.Automation.ErrorRecord]::new([InvalidOperationException]::new('synthetic temporary failure'),'TokenForge.TransientIdentity',[Management.Automation.ErrorCategory]::ResourceUnavailable,$null)}
   [pscustomobject]@{PlanId=('c'*64);PendingClients=($n-1)}
  }
  $r=Invoke-TokenForgeDiscoveryRun @options
  $r.Status|Should -Be Complete
  $r.CompletedClients|Should -Be 3
  $r.ChunkAttempts|Should -Be 3
  $r.ChunksExecuted|Should -Be 2
  $r.TransientRetries|Should -Be 1
  Should -Invoke Start-Sleep -ModuleName TokenForge -Times 1 -Exactly -ParameterFilter {$Seconds -eq 1}
  Should -Invoke Get-TokenForgeResearchCohort -ModuleName TokenForge -Times 1 -Exactly
 }
 It 'stops at the retry limit with exponential delays' {
  Mock Invoke-TokenForgeResearchChunk -ModuleName TokenForge {throw [Management.Automation.ErrorRecord]::new([InvalidOperationException]::new('synthetic temporary failure'),'TokenForge.TransientIdentity',[Management.Automation.ErrorCategory]::ResourceUnavailable,$null)}
  {Invoke-TokenForgeDiscoveryRun @options -MaxTransientRetries 2}|Should -Throw '*synthetic temporary failure*'
  Should -Invoke Invoke-TokenForgeResearchChunk -ModuleName TokenForge -Times 3 -Exactly
  Should -Invoke Start-Sleep -ModuleName TokenForge -Times 2 -Exactly
  Should -Invoke Start-Sleep -ModuleName TokenForge -Times 1 -Exactly -ParameterFilter {$Seconds -eq 1}
  Should -Invoke Start-Sleep -ModuleName TokenForge -Times 1 -Exactly -ParameterFilter {$Seconds -eq 2}
 }
 It 'allows retry to be disabled' {
  Mock Invoke-TokenForgeResearchChunk -ModuleName TokenForge {throw [Management.Automation.ErrorRecord]::new([InvalidOperationException]::new('synthetic temporary failure'),'TokenForge.TransientIdentity',[Management.Automation.ErrorCategory]::ResourceUnavailable,$null)}
  {Invoke-TokenForgeDiscoveryRun @options -MaxTransientRetries 0}|Should -Throw '*synthetic temporary failure*'
  Should -Invoke Invoke-TokenForgeResearchChunk -ModuleName TokenForge -Times 1 -Exactly
  Should -Invoke Start-Sleep -ModuleName TokenForge -Times 0 -Exactly
 }
 It 'includes failed attempts in the chunk budget and refreshes partial completion counts' {
  Mock Invoke-TokenForgeResearchChunk -ModuleName TokenForge {Set-Content $counter 2;throw [Management.Automation.ErrorRecord]::new([InvalidOperationException]::new('synthetic temporary failure'),'TokenForge.TransientIdentity',[Management.Automation.ErrorCategory]::ResourceUnavailable,$null)}
  $r=Invoke-TokenForgeDiscoveryRun @options -MaxChunks 1
  $r.Status|Should -Be BudgetReached
  $r.CompletedClients|Should -Be 1
  $r.PendingClients|Should -Be 2
  $r.ChunkAttempts|Should -Be 1
  $r.ChunksExecuted|Should -Be 0
  $r.TransientRetries|Should -Be 0
  Should -Invoke Start-Sleep -ModuleName TokenForge -Times 0 -Exactly
 }
 It 'does not sleep when the backoff would exceed the remaining time budget' {
  $options.RetryDelaySeconds=60
  Mock Invoke-TokenForgeResearchChunk -ModuleName TokenForge {throw [Management.Automation.ErrorRecord]::new([InvalidOperationException]::new('synthetic temporary failure'),'TokenForge.TransientIdentity',[Management.Automation.ErrorCategory]::ResourceUnavailable,$null)}
  $r=Invoke-TokenForgeDiscoveryRun @options -MaxMinutes 1
  $r.Status|Should -Be BudgetReached
  $r.TransientRetries|Should -Be 0
  Should -Invoke Start-Sleep -ModuleName TokenForge -Times 0 -Exactly
 }
 It 'never retries untyped failures (<Message>)' -ForEach @(
  @{Message='Native metadata operation failed; HTTP 429'},
  @{Message='Issued-token context mismatch'},
  @{Message='TokenForge.TransientIdentity'}
 ) {
  Mock Invoke-TokenForgeResearchChunk -ModuleName TokenForge {throw $Message}
  {Invoke-TokenForgeDiscoveryRun @options}|Should -Throw
  Should -Invoke Invoke-TokenForgeResearchChunk -ModuleName TokenForge -Times 1 -Exactly
  Should -Invoke Start-Sleep -ModuleName TokenForge -Times 0 -Exactly
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
 It 'retries a partial native chunk without repeating completed client issuance' {
  $native=$env:TOKENFORGE_TEST_NATIVE
  $root=Join-Path $TestDrive ([guid]::NewGuid().ToString())
  $clients=@('11111111-1111-1111-1111-111111111111','22222222-2222-2222-2222-222222222222')
  $inventory=[pscustomobject]@{CapturedAt=[DateTimeOffset]::UtcNow.ToString('o');TenantFingerprint=('a'*64);PrincipalFingerprint=('b'*64);DiscoveryCatalogHash=('c'*64);TenantGrants=@();Applications=@($clients|ForEach-Object {[pscustomobject]@{AppId=$_;Registration='Present';Ownership='VerifiedMicrosoftOwner';AccountEnabled=$true;RedirectUris=@('https://login.microsoftonline.com/common/oauth2/nativeclient');PreferredRedirectUri='https://login.microsoftonline.com/common/oauth2/nativeclient';IdentifierUris=@();PublishedGrants=@();DelegatedScopeDefinitions=@()}})}
  $script:retryCalls=0
  Mock Start-Sleep -ModuleName TokenForge {}
  Mock Get-TokenForgeToken -ModuleName TokenForge {param($Request) $script:retryCalls++;if($script:retryCalls -eq 2){throw 'Identity request failed (HTTP 429); details suppressed.'}; [pscustomobject]@{AccessToken=ConvertTo-SecureString synthetic -AsPlainText -Force;RefreshToken=$null;GrantedScopes=@('User.Read');TokenClaims=[pscustomobject]@{Readable=$true;HasDelegatedScopeClaim=$true;Scopes=@('User.Read');TenantFingerprint=('a'*64);PrincipalFingerprint=('b'*64);ClientId=$Request.ClientId;Audience=$Request.ResourceId}}}
  $secret=ConvertTo-SecureString synthetic -AsPlainText -Force
  try{
   $options=@{Inventory=$inventory;EstsAuth=$secret;StatePath=$root;NativeExecutablePath=$native;GraphOnly=$true;BatchSize=2;MaxRedirects=1;ExploreAllFlows=$false;RetryDelaySeconds=1}
   $result=Invoke-TokenForgeDiscoveryRun @options
   $result.Status|Should -Be Complete
   $result.CompletedClients|Should -Be 2
   $result.ChunkAttempts|Should -Be 2
   $result.ChunksExecuted|Should -Be 1
   $result.TransientRetries|Should -Be 1
   Should -Invoke Get-TokenForgeToken -ModuleName TokenForge -Times 3 -Exactly
   Should -Invoke Start-Sleep -ModuleName TokenForge -Times 1 -Exactly -ParameterFilter {$Seconds -eq 1}
   foreach($name in @('applications.sqlite','scopes.sqlite','flows.sqlite')){Test-Path (Join-Path $root $name)|Should -BeTrue}
  }finally{$secret.Dispose()}
 }
}
