BeforeDiscovery {
 $nativeAvailable=[bool]($env:TOKENFORGE_TEST_NATIVE -and (Test-Path -LiteralPath $env:TOKENFORGE_TEST_NATIVE -PathType Leaf))
}
BeforeAll {
 . "$PSScriptRoot/../scripts/TokenForgeDiscoveryCandidate.ps1"
 $native=$env:TOKENFORGE_TEST_NATIVE
}
Describe 'Original-target saved candidate integration with mocked issuance' -Skip:(-not $nativeAvailable) {
 BeforeEach {
  $root=Join-Path ($TestDrive -replace '^/var/','/private/var/') ([guid]::NewGuid().ToString())
  $scopePath=Join-Path $root scopes.sqlite;$flowPath=Join-Path $root flows.sqlite
  $null=Get-TokenForgeFlowEvidence (Join-Path $root missing.json)
  $client='11111111-1111-1111-1111-111111111111';$graph='00000003-0000-0000-c000-000000000000'
  $callback='https://login.microsoftonline.com/common/oauth2/nativeclient'
  $app=[pscustomobject]@{AppId=$client;Name='Synthetic';Registration='Present';Ownership='VerifiedMicrosoftOwner';AccountEnabled=$true;RedirectUris=@($callback);PreferredRedirectUri=$callback;IdentifierUris=@();PublishedGrants=@();DelegatedScopeDefinitions=@()}
  $inventory=[pscustomobject]@{CapturedAt=[DateTimeOffset]::UtcNow.ToString('o');TenantFingerprint=('a'*64);PrincipalFingerprint=('b'*64);DiscoveryCatalogHash=('c'*64);TenantGrants=@();Applications=@($app)}
  $secret=ConvertTo-SecureString synthetic -AsPlainText -Force
  Mock Get-TokenForgeToken -ModuleName TokenForge {param($Request)
   [pscustomobject]@{AccessToken=ConvertTo-SecureString private-access -AsPlainText -Force;RefreshToken=$null;GrantedScopes=@('User.Read');TokenClaims=[pscustomobject]@{Readable=$true;HasDelegatedScopeClaim=$true;Scopes=@('User.Read');TenantFingerprint=('a'*64);PrincipalFingerprint=('b'*64);ClientId=$Request.ClientId;Audience=$Request.ResourceId}}
  }
  $cohort=New-TokenForgeResearchCohort -Inventory $inventory -DatabasePath $scopePath -GraphOnly -Protocols OAuth2V2Pkce -BatchSize 1 -MaxRedirects 1 -ExploreAllFlows -NativeExecutablePath $native
  $probe=@{Inventory=$inventory;EstsAuth=$secret;Plan=@($cohort.Cohort.Pairs);DatabasePath=$scopePath;FlowDatabasePath=$flowPath;CohortFingerprint=$cohort.PlanId;Protocols=@('OAuth2V2Pkce');MaxRedirects=1;ExploreAllFlows=$true;DelayMilliseconds=0;NativeExecutablePath=$native}
  $candidateOptions=@{ScopePath=$scopePath;FlowPath=$flowPath;CohortId=$cohort.PlanId;OutputPath=(Join-Path $root candidate);SourceCommit=('d'*40);ProducerRunId='1';ProducerAttempt='1';NativeExecutablePath=$native}
 }
 AfterEach {$secret.Dispose()}
 It 'rebuilds an omitted aggregate projection using actual native cohort and terminal checkpoints' {
  # Simulate interruption after durable flow checkpoint, before aggregate persistence.
  Mock Add-TokenForgeScopeObservation -ModuleName TokenForge {param($Database) $Database}
  $null=Invoke-TokenForgeScopeProbe @probe
  (Get-TokenForgeScopeDatabase $scopePath -NativeExecutablePath $native).Observations.Count|Should -Be 0
  $before=Get-TokenForgeFlowEvidence $flowPath -NativeExecutablePath $native
  @($before.Attempts|Where-Object Outcome -eq Succeeded).Count|Should -Be 1
  $observedAt=@($before.Attempts|Where-Object Outcome -eq Succeeded)[0].ObservedAt
  $hash=New-TfDiscoveryCandidate @candidateOptions
  $null=Assert-TfDiscoveryCandidate $candidateOptions.OutputPath $hash
  $v=Read-TfCandidateJson "$($candidateOptions.OutputPath)/validation.json"
  $v.SelectedPairs|Should -Be 1;$v.PlannedCells|Should -Be 1;$v.TerminalCells|Should -Be 1;$v.ScopeObservations|Should -Be 1
  $export=Read-TfCandidateJson "$($candidateOptions.OutputPath)/scopes.json"
  [DateTimeOffset]$export.Observations[0].ObservedAt|Should -Be ([DateTimeOffset]$observedAt)
  (Get-TokenForgeScopeDatabase $scopePath -NativeExecutablePath $native).Observations.Count|Should -Be 0
  (Get-TokenForgeFlowEvidence $flowPath -NativeExecutablePath $native).Attempts.Count|Should -Be $before.Attempts.Count
  Should -Invoke Get-TokenForgeToken -ModuleName TokenForge -Times 1 -Exactly
 }
 It 'exports a paused native run with zero successes and no additional issuance' {
  Mock Get-TokenForgeToken -ModuleName TokenForge {throw 'AADSTS50173 synthetic expired session'}
  {Invoke-TokenForgeScopeProbe @probe}|Should -Throw '*paused*'
  $hash=New-TfDiscoveryCandidate @candidateOptions
  $null=Assert-TfDiscoveryCandidate $candidateOptions.OutputPath $hash
  $v=Read-TfCandidateJson "$($candidateOptions.OutputPath)/validation.json"
  $v.PausedCells|Should -Be 1;$v.TerminalCells|Should -Be 0;$v.ScopeObservations|Should -Be 0;$v.FlowObservations|Should -Be 0
  Should -Invoke Get-TokenForgeToken -ModuleName TokenForge -Times 1 -Exactly
 }
 It 'exports only this frozen cohort when the native store contains another valid cohort' {
  $null=Invoke-TokenForgeScopeProbe @probe
  $other=New-TokenForgeResearchCohort -Inventory $inventory -DatabasePath $scopePath -GraphOnly -Protocols OAuth2V2Pkce -BatchSize 1 -MaxRedirects 1 -ExploreAllFlows -NativeExecutablePath $native
  $other.PlanId|Should -Not -Be $cohort.PlanId
  $otherProbe=$probe.Clone();$otherProbe.CohortFingerprint=$other.PlanId
  $null=Invoke-TokenForgeScopeProbe @otherProbe
  $hash=New-TfDiscoveryCandidate @candidateOptions
  $null=Assert-TfDiscoveryCandidate $candidateOptions.OutputPath $hash
  (Read-TfCandidateJson "$($candidateOptions.OutputPath)/scopes.json").Observations.Count|Should -Be 1
  Should -Invoke Get-TokenForgeToken -ModuleName TokenForge -Times 2 -Exactly
 }
}
