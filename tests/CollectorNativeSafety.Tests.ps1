BeforeAll {Import-Module "$PSScriptRoot/../src/TokenForge/TokenForge.psd1" -Force}
Describe 'Original-target SQLite collector recovery' -Skip:([string]::IsNullOrEmpty($env:TOKENFORGE_TEST_NATIVE)) {
 BeforeEach {
  $root=Join-Path $TestDrive ([guid]::NewGuid().ToString());$null=New-Item -ItemType Directory $root
  if(-not $IsWindows){[IO.File]::SetUnixFileMode($root,[IO.UnixFileMode]448)}
  $path=Join-Path $root scopes.sqlite;$flow=Join-Path $root flows.sqlite
  $secret=ConvertTo-SecureString synthetic -AsPlainText -Force
  $client='11111111-1111-1111-1111-111111111111';$graph='00000003-0000-0000-c000-000000000000'
  $inventory=[pscustomobject]@{TenantFingerprint=('a'*64);PrincipalFingerprint=('b'*64);DiscoveryCatalogHash=('c'*64);Applications=@([pscustomobject]@{AppId=$client;Registration='Present';Ownership='VerifiedMicrosoftOwner';AccountEnabled=$true;RedirectUris=@('https://login.microsoftonline.com/common/oauth2/nativeclient');PreferredRedirectUri='https://login.microsoftonline.com/common/oauth2/nativeclient';IdentifierUris=@()})}
  $budget=& (Get-Module TokenForge) {New-TokenForgeOperationBudget}
  $opts=@{Inventory=$inventory;EstsAuth=$secret;ResourceId=$graph;DatabasePath=$path;FlowDatabasePath=$flow;Protocols=@('OAuth2V2Pkce');DelayMilliseconds=0;StopOnTransientFailure=$true;OperationBudget=$budget;NativeExecutablePath=$env:TOKENFORGE_TEST_NATIVE;CohortFingerprint=('d'*64)}
  Mock Get-TokenForgeToken -ModuleName TokenForge {param($Request) [pscustomobject]@{AccessToken=ConvertTo-SecureString synthetic -AsPlainText -Force;RefreshToken=$null;GrantedScopes=@('User.Read');TokenClaims=[pscustomobject]@{Readable=$true;HasDelegatedScopeClaim=$true;Scopes=@('User.Read');TenantFingerprint=('a'*64);PrincipalFingerprint=('b'*64);ClientId=$Request.ClientId;Audience=$Request.ResourceId}}}
 }
 AfterEach {$secret.Dispose()}
 It 'counts every persisted uncertainty and refuses a second recovery after restart' {
  {Invoke-TokenForgeScopeProbe @opts -CheckpointAction {throw 'synthetic interruption'}}|Should -Throw
  {Invoke-TokenForgeScopeProbe @opts -RecoverUnknown -CheckpointAction {throw 'synthetic interruption'}}|Should -Throw
  (Get-TokenForgeFlowEvidence $flow -NativeExecutablePath $env:TOKENFORGE_TEST_NATIVE).Attempts.Count|Should -Be 2
  {Invoke-TokenForgeScopeProbe @opts -RecoverUnknown}|Should -Throw '*unknown*'
  Should -Invoke Get-TokenForgeToken -ModuleName TokenForge -Times 0 -Exactly
 }
 It 'repairs primary evidence without issuance and preserves its original observation date' {
  $script:checks=0
  {Invoke-TokenForgeScopeProbe @opts -CheckpointAction {$script:checks++;if($script:checks -eq 2){throw 'synthetic projection interruption'}}}|Should -Throw
  $before=Get-TokenForgeFlowEvidence $flow -NativeExecutablePath $env:TOKENFORGE_TEST_NATIVE
  $result=Invoke-TokenForgeScopeProbe @opts
  $result.ObservedAt|Should -Be $before.Attempts[0].ObservedAt
  $after=Get-TokenForgeFlowEvidence $flow -NativeExecutablePath $env:TOKENFORGE_TEST_NATIVE
  $after.Attempts.Count|Should -Be 1
  Should -Invoke Get-TokenForgeToken -ModuleName TokenForge -Times 1 -Exactly
 }
 It 'refuses corrupted older history before issuing a request' {
  $null=Invoke-TokenForgeScopeProbe @opts
  $program='import sqlite3,sys; c=sqlite3.connect(sys.argv[1]); c.execute("UPDATE flow_attempts SET payload=?", ("{\"AccessToken\":\"synthetic\"}",)); c.commit(); c.close()'
  & python3 -c $program $flow
  $LASTEXITCODE|Should -Be 0
  {Invoke-TokenForgeScopeProbe @opts}|Should -Throw '*cannot be read*'
  Should -Invoke Get-TokenForgeToken -ModuleName TokenForge -Times 1 -Exactly
 }
}
