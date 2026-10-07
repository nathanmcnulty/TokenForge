BeforeDiscovery {
 $nativeAvailable=[bool]($env:TOKENFORGE_TEST_NATIVE -and (Test-Path -LiteralPath $env:TOKENFORGE_TEST_NATIVE -PathType Leaf))
}
BeforeAll {
 Import-Module "$PSScriptRoot/../src/TokenForge/TokenForge.psd1" -Force
 $native=$env:TOKENFORGE_TEST_NATIVE
}
Describe 'Native SQLite flow integration' -Skip:(-not $nativeAvailable) {
 BeforeEach {
  $root=Join-Path ($TestDrive -replace '^/var/','/private/var/') ([guid]::NewGuid().ToString())
  $path=Join-Path $root scopes.json;$sqlite=Join-Path $root flows.sqlite
  # Let the shared private-path helper create a protected current-user directory.
  $null=Get-TokenForgeFlowEvidence (Join-Path $root missing.json)
  $graph='00000003-0000-0000-c000-000000000000';$client='11111111-1111-1111-1111-111111111111'
  $app=[pscustomobject]@{AppId=$client;Name='Fixture';Registration='Present';Ownership='VerifiedMicrosoftOwner';AccountEnabled=$true;RedirectUris=@('https://example.test/callback');PreferredRedirectUri='https://example.test/callback';IdentifierUris=@()}
  $inventory=[pscustomobject]@{TenantFingerprint=('a'*64);PrincipalFingerprint=('b'*64);DiscoveryCatalogHash=('c'*64);Applications=@($app)}
  $secret=ConvertTo-SecureString synthetic -AsPlainText -Force
  Mock Get-TokenForgeToken -ModuleName TokenForge {param($Request) [pscustomobject]@{AccessToken=ConvertTo-SecureString private-access -AsPlainText -Force;RefreshToken=$null;GrantedScopes=@('User.Read');TokenClaims=[pscustomobject]@{Readable=$true;HasDelegatedScopeClaim=$true;Scopes=@('User.Read');TenantFingerprint=('a'*64);PrincipalFingerprint=('b'*64);ClientId=$Request.ClientId;Audience=$Request.ResourceId}}}
 }
 AfterEach {$secret.Dispose()}
 It 'writes individual attempts, reads current plans, and resumes without issuance' {
  $probe=@{Inventory=$inventory;EstsAuth=$secret;ResourceId=$graph;DatabasePath=$path;FlowDatabasePath=$sqlite;NativeExecutablePath=$native;ExploreAllFlows=$true;DelayMilliseconds=0}
  $changes=@{Plans=@{};Attempts=@{}}
  $null=Invoke-TokenForgeScopeProbe @probe -FlowChanges $changes
  $changes.Plans.Count|Should -Be 1
  $changes.Attempts.Count|Should -Be 4
  @($changes.Attempts.Values|Where-Object Outcome -eq Started).Count|Should -Be 0
  $db=Get-TokenForgeFlowEvidence $sqlite -NativeExecutablePath $native
  $db.Attempts.Count|Should -Be 4
  (Get-TokenForgeFlowEvidence $sqlite -NativeExecutablePath $native -TenantFingerprint ('a'*64) -PrincipalFingerprint ('d'*64) -Latest).Attempts.Count|Should -Be 0
  (Get-TokenForgeFlowEvidence $sqlite -NativeExecutablePath $native -TenantFingerprint ('a'*64) -PrincipalFingerprint ('b'*64) -Latest).Attempts.Count|Should -Be 4
  $hash=@($db.Plans.Keys)[0]
  (Get-TokenForgeFlowEvidence $sqlite -NativeExecutablePath $native -PlanFingerprint $hash -TenantFingerprint ('a'*64) -PrincipalFingerprint ('b'*64)).Attempts.Count|Should -Be 4
  $changes=@{Plans=@{};Attempts=@{}}
  @(Invoke-TokenForgeScopeProbe @probe -FlowChanges $changes).Count|Should -Be 0
  $changes.Attempts.Count|Should -Be 4
  Should -Invoke Get-TokenForgeToken -ModuleName TokenForge -Times 4
  @(Get-ChildItem $root -Filter '*.flow-input.json').Count|Should -Be 0
 }
 It 'migrates legacy JSON idempotently and round trips through strict PowerShell validation' {
  $legacy=Join-Path $root legacy.json
  $null=Invoke-TokenForgeScopeProbe $inventory $secret -ResourceId $graph -DatabasePath $path -FlowDatabasePath $legacy -DelayMilliseconds 0
  (Import-TokenForgeFlowEvidence $sqlite $legacy -NativeExecutablePath $native).Imported|Should -Be 1
  (Import-TokenForgeFlowEvidence $sqlite $legacy -NativeExecutablePath $native).Imported|Should -Be 0
  $db=Get-TokenForgeFlowEvidence $sqlite -NativeExecutablePath $native
  $export=Join-Path $root roundtrip.json
  $db|ConvertTo-Json -Depth 12|Set-Content $export
  if(-not $IsWindows){[IO.File]::SetUnixFileMode($export,[IO.UnixFileMode]384)}
  (Get-TokenForgeFlowEvidence $export).Attempts.Count|Should -Be 1
  $db.Plans.Values|ForEach-Object {$_.ResourceAliases=[array]@($_.ResourceAliases|Sort-Object -Descending)}
  $db|ConvertTo-Json -Depth 12|Set-Content $export
  (Import-TokenForgeFlowEvidence $sqlite $export -NativeExecutablePath $native).Imported|Should -Be 0
 }
 It 'fails safely when the native dependency is missing before token acquisition' {
  {Invoke-TokenForgeScopeProbe $inventory $secret -ResourceId $graph -DatabasePath $path -FlowDatabasePath $sqlite -NativeExecutablePath "$root/no-native" -DelayMilliseconds 0}|Should -Throw '*native*'
  Should -Invoke Get-TokenForgeToken -ModuleName TokenForge -Times 0
 }
}
