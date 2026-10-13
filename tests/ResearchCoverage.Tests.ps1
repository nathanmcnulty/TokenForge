BeforeAll {
 Import-Module "$PSScriptRoot/../src/TokenForge/TokenForge.psd1" -Force
 $native=$env:TOKENFORGE_TEST_NATIVE
 $client='11111111-1111-1111-1111-111111111111';$graph='00000003-0000-0000-c000-000000000000'
}
Describe 'Research coverage temporal and native parity' {
 BeforeEach {
  $state=Join-Path ($TestDrive -replace '^/var/','/private/var/') ([guid]::NewGuid().ToString())
  $null=New-Item -ItemType Directory $state
  if(-not $IsWindows){[IO.File]::SetUnixFileMode($state,[IO.UnixFileMode]448)}
  $metadata=Join-Path $state applications.json;$scope=Join-Path $state scopes.json;$flow="$scope.flows.json"
  $cookie=ConvertTo-SecureString synthetic -AsPlainText -Force
  $app=[pscustomobject]@{AppId=$client;Name='2026-01-01T00:00:00+02:00';Registration='Present';Ownership='VerifiedMicrosoftOwner';AccountEnabled=$true;RedirectUris=@('https://example.test/callback');PreferredRedirectUri='https://example.test/callback';IdentifierUris=@();PublicClient=$true;PublishedGrants=@();DelegatedScopeDefinitions=@();IsResourceCandidate=$false;Sources=@();OwnerTenantId='f8cdef31-a31e-4b4a-93e4-5f571e91255a'}
  $inventory=[pscustomobject]@{SchemaVersion=1;CapturedAt=[DateTimeOffset]::UtcNow.ToString('o');TenantFingerprint=('a'*64);PrincipalFingerprint=('b'*64);DiscoveryCatalogHash=('c'*64);Applications=@($app);TenantGrants=@()}
  Mock Get-TokenForgeToken -ModuleName TokenForge {param($Request)
   [pscustomobject]@{AccessToken=ConvertTo-SecureString synthetic-access -AsPlainText -Force;RefreshToken=$null;GrantedScopes=@('User.Read');TokenClaims=[pscustomobject]@{Readable=$true;HasDelegatedScopeClaim=$true;Scopes=@('User.Read');TenantFingerprint=('a'*64);PrincipalFingerprint=('b'*64);ClientId=$Request.ClientId;Audience=$Request.ResourceId}}
  }
  $null=Invoke-TokenForgeScopeProbe $inventory $cookie -ResourceId $graph -DatabasePath $scope -DelayMilliseconds 0
  $null=Update-TokenForgeApplicationMetadata $metadata $inventory Inventory
 }
 AfterEach {$cookie.Dispose()}
 It 'selects UTC instants rather than offset timestamp strings and preserves inputs' {
  $db=Get-TokenForgeFlowEvidence $flow;$older=$db.Attempts[0];$older.ObservedAt=[DateTimeOffset]::UtcNow.AddSeconds(-30).ToOffset([TimeSpan]::FromHours(2)).ToString('o');$older.StartedAt=$older.ObservedAt
  $retry=$older.Clone();$retry.AttemptId=[guid]::NewGuid().ToString();$retry.Outcome='Started';$retry.ObservedAt=[DateTimeOffset]::UtcNow.AddSeconds(-10).ToString('o');$retry.StartedAt=$retry.ObservedAt
  $db.Attempts=@($older,$retry);[IO.File]::WriteAllText($flow,($db|ConvertTo-Json -Depth 12))
  $before=(Get-FileHash $flow).Hash;$metadataBefore=(Get-FileHash $metadata).Hash
  $report=Get-TokenForgeResearchCoverage $metadata -FlowPath $flow -TenantFingerprint ('a'*64) -PrincipalFingerprint ('b'*64)
  $report.InterruptedSlots|Should -Be 1;$report.ApplicationsWithObservedSuccess|Should -Be 0
  (Get-FileHash $flow).Hash|Should -Be $before;(Get-FileHash $metadata).Hash|Should -Be $metadataBefore
 }
 It 'uses later append order on tied attempt instants' {
  $db=Get-TokenForgeFlowEvidence $flow;$retry=$db.Attempts[0].Clone();$retry.AttemptId=[guid]::NewGuid().ToString();$retry.Outcome='Failed'
  $db.Attempts+=@($retry);[IO.File]::WriteAllText($flow,($db|ConvertTo-Json -Depth 12))
  $report=Get-TokenForgeResearchCoverage $metadata -FlowPath $flow -TenantFingerprint ('a'*64) -PrincipalFingerprint ('b'*64)
  $report.ApplicationsWithObservedSuccess|Should -Be 0;$report.Applications[0].FlowCoverage[0].FailedSlots|Should -Be 1
 }
 It 'rejects malformed explicit flow history even without an account selection' {
  $db=Get-TokenForgeFlowEvidence $flow;$db.Attempts[0].AccessToken='synthetic';[IO.File]::WriteAllText($flow,($db|ConvertTo-Json -Depth 12))
  {Get-TokenForgeResearchCoverage $metadata -FlowPath $flow}|Should -Throw
 }
 It 'rejects duplicate fields before PowerShell JSON projection' {
  $text=[IO.File]::ReadAllText($flow);$text=$text -replace '"SchemaVersion": 1','"SchemaVersion": 1, "SchemaVersion": 1';[IO.File]::WriteAllText($flow,$text)
  {Get-TokenForgeResearchCoverage $metadata -FlowPath $flow}|Should -Throw
 }
 It 'rejects injected current catalog attributes on both adapters' {
  $catalog=[TokenForge.Core.DiscoverySourceClaims]::ReadMetadataJson([IO.File]::ReadAllText($metadata))
  $record=@($catalog.Applications[$client].Records.Values)[0]
  $record.Attributes.Name=@{AccessToken='synthetic'}
  [IO.File]::WriteAllText($metadata,($catalog|ConvertTo-Json -Depth 40))
  {Get-TokenForgeResearchCoverage $metadata}|Should -Throw
  if($native){$output=& $native research report --metadata-path $metadata --json 2>&1;$LASTEXITCODE|Should -Not -Be 0;($output -join ' ')|Should -Not -Match 'synthetic'}
 }
 It 'rejects injected historical catalog attributes before app filtering' {
  $catalog=[TokenForge.Core.DiscoverySourceClaims]::ReadMetadataJson([IO.File]::ReadAllText($metadata))
  $record=@($catalog.Applications[$client].Records.Values)[0]
  $record.PreviousVersions=@(@{FirstSeenAt=$record.FirstSeenAt;LastSeenAt=$record.LastSeenAt;Attributes=@{AppId=$client;Name=@{AccessToken='synthetic'}};Sources=@();ContentSha256=('c'*64)})
  [IO.File]::WriteAllText($metadata,($catalog|ConvertTo-Json -Depth 40))
  {Get-TokenForgeResearchCoverage $metadata -AppId '22222222-2222-2222-2222-222222222222'}|Should -Throw
  if($native){$output=& $native research report --metadata-path $metadata --app '22222222-2222-2222-2222-222222222222' --json 2>&1;$LASTEXITCODE|Should -Not -Be 0;($output -join ' ')|Should -Not -Match 'synthetic'}
 }
 It 'rejects a missing explicit flow path while optional state coverage stays empty' {
  {Get-TokenForgeResearchCoverage $metadata -FlowPath (Join-Path $state missing.json)}|Should -Throw
  (Get-TokenForgeResearchCoverage $metadata).PlannedSlots|Should -Be 0
  if($native){$null=& $native research report --metadata-path $metadata --flow-path (Join-Path $state missing.json) --json 2>&1;$LASTEXITCODE|Should -Not -Be 0}
 }
 It 'runs the native JSON report with the same selected-account fields' -Skip:(-not $env:TOKENFORGE_TEST_NATIVE) {
  $expected=Get-TokenForgeResearchCoverage $metadata -FlowPath $flow -TenantFingerprint ('a'*64) -PrincipalFingerprint ('b'*64)
  $actualJson=& $native research report --metadata-path $metadata --flow-path $flow --tenant-fingerprint ('a'*64) --principal-fingerprint ('b'*64) --json
  $actual=[pscustomobject][TokenForge.Core.DiscoverySourceClaims]::ReadMetadataJson(($actualJson -join [Environment]::NewLine))
  $LASTEXITCODE|Should -Be 0
  ($actual|ConvertTo-Json -Depth 30 -Compress)|Should -BeExactly ($expected|ConvertTo-Json -Depth 30 -Compress)
  $actual.Applications[0].Name|Should -BeExactly '2026-01-01T00:00:00+02:00'
 }
 It 'reads SQLite catalog and flows without changing bytes or requiring PowerShell' -Skip:(-not $env:TOKENFORGE_TEST_NATIVE) {
  $catalogSqlite=Join-Path $state applications.sqlite;$flowSqlite=Join-Path $state flows.sqlite
  $null=Import-TokenForgeApplicationMetadata $catalogSqlite -InputPath $metadata -NativeExecutablePath $native
  $null=Import-TokenForgeFlowEvidence $flowSqlite -InputPath $flow -NativeExecutablePath $native
  $before=@((Get-FileHash $catalogSqlite).Hash,(Get-FileHash $flowSqlite).Hash)
  $savedPath=$env:PATH
  try{$env:PATH=Split-Path $native -Parent
   $report=& $native research report --metadata-path $catalogSqlite --flow-path $flowSqlite --tenant-fingerprint ('a'*64) --principal-fingerprint ('b'*64) --json | ConvertFrom-Json
   $LASTEXITCODE|Should -Be 0;$report.ApplicationsWithObservedSuccess|Should -Be 1
  }finally{$env:PATH=$savedPath}
  (Get-FileHash $catalogSqlite).Hash|Should -Be $before[0];(Get-FileHash $flowSqlite).Hash|Should -Be $before[1]
 }
}
