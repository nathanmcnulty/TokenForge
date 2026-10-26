BeforeDiscovery {
 $nativeAvailable=[bool]($env:TOKENFORGE_TEST_NATIVE -and (Test-Path -LiteralPath $env:TOKENFORGE_TEST_NATIVE -PathType Leaf))
}
BeforeAll {
 Import-Module "$PSScriptRoot/../src/TokenForge/TokenForge.psd1" -Force
 function Write-ChangeFile($Path,$Object) {
  $file=[TokenForge.Core.V0220.PrivateFiles]::Open($Path,$true)
  try{$bytes=[Text.Encoding]::UTF8.GetBytes((ConvertTo-Json -InputObject $Object -Depth 40 -Compress));$file.Write($bytes);$file.Flush($true)}finally{$file.Dispose()}
 }
 function Invoke-ChangeNative([string[]]$Options,[int]$Exit=0) {
  $start=[Diagnostics.ProcessStartInfo]::new($env:TOKENFORGE_TEST_NATIVE);$start.UseShellExecute=$false;$start.RedirectStandardOutput=$true;$start.RedirectStandardError=$true
  $start.Environment['PATH']=Join-Path $root no-powershell
  foreach($arg in @('research')+$Options){$start.ArgumentList.Add($arg)}
  $p=[Diagnostics.Process]::Start($start)
  try{$out=$p.StandardOutput.ReadToEndAsync();$err=$p.StandardError.ReadToEndAsync();if(-not $p.WaitForExit(30000)){$p.Kill($true);throw 'Native change report fixture timed out.'};$p.ExitCode|Should -Be $Exit;$stdout=$out.GetAwaiter().GetResult();$stderr=$err.GetAwaiter().GetResult()
   if($Exit){$stdout|Should -BeNullOrEmpty;$stderr|Should -Not -Match ([regex]::Escape($root));$stderr|Should -Not -Match 'synthetic-private|AccessToken';($stderr|ConvertFrom-Json).Code|Should -Be OperationFailed}
   else{$stderr|Should -BeNullOrEmpty;[TokenForge.Core.DiscoverySourceClaims]::ReadMetadataJson($stdout)}
  }finally{$p.Dispose()}
 }
}
Describe 'Native Goal 2 explicit saved-evidence consumers' -Skip:(-not $nativeAvailable) {
 BeforeEach {
  $root=Join-Path ($TestDrive -replace '^/var/','/private/var/') ([guid]::NewGuid().ToString());$null=New-Item -ItemType Directory $root
  if(-not $IsWindows){[IO.File]::SetUnixFileMode($root,[IO.UnixFileMode]448)}
  $beforePath=Join-Path $root before.json;$afterPath=Join-Path $root after.json
  $client='11111111-1111-1111-1111-111111111111';$graph='00000003-0000-0000-c000-000000000000'
  $context=@{ContextVersion=1;QueryFingerprint=('1'*64);TenantFingerprint=('a'*64);PrincipalFingerprint=('b'*64);ClientId=$client;ResourceId=$graph;AuthorityFingerprint=('c'*64);RequestedScopes=@("$graph/.default",'offline_access');Protocol='OAuth2V2Pkce';CallbackFingerprint=('d'*64);CallbackClass='Native';Spa=$false;RecipeFingerprint=('e'*64);ExecutionPolicyFingerprint=('f'*64)}
  $row=@{ClientId=$client;ResourceId=$graph;TenantFingerprint=('a'*64);PrincipalFingerprint=('b'*64);ObservedAt='2026-01-02T00:00:00Z';Outcome='Succeeded';Protocol='OAuth2V2Pkce';Spa=$false;RedirectFingerprint=('d'*64);RequestedScopes=$context.RequestedScopes;ScpScopes=@('User.Read','Mail.Read');ClaimsReadable=$true;HasScpClaim=$true;NamespaceVerification='Matched';RequestVerification='Matched';SignatureValidated=$false;ComparisonContext=$context}
  $before=@{SchemaVersion=1;UpdatedAt='2026-01-02T01:00:00Z';Observations=@($row);RegistrationAttempts=@()}
  $after=[TokenForge.Core.DiscoverySourceClaims]::ReadMetadataJson(($before|ConvertTo-Json -Depth 30 -Compress));$after.Observations[0].ScpScopes=@('User.Read')
  Write-ChangeFile $beforePath $before;Write-ChangeFile $afterPath $after
  $options=@('changes','--before-path',$beforePath,'--after-path',$afterPath,'--kind','ScopeDatabase','--as-of','2026-01-02T01:00:00Z','--json')
 }
 It 'matches PowerShell output exactly without PowerShell on PATH and preserves inputs' {
  $beforeHash=(Get-FileHash $beforePath).Hash;$afterHash=(Get-FileHash $afterPath).Hash
  $native=Invoke-ChangeNative $options
  $ps=Get-TokenForgeChangeReport $beforePath $afterPath -Kind ScopeDatabase -AsOf ([DateTimeOffset]'2026-01-02T01:00:00Z')
  ($native|ConvertTo-Json -Depth 50 -Compress)|Should -Be ($ps|ConvertTo-Json -Depth 50 -Compress)
  $native.Entries[0].EventType|Should -Be MatchedRequestScopesChanged
  (Get-FileHash $beforePath).Hash|Should -Be $beforeHash;(Get-FileHash $afterPath).Hash|Should -Be $afterHash
  @(Get-ChildItem $root).Count|Should -Be 2
 }
 It 'normalizes saved input natively with the same typed snapshot as PowerShell' {
  $n=Invoke-ChangeNative @('snapshot','--input-path',$beforePath,'--kind','ScopeDatabase','--json')
  $p=ConvertTo-TokenForgeChangeSnapshot $before -Kind ScopeDatabase
  ($n|ConvertTo-Json -Depth 40 -Compress)|Should -Be ($p|ConvertTo-Json -Depth 40 -Compress)
 }
 It 'refuses private evidence in public-only reports' {Invoke-ChangeNative ($options+@('--public-only')) 1}
 It 'rejects unknown or duplicate options before emitting any evidence' -TestCases @(@{Flag='--profile'},@{Flag='--kind'},@{Flag='--root'}) {
  param($Flag)
  Invoke-ChangeNative ($options+@($Flag,'synthetic-private')) 1
 }
 It 'rejects missing evidence paths without initializing a store' {
  $missing=Join-Path $root missing.json
  Invoke-ChangeNative @('changes','--before-path',$missing,'--after-path',$afterPath,'--kind','ScopeDatabase') 1
  Test-Path $missing|Should -BeFalse
 }
 It 'rejects credential-bearing saved history without echoing field values or paths' {
  $after.Observations[0].AccessToken='synthetic-private';Remove-Item $afterPath;Write-ChangeFile $afterPath $after
  Invoke-ChangeNative $options 1
  {Get-TokenForgeChangeReport $beforePath $afterPath -Kind ScopeDatabase}|Should -Throw '*Change evidence*'
 }
 It 'rejects symbolic links and broad permissions at explicit file ingress' -Skip:$IsWindows {
  $link=Join-Path $root link.json;$null=New-Item -ItemType SymbolicLink -Path $link -Target $beforePath
  Invoke-ChangeNative @('changes','--before-path',$link,'--after-path',$afterPath,'--kind','ScopeDatabase') 1
  [IO.File]::SetUnixFileMode($beforePath,[IO.UnixFileMode]420)
  Invoke-ChangeNative $options 1
  {Get-TokenForgeChangeReport $beforePath $afterPath -Kind ScopeDatabase}|Should -Throw '*Change evidence file*'
 }
 It 'rejects oversized JSON before parsing' {
  $oversized=Join-Path $root large.json;$file=[TokenForge.Core.V0220.PrivateFiles]::Open($oversized,$true)
  try{$file.SetLength(67108865)}finally{$file.Dispose()}
  Invoke-ChangeNative @('snapshot','--input-path',$oversized,'--kind','ScopeDatabase') 1
 }
 It 'round trips bound request context through native SQLite evidence storage' {
  $sql=Join-Path $root scopes.sqlite
  $null=& $env:TOKENFORGE_TEST_NATIVE evidence import --database $sql --input $beforePath
  $LASTEXITCODE|Should -Be 0
  $loaded=Get-TokenForgeScopeDatabase $sql -NativeExecutablePath $env:TOKENFORGE_TEST_NATIVE
  $s=ConvertTo-TokenForgeChangeSnapshot $loaded -Kind ScopeDatabase
  $s.Collections[0].Context.ExecutionPolicyFingerprint|Should -Be ('f'*64)
  (Compare-TokenForgeEvidence $s $s -MaxAgeHours 87600).Entries[0].EventType|Should -Be Unchanged
 }
 It 'persists new bounded descriptors in native SQLite flow and metadata stores' {
  $scopePath=Join-Path $root collector.sqlite;$flowPath=Join-Path $root flows.sqlite;$meta=Join-Path $root metadata.sqlite
  $inventory=[pscustomobject]@{TenantFingerprint=('a'*64);PrincipalFingerprint=('b'*64);DiscoveryCatalogHash=('c'*64);Applications=@([pscustomobject]@{AppId=$client;Registration='Present';Ownership='VerifiedMicrosoftOwner';AccountEnabled=$true;RedirectUris=@('https://login.microsoftonline.com/common/oauth2/nativeclient');PreferredRedirectUri='https://login.microsoftonline.com/common/oauth2/nativeclient';IdentifierUris=@()})}
  $secret=ConvertTo-SecureString synthetic -AsPlainText -Force;$budget=& (Get-Module TokenForge) {New-TokenForgeOperationBudget}
  Mock Get-TokenForgeToken -ModuleName TokenForge {param($Request) [pscustomobject]@{AccessToken=ConvertTo-SecureString synthetic -AsPlainText -Force;RefreshToken=$null;GrantedScopes=@('User.Read');TokenClaims=[pscustomobject]@{Readable=$true;HasDelegatedScopeClaim=$true;Scopes=@('User.Read');TenantFingerprint=('a'*64);PrincipalFingerprint=('b'*64);ClientId=$Request.ClientId;Audience=$Request.ResourceId}}}
  try{$null=Invoke-TokenForgeScopeProbe $inventory $secret -ResourceId $graph -DatabasePath $scopePath -FlowDatabasePath $flowPath -NativeExecutablePath $env:TOKENFORGE_TEST_NATIVE -Protocols OAuth2V2Pkce -DelayMilliseconds 0 -OperationBudget $budget}finally{$secret.Dispose()}
  $flows=Get-TokenForgeFlowEvidence $flowPath -NativeExecutablePath $env:TOKENFORGE_TEST_NATIVE
  $flows.Attempts[0].ComparisonContext.RequestedScopes|Should -Contain offline_access
  $scope=Get-TokenForgeScopeDatabase $scopePath -NativeExecutablePath $env:TOKENFORGE_TEST_NATIVE
  $scope.Observations[0].ComparisonContext.RequestedScopes|Should -Contain offline_access
  $null=Update-TokenForgeApplicationMetadata $meta $flows FlowAttempts -NativeExecutablePath $env:TOKENFORGE_TEST_NATIVE
  $null=Update-TokenForgeApplicationMetadata $meta $scope ScopeObservations -NativeExecutablePath $env:TOKENFORGE_TEST_NATIVE
  $metadata=Get-TokenForgeApplicationMetadata $meta -NativeExecutablePath $env:TOKENFORGE_TEST_NATIVE
  $metadata.Applications.Count|Should -Be 1
 }
 It 'refuses native Started-to-terminal descriptor changes including legacy upgrades' -TestCases @(@{Case='Changed'},@{Case='Removed'},@{Case='AddedToLegacy'}) {
  param($Case)
  $scopePath=Join-Path $root context-scopes.json;$flowPath=Join-Path $root context-flows.json;$sql=Join-Path $root flow-context.sqlite
  $inventory=[pscustomobject]@{TenantFingerprint=('a'*64);PrincipalFingerprint=('b'*64);DiscoveryCatalogHash=('c'*64);Applications=@([pscustomobject]@{AppId=$client;Registration='Present';Ownership='VerifiedMicrosoftOwner';AccountEnabled=$true;RedirectUris=@('https://login.microsoftonline.com/common/oauth2/nativeclient');PreferredRedirectUri='https://login.microsoftonline.com/common/oauth2/nativeclient';IdentifierUris=@()})}
  $secret=ConvertTo-SecureString synthetic -AsPlainText -Force;$budget=& (Get-Module TokenForge) {New-TokenForgeOperationBudget}
  Mock Get-TokenForgeToken -ModuleName TokenForge {param($Request) [pscustomobject]@{AccessToken=ConvertTo-SecureString synthetic -AsPlainText -Force;RefreshToken=$null;GrantedScopes=@('User.Read');TokenClaims=[pscustomobject]@{Readable=$true;HasDelegatedScopeClaim=$true;Scopes=@('User.Read');TenantFingerprint=('a'*64);PrincipalFingerprint=('b'*64);ClientId=$Request.ClientId;Audience=$Request.ResourceId}}}
  try{$null=Invoke-TokenForgeScopeProbe $inventory $secret -ResourceId $graph -DatabasePath $scopePath -FlowDatabasePath $flowPath -Protocols OAuth2V2Pkce -DelayMilliseconds 0 -OperationBudget $budget}finally{$secret.Dispose()}
  $flows=Get-TokenForgeFlowEvidence $flowPath;$terminal=$flows.Attempts[0].Clone();$started=$terminal.Clone();$started.Outcome='Started';$started.ObservedAt=$started.StartedAt
  if($Case -eq 'AddedToLegacy'){$null=$started.Remove('ComparisonContext')}
  $flows.Attempts=@($started);$input=Join-Path $root started.json;Write-ChangeFile $input $flows
  $null=& $env:TOKENFORGE_TEST_NATIVE flows import --database $sql --input $input;$LASTEXITCODE|Should -Be 0
  if($Case -eq 'Changed'){$terminal.ComparisonContext=$terminal.ComparisonContext.Clone();$terminal.ComparisonContext.ExecutionPolicyFingerprint='9'*64}
  if($Case -eq 'Removed'){$null=$terminal.Remove('ComparisonContext')}
  $terminalPath=Join-Path $root terminal.json;Write-ChangeFile $terminalPath $terminal
  $errorOutput=& $env:TOKENFORGE_TEST_NATIVE flows attempt --database $sql --input $terminalPath 2>&1
  $LASTEXITCODE|Should -Be 1
  ($errorOutput -join '')|Should -Not -Match 'offline_access|ComparisonContext|RecipeFingerprint'
  $unchanged=Get-TokenForgeFlowEvidence $sql -NativeExecutablePath $env:TOKENFORGE_TEST_NATIVE
  $unchanged.Attempts[0].Outcome|Should -Be Started
 }

}
