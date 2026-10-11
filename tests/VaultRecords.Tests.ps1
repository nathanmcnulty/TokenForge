BeforeAll {
 Import-Module "$PSScriptRoot/../src/TokenForge/TokenForge.psd1" -Force
 function New-RecordFixture {
  $now=[DateTimeOffset]::UtcNow;$id='c'*64
  @{SchemaVersion=1;Sessions=@{Test=@{TenantFingerprint='a'*64;PrincipalFingerprint='b'*64;Revision=[guid]::NewGuid().ToString();CreatedAt=$now.ToString('o');LastConfirmedAt=$now.ToString('o');RetainUntil=$now.AddHours(1).ToString('o');Cookie='synthetic-cookie';CookieName='ESTSAUTH';Tokens=@{$id=@{Id=$id;ClientId='11111111-1111-1111-1111-111111111111';ResourceId='00000003-0000-0000-c000-000000000000';Tenant='example.test';Audience='00000003-0000-0000-c000-000000000000';Scopes=@('User.Read');IssuedScopes=@('User.Read');AdditionalScopeCount=0;RedirectUri='http://localhost/';Spa=$false;OfflineAccess=$true;Protocol='OAuth2V2Pkce';AcquiredAt=$now.ToString('o');ExpiresAt=$null;AccessToken='synthetic-access';RefreshToken='synthetic-refresh';ConsentEvidence='SyntheticOnly'}}}}}
 }
 function Write-RawRecordFixture {
  param([string]$Json)
  $bytes=[Text.Encoding]::UTF8.GetBytes($Json)
  try{$encoded=[TokenForge.Core.V0190.VaultEnvelope]::Encrypt($bytes,$password);[IO.File]::WriteAllBytes($path,$encoded)}finally{[Array]::Clear($bytes)}
 }
}
Describe 'Shared decrypted vault record validation' {
 BeforeEach {
  $root=if($IsMacOS){$TestDrive -replace '^/var/','/private/var/'}else{$TestDrive}
  $path=Join-Path $root ([guid]::NewGuid().ToString()+'/records.tfvault')
  $password=ConvertTo-SecureString synthetic-record-passphrase -AsPlainText -Force
  $null=New-TokenForgeVault $path $password
 }
 AfterEach {$password.Dispose()}
 It 'preserves valid mixed-case legacy names and nullable unknown expiry' {
  Write-RawRecordFixture (New-RecordFixture|ConvertTo-Json -Depth 8 -Compress)
  $view=Get-TokenForgeVault $path $password
  $view.Sessions[0].Name|Should -BeExactly Test
  $view.Sessions[0].Tokens[0].ExpiryStatus|Should -Be Unknown
  $saved=Get-TokenForgeVaultToken $path $password -SessionName Test -TokenId ('c'*64) -RefreshOnly
  try{$saved.RefreshToken|Should -BeOfType securestring;$saved.AccessToken|Should -BeNullOrEmpty}finally{$saved.RefreshToken.Dispose()}
 }
 It 'rejects authenticated malformed records before projecting or retrieving credentials' -TestCases @(
  @{Case='UnknownField'},@{Case='NestedSecret'},@{Case='WrongId'},@{Case='Duplicate'},@{Case='CaseAlias'},@{Case='CaseCollision'},@{Case='Missing'},@{Case='BadType'}
 ) {
  param($Case)
  $d=New-RecordFixture;$token=$d.Sessions.Test.Tokens['c'*64]
  switch($Case){
   UnknownField {$d.Sessions.Test.Extra='synthetic-secret'}
   NestedSecret {$token.ConsentEvidence=@{AccessToken='synthetic-secret'}}
   WrongId {$token.Id='d'*64}
   Missing {$token.Remove('RefreshToken')}
   BadType {$token.Spa='false'}
  }
  $json=$d|ConvertTo-Json -Depth 8 -Compress
  if($Case -eq 'Duplicate'){$json=$json.Replace('"SchemaVersion":1','"SchemaVersion":1,"SchemaVersion":1')}
  if($Case -eq 'CaseAlias'){$json=$json.Replace('"SchemaVersion":1','"SchemaVersion":1,"schemaVersion":1')}
  if($Case -eq 'CaseCollision'){$json=$json.Replace('"Test":{','"test":{},"Test":{')}
  Write-RawRecordFixture $json
  $before=(Get-FileHash $path).Hash
  {Get-TokenForgeVault $path $password}|Should -Throw '*Details suppressed*'
  {Get-TokenForgeVaultToken $path $password -SessionName Test -TokenId ('c'*64) -RefreshOnly}|Should -Throw '*Details suppressed*'
  try{Get-TokenForgeVault $path $password}catch{$_.Exception.ToString()|Should -Not -Match 'synthetic-secret|synthetic-cookie|synthetic-refresh'}
  (Get-FileHash $path).Hash|Should -BeExactly $before
 }
 It 'refuses an invalid update and leaves the prior encrypted bytes intact' {
  Write-RawRecordFixture (New-RecordFixture|ConvertTo-Json -Depth 8 -Compress)
  $before=(Get-FileHash $path).Hash
  InModuleScope TokenForge -Parameters @{Path=$path;Password=$password} {
   {Invoke-TokenForgeVaultTransaction $Path $Password -Mode Update -Update {param($d)$d.Sessions.Test.Tokens['c'*64].RefreshToken=@{secret='synthetic-secret'}}}|Should -Throw '*Details suppressed*'
  }
  (Get-FileHash $path).Hash|Should -BeExactly $before
  (Get-TokenForgeVault $path $password).Sessions[0].Name|Should -BeExactly Test
  @(Get-ChildItem (Split-Path $path) -Filter '*.tmp').Count|Should -Be 0
 }
}
