BeforeAll {
 Import-Module "$PSScriptRoot/../src/TokenForge/TokenForge.psd1" -Force
 $runner="$PSScriptRoot/../scripts/Invoke-TokenForgeCiDiscovery.ps1"
}
Describe 'CI discovery boundaries' {
 BeforeEach {
  Mock Import-Module {}
  Mock Update-TokenForgeCatalog -ModuleName TokenForge {
   $catalog=Get-TokenForgeCatalog -Path "$PSScriptRoot/fixtures/catalog.json"
   $catalog.Source='https://raw.githubusercontent.com/example/public/main/scopes.json'
   $catalog
  }
  Mock Invoke-RestMethod -ModuleName TokenForge {@()}
 }
 It 'runs public-only without credentials and validates existing anonymous exports' {
  $data=Join-Path $TestDrive 'data'
  $result=& $runner -DataPath $data -PublicOnly
  $result.Stage|Should -Be PublicDiscovery
  $null=New-Item -ItemType Directory (Join-Path $data scopes)
  @{SchemaVersion=1;Disclaimer='Observed scopes are session/tenant dependent, not universal consent or guaranteed API access.';Observations=@(@{TenantFingerprint=('a'*64);ClientId='11111111-1111-1111-1111-111111111111'})}|ConvertTo-Json -Depth 10|Set-Content (Join-Path $data 'scopes/chunk-0000.json')
  {& $runner -DataPath $data -PublicOnly}|Should -Throw '*No private state*'
 }
 It 'rejects hidden or nested export files before refreshing metadata' {
  foreach($relative in @('scopes/.hidden.json','scopes/private/inventory.json')){
   $data=Join-Path $TestDrive ([guid]::NewGuid().ToString());$path=Join-Path $data $relative
   $null=New-Item -ItemType Directory (Split-Path $path) -Force
   '{}'|Set-Content $path
   {& $runner -DataPath $data -PublicOnly}|Should -Throw '*No private state*'
   Test-Path (Join-Path $data applications.json)|Should -BeFalse
  }
 }
 It 'rejects private nested values in anonymous observation dates' {
  $data=Join-Path $TestDrive 'nested-export';$null=New-Item -ItemType Directory (Join-Path $data scopes) -Force
  @{SchemaVersion=1;Disclaimer='Observed scopes are session/tenant dependent, not universal consent or guaranteed API access.';Observations=@(@{ClientId='11111111-1111-1111-1111-111111111111';ResourceId='00000003-0000-0000-c000-000000000000';ObservedAt=@{AccessToken='nested-secret'};Scopes=@('User.Read');Evidence='AnonymousTenantTokenObservation';SignatureValidated=$false})}|ConvertTo-Json -Depth 10|Set-Content (Join-Path $data 'scopes/chunk-0000.json')
  {& $runner -DataPath $data -PublicOnly}|Should -Throw '*No private state*'
 }
 It 'refuses a mismatched bootstrap before inventory reads and clears the cookie environment' {
  $env:TOKENFORGE_ESTS_COOKIE='synthetic-cookie';$env:TOKENFORGE_COOKIE_NAME='ESTSAUTHPERSISTENT'
  $env:TOKENFORGE_TENANT_FINGERPRINT='a'*64;$env:TOKENFORGE_PRINCIPAL_FINGERPRINT='b'*64
  Mock Get-TokenForgeToken {[pscustomobject]@{AccessToken=(ConvertTo-SecureString synthetic-access -AsPlainText -Force);RefreshToken=$null;TokenClaims=[pscustomobject]@{TenantFingerprint=('a'*64);PrincipalFingerprint=('c'*64);ClientId='14d82eec-204b-4c2f-b7e8-296a70dab67e';Audience='00000003-0000-0000-c000-000000000000'}}}
  Mock Get-TokenForgeTenantInventory {throw 'Unexpected inventory read'}
  try{
   {& $runner -DataPath (Join-Path $TestDrive 'wrong-account')}|Should -Throw '*No private state*'
   Should -Invoke Get-TokenForgeTenantInventory -Times 0
   Should -Invoke Get-TokenForgeToken -Times 1 -ParameterFilter {$CookieName -eq 'ESTSAUTHPERSISTENT'}
   $env:TOKENFORGE_ESTS_COOKIE|Should -BeNullOrEmpty
  }finally{$env:TOKENFORGE_TENANT_FINGERPRINT=$null;$env:TOKENFORGE_PRINCIPAL_FINGERPRINT=$null}
 }
}
