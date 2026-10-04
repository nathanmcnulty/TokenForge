BeforeAll {
 Import-Module "$PSScriptRoot/../src/TokenForge/TokenForge.psd1" -Force
}
Describe 'Comparison completeness and privacy' {
 BeforeEach {
  $tid='aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa';$fixtureoid='bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb'
  $payload=@{tid=$tid;oid=$fixtureoid;appid='14d82eec-204b-4c2f-b7e8-296a70dab67e';aud='00000003-0000-0000-c000-000000000000';scp='User.Read'}|ConvertTo-Json -Compress
  $b64=[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($payload)).TrimEnd('=').Replace('+','-').Replace('/','_')
  $access=ConvertTo-SecureString "e30.$b64.synthetic" -AsPlainText -Force
  $fixturecontext=[pscustomobject]@{AccessToken=$access;RefreshToken=$null;TokenClaims=(Get-TokenForgeTokenClaims -AccessToken $access)}
  $fixturecookie=ConvertTo-SecureString synthetic -AsPlainText -Force
  @{TenantFingerprint=$fixturecontext.TokenClaims.TenantFingerprint;PrincipalFingerprint=$fixturecontext.TokenClaims.PrincipalFingerprint}|ConvertTo-Json|Set-Content "$TestDrive/inventory.json"
  $database=New-TokenForgeScopeDatabase;$database|ConvertTo-Json -Depth 8|Set-Content "$TestDrive/scopes.json"
  $observer=@{Alias='User';DatabasePath="$TestDrive/scopes.json";PasskeyPath='synthetic.passkey'}
  $fixturemembers=@(@{'@odata.type'='#microsoft.graph.group';id='11111111-1111-1111-1111-111111111111'},@{'@odata.type'='#microsoft.graph.group';id='22222222-2222-2222-2222-222222222222'})
  Mock Import-Module {}
  Mock Get-TokenForgeEstsCookie {return $fixturecookie}
  Mock New-TokenForgeTenantRequest {return @{}}
  Mock Get-TokenForgeToken {return $fixturecontext}
  Mock Get-TokenForgeScopedToken {param($ResourceId)[pscustomobject]@{AccessToken=(ConvertTo-SecureString synthetic -AsPlainText -Force);RefreshToken=$null;TokenClaims=$fixturecontext.TokenClaims;ClientId='33333333-3333-3333-3333-333333333333';ObservedAdditionalScopeCount=0;ApiCheck=@{Status=200;Accepted=$true}}}
  Mock Invoke-TokenForgeGraph -ModuleName TokenForge {return @{id=$fixtureoid}}
  Mock Get-TokenForgeGraphCollection -ModuleName TokenForge {
   param($AccessToken,$Uri)
   if($Uri.AbsolutePath -eq '/v1.0/me/transitiveMemberOf'){return ,$fixturemembers}
   return ,@()
  }
 }
 It 'does not report groups as queried when the group cap prevents their queries' {
  $report=& "$PSScriptRoot/../scripts/Invoke-TokenForgeLiveComparison.ps1" -InventoryPath "$TestDrive/inventory.json" -Observers @($observer) -XdrModulePath synthetic.psd1 -MaxGroups 1
  $roles=$report.Observers[0].Context.GroupDerivedRoles
  $roles.VisibleGroupCount|Should -Be 2
  $roles.QueriedGroupCount|Should -Be 0
  $roles.Complete|Should -BeFalse
  $roles.ActiveCount|Should -BeNullOrEmpty
  ($report|ConvertTo-Json -Depth 12)|Should -Not -Match 'synthetic.passkey|bbbbbbbb|TokenClaims|AccessToken|DatabasePath'
 }
 It 'marks denied eligible-role reads unknown rather than zero' {
  Mock Get-TokenForgeGraphCollection -ModuleName TokenForge {
   param($AccessToken,$Uri)
   if($Uri.AbsolutePath -match 'roleEligibilityScheduleInstances'){throw 'Graph request failed (HTTP 403); response details suppressed.'}
   return ,@()
  }
  $report=& "$PSScriptRoot/../scripts/Invoke-TokenForgeLiveComparison.ps1" -InventoryPath "$TestDrive/inventory.json" -Observers @($observer) -XdrModulePath synthetic.psd1
  $report.Observers[0].Context.DirectEligibleRoles.Status|Should -Be 403
  $report.Observers[0].Context.DirectEligibleRoles.Complete|Should -BeFalse
  $report.Observers[0].Context.DirectEligibleRoles.Count|Should -BeNullOrEmpty
 }
}
