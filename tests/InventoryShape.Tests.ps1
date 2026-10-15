BeforeAll {
 Import-Module "$PSScriptRoot/../src/TokenForge/TokenForge.psd1" -Force
}
Describe 'Inventory object and literal dictionary planning equivalence' {
 BeforeEach {
  $client='11111111-1111-1111-1111-111111111111';$resource='22222222-2222-2222-2222-222222222222'
  $inventory=[pscustomobject]@{SchemaVersion=1;CapturedAt='2026-01-01T00:00:00Z';TenantFingerprint=('a'*64);PrincipalFingerprint=('b'*64);GrantEnumeration='Complete';Applications=@([pscustomobject]@{AppId=$client;Name='2026-01-01T00:00:00Z';Registration='Present';Ownership='VerifiedMicrosoftOwner';AccountEnabled=$true;RedirectUris=@('https://login.microsoftonline.com/common/oauth2/nativeclient');PublishedGrants=@([pscustomobject]@{ResourceId=$resource;Scopes=@('Example.Read')});DelegatedScopeDefinitions=@([pscustomobject]@{Value='Own.Read';Enabled=$true})});TenantGrants=@([pscustomobject]@{ClientId=$client;ResourceId='33333333-3333-3333-3333-333333333333';ConsentType='AllPrincipals';PrincipalFingerprint=$null;Scopes=@('Tenant.Read')})}
 }
 It 'preserves complete planner fields including literal names and grant enumeration' {
  $inventory|Add-Member AccessToken 'synthetic-private-root'
  $inventory.Applications[0]|Add-Member RefreshToken 'synthetic-private-app'
  $inventory.Applications[0].PublishedGrants[0]|Add-Member Secret 'synthetic-private-grant'
  $inventory.TenantGrants[0]|Add-Member Secret 'synthetic-private-tenant-grant'
  $cached=[TokenForge.Core.DiscoverySourceClaims]::ReadMetadataJson((ConvertTo-Json -InputObject $inventory -Depth 100))
  $before=& (Get-Module TokenForge) {param($i) ConvertTo-TokenForgePlanningInventory $i} $inventory
  $after=& (Get-Module TokenForge) {param($i) ConvertTo-TokenForgePlanningInventory $i} $cached
  $after|Should -BeExactly $before
  $after|Should -Not -Match 'synthetic-private'
 }
 It 'preserves published, own-resource and all-principal grant pairs' {
  $cached=[TokenForge.Core.DiscoverySourceClaims]::ReadMetadataJson((ConvertTo-Json -InputObject $inventory -Depth 100))
  $before=Get-TokenForgeProbePlan -Inventory $inventory|ConvertTo-Json -Depth 10 -Compress
  $after=Get-TokenForgeProbePlan -Inventory $cached|ConvertTo-Json -Depth 10 -Compress
  $after|Should -BeExactly $before
  @(Get-TokenForgeProbePlan -Inventory $cached).Count|Should -Be 4
 }
 It 'preserves principal-specific applicability and excludes another principal' {
  $inventory.TenantGrants[0].ConsentType='Principal';$inventory.TenantGrants[0].PrincipalFingerprint='b'*64
  $cached=[TokenForge.Core.DiscoverySourceClaims]::ReadMetadataJson((ConvertTo-Json -InputObject $inventory -Depth 100))
  @(Get-TokenForgeProbePlan -Inventory $cached).Count|Should -Be 4
  @(Get-TokenForgeProbePlan -Inventory $cached -PrincipalFingerprint ('c'*64)).Count|Should -Be 3
 }
 It 'retains null and empty projections for omitted legacy optional members' {
  $inventory.Applications[0].PSObject.Properties.Remove('AccountEnabled')
  $inventory.Applications[0].PSObject.Properties.Remove('DelegatedScopeDefinitions')
  $inventory.TenantGrants[0].PSObject.Properties.Remove('PrincipalFingerprint')
  foreach($shape in @($inventory,[TokenForge.Core.DiscoverySourceClaims]::ReadMetadataJson((ConvertTo-Json -InputObject $inventory -Depth 100)))){
   $json=& (Get-Module TokenForge) {param($i) Set-StrictMode -Version Latest; ConvertTo-TokenForgePlanningInventory $i} $shape
   $projection=[TokenForge.Core.DiscoverySourceClaims]::ReadMetadataJson($json)
   $projection.Applications[0].Contains('AccountEnabled')|Should -BeTrue
   $projection.Applications[0].AccountEnabled|Should -BeNullOrEmpty
   $projection.Applications[0].DelegatedScopeDefinitions.Count|Should -Be 0
   $projection.TenantGrants[0].Contains('PrincipalFingerprint')|Should -BeTrue
   $projection.TenantGrants[0].PrincipalFingerprint|Should -BeNullOrEmpty
  }
 }

 It 'retains non-Graph audience aliases when probing a cached inventory' {
  $inventory|Add-Member DiscoveryCatalogHash ('c'*64)
  $inventory.Applications[0]|Add-Member PreferredRedirectUri $inventory.Applications[0].RedirectUris[0]
  $inventory.Applications[0]|Add-Member IdentifierUris @()
  $inventory.Applications+=[pscustomobject]@{AppId=$resource;Name='resource';IdentifierUris=@('https://example.test/resource');Registration='Present';Ownership='VerifiedMicrosoftOwner';AccountEnabled=$true;RedirectUris=@();PreferredRedirectUri='';PublishedGrants=@();DelegatedScopeDefinitions=@()}
  Mock Get-TokenForgeToken -ModuleName TokenForge {[pscustomobject]@{AccessToken=(ConvertTo-SecureString synthetic -AsPlainText -Force);RefreshToken=$null;GrantedScopes=@('Example.Read');TokenClaims=[pscustomobject]@{Readable=$true;HasDelegatedScopeClaim=$true;Scopes=@('Example.Read');TenantFingerprint=('a'*64);PrincipalFingerprint=('b'*64);ClientId='11111111-1111-1111-1111-111111111111';Audience='https://example.test/resource'}}}
  $cookie=ConvertTo-SecureString synthetic -AsPlainText -Force
  try{
   foreach($shape in @($inventory,[TokenForge.Core.DiscoverySourceClaims]::ReadMetadataJson((ConvertTo-Json -InputObject $inventory -Depth 100)))){
    $path=Join-Path (Join-Path $TestDrive ([guid]::NewGuid().ToString())) scopes.json
    $r=@(Invoke-TokenForgeScopeProbe -Inventory $shape -EstsAuth $cookie -ResourceId $resource -ClientId $client -Protocols OAuth2V2Pkce -DatabasePath $path -DelayMilliseconds 0)
    $r.Count|Should -Be 1
    $r[0].Outcome|Should -Be Succeeded
    $r[0].ScpScopes|Should -Be @('Example.Read')
   }
  }finally{$cookie.Dispose()}
 }

}
