BeforeAll {
 Import-Module "$PSScriptRoot/../src/TokenForge/TokenForge.psd1" -Force
 if(Get-Module Microsoft.Graph.Authentication -ListAvailable){Import-Module Microsoft.Graph.Authentication}else{
  function global:Get-MgContext {}
  function global:Connect-MgGraph {param([securestring]$AccessToken,[switch]$NoWelcome)}
  function global:Disconnect-MgGraph {}
 }
}
Describe 'Graph SDK context ownership' {
 BeforeEach {
  $secret=ConvertTo-SecureString synthetic-access -AsPlainText -Force
  $refresh=ConvertTo-SecureString synthetic-refresh -AsPlainText -Force
  $sdkContext=[pscustomobject]@{ClientId='synthetic';AuthType='UserProvidedAccessToken'}
  $token=[pscustomobject]@{AccessToken=$secret;RefreshToken=$refresh;ExpiresAt=[DateTimeOffset]::UtcNow.AddHours(1);Evidence='CachedVerifiedContextNotNewIssuance';TokenClaims=[pscustomobject]@{Scopes=@('User.Read')}}
  Mock Import-Module -ModuleName TokenForge {} -ParameterFilter {$Name -eq 'Microsoft.Graph.Authentication'}
  Mock Get-TokenForgeProfileToken -ModuleName TokenForge {return $token}
  Mock Connect-MgGraph -ModuleName TokenForge {}
  Mock Disconnect-MgGraph -ModuleName TokenForge {}
  Mock Get-MgContext -ModuleName TokenForge {return $null}
 }
 AfterEach {& (Get-Module TokenForge) {if($script:GraphConnection){$script:GraphConnection.Secret.Dispose();$script:GraphConnection=$null}}}
 It 'refuses an existing SDK context before acquiring credentials' {
  Mock Get-MgContext -ModuleName TokenForge {return $sdkContext}
  {Connect-TokenForgeGraph lab -Scope User.Read}|Should -Throw '*process-wide*'
  Should -Invoke Get-TokenForgeProfileToken -ModuleName TokenForge -Times 0 -Exactly
 }
 It 'hands off only the access token and does not retry SDK calls' {
  $null=Connect-TokenForgeGraph lab -Scope User.Read
  Should -Invoke Connect-MgGraph -ModuleName TokenForge -Times 1 -Exactly -ParameterFilter {$AccessToken -is [securestring] -and $NoWelcome}
  {[Net.NetworkCredential]::new('', $secret).Password}|Should -Throw
  {[Net.NetworkCredential]::new('', $refresh).Password}|Should -Throw
 }
 It 'refuses to disconnect a replaced context' {
  $null=Connect-TokenForgeGraph lab -Scope User.Read
  Mock Get-MgContext -ModuleName TokenForge {return $sdkContext}
  {Disconnect-TokenForgeGraph}|Should -Throw '*replaced outside*'
  Should -Invoke Disconnect-MgGraph -ModuleName TokenForge -Times 0 -Exactly
 }
 It 'does not replace a context established while acquiring a token' {
  $state=@{Current=$null}
  Mock Get-MgContext -ModuleName TokenForge {return $state.Current}
  Mock Get-TokenForgeProfileToken -ModuleName TokenForge {$state.Current=$sdkContext;return $token}
  {Connect-TokenForgeGraph lab -Scope User.Read}|Should -Throw '*connection failed*'
  Should -Invoke Connect-MgGraph -ModuleName TokenForge -Times 0 -Exactly
  {[Net.NetworkCredential]::new('', $secret).Password}|Should -Throw
 }
 It 'keeps ownership when SDK disconnection fails so it can be retried' {
  $state=@{Current=$null}
  Mock Get-MgContext -ModuleName TokenForge {return $state.Current}
  Mock Connect-MgGraph -ModuleName TokenForge {$state.Current=$sdkContext}
  $null=Connect-TokenForgeGraph lab -Scope User.Read
  Mock Disconnect-MgGraph -ModuleName TokenForge {throw 'synthetic failure'}
  {Disconnect-TokenForgeGraph}|Should -Throw '*retained*'
  $owned=& (Get-Module TokenForge) {$script:GraphConnection.Secret.Length}
  $owned|Should -BeGreaterThan 0
 }

}
