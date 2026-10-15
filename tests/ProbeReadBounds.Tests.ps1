BeforeAll {Import-Module "$PSScriptRoot/../src/TokenForge/TokenForge.psd1" -Force}
Describe 'Cohort observation read bounds' {
 BeforeEach {
  $client='11111111-1111-1111-1111-111111111111';$graph='00000003-0000-0000-c000-000000000000'
  $inventory=[pscustomobject]@{TenantFingerprint=('a'*64);PrincipalFingerprint=('b'*64);DiscoveryCatalogHash=('c'*64);Applications=@([pscustomobject]@{AppId=$client;Registration='Present';Ownership='VerifiedMicrosoftOwner';AccountEnabled=$true;RedirectUris=@('https://login.microsoftonline.com/common/oauth2/nativeclient');PreferredRedirectUri='https://login.microsoftonline.com/common/oauth2/nativeclient';IdentifierUris=@()})}
  $root=Join-Path $TestDrive ([guid]::NewGuid().ToString())
  $secret=ConvertTo-SecureString synthetic -AsPlainText -Force
  $options=@{Inventory=$inventory;EstsAuth=$secret;ResourceId=$graph;DatabasePath=(Join-Path $root scopes.sqlite);Protocols=@('OAuth2V2Pkce');DelayMilliseconds=0;NativeExecutablePath='/synthetic/tokenforge'}
  Mock Invoke-TokenForgeNativeEvidence -ModuleName TokenForge {@{Imported=0}} -ParameterFilter {$Domain -eq 'evidence' -and $Operation -eq 'update'}
  Mock Get-TokenForgeScopeDatabase -ModuleName TokenForge {New-TokenForgeScopeDatabase}
  Mock Get-TokenForgeToken -ModuleName TokenForge {param($Request) [pscustomobject]@{AccessToken=ConvertTo-SecureString synthetic -AsPlainText -Force;RefreshToken=$null;GrantedScopes=@('User.Read');TokenClaims=[pscustomobject]@{Readable=$true;HasDelegatedScopeClaim=$true;Scopes=@('User.Read');TenantFingerprint=('a'*64);PrincipalFingerprint=('b'*64);ClientId=$Request.ClientId;Audience=$Request.ResourceId}}}
 }
 AfterEach {$secret.Dispose()}
 It 'reads only the exact account, client, resource and flow plan for a cohort' {
  $rows=@(Invoke-TokenForgeScopeProbe @options -CohortFingerprint ('d'*64))
  $rows.Count|Should -Be 1
  $rows[0].Outcome|Should -Be Succeeded
  Should -Invoke Get-TokenForgeScopeDatabase -ModuleName TokenForge -Times 1 -Exactly
  Should -Invoke Get-TokenForgeScopeDatabase -ModuleName TokenForge -Times 1 -Exactly -ParameterFilter {$Latest -and $TenantFingerprint -eq ('a'*64) -and $PrincipalFingerprint -eq ('b'*64) -and $ClientId -eq $client -and $ResourceId -eq $graph -and $PlanFingerprint -eq $rows[0].PlanFingerprint}
 }
 It 'repairs scope metadata from the exact saved aggregate without another issuance' {
  $rows=@(Invoke-TokenForgeScopeProbe @options -CohortFingerprint ('d'*64))
  Mock Get-TokenForgeScopeDatabase -ModuleName TokenForge {[pscustomobject]@{SchemaVersion=1;UpdatedAt=[DateTimeOffset]::UtcNow.ToString('o');Observations=$rows;RegistrationAttempts=@()}}
  $changes=@{}
  @(Invoke-TokenForgeScopeProbe @options -CohortFingerprint ('d'*64) -ScopeChanges $changes).Count|Should -Be 0
  $changes.Count|Should -Be 1
  $changes["$client/$graph"].Outcome|Should -Be Succeeded
  Should -Invoke Get-TokenForgeToken -ModuleName TokenForge -Times 1 -Exactly
  Should -Invoke Get-TokenForgeScopeDatabase -ModuleName TokenForge -Times 2 -Exactly
 }
 It 'retains the account-wide latest read outside a cohort' {
  $rows=@(Invoke-TokenForgeScopeProbe @options)
  $rows[0].Outcome|Should -Be Succeeded
  Should -Invoke Get-TokenForgeScopeDatabase -ModuleName TokenForge -Times 1 -Exactly -ParameterFilter {$Latest -and $TenantFingerprint -eq ('a'*64) -and $PrincipalFingerprint -eq ('b'*64) -and -not $PlanFingerprint}
 }
}
