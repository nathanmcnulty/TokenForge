BeforeAll {
 Import-Module "$PSScriptRoot/../src/TokenForge/TokenForge.psd1" -Force
 function New-WorkflowToken {
  param($Client,$TenantId,$ObjectId,$Scopes=@('User.Read'))
  $json=@{tid=$TenantId;oid=$ObjectId;appid=$Client;aud='00000003-0000-0000-c000-000000000000';scp=($Scopes -join ' ')}|ConvertTo-Json -Compress
  $encoded=[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($json)).TrimEnd('=').Replace('+','-').Replace('/','_')
  $secret=ConvertTo-SecureString "e30.$encoded.synthetic" -AsPlainText -Force
  [pscustomobject]@{AccessToken=$secret;RefreshToken=(ConvertTo-SecureString synthetic-refresh -AsPlainText -Force);TokenClaims=(Get-TokenForgeTokenClaims -AccessToken $secret);AdditionalScopes=@();ClientId=$Client;ResourceId='00000003-0000-0000-c000-000000000000'}
 }
}
Describe 'Single-command scoped tokens' {
 BeforeEach {
  $tid='aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa';$oid='bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb'
  $bootstrapId='14d82eec-204b-4c2f-b7e8-296a70dab67e';$client='11111111-1111-1111-1111-111111111111';$other='22222222-2222-2222-2222-222222222222';$graph='00000003-0000-0000-c000-000000000000'
  $bootstrap=New-WorkflowToken $bootstrapId $tid $oid
  $issued=New-WorkflowToken $client $tid $oid
  $tenantFp=$bootstrap.TokenClaims.TenantFingerprint;$principalFp=$bootstrap.TokenClaims.PrincipalFingerprint
  $applications=foreach($id in @($bootstrapId,$client,$other,$graph)){[pscustomobject]@{AppId=$id;Name='Synthetic';Registration='Present';Ownership='VerifiedMicrosoftOwner';AccountEnabled=$true;PublicClient=$true;Foci=$false;RedirectUris=@('https://login.microsoftonline.com/common/oauth2/nativeclient','https://example.test/callback','http://localhost');PreferredRedirectUri='https://login.microsoftonline.com/common/oauth2/nativeclient';IdentifierUris=@('https://graph.microsoft.com');DelegatedScopeDefinitions=@([pscustomobject]@{Enabled=$true;Value='User.Read'})}}
  $inventory=[pscustomobject]@{CapturedAt=[DateTimeOffset]::UtcNow.ToString('o');TenantFingerprint=$tenantFp;PrincipalFingerprint=('c'*64);DiscoveryCatalogHash=('d'*64);Applications=@($applications)}
  $db=New-TokenForgeScopeDatabase
  $redirect='https://example.test/callback';$redirectHash=[Convert]::ToHexString([Security.Cryptography.SHA256]::HashData([Text.Encoding]::UTF8.GetBytes($redirect))).ToLowerInvariant()
  $observation=[pscustomobject]@{ClientId=$client;ResourceId=$graph;Outcome='Succeeded';ObservedAt=[DateTimeOffset]::UtcNow.ToString('o');TenantFingerprint=$tenantFp;PrincipalFingerprint=$principalFp;ScpScopes=@('User.Read');NamespaceVerification='Matched';RequestVerification='Matched';Spa=$true;Protocol='OAuth2V2Pkce';RedirectFingerprint=$redirectHash}
  $db.Observations=@($observation)
  $cookie=ConvertTo-SecureString synthetic-cookie -AsPlainText -Force
  $options=@{Inventory=$inventory;Database=$db;ResourceId=$graph;Scope=@('User.Read');EstsAuth=$cookie}
  $requests=[Collections.Generic.List[object]]::new()
  Mock Get-TokenForgeToken -ModuleName TokenForge {param($Request) $requests.Add($Request);if($Request.ClientId -eq $bootstrapId){return $bootstrap};return $issued}
  Mock Invoke-TokenForgeGraph -ModuleName TokenForge {return @{id=$oid}}
 }
 It 'uses actual observer rather than inventory observer, preserving recorded callback and SPA' {
  $result=Get-TokenForgeScopedToken @options
  $result.Request.ClientId|Should -Be $client
  $result.Request.RedirectUri|Should -Be $redirect
  $result.Request.Spa|Should -BeTrue
  $result.Request.Tenant|Should -Be $tid
  $result.Request.PSObject.Properties.Name|Should -Not -Contain Discovery
  $result.Request.Scopes|Should -Be @('User.Read')
  $result.ObservedAdditionalScopeCount|Should -Be 0
  $result.AccessToken.Length|Should -BeGreaterThan 0
  {[Net.NetworkCredential]::new('', $bootstrap.AccessToken).Password}|Should -Throw
  $cookie.Length|Should -BeGreaterThan 0
 }
 It 'does not use another account coverage when signed-in account has none' {
  $observation.PrincipalFingerprint='c'*64
  {Get-TokenForgeScopedToken @options}|Should -Throw '*No fresh coverage*'
  Should -Invoke Get-TokenForgeToken -ModuleName TokenForge -Times 1 -Exactly
 }
 It 'rejects a different bootstrap tenant before scope selection' {
  $inventory.TenantFingerprint='e'*64
  {Get-TokenForgeScopedToken @options}|Should -Throw '*bootstrap context*'
  {[Net.NetworkCredential]::new('', $bootstrap.AccessToken).Password}|Should -Throw
 }
 It 'rejects a bootstrap token whose oid does not match Graph me' {
  Mock Invoke-TokenForgeGraph -ModuleName TokenForge {return @{id='cccccccc-cccc-cccc-cccc-cccccccccccc'}}
  {Get-TokenForgeScopedToken @options}|Should -Throw '*Graph identity*'
 }
 It 'rejects wrong final account and disposes its secrets' {
  $issued=New-WorkflowToken $client $tid 'cccccccc-cccc-cccc-cccc-cccccccccccc'
  {Get-TokenForgeScopedToken @options -MaxRedirects 1}|Should -Throw '*No candidate*'
  {[Net.NetworkCredential]::new('', $issued.AccessToken).Password}|Should -Throw
  {[Net.NetworkCredential]::new('', $issued.RefreshToken).Password}|Should -Throw
 }
 It 'rejects a wrong final client or audience' {
  $issued.TokenClaims.ClientId=$other
  {Get-TokenForgeScopedToken @options -MaxRedirects 1}|Should -Throw '*No candidate*'
 }
 It 'rejects a wrong final audience independently' {
  $issued.TokenClaims.Audience='https://other.example.test'
  {Get-TokenForgeScopedToken @options -MaxRedirects 1}|Should -Throw '*No candidate*'
 }
 It 'rejects opaque scope/context evidence' {
  $issued.TokenClaims.HasDelegatedScopeClaim=$false
  {Get-TokenForgeScopedToken @options -MaxRedirects 1}|Should -Throw '*No candidate*'
 }
 It 'enforces additional scope limit against actual issued scp' {
  $issued.TokenClaims.Scopes=@('User.Read','Mail.Read')
  {Get-TokenForgeScopedToken @options -MaxAdditionalScopes 0 -MaxRedirects 1}|Should -Throw '*No candidate*'
 }
 It 'returns valid token with API 403 separately without fallback' {
  Mock Test-TokenForgeTokenAccess -ModuleName TokenForge {[pscustomobject]@{Status=403;Accepted=$false}}
  $result=Get-TokenForgeScopedToken @options -ApiUri https://graph.microsoft.com/v1.0/me
  $result.ApiCheck.Status|Should -Be 403
  $result.AccessToken.Length|Should -BeGreaterThan 0
  Should -Invoke Get-TokenForgeToken -ModuleName TokenForge -Times 2 -Exactly
 }
 It 'rejects API host before authenticating' {
  {Get-TokenForgeScopedToken @options -ApiUri https://other.example.test/me}|Should -Throw '*boundary*'
  Should -Invoke Get-TokenForgeToken -ModuleName TokenForge -Times 0 -Exactly
 }
 It 'does not try disabled applications or resources' {
  ($inventory.Applications|Where-Object AppId -eq $graph).AccountEnabled=$false
  {Get-TokenForgeScopedToken @options}|Should -Throw '*Enabled*'
 }
 It 'rejects stale inventory before authenticating' {
  $inventory.CapturedAt=[DateTimeOffset]::UtcNow.AddDays(-2).ToString('o')
  {Get-TokenForgeScopedToken @options}|Should -Throw '*Inventory is stale*'
 }
 It 'does not revive older coverage after a newer failed observation' {
  $failure=$observation.PSObject.Copy();$failure.Outcome='Failed';$failure.ObservedAt=[DateTimeOffset]::UtcNow.AddSeconds(1).ToString('o');$db.Observations+=$failure
  {Get-TokenForgeScopedToken @options}|Should -Throw '*No fresh coverage*'
 }
 It 'tries another ranked client after rejected explicit request without using default scopes' {
  $second=$observation.PSObject.Copy();$second.ClientId=$other;$second.ScpScopes=@('User.Read','Mail.Read');$db.Observations+=$second
  $issued=New-WorkflowToken $other $tid $oid
  Mock Get-TokenForgeToken -ModuleName TokenForge {param($Request)$requests.Add($Request);if($Request.ClientId -eq $bootstrapId){return $bootstrap};if($Request.ClientId -eq $client){throw 'AADSTS65002 synthetic sensitive details'};return $issued}
  $result=Get-TokenForgeScopedToken @options -MaxRedirects 1
  $result.Request.ClientId|Should -Be $other
  $result.AttemptSummary[0].EntraCodes|Should -Contain AADSTS65002
  ($result.AttemptSummary|ConvertTo-Json -Depth 5)|Should -Not -Match 'sensitive details'
  @($requests|Where-Object {$_.OAuthScopes -match '\.default'}).Count|Should -Be 0
 }
 It 'disposes the internally acquired passkey cookie' {
  Mock Get-TokenForgeEstsCookie -ModuleName TokenForge {return $cookie}
  $options.Remove('EstsAuth');$options.PasskeyPath='synthetic.passkey';$options.XdrModulePath='synthetic.psd1'
  $result=Get-TokenForgeScopedToken @options
  {[Net.NetworkCredential]::new('', $cookie).Password}|Should -Throw
  $result.AccessToken.Length|Should -BeGreaterThan 0
 }
 It 'uses only a published localhost callback in browser mode' {
  $options.Remove('EstsAuth');$options.Browser=$true
  $result=Get-TokenForgeScopedToken @options
  $result.Request.RedirectUri|Should -Be 'http://localhost'
  $result.Request.Spa|Should -BeFalse
 }
 It 'skips disabled ranked clients before consuming the candidate limit' {
  ($inventory.Applications|Where-Object AppId -eq $client).AccountEnabled=$false
  $second=$observation.PSObject.Copy();$second.ClientId=$other;$second.ScpScopes=@('User.Read','Mail.Read');$db.Observations+=$second
  $issued=New-WorkflowToken $other $tid $oid
  (Get-TokenForgeScopedToken @options -MaxCandidates 1).Request.ClientId|Should -Be $other
 }
 It 'accepts ARM audience aliases with a trailing slash' {
  $arm='797f4846-ba00-4fd7-ba43-dac1f8f63013'
  $armResource=($inventory.Applications|Where-Object AppId -eq $graph).PSObject.Copy();$armResource.AppId=$arm;$armResource.IdentifierUris=@('https://management.core.windows.net');$inventory.Applications+=$armResource
  $observation.ResourceId=$arm;$observation.ScpScopes=@('user_impersonation');$options.ResourceId=$arm;$options.Scope=@('user_impersonation')
  $issued.TokenClaims.Audience='https://management.core.windows.net/';$issued.TokenClaims.Scopes=@('user_impersonation')
  (Get-TokenForgeScopedToken @options).Request.ResourceId|Should -Be $arm
 }
}
