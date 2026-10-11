BeforeAll {
 Import-Module "$PSScriptRoot/../src/TokenForge/TokenForge.psd1" -Force
 function New-ProfileTestToken {
  param([string]$Client='038ddad9-5bbe-4f64-b0cd-12434d1e633b',[string]$ObjectId='bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb',[string[]]$Scopes=@('User.Read'),[int]$Minutes=60)
  $json=@{tid='aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa';oid=$ObjectId;appid=$Client;aud='00000003-0000-0000-c000-000000000000';scp=($Scopes -join ' ');exp=[DateTimeOffset]::UtcNow.AddMinutes($Minutes).ToUnixTimeSeconds()}|ConvertTo-Json -Compress
  $encoded=[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($json)).TrimEnd('=').Replace('+','-').Replace('/','_')
  $secret=ConvertTo-SecureString "e30.$encoded.synthetic" -AsPlainText -Force
  [pscustomobject]@{AccessToken=$secret;RefreshToken=(ConvertTo-SecureString synthetic-refresh -AsPlainText -Force);TokenClaims=(Get-TokenForgeTokenClaims $secret);AdditionalScopes=@();ExpiresAt=[DateTimeOffset]::UtcNow.AddMinutes($Minutes);ClientId=$Client;ResourceId='00000003-0000-0000-c000-000000000000';Protocol='OAuth2V2Pkce'}
 }
}
Describe 'Named profile sessions and managed tokens' {
 BeforeEach {
  $root=if($IsMacOS){($TestDrive -replace '^/var/','/private/var/')+'/profiles'}else{"$TestDrive/profiles"}
  if(Test-Path $root){Remove-Item $root -Recurse -Force}
  $profile=New-TokenForgeProfile -Name lab -Tenant example.test -Root $root
  $loginToken=New-ProfileTestToken
  $apps=foreach($id in @($profile.BootstrapClientId,'00000003-0000-0000-c000-000000000000')){[pscustomobject]@{AppId=$id;Name='Synthetic';PublishedGrants=$(if($id -eq $profile.BootstrapClientId){@([pscustomobject]@{ResourceId='00000003-0000-0000-c000-000000000000';Scopes=@('User.Read','Internal.Read','user.read')})}else{@()});PublicClient=$true;Foci=$false;PreferredRedirectUri='https://login.microsoftonline.com/common/oauth2/nativeclient';Registration='Present';Ownership='VerifiedMicrosoftOwner';AccountEnabled=$true;RedirectUris=@('https://login.microsoftonline.com/common/oauth2/nativeclient','http://localhost');IdentifierUris=@('https://graph.microsoft.com');DelegatedScopeDefinitions=@([pscustomobject]@{Enabled=$true;Value='User.Read'})}}
  @{DiscoveryCatalogHash=('d'*64);CapturedAt=[DateTimeOffset]::UtcNow.ToString('o');TenantFingerprint=$loginToken.TokenClaims.TenantFingerprint;Applications=@($apps)}|ConvertTo-Json -Depth 6|Set-Content "$($profile.StatePath)/inventory.json"
  if(-not $IsWindows){[IO.File]::SetUnixFileMode("$($profile.StatePath)/inventory.json",[IO.UnixFileMode]384)}
  $cookie=ConvertTo-SecureString synthetic-cookie -AsPlainText -Force
  $password=ConvertTo-SecureString synthetic-passphrase -AsPlainText -Force
  Mock Get-TokenForgeToken -ModuleName TokenForge {return $loginToken}
  Mock Get-TokenForgeAssessmentCoverage -ModuleName TokenForge {return [pscustomobject]@{CoversAll=$true}}
  Mock Invoke-TokenForgeGraph -ModuleName TokenForge {return @{id='bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb'}}
 }
 AfterEach {Remove-Module TokenForge;Import-Module "$PSScriptRoot/../src/TokenForge/TokenForge.psd1" -Force}
 It 'stores no secrets in a profile and starts logged out' {
  (Get-TokenForgeProfileStatus lab -Root $root).SessionState|Should -Be LoginRequired
  $raw=Get-Content "$root/lab/profile.json" -Raw
  $raw|Should -Not -Match 'synthetic|AccessToken|RefreshToken|Cookie'
  (Get-TokenForgeProfile lab -Root $root).MaxAdditionalScopes|Should -Be 0
 }
 It 'rejects unknown injected configuration fields' {
  $p=Get-Content "$root/lab/profile.json" -Raw|ConvertFrom-Json -AsHashtable;$p.Cookie='synthetic';$p|ConvertTo-Json|Set-Content "$root/lab/profile.json"
  {Get-TokenForgeProfile lab -Root $root}|Should -Throw '*cannot be read*'
 }
 It 'confirms account and canonical tenant without disposing caller credentials' {
  $result=Connect-TokenForgeProfile lab -Root $root -EstsAuth $cookie
  $result.Evidence|Should -Be ProfileLoginGraphIdentityConfirmed
  (Get-TokenForgeProfile lab -Root $root).Tenant|Should -Be aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
  (Get-TokenForgeProfileStatus lab -Root $root).SessionState|Should -Be Available
  $cookie.Length|Should -BeGreaterThan 0
  {[Net.NetworkCredential]::new('', $loginToken.AccessToken).Password}|Should -Throw
 }
 It 'rejects bootstrap response additional scopes independently of JWT' {
  $loginToken.AdditionalScopes=@('Mail.Read')
  {Connect-TokenForgeProfile lab -Root $root -EstsAuth $cookie}|Should -Throw '*scope policy*'
 }
 It 'rejects Graph identity mismatch and remains logged out' {
  Mock Invoke-TokenForgeGraph -ModuleName TokenForge {return @{id='cccccccc-cccc-cccc-cccc-cccccccccccc'}}
  {Connect-TokenForgeProfile lab -Root $root -EstsAuth $cookie}|Should -Throw '*identity*'
  (Get-TokenForgeProfileStatus lab -Root $root).SessionState|Should -Be LoginRequired
 }
 It 'rejects insufficient token lifetime' {
  $loginToken=New-ProfileTestToken -Minutes 1
  {Connect-TokenForgeProfile lab -Root $root -EstsAuth $cookie}|Should -Throw '*lifetime*'
 }
 It 'removes the local session while preserving profile identity binding' {
  $null=Connect-TokenForgeProfile lab -Root $root -EstsAuth $cookie
  $null=Disconnect-TokenForgeProfile lab -Root $root
  (Get-TokenForgeProfileStatus lab -Root $root).SessionState|Should -Be LoginRequired
  (Get-TokenForgeProfile lab -Root $root).ExpectedPrincipalFingerprint|Should -Not -BeNullOrEmpty
 }
 It 'acquires once then returns an independently owned cache copy and reruns API checks' {
  $null=Connect-TokenForgeProfile lab -Root $root -EstsAuth $cookie
  $issued=New-ProfileTestToken
  $issued|Add-Member Request ([pscustomobject]@{ClientId=$profile.BootstrapClientId;ResourceId=$issued.ResourceId;Tenant='aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa';Scopes=@('User.Read');OAuthScopes=@('User.Read','offline_access');RedirectUri='https://login.microsoftonline.com/common/oauth2/nativeclient';Spa=$false;Protocol='OAuth2V2Pkce'})
  Mock Get-TokenForgeScopedToken -ModuleName TokenForge {return $issued}
  Mock Test-TokenForgeTokenAccess -ModuleName TokenForge {return [pscustomobject]@{Status=403;Accepted=$false}}
  $first=Get-TokenForgeProfileToken lab -Root $root -Scope User.Read -ApiUri https://graph.microsoft.com/v1.0/me
  $first.AccessToken.Dispose();$first.RefreshToken.Dispose()
  $second=Get-TokenForgeProfileToken lab -Root $root -Scope User.Read -ApiUri https://graph.microsoft.com/v1.0/me
  $second.Evidence|Should -Be CachedVerifiedContextNotNewIssuance
  $second.ApiCheck.Status|Should -Be 403
  $second.AccessToken.Length|Should -BeGreaterThan 0
  Should -Invoke Get-TokenForgeScopedToken -ModuleName TokenForge -Times 1 -Exactly
  Should -Invoke Test-TokenForgeTokenAccess -ModuleName TokenForge -Times 2 -Exactly
  $second.Request.Scopes=@('Mail.Read')
  $third=Get-TokenForgeProfileToken lab -Root $root -Scope User.Read
  $third.Request.Scopes|Should -Be @('User.Read')
  foreach($t in @($second,$third)){$t.AccessToken.Dispose();$t.RefreshToken.Dispose()}
 }
 It 'renewal preserves retention and same-client binding, including an omitted rotated refresh token' {
  $null=Connect-TokenForgeProfile lab -Root $root -EstsAuth $cookie
  $expired=New-ProfileTestToken -Minutes -10
  $expired|Add-Member Request ([pscustomobject]@{ClientId=$profile.BootstrapClientId;ResourceId=$expired.ResourceId;Tenant='aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa';Scopes=@('User.Read');OAuthScopes=@('User.Read','offline_access');RedirectUri='https://login.microsoftonline.com/common/oauth2/nativeclient';Spa=$false;Protocol='OAuth2V2Pkce'})
  $before=Get-TokenForgeProfileStatus lab -Root $root
  & (Get-Module TokenForge) {param($expired,$root) $r=Read-TokenForgeProfile lab $root;$key=Get-TokenForgeFingerprint ($expired.ResourceId+'|User.Read');$script:ProfileContexts[$r.ContextKey].Tokens[$key]=$expired} $expired $root
  $renewed=New-ProfileTestToken;$renewed.RefreshToken.Dispose();$renewed.RefreshToken=$null
  Mock Get-TokenForgeToken -ModuleName TokenForge {param($Request,$RefreshToken) $Request.ClientId|Should -Be '038ddad9-5bbe-4f64-b0cd-12434d1e633b';$RefreshToken.Length|Should -BeGreaterThan 0;return $renewed}
  $result=Get-TokenForgeProfileToken lab -Root $root -Scope User.Read
  $result.Evidence|Should -Be SameClientRefreshMatchedIssuedContext
  $result.RefreshToken.Length|Should -BeGreaterThan 0
  (Get-TokenForgeProfileStatus lab -Root $root).RetainUntil|Should -Be $before.RetainUntil
  $result.AccessToken.Dispose();$result.RefreshToken.Dispose()
 }
 It 'uses encrypted persistence without plaintext session credentials in process context' {
  Remove-Item "$root/lab/profile.json"
  $profile=New-TokenForgeProfile lab example.test -Root $root -Storage Passphrase -StatePath $profile.StatePath
  $null=Connect-TokenForgeProfile lab -Root $root -EstsAuth $cookie -VaultPassword $password
  $hasPlaintext=& (Get-Module TokenForge) {param($root) $r=Read-TokenForgeProfile lab $root;$c=$script:ProfileContexts[$r.ContextKey];$c.Session.Contains('Cookie')} $root
  $hasPlaintext|Should -BeFalse
  (Get-TokenForgeVault "$root/lab/session.tfvault" $password).Sessions[0].HasCookie|Should -BeTrue
 }
 It 'rejects invalid API destinations before token calls' {
  $null=Connect-TokenForgeProfile lab -Root $root -EstsAuth $cookie
  {Get-TokenForgeProfileToken lab -Root $root -Scope User.Read -ApiUri https://example.test/me}|Should -Throw '*resource boundary*'
  Should -Invoke Get-TokenForgeToken -ModuleName TokenForge -Times 1 -Exactly
 }
 It 'rejects poisoned saved refresh authority before redemption' {
  $null=Connect-TokenForgeProfile lab -Root $root -EstsAuth $cookie
  $expired=New-ProfileTestToken -Minutes -10
  $expired|Add-Member Request ([pscustomobject]@{ClientId=$profile.BootstrapClientId;ResourceId=$expired.ResourceId;Tenant='cccccccc-cccc-cccc-cccc-cccccccccccc';Scopes=@('User.Read');OAuthScopes=@('User.Read','offline_access');RedirectUri='https://login.microsoftonline.com/common/oauth2/nativeclient';Spa=$false;Protocol='OAuth2V2Pkce'})
  & (Get-Module TokenForge) {param($expired,$root) $r=Read-TokenForgeProfile lab $root;$key=Get-TokenForgeFingerprint ($expired.ResourceId+'|User.Read');$script:ProfileContexts[$r.ContextKey].Tokens[$key]=$expired} $expired $root
  {Get-TokenForgeProfileToken lab -Root $root -Scope User.Read}|Should -Throw '*canonical profile authority*'
  Should -Invoke Get-TokenForgeToken -ModuleName TokenForge -Times 1 -Exactly
 }
 It 'rejects retention expiring during acquisition and disposes the result' {
  $null=Connect-TokenForgeProfile lab -Root $root -EstsAuth $cookie
  $issued=New-ProfileTestToken
  $issued|Add-Member Request ([pscustomobject]@{ClientId=$profile.BootstrapClientId;ResourceId=$issued.ResourceId;Tenant='aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa';Scopes=@('User.Read');OAuthScopes=@('User.Read','offline_access');RedirectUri='https://login.microsoftonline.com/common/oauth2/nativeclient';Spa=$false;Protocol='OAuth2V2Pkce'})
  $testContext=& (Get-Module TokenForge) {param($root) $r=Read-TokenForgeProfile lab $root;$script:ProfileContexts[$r.ContextKey]} $root
  Mock Get-TokenForgeScopedToken -ModuleName TokenForge { $testContext.Session.RetainUntil=[DateTimeOffset]::UtcNow.AddSeconds(-1).ToString('o');return $issued }
  {Get-TokenForgeProfileToken lab -Root $root -Scope User.Read}|Should -Throw '*Session changed*'
  {[Net.NetworkCredential]::new('', $issued.AccessToken).Password}|Should -Throw
 }
 It 'resolves missing observations using bounded explicit candidates' {
  $null=Connect-TokenForgeProfile lab -Root $root -EstsAuth $cookie
  Mock Get-TokenForgeAssessmentCoverage -ModuleName TokenForge {return @()}
  $issued=New-ProfileTestToken
  Mock Get-TokenForgeToken -ModuleName TokenForge {param($Request) $Request.Scopes|Should -Be @('User.Read');$Request.PSObject.Properties.Name|Should -Not -Contain Discovery;return $issued}
  $result=Get-TokenForgeProfileToken lab -Root $root -Scope User.Read
  $result.Evidence|Should -Be BoundedTargetedSilentExplicitScopeAcquisition
  (Get-TokenForgeScopeDatabase "$($profile.StatePath)/scopes.json").Observations.Count|Should -Be 1
  $result.AccessToken.Dispose();$result.RefreshToken.Dispose()
 }

 It 'rejects wrong-tenant cold inventory before candidate requests' {
  $null=Connect-TokenForgeProfile lab -Root $root -EstsAuth $cookie
  Mock Get-TokenForgeAssessmentCoverage -ModuleName TokenForge {return @()}
  $inventory=Get-Content "$($profile.StatePath)/inventory.json" -Raw|ConvertFrom-Json
  $inventory.TenantFingerprint='c'*64
  $inventory|ConvertTo-Json -Depth 6|Set-Content "$($profile.StatePath)/inventory.json"
  {Get-TokenForgeProfileToken lab -Root $root -Scope User.Read}|Should -Throw '*match the profile tenant*'
  Should -Invoke Get-TokenForgeToken -ModuleName TokenForge -Times 1 -Exactly
 }

 It 'does not resurrect a persisted session deleted during acquisition' {
  Remove-Item "$root/lab/profile.json"
  $profile=New-TokenForgeProfile lab example.test -Root $root -Storage Passphrase -StatePath $profile.StatePath
  $null=Connect-TokenForgeProfile lab -Root $root -EstsAuth $cookie -VaultPassword $password
  $issued=New-ProfileTestToken
  $issued|Add-Member Request ([pscustomobject]@{ClientId=$profile.BootstrapClientId;ResourceId=$issued.ResourceId;Tenant='aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa';Scopes=@('User.Read');OAuthScopes=@('User.Read','offline_access');RedirectUri='https://login.microsoftonline.com/common/oauth2/nativeclient';Spa=$false;Protocol='OAuth2V2Pkce'})
  Mock Get-TokenForgeToken -ModuleName TokenForge {$null=Remove-TokenForgeVaultEntry "$root/lab/session.tfvault" $password -SessionName lab;return $issued}
  {Get-TokenForgeProfileToken lab -Root $root -VaultPassword $password -Scope User.Read}|Should -Throw
  (Get-TokenForgeVault "$root/lab/session.tfvault" $password).Sessions.Count|Should -Be 0
  {[Net.NetworkCredential]::new('', $issued.AccessToken).Password}|Should -Throw
 }
 It 'terminates a successful cold request when checkpoint persistence fails' {
  $null=Connect-TokenForgeProfile lab -Root $root -EstsAuth $cookie
  Mock Get-TokenForgeAssessmentCoverage -ModuleName TokenForge {return @()}
  $issued=New-ProfileTestToken
  Mock Get-TokenForgeToken -ModuleName TokenForge {return $issued}
  Mock Add-TokenForgeScopeObservation -ModuleName TokenForge {throw 'synthetic disk failure'}
  {Get-TokenForgeProfileToken lab -Root $root -Scope User.Read}|Should -Throw '*checkpoint could not be saved*'
  Should -Invoke Get-TokenForgeToken -ModuleName TokenForge -Times 2 -Exactly
  {[Net.NetworkCredential]::new('', $issued.AccessToken).Password}|Should -Throw
 }

 It 'explicit login clears stale persisted token credentials for renewal recovery' {
  Remove-Item "$root/lab/profile.json"
  $profile=New-TokenForgeProfile lab example.test -Root $root -Storage Passphrase -StatePath $profile.StatePath
  $null=Connect-TokenForgeProfile lab -Root $root -EstsAuth $cookie -VaultPassword $password
  & (Get-Module TokenForge) {param($root,$password) Invoke-TokenForgeVaultTransaction "$root/lab/session.tfvault" $password -Mode Update -Update {param($vault) $id='c'*64;$now=[DateTimeOffset]::UtcNow;$vault.Sessions.lab.Tokens[$id]=@{Id=$id;ClientId='038ddad9-5bbe-4f64-b0cd-12434d1e633b';ResourceId='00000003-0000-0000-c000-000000000000';Tenant='example.test';Audience='00000003-0000-0000-c000-000000000000';Scopes=@('User.Read');IssuedScopes=@('User.Read');AdditionalScopeCount=0;RedirectUri='https://login.microsoftonline.com/common/oauth2/nativeclient';Spa=$false;OfflineAccess=$true;Protocol='OAuth2V2Pkce';AcquiredAt=$now.AddHours(-2).ToString('o');ExpiresAt=$now.AddHours(-1).ToString('o');AccessToken='synthetic-expired';RefreshToken='synthetic-revoked';ConsentEvidence='SyntheticOnly'}}} $root $password
  $loginToken=New-ProfileTestToken
  $null=Connect-TokenForgeProfile lab -Root $root -EstsAuth $cookie -VaultPassword $password
  (Get-TokenForgeVault "$root/lab/session.tfvault" $password).Sessions[0].Tokens.Count|Should -Be 0
 }

 It 'can validate hinted scopes absent from resource definitions using explicit issuance' {
  $null=Connect-TokenForgeProfile lab -Root $root -EstsAuth $cookie
  Mock Get-TokenForgeAssessmentCoverage -ModuleName TokenForge {return @()}
  $issued=New-ProfileTestToken -Scopes @('Internal.Read')
  Mock Get-TokenForgeToken -ModuleName TokenForge {param($Request) $Request.Scopes|Should -Be @('Internal.Read');$Request.Source|Should -Be 'PublishedOrConfiguredHintNotProvenConsent';return $issued}
  $result=Get-TokenForgeProfileToken lab -Root $root -Scope Internal.Read
  $result.TokenClaims.Scopes|Should -Be @('Internal.Read')
  $result.AccessToken.Dispose();$result.RefreshToken.Dispose()
 }

 It 'uses the native persisted lifecycle for fresh acquisition and cache reuse without rewriting' {
  Remove-Item "$root/lab/profile.json"
  $profile=New-TokenForgeProfile lab example.test -Root $root -Storage Passphrase -StatePath $profile.StatePath
  $null=Connect-TokenForgeProfile lab -Root $root -EstsAuth $cookie -VaultPassword $password
  $issued=New-ProfileTestToken
  $issued|Add-Member Request ([pscustomobject]@{ClientId=$profile.BootstrapClientId;ResourceId=$issued.ResourceId;Tenant='aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa';Scopes=@('User.Read');OAuthScopes=@("$($issued.ResourceId)/User.Read",'offline_access');RedirectUri='https://login.microsoftonline.com/common/oauth2/nativeclient';Spa=$false;Protocol='OAuth2V2Pkce'})
  Mock Get-TokenForgeToken -ModuleName TokenForge {return $issued}
  $first=Get-TokenForgeProfileToken lab -Root $root -Scope User.Read
  $first.Evidence|Should -Be BoundedTargetedSilentExplicitScopeAcquisition
  $before=(Get-FileHash "$root/lab/session.tfvault").Hash
  $first.AccessToken.Dispose();$first.RefreshToken.Dispose()
  $cached=Get-TokenForgeProfileToken lab -Root $root -Scope User.Read
  try{$cached.Evidence|Should -Be CachedVerifiedContextNotNewIssuance;$cached.AccessToken.Length|Should -BeGreaterThan 0}
  finally{$cached.AccessToken.Dispose();$cached.RefreshToken.Dispose()}
  (Get-FileHash "$root/lab/session.tfvault").Hash|Should -Be $before
  Should -Invoke Get-TokenForgeToken -ModuleName TokenForge -Times 2 -Exactly
  {[Net.NetworkCredential]::new('', $issued.AccessToken).Password}|Should -Throw
 }
 It 'uses native persisted renewal while preserving deadlines and an omitted replacement refresh token' {
  Remove-Item "$root/lab/profile.json"
  $profile=New-TokenForgeProfile lab example.test -Root $root -Storage Passphrase -StatePath $profile.StatePath
  $null=Connect-TokenForgeProfile lab -Root $root -EstsAuth $cookie -VaultPassword $password
  $issued=New-ProfileTestToken
  $issued|Add-Member Request ([pscustomobject]@{ClientId=$profile.BootstrapClientId;ResourceId=$issued.ResourceId;Tenant='aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa';Scopes=@('User.Read');OAuthScopes=@("$($issued.ResourceId)/User.Read",'offline_access');RedirectUri='https://login.microsoftonline.com/common/oauth2/nativeclient';Spa=$false;Protocol='OAuth2V2Pkce'})
  Mock Get-TokenForgeToken -ModuleName TokenForge {return $issued}
  $first=Get-TokenForgeProfileToken lab -Root $root -Scope User.Read
  $first.AccessToken.Dispose();$first.RefreshToken.Dispose()
  $before=(Get-TokenForgeVault "$root/lab/session.tfvault" $password).Sessions[0]
  & (Get-Module TokenForge) {param($root,$password) Invoke-TokenForgeVaultTransaction "$root/lab/session.tfvault" $password -Mode Update -Update {param($vault) foreach($entry in $vault.Sessions.lab.Tokens.Values){$entry.ExpiresAt=[DateTimeOffset]::UtcNow.AddMinutes(-1).ToString('o')}}} $root $password
  $replacement=New-ProfileTestToken;$replacement.RefreshToken.Dispose();$replacement.RefreshToken=$null
  Mock Get-TokenForgeToken -ModuleName TokenForge {param($Request,$RefreshToken) $Request.ClientId|Should -Be $profile.BootstrapClientId;$RefreshToken.Length|Should -BeGreaterThan 0;return $replacement}
  $renewed=Get-TokenForgeProfileToken lab -Root $root -Scope User.Read
  try{$renewed.Evidence|Should -Be SameClientRefreshMatchedIssuedContext;$renewed.RefreshToken.Length|Should -BeGreaterThan 0}
  finally{$renewed.AccessToken.Dispose();$renewed.RefreshToken.Dispose()}
  $after=(Get-TokenForgeVault "$root/lab/session.tfvault" $password).Sessions[0]
  $after.RetainUntil|Should -Be $before.RetainUntil;$after.LastConfirmedAt|Should -Be $before.LastConfirmedAt
  $after.Tokens.Count|Should -Be 1;$after.Tokens[0].HasRefreshToken|Should -BeTrue
  Should -Invoke Get-TokenForgeToken -ModuleName TokenForge -Times 3 -Exactly
 }

 It 'runs persisted warm acquisition through shared bootstrap and verifies Graph identity' {
  Remove-Item "$root/lab/profile.json"
  $profile=New-TokenForgeProfile lab example.test -Root $root -Storage Passphrase -StatePath $profile.StatePath
  $null=Connect-TokenForgeProfile lab -Root $root -EstsAuth $cookie -VaultPassword $password
  $bound=Get-TokenForgeProfile lab -Root $root
  $databasePath=Join-Path $profile.StatePath scopes.json
  $db=Get-TokenForgeScopeDatabase $databasePath
  $observation=[pscustomobject]@{ClientId=$profile.BootstrapClientId;ResourceId='00000003-0000-0000-c000-000000000000';Outcome='Succeeded';TenantFingerprint=$bound.ExpectedTenantFingerprint;PrincipalFingerprint=$bound.ExpectedPrincipalFingerprint;ObservedAt=[DateTimeOffset]::UtcNow.ToString('o');ScpScopes=@('User.Read');RequestedScopes=@('User.Read');NamespaceVerification='Matched';RequestVerification='Matched';Protocol='OAuth2V2Pkce'}
  $null=Add-TokenForgeScopeObservation $db $observation -Path $databasePath
  Mock Get-TokenForgeToken -ModuleName TokenForge {New-ProfileTestToken}
  $token=Get-TokenForgeProfileToken lab -Root $root -Scope User.Read
  try{$token.Evidence|Should -Be SilentExplicitScopeAcquisition}finally{$token.AccessToken.Dispose();$token.RefreshToken.Dispose()}
  Should -Invoke Get-TokenForgeToken -ModuleName TokenForge -Times 3 -Exactly
  Should -Invoke Invoke-TokenForgeGraph -ModuleName TokenForge -Times 2 -Exactly
 }
 It 'preserves metadata added during persisted cold acquisition' {
  Remove-Item "$root/lab/profile.json"
  $profile=New-TokenForgeProfile lab example.test -Root $root -Storage Passphrase -StatePath $profile.StatePath
  $null=Connect-TokenForgeProfile lab -Root $root -EstsAuth $cookie -VaultPassword $password
  $databasePath=Join-Path $profile.StatePath scopes.json;$bound=Get-TokenForgeProfile lab -Root $root
  Mock Get-TokenForgeToken -ModuleName TokenForge {
   $new=[pscustomobject]@{ClientId='11111111-1111-1111-1111-111111111111';ResourceId='00000003-0000-0000-c000-000000000000';Outcome='Failed';TenantFingerprint=$bound.ExpectedTenantFingerprint;PrincipalFingerprint=$bound.ExpectedPrincipalFingerprint;ObservedAt=[DateTimeOffset]::UtcNow.ToString('o')}
   $db=Get-TokenForgeScopeDatabase $databasePath;$null=Add-TokenForgeScopeObservation $db $new -Path $databasePath
   New-ProfileTestToken
  }
  $token=Get-TokenForgeProfileToken lab -Root $root -Scope User.Read
  try{$token.Evidence|Should -Be BoundedTargetedSilentExplicitScopeAcquisition}finally{$token.AccessToken.Dispose();$token.RefreshToken.Dispose()}
  $rows=(Get-TokenForgeScopeDatabase $databasePath).Observations
  $rows.Count|Should -Be 2;$rows[0].Outcome|Should -Be Failed;$rows[1].Outcome|Should -Be Succeeded
 }

 It 'preserves case-distinct profile scopes before cold request planning' {
  $null=Connect-TokenForgeProfile lab -Root $root -EstsAuth $cookie
  Mock Get-TokenForgeAssessmentCoverage -ModuleName TokenForge {return @()}
  $issued=New-ProfileTestToken -Scopes @('User.Read','user.read')
  Mock Get-TokenForgeToken -ModuleName TokenForge {return $issued}
  $result=Get-TokenForgeProfileToken lab -Root $root -Scope User.Read,user.read
  try{$result.Request.Scopes|Should -Be @('User.Read','user.read')}finally{$result.AccessToken.Dispose();$result.RefreshToken.Dispose()}
 }
}
Describe 'OS-protected profile boundaries' {
 BeforeEach {
  $root=if($IsMacOS){($TestDrive -replace '^/var/','/private/var/')+'/os-profiles'}else{"$TestDrive/os-profiles"}
  if(Test-Path $root){Remove-Item $root -Recurse -Force}
  $password=ConvertTo-SecureString synthetic-platform-key -AsPlainText -Force
 }
 AfterEach {Remove-Module TokenForge;Import-Module "$PSScriptRoot/../src/TokenForge/TokenForge.psd1" -Force}
 It 'fails closed on macOS until a signed helper exists' -Skip:(-not $IsMacOS) {
  {New-TokenForgeProfile lab example.test -Root $root -Storage OperatingSystem}|Should -Throw '*supported on Windows and Linux*'
 }
 It 'does not read the OS store from create/status/doctor' -Skip:$IsMacOS {
  Mock Open-TokenForgeProfilePlatformKey -ModuleName TokenForge {throw 'Must not unlock.'}
  $p=New-TokenForgeProfile lab example.test -Root $root -Storage OperatingSystem
  $p.SchemaVersion|Should -Be 2
  $p.KeyId|Should -Match '^[a-f0-9]{32}$'
  (Get-TokenForgeProfileStatus lab -Root $root).SessionState|Should -Be LoginRequired
  $null=Test-TokenForgeProfile lab -Root $root
  Should -Invoke Open-TokenForgeProfilePlatformKey -ModuleName TokenForge -Times 0
 }
 It 'rejects passphrases and injected/missing key IDs' -Skip:$IsMacOS {
  $p=New-TokenForgeProfile lab example.test -Root $root -Storage OperatingSystem
  {Get-TokenForgeProfileStatus lab -Root $root -VaultPassword $password}|Should -Throw '*do not accept*'
  {Connect-TokenForgeProfile lab -Root $root -VaultPassword $password}|Should -Throw '*do not accept*'
  $p=Get-Content "$root/lab/profile.json" -Raw|ConvertFrom-Json -AsHashtable
  $p.Remove('KeyId');$p|ConvertTo-Json|Set-Content "$root/lab/profile.json"
  {Get-TokenForgeProfile lab -Root $root}|Should -Throw '*cannot be read*'
 }
 It 'refuses new key creation when an encrypted vault exists' -Skip:$IsMacOS {
  $p=New-TokenForgeProfile lab example.test -Root $root -Storage OperatingSystem
  $null=New-TokenForgeVault "$root/lab/session.tfvault" $password
  Mock Open-TokenForgeProfilePlatformKey -ModuleName TokenForge {throw 'OS store locked or key missing.'}
  {Connect-TokenForgeProfile lab -Root $root}|Should -Throw '*locked or key missing*'
  (Get-TokenForgeVault "$root/lab/session.tfvault" $password).Sessions.Count|Should -Be 0
  Should -Invoke Open-TokenForgeProfilePlatformKey -ModuleName TokenForge -Times 1
 }
 It 'logout retains the OS key and forget reports a retryable deletion failure' -Skip:$IsMacOS {
  $p=New-TokenForgeProfile lab example.test -Root $root -Storage OperatingSystem
  $null=New-TokenForgeVault "$root/lab/session.tfvault" $password
  Mock Open-TokenForgeProfilePlatformKey -ModuleName TokenForge {return $password.Copy()}
  Mock Remove-TokenForgeProfilePlatformKey -ModuleName TokenForge {if(Test-Path "$root/lab/session.tfvault"){throw 'Deletion order wrong.'};throw 'Store unavailable.'}
  (Disconnect-TokenForgeProfile lab -Root $root).Removed|Should -BeTrue
  Should -Invoke Remove-TokenForgeProfilePlatformKey -ModuleName TokenForge -Times 0
  $result=Remove-TokenForgeProfileKey lab -Root $root
  $result.VaultRemoved|Should -BeTrue;$result.KeyRemoved|Should -BeFalse
  Test-Path "$root/lab/session.tfvault"|Should -BeFalse
  $result.NextStep|Should -Match 'retry'
  Mock Remove-TokenForgeProfilePlatformKey -ModuleName TokenForge {}
  (Remove-TokenForgeProfileKey lab -Root $root).KeyRemoved|Should -BeTrue
 }


}
