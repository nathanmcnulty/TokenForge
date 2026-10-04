BeforeAll {
 Import-Module "$PSScriptRoot/../src/TokenForge/TokenForge.psd1" -Force
 function New-VaultFixtureToken {
  param([string[]]$Scopes=@('User.Read'))
  $client='11111111-1111-1111-1111-111111111111';$graph='00000003-0000-0000-c000-000000000000'
  $payload=@{tid='aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa';oid='bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb';appid=$client;aud=$graph;scp=($Scopes -join ' ');exp=[DateTimeOffset]::UtcNow.AddHours(1).ToUnixTimeSeconds()}|ConvertTo-Json -Compress
  $encoded=[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($payload)).TrimEnd('=').Replace('+','-').Replace('/','_')
  $access=ConvertTo-SecureString "e30.$encoded.synthetic" -AsPlainText -Force
  [pscustomobject]@{AccessToken=$access;RefreshToken=(ConvertTo-SecureString synthetic-refresh-secret -AsPlainText -Force);TokenClaims=(Get-TokenForgeTokenClaims $access);ExpiresAt=[DateTimeOffset]::UtcNow.AddHours(1);Protocol='OAuth2V2Pkce';ConsentEvidence='SilentAuthorizationSucceededForThisRequest';ObservedAdditionalScopeCount=@($Scopes|Where-Object {$_ -ne 'User.Read'}).Count;Request=[pscustomobject]@{ClientId=$client;ResourceId=$graph;Tenant='aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa';Scopes=@('User.Read');OAuthScopes=@("$graph/User.Read",'offline_access');RedirectUri='https://login.microsoftonline.com/common/oauth2/nativeclient';Spa=$false}}
 }
 function Save-VaultFixture {
  param($Path,$Password,$Cookie,$Token,$Revision=$null,[switch]$Reuse)
  InModuleScope TokenForge -Parameters @{Path=$Path;Password=$Password;Cookie=$Cookie;Token=$Token;Revision=$Revision;Reuse=$Reuse} {
   Save-TokenForgeScopedCredential -Path $Path -Password $Password -SessionName test -Cookie $Cookie -CookieName ESTSAUTHPERSISTENT -Token $Token -RetentionHours 8 -ExpectedRevision $Revision -ReuseSession:$Reuse
  }
 }
}
Describe 'Encrypted session vault' {
 BeforeEach {
  $vaultRoot=if($IsMacOS){$TestDrive -replace '^/var/','/private/var/'}else{$TestDrive}
  $path=Join-Path $vaultRoot ([guid]::NewGuid().ToString()+'/session.tfvault')
  $password=ConvertTo-SecureString synthetic-unlock-passphrase -AsPlainText -Force
  $cookie=ConvertTo-SecureString synthetic-session-cookie -AsPlainText -Force
  $token=New-VaultFixtureToken
  $null=New-TokenForgeVault -Path $path -Password $password
 }
 AfterEach {$password.Dispose();$cookie.Dispose();$token.AccessToken.Dispose();$token.RefreshToken.Dispose()}
 It 'encrypts all credential/context records and lists only metadata' {
  $id=Save-VaultFixture $path $password $cookie $token
  $cipher=Get-Content $path -Raw
  $cipher|Should -Not -Match 'synthetic-session-cookie|synthetic-refresh-secret|User.Read|PrincipalFingerprint|AccessToken'
  $view=Get-TokenForgeVault -Path $path -Password $password
  $view.Sessions[0].CookieName|Should -Be ESTSAUTHPERSISTENT
  $view.Sessions[0].Tokens[0].Id|Should -Be $id
  ($view|ConvertTo-Json -Depth 12)|Should -Not -Match 'synthetic-session-cookie|synthetic-refresh-secret|AccessToken'
 }
 It 'retrieves caller-owned secure tokens with context and lifetime checks' {
  $id=Save-VaultFixture $path $password $cookie $token
  $saved=Get-TokenForgeVaultToken -Path $path -Password $password -SessionName test -TokenId $id -MaxAdditionalScopes 0
  try {$saved.AccessToken|Should -BeOfType securestring;$saved.RefreshToken|Should -BeOfType securestring;$saved.Request.ClientId|Should -Be $token.Request.ClientId;$saved.Evidence|Should -Be ExplicitSavedCredentialRetrievalNotNewIssuance}
  finally {$saved.AccessToken.Dispose();$saved.RefreshToken.Dispose()}
 }
 It 'rejects wrong passwords without changing the vault' {
  $before=(Get-FileHash $path).Hash;$wrong=ConvertTo-SecureString synthetic-wrong-passphrase -AsPlainText -Force
  try{{Get-TokenForgeVault -Path $path -Password $wrong}|Should -Throw '*Details suppressed*'}finally{$wrong.Dispose()}
  (Get-FileHash $path).Hash|Should -Be $before
 }
 It 'rejects corrupted authentication data and bounded envelope parameters' -TestCases @(@{Field='Tag'},@{Field='Ciphertext'},@{Field='Iterations'},@{Field='Version'}) {
  param($Field)
  $data=Get-Content $path -Raw|ConvertFrom-Json
  if($Field -in @('Tag','Ciphertext')){$bytes=[Convert]::FromBase64String($data.$Field);$bytes[0]=$bytes[0] -bxor 1;$data.$Field=[Convert]::ToBase64String($bytes)}else{$data.$Field=1+$data.$Field}
  [IO.File]::WriteAllText($path,($data|ConvertTo-Json -Compress))
  {Get-TokenForgeVault -Path $path -Password $password}|Should -Throw '*Details suppressed*'
 }
 It 'generates fresh encryption salt and nonce for every rewrite' {
  $before=Get-Content $path -Raw|ConvertFrom-Json
  $null=Save-VaultFixture $path $password $cookie $token
  $after=Get-Content $path -Raw|ConvertFrom-Json
  $after.Salt|Should -Not -Be $before.Salt;$after.Nonce|Should -Not -Be $before.Nonce
 }
 It 'does not overwrite an existing vault during initialization' {
  $before=(Get-FileHash $path).Hash
  {New-TokenForgeVault -Path $path -Password $password}|Should -Throw '*Details suppressed*'
  (Get-FileHash $path).Hash|Should -Be $before
 }
 It 'fails concurrent access without changing the original' {
  $before=(Get-FileHash $path).Hash;$lock=[IO.File]::Open("$path.lock",[IO.FileMode]::Open,[IO.FileAccess]::ReadWrite,[IO.FileShare]::None)
  try{{Get-TokenForgeVault -Path $path -Password $password}|Should -Throw '*Details suppressed*'}finally{$lock.Dispose()}
  (Get-FileHash $path).Hash|Should -Be $before
 }
 It 'preserves the original when a transaction fails and suppresses exception details' {
  $before=(Get-FileHash $path).Hash
  InModuleScope TokenForge -Parameters @{Path=$path;Password=$password} {
   {Invoke-TokenForgeVaultTransaction -Path $Path -Password $Password -Mode Update -Update {throw 'synthetic-secret-error'}}|Should -Throw '*Details suppressed*'
  }
  (Get-FileHash $path).Hash|Should -Be $before
  @(Get-ChildItem (Split-Path $path) -Filter '*.tmp').Count|Should -Be 0
 }
 It 'rejects unsafe Unix permissions and linked paths' -Skip:$IsWindows {
  [IO.File]::SetUnixFileMode($path,420)
  {Get-TokenForgeVault -Path $path -Password $password}|Should -Throw '*Details suppressed*'
  [IO.File]::SetUnixFileMode($path,384)
  $link=Join-Path (Split-Path $path) linked.tfvault
  $null=New-Item -ItemType SymbolicLink -Path $link -Target $path
  {Get-TokenForgeVault -Path $link -Password $password}|Should -Throw '*Details suppressed*'
 }
 It 'creates private files and directories from the outset on Unix' -Skip:$IsWindows {
  [int](Get-Item $path).UnixFileMode|Should -Be 384
  [int](Get-Item (Split-Path $path)).UnixFileMode|Should -Be 448
  [int](Get-Item "$path.lock").UnixFileMode|Should -Be 384
 }
 It 'creates protected current-user ACLs on Windows' -Skip:(-not $IsWindows) {
  (Get-Acl $path).AreAccessRulesProtected|Should -BeTrue
  (Get-Acl (Split-Path $path)).AreAccessRulesProtected|Should -BeTrue
 }
 It 'does not extend retention during cookie reuse' {
  $null=Save-VaultFixture $path $password $cookie $token
  $before=(Get-TokenForgeVault $path $password).Sessions[0].RetainUntil
  $revision=InModuleScope TokenForge -Parameters @{Path=$path;Password=$password} {(Invoke-TokenForgeVaultTransaction $Path $Password).Sessions['test'].Revision}
  $null=Save-VaultFixture $path $password $cookie $token $revision -Reuse
  (Get-TokenForgeVault $path $password).Sessions[0].RetainUntil|Should -Be $before
 }
 It 'rejects a stale revision after another writer or deletion' {
  $null=Save-VaultFixture $path $password $cookie $token
  $revision=InModuleScope TokenForge -Parameters @{Path=$path;Password=$password} {(Invoke-TokenForgeVaultTransaction $Path $Password).Sessions['test'].Revision}
  $null=Remove-TokenForgeVaultEntry -Path $path -Password $password -SessionName test
  {Save-VaultFixture $path $password $cookie $token $revision -Reuse}|Should -Throw '*Details suppressed*'
  (Get-TokenForgeVault $path $password).Sessions.Count|Should -Be 0
 }
 It 'rejects expired retention and expired access, but permits explicit refresh-only retrieval' {
  $token.ExpiresAt=[DateTimeOffset]::UtcNow.AddMinutes(-1)
  $id=Save-VaultFixture $path $password $cookie $token
  {Get-TokenForgeVaultToken -Path $path -Password $password -SessionName test -TokenId $id}|Should -Throw '*expired*'
  $refresh=Get-TokenForgeVaultToken -Path $path -Password $password -SessionName test -TokenId $id -RefreshOnly
  try {$refresh.AccessToken|Should -BeNullOrEmpty;$refresh.RefreshToken|Should -BeOfType securestring}finally{$refresh.RefreshToken.Dispose()}
  InModuleScope TokenForge -Parameters @{Path=$path;Password=$password} {Invoke-TokenForgeVaultTransaction $Path $Password -Mode Update -Update {param($d)$d.Sessions['test'].RetainUntil=[DateTimeOffset]::UtcNow.AddMinutes(-1).ToString('o')}}
  {Get-TokenForgeVaultToken -Path $path -Password $password -SessionName test -TokenId $id -RefreshOnly}|Should -Throw '*retention*'
 }
 It 'drops an expired cookie when explicit browser authentication saves a fresh token' {
  $null=Save-VaultFixture $path $password $cookie $token
  InModuleScope TokenForge -Parameters @{Path=$path;Password=$password} {Invoke-TokenForgeVaultTransaction $Path $Password -Mode Update -Update {param($d)$d.Sessions['test'].RetainUntil=[DateTimeOffset]::UtcNow.AddMinutes(-1).ToString('o')}}
  $id=Save-VaultFixture $path $password $null $token
  $view=Get-TokenForgeVault $path $password
  $view.Sessions[0].HasCookie|Should -BeFalse;$view.Sessions[0].RetentionExpired|Should -BeFalse
  $saved=Get-TokenForgeVaultToken -Path $path -Password $password -SessionName test -TokenId $id
  $saved.AccessToken.Dispose();$saved.RefreshToken.Dispose()
 }
 It 'checks cached additional scope limits and namespace' {
  $token.AccessToken.Dispose();$token.RefreshToken.Dispose();$token=New-VaultFixtureToken -Scopes @('User.Read','Mail.Read')
  $id=Save-VaultFixture $path $password $cookie $token
  {Get-TokenForgeVaultToken -Path $path -Password $password -SessionName test -TokenId $id -MaxAdditionalScopes 0}|Should -Throw '*additional-scope*'
  InModuleScope TokenForge -Parameters @{Path=$path;Password=$password} {Invoke-TokenForgeVaultTransaction $Path $Password -Mode Update -Update {param($d)$d.Sessions['test'].PrincipalFingerprint='c'*64}}
  {Get-TokenForgeVaultToken -Path $path -Password $password -SessionName test -TokenId $id}|Should -Throw '*context or scope mismatch*'
 }
 It 'preserves multiple client resource scope entries and replaces only an exact match' {
  $first=Save-VaultFixture $path $password $cookie $token
  $token.Request.Scopes=@('User.Read','Mail.Read');$second=Save-VaultFixture $path $password $cookie $token
  $second|Should -Not -Be $first
  $null=Save-VaultFixture $path $password $cookie $token
  (Get-TokenForgeVault $path $password).Sessions[0].Tokens.Count|Should -Be 2
  $null=Remove-TokenForgeVaultEntry -Path $path -Password $password -SessionName test -TokenId $first
  (Get-TokenForgeVault $path $password).Sessions[0].Tokens.Count|Should -Be 1
 }
 It 'exports an offline metadata viewer without raw secrets and refuses overwrite' {
  $null=Save-VaultFixture $path $password $cookie $token
  $html=Join-Path $TestDrive view.html
  $null=Export-TokenForgeVaultView -Path $path -Password $password -OutputPath $html
  $content=Get-Content $html -Raw
  $content|Should -Not -Match 'synthetic-session-cookie|synthetic-refresh-secret|e30\.'
  $content|Should -Match "connect-src 'none'"
  $content|Should -Not -Match '@DATA@|@SCRIPT_HASH@|@STYLE_HASH@'
  {Export-TokenForgeVaultView -Path $path -Password $password -OutputPath $html}|Should -Throw '*never overwritten*'
 }
 It 'keeps hostile metadata inside the JSON string rather than creating HTML elements' {
  $token.TokenClaims.Audience='</script><img src=x onerror=alert(1)>'
  $null=Save-VaultFixture $path $password $cookie $token
  $html=Join-Path $TestDrive hostile.html
  $null=Export-TokenForgeVaultView $path $password -OutputPath $html
  $content=Get-Content $html -Raw
  $content|Should -Not -Match '<img'
  ([regex]::Matches($content,'<script>').Count)|Should -Be 1
  $content|Should -Match '\\u003c/script\\u003e'
 }
 It 'rejects an access token with unknown lifetime instead of assuming cached availability' {
  $token.ExpiresAt=$null;$token.TokenClaims.ExpiresAt=$null
  $id=Save-VaultFixture $path $password $cookie $token
  {Get-TokenForgeVaultToken $path $password -SessionName test -TokenId $id}|Should -Throw '*unknown expiry*'
 }
 It 'normalizes CRLF before calculating inline CSP hashes' {
  $template=(Get-Content "$PSScriptRoot/../src/TokenForge/viewer/vault.html" -Raw).Replace("`n","`r`n")
  Mock Get-Content -ModuleName TokenForge {return $template} -ParameterFilter {$LiteralPath -like '*viewer/vault.html'}
  $html=Join-Path $TestDrive normalized.html
  $null=Export-TokenForgeVaultView -Path $path -Password $password -OutputPath $html
  $content=Get-Content $html -Raw
  $content|Should -Not -Match "`r"
  $script=[regex]::Match($content,'(?s)<script>(.*?)</script>').Groups[1].Value
  $hash=[Convert]::ToBase64String([Security.Cryptography.SHA256]::HashData([Text.Encoding]::UTF8.GetBytes($script)))
  $content|Should -Match ([regex]::Escape("script-src 'sha256-$hash'"))
 }
}
