BeforeDiscovery {$nativeAvailable=[bool]($env:TOKENFORGE_TEST_NATIVE -and (Test-Path -LiteralPath $env:TOKENFORGE_TEST_NATIVE))}
Describe 'Native saved profile tokens without PowerShell on PATH' -Skip:(-not $nativeAvailable) {
 BeforeAll {
  Import-Module "$PSScriptRoot/../src/TokenForge/TokenForge.psd1" -Force
  function Invoke-NativeProfileToken([string[]]$Arguments,[int]$ExitCode=0,[string]$Secret='synthetic-native-passphrase'){
   $start=[Diagnostics.ProcessStartInfo]::new($env:TOKENFORGE_TEST_NATIVE)
   $start.UseShellExecute=$false;$start.RedirectStandardOutput=$true;$start.RedirectStandardError=$true;$start.RedirectStandardInput=$true
   $start.Environment['PATH']=Join-Path $root no-pwsh
   foreach($arg in @('token','get','--profile','lab','--root',$root)+$Arguments){$start.ArgumentList.Add($arg)}
   $process=[Diagnostics.Process]::Start($start)
   try{
    $process.StandardInput.Write($Secret);$process.StandardInput.Close()
    $output=$process.StandardOutput.ReadToEndAsync();$errors=$process.StandardError.ReadToEndAsync()
    if(-not $process.WaitForExit(20000)){$process.Kill($true);throw 'Native profile token command timed out.'}
    $process.ExitCode|Should -Be $ExitCode
    if($ExitCode){$output.GetAwaiter().GetResult()|Should -BeNullOrEmpty;$errors.GetAwaiter().GetResult()|Should -Not -Match 'synthetic-native|e30\.';return}
    $errors.GetAwaiter().GetResult()|Should -BeNullOrEmpty
    $text=$output.GetAwaiter().GetResult();$text|Should -Not -Match 'synthetic-native|e30\.|"AccessToken"|"RefreshToken"|"Cookie"'
    $text|ConvertFrom-Json
   }finally{$process.Dispose()}
  }
 }
 BeforeEach {
  $root=Join-Path $TestDrive ([guid]::NewGuid().ToString('N'));if($IsMacOS){$root=$root -replace '^/var/','/private/var/'}
  $tenant='aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa';$principal='bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb';$client='11111111-1111-1111-1111-111111111111';$graph='00000003-0000-0000-c000-000000000000'
  $p=New-TokenForgeProfile lab $tenant -Root $root -Storage Passphrase
  $configPath=Join-Path $root lab/profile.json;$config=Get-Content $configPath -Raw|ConvertFrom-Json -AsHashtable
  $hash={param($s)[Convert]::ToHexString([Security.Cryptography.SHA256]::HashData([Text.Encoding]::UTF8.GetBytes($s))).ToLowerInvariant()}
  $config.ExpectedTenantFingerprint=& $hash $tenant;$config.ExpectedPrincipalFingerprint=& $hash "$tenant/$principal"
  [IO.File]::WriteAllText($configPath,($config|ConvertTo-Json -Depth 6))
  $vault=Join-Path $root lab/session.tfvault;$password=ConvertTo-SecureString synthetic-native-passphrase -AsPlainText -Force
  $claims=@{tid=$tenant;oid=$principal;appid=$client;aud=$graph;scp='User.Read';exp=[DateTimeOffset]::UtcNow.AddHours(1).ToUnixTimeSeconds()}|ConvertTo-Json -Compress
  $jwt='e30.'+[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($claims)).TrimEnd('=').Replace('+','-').Replace('/','_')+'.synthetic-native'
  $null=New-TokenForgeVault $vault $password
  & (Get-Module TokenForge) {
   param($vault,$password,$config,$jwt,$client,$graph)
   Invoke-TokenForgeVaultTransaction $vault $password -Mode Update -Update {
    param($d)
    $now=[DateTimeOffset]::UtcNow;$id='c'*64
    $d.Sessions.lab=@{TenantFingerprint=$config.ExpectedTenantFingerprint;PrincipalFingerprint=$config.ExpectedPrincipalFingerprint;Revision=[guid]::NewGuid().ToString();CreatedAt=$now.ToString('o');LastConfirmedAt=$now.ToString('o');RetainUntil=$now.AddHours(1).ToString('o');Cookie=$null;CookieName=$null;Tokens=@{$id=@{Id=$id;ClientId=$client;ResourceId=$graph;Tenant=$config.Tenant;Audience=$graph;Scopes=@('User.Read');IssuedScopes=@('User.Read');AdditionalScopeCount=0;RedirectUri='http://localhost/';Spa=$false;OfflineAccess=$true;Protocol='OAuth2V2Pkce';AcquiredAt=$now.ToString('o');ExpiresAt=$now.AddHours(1).ToString('o');AccessToken=$jwt;RefreshToken=$null;ConsentEvidence='SyntheticOnly'}}}
   }
  } $vault $password $config $jwt $client $graph
 }
 AfterEach {$password.Dispose()}
 It 'returns cached metadata without evidence files, network, or PowerShell' {
  $before=(Get-FileHash $vault).Hash
  $result=Invoke-NativeProfileToken @('--scope','User.Read','--stdin','--json')
  $result.Evidence|Should -Be CachedVerifiedContextNotNewIssuance;$result.ClientId|Should -Be $client;$result.IssuedScopes|Should -Be @('User.Read');$result.CredentialOutput|Should -BeFalse
  (Get-FileHash $vault).Hash|Should -Be $before
  Test-Path (Join-Path $p.StatePath inventory.json)|Should -BeFalse;Test-Path (Join-Path $p.StatePath scopes.sqlite)|Should -BeFalse
 }
 It 'fails missing-cookie fresh acquisition without creating evidence or changing the vault' {
  $before=(Get-FileHash $vault).Hash
  Invoke-NativeProfileToken @('--scope','Mail.Read','--stdin') 1
  (Get-FileHash $vault).Hash|Should -Be $before
  Test-Path (Join-Path $p.StatePath inventory.json)|Should -BeFalse
 }
 It 'refuses an incorrect passphrase without changing ciphertext' {
  $before=(Get-FileHash $vault).Hash
  Invoke-NativeProfileToken @('--scope','User.Read','--stdin') 1 'synthetic-native-wrong-password'
  (Get-FileHash $vault).Hash|Should -Be $before
 }
 It 'refuses missing and truncated SQLite stores through the PowerShell checkpoint bridge' {
  $sqlite=Join-Path $p.StatePath scopes.sqlite
  $write={& (Get-Module TokenForge) {param($path,$exe) $doc=New-TokenForgeScopeDatabase;Invoke-TokenForgeNativeEvidence $path update -Document $doc -Domain evidence -NativeExecutablePath $exe -RequireExisting} $sqlite $env:TOKENFORGE_TEST_NATIVE}
  $write|Should -Throw
  Test-Path $sqlite|Should -BeFalse
  [IO.File]::WriteAllText($sqlite,'');if(-not $IsWindows){[IO.File]::SetUnixFileMode($sqlite,[IO.UnixFileMode]384)}
  $write|Should -Throw
  (Get-Item $sqlite).Length|Should -Be 0
 }
 It 'rejects invalid or duplicate requests and off-resource API URLs' {
  $before=(Get-FileHash $vault).Hash
  foreach($arguments in @(
   @('--scope','.default','--stdin'),@('--scope','User.Read','--scope','Mail.Read','--stdin'),
   @('--scope','User.Read','--stdin','--api-uri','https://example.test/'),
   @('--scope','User.Read','--stdin','--resource','graph','--resource-id',$graph),
   @('--scope','User.Read','--stdin','--max-candidates','101')
  )){Invoke-NativeProfileToken $arguments 1}
  (Get-FileHash $vault).Hash|Should -Be $before
 }
}
