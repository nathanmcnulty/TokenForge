BeforeAll {
 Import-Module "$PSScriptRoot/../src/TokenForge/TokenForge.psd1" -Force
 $modulePath=(Resolve-Path "$PSScriptRoot/../src/TokenForge/TokenForge.psd1").Path
}
Describe 'Shared timestamp projection policy' {
 It 'preserves parsed UTC DateTime Kind and explicit offsets' {
  $json='{"Date":"2026-10-11T01:16:41Z"}'|ConvertFrom-Json -AsHashtable
  [TokenForge.Core.V0240.TimestampPolicy]::Parse($json.Date)|Should -Be ([DateTimeOffset]'2026-10-11T01:16:41Z')
  [TokenForge.Core.V0240.TimestampPolicy]::Parse([DateTimeOffset]'2026-10-11T09:16:41+08:00')|Should -Be ([DateTimeOffset]'2026-10-11T01:16:41Z')
 }
 It 'preserves UTC projections in nonthrowing export validation' {
  $json='{"Date":"2026-10-11T01:16:41Z"}'|ConvertFrom-Json -AsHashtable
  $value=[DateTimeOffset]::MinValue
  [TokenForge.Core.V0240.TimestampPolicy]::TryParse($json.Date,[ref]$value)|Should -BeTrue
  $value|Should -Be ([DateTimeOffset]'2026-10-11T01:16:41Z')
  [TokenForge.Core.V0240.TimestampPolicy]::TryParse('synthetic-secret',[ref]$value)|Should -BeFalse
 }
 It 'preserves current-culture legacy string parsing' {
  $old=[Globalization.CultureInfo]::CurrentCulture
  try{
   [Globalization.CultureInfo]::CurrentCulture=[Globalization.CultureInfo]::GetCultureInfo('fr-FR')
   $value=[TokenForge.Core.V0240.TimestampPolicy]::Parse('17/10/2026 12:34:56')
   $value.Day|Should -Be 17;$value.Month|Should -Be 10;$value.Year|Should -Be 2026
  }finally{[Globalization.CultureInfo]::CurrentCulture=$old}
 }
 It 'sanitizes invalid timestamps without retaining an inner exception' {
  try{[TokenForge.Core.V0240.TimestampPolicy]::Parse('synthetic-secret');throw 'Unexpected acceptance.'}catch{
   $_.Exception.ToString()|Should -Not -Match synthetic-secret
   $_.Exception.InnerException.InnerException|Should -BeNullOrEmpty
  }
  {[TokenForge.Core.V0240.TimestampPolicy]::Parse($null)}|Should -Throw '*Details suppressed*'
 }
 It 'refuses expired Z-serialized vault sessions in both non-UTC directions' -Skip:($IsWindows) {
  $child=Join-Path $TestDrive 'vault-timezone.ps1'
  @'
param([string]$Module,[string]$Root)
$ErrorActionPreference='Stop'
Import-Module $Module -Force
$path=Join-Path $Root session.tfvault
$password=ConvertTo-SecureString synthetic-regression-password -AsPlainText -Force
$saved=$null
try {
 $null=New-TokenForgeVault $path $password
 & (Get-Module TokenForge) {
  param($Path,$Password)
  Invoke-TokenForgeVaultTransaction $Path $Password -Mode Update -Update {
   param($document)
   $now=[DateTimeOffset]::UtcNow;$id='c'*64
   $document.Sessions.test=@{
    TenantFingerprint='a'*64;PrincipalFingerprint='b'*64;Revision=[guid]::NewGuid().ToString()
    CreatedAt=$now.AddHours(-2).ToString('o');LastConfirmedAt=$now.AddHours(-1).ToString('o');RetainUntil=$now.AddMinutes(-5).UtcDateTime.ToString('o')
    Cookie='synthetic-cookie';CookieName='ESTSAUTH';Tokens=@{
     $id=@{Id=$id;ClientId='11111111-1111-1111-1111-111111111111';ResourceId='00000003-0000-0000-c000-000000000000';Tenant='aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa';Audience='00000003-0000-0000-c000-000000000000';Scopes=@('User.Read');IssuedScopes=@('User.Read');AdditionalScopeCount=0;RedirectUri='https://login.microsoftonline.com/common/oauth2/nativeclient';Spa=$false;OfflineAccess=$true;Protocol='OAuth2V2Pkce';AcquiredAt=$now.AddHours(-1).ToString('o');ExpiresAt=$now.AddMinutes(20).ToString('o');AccessToken='synthetic-access';RefreshToken='synthetic-refresh';ConsentEvidence='SyntheticOnly'}
    }
   }
  }
 } $path $password
 $view=Get-TokenForgeVault $path $password
 $retrieved=$false
 try{$saved=Get-TokenForgeVaultToken $path $password -SessionName test -TokenId ('c'*64) -RefreshOnly;$retrieved=$true}catch{}
 [pscustomobject]@{Expired=$view.Sessions[0].RetentionExpired;ReturnedCredential=$retrieved}|ConvertTo-Json -Compress
}finally{
 if($saved){if($saved.AccessToken){$saved.AccessToken.Dispose()};if($saved.RefreshToken){$saved.RefreshToken.Dispose()}}
 $password.Dispose();if(Test-Path $Root){Remove-Item $Root -Recurse -Force}
}
'@|Set-Content $child
  foreach($zone in @('America/Anchorage','Asia/Tokyo')){
   $start=[Diagnostics.ProcessStartInfo]::new((Get-Process -Id $PID).Path)
   $start.UseShellExecute=$false;$start.RedirectStandardOutput=$true;$start.RedirectStandardError=$true;$start.Environment['TZ']=$zone
   $childRoot=Join-Path $TestDrive ([guid]::NewGuid().ToString('N'))
   if($IsMacOS){$childRoot=$childRoot -replace '^/var/','/private/var/'}
   foreach($arg in @('-NoProfile','-File',$child,$modulePath,$childRoot)){$start.ArgumentList.Add($arg)}
   $process=[Diagnostics.Process]::Start($start)
   try{
    $stdout=$process.StandardOutput.ReadToEndAsync();$stderr=$process.StandardError.ReadToEndAsync()
    if(-not $process.WaitForExit(30000)){$process.Kill($true);throw 'Timezone vault fixture timed out.'}
    $process.ExitCode|Should -Be 0 -Because $stderr.GetAwaiter().GetResult()
    $view=$stdout.GetAwaiter().GetResult()|ConvertFrom-Json
    $view.Expired|Should -BeTrue -Because $zone
    $view.ReturnedCredential|Should -BeFalse -Because $zone
   }finally{$process.Dispose()}
  }
 }
}
