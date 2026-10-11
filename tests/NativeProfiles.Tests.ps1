BeforeDiscovery {
 $nativeAvailable=[bool]($env:TOKENFORGE_TEST_NATIVE -and (Test-Path -LiteralPath $env:TOKENFORGE_TEST_NATIVE -PathType Leaf))
}
Describe 'Native profile configuration interoperability' -Skip:(-not $nativeAvailable) {
 BeforeAll {
  Import-Module (Join-Path $PSScriptRoot '../src/TokenForge/TokenForge.psd1') -Force
  function Invoke-NativeProfile([string[]]$Arguments,[int]$ExitCode=0,[string]$InputSecret=$null) {
   $start=[Diagnostics.ProcessStartInfo]::new($env:TOKENFORGE_TEST_NATIVE)
   $start.UseShellExecute=$false;$start.RedirectStandardOutput=$true;$start.RedirectStandardError=$true;$start.RedirectStandardInput=$true
   $start.Environment['PATH']=Join-Path $root no-pwsh
   foreach($argument in $Arguments){$start.ArgumentList.Add($argument)}
   $process=[Diagnostics.Process]::Start($start)
   try {
    if($null -ne $InputSecret){$process.StandardInput.Write($InputSecret)};$process.StandardInput.Close()
    $output=$process.StandardOutput.ReadToEndAsync();$errors=$process.StandardError.ReadToEndAsync()
    if(-not $process.WaitForExit(20000)){$process.Kill($true);throw 'Native profile command timed out.'}
    $process.ExitCode|Should -Be $ExitCode
    if($ExitCode){$output.GetAwaiter().GetResult()|Should -BeNullOrEmpty;$errors.GetAwaiter().GetResult()|Should -Not -Match 'synthetic-private';return}
    $errors.GetAwaiter().GetResult()|Should -BeNullOrEmpty
    $output.GetAwaiter().GetResult()|ConvertFrom-Json
   }finally{$process.Dispose()}
  }
 }
 BeforeEach {
  $root=Join-Path $TestDrive ([guid]::NewGuid().ToString('N'))
  if($IsMacOS){$root=$root -replace '^/var/','/private/var/'}
 }
 It 'creates and shows the default profile without PowerShell on PATH' {
  $created=Invoke-NativeProfile @('profile','create','--tenant','example.onmicrosoft.com','--root',$root)
  $created.Name|Should -Be default;$created.Storage|Should -Be Passphrase
  $shown=Invoke-NativeProfile @('profile','show','--root',$root)
  $shown.Revision|Should -Be $created.Revision
  (Get-TokenForgeProfile -Name default -Root $root).Revision|Should -Be $created.Revision
  @(Get-ChildItem (Join-Path $root default) -File -Force).Count|Should -Be 2
 }
 It 'reads a PowerShell-created profile and preserves its memory default' {
  $created=New-TokenForgeProfile -Name lab -Tenant example.onmicrosoft.com -Root $root
  $shown=Invoke-NativeProfile @('profile','show','--profile','lab','--root',$root,'--json')
  $shown.Storage|Should -Be Memory;$shown.Revision|Should -Be $created.Revision
  $shown.StatePath|Should -Be $created.StatePath
 }
 It 'refuses overwrite without changing existing configuration' {
  $created=Invoke-NativeProfile @('profile','create','--tenant','example.onmicrosoft.com','--root',$root)
  Invoke-NativeProfile @('profile','create','--tenant','other.onmicrosoft.com','--root',$root) 1
  (Invoke-NativeProfile @('profile','show','--root',$root)).Revision|Should -Be $created.Revision
 }
 It 'rejects duplicate options and invalid policy before creating directories' {
  Invoke-NativeProfile @('profile','create','--tenant','example.onmicrosoft.com','--root',$root,'--root',$root) 1
  Invoke-NativeProfile @('profile','create','--tenant','example.onmicrosoft.com','--root',$root,'--max-age-hours','0') 1
  Invoke-NativeProfile @('profile','create','--tenant','example.onmicrosoft.com','--root',$root,'--profile','') 1
  Test-Path $root|Should -BeFalse
 }
 It 'does not create missing directories when showing a profile' {
  Invoke-NativeProfile @('profile','show','--root',$root) 1
  Test-Path $root|Should -BeFalse
 }
 It 'refuses forgetting a non-OS profile without changing configuration' {
  $created=Invoke-NativeProfile @('profile','create','--tenant','example.onmicrosoft.com','--root',$root)
  Invoke-NativeProfile @('profile','forget-key','--root',$root) 1
  (Invoke-NativeProfile @('profile','show','--root',$root)).Revision|Should -Be $created.Revision
 }
 It 'honors both operation and vault locks before removing ciphertext' -Skip:$IsMacOS {
  $created=Invoke-NativeProfile @('profile','create','--tenant','example.onmicrosoft.com','--root',$root,'--storage','OperatingSystem')
  $vault=Join-Path $root 'default/session.tfvault'
  $password=ConvertTo-SecureString synthetic-unlock-passphrase -AsPlainText -Force
  try{$null=New-TokenForgeVault $vault $password}finally{$password.Dispose()}
  $before=(Get-FileHash $vault).Hash
  foreach($leaf in @('.operation.lock','session.tfvault.lock')){
   $lock=[IO.FileStream]::new((Join-Path $root "default/$leaf"),[IO.FileMode]::Open,[IO.FileAccess]::ReadWrite,[IO.FileShare]::None)
   try{Invoke-NativeProfile @('profile','forget-key','--root',$root) 1}finally{$lock.Dispose()}
   (Get-FileHash $vault).Hash|Should -Be $before
  }
 }
 It 'refuses a linked vault before accessing the OS store' -Skip:($IsWindows -or $IsMacOS) {
  $created=Invoke-NativeProfile @('profile','create','--tenant','example.onmicrosoft.com','--root',$root,'--storage','OperatingSystem')
  $target=Join-Path $root target.tfvault
  $password=ConvertTo-SecureString synthetic-unlock-passphrase -AsPlainText -Force
  try{$null=New-TokenForgeVault $target $password}finally{$password.Dispose()}
  $before=(Get-FileHash $target).Hash
  $null=New-Item -ItemType SymbolicLink -Path (Join-Path $root 'default/session.tfvault') -Target $target
  Invoke-NativeProfile @('profile','forget-key','--root',$root) 1
  (Get-FileHash $target).Hash|Should -Be $before
 }
 It 'preserves moved OS-profile ciphertext on an unsupported platform' -Skip:(-not $IsMacOS) {
  $created=Invoke-NativeProfile @('profile','create','--tenant','example.onmicrosoft.com','--root',$root)
  $path=Join-Path $root 'default/profile.json';$profile=Get-Content $path -Raw|ConvertFrom-Json
  $profile.Storage='OperatingSystem';$profile.SchemaVersion=2;$profile|Add-Member KeyId ([guid]::NewGuid().ToString('N'))
  $profile|ConvertTo-Json|Set-Content $path
  $vault=Join-Path $root 'default/session.tfvault';$password=ConvertTo-SecureString synthetic-unlock-passphrase -AsPlainText -Force
  try{$null=New-TokenForgeVault $vault $password}finally{$password.Dispose()}
  $before=(Get-FileHash $vault).Hash
  Invoke-NativeProfile @('profile','forget-key','--root',$root) 1
  (Get-FileHash $vault).Hash|Should -Be $before
 }
 It 'honors the PowerShell operation lock and reports explicit retention settings' {
  $created=New-TokenForgeProfile -Name lab -Tenant example.onmicrosoft.com -Root $root
  Remove-Item (Join-Path $root 'lab/profile.json')
  $lock=[IO.FileStream]::new((Join-Path $root 'lab/.operation.lock'),[IO.FileMode]::Open,[IO.FileAccess]::ReadWrite,[IO.FileShare]::None)
  try{Invoke-NativeProfile @('profile','create','--profile','lab','--tenant','example.onmicrosoft.com','--root',$root) 1}finally{$lock.Dispose()}
  Test-Path (Join-Path $root 'lab/profile.json')|Should -BeFalse
  $other=Invoke-NativeProfile @('profile','create','--profile','other','--tenant','example.onmicrosoft.com','--root',$root,'--max-age-hours','168','--session-retention-hours','12')
  $other.MaxAgeHours|Should -Be 168;$other.SessionRetentionHours|Should -Be 12
 }
 It 'inspects a PowerShell-created vault natively with explicit stdin and no credential output' {
  $p=New-TokenForgeProfile lab example.test -Root $root -Storage Passphrase
  $path=Join-Path $root 'lab/profile.json';$p=Get-Content $path -Raw|ConvertFrom-Json
  $p.ExpectedTenantFingerprint='a'*64;$p.ExpectedPrincipalFingerprint='b'*64;$p|ConvertTo-Json|Set-Content $path
  $vault=Join-Path $root 'lab/session.tfvault';$password=ConvertTo-SecureString synthetic-inspection-passphrase -AsPlainText -Force
  try {
   $null=New-TokenForgeVault $vault $password
   & (Get-Module TokenForge) {
    param($vault,$password)
    Invoke-TokenForgeVaultTransaction $vault $password -Mode Update -Update {
     param($d)
     $now=[DateTimeOffset]::UtcNow;$id='c'*64
     $d.Sessions.lab=@{TenantFingerprint='a'*64;PrincipalFingerprint='b'*64;Revision=[guid]::NewGuid().ToString();CreatedAt=$now.ToString('o');LastConfirmedAt=$now.ToString('o');RetainUntil=$now.AddHours(1).ToString('o');Cookie='synthetic-private-cookie';CookieName='ESTSAUTH';Tokens=@{$id=@{Id=$id;ClientId='11111111-1111-1111-1111-111111111111';ResourceId='00000003-0000-0000-c000-000000000000';Tenant='example.test';Audience='00000003-0000-0000-c000-000000000000';Scopes=@('User.Read');IssuedScopes=@('User.Read');AdditionalScopeCount=0;RedirectUri='http://localhost/';Spa=$false;OfflineAccess=$true;Protocol='OAuth2V2Pkce';AcquiredAt=$now.ToString('o');ExpiresAt=$now.AddHours(1).ToString('o');AccessToken='synthetic-private-access';RefreshToken='synthetic-private-refresh';ConsentEvidence='SyntheticOnly'}}}
    }
   } $vault $password
   $before=(Get-FileHash $vault).Hash
   $view=Invoke-NativeProfile @('profile','inspect-vault','--profile','lab','--root',$root,'--stdin','--json') 0 'synthetic-inspection-passphrase'
   $view.Sessions[0].Name|Should -Be lab;$view.Sessions[0].HasCookie|Should -BeTrue
   $view.Sessions[0].Tokens[0].HasRefreshToken|Should -BeTrue
   $view.Sessions[0].Tokens[0].RequestedScopes|Should -Be @('User.Read')
   ($view|ConvertTo-Json -Depth 8)|Should -Not -Match 'synthetic-private|"AccessToken"|"RefreshToken"|"Cookie"'
   $view.Evidence|Should -Be StoredMetadataNotNewIssuanceOrApiAuthorization
   (Get-FileHash $vault).Hash|Should -Be $before
   Invoke-NativeProfile @('profile','inspect-vault','--profile','lab','--root',$root,'--stdin') 1 'synthetic-wrong-passphrase'
   (Get-FileHash $vault).Hash|Should -Be $before
  } finally {$password.Dispose()}
 }
 It 'rejects implicit redirected input, unsafe options and unsupported storage without creating a vault' {
  $null=Invoke-NativeProfile @('profile','create','--tenant','example.test','--root',$root)
  foreach($caseArguments in @(
   @('profile','inspect-vault','--root',$root),
   @('profile','inspect-vault','--root',$root,'--stdin','--stdin'),
   @('profile','inspect-vault','--root',$root,'--password','synthetic-private'),
   @('profile','inspect-vault','--root',$root,'--stdin')
  )){Invoke-NativeProfile $caseArguments 1 'short'}
  Test-Path (Join-Path $root 'default/session.tfvault')|Should -BeFalse
  $memory=New-TokenForgeProfile lab example.test -Root $root
  Invoke-NativeProfile @('profile','inspect-vault','--profile','lab','--root',$root,'--stdin') 1 'synthetic-inspection-passphrase'
  Test-Path (Join-Path $root 'lab/session.tfvault')|Should -BeFalse
 }

 It 'logs out locally without PowerShell and preserves profile configuration' {
  $p=New-TokenForgeProfile lab example.test -Root $root -Storage Passphrase
  $vault=Join-Path $root 'lab/session.tfvault';$password=ConvertTo-SecureString synthetic-logout-passphrase -AsPlainText -Force
  try {
   $null=New-TokenForgeVault $vault $password
   & (Get-Module TokenForge) {
    param($vault,$password)
    Invoke-TokenForgeVaultTransaction $vault $password -Mode Update -Update {
     param($d)
     $now=[DateTimeOffset]::UtcNow
     $d.Sessions.lab=@{TenantFingerprint='a'*64;PrincipalFingerprint='b'*64;Revision=[guid]::NewGuid().ToString();CreatedAt=$now.ToString('o');LastConfirmedAt=$now.ToString('o');RetainUntil=$now.AddHours(1).ToString('o');Cookie='synthetic-private-cookie';CookieName='ESTSAUTH';Tokens=@{}}
    }
   } $vault $password
   $configuration=(Get-FileHash (Join-Path $root 'lab/profile.json')).Hash
   $before=(Get-FileHash $vault).Hash
   Invoke-NativeProfile @('logout','--profile','lab','--root',$root,'--stdin') 1 'synthetic-wrong-passphrase'
   (Get-FileHash $vault).Hash|Should -Be $before
   $result=Invoke-NativeProfile @('logout','--profile','lab','--root',$root,'--stdin') 0 'synthetic-logout-passphrase'
   $result.Removed|Should -BeTrue;$result.Profile|Should -Be lab
   $result.Evidence|Should -Be LocalLogoutNotServerRevocation
   ($result|ConvertTo-Json)|Should -Not -Match 'synthetic-private|Cookie|AccessToken|RefreshToken'
   (Get-TokenForgeVault -Path $vault -Password $password).Sessions.Count|Should -Be 0
   (Get-FileHash (Join-Path $root 'lab/profile.json')).Hash|Should -Be $configuration
   $after=(Get-FileHash $vault).Hash
   $null=Invoke-NativeProfile @('logout','--profile','lab','--root',$root,'--stdin') 0 'synthetic-logout-passphrase'
   (Get-FileHash $vault).Hash|Should -Be $after
  }finally{$password.Dispose()}
 }
 It 'logs out missing and memory vaults without reading redirected credentials' {
  $null=Invoke-NativeProfile @('profile','create','--tenant','example.test','--root',$root)
  (Invoke-NativeProfile @('logout','--root',$root)).Removed|Should -BeTrue
  Test-Path (Join-Path $root 'default/session.tfvault')|Should -BeFalse
  $null=New-TokenForgeProfile lab example.test -Root $root
  (Invoke-NativeProfile @('logout','--profile','lab','--root',$root)).Removed|Should -BeTrue
  Test-Path (Join-Path $root 'lab/session.tfvault')|Should -BeFalse
 }
 It 'rejects unsafe logout options and credentials before modifying ciphertext' {
  $null=Invoke-NativeProfile @('profile','create','--tenant','example.test','--root',$root)
  $vault=Join-Path $root 'default/session.tfvault';$password=ConvertTo-SecureString synthetic-logout-passphrase -AsPlainText -Force
  try{$null=New-TokenForgeVault $vault $password}finally{$password.Dispose()}
  $before=(Get-FileHash $vault).Hash
  foreach($arguments in @(
   @('logout','--root',$root),
   @('logout','--root',$root,'--stdin','--stdin'),
   @('logout','--root',$root,'--stdin','--prompt-passphrase'),
   @('logout','--root',$root,'--password','synthetic-private'),
   @('logout','--root',$root,'--stdin')
  )){Invoke-NativeProfile $arguments 1 'short';(Get-FileHash $vault).Hash|Should -Be $before}
  Invoke-NativeProfile @('logout','--root',$root,'--stdin') 1 ('x'*1025)
  (Get-FileHash $vault).Hash|Should -Be $before
  $null=New-TokenForgeProfile lab example.test -Root $root
  Invoke-NativeProfile @('logout','--profile','lab','--root',$root,'--stdin') 1 'synthetic-logout-passphrase'
  if(-not $IsMacOS){
   $null=Invoke-NativeProfile @('profile','create','--profile','osfixture','--tenant','example.test','--root',$root,'--storage','OperatingSystem')
   foreach($flag in @('--stdin','--prompt-passphrase')){
    Invoke-NativeProfile @('logout','--profile','osfixture','--root',$root,$flag) 1 'synthetic-logout-passphrase'
   }
   Test-Path (Join-Path $root 'osfixture/session.tfvault')|Should -BeFalse
  }
 }

}
