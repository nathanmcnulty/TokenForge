BeforeDiscovery {
 $nativeAvailable=[bool]($env:TOKENFORGE_TEST_NATIVE -and (Test-Path -LiteralPath $env:TOKENFORGE_TEST_NATIVE -PathType Leaf))
}
Describe 'Native immutable maintenance backup' -Skip:(-not $nativeAvailable) {
 BeforeAll {
  Import-Module "$PSScriptRoot/../src/TokenForge/TokenForge.psd1" -Force
  function Start-Backup([string[]]$Options) {
   $start=[Diagnostics.ProcessStartInfo]::new($env:TOKENFORGE_TEST_NATIVE)
   $start.UseShellExecute=$false;$start.RedirectStandardOutput=$true;$start.RedirectStandardError=$true
   $start.Environment['PATH']=Join-Path $root no-powershell
   foreach($arg in (@('research','backup')+$Options)){$start.ArgumentList.Add($arg)}
   [Diagnostics.Process]::Start($start)
  }
  function Complete-Backup($Process,[int]$Exit=0) {
   try{
    $output=$Process.StandardOutput.ReadToEndAsync();$errors=$Process.StandardError.ReadToEndAsync()
    if(-not $Process.WaitForExit(30000)){$Process.Kill($true);throw 'Backup fixture timed out.'}
    $Process.ExitCode|Should -Be $Exit
    $stdout=$output.GetAwaiter().GetResult();$stderr=$errors.GetAwaiter().GetResult()
    if($Exit){$stdout|Should -BeNullOrEmpty;$stderr|Should -Not -Match ([regex]::Escape($root));($stderr|ConvertFrom-Json).Code|Should -Be OperationFailed}
    else{$stderr|Should -BeNullOrEmpty;$stdout|ConvertFrom-Json}
   }finally{$Process.Dispose()}
  }
  function Invoke-Backup([string[]]$Options) { Complete-Backup (Start-Backup $Options) }
 }
 BeforeEach {
  $root=Join-Path $TestDrive ([guid]::NewGuid().ToString())
  if($IsMacOS){$root=$root -replace '^/var/','/private/var/'}
  $source=[TokenForge.Core.V0220.PrivateFiles]::Resolve((Join-Path $root source.sealed),$true)
  $blob=[Security.Cryptography.RandomNumberGenerator]::GetBytes(128);$blob[0]=1
  $stream=[TokenForge.Core.V0220.PrivateFiles]::Open($source,$true)
  try{$stream.Write($blob)}finally{$stream.Dispose()}
  $destination=Join-Path $root backups
  $options=@('--snapshot-path',$source,'--backup-directory',$destination,'--json')
 }
 It 'copies ciphertext through the native executable without PowerShell' {
  $result=Invoke-Backup $options
  $result.Saved|Should -BeTrue;$result.AlreadyExists|Should -BeFalse;$result.Authenticated|Should -BeFalse
  $result.Bytes|Should -Be 128
  $result.Sha256|Should -Be ([Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($blob)).ToLowerInvariant())
  [Convert]::ToBase64String([IO.File]::ReadAllBytes($result.BackupPath))|Should -Be ([Convert]::ToBase64String($blob))
  [TokenForge.Core.V0220.PrivateFiles]::Resolve($result.BackupPath,$false)|Should -Be $result.BackupPath
 }
 It 'deduplicates a copy without replacing it' {
  $first=Invoke-Backup $options;$date=[IO.File]::GetLastWriteTimeUtc($first.BackupPath)
  $second=Invoke-Backup $options;$second.Saved|Should -BeFalse;$second.AlreadyExists|Should -BeTrue
  [IO.File]::GetLastWriteTimeUtc($first.BackupPath)|Should -Be $date
 }
 It 'rejects same-length corrupt data at the content-addressed target' {
  $first=Invoke-Backup $options;$blob[1]=$blob[1] -bxor 1;[IO.File]::WriteAllBytes($first.BackupPath,$blob)
  $null=Complete-Backup (Start-Backup $options) 1
  [Convert]::ToBase64String([IO.File]::ReadAllBytes($first.BackupPath))|Should -Be ([Convert]::ToBase64String($blob))
 }
 It 'rejects <Case> envelopes before creating a destination' -ForEach @(@{Case='Version'},@{Case='Truncated'},@{Case='Oversized'}) {
  switch($Case){
   Version {$blob[0]=2;[IO.File]::WriteAllBytes($source,$blob)}
   Truncated {[IO.File]::WriteAllBytes($source,[byte[]](1,2,3))}
   Oversized {$stream=[IO.File]::OpenWrite($source);try{$stream.SetLength(134217758)}finally{$stream.Dispose()}}
  }
  $null=Complete-Backup (Start-Backup $options) 1
  Test-Path $destination|Should -BeFalse
 }
 It 'rejects a missing source without creating destination storage' {
  [IO.File]::Delete($source);$null=Complete-Backup (Start-Backup $options) 1
  Test-Path $destination|Should -BeFalse
 }
 It 'rejects authentication flags without creating storage' {
  $null=Complete-Backup (Start-Backup ($options+@('--prompt-passphrase'))) 1
  Test-Path $destination|Should -BeFalse
 }
 It 'rejects duplicate options before writing storage' {
  $null=Complete-Backup (Start-Backup ($options+@('--snapshot-path',$source))) 1
  Test-Path $destination|Should -BeFalse
 }
 It 'rejects missing option values before writing storage' {
  $null=Complete-Backup (Start-Backup @('--snapshot-path',$source,'--backup-directory')) 1
  Test-Path $destination|Should -BeFalse
 }
 It 'saves identical snapshots concurrently and cleans losing temporary files' {
  $first=Start-Backup $options;$second=Start-Backup $options
  $a=Complete-Backup $first;$b=Complete-Backup $second
  @($a,$b|Where-Object Saved).Count|Should -Be 1
  $a.BackupPath|Should -Be $b.BackupPath
  @(Get-ChildItem -LiteralPath $destination -Force).Count|Should -Be 1
 }
 It 'rejects Unix <Case> paths' -Skip:$IsWindows -ForEach @(@{Case='LinkedSource'},@{Case='LinkedDestination'},@{Case='SharedSource'},@{Case='SharedDestination'}) {
  switch($Case){
   LinkedSource {$link=Join-Path $root linked.sealed;$null=New-Item -ItemType SymbolicLink -Path $link -Target $source;$options=@('--snapshot-path',$link,'--backup-directory',$destination)}
   LinkedDestination {$null=New-Item -ItemType SymbolicLink -Path $destination -Target $root}
   SharedSource {[IO.File]::SetUnixFileMode($source,[IO.UnixFileMode]420)}
   SharedDestination {$null=[IO.Directory]::CreateDirectory($destination,[IO.UnixFileMode]493)}
  }
  $null=Complete-Backup (Start-Backup $options) 1
  [IO.File]::ReadAllBytes($source).Length|Should -Be 128
 }
}
