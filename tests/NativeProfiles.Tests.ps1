BeforeDiscovery {
 $nativeAvailable=[bool]($env:TOKENFORGE_TEST_NATIVE -and (Test-Path -LiteralPath $env:TOKENFORGE_TEST_NATIVE -PathType Leaf))
}
Describe 'Native profile configuration interoperability' -Skip:(-not $nativeAvailable) {
 BeforeAll {
  Import-Module (Join-Path $PSScriptRoot '../src/TokenForge/TokenForge.psd1') -Force
  function Invoke-NativeProfile([string[]]$Arguments,[int]$ExitCode=0) {
   $start=[Diagnostics.ProcessStartInfo]::new($env:TOKENFORGE_TEST_NATIVE)
   $start.UseShellExecute=$false;$start.RedirectStandardOutput=$true;$start.RedirectStandardError=$true
   $start.Environment['PATH']=Join-Path $root no-pwsh
   foreach($argument in $Arguments){$start.ArgumentList.Add($argument)}
   $process=[Diagnostics.Process]::Start($start)
   try {
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
 It 'honors the PowerShell operation lock and reports explicit retention settings' {
  $created=New-TokenForgeProfile -Name lab -Tenant example.onmicrosoft.com -Root $root
  Remove-Item (Join-Path $root 'lab/profile.json')
  $lock=[IO.FileStream]::new((Join-Path $root 'lab/.operation.lock'),[IO.FileMode]::Open,[IO.FileAccess]::ReadWrite,[IO.FileShare]::None)
  try{Invoke-NativeProfile @('profile','create','--profile','lab','--tenant','example.onmicrosoft.com','--root',$root) 1}finally{$lock.Dispose()}
  Test-Path (Join-Path $root 'lab/profile.json')|Should -BeFalse
  $other=Invoke-NativeProfile @('profile','create','--profile','other','--tenant','example.onmicrosoft.com','--root',$root,'--max-age-hours','168','--session-retention-hours','12')
  $other.MaxAgeHours|Should -Be 168;$other.SessionRetentionHours|Should -Be 12
 }
}
