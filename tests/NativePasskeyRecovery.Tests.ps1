BeforeDiscovery {
 $nativeAvailable=[bool]($env:TOKENFORGE_TEST_NATIVE -and (Test-Path -LiteralPath $env:TOKENFORGE_TEST_NATIVE -PathType Leaf))
}
Describe 'Native pending passkey recovery input boundaries' -Skip:(-not $nativeAvailable) {
 BeforeAll {
  Import-Module "$PSScriptRoot/../src/TokenForge/TokenForge.psd1" -Force
  function Invoke-RecoveryFixture([string[]]$Options) {
   $start=[Diagnostics.ProcessStartInfo]::new($env:TOKENFORGE_TEST_NATIVE)
   $start.UseShellExecute=$false;$start.RedirectStandardOutput=$true;$start.RedirectStandardError=$true
   $start.Environment['PATH']=Join-Path $root no-powershell
   foreach($arg in (@('passkey','recover')+$Options)){$start.ArgumentList.Add($arg)}
   $process=[Diagnostics.Process]::Start($start)
   try{
    $output=$process.StandardOutput.ReadToEndAsync();$errors=$process.StandardError.ReadToEndAsync()
    if(-not $process.WaitForExit(30000)){$process.Kill($true);throw 'Recovery fixture timed out.'}
    $process.ExitCode|Should -Be 1;$output.GetAwaiter().GetResult()|Should -BeNullOrEmpty
    $stderr=$errors.GetAwaiter().GetResult();$stderr|Should -Not -Match ([regex]::Escape($root))
    $stderr|ConvertFrom-Json
   }finally{$process.Dispose()}
  }
 }
 BeforeEach {
  $root=Join-Path ($TestDrive -replace '^/var/','/private/var/') ([guid]::NewGuid().ToString())
  $key=[TokenForge.Core.V0220.PrivateFiles]::Resolve((Join-Path $root fixture.passkey),$true)
  $identity=Join-Path $root identity.json
  foreach($path in @($key,$identity)){$stream=[TokenForge.Core.V0220.PrivateFiles]::Open($path,$true);try{$stream.Write([Text.Encoding]::UTF8.GetBytes('{}'))}finally{$stream.Dispose()}}
  $options=@('--passkey-file',$key,'--identity-file',$identity,'--json')
 }
 It 'rejects <Case> before authentication' -ForEach @(
  @{Case='unknown option';Extra=@('--cookie','synthetic')},
  @{Case='duplicate key';Extra=@('--passkey-file','synthetic')},
  @{Case='duplicate JSON switch';Extra=@('--json')},
  @{Case='negative scope allowance';Extra=@('--max-extra-scopes','-1')},
  @{Case='excessive scope allowance';Extra=@('--max-extra-scopes','513')},
  @{Case='noninteger scope allowance';Extra=@('--max-extra-scopes','1.0')},
  @{Case='missing value';Extra=@('--max-extra-scopes')}
 ) {
  (Invoke-RecoveryFixture ($options+$Extra)).Code|Should -Be OperationFailed
  Test-Path ($key+'.registered.json')|Should -BeFalse
 }
 It 'rejects malformed expected identity in the native executable without PowerShell' {
  $result=Invoke-RecoveryFixture $options
  $result.Error|Should -Be PasskeyRecoveryFailed;$result.Stage|Should -Be Inputs
  $result.ReceiptSaved|Should -BeFalse;$result.DetailsSuppressed|Should -BeTrue
  Test-Path ($key+'.registered.json')|Should -BeFalse
  [IO.File]::ReadAllText($key)|Should -Be '{}'
 }
}
