BeforeDiscovery {
 $available=[bool]($env:TOKENFORGE_TEST_NATIVE -and $env:TOKENFORGE_TEST_PREVIOUS_NATIVE)
}
Describe 'Real credential assemblies in isolated fresh PowerShell processes' -Skip:(-not $available) {
 BeforeAll {
  $repo=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
  $oldDll=Join-Path (Split-Path $env:TOKENFORGE_TEST_PREVIOUS_NATIVE -Parent) src/TokenForge/lib/net10.0/TokenForge.Credentials.dll
  $newDll=Join-Path (Split-Path $env:TOKENFORGE_TEST_NATIVE -Parent) src/TokenForge/lib/net10.0/TokenForge.Credentials.dll
  [Reflection.AssemblyName]::GetAssemblyName($oldDll).Version.ToString()|Should -Be '0.48.0.0'
  [Reflection.AssemblyName]::GetAssemblyName($newDll).Version.ToString()|Should -Be '0.48.0.0'
  (Get-FileHash $oldDll).Hash|Should -Not -Be (Get-FileHash $newDll).Hash
 }
 It 'binds actual loaded bytes and module identity for <Case>' -ForEach @(
  @{Case='HealthOldThenNew'},@{Case='HealthNewThenOld'},@{Case='HealthSourceThenNew'},
  @{Case='HealthFresh'},@{Case='HealthRepeated'},@{Case='HealthIdenticalCopy'},@{Case='HealthReplacement'},
  @{Case='DirectOldThenNew'},@{Case='DirectNewThenOld'},@{Case='DirectSourceThenNew'},@{Case='DirectRepeated'},@{Case='DirectReplacement'}
 ) {
  $root=Join-Path $TestDrive $Case;$null=[IO.Directory]::CreateDirectory($root,[IO.UnixFileMode]448)
  $psi=[Diagnostics.ProcessStartInfo]::new((Get-Process -Id $PID).Path)
  $psi.UseShellExecute=$false;$psi.RedirectStandardOutput=$true;$psi.RedirectStandardError=$true
  foreach($arg in @('-NoLogo','-NoProfile','-NonInteractive','-File',"$PSScriptRoot/fixtures/bootstrap/RuntimeAssemblyProcess.ps1",'-Case',$Case,'-Root',$root,'-Source',$repo,'-OldNative',$env:TOKENFORGE_TEST_PREVIOUS_NATIVE,'-NewNative',$env:TOKENFORGE_TEST_NATIVE)){$psi.ArgumentList.Add($arg)}
  $process=[Diagnostics.Process]::Start($psi)
  try{
   $stdout=$process.StandardOutput.ReadToEndAsync();$stderr=$process.StandardError.ReadToEndAsync()
   if(-not $process.WaitForExit(90000)){$process.Kill($true);throw 'Runtime identity subprocess timed out.'}
   $text=$stdout.GetAwaiter().GetResult();$errorText=$stderr.GetAwaiter().GetResult()
   $errorText|Should -BeNullOrEmpty
   $process.ExitCode|Should -Be 0 -Because $text
   $result=$text|ConvertFrom-Json
   $result.Version|Should -Be '0.48.0'
   $result.Refused|Should -Be $result.ExpectedFailure
   if($result.ExpectedFailure){$result.OutputExists|Should -BeFalse;$result.ModuleCount|Should -Be 0;if(-not $result.Direct){$result.ModuleImports|Should -Be 0}}
   else{$result.OutputExists|Should -BeTrue;$result.ModuleCount|Should -Be 1;$result.AssemblyName|Should -Be TokenForge.Credentials}
  }finally{$process.Dispose()}
 }
}
