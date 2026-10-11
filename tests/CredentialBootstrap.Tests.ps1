BeforeDiscovery {
 $nativeAvailable=[bool]($env:TOKENFORGE_TEST_NATIVE -and (Test-Path -LiteralPath $env:TOKENFORGE_TEST_NATIVE -PathType Leaf))
}
Describe 'Unified in-process credential runtime bootstrap' {
 BeforeAll {
  $manifest=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../src/TokenForge/TokenForge.psd1'))
  $ci=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../scripts/TokenForgeCiState.ps1'))
  function Quote-BootstrapPath([string]$Path){"'"+$Path.Replace("'","''")+"'"}
  function Invoke-Bootstrap([string]$Code,[int]$ExitCode=0){
   $start=[Diagnostics.ProcessStartInfo]::new((Join-Path $PSHOME $(if($IsWindows){'pwsh.exe'}else{'pwsh'})))
   $start.UseShellExecute=$false;$start.RedirectStandardOutput=$true;$start.RedirectStandardError=$true
   foreach($arg in @('-NoProfile','-NonInteractive','-Command',('$ErrorActionPreference=''Stop''; try {'+$Code+'} catch {[Console]::Error.WriteLine($_.Exception.Message); exit 1}'))){$start.ArgumentList.Add($arg)}
   $process=[Diagnostics.Process]::Start($start)
   try{
    $stdout=$process.StandardOutput.ReadToEndAsync();$stderr=$process.StandardError.ReadToEndAsync()
    if(-not $process.WaitForExit(60000)){$process.Kill($true);throw 'Credential bootstrap timed out.'}
    $process.ExitCode|Should -Be $ExitCode
    if($ExitCode){$stdout.GetAwaiter().GetResult()|Should -BeNullOrEmpty;return $stderr.GetAwaiter().GetResult()}
    $stderr.GetAwaiter().GetResult()|Should -BeNullOrEmpty
    $stdout.GetAwaiter().GetResult()|ConvertFrom-Json
   }finally{$process.Dispose()}
  }
 }
 It 'compiles one BCL source assembly with module-first initialization and repeated imports' {
  $result=Invoke-Bootstrap ("Import-Module "+(Quote-BootstrapPath $manifest)+"; . "+(Quote-BootstrapPath $ci)+"; Import-Module "+(Quote-BootstrapPath $manifest)+" -Force; @{Version=[TokenForge.Core.CredentialRuntime]::Version;SameAssembly=([TokenForge.Core.ProfileTokenLifecycle].Assembly -eq [TokenForge.Core.V0240.TimestampPolicy].Assembly);SqliteDependency=@([TokenForge.Core.ProfileTokenLifecycle].Assembly.GetReferencedAssemblies()|Where-Object Name -Like '*Sqlite*').Count}|ConvertTo-Json")
  $result.Version|Should -Be '0.36.1';$result.SameAssembly|Should -BeTrue;$result.SqliteDependency|Should -Be 0
 }
 It 'allows CI-state-first initialization without a separately compiled timestamp type' {
  $result=Invoke-Bootstrap (". "+(Quote-BootstrapPath $ci)+"; Import-Module "+(Quote-BootstrapPath $manifest)+"; @{SameAssembly=([TokenForge.Core.V0240.TimestampPolicy].Assembly -eq [TokenForge.Core.ProfileStore].Assembly);Week=(Get-TfCiWeek ([DateTimeOffset]'2026-10-07T00:00:00Z'))}|ConvertTo-Json")
  $result.SameAssembly|Should -BeTrue;$result.Week|Should -Be '2026-W41'
 }
 It 'rejects legacy separately loaded types with a fresh-process explanation' {
  $old=Join-Path $PSScriptRoot '../src/TokenForge/Core/TimestampPolicy.cs'
  Invoke-Bootstrap ("Add-Type -Path "+(Quote-BootstrapPath $old)+"; Import-Module "+(Quote-BootstrapPath $manifest)) 1|Should -Match 'fresh PowerShell process'
 }
 It 'rejects an incompatible runtime marker instead of mixing source assemblies' {
  Invoke-Bootstrap ("Add-Type -TypeDefinition 'namespace TokenForge.Core {public static class CredentialRuntime {public const string Version=""0.0.0"";}}'; Import-Module "+(Quote-BootstrapPath $manifest)) 1|Should -Match 'fresh PowerShell process'
 }
 It 'validates agreement between the source loader and compiled credential project' {
  $names=Get-Content (Join-Path $PSScriptRoot '../src/TokenForge/Core/CredentialSources.json') -Raw|ConvertFrom-Json
  $project=[xml](Get-Content (Join-Path $PSScriptRoot '../native/TokenForge.Credentials/TokenForge.Credentials.csproj') -Raw)
  $compiled=@($project.Project.ItemGroup.Compile|ForEach-Object {[IO.Path]::GetFileName($_.Include)})
  @(Compare-Object $names $compiled).Count|Should -Be 0
 }
 It 'loads the packaged BCL DLL in a fresh process' -Skip:(-not $nativeAvailable) {
  $packaged=Join-Path (Split-Path $env:TOKENFORGE_TEST_NATIVE -Parent) 'src/TokenForge/TokenForge.psd1'
  $result=Invoke-Bootstrap ("Import-Module "+(Quote-BootstrapPath $packaged)+"; @{Name=[TokenForge.Core.ProfileTokenLifecycle].Assembly.GetName().Name;Version=[TokenForge.Core.CredentialRuntime]::Version;SqliteDependency=@([TokenForge.Core.ProfileTokenLifecycle].Assembly.GetReferencedAssemblies()|Where-Object Name -Like '*Sqlite*').Count}|ConvertTo-Json")
  $result.Name|Should -Be TokenForge.Credentials;$result.Version|Should -Be '0.36.1';$result.SqliteDependency|Should -Be 0
 }
 It 'refuses an invalid bundled DLL without source fallback' {
  $copy=Join-Path $TestDrive brokenmodule
  Copy-Item (Join-Path $PSScriptRoot '../src/TokenForge') $copy -Recurse
  $lib=Join-Path $copy lib/net8.0;$null=New-Item -ItemType Directory $lib -Force
  [IO.File]::WriteAllBytes((Join-Path $lib TokenForge.Credentials.dll),[byte[]]@(1,2,3))
  Invoke-Bootstrap ("Import-Module "+(Quote-BootstrapPath (Join-Path $copy TokenForge.psd1))) 1|Should -Match 'source fallback is disabled'
 }
}
