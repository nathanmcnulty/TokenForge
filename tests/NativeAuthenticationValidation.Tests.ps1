BeforeAll {
 $driver=Join-Path $PSScriptRoot '../scripts/Test-TokenForgeNativeAuthentication.ps1'
 $pwsh=Join-Path $PSHOME $(if($IsWindows){'pwsh.exe'}else{'pwsh'})
 . $driver -NativeExecutablePath $pwsh -Runtime linux-x64 -SourceCommit ('a'*40) -ReportPath (Join-Path $TestDrive 'unused.json')
 function Invoke-SyntheticNative([string]$Code){
  Invoke-TfNativeValidationCommand -Executable $pwsh -PrivateRoot $TestDrive -Arguments @('-NoProfile','-NonInteractive','-Command',$Code)
 }
}
Describe 'Native authentication validation trust boundaries' {
 It 'does not enter the authentication body when loaded for boundary tests' {
  Test-Path (Join-Path $TestDrive unused.json)|Should -BeFalse
 }
 It 'refuses nested credential fields and JWT-shaped metadata' {
  {Assert-TfNativeMetadata @{Nested=@(@{PRIVATEKEY='synthetic'})}}|Should -Throw '*refused*'
  {Assert-TfNativeMetadata @{Nested=@{value='eyJhbGciOiJub25lIn0.eyJzdWIiOiJ0ZXN0In0.signature'}}}|Should -Throw '*refused*'
  {Assert-TfNativeMetadata @{Cookie=$null}}|Should -Throw '*refused*'
  {Assert-TfNativeMetadata @{CredentialOutput=$false;IssuedScopes=@('User.Read')}}|Should -Not -Throw
 }
 It 'removes ambient credentials and PowerShell from child PATH' {
  $old=[Environment]::GetEnvironmentVariable('TOKENFORGE_PASSKEY_PRIVATE_KEY')
  try{
   $env:TOKENFORGE_PASSKEY_PRIVATE_KEY='synthetic-private-marker'
   $result=Invoke-SyntheticNative '[ordered]@{Inherited=([bool]$env:TOKENFORGE_PASSKEY_PRIVATE_KEY);Path=$env:PATH}|ConvertTo-Json -Compress'
   $result.Inherited|Should -BeFalse
   # The synthetic pwsh host prepends PSHOME during its own startup. The real
   # child is TokenForge; subtract only this known fixture prefix, never ambient PATH.
   $path=$result.Path;$prefix=$PSHOME+[IO.Path]::PathSeparator
   if($path.StartsWith($prefix,[StringComparison]::Ordinal)){$path=$path.Substring($prefix.Length)}
   $path|Should -Be (Join-Path $TestDrive no-powershell)
  }finally{[Environment]::SetEnvironmentVariable('TOKENFORGE_PASSKEY_PRIVATE_KEY',$old)}
 }
 It 'suppresses stdout and stderr on failed or credential-bearing child output' {
  foreach($code in @('Write-Output ''{"AccessToken":"synthetic-private-marker"}''','[Console]::Error.WriteLine("synthetic-private-marker"); exit 1','Write-Output "synthetic-private-marker"; exit 1')){
   $failure=$null;try{Invoke-SyntheticNative $code}catch{$failure=$_}
   $failure|Should -Not -BeNullOrEmpty
   $failure.Exception.Message|Should -Be 'Native validation command failed; output suppressed.'
   $failure.Exception.Message|Should -Not -Match 'synthetic-private-marker'
  }
 }
 It 'rejects non-object JSON while allowing bounded credential-free command metadata' {
  {Invoke-SyntheticNative 'Write-Output "[]"'}|Should -Throw '*output suppressed*'
  (Invoke-SyntheticNative 'Write-Output ''{"SchemaVersion":1,"CredentialOutput":false}''').CredentialOutput|Should -BeFalse
 }
}
