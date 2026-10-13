BeforeAll {Import-Module (Join-Path $PSScriptRoot '../src/TokenForge/TokenForge.psd1')}
Describe 'Explicit software passkey enrollment surface' {
 It 'does no reads, output writes or authentication under WhatIf' {
  {Register-TokenForgeSoftwarePasskey -PasskeyPath '/missing/key' -IdentityPath '/missing/identity' -OutputPath '/missing/output' -WhatIf}|Should -Not -Throw
 }
 It 'rejects an existing output before opening credentials or contacting identity services' {
  $root=Join-Path $TestDrive private
  if($IsMacOS -and $root.StartsWith('/var/')){$root='/private'+$root}
  $path=[TokenForge.Core.V0220.PrivateFiles]::Resolve((Join-Path $root existing.passkey),$true)
  $file=[TokenForge.Core.V0220.PrivateFiles]::Open($path,$true);try{$file.Write([Text.Encoding]::UTF8.GetBytes('existing key marker'))}finally{$file.Dispose()}
  $before=(Get-FileHash $path).Hash
  {[TokenForge.Core.SoftwarePasskeyEnrollment]::Enroll('/missing/key','{}',$path,'Test')}|Should -Throw '*No recovery key*'
  (Get-FileHash $path).Hash|Should -BeExactly $before
 }
}
