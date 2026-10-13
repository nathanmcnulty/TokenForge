BeforeAll {
 Import-Module "$PSScriptRoot/../src/TokenForge/TokenForge.psd1" -Force
 function Write-Fixture([string]$Path,[byte[]]$Bytes) {
  $file=[TokenForge.Core.V0220.PrivateFiles]::Open($Path,(-not (Test-Path -LiteralPath $Path)))
  try{$file.SetLength(0);$file.Write($Bytes)}finally{$file.Dispose()}
 }
 function Set-Fixture($Data) {Write-Fixture $key ([Text.Encoding]::UTF8.GetBytes(($Data|ConvertTo-Json -Compress -Depth 16)))}
 function Set-Receipt([int]$Schema=2) {
  $hash=(Get-FileHash -LiteralPath $key -Algorithm SHA256).Hash.ToLowerInvariant()
  $data=if($Schema -eq 1){@{SchemaVersion=1;Registered=$true;CredentialFileSha256=$hash;CredentialId=$record.credentialId}}else{@{SchemaVersion=2;Usable=$true;Proof='FreshSoftwarePasskeyAuthenticationAndGraphIdentity';CredentialFileSha256=$hash;CredentialId=$record.credentialId}}
  Write-Fixture ($key+'.registered.json') ([Text.Encoding]::UTF8.GetBytes(($data|ConvertTo-Json -Compress)))
 }
 function Assert-Blocked([int]$Calls=0,[bool]$InvalidPrivatePath=$false) {
  $output=@();$failure=$null
  try{$output=@(Get-TokenForgeEstsCookie -PasskeyPath $key -XdrModulePath $provider -ErrorAction Stop)}catch{$failure=$_}
  $output.Count|Should -Be 0;$failure|Should -Not -BeNullOrEmpty
  $failure.Exception.Message|Should -Be 'Software passkey authentication failed; dependency details suppressed.'
  $failure.Exception.Message|Should -Not -Match ([regex]::Escape($root))
  $global:TokenForgeAdapterCalls|Should -Be $Calls
  # No reader handle should survive either the provider or confirmation failure.
  if(-not $InvalidPrivatePath){$file=[TokenForge.Core.V0220.PrivateFiles]::Open($key,$false);$file.Dispose()}
 }
}
Describe 'Legacy PowerShell passkey adapter receipt boundary' {
 BeforeEach {
  $root=Join-Path ($TestDrive -replace '^/var/','/private/var/') ([guid]::NewGuid().ToString())
  $key=[TokenForge.Core.V0220.PrivateFiles]::Resolve((Join-Path $root key.passkey),$true)
  $provider=Join-Path $root XDRInternals.psm1
  Set-Content -LiteralPath $provider -Value @'
function Invoke-XdrPasskeyAuthentication {
 param($KeyFilePath)
 $global:TokenForgeAdapterCalls++
 $global:TokenForgeAdapterObservedPath=$KeyFilePath
 if($global:TokenForgeAdapterAction){& $global:TokenForgeAdapterAction $KeyFilePath}
 'synthetic-cookie'
}
'@
  Remove-Module XDRInternals -Force -ErrorAction SilentlyContinue
  $global:TokenForgeAdapterCalls=0;$global:TokenForgeAdapterAction=$null;$global:TokenForgeAdapterObservedPath=$null
  $ecdsa=[Security.Cryptography.ECDsa]::Create([Security.Cryptography.ECCurve+NamedCurves]::nistP256)
  $record=@{username='synthetic@example.test';credentialId='AAAAAAAAAAAAAAAAAAAAAQ';privateKey=$ecdsa.ExportPkcs8PrivateKeyPem();userHandle='AQ';counter=0;enrollmentStatus='PendingRemoteVerification'}
  $ecdsa.Dispose();Set-Fixture $record
 }
 AfterEach {
  Remove-Module XDRInternals -Force -ErrorAction SilentlyContinue
  Remove-Variable TokenForgeAdapterCalls,TokenForgeAdapterAction,TokenForgeAdapterObservedPath -Scope Global -ErrorAction SilentlyContinue
  if($record){$record.Clear()}
 }
 It 'rejects a pending key before loading or invoking the provider' {
  Assert-Blocked;Get-Module XDRInternals|Should -BeNullOrEmpty
 }
 It 'accepts a matching schema <Schema> receipt and preserves its inputs' -ForEach @(@{Schema=1},@{Schema=2}) {
  Set-Receipt $Schema;$before=(Get-FileHash $key).Hash;$receiptBefore=(Get-FileHash ($key+'.registered.json')).Hash
  $cookie=Get-TokenForgeEstsCookie -PasskeyPath $key -XdrModulePath $provider
  try{$cookie|Should -BeOfType [Security.SecureString];[Net.NetworkCredential]::new('',$cookie).Password|Should -Be 'synthetic-cookie'}finally{$cookie.Dispose()}
  $global:TokenForgeAdapterCalls|Should -Be 1
  (Get-FileHash $key).Hash|Should -Be $before;(Get-FileHash ($key+'.registered.json')).Hash|Should -Be $receiptBefore
 }
 It 'accepts unmarked <Format> JSON through the existing provider' -ForEach @(@{Format='Local'},@{Format='LocalBom'},@{Format='KeyVaultReference'}) {
  $record.Remove('enrollmentStatus')
  if($Format -eq 'KeyVaultReference'){$record.Remove('privateKey');$record.keyVault=@{vaultName='synthetic-vault';keyName='synthetic-key'}}
  Set-Fixture $record
  if($Format -eq 'LocalBom'){Write-Fixture $key ([byte[]](239,187,191)+[IO.File]::ReadAllBytes($key))}
  $cookie=Get-TokenForgeEstsCookie -PasskeyPath $key -XdrModulePath $provider
  try{$cookie|Should -BeOfType [Security.SecureString]}finally{$cookie.Dispose()}
  $global:TokenForgeAdapterCalls|Should -Be 1;Test-Path ($key+'.registered.json')|Should -BeFalse
 }
 It 'canonicalizes relative paths before invoking the provider' {
  Set-Receipt;Push-Location $root
  try{$cookie=Get-TokenForgeEstsCookie -PasskeyPath './key.passkey' -XdrModulePath $provider;$cookie.Dispose()}finally{Pop-Location}
  $global:TokenForgeAdapterObservedPath|Should -Be $key
 }
 It 'resolves a local PowerShell filesystem drive to its native path' {
  Set-Receipt;$drive='TfAdapter'+[guid]::NewGuid().ToString('N')
  $null=New-PSDrive -Name $drive -PSProvider FileSystem -Root $root
  try{$cookie=Get-TokenForgeEstsCookie -PasskeyPath ($drive+':/key.passkey') -XdrModulePath $provider;$cookie.Dispose()}finally{Remove-PSDrive $drive}
  $global:TokenForgeAdapterObservedPath|Should -Be $key
 }
 It 'rejects non-filesystem provider paths without invoking the backend' {
  {Get-TokenForgeEstsCookie -PasskeyPath 'Variable:TokenForgeAdapterCalls' -XdrModulePath $provider}|Should -Throw '*dependency details suppressed*'
  $global:TokenForgeAdapterCalls|Should -Be 0
 }
 It 'uses the requested provider even when another copy has the same module name' {
  Set-Receipt;$other=Join-Path $root other;$null=New-Item -ItemType Directory $other
  $otherPath=Join-Path $other XDRInternals.psm1
  Set-Content $otherPath 'function Invoke-XdrPasskeyAuthentication {throw "Unexpected provider selected."}'
  Import-Module $otherPath -Force
  $cookie=Get-TokenForgeEstsCookie -PasskeyPath $key -XdrModulePath $provider
  try{$cookie|Should -BeOfType [Security.SecureString]}finally{$cookie.Dispose()}
  $global:TokenForgeAdapterCalls|Should -Be 1
 }
 It 'rejects an unexpected provider module name before invoking it' {
  Set-Receipt;$wrongProvider=Join-Path $root Unexpected.psm1;Copy-Item $provider $wrongProvider
  {Get-TokenForgeEstsCookie -PasskeyPath $key -XdrModulePath $wrongProvider}|Should -Throw '*dependency details suppressed*'
  $global:TokenForgeAdapterCalls|Should -Be 0
 }
 It 'rejects pathname replacement or an attempted replacement while leased' {
  Set-Receipt;$global:TokenForgeAdapterAction={param($path)
   [IO.File]::Move($path,$path+'.previous');[IO.File]::WriteAllText($path,'{}')
   if(-not $IsWindows){[IO.File]::SetUnixFileMode($path,[IO.UnixFileMode]384)}
  }
  Assert-Blocked 1
 }
 It 'rejects permissions broadened during authentication on Unix' -Skip:$IsWindows {
  Set-Receipt;$global:TokenForgeAdapterAction={param($path)[IO.File]::SetUnixFileMode($path,[IO.UnixFileMode]420)}
  Assert-Blocked 1 $true
  [IO.File]::SetUnixFileMode($key,[IO.UnixFileMode]384)
  $file=[TokenForge.Core.V0220.PrivateFiles]::Open($key,$false);$file.Dispose()
 }
 It 'rejects <Case> input before the provider' -ForEach @(@{Case='DuplicateMarker'},@{Case='InvalidUtf8'},@{Case='UnknownStatus'},@{Case='NonstringStatus'},@{Case='Oversized'}) {
  switch($Case){
   DuplicateMarker {$text=($record|ConvertTo-Json -Compress) -replace '^\{','{"enrollmentStatus":"PendingRemoteVerification",';Write-Fixture $key ([Text.Encoding]::UTF8.GetBytes($text))}
   InvalidUtf8 {Write-Fixture $key ([byte[]](123,34,120,34,58,34,255,34,125))}
   UnknownStatus {$record.enrollmentStatus='Registered';Set-Fixture $record}
   NonstringStatus {$record.enrollmentStatus=$true;Set-Fixture $record}
   Oversized {Write-Fixture $key ([byte[]]::new(65537))}
  }
  Assert-Blocked
 }
 It 'rejects a receipt removed during provider authentication' {
  Set-Receipt;$global:TokenForgeAdapterAction={param($path)[IO.File]::Delete($path+'.registered.json')}
  Assert-Blocked 1
 }
 It 'rejects a receipt changed during provider authentication' {
  Set-Receipt;$global:TokenForgeAdapterAction={param($path)[IO.File]::WriteAllText($path+'.registered.json','{"SchemaVersion":99}')}
  Assert-Blocked 1
 }
 It 'rejects a provider that changes the key or attempts to write through the lease' {
  Set-Receipt;$global:TokenForgeAdapterAction={param($path)[IO.File]::WriteAllText($path,'{}')}
  Assert-Blocked 1
 }
 It 'suppresses provider failures and releases the file lease' {
  Set-Receipt;$global:TokenForgeAdapterAction={throw 'synthetic-private-provider-details'}
  Assert-Blocked 1
 }
 It 'serializes no credential or path metadata from the shared lease' {
  Set-Receipt;$lease=[TokenForge.Core.SoftwarePasskeyFileLease]::Open($key)
  try{[Text.Json.JsonSerializer]::Serialize($lease,[TokenForge.Core.SoftwarePasskeyFileLease],[Text.Json.JsonSerializerOptions]$null)|Should -Be '{}';$lease.ConfirmUnchanged()}finally{$lease.Dispose()}
  {$lease.ConfirmUnchanged()}|Should -Throw '*Details suppressed*'
 }
 It 'rejects Unix <Case> paths before the provider' -Skip:$IsWindows -ForEach @(@{Case='SharedDirectory'},@{Case='SharedFile'},@{Case='LinkedAncestor'}) {
  switch($Case){
   SharedDirectory {[IO.File]::SetUnixFileMode($root,[IO.UnixFileMode]493)}
   SharedFile {[IO.File]::SetUnixFileMode($key,[IO.UnixFileMode]420)}
   LinkedAncestor {$link=Join-Path ($TestDrive -replace '^/var/','/private/var/') ([guid]::NewGuid().ToString());$null=New-Item -ItemType SymbolicLink -Path $link -Target $root;$original=$key;$key=Join-Path $link key.passkey}
  }
  # These cases deliberately violate the private policy; only inspect output/side effects.
  {Get-TokenForgeEstsCookie -PasskeyPath $key -XdrModulePath $provider}|Should -Throw '*dependency details suppressed*'
  $global:TokenForgeAdapterCalls|Should -Be 0
 }
}
