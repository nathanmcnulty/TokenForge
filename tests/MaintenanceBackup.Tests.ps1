BeforeAll {
 $scriptPath="$PSScriptRoot/../scripts/Export-TokenForgeMaintenanceBackup.ps1"
 . "$PSScriptRoot/../scripts/TokenForgeCiState.ps1"
 Import-Module "$PSScriptRoot/../src/TokenForge/TokenForge.psd1" -Force
}
Describe 'Immutable encrypted maintenance backups' {
 BeforeEach {
  $root=Join-Path $TestDrive ([guid]::NewGuid().ToString())
  if($IsMacOS -and $root.StartsWith('/var/')){$root='/private'+$root}
  $module=Get-Module TokenForge
  $source=& $module {param($p) Resolve-TokenForgeVaultPath $p -CreateDirectory} (Join-Path $root 'source.sealed')
  $key=[Convert]::ToBase64String([Security.Cryptography.RandomNumberGenerator]::GetBytes(32))
  $context='private-maintenance/v1/test-tenant/test-account'
  $blob=Protect-TfCiCheckpoint ([Text.Encoding]::UTF8.GetBytes('{"SchemaVersion":1,"Metadata":{"Runs":[]}}')) $key $context
  $stream=& $module {param($p) Open-TokenForgeVaultFile $p -Create} $source
  try{$stream.Write($blob,0,$blob.Length)}finally{$stream.Dispose()}
  $destination=Join-Path $root backups
 }
 It 'preserves ciphertext, identity binding, and private filesystem permissions' {
  $result=& $scriptPath -SnapshotPath $source -BackupDirectory $destination
  $result.Saved|Should -BeTrue
  $result.Authenticated|Should -BeFalse
  (Get-FileHash $result.BackupPath).Hash.ToLowerInvariant()|Should -Be $result.Sha256
  $saved=[IO.File]::ReadAllBytes($result.BackupPath)
  [Text.Encoding]::UTF8.GetString((Unprotect-TfCiCheckpoint $saved $key $context))|Should -Be '{"SchemaVersion":1,"Metadata":{"Runs":[]}}'
  {Unprotect-TfCiCheckpoint $saved $key 'wrong-account'}|Should -Throw '*authentication failed*'
  $null=& $module {param($p) Resolve-TokenForgeVaultPath $p} $result.BackupPath
 }
 It 'backs up through the CLI without requiring an authentication profile' {
  $profileRoot=Join-Path $root missing-profiles
  $json=& pwsh -NoProfile -File "$PSScriptRoot/../scripts/tokenforge.ps1" -Command research -Operation backup -SnapshotPath $source -BackupDirectory $destination -Root $profileRoot -Json
  $LASTEXITCODE|Should -Be 0
  $result=$json|ConvertFrom-Json
  $result.Saved|Should -BeTrue
  $result.Authenticated|Should -BeFalse
  Test-Path $profileRoot|Should -BeFalse
 }
 It 'rejects authentication prompts before reading credentials or writing backups' {
  Mock Read-Host {throw 'Unexpected credential prompt.'}
  $promptResult=. "$PSScriptRoot/../scripts/tokenforge.ps1" -Command research -Operation backup -SnapshotPath $source -BackupDirectory $destination -PromptPassphrase -Json
  $LASTEXITCODE|Should -Be 1
  ($promptResult|ConvertFrom-Json).Code|Should -Be 'OperationFailed'
  Should -Invoke Read-Host -Exactly -Times 0
  Test-Path $destination|Should -BeFalse
 }
 It 'deduplicates identical snapshots without changing the existing backup' {
  $first=& $scriptPath -SnapshotPath $source -BackupDirectory $destination
  $created=(Get-Item $first.BackupPath).LastWriteTimeUtc
  $second=& $scriptPath -SnapshotPath $source -BackupDirectory $destination
  $second.Saved|Should -BeFalse
  $second.AlreadyExists|Should -BeTrue
  (Get-Item $first.BackupPath).LastWriteTimeUtc|Should -Be $created
 }
 It 'does not replace a corrupt existing backup' {
  $first=& $scriptPath -SnapshotPath $source -BackupDirectory $destination
  [IO.File]::WriteAllBytes($first.BackupPath,[byte[]](1,2,3))
  {& $scriptPath -SnapshotPath $source -BackupDirectory $destination}|Should -Throw '*never overwritten*'
  [IO.File]::ReadAllBytes($first.BackupPath).Length|Should -Be 3
 }
 It 'rejects plaintext and truncated inputs before creating backup storage' {
  [IO.File]::WriteAllBytes($source,[byte[]]::new(32))
  {& $scriptPath -SnapshotPath $source -BackupDirectory $destination}|Should -Throw '*backup failed*'
  Test-Path $destination|Should -BeFalse
 }
 It 'does not read input or create storage under WhatIf' {
  & $scriptPath -SnapshotPath (Join-Path $root missing) -BackupDirectory $destination -WhatIf
  Test-Path $destination|Should -BeFalse
 }
 It 'rejects broadly accessible source and destination directories' -Skip:($IsWindows) {
  [IO.File]::SetUnixFileMode($root,[IO.UnixFileMode]493)
  {& $scriptPath -SnapshotPath $source -BackupDirectory $destination}|Should -Throw '*backup failed*'
  [IO.File]::SetUnixFileMode($root,[IO.UnixFileMode]448)
  $null=[IO.Directory]::CreateDirectory($destination,[IO.UnixFileMode]493)
  {& $scriptPath -SnapshotPath $source -BackupDirectory $destination}|Should -Throw '*backup failed*'
 }
 It 'rejects symbolic backup directories' -Skip:($IsWindows) {
  $null=New-Item -ItemType SymbolicLink -Path $destination -Target $root
  {& $scriptPath -SnapshotPath $source -BackupDirectory $destination}|Should -Throw '*backup failed*'
 }
 It 'rejects symbolic source paths' -Skip:($IsWindows) {
  $link=Join-Path $root link.sealed
  $null=New-Item -ItemType SymbolicLink -Path $link -Target $source
  {& $scriptPath -SnapshotPath $link -BackupDirectory $destination}|Should -Throw '*backup failed*'
 }
}
