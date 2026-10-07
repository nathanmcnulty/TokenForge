#Requires -Version 7.4
<# .SYNOPSIS
Keep an immutable local copy of an encrypted maintenance snapshot.
.DESCRIPTION
Copies ciphertext only. SHA-256 identifies the saved bytes; authentication and
account checks still happen during maintenance restoration. Keep the encryption
key separately. Backup storage must be a private local filesystem directory.
#>
[CmdletBinding(SupportsShouldProcess)]
param([Parameter(Mandatory)][string]$SnapshotPath,[Parameter(Mandatory)][string]$BackupDirectory)
$ErrorActionPreference='Stop'
if(-not $PSCmdlet.ShouldProcess($BackupDirectory,'Save an immutable encrypted maintenance backup')){return}
$module=Import-Module (Join-Path $PSScriptRoot '../src/TokenForge/TokenForge.psd1') -Force -PassThru
$temporary=$null;$stream=$null;$inputStream=$null;$blob=$null
try{
 $source=& $module {param($path) Resolve-TokenForgeVaultPath $path} $SnapshotPath
 $inputStream=[IO.File]::OpenRead($source)
 if($inputStream.Length -le 29 -or $inputStream.Length -gt 134217757){throw 'Invalid encrypted snapshot size.'}
 $blob=[byte[]]::new([int]$inputStream.Length)
 $inputStream.ReadExactly($blob,0,$blob.Length)
 if($inputStream.ReadByte() -ne -1){throw 'Snapshot changed during backup.'}
 $inputStream.Dispose();$inputStream=$null
 if($blob.Length -le 29 -or $blob.Length -gt 134217757 -or $blob[0] -ne 1){throw 'Invalid encrypted snapshot format.'}
 $hash=[Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($blob)).ToLowerInvariant()
 $target=& $module {param($path) Resolve-TokenForgeVaultPath $path -CreateDirectory} (Join-Path $BackupDirectory "$hash.sealed")
 $exists=[IO.File]::Exists($target)
 if($exists){
  # Never overwrite a prior backup, including corrupt data at the expected name.
  $stored=Get-Item -LiteralPath $target -Force
  if($stored.Length -ne $blob.Length -or (Get-FileHash -LiteralPath $target -Algorithm SHA256).Hash.ToLowerInvariant() -cne $hash){throw 'Existing backup does not match its content identity.'}
 }else{
  $temporary=& $module {param($path) Resolve-TokenForgeVaultPath $path} (Join-Path ([IO.Path]::GetDirectoryName($target)) ('.backup-'+[guid]::NewGuid()+'.tmp'))
  $stream=& $module {param($path) Open-TokenForgeVaultFile $path -Create} $temporary
  $stream.Write($blob,0,$blob.Length);$stream.Flush($true);$stream.Dispose();$stream=$null
  [IO.File]::Move($temporary,$target,$false);$temporary=$null
 }
 [pscustomobject]@{Saved=(-not $exists);AlreadyExists=$exists;Sha256=$hash;Bytes=$blob.Length;BackupPath=$target;Authenticated=$false}
}catch{throw 'Encrypted maintenance backup failed; details suppressed. Existing backups are never overwritten.'}
finally{
 if($stream){$stream.Dispose()}
 if($inputStream){$inputStream.Dispose()}
 if($temporary -and [IO.File]::Exists($temporary)){[IO.File]::Delete($temporary)}
 if($blob){[Security.Cryptography.CryptographicOperations]::ZeroMemory($blob)}
}
