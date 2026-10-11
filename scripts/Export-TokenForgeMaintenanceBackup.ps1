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
$null=Import-Module (Join-Path $PSScriptRoot '../src/TokenForge/TokenForge.psd1') -Force
[TokenForge.Core.MaintenanceBackup]::Save($SnapshotPath,$BackupDirectory)
