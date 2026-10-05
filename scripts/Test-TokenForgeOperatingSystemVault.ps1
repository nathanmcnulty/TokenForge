#Requires -Version 7.4
[CmdletBinding()]
param([string]$Dotnet='dotnet')
$ErrorActionPreference='Stop'
$repo=Split-Path $PSScriptRoot -Parent
& $Dotnet run --project (Join-Path $repo 'native/TokenForge.Core.Tests') --no-restore -- --os-store
if($LASTEXITCODE){throw 'Synthetic platform-store checks failed.'}
Import-Module (Join-Path $repo 'src/TokenForge/TokenForge.psd1') -Force
$root=Join-Path ([IO.Path]::GetTempPath()) ('TokenForge-os-fixture-'+[guid]::NewGuid())
$password=$null
try{
    $null=New-TokenForgeProfile fixture example.test -Root $root -Storage OperatingSystem
    $record=& (Get-Module TokenForge) {param($root) Read-TokenForgeProfile fixture $root} $root
    # Synthetic key/vault setup only; no inventory or authentication/network call is needed.
    $password=& (Get-Module TokenForge) {param($record) Open-TokenForgeProfilePlatformKey $record -Create} $record
    $null=New-TokenForgeVault $record.VaultPath $password
    $before=(Get-FileHash -LiteralPath $record.VaultPath).Hash
    & (Get-Module TokenForge) {param($record) Remove-TokenForgeProfilePlatformKey $record} $record
    $failedClosed=$false
    try{$null=Connect-TokenForgeProfile fixture -Root $root}catch{$failedClosed=$_.Exception.Message -match 'Operating-system vault key unavailable'}
    if(-not $failedClosed -or (Get-FileHash -LiteralPath $record.VaultPath).Hash -ne $before){throw 'Missing-key recovery changed the vault or failed to stop before authentication.'}
    $keyStillAbsent=$false
    try{$opened=& (Get-Module TokenForge) {param($record) Open-TokenForgeProfilePlatformKey $record} $record; $opened.Dispose()}catch{$keyStillAbsent=$_.Exception.Message -match 'Operating-system vault key unavailable'}
    if(-not $keyStillAbsent){throw 'A missing key was recreated for an existing vault.'}
    $removed=Remove-TokenForgeProfileKey fixture -Root $root
    if(-not $removed.VaultRemoved -or -not $removed.KeyRemoved){throw 'Synthetic fixture cleanup failed.'}
    Write-Output 'Synthetic profile missing-key/ciphertext-preservation checks passed.'
    if($IsLinux){
        $lockedKey=& (Get-Module TokenForge) {param($record) Open-TokenForgeProfilePlatformKey $record -Create} $record
        $lockedKey.Dispose()
        $lockResult=& gdbus call --session --dest org.freedesktop.secrets --object-path /org/freedesktop/secrets --method org.freedesktop.Secret.Service.Lock "['/org/freedesktop/secrets/collection/login']"
        if($LASTEXITCODE -or ($lockResult -join '') -notmatch '/org/freedesktop/secrets/collection/login'){throw 'Synthetic collection locking failed.'}
        $partial=Remove-TokenForgeProfileKey fixture -Root $root
        if($partial.KeyRemoved){throw 'Locked-item deletion was incorrectly reported as successful.'}
        Write-Output 'Synthetic locked-item deletion reports a retryable failure.'
        $lockedFailure=$false
        try{$unexpected=& (Get-Module TokenForge) {param($record) Open-TokenForgeProfilePlatformKey $record -Create} $record; $unexpected.Dispose()}catch{$lockedFailure=$_.Exception.Message -match 'Operating-system vault key unavailable'}
        if(-not $lockedFailure){throw 'A locked synthetic key was replaced or unexpectedly unlocked.'}
        Write-Output 'Synthetic locked-key acquisition fails without replacement.' 
        # The isolated keyring fixture is deleted by the Linux harness after this process exits.
    }
}finally{
    if($password){$password.Dispose()}
    try{$null=Remove-TokenForgeProfileKey fixture -Root $root}catch{}
    if(Test-Path -LiteralPath $root){Remove-Item -LiteralPath $root -Recurse -Force}
}
