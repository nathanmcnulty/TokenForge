#Requires -Version 7.4
[CmdletBinding()]
param([string]$Dotnet='dotnet',[string]$NativeExecutablePath)
$ErrorActionPreference='Stop'
$repo=Split-Path $PSScriptRoot -Parent
& $Dotnet run --project (Join-Path $repo 'native/TokenForge.Core.Tests') --no-restore -- --os-store
if($LASTEXITCODE){throw 'Synthetic platform-store checks failed.'}
Import-Module (Join-Path $repo 'src/TokenForge/TokenForge.psd1') -Force
$root=Join-Path ([IO.Path]::GetTempPath()) ('TokenForge-os-fixture-'+[guid]::NewGuid())
$password=$null
function Invoke-NativeFixtureForget([string]$Name='fixture',[int]$ExpectedExit=0,[switch]$Partial) {
    $start=[Diagnostics.ProcessStartInfo]::new($NativeExecutablePath)
    $start.UseShellExecute=$false;$start.RedirectStandardOutput=$true;$start.RedirectStandardError=$true
    $start.Environment['PATH']=Join-Path $root no-pwsh
    foreach($argument in @('profile','forget-key','--profile',$Name,'--root',$root,'--json')){$start.ArgumentList.Add($argument)}
    $process=[Diagnostics.Process]::Start($start)
    try{
        $output=$process.StandardOutput.ReadToEndAsync();$errors=$process.StandardError.ReadToEndAsync()
        if(-not $process.WaitForExit(20000)){$process.Kill($true);throw 'Native synthetic deletion timed out.'}
        if($process.ExitCode -ne $ExpectedExit){throw 'Native synthetic deletion returned an unexpected exit code.'}
        $text=$output.GetAwaiter().GetResult();$errorText=$errors.GetAwaiter().GetResult()
        if($ExpectedExit -eq 0 -or $Partial){
            if($errorText){throw 'Native synthetic deletion returned unexpected diagnostics.'}
            $result=$text|ConvertFrom-Json
            if($result.Profile -ne $Name -or -not $result.VaultRemoved -or $result.KeyRemoved -eq [bool]$Partial -or $result.Evidence -ne 'LocalDeletionNotServerRevocation'){throw 'Native synthetic deletion metadata mismatched.'}
            return $result
        }
        if($text -or ($errorText|ConvertFrom-Json).Code -ne 'OperationFailed'){throw 'Native synthetic lock failure was not sanitized.'}
    }finally{$process.Dispose()}
}
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
    if($NativeExecutablePath){
        $null=New-TokenForgeProfile nativefixture example.test -Root $root -Storage OperatingSystem
        $nativeRecord=& (Get-Module TokenForge) {param($root) Read-TokenForgeProfile nativefixture $root} $root
        $legacyHandle=& (Get-Module TokenForge) {param($record) $directory=[IO.Path]::GetFullPath($record.Directory);if($IsWindows){$directory=$directory.ToLowerInvariant()};Get-TokenForgeFingerprint ($directory+'|'+$record.Configuration.KeyId)} $nativeRecord
        if([TokenForge.Core.V0230.ProfileKeyIdentity]::Compute($nativeRecord.Directory,$nativeRecord.Configuration.KeyId) -ne $legacyHandle){throw 'Shared key identity differs from the legacy binding.'}
        $nativePassword=[TokenForge.Core.V0110.PlatformVaultKey]::Open($legacyHandle,$true)
        try{$null=New-TokenForgeVault $nativeRecord.VaultPath $nativePassword}finally{$nativePassword.Dispose()}
        $nativeBefore=(Get-FileHash $nativeRecord.VaultPath).Hash
        foreach($leaf in @('.operation.lock','session.tfvault.lock')){
            $held=[IO.FileStream]::new((Join-Path $nativeRecord.Directory $leaf),[IO.FileMode]::Open,[IO.FileAccess]::ReadWrite,[IO.FileShare]::None)
            try{$null=Invoke-NativeFixtureForget nativefixture 1}finally{$held.Dispose()}
            if((Get-FileHash $nativeRecord.VaultPath).Hash -ne $nativeBefore){throw 'Native lock conflict changed synthetic ciphertext.'}
        }
        $null=Invoke-NativeFixtureForget nativefixture
        if(Test-Path $nativeRecord.VaultPath){throw 'Native synthetic deletion left ciphertext.'}
        $absent=$false
        try{$unexpected=[TokenForge.Core.V0110.PlatformVaultKey]::Open($legacyHandle,$false);$unexpected.Dispose()}catch{$absent=$_.Exception.Message -match 'Operating-system vault key unavailable'}
        if(-not $absent){throw 'Native synthetic deletion left its OS key.'}
        $null=Invoke-NativeFixtureForget nativefixture
        Write-Output 'Native synthetic key deletion works without PowerShell on PATH, shares locks and key identity, and is idempotent.'
    }
    if($IsLinux){
        $lockedKey=& (Get-Module TokenForge) {param($record) Open-TokenForgeProfilePlatformKey $record -Create} $record
        $lockedKey.Dispose()
        $lockResult=& gdbus call --session --dest org.freedesktop.secrets --object-path /org/freedesktop/secrets --method org.freedesktop.Secret.Service.Lock "['/org/freedesktop/secrets/collection/login']"
        if($LASTEXITCODE -or ($lockResult -join '') -notmatch '/org/freedesktop/secrets/collection/login'){throw 'Synthetic collection locking failed.'}
        $partial=Remove-TokenForgeProfileKey fixture -Root $root
        if($partial.KeyRemoved){throw 'Locked-item deletion was incorrectly reported as successful.'}
        if($NativeExecutablePath){$null=Invoke-NativeFixtureForget fixture 1 -Partial;Write-Output 'Native locked-item deletion preserves retry metadata and exit code 1 without PowerShell on PATH.'}
        $cliResult=& pwsh -NoProfile -File (Join-Path $PSScriptRoot 'tokenforge.ps1') -Command profile -Operation forget-key -Profile fixture -Root $root -Json
        if($LASTEXITCODE -ne 1 -or ($cliResult|ConvertFrom-Json).KeyRemoved){throw 'CLI partial deletion must retain its metadata and return a failure exit code.'}
        Write-Output 'Synthetic locked-item deletion reports a retryable failure and CLI exit code 1.'
        $lockedFailure=$false
        try{$unexpected=& (Get-Module TokenForge) {param($record) Open-TokenForgeProfilePlatformKey $record -Create} $record; $unexpected.Dispose()}catch{$lockedFailure=$_.Exception.Message -match 'Operating-system vault key unavailable'}
        if(-not $lockedFailure){throw 'A locked synthetic key was replaced or unexpectedly unlocked.'}
        Write-Output 'Synthetic locked-key acquisition fails without replacement.'
        # The isolated keyring fixture is deleted by the Linux harness after this process exits.
    }
}finally{
    if($password){$password.Dispose()}
    try{$null=Remove-TokenForgeProfileKey fixture -Root $root}catch{}
    if($NativeExecutablePath){try{$null=Remove-TokenForgeProfileKey nativefixture -Root $root}catch{}}
    if(Test-Path -LiteralPath $root){Remove-Item -LiteralPath $root -Recurse -Force}
}
