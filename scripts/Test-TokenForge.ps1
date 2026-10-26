#Requires -Version 7.6
$ErrorActionPreference = 'Stop'
Import-Module Pester -RequiredVersion 6.2.0 -ErrorAction Stop
$manifest = Join-Path $PSScriptRoot '../src/TokenForge/TokenForge.psd1'
$null = Test-ModuleManifest $manifest
$result = Invoke-Pester -Path (Join-Path $PSScriptRoot '../tests') -PassThru -Output Detailed
if ($result.FailedCount -gt 0 -or $result.FailedContainersCount -gt 0 -or $result.PassedCount -eq 0) { exit 1 }
