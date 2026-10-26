#Requires -Version 7.6
$ErrorActionPreference = 'Stop'
Import-Module Pester -RequiredVersion 6.2.0 -ErrorAction Stop
Write-Host ("Selected runtime: PowerShell {0}; {1}; Pester {2}" -f $PSVersionTable.PSVersion, [Runtime.InteropServices.RuntimeInformation]::FrameworkDescription, (Get-Module Pester).Version)
$manifest = Join-Path $PSScriptRoot '../src/TokenForge/TokenForge.psd1'
$null = Test-ModuleManifest $manifest
if ($env:TOKENFORGE_TEST_NATIVE) {
    # Establish the explicit package's credential types before source imports.
    # Source-only bootstrap is exercised separately in fresh-process tests.
    $package = Split-Path (Resolve-Path -LiteralPath $env:TOKENFORGE_TEST_NATIVE).Path -Parent
    $packagedManifest = Join-Path $package 'src/TokenForge/TokenForge.psd1'
    if ((Import-PowerShellDataFile $packagedManifest).ModuleVersion -cne (Import-PowerShellDataFile $manifest).ModuleVersion) { throw 'Test package version differs from source.' }
    if (-not (Test-Path -LiteralPath (Join-Path $package 'src/TokenForge/lib/net10.0/TokenForge.Credentials.dll') -PathType Leaf)) { throw 'A matching .NET 10 package is required.' }
    Import-Module $packagedManifest -Force -ErrorAction Stop
    Remove-Module TokenForge
}
$result = Invoke-Pester -Path (Join-Path $PSScriptRoot '../tests') -PassThru -Output Detailed
if ($result.FailedCount -gt 0 -or $result.FailedContainersCount -gt 0 -or $result.PassedCount -eq 0) { exit 1 }
