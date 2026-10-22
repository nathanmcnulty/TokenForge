#Requires -Version 7.4
[CmdletBinding()]
param(
    [ValidateSet('Weekly', 'Native', 'Discovery', 'Collector', 'ReleaseGuards')]
    [string]$Preset = 'Weekly',
    [string]$NativeExecutable,
    [string]$ReportPath
)

$ErrorActionPreference = 'Stop'
if (-not $IsLinux) { throw 'This local validation runner supports Linux only.' }

$repo = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$sourceManifest = Join-Path $repo 'src/TokenForge/TokenForge.psd1'
$version = (Import-PowerShellDataFile -LiteralPath $sourceManifest).ModuleVersion
$summary = [ordered]@{
    preset = $Preset
    platform = 'linux'
    version = $version
    passed = 0
    failed = 0
    skipped = 0
    containersfailed = 0
    code = 'SetupFailed'
    failedTests = @()
}
$previousNative = $env:TOKENFORGE_TEST_NATIVE
$reportTarget = $null
$testPaths = @()

try {
    if (-not [string]::IsNullOrWhiteSpace($ReportPath)) {
        $reportTarget = [IO.Path]::GetFullPath($ReportPath)
        $reportEntry = [IO.FileInfo]::new($reportTarget)
        if ($null -ne $reportEntry.LinkTarget -or (Test-Path -LiteralPath $reportTarget)) { throw 'ReportPath already exists; reports are never overwritten.' }
        $parent = Split-Path -Parent $reportTarget
        if (-not (Test-Path -LiteralPath $parent -PathType Container)) { throw 'ReportPath parent directory must already exist.' }
        $cursor = Get-Item -LiteralPath $parent -Force
        while ($null -ne $cursor) {
            if ($cursor.LinkType) { throw 'ReportPath cannot be inside a linked directory.' }
            $cursor = if ($cursor.Parent) { Get-Item -LiteralPath $cursor.Parent.FullName -Force } else { $null }
        }
    }
    if ($Preset -in @('Weekly', 'Native', 'Discovery', 'Collector')) {
        if ([string]::IsNullOrWhiteSpace($NativeExecutable)) { throw 'NativeExecutable is required for the Weekly, Native, Discovery, and Collector presets.' }
        $exe = (Resolve-Path -LiteralPath $NativeExecutable).Path
        if (-not (Test-Path -LiteralPath $exe -PathType Leaf)) { throw 'NativeExecutable must be an existing Linux executable file.' }
        $executeBits = [IO.UnixFileMode]::UserExecute -bor [IO.UnixFileMode]::GroupExecute -bor [IO.UnixFileMode]::OtherExecute
        if (([IO.File]::GetUnixFileMode($exe) -band $executeBits) -eq 0) { throw 'NativeExecutable must have an execute permission bit.' }
        $packageRoot = Split-Path -Parent $exe
        $packagedManifest = Join-Path $packageRoot 'src/TokenForge/TokenForge.psd1'
        if (-not (Test-Path -LiteralPath $packagedManifest -PathType Leaf)) { throw 'The packaged TokenForge module manifest is missing.' }
        $packagedVersion = (Import-PowerShellDataFile -LiteralPath $packagedManifest).ModuleVersion
        if ($packagedVersion -cne $version) { throw 'The packaged TokenForge module version does not match the source module.' }
        $env:TOKENFORGE_TEST_NATIVE = $exe
        Import-Module $packagedManifest -Force -ErrorAction Stop
        Remove-Module TokenForge -ErrorAction SilentlyContinue
    }
    $testPaths = switch ($Preset) {
        'Weekly' {
            @('./tests/WeeklyCli.Tests.ps1', './tests/NativeWeekly.Tests.ps1', './tests/CiWeekly.Tests.ps1', './tests/CredentialBootstrap.Tests.ps1')
        }
        'Collector' { @('./tests/CollectorSafety.Tests.ps1', './tests/CollectorNativeSafety.Tests.ps1', './tests/OperationBudget.Tests.ps1', './tests/DiscoveryCandidate.Tests.ps1', './tests/DiscoveryCandidateNative.Tests.ps1', './tests/CollectorKill.Tests.ps1') }
        'Discovery' { @('./tests/DiscoveryRun.Tests.ps1', './tests/DiscoveryStatus.Tests.ps1', './tests/DiscoveryReport.Tests.ps1', './tests/DiscoveryBootstrap.Tests.ps1', './tests/InventoryCheckpoint.Tests.ps1', './tests/InventoryShape.Tests.ps1', './tests/ProbeReadBounds.Tests.ps1', './tests/RoleOrigin.Tests.ps1', './tests/ResearchCohort.Tests.ps1', './tests/ResearchChunkPending.Tests.ps1', './tests/PublicPermissions.Tests.ps1', './tests/PermissionIdentifiers.Tests.ps1', './tests/RegistrationResume.Tests.ps1') }
        'Native' {
            $workflow = Get-Content -LiteralPath (Join-Path $repo '.github/workflows/native.yml') -Raw
            $match = [regex]::Match($workflow, '(?m)^\s*\$result\s*=\s*Invoke-Pester\s+(.+?)\s+-PassThru\b')
            if (-not $match.Success) { throw 'The fixed Invoke-Pester path list was not found in native.yml.' }
            $paths = @($match.Groups[1].Value -split ',' | ForEach-Object { $_.Trim() })
            if (-not $paths.Count -or @($paths | Select-Object -Unique).Count -ne $paths.Count) { throw 'The native.yml Pester path list is empty or contains duplicates.' }
            foreach ($path in $paths) {
                if ($path -cnotmatch '^\./tests/[A-Za-z0-9_.-]+\.Tests\.ps1$' -or -not (Test-Path -LiteralPath (Join-Path $repo $path.Substring(2)) -PathType Leaf)) {
                    throw 'The native.yml Pester list contains a missing or disallowed test path.'
                }
            }
            $paths
        }
        'ReleaseGuards' { @('./tests/ReleaseSource.Tests.ps1', './tests/ReleaseAssets.Tests.ps1') }
    }

    Import-Module Pester -RequiredVersion 5.7.1 -ErrorAction Stop
    $summary.code = 'Ready'
} catch {
    $summary.code = 'SetupFailed'
}

try {
    if ($summary.code -eq 'SetupFailed') { throw 'setup failed' }
    $absoluteTestPaths = @($testPaths | ForEach-Object { [IO.Path]::GetFullPath((Join-Path $repo $_.Substring(2))) })
    $result = Invoke-Pester -Path $absoluteTestPaths -PassThru -Output None
    $summary.passed = [int]$result.PassedCount
    $summary.failed = [int]$result.FailedCount
    $summary.skipped = [int]$result.SkippedCount
    $summary.containersfailed = [int]$result.FailedContainersCount
    $allowedPaths = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    foreach ($path in $absoluteTestPaths) { $null = $allowedPaths.Add($path) }
    $locations = [Collections.Generic.List[object]]::new()
    $seenLocations = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    foreach ($failedTest in @($result.Failed)) {
        $file = $failedTest.ScriptBlock.Ast.Extent.File
        $line = $failedTest.ScriptBlock.Ast.Extent.StartLineNumber
        if ([string]::IsNullOrWhiteSpace($file) -or $line -lt 1) { continue }
        $fullFile = [IO.Path]::GetFullPath($file)
        if (-not $allowedPaths.Contains($fullFile)) { continue }
        $locationKey = "$([IO.Path]::GetFileName($fullFile))`:$line"
        if ($seenLocations.Add($locationKey)) {
            $locations.Add([pscustomobject]@{ file = [IO.Path]::GetFileName($fullFile); line = [int]$line })
            if ($locations.Count -ge 32) { break }
        }
    }
    $summary.failedTests = @($locations.ToArray())
    if (($summary.passed + $summary.failed + $summary.skipped) -eq 0) {
        $summary.code = 'NoTestsExecuted'
        $summary.failed = 1
    } elseif ($summary.failed -gt 0 -or $summary.containersfailed -gt 0 -or $summary.passed -eq 0) {
        $summary.code = 'TestsFailed'
    } else {
        $summary.code = 'Success'
    }
} catch {
    if ($summary.code -ne 'SetupFailed') { $summary.code = 'TestsFailed' }
    if ($summary.failed -eq 0 -and $summary.containersfailed -eq 0) { $summary.failed = 1 }
} finally {
    if ($null -eq $previousNative) { Remove-Item Env:TOKENFORGE_TEST_NATIVE -ErrorAction SilentlyContinue }
    else { $env:TOKENFORGE_TEST_NATIVE = $previousNative }
}

if ($null -ne $reportTarget -and $summary.code -ne 'SetupFailed') {
    try {
        $json = $summary | ConvertTo-Json -Compress
        $stream = [IO.File]::Open($reportTarget, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
        try {
            $bytes = [Text.UTF8Encoding]::new($false).GetBytes($json + [Environment]::NewLine)
            $stream.Write($bytes, 0, $bytes.Length)
        } finally { $stream.Dispose() }
    } catch {
        $summary.code = 'ReportWriteFailed'
        if ($summary.failed -eq 0) { $summary.failed = 1 }
    }
}
$json = $summary | ConvertTo-Json -Compress
Write-Output $json
if ($summary.code -ne 'Success') { exit 1 }
