[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$SnapshotPath,
    [Parameter(Mandatory)][guid]$TenantId,
    [Parameter(Mandatory)][string]$ExpectedAccount,
    [Parameter(Mandatory)][string]$StateRoot
)

$ErrorActionPreference='Stop'
if (-not $IsLinux) { throw 'This private app-addability runner is limited to the Linux operator environment.' }
. "$PSScriptRoot/TokenForgeAppAddability.ps1"
Import-Module Microsoft.Graph.Authentication -ErrorAction Stop

$repoRoot=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$stateRootFull=[IO.Path]::GetFullPath($StateRoot)
$repoPrefix=$repoRoot.TrimEnd([IO.Path]::DirectorySeparatorChar)+[IO.Path]::DirectorySeparatorChar
if ($stateRootFull.Equals($repoRoot,[StringComparison]::Ordinal) -or $stateRootFull.StartsWith($repoPrefix,[StringComparison]::Ordinal)) { throw 'StateRoot must remain outside the Git worktree.' }
if (-not (Test-Path -LiteralPath $SnapshotPath -PathType Leaf)) { throw 'SnapshotPath must identify the pinned public catalog file.' }
$snapshotFull=(Resolve-Path -LiteralPath $SnapshotPath).Path
$snapshotBytes=[IO.File]::ReadAllBytes($snapshotFull)
$snapshotSha=[Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($snapshotBytes)).ToLowerInvariant()
if ($snapshotSha -cne '930413f4bef996dfa2b4dc6257ddabc77896de9a443d0ad693aea47e1510910b') { throw 'SnapshotPath does not match the pinned 5,470-ID source.' }
$snapshot=[Text.Encoding]::UTF8.GetString($snapshotBytes) | ConvertFrom-Json -AsHashtable -ErrorAction Stop
$applications=Get-AppAddabilityValue $snapshot 'Applications'
if ($applications -isnot [Collections.IDictionary] -or $applications.Count -ne 5470) { throw 'The pinned snapshot must contain exactly 5,470 application IDs.' }

if (-not [IO.Directory]::Exists($stateRootFull)) { [IO.Directory]::CreateDirectory($stateRootFull)|Out-Null }
[IO.File]::SetUnixFileMode($stateRootFull,[IO.UnixFileMode]::UserRead -bor [IO.UnixFileMode]::UserWrite -bor [IO.UnixFileMode]::UserExecute)
$checkpointPath=Join-Path $stateRootFull 'checkpoint.json'
if ([IO.File]::Exists($checkpointPath)) {
    $state=Get-Content -LiteralPath $checkpointPath -Raw | ConvertFrom-Json -AsHashtable -ErrorAction Stop
    if ($state.Format -cne 'TokenForgeAppAddabilityCheckpoint' -or $state.SchemaVersion -ne 1) { throw 'Checkpoint format is not supported.' }
    if ([guid]$state.TenantId -ne $TenantId) { throw 'Checkpoint tenant does not match the requested lab tenant.' }
    if ([string]$state.ExpectedAccount -ine $ExpectedAccount) { throw 'Checkpoint account does not match the authorized account.' }
    if ([string]$state.SnapshotSha256 -cne $snapshotSha) { throw 'Checkpoint snapshot hash does not match SnapshotPath.' }
} else {
    $state=New-AppAddabilityCheckpoint $applications $snapshotSha $TenantId $ExpectedAccount
    Save-AppAddabilityCheckpoint $state $checkpointPath
}

$request={ param($Method,$AppId) Invoke-AppAddabilityGraphRequest -Method $Method -AppId $AppId -TenantId $TenantId -ExpectedAccount $ExpectedAccount }.GetNewClosure()
$result=Invoke-AppAddabilityCatalog -State $state -CheckpointPath $checkpointPath -TenantId $TenantId -ExpectedAccount $ExpectedAccount -Request $request
$result
