#Requires -Version 7.6
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$CatalogRepository,
    [Parameter(Mandatory)][ValidatePattern('\A[0-9a-f]{40}\z')][string]$CatalogCommit
)
$PSDefaultParameterValues = @{ Disabled = $true }
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function ConvertTo-ObservedGuid($Value) {
    $parsed = [guid]::Empty
    if ($Value -is [string] -and [guid]::TryParseExact($Value, 'D', [ref]$parsed) -and $parsed -ne [guid]::Empty) {
        return $parsed.ToString()
    }
}

function Read-LocalCatalogGit([string[]]$Arguments) {
    $info = [Diagnostics.ProcessStartInfo]::new()
    $info.FileName = 'git'
    $info.UseShellExecute = $false
    $info.RedirectStandardOutput = $true
    $info.RedirectStandardError = $true
    $info.StandardOutputEncoding = [Text.UTF8Encoding]::new($false,$true)
    $info.Environment['GIT_NO_LAZY_FETCH'] = '1'
    $info.Environment['GIT_ALLOW_PROTOCOL'] = ''
    $info.Environment['GIT_TERMINAL_PROMPT'] = '0'
    foreach ($argument in (@('--no-replace-objects','-c','protocol.allow=never','-C',$CatalogRepository) + $Arguments)) {
        $info.ArgumentList.Add($argument)
    }
    $process = [Diagnostics.Process]::Start($info)
    try {
        $output = $process.StandardOutput.ReadToEndAsync()
        $diagnostics = $process.StandardError.ReadToEndAsync()
        if (-not $process.WaitForExit(30000)) {
            $process.Kill($true)
            throw 'Local Git catalog read timed out.'
        }
        if ($process.ExitCode -ne 0) { throw 'Pinned catalog objects must be available locally.' }
        $null = $diagnostics.GetAwaiter().GetResult()
        return $output.GetAwaiter().GetResult()
    } finally { $process.Dispose() }
}

$objectType = Read-LocalCatalogGit @('cat-file','-t',$CatalogCommit)
if ($objectType.Trim() -cne 'commit') { throw 'The pinned catalog object must be a Git commit.' }
$known = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
foreach ($file in @('applications.json','applications.non-verified.json')) {
    $text = Read-LocalCatalogGit @('cat-file','blob',"${CatalogCommit}:$file")
    $catalog = $text | ConvertFrom-Json -AsHashtable -DateKind String
    $format = if ($file -eq 'applications.json') { 'TokenForgeApplicationMetadata' } else { 'TokenForgeNonVerifiedApplications' }
    $schema = if ($file -eq 'applications.json') { 2 } else { 1 }
    if ($catalog['Format'] -cne $format -or $catalog['SchemaVersion'] -ne $schema -or
        $catalog['Applications'] -isnot [Collections.IDictionary]) { throw 'Unexpected catalog format.' }
    foreach ($key in $catalog.Applications.Keys) {
        $id = ConvertTo-ObservedGuid $key
        if (-not $id -or $id -cne $key -or -not $known.Add($id)) { throw 'Malformed or overlapping catalog partitions.' }
    }
}
return ,$known
