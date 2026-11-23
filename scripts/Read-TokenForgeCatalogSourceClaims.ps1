[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$Name,
    [Parameter(Mandatory)][string]$CapturePath,
    [Parameter(Mandatory)][string]$Sha256,
    [Parameter(Mandatory)][string]$NativeExecutablePath
)
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'TokenForgePublicHealth.ps1')
if ($Name -cnotin $script:HealthSources.Keys) { throw 'Unrecognized public source.' }

$bytes = Read-TokenForgeHealthBytes $CapturePath $script:HealthLimits.SourceBytes
if ((Get-TokenForgeHealthHash $bytes) -cne $Sha256) { throw 'Capture digest mismatch.' }
Initialize-TokenForgeHealthRuntime $NativeExecutablePath
$data = Read-TokenForgeHealthJson $bytes
if ($Name -ceq 'microsoftApps') {
    $data = (ConvertTo-TokenForgeHealthMicrosoftApps $data $Sha256).Records
}
$null = Assert-TokenForgeHealthSource $Name $data
$catalogPath = [IO.Path]::GetTempFileName()
try {
    $projection = Invoke-TokenForgeHealthProjection -Data @{$Name = $data} -CatalogPath $catalogPath -Now '2000-01-01T00:00:00Z'
    if (-not $projection.Valid) { throw 'Public source projection failed.' }
    $rows = [ordered]@{}
    foreach ($row in $projection.Discovery.Applications) {
        $rows[$row.AppId] = @($row.SourceClaims)
    }
    ConvertTo-Json -InputObject $rows -Depth 32 -Compress
} finally {
    if (Test-Path -LiteralPath $catalogPath) { Remove-Item -LiteralPath $catalogPath -Force }
}
