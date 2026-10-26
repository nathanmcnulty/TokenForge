function ConvertTo-TokenForgeChangeSnapshot {
    <# .SYNOPSIS
    Normalize an explicit saved evidence document; missing legacy context remains unknown.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)]$InputObject,
        [ValidateSet('Snapshot','PublicPermissions','Discovery','Inventory','ScopeDatabase','FlowEvidence','Anonymous','ApiChecks','Maintenance')][string]$Kind='Snapshot')
    $json=ConvertTo-Json -InputObject $InputObject -Depth 64 -Compress
    [TokenForge.Core.DiscoverySourceClaims]::ReadMetadataJson([TokenForge.Core.ChangeReports]::Normalize($Kind,$json))
}

function Compare-TokenForgeEvidence {
    <# .SYNOPSIS
    Compare explicit saved evidence without authentication or requests.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Before,[Parameter(Mandatory)]$After,
        [ValidateSet('Snapshot','PublicPermissions','Discovery','Inventory','ScopeDatabase','FlowEvidence','Anonymous','ApiChecks','Maintenance')][string]$Kind='Snapshot',
        [ValidateRange(1,87600)][int]$MaxAgeHours=24,[DateTimeOffset]$AsOf=[DateTimeOffset]::UtcNow,[switch]$PublicOnly)
    [TokenForge.Core.DiscoverySourceClaims]::ReadMetadataJson([TokenForge.Core.ChangeReports]::CompareSaved($Kind,(ConvertTo-Json -InputObject $Before -Depth 64 -Compress),(ConvertTo-Json -InputObject $After -Depth 64 -Compress),$MaxAgeHours,$AsOf,$PublicOnly.IsPresent))
}

function Get-TokenForgeChangeReport {
    <# .SYNOPSIS
    Read two bounded private JSON files and report typed observed changes.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$BeforePath,[Parameter(Mandatory)][string]$AfterPath,
        [ValidateSet('Snapshot','PublicPermissions','Discovery','Inventory','ScopeDatabase','FlowEvidence','Anonymous','ApiChecks','Maintenance')][string]$Kind='Snapshot',
        [ValidateRange(1,87600)][int]$MaxAgeHours=24,[DateTimeOffset]$AsOf=[DateTimeOffset]::UtcNow,[switch]$PublicOnly)
    $before=[TokenForge.Core.ChangeReportFiles]::Read($ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($BeforePath))
    $after=[TokenForge.Core.ChangeReportFiles]::Read($ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($AfterPath))
    [TokenForge.Core.DiscoverySourceClaims]::ReadMetadataJson([TokenForge.Core.ChangeReports]::CompareSaved($Kind,$before,$after,$MaxAgeHours,$AsOf,$PublicOnly.IsPresent))
}
