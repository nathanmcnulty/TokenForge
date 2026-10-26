function New-TokenForgeStrictProfile {
    <# .SYNOPSIS
    Create a credential-free opt-in strict policy. Does not create or unlock a session.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][guid]$TenantId,[Parameter(Mandatory)][ValidatePattern('^[a-f0-9]{64}$')][string]$PrincipalFingerprint,
        [Parameter(Mandatory)][guid]$BootstrapClientId,[Parameter(Mandatory)][guid[]]$ApprovedClientId,
        [ValidateRange(0,64)][int]$MaxAdditionalScopes=0,[ValidateRange(0,64)][int]$MaxBootstrapAdditionalScopes=0,
        [ValidateRange(1,8760)][int]$MaxAgeHours=24,[ValidateRange(1,900)][int]$MaxSeconds=180)
    [TokenForge.Core.DiscoverySourceClaims]::ReadMetadataJson([TokenForge.Core.AdminWorkflows]::CreateStrictProfile($TenantId.ToString(),$PrincipalFingerprint,$BootstrapClientId.ToString(),[string[]]@($ApprovedClientId|ForEach-Object ToString),$MaxAdditionalScopes,$MaxBootstrapAdditionalScopes,$MaxAgeHours,$MaxSeconds))
}
function Get-TokenForgeToolExplanation {
    <# .SYNOPSIS
    Explain one declared tool from complete saved evidence; never authenticates.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Profile,[Parameter(Mandatory)]$Requirements,[Parameter(Mandatory)]$Inventory,[Parameter(Mandatory)]$Snapshot,
        [Parameter(Mandatory)][string]$ToolId,$PrerequisiteEvidence,[DateTimeOffset]$AsOf=[DateTimeOffset]::UtcNow)
    $pre=if($null -ne $PrerequisiteEvidence){ConvertTo-Json -InputObject $PrerequisiteEvidence -Depth 40 -Compress}else{[NullString]::Value}
    [TokenForge.Core.DiscoverySourceClaims]::ReadMetadataJson([TokenForge.Core.AdminWorkflows]::Explain((ConvertTo-Json -InputObject $Profile -Depth 40 -Compress),(ConvertTo-Json -InputObject $Requirements -Depth 40 -Compress),(ConvertTo-Json -InputObject $Inventory -Depth 40 -Compress),(ConvertTo-Json -InputObject $Snapshot -Depth 64 -Compress),$ToolId,$pre,$AsOf))
}
function Test-TokenForgeTool {
    <# .SYNOPSIS
    Report declared tool readiness from exact saved evidence, not arbitrary script text.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Profile,[Parameter(Mandatory)]$Requirements,[Parameter(Mandatory)]$Inventory,[Parameter(Mandatory)]$Snapshot,
        [Parameter(Mandatory)][string]$ToolId,$PrerequisiteEvidence,[DateTimeOffset]$AsOf=[DateTimeOffset]::UtcNow)
    $pre=if($null -ne $PrerequisiteEvidence){ConvertTo-Json -InputObject $PrerequisiteEvidence -Depth 40 -Compress}else{[NullString]::Value}
    [TokenForge.Core.DiscoverySourceClaims]::ReadMetadataJson([TokenForge.Core.AdminWorkflows]::Check((ConvertTo-Json -InputObject $Profile -Depth 40 -Compress),(ConvertTo-Json -InputObject $Requirements -Depth 40 -Compress),(ConvertTo-Json -InputObject $Inventory -Depth 40 -Compress),(ConvertTo-Json -InputObject $Snapshot -Depth 64 -Compress),$ToolId,$pre,$AsOf))
}
function Invoke-TokenForgeStrictAcquisition {
    <# .SYNOPSIS
    Attempt one explicitly approved silent request and optional declared read-only proof.
    .DESCRIPTION
    Requires a caller-supplied existing session. Prints only metadata and disposes acquired credentials.
    For owned in-process credential delivery use the shared AdminWorkflows.Acquire result API.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Profile,[Parameter(Mandatory)]$Requirements,[Parameter(Mandatory)]$Inventory,[Parameter(Mandatory)][string]$ToolId,
        [securestring]$EstsAuth,[ValidateSet('ESTSAUTH','ESTSAUTHPERSISTENT')][string]$CookieName='ESTSAUTH',
        [guid]$ClientId=[guid]::Empty,[ValidatePattern('^[a-f0-9]{64}$')][string]$CallbackFingerprint,[switch]$OperationCheck,$PrerequisiteEvidence,
        [Threading.CancellationToken]$CancellationToken=[Threading.CancellationToken]::None)
    $client=if($ClientId -ne [guid]::Empty){$ClientId.ToString()}else{[NullString]::Value}
    $callback=if($CallbackFingerprint){$CallbackFingerprint}else{[NullString]::Value}
    $pre=if($null -ne $PrerequisiteEvidence){ConvertTo-Json -InputObject $PrerequisiteEvidence -Depth 40 -Compress}else{[NullString]::Value}
    $result=[TokenForge.Core.AdminWorkflows]::Acquire((ConvertTo-Json -InputObject $Profile -Depth 40 -Compress),(ConvertTo-Json -InputObject $Requirements -Depth 40 -Compress),(ConvertTo-Json -InputObject $Inventory -Depth 40 -Compress),$ToolId,$EstsAuth,$CookieName,$client,$callback,$OperationCheck.IsPresent,$pre,$null,$null,$null,$CancellationToken)
    try{[TokenForge.Core.DiscoverySourceClaims]::ReadMetadataJson($result.ToJson())}finally{$result.Dispose()}
}
function New-TokenForgeToolChangePacket {
    <# .SYNOPSIS
    Recompute typed changes and prepare a bounded private-review packet; sends nothing.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Requirements,[Parameter(Mandatory)]$Before,[Parameter(Mandatory)]$After,
        [Parameter(Mandatory)][ValidatePattern('^([a-f0-9]{40}|[a-f0-9]{64})$')][string]$SourceRevision,
        [Parameter(Mandatory)][ValidatePattern('^[a-f0-9]{64}$')][string]$PackageManifestSha256,
        [ValidateRange(1,128)][int]$MaxEntries=64,[ValidateRange(1,87600)][int]$MaxAgeHours=24,[DateTimeOffset]$AsOf=[DateTimeOffset]::UtcNow,[switch]$SecuritySensitive)
    [TokenForge.Core.DiscoverySourceClaims]::ReadMetadataJson([TokenForge.Core.AdminWorkflows]::PreparePacket((ConvertTo-Json -InputObject $Requirements -Depth 40 -Compress),(ConvertTo-Json -InputObject $Before -Depth 64 -Compress),(ConvertTo-Json -InputObject $After -Depth 64 -Compress),$SourceRevision,$PackageManifestSha256,$MaxEntries,$MaxAgeHours,$AsOf,$SecuritySensitive.IsPresent))
}

function ConvertTo-TokenForgeToolEvidence {
    <# .SYNOPSIS
    Convert sanitized strict-acquisition metadata to the existing typed saved-evidence format.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Acquisition)
    [TokenForge.Core.DiscoverySourceClaims]::ReadMetadataJson([TokenForge.Core.AdminWorkflows]::AcquisitionEvidence((ConvertTo-Json -InputObject $Acquisition -Depth 64 -Compress)))
}
