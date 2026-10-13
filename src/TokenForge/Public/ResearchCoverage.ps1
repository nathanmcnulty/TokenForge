function Get-TokenForgeResearchCoverage {
    <# .SYNOPSIS
    Categorize catalog evidence and exact flow-plan coverage without authenticating or authorizing anything.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$MetadataPath,[string]$FlowPath,[string]$NativeExecutablePath,
        [ValidatePattern('^[a-f0-9]{64}$')][string]$TenantFingerprint,
        [ValidatePattern('^[a-f0-9]{64}$')][string]$PrincipalFingerprint,
        [guid[]]$AppId,[ValidateRange(1,8760)][int]$MaxAgeHours=24,[switch]$SummaryOnly
    )
    if([bool]$TenantFingerprint -ne [bool]$PrincipalFingerprint){throw 'Select both tenant and principal for account-specific flow coverage.'}
    # Validate all history before deriving a current report; never prefilter attempts.
    if(-not (Test-Path -LiteralPath $MetadataPath -PathType Leaf)){throw 'Research metadata does not exist.'}
    $catalog=Get-TokenForgeApplicationMetadata $MetadataPath -NativeExecutablePath $NativeExecutablePath
    if($FlowPath -and -not (Test-Path -LiteralPath $FlowPath -PathType Leaf)){throw 'Explicit flow evidence does not exist.'}
    $flows=if($FlowPath -and (Test-Path -LiteralPath $FlowPath -PathType Leaf)){Get-TokenForgeFlowEvidence $FlowPath -NativeExecutablePath $NativeExecutablePath}else{$null}
    $flowJson=if($flows){$flows|ConvertTo-Json -Depth 20 -Compress}else{$null}
    $ids=if($AppId){[string[]]@($AppId|ForEach-Object ToString)}else{$null}
    $report=[TokenForge.Core.ResearchCoverage]::CreateFromValidatedDocuments(
        ($catalog|ConvertTo-Json -Depth 100 -Compress),$flowJson,
        $(if($TenantFingerprint){$TenantFingerprint}else{$null}),
        $(if($PrincipalFingerprint){$PrincipalFingerprint}else{$null}),$ids,$MaxAgeHours,[bool]$SummaryOnly,$null
    )
    [pscustomobject][TokenForge.Core.DiscoverySourceClaims]::ReadMetadataJson($report)
}
