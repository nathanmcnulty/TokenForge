function Get-TokenForgeScopeCandidates {
    <#
    .SYNOPSIS
    Compare published scope hints, applicable tenant grants, and fresh observer coverage.
    .DESCRIPTION
    Read-only planning evidence, not proof of global first-party preauthorization. Only a
    successful silent explicit request establishes no interaction for that request.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Inventory,
        [Parameter(Mandatory)]$Database,
        [Parameter(Mandatory)][guid]$ResourceId,
        [Parameter(Mandatory)][ValidateCount(1,64)][string[]]$Scope,
        [Parameter(Mandatory)][ValidatePattern('^[a-f0-9]{64}$')][string]$PrincipalFingerprint,
        [ValidateRange(1,8760)][int]$MaxAgeHours=24
    )
    $inventoryJson=ConvertTo-TokenForgePlanningInventory $Inventory
    $databaseJson=ConvertTo-TokenForgePlanningDatabase $Database
    ConvertFrom-TokenForgePlanningResult ([TokenForge.Core.ScopePlanning]::Candidates($inventoryJson,$databaseJson,$ResourceId.ToString(),[string[]]$Scope,$PrincipalFingerprint,$MaxAgeHours,$null))
}
