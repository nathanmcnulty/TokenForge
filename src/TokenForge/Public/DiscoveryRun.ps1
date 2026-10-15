function Invoke-TokenForgeDiscoveryRun {
    <# .SYNOPSIS
    Run or resume bounded discovery chunks using transactional SQLite checkpoints.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]$Inventory,
        [Parameter(Mandatory)][securestring]$EstsAuth,
        [Parameter(Mandatory)][string]$StatePath,
        [Parameter(Mandatory)][string]$NativeExecutablePath,
        [switch]$NewRun,[switch]$GraphOnly,
        [ValidateRange(1,1000)][int]$BatchSize=25,
        [ValidateRange(1,1000)][int]$MaxRedirects=8,
        [ValidateRange(1,100000)][int]$MaxChunks=100000,
        [ValidateRange(1,10080)][int]$MaxMinutes=60,
        [switch]$ExploreAllFlows=$true
    )
    if(-not $PSCmdlet.ShouldProcess($StatePath,'Run resumable discovery with existing authorization')){return}
    $root=Split-Path (Resolve-TokenForgeVaultPath (Join-Path $StatePath '.state') -CreateDirectory) -Parent
    $manifest=Join-Path $root 'discovery-run.json'
    $database=Join-Path $root 'scopes.sqlite';$flows=Join-Path $root 'flows.sqlite';$metadata=Join-Path $root 'applications.sqlite'
    $lock=$null;$timer=[Diagnostics.Stopwatch]::StartNew();$chunks=0
    try {
        $lockPath=Resolve-TokenForgeVaultPath (Join-Path $root '.writer.lock') -CreateDirectory
        $lock=if(Test-Path -LiteralPath $lockPath){Open-TokenForgeVaultFile $lockPath}else{Open-TokenForgeVaultFile $lockPath -Create}
        if((Test-Path -LiteralPath $manifest) -and -not $NewRun){
            $file=Get-Item -LiteralPath (Resolve-TokenForgeVaultPath $manifest)
            if($file.Length -gt 1024){throw 'Invalid discovery run manifest.'}
            $saved=[TokenForge.Core.DiscoverySourceClaims]::ReadMetadataJson((Get-Content -LiteralPath $file.FullName -Raw))
            if($saved.Count -ne 2 -or -not $saved.Contains('SchemaVersion') -or -not $saved.Contains('CohortId') -or $saved.SchemaVersion -ne 1 -or $saved.CohortId -cnotmatch '^[a-f0-9]{64}$'){throw 'Invalid discovery run manifest.'}
            $cohort=Get-TokenForgeResearchCohort -DatabasePath $database -CohortId $saved.CohortId -NativeExecutablePath $NativeExecutablePath
        }else{
            $cohort=New-TokenForgeResearchCohort -Inventory $Inventory -DatabasePath $database -GraphOnly:$GraphOnly -BatchSize $BatchSize -MaxRedirects $MaxRedirects -ExploreAllFlows:$ExploreAllFlows -NativeExecutablePath $NativeExecutablePath -Confirm:$false
            Save-TokenForgeDocument -Path $manifest -Document @{SchemaVersion=1;CohortId=$cohort.PlanId}
        }
        $recipe=$cohort.Cohort
        $inventoryHash=Get-TokenForgeFingerprint (ConvertTo-Json -InputObject @($Inventory.Applications|Sort-Object {[string]$_.AppId}) -Depth 32 -Compress)
        if($Inventory.TenantFingerprint -cne $recipe.TenantFingerprint -or $Inventory.PrincipalFingerprint -cne $recipe.PrincipalFingerprint -or $inventoryHash -cne $recipe.InventoryHash -or $Inventory.DiscoveryCatalogHash -cne $recipe.CatalogHash){throw 'Inventory differs from the frozen cohort. Create a new run after reviewing refreshed metadata.'}
        $reason='Complete';$pending=$cohort.Pending.Count
        while($pending){
            if($chunks -ge $MaxChunks -or $timer.Elapsed.TotalMinutes -ge $MaxMinutes){$reason='BudgetReached';break}
            $before=$pending
            $result=Invoke-TokenForgeResearchChunk -Inventory $Inventory -EstsAuth $EstsAuth -DatabasePath $database -CohortId $cohort.PlanId -FlowDatabasePath $flows -MetadataPath $metadata -NativeExecutablePath $NativeExecutablePath -Confirm:$false
            $chunks++
            if($null -eq $result -or $null -eq $result.PSObject.Properties['PlanId'] -or $null -eq $result.PSObject.Properties['PendingClients'] -or $result.PlanId -cne $cohort.PlanId -or ($result.PendingClients -isnot [int] -and $result.PendingClients -isnot [long]) -or $result.PendingClients -lt 0 -or $result.PendingClients -gt $cohort.ClientCount){throw 'Invalid discovery chunk summary; saved checkpoints are retained for retry.'}
            $pending=$result.PendingClients
            if($pending -ge $before){throw 'Discovery made no checkpoint progress; inspect the saved evidence before retrying.'}
        }
        [pscustomobject]@{SchemaVersion=1;Status=$reason;CohortId=$cohort.PlanId;Clients=$cohort.ClientCount;CompletedClients=($cohort.ClientCount-$pending);PendingClients=$pending;ChunksExecuted=$chunks;CredentialOutput=$false}
    }finally{if($lock){$lock.Dispose()}}
}
