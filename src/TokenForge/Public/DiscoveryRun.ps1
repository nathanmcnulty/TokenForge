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
        [ValidateRange(0,10)][int]$MaxTransientRetries=3,
        [ValidateRange(1,300)][int]$RetryDelaySeconds=30,
        [switch]$ExploreAllFlows=$true,
        [ValidateRange(0,1000)][int]$MaxPendingClients=0,
        [switch]$RecoverUnknown,[switch]$ResumePaused,[switch]$Bounded,
        [ValidateRange(0,1000000)][int]$MaxIssuanceAttempts=30,
        [ValidateRange(0,1000000)][int]$MaxTotalRequests=300,
        [Threading.CancellationToken]$CancellationToken=[Threading.CancellationToken]::None,
        $OperationBudget
    )
    if(-not $PSCmdlet.ShouldProcess($StatePath,'Run resumable discovery with existing authorization')){return}
    if($Bounded -and -not $OperationBudget){$OperationBudget=New-TokenForgeOperationBudget -MaxSeconds ($MaxMinutes*60) -MaxIssuanceAttempts $MaxIssuanceAttempts -MaxTotalRequests $MaxTotalRequests -MaxTransientRetries ([Math]::Min(3,$MaxTransientRetries)) -CancellationToken $CancellationToken}
    $previousBudget=$script:OperationBudget
    $root=Split-Path (Resolve-TokenForgeVaultPath (Join-Path $StatePath '.state') -CreateDirectory) -Parent
    $manifest=Join-Path $root 'discovery-run.json'
    $database=Join-Path $root 'scopes.sqlite';$flows=Join-Path $root 'flows.sqlite';$metadata=Join-Path $root 'applications.sqlite'
    $lock=$null;$timer=[Diagnostics.Stopwatch]::StartNew();$chunks=0;$attempts=0;$retries=0
    try {
        if($OperationBudget){
            $script:OperationBudget=$OperationBudget;$OperationBudget.Preflight=$false
            if(-not $OperationBudget.LedgerPath){$OperationBudget.LedgerPath=Join-Path $root ('budget-intent-'+[guid]::NewGuid().ToString('N')+'.json')}
            Assert-TokenForgeOperationBudget $OperationBudget
        }
        $lockPath=Resolve-TokenForgeVaultPath (Join-Path $root '.writer.lock') -CreateDirectory
        $lock=if(Test-Path -LiteralPath $lockPath){Open-TokenForgeVaultFile $lockPath}else{Open-TokenForgeVaultFile $lockPath -Create}
        if($OperationBudget){Save-TokenForgeBudgetLedger $OperationBudget}
        if((Test-Path -LiteralPath $manifest) -and -not $NewRun){
            $id=Get-TokenForgeDiscoveryRunId $manifest
            $cohort=Get-TokenForgeResearchCohort -DatabasePath $database -CohortId $id -NativeExecutablePath $NativeExecutablePath
        }else{
            $cohort=New-TokenForgeResearchCohort -Inventory $Inventory -DatabasePath $database -GraphOnly:$GraphOnly -BatchSize $BatchSize -MaxRedirects $MaxRedirects -ExploreAllFlows:$ExploreAllFlows -NativeExecutablePath $NativeExecutablePath -Confirm:$false
            Save-TokenForgeDocument -Path $manifest -Document @{SchemaVersion=1;CohortId=$cohort.PlanId}
        }
        $recipe=$cohort.Cohort
        $inventoryHash=Get-TokenForgeFingerprint (ConvertTo-Json -InputObject @($Inventory.Applications|Sort-Object {[string]$_.AppId}) -Depth 32 -Compress)
        if($Inventory.TenantFingerprint -cne $recipe.TenantFingerprint -or $Inventory.PrincipalFingerprint -cne $recipe.PrincipalFingerprint -or $inventoryHash -cne $recipe.InventoryHash -or $Inventory.DiscoveryCatalogHash -cne $recipe.CatalogHash){throw 'Inventory differs from the frozen cohort. Create a new run after reviewing refreshed metadata.'}
        $reason='Complete';$stopReason=$null;$pending=$cohort.Pending.Count
        while($pending){
            if($attempts -ge $MaxChunks -or $timer.Elapsed.TotalMinutes -ge $MaxMinutes){$reason='BudgetReached';break}
            if($OperationBudget){try{Assert-TokenForgeOperationBudget $OperationBudget}catch{$reason='BudgetReached';break}}
            $before=$pending
            $attempts++
            try{
                $result=Invoke-TokenForgeResearchChunk -Inventory $Inventory -EstsAuth $EstsAuth -DatabasePath $database -CohortId $cohort.PlanId -MaxPendingClients $MaxPendingClients -FlowDatabasePath $flows -MetadataPath $metadata -NativeExecutablePath $NativeExecutablePath -OperationBudget $OperationBudget -RecoverUnknown:$RecoverUnknown -ResumePaused:$ResumePaused -Confirm:$false
            }catch{
                if($OperationBudget -and $_.FullyQualifiedErrorId.Split(',')[0] -cin @('TokenForge.SessionPaused','TokenForge.InFlightUnknown','TokenForge.RecoveryExhausted','TokenForge.AccountMismatch','TokenForge.TransientExhausted')){
                    $stop=Get-TokenForgeCollectorStopSummary -ErrorRecord $_ -Stage Discovery -Budget $OperationBudget
                    $reason=$stop.Status;$stopReason=$stop.Reason
                    $fresh=Get-TokenForgeResearchCohort -DatabasePath $database -CohortId $cohort.PlanId -NativeExecutablePath $NativeExecutablePath;$pending=$fresh.Pending.Count;break
                }
                if($OperationBudget -and $_.FullyQualifiedErrorId.Split(',')[0] -ceq 'TokenForge.TransientIdentity' -and $retries -ge $MaxTransientRetries){$reason='TransientExhausted';$stopReason='TransientExhausted';$fresh=Get-TokenForgeResearchCohort -DatabasePath $database -CohortId $cohort.PlanId -NativeExecutablePath $NativeExecutablePath;$pending=$fresh.Pending.Count;break}
                if($_.FullyQualifiedErrorId.Split(',')[0] -ceq 'TokenForge.BudgetReached'){$reason='BudgetReached';$fresh=Get-TokenForgeResearchCohort -DatabasePath $database -CohortId $cohort.PlanId -NativeExecutablePath $NativeExecutablePath;$pending=$fresh.Pending.Count;break}
                # Only the probe's explicit transient identity error can trigger another attempt.
                if($_.FullyQualifiedErrorId.Split(',')[0] -cne 'TokenForge.TransientIdentity' -or $_.CategoryInfo.Category -ne [Management.Automation.ErrorCategory]::ResourceUnavailable -or $retries -ge $MaxTransientRetries){throw}
                $fresh=Get-TokenForgeResearchCohort -DatabasePath $database -CohortId $cohort.PlanId -NativeExecutablePath $NativeExecutablePath
                $pending=$fresh.Pending.Count
                if(-not $pending){break}
                $delay=[int][Math]::Min(300,$RetryDelaySeconds*[Math]::Pow(2,$retries))
                if($attempts -ge $MaxChunks -or $timer.Elapsed.TotalSeconds+$delay -ge $MaxMinutes*60){$reason='BudgetReached';break}
                $retries++
                if($OperationBudget){try{Wait-TokenForgeOperationBudget -Seconds $delay -Budget $OperationBudget}catch{$reason='BudgetReached';break}}else{Start-Sleep -Seconds $delay}
                continue
            }
            $chunks++
            if($null -eq $result -or $null -eq $result.PSObject.Properties['PlanId'] -or $null -eq $result.PSObject.Properties['PendingClients'] -or $result.PlanId -cne $cohort.PlanId -or ($result.PendingClients -isnot [int] -and $result.PendingClients -isnot [long]) -or $result.PendingClients -lt 0 -or $result.PendingClients -gt $cohort.ClientCount){throw 'Invalid discovery chunk summary; saved checkpoints are retained for retry.'}
            $pending=$result.PendingClients
            if($pending -ge $before){throw 'Discovery made no checkpoint progress; inspect the saved evidence before retrying.'}
        }
        $collectorStatus=$null
        if($OperationBudget -and (Test-Path -LiteralPath $flows -PathType Leaf)){
            $collectorStatus=Get-TokenForgeCollectorStatus -DatabasePath $database -CohortId $cohort.PlanId -FlowPath $flows -NativeExecutablePath $NativeExecutablePath
            if($reason -eq 'Complete'){$reason=$collectorStatus.Status;$stopReason=$collectorStatus.Status}
        }
        [pscustomobject]@{SchemaVersion=1;Status=$reason;Reason=if($stopReason){$stopReason}else{$reason};CollectorStatus=$collectorStatus;CohortId=$cohort.PlanId;Clients=$cohort.ClientCount;CompletedClients=($cohort.ClientCount-$pending);PendingClients=$pending;ChunksExecuted=$chunks;ChunkAttempts=$attempts;TransientRetries=$retries;CredentialOutput=$false;OperationBudget=(Get-TokenForgeOperationBudgetSummary $OperationBudget)}
    }finally{if($lock){$lock.Dispose()};$script:OperationBudget=$previousBudget}
}
