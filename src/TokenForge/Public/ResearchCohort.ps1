function New-TokenForgeResearchCohort {
    <# .SYNOPSIS
    Freeze a namespace-bound client/resource recipe and deterministic chunk membership in SQLite.
    #>
    [CmdletBinding(SupportsShouldProcess,ConfirmImpact='Low')]
    param([Parameter(Mandatory)]$Inventory,[Parameter(Mandatory)][string]$DatabasePath,
        [ValidatePattern('^[a-f0-9]{64}$')][string]$PrincipalFingerprint,[guid[]]$ClientId,[switch]$GraphOnly,
        [ValidateRange(1,1000)][int]$BatchSize=25,[ValidateRange(1,1000)][int]$MaxRedirects=8,[switch]$ExploreAllFlows,
        [ValidateSet('OAuth2V2Pkce','OAuth2V2Implicit','OAuth2V1Implicit')][string[]]$Protocols=@('OAuth2V2Pkce','OAuth2V2Implicit','OAuth2V1Implicit'),
        [string]$Tenant='organizations',[string]$NativeExecutablePath)
    if(-not $DatabasePath.EndsWith('.sqlite',[StringComparison]::OrdinalIgnoreCase)){throw 'Research cohorts require a SQLite scope database.'}
    $principal=if($PrincipalFingerprint){$PrincipalFingerprint}else{$Inventory.PrincipalFingerprint}
    if(-not $principal){throw 'A cohort principal fingerprint is required.'}
    $pairs=@(Get-TokenForgeProbePlan -Inventory $Inventory -ClientId $ClientId -GraphOnly:$GraphOnly -PrincipalFingerprint $principal|ForEach-Object {@{ClientId=$_.ClientId;ResourceId=$_.ResourceId}})
    if(-not $pairs.Count){throw 'No eligible client/resource pairs were selected for the cohort.'}
    $inventoryHash=Get-TokenForgeFingerprint (ConvertTo-Json -InputObject @($Inventory.Applications|Sort-Object AppId) -Depth 32 -Compress)
    $document=@{Format='TokenForgeResearchCohort';SchemaVersion=1;CreatedAt=[DateTimeOffset]::UtcNow.ToString('o');TenantFingerprint=$Inventory.TenantFingerprint;PrincipalFingerprint=$principal;CatalogHash=$Inventory.DiscoveryCatalogHash;InventoryHash=$inventoryHash;Authority=$Tenant;Protocols=@($Protocols|Select-Object -Unique);MaxRedirects=$MaxRedirects;ExploreAllFlows=[bool]$ExploreAllFlows;Pairs=$pairs}
    if(-not $PSCmdlet.ShouldProcess($DatabasePath,'Create a frozen research cohort')){return}
    $created=Invoke-TokenForgeNativeEvidence $DatabasePath cohort -Domain evidence -Document $document -BatchSize $BatchSize -NativeExecutablePath $NativeExecutablePath
    Get-TokenForgeResearchCohort $DatabasePath $created.PlanId -NativeExecutablePath $NativeExecutablePath
}

function Get-TokenForgeResearchCohort {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$DatabasePath,[Parameter(Mandatory)][ValidatePattern('^[a-f0-9]{64}$')][string]$CohortId,[string]$NativeExecutablePath)
    $plan=Invoke-TokenForgeNativeEvidence $DatabasePath cohort-export -Domain evidence -PlanFingerprint $CohortId -NativeExecutablePath $NativeExecutablePath
    $pending=@(Invoke-TokenForgeNativeEvidence $DatabasePath pending -Domain evidence -PlanFingerprint $CohortId -NativeExecutablePath $NativeExecutablePath)
    $members=@($plan.Cohort.Pairs.ClientId|Sort-Object -Unique)
    [pscustomobject]@{PlanId=$plan.PlanId;BatchSize=$plan.BatchSize;Cohort=$plan.Cohort;ClientCount=$members.Count;PairCount=$plan.Cohort.Pairs.Count;ChunkCount=[int][Math]::Ceiling($members.Count/[double]$plan.BatchSize);CompletedClients=$members.Count-$pending.Count;Pending=$pending}
}

function Invoke-TokenForgeResearchChunk {
    <# .SYNOPSIS
    Execute or resume one frozen cohort chunk and checkpoint only after evidence and catalog updates succeed.
    #>
    [CmdletBinding(SupportsShouldProcess,ConfirmImpact='Low')]
    param([Parameter(Mandatory)]$Inventory,[Parameter(Mandatory)][securestring]$EstsAuth,
        [Parameter(Mandatory)][string]$DatabasePath,[Parameter(Mandatory)][ValidatePattern('^[a-f0-9]{64}$')][string]$CohortId,
        [ValidateRange(-1,100000)][int]$ChunkIndex=-1,[string]$FlowDatabasePath,[string]$MetadataPath,[string]$NativeExecutablePath,
        [ValidateSet('ESTSAUTH','ESTSAUTHPERSISTENT')][string]$CookieName='ESTSAUTH',
        [ValidateRange(1,8760)][int]$MaxAgeHours=24,[ValidateRange(0,60000)][int]$DelayMilliseconds=250)
    if(-not $DatabasePath.EndsWith('.sqlite',[StringComparison]::OrdinalIgnoreCase)){throw 'Research cohorts require a SQLite scope database.'}
    if(-not $PSCmdlet.ShouldProcess($CohortId,'Execute the frozen research chunk using existing authorization')){return}
    $lock=$null
    try{
        $lockPath=Resolve-TokenForgeVaultPath ($DatabasePath+'.cohort.lock') -CreateDirectory
        $lock=if(Test-Path -LiteralPath $lockPath){Open-TokenForgeVaultFile $lockPath}else{Open-TokenForgeVaultFile $lockPath -Create}
        $plan=Get-TokenForgeResearchCohort $DatabasePath $CohortId -NativeExecutablePath $NativeExecutablePath
        $recipe=$plan.Cohort
        $inventoryHash=Get-TokenForgeFingerprint (ConvertTo-Json -InputObject @($Inventory.Applications|Sort-Object AppId) -Depth 32 -Compress)
        if($Inventory.TenantFingerprint -ne $recipe.TenantFingerprint -or $inventoryHash -ne $recipe.InventoryHash -or $Inventory.DiscoveryCatalogHash -ne $recipe.CatalogHash){throw 'Inventory differs from the frozen cohort. Create a new cohort after refreshing metadata.'}
        $captured=[DateTimeOffset]$Inventory.CapturedAt
        if($captured -lt [DateTimeOffset]::UtcNow.AddHours(-$MaxAgeHours) -or $captured -gt [DateTimeOffset]::UtcNow.AddMinutes(5)){throw 'Cohort execution requires a fresh inventory.'}
        if($ChunkIndex -lt 0){
            if(-not $plan.Pending.Count){return [pscustomobject]@{PlanId=$CohortId;Complete=$true;PendingClients=0;NewObservations=0}}
            $ChunkIndex=@($plan.Pending|Sort-Object Chunk)[0].Chunk
        }
        if($ChunkIndex -ge $plan.ChunkCount){throw 'ChunkIndex exceeds the frozen cohort.'}
        $members=@($recipe.Pairs.ClientId|Sort-Object -Unique)
        $selected=@($members|Select-Object -Skip ($ChunkIndex*$plan.BatchSize) -First $plan.BatchSize)
        $pairs=@($recipe.Pairs|Where-Object {$_.ClientId -in $selected}|ForEach-Object {[pscustomobject]$_})
        $directory=Split-Path $DatabasePath -Parent
        if(-not $FlowDatabasePath){$FlowDatabasePath=Join-Path $directory flows.sqlite}
        if(-not $MetadataPath){$MetadataPath=Join-Path $directory $(if(Test-Path (Join-Path $directory applications.sqlite)){'applications.sqlite'}else{'applications.json'})}
        $flowChanges=@{Plans=@{};Attempts=@{}};$scopeChanges=@{};$observations=@()
        try{
            $observations=@(Invoke-TokenForgeScopeProbe -Inventory $Inventory -EstsAuth $EstsAuth -CookieName $CookieName -Plan $pairs -Protocols $recipe.Protocols -DatabasePath $DatabasePath -FlowDatabasePath $FlowDatabasePath -NativeExecutablePath $NativeExecutablePath -FlowChanges $flowChanges -ScopeChanges $scopeChanges -CohortFingerprint $CohortId -ClientId $selected -PrincipalFingerprint $recipe.PrincipalFingerprint -Tenant $recipe.Authority -MaxApplications $selected.Count -MaxRedirects $recipe.MaxRedirects -ExploreAllFlows:$recipe.ExploreAllFlows -DelayMilliseconds $DelayMilliseconds)
        }finally{
            # Leave cohort members pending if either metadata projection fails; resume repairs from primary checkpoints.
            if($scopeChanges.Count){$null=Update-TokenForgeApplicationMetadata $MetadataPath -Document @{SchemaVersion=1;UpdatedAt=[DateTimeOffset]::UtcNow.ToString('o');Observations=@($scopeChanges.Values)} -Kind ScopeObservations -NativeExecutablePath $NativeExecutablePath}
            if($flowChanges.Plans.Count){$null=Update-TokenForgeApplicationMetadata $MetadataPath -Document @{Format='TokenForgeFlowEvidence';SchemaVersion=1;UpdatedAt=[DateTimeOffset]::UtcNow.ToString('o');Plans=$flowChanges.Plans;Attempts=@($flowChanges.Attempts.Values)} -Kind FlowAttempts -NativeExecutablePath $NativeExecutablePath}
            foreach($client in $selected){
                $expected=@($pairs|Where-Object ClientId -eq $client)
                $handled=@($expected|ForEach-Object {$scopeChanges["$($_.ClientId)/$($_.ResourceId)"]}|Where-Object {$_})
                if($handled.Count -ne $expected.Count -or @($handled|Where-Object Outcome -eq ContextMismatch).Count){continue}
                $outcomes=@($handled.Outcome|Sort-Object -Unique);$outcome=if($outcomes.Count -eq 1){$outcomes[0]}else{'Failed'}
                $null=Invoke-TokenForgeNativeEvidence $DatabasePath checkpoint -Domain evidence -PlanFingerprint $CohortId -ClientId $client -Outcome $outcome -NativeExecutablePath $NativeExecutablePath
            }
        }
        if(@($scopeChanges.Values|Where-Object Outcome -eq ContextMismatch).Count){throw 'Cohort stopped on an issued-token context mismatch; affected clients remain pending.'}
        $remaining=Get-TokenForgeResearchCohort $DatabasePath $CohortId -NativeExecutablePath $NativeExecutablePath
        [pscustomobject]@{PlanId=$CohortId;ChunkIndex=$ChunkIndex;SelectedClients=$selected.Count;HandledPairs=$scopeChanges.Count;NewObservations=$observations.Count;CompletedClients=$remaining.CompletedClients;PendingClients=$remaining.Pending.Count;Complete=($remaining.Pending.Count -eq 0)}
    }finally{if($lock){$lock.Dispose()}}
}
