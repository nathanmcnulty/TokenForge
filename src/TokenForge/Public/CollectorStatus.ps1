function Get-TokenForgeCollectorStatus {
    <# .SYNOPSIS
    Inspect saved evidence without authentication or changing checkpoints.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$DatabasePath,
        [Parameter(Mandatory)][ValidatePattern('^[a-f0-9]{64}$')][string]$CohortId,
        [Parameter(Mandatory)][string]$FlowPath,[string]$NativeExecutablePath)
    if(-not (Test-Path -LiteralPath $DatabasePath -PathType Leaf) -or -not (Test-Path -LiteralPath $FlowPath -PathType Leaf)){throw 'Collector status requires existing evidence files.'}
    $null=Get-TokenForgeScopeDatabase -Path $DatabasePath -NativeExecutablePath $NativeExecutablePath
    $cohort=Get-TokenForgeResearchCohort -DatabasePath $DatabasePath -CohortId $CohortId -NativeExecutablePath $NativeExecutablePath
    # Validate full history before selecting the frozen namespace/recipe.
    $history=Get-TokenForgeFlowEvidence -Path $FlowPath -NativeExecutablePath $NativeExecutablePath
    $counts=[ordered]@{Complete=0;StructurallyExcluded=0;Pending=0;Paused=0;RequestBlocked=0;TransientExhausted=0;InFlightUnknown=0;Failed=0}
    $pairCounts=[ordered]@{Complete=0;StructurallyExcluded=0;Pending=0;Paused=0;RequestBlocked=0;TransientExhausted=0;InFlightUnknown=0;Failed=0}
    foreach($hash in $history.Plans.Keys){
        $p=$history.Plans[$hash]
        if($p.Contains('CohortFingerprint') -and $p.CohortFingerprint -ceq $CohortId){
            if($p.Tenant -cne $cohort.Cohort.Authority -or @($p.Cells|Where-Object {$_.Protocol -cnotin $cohort.Cohort.Protocols}).Count -or @($p.Cells|ForEach-Object {$_.RedirectFingerprint}|Sort-Object -Unique).Count -gt $cohort.Cohort.MaxRedirects){throw 'Saved evidence differs from the frozen recipe.'}
            if($p.TenantFingerprint -cne $cohort.Cohort.TenantFingerprint -or $p.PrincipalFingerprint -cne $cohort.Cohort.PrincipalFingerprint -or $p.CatalogHash -cne $cohort.Cohort.CatalogHash -or -not @($cohort.Cohort.Pairs|Where-Object {$_.ClientId -ceq $p.ClientId -and $_.ResourceId -ceq $p.ResourceId}).Count){throw 'Saved evidence namespace differs from the frozen cohort.'}
        }
    }
    $planned=0;$unplanned=0;$mismatch=$false
    foreach($pair in $cohort.Cohort.Pairs){
        $plans=@($history.Plans.Keys|Where-Object {
            $p=$history.Plans[$_]
            $p.Contains('CohortFingerprint') -and $p.CohortFingerprint -ceq $CohortId -and $p.ClientId -ceq $pair.ClientId -and $p.ResourceId -ceq $pair.ResourceId
        })
        if($plans.Count -gt 1){throw 'Ambiguous frozen pair evidence.'}
        if(-not $plans.Count){$unplanned++;$pairCounts.Pending++;continue}
        $hash=$plans[0];$plan=$history.Plans[$hash]
        if($plan.TenantFingerprint -cne $cohort.Cohort.TenantFingerprint -or $plan.PrincipalFingerprint -cne $cohort.Cohort.PrincipalFingerprint -or $plan.CatalogHash -cne $cohort.Cohort.CatalogHash){throw 'Saved evidence namespace differs from the frozen cohort.'}
        if($plan.Eligibility -ne 'Eligible'){$pairCounts.StructurallyExcluded++;continue}
        $latest=@{}
        foreach($row in @($history.Attempts|Where-Object PlanFingerprint -CEQ $hash|Sort-Object {([DateTimeOffset]$_.ObservedAt).UtcDateTime})){$latest[$row.AttemptKey]=$row}
        $states=@();$planned+=$plan.Cells.Count
        foreach($cell in $plan.Cells){
            $key=& (Get-Module TokenForge) {param($h,$c) Get-TokenForgeFingerprint ($h+'|'+$c.Protocol+'|'+[int]$c.Spa+'|'+$c.RedirectFingerprint)} $hash $cell
            $row=$latest[$key]
            $state=if(-not $row){'Pending'}else{switch -CaseSensitive ($row.Outcome){
                Started {'InFlightUnknown'} SessionPaused {'Paused'} RequestBlocked {'RequestBlocked'}
                TransientFailure {'TransientExhausted'} Failed {'Failed'} ContextMismatch {$mismatch=$true;'Failed'}
                default {'Complete'}
            }}
            $counts[$state]++;$states+=,$state
        }
        # First-success recipes may deliberately leave alternative cells pending.
        $state=if(-not $cohort.Cohort.ExploreAllFlows -and $states -contains 'Complete'){'Complete'}else{
            @('InFlightUnknown','Paused','TransientExhausted','Pending','Failed','RequestBlocked','Complete')|Where-Object {$_ -in $states}|Select-Object -First 1
        }
        if(-not $state){$state='Pending'}
        $pairCounts[$state]++
    }
    $reason=if($mismatch){'AccountMismatch'}elseif($pairCounts.InFlightUnknown){'InFlightUnknown'}elseif($pairCounts.Paused){'Paused'}elseif($pairCounts.TransientExhausted){'TransientExhausted'}elseif($pairCounts.Pending){'Pending'}elseif($pairCounts.Failed){'Failed'}elseif($pairCounts.RequestBlocked){'RequestBlocked'}elseif($pairCounts.StructurallyExcluded -eq $cohort.PairCount){'StructurallyExcluded'}else{'Complete'}
    $exitCode=switch($reason){Complete {0} StructurallyExcluded {0} Pending {2} Paused {3} RequestBlocked {4} TransientExhausted {5} InFlightUnknown {6} AccountMismatch {7} default {1}}
    [pscustomobject]@{SchemaVersion=1;Status=$reason;ExitCode=$exitCode;SelectedPairs=$cohort.PairCount;Pairs=$pairCounts;PlannedCells=$planned;UnmaterializedPairs=$unplanned;Cells=$counts;CompletedClients=$cohort.CompletedClients;PendingClients=$cohort.Pending.Count;SnapshotConsistency='SeparateValidatedReads';CredentialOutput=$false;ApiAcceptance='NotEstablished'}
}
