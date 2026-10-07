function Get-TokenForgeResearchCoverage {
    <# .SYNOPSIS
    Categorize catalog evidence and exact flow-plan coverage without authenticating or authorizing anything.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$MetadataPath,[string]$FlowPath,
        [ValidatePattern('^[a-f0-9]{64}$')][string]$TenantFingerprint,
        [ValidatePattern('^[a-f0-9]{64}$')][string]$PrincipalFingerprint,
        [guid[]]$AppId,[ValidateRange(1,8760)][int]$MaxAgeHours=24,[switch]$SummaryOnly
    )
    if([bool]$TenantFingerprint -ne [bool]$PrincipalFingerprint){throw 'Select both tenant and principal for account-specific flow coverage.'}
    $catalog=Get-TokenForgeApplicationMetadata $MetadataPath
    $flows=if($FlowPath){Get-TokenForgeFlowEvidence $FlowPath}else{@{Plans=@{};Attempts=@()}}
    $latest=@{};foreach($attempt in @($flows.Attempts|Sort-Object ObservedAt)){$latest[$attempt.AttemptKey]=$attempt}
    $selectedPlans=@{}
    if($TenantFingerprint){foreach($hash in $flows.Plans.Keys){
        $plan=$flows.Plans[$hash]
        if($plan.TenantFingerprint -ne $TenantFingerprint -or $plan.PrincipalFingerprint -ne $PrincipalFingerprint){continue}
        $key=$plan.ClientId+'/'+$plan.ResourceId
        if(-not $selectedPlans.ContainsKey($key) -or ([DateTimeOffset]$plan.PlannedAt) -gt ([DateTimeOffset]$flows.Plans[$selectedPlans[$key]].PlannedAt)){$selectedPlans[$key]=$hash}
    }}
    $plansByClient=@{};$attemptsByPlan=@{}
    foreach($hash in $selectedPlans.Values){$client=$flows.Plans[$hash].ClientId;if(-not $plansByClient.ContainsKey($client)){$plansByClient[$client]=@()};$plansByClient[$client]+=$hash}
    foreach($attempt in $latest.Values){$hash=$attempt.PlanFingerprint;if(-not $attemptsByPlan.ContainsKey($hash)){$attemptsByPlan[$hash]=@()};$attemptsByPlan[$hash]+=$attempt}
    $rows=@(foreach($id in @($catalog.Applications.Keys|Sort-Object)){
        if($AppId -and $id -notin @($AppId|ForEach-Object ToString)){continue}
        $app=$catalog.Applications[$id]
        $discovery=@($app.Records.Values|Where-Object {$_.Kind -eq 'Discovery' -and $_.PresentInLatestRun}|Sort-Object LastSeenAt -Descending|Select-Object -First 1)
        $inventory=@($app.Records.Values|Where-Object {$_.Kind -eq 'Inventory' -and $_.TenantFingerprint -eq $TenantFingerprint -and $_.PresentInLatestRun}|Sort-Object LastSeenAt -Descending|Select-Object -First 1)
        $registration=@($app.Records.Values|Where-Object {$_.Kind -eq 'RegistrationAttempts' -and $_.TenantFingerprint -eq $TenantFingerprint}|Sort-Object LastSeenAt -Descending|Select-Object -First 1)
        $signin=@($app.Records.Values|Where-Object {$_.Kind -eq 'SignIns' -and $_.TenantFingerprint -eq $TenantFingerprint -and $_.PresentInLatestRun}|Sort-Object LastSeenAt -Descending|Select-Object -First 1)
        $attributes=if($inventory.Count){$inventory[0].Attributes}elseif($discovery.Count){$discovery[0].Attributes}else{@{}}
        $hints=@(@(foreach($redirect in @($attributes['RedirectUris'])){
            if($redirect -match '^(brk-|ms-appx-web:)'){'BrokerCallbackPublished'}
            elseif($redirect -match 'nativeclient|localhost|^urn:'){'NativeCallbackPublished'}
            elseif($redirect -match '^https://'){'BrowserCallbackPublished'}
        })|Sort-Object -Unique)
        $clientHint=($attributes.Contains('PublicClient') -and $null -ne $attributes.PublicClient) -or ($attributes.Contains('Grants') -and @($attributes.Grants).Count -gt 0) -or ($attributes.Contains('PublishedGrants') -and @($attributes.PublishedGrants).Count -gt 0)
        $resourceHint=($attributes.Contains('IsResourceCandidate') -and $attributes.IsResourceCandidate) -or ($attributes.Contains('DelegatedScopeDefinitions') -and @($attributes.DelegatedScopeDefinitions).Count -gt 0)
        $plans=@(foreach($hash in @($plansByClient[$id]|Where-Object {$_})){
            $plan=$flows.Plans[$hash];if($plan.ClientId -ne $id){continue}
            $attempts=@($attemptsByPlan[$hash]|Where-Object {$_})
            $terminal=@($attempts|Where-Object Outcome -ne 'Started');$successful=@($terminal|Where-Object Outcome -eq 'Succeeded')
            [pscustomobject]@{ResourceId=$plan.ResourceId;PlanFingerprint=$hash;Eligibility=$plan.Eligibility;PlannedSlots=$plan.Cells.Count;TerminalSlots=$terminal.Count;InterruptedSlots=@($attempts|Where-Object Outcome -eq 'Started').Count;UntestedSlots=$plan.Cells.Count-$attempts.Count;SuccessfulSlots=$successful.Count;FailedSlots=@($terminal|Where-Object Outcome -eq 'Failed').Count;ContextMismatchSlots=@($terminal|Where-Object Outcome -eq 'ContextMismatch').Count;ObservedProtocols=@($successful|ForEach-Object {$_.Protocol}|Sort-Object -Unique);SpaRedemptionObserved=[bool]@($successful|Where-Object Spa);LatestObservationAt=if($attempts.Count){@($attempts|Sort-Object ObservedAt -Descending)[0].ObservedAt}else{$null};FreshSuccessfulSlots=@($successful|Where-Object {([DateTimeOffset]$_.ObservedAt) -ge [DateTimeOffset]::UtcNow.AddHours(-$MaxAgeHours)}).Count;Evidence='ObservedForSelectedAccountNotUniversalSupport';ApiAcceptance='NotEstablishedByTokenProbe'}
        })
        [pscustomobject]@{AppId=$id;Name=if($attributes.Contains('Name')){$attributes.Name}else{$id};FirstSeenAt=$app.FirstSeenAt;LastSeenAt=$app.LastSeenAt;PublishedInLatestSnapshot=[bool]$discovery.Count;RoleHint=if($clientHint -and $resourceHint){'ClientAndResource'}elseif($clientHint){'Client'}elseif($resourceHint){'Resource'}else{'Unknown'};Ownership=if($inventory.Count){$attributes.Ownership}elseif($discovery.Count){$attributes.Ownership}else{'Unknown'};Registration=if($inventory.Count){$attributes.Registration}else{'Unknown'};LatestRegistrationOutcome=if($registration.Count){$registration[0].Attributes.Outcome}else{$null};RegistrationNeedsInventoryRefresh=if($registration.Count){-not $inventory.Count -or ([DateTimeOffset]$registration[0].LastSeenAt) -gt ([DateTimeOffset]$inventory[0].LastSeenAt)}else{$false};PublishedFlowHints=$hints;SignInSummary=if($signin.Count){$signin[0].Attributes}else{$null};FlowCoverage=$plans;Classification='DiagnosticEvidenceOnly';FlowContext=if($TenantFingerprint){'SelectedAccount'}else{'SelectTenantAndPrincipal'} }
    })
    $planRows=@($rows|ForEach-Object {$_.FlowCoverage})
    [pscustomobject]@{SchemaVersion=1;ApplicationCount=$rows.Count;ApplicationsWithSelectedPlans=@($rows|Where-Object {$_.FlowCoverage.Count}).Count;ApplicationsWithObservedSuccess=@($rows|Where-Object {@($_.FlowCoverage|Where-Object SuccessfulSlots -gt 0).Count}).Count;PlannedSlots=$(if($planRows.Count){[int](($planRows|Measure-Object PlannedSlots -Sum).Sum)}else{0});TerminalSlots=$(if($planRows.Count){[int](($planRows|Measure-Object TerminalSlots -Sum).Sum)}else{0});UntestedSlots=$(if($planRows.Count){[int](($planRows|Measure-Object UntestedSlots -Sum).Sum)}else{0});InterruptedSlots=$(if($planRows.Count){[int](($planRows|Measure-Object InterruptedSlots -Sum).Sum)}else{0});Applications=@(if(-not $SummaryOnly){$rows});Evidence='CatalogAndSelectedLatestPlanMetadataNoAuthentication';Scope='SelectedAccountPlansOnly';RequiredAuthenticationFlow='NotInferred'}
}
