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
    if(@($Scope|Where-Object {$_ -notmatch '^[A-Za-z0-9_-][A-Za-z0-9_.-]*$' -or $_ -cin @('openid','profile','email','offline_access')}).Count){throw 'Provide explicit API scope names.'}
    $now=[DateTimeOffset]::UtcNow
    $captured=[DateTimeOffset]::Parse($Inventory.CapturedAt)
    $inventoryFresh=$captured -ge $now.AddHours(-$MaxAgeHours) -and $captured -le $now.AddMinutes(5)
    $resource=@($Inventory.Applications|Where-Object {$_.AppId -eq $ResourceId.ToString() -and $_.Registration -eq 'Present' -and $_.Ownership -eq 'VerifiedMicrosoftOwner' -and $_.AccountEnabled})
    $resourceEligible=$resource.Count -eq 1
    $coverage=@{}
    foreach($row in @(Get-TokenForgeAssessmentCoverage -Database $Database -ResourceId $ResourceId -Scope $Scope -TenantFingerprint $Inventory.TenantFingerprint -PrincipalFingerprint $PrincipalFingerprint -MaxAgeHours $MaxAgeHours)){$coverage[$row.ClientId]=$row}
    $latest=@{}
    foreach($observation in @($Database.Observations|Where-Object {$_.ResourceId -eq $ResourceId.ToString() -and $_.TenantFingerprint -eq $Inventory.TenantFingerprint -and $_.PrincipalFingerprint -eq $PrincipalFingerprint}|Sort-Object {[DateTimeOffset]::Parse($_.ObservedAt).UtcDateTime})){$latest[$observation.ClientId]=$observation}
    $grantEnumeration=if($Inventory.PSObject.Properties['GrantEnumeration']){$Inventory.GrantEnumeration}else{'Unknown'}
    $rows=foreach($app in $Inventory.Applications){
        $published=@($app.PublishedGrants|Where-Object ResourceId -eq $ResourceId.ToString()|ForEach-Object Scopes|Sort-Object -Unique)
        # AppliesToCurrentPrincipal describes the inventory collector, not this observer.
        $granted=@($Inventory.TenantGrants|Where-Object {
            $_.ClientId -eq $app.AppId -and $_.ResourceId -eq $ResourceId.ToString() -and
            ($_.ConsentType -eq 'AllPrincipals' -or ($_.ConsentType -eq 'Principal' -and $_.PSObject.Properties['PrincipalFingerprint'] -and $_.PrincipalFingerprint -eq $PrincipalFingerprint))
        }|ForEach-Object Scopes|Sort-Object -Unique)
        $observation=$latest[$app.AppId];$observed=$coverage[$app.AppId]
        if(-not $published.Count -and -not $granted.Count -and -not $observation){continue}
        $publishedMissing=@($Scope|Where-Object {$published -cnotcontains $_})
        $grantedMissing=@($Scope|Where-Object {$granted -cnotcontains $_})
        $grantStatus=if($granted.Count -and -not $grantedMissing.Count){'Covered'}elseif($grantEnumeration -ne 'Complete'){'Unknown'}elseif($granted.Count){'Partial'}else{'NotPresent'}
        $observedScopes=@(if($observed){@($Scope|Where-Object {$observed.MissingScopes -cnotcontains $_})+@($observed.AdditionalScopes)})
        $observedMissing=@($Scope|Where-Object {$observedScopes -cnotcontains $_})
        $observationStatus=if($observed){if($observed.CoversAll){'FreshCoverage'}else{'FreshPartialCoverage'}}elseif(-not $observation){'NotObserved'}elseif([DateTimeOffset]::Parse($observation.ObservedAt) -gt $now.AddMinutes(5)){'FutureDated'}elseif($observation.Outcome -ne 'Succeeded'){'LatestAttemptUnsuccessful'}elseif([DateTimeOffset]::Parse($observation.ObservedAt) -lt $now.AddHours(-$MaxAgeHours)){'Stale'}else{'Unverified'}
        $eligible=$inventoryFresh -and $resourceEligible -and $app.Registration -eq 'Present' -and $app.Ownership -eq 'VerifiedMicrosoftOwner' -and $app.AccountEnabled
        $rank=if($eligible -and $observed -and $observed.CoversAll){0}elseif($eligible -and $granted.Count -and -not $grantedMissing.Count){1}elseif($eligible -and $published.Count -and -not $publishedMissing.Count){2}else{3}
        [pscustomobject]@{
            ClientId=$app.AppId; Name=$app.Name; ResourceId=$ResourceId.ToString()
            Registration=$app.Registration; Ownership=$app.Ownership; AccountEnabled=$app.AccountEnabled
            InventoryFresh=$inventoryFresh; InventoryCapturedAt=$Inventory.CapturedAt; ResourceEligible=$resourceEligible; GrantEnumeration=$grantEnumeration
            PublishedScopes=$published; PublishedMissingScopes=$publishedMissing
            ApplicableConfiguredGrantScopes=$granted; ConfiguredGrantStatus=$grantStatus; ConfiguredGrantMissingScopes=if($grantStatus -eq 'Unknown'){$null}else{$grantedMissing}
            FreshObservedScopes=$observedScopes; ObservedMissingScopes=$observedMissing
            ObservedAdditionalScopeCount=if($observed){$observed.AdditionalScopeCount}else{$null}
            ObservationStatus=$observationStatus; LatestOutcome=if($observation){$observation.Outcome}else{'NotObserved'}
            ObservedAt=if($observation){$observation.ObservedAt}else{$null}
            Protocol=if($observation -and $observation.PSObject.Properties['Protocol']){$observation.Protocol}else{'Unknown'}
            RequestedScopes=@(if($observation -and $observation.PSObject.Properties['RequestedScopes']){$observation.RequestedScopes})
            BrowserCallbackAvailable=@($app.RedirectUris|Where-Object {
                $u=$null
                [uri]::TryCreate($_,[UriKind]::Absolute,[ref]$u) -and $u.Scheme -eq 'http' -and $u.Host -eq 'localhost' -and $u.AbsolutePath -eq '/' -and -not $u.UserInfo -and -not $u.Query -and -not $u.Fragment
            }).Count -gt 0
            CandidateRank=$rank; Evidence='PlanningHintsNotGuaranteedSilentExplicitAuthorization'
        }
    }
    @($rows|Sort-Object CandidateRank,@{Expression={if($null -eq $_.ObservedAdditionalScopeCount){[int]::MaxValue}else{$_.ObservedAdditionalScopeCount}}},ClientId)
}
