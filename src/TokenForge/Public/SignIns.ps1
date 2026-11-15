function Get-TokenForgeSignInApplications {
    <# .SYNOPSIS
    Extract client app IDs and typed target references from sign-ins without returning or persisting sign-in records.
    .DESCRIPTION
    Observed IDs are discovery candidates, not Microsoft ownership evidence. Graph beta includes all selected sign-in types.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][securestring]$GraphToken,
        [Parameter(Mandatory)]$Inventory,
        [DateTimeOffset]$Since=[DateTimeOffset]::UtcNow.AddDays(-7),
        [DateTimeOffset]$Until=[DateTimeOffset]::UtcNow,
        [ValidateSet('interactiveUser','nonInteractiveUser','servicePrincipal','managedIdentity')][string[]]$EventTypes=@('interactiveUser','nonInteractiveUser','servicePrincipal','managedIdentity'),
        [ValidateRange(1,10000)][int]$MaxPages=1000,
        [string]$CheckpointPath
    )
    if($Since -ge $Until -or ($Until-$Since).TotalDays -gt 31 -or $Until -gt [DateTimeOffset]::UtcNow.AddMinutes(5)){throw 'Choose an ordered sign-in window of at most 31 days, ending no later than now.'}
    if(-not $EventTypes.Count){throw 'Select at least one sign-in event type.'}
    $claims=Get-TokenForgeTokenClaims -AccessToken $GraphToken
    if(-not $claims.TenantFingerprint -or $claims.TenantFingerprint -ne $Inventory.TenantFingerprint){throw 'Graph token tenant does not match inventory.'}
    $filter="createdDateTime ge $($Since.UtcDateTime.ToString('yyyy-MM-ddTHH:mm:ssZ')) and createdDateTime le $($Until.UtcDateTime.ToString('yyyy-MM-ddTHH:mm:ssZ')) and signInEventTypes/any(t: $((@($EventTypes|Sort-Object -Unique|ForEach-Object {"t eq '$_'"})) -join ' or '))"
    $next='https://graph.microsoft.com/beta/auditLogs/signIns?$select=appId,resourceId,authenticationProtocol,clientAppUsed,signInEventTypes,authenticationMethodsUsed,clientCredentialType,incomingTokenType,status,servicePrincipalId,resourceServicePrincipalId,createdDateTime&$top=1000&$filter='+[uri]::EscapeDataString($filter)
    $allowedProtocols=@(Get-TokenForgeSignInSummaryValues ProtocolCounts);$allowedClients=@(Get-TokenForgeSignInSummaryValues ClientTypeCounts)
    $allowedCredentials=@(Get-TokenForgeSignInSummaryValues CredentialTypeCounts);$allowedIncoming=@(Get-TokenForgeSignInSummaryValues IncomingTokenTypeCounts);$allowedMethods=@(Get-TokenForgeSignInSummaryValues AuthenticationMethodCounts)
    $seen=[Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    $counts=@{};$summaries=@{};$records=0;$invalid=0;$pages=0
    $resourceCounts=@{};$identifierCounts=@{};$requestCount=0;$checkpointLock=$null;$save=$null;$capturedAt=[DateTimeOffset]::UtcNow.ToString('o');$eventCoverage=@{}
    foreach($type in $EventTypes){$eventCoverage[$type]=@{RecordCount=0;TimestampedRecordCount=0;FirstObservedAt=$null;LastObservedAt=$null}}
    $binding=Get-TokenForgeFingerprint (($claims.TenantFingerprint+'|'+[string](Get-TokenForgeSignInField $claims PrincipalFingerprint)+'|'+[string](Get-TokenForgeSignInField $claims ClientId)+'|'+[string](Get-TokenForgeSignInField $claims Audience)+'|'+$filter+'|'+$MaxPages+'|'+(ConvertTo-Json -InputObject $Inventory -Depth 100 -Compress)))
    try{
    if($CheckpointPath){
        $CheckpointPath=[TokenForge.Core.V0220.PrivateFiles]::Resolve($CheckpointPath,$true)
        $checkpointLockPath=[TokenForge.Core.V0220.PrivateFiles]::Resolve(($CheckpointPath+'.lock'),$false)
        $checkpointLock=[IO.File]::Open($checkpointLockPath,[IO.FileMode]::OpenOrCreate,[IO.FileAccess]::ReadWrite,[IO.FileShare]::None)
        if(-not $IsWindows){[IO.File]::SetUnixFileMode(($CheckpointPath+'.lock'),[IO.UnixFileMode]384)}
        if(Test-Path -LiteralPath $CheckpointPath){
            $saved=Read-TokenForgeSignInCheckpoint $CheckpointPath $binding
            $counts=$saved.Counts;$summaries=$saved.Summaries;$resourceCounts=$saved.Resources;$identifierCounts=$saved.Identifiers
            $records=$saved.Records;$invalid=$saved.Invalid;$pages=$saved.Pages;$requestCount=$saved.Requests;$next=$saved.Next;$capturedAt=$saved.CapturedAt;$eventCoverage=$saved.EventCoverage
            foreach($url in $saved.Seen){$null=$seen.Add($url)}
        }
    }
    $save={param($enumeration)
        Save-TokenForgeSignInCheckpoint $CheckpointPath ([ordered]@{Binding=$binding;Enumeration=$enumeration;CapturedAt=$capturedAt;EventCoverage=$eventCoverage;Counts=$counts;Summaries=$summaries;Resources=$resourceCounts;Identifiers=$identifierCounts;Records=$records;Invalid=$invalid;Pages=$pages;Requests=$requestCount;Next=$next;Seen=@($seen)})
    }
    while($next){
        $u=[uri]$next
        if($u.Scheme -ne 'https' -or $u.Host -ne 'graph.microsoft.com' -or $u.Port -ne 443 -or $u.UserInfo -or $u.Fragment -or $u.AbsolutePath -cne '/beta/auditLogs/signIns'){throw 'Sign-in pagination left its endpoint boundary.'}
        if($requestCount -ge $MaxPages -or $seen.Contains($next)){throw 'Sign-in page limit or pagination loop reached; no complete discovery returned.'}
        $requestCount++; & $save 'Partial'
        $response=Invoke-TokenForgeGraph -AccessToken $GraphToken -Uri $u -IncludeUnknownEnumMembers;$pages++;$null=$seen.Add($next)
        if($response -isnot [Collections.IDictionary] -or -not $response.Contains('value') -or $response['value'] -isnot [array] -or $response['value'].Count -gt 1000){throw 'Invalid sign-in collection response.'}
        foreach($row in $response['value']){
            $records++;$id=[guid]::Empty
            if($row -is [Collections.IDictionary]){
                $rawResource=ConvertTo-TokenForgeSignInResourceIdentifier $row['resourceId']
                $resourceObject=ConvertTo-TokenForgeSignInGuid ([string]$row['resourceServicePrincipalId'])
                $types=@($row['signInEventTypes']|Where-Object {$_ -cin @('interactiveUser','nonInteractiveUser','servicePrincipal','managedIdentity')}|Sort-Object -Unique)
                $observedAt=[DateTimeOffset]::MinValue
                $timestamp=$row['createdDateTime'];$hasObservedAt=$false
                # ConvertFrom-Json can materialize ISO dates as DateTime. A string
                # cast drops Kind and reparses UTC using the host's local offset.
                if($timestamp -is [DateTimeOffset]){$observedAt=$timestamp;$hasObservedAt=$true}
                elseif($timestamp -is [DateTime]){
                    if($timestamp.Kind -eq [DateTimeKind]::Unspecified){throw 'Sign-in event timestamp has no timezone context.'}
                    $observedAt=[DateTimeOffset]::new($timestamp);$hasObservedAt=$true
                }elseif($null -ne $timestamp){
                    if($timestamp -isnot [string] -or $timestamp -cnotmatch '(?:Z|[+-][0-9]{2}:[0-9]{2})\z' -or -not [DateTimeOffset]::TryParse($timestamp,[Globalization.CultureInfo]::InvariantCulture,[Globalization.DateTimeStyles]::None,[ref]$observedAt)){throw 'Sign-in event timestamp has no valid timezone context.'}
                    $hasObservedAt=$true
                }
                if($hasObservedAt -and ($observedAt -lt $Since -or $observedAt -gt $Until)){throw 'Sign-in event timestamp is outside requested coverage.'}
                foreach($type in $types){
                    if(-not $eventCoverage.Contains($type)){continue}
                    $eventCoverage[$type].RecordCount++
                    if($hasObservedAt){
                        $eventCoverage[$type].TimestampedRecordCount++
                        $stamp=$observedAt.ToUniversalTime().ToString('o')
                        if(-not $eventCoverage[$type].FirstObservedAt -or $stamp -clt $eventCoverage[$type].FirstObservedAt){$eventCoverage[$type].FirstObservedAt=$stamp}
                        if(-not $eventCoverage[$type].LastObservedAt -or $stamp -cgt $eventCoverage[$type].LastObservedAt){$eventCoverage[$type].LastObservedAt=$stamp}
                    }
                }
                foreach($field in @('appId','servicePrincipalId','resourceId','resourceServicePrincipalId')){
                    $value=if($field -ceq 'resourceId'){ConvertTo-TokenForgeSignInResourceIdentifier $row[$field]}else{ConvertTo-TokenForgeSignInGuid ([string]$row[$field])};if(-not $value){continue}
                    $identity=$field+'/'+$value
                    if(-not $identifierCounts.Contains($identity)){$identifierCounts[$identity]=@{Field=$field;Value=$value;Count=0}}
                    $identifierCounts[$identity].Count++
                }
                if($rawResource -or $resourceObject){
                    $resourceKey=[string]$rawResource+'/'+[string]$resourceObject
                    if(-not $resourceCounts.Contains($resourceKey)){
                        $mapping=Resolve-TokenForgeSignInResource $Inventory $rawResource $resourceObject
                        $resourceCounts[$resourceKey]=@{SignInResourceId=$rawResource;ResourceServicePrincipalObjectId=$resourceObject;SignInCount=0;EventTypeCounts=@{};Resolution=$mapping.Resolution;ResolvedAppId=$mapping.ResolvedAppId;CandidateAppIds=$mapping.CandidateAppIds;MappingEvidence=$mapping.MappingEvidence;Evidence='ObservedTargetNotTokenAudienceOrApiAccess'}
                    }
                    $resourceCounts[$resourceKey].SignInCount++
                    foreach($type in $types){if(-not $resourceCounts[$resourceKey].EventTypeCounts.Contains($type)){$resourceCounts[$resourceKey].EventTypeCounts[$type]=0};$resourceCounts[$resourceKey].EventTypeCounts[$type]++}
                }
            }
            if($row -isnot [Collections.IDictionary] -or -not [guid]::TryParse([string]$row['appId'],[ref]$id) -or $id -eq [guid]::Empty){$invalid++;continue}
            $key=$id.ToString();if(-not $counts.Contains($key)){$counts[$key]=0;$summaries[$key]=@{Protocols=@{};ClientTypes=@{};EventTypes=@{};Resources=@{};CredentialTypes=@{};IncomingTokenTypes=@{};AuthenticationMethods=@{};Outcomes=@{Succeeded=0;Failed=0;Unknown=0}}};$counts[$key]++
            $summary=$summaries[$key]
            foreach($field in @('authenticationProtocol','clientAppUsed')){
                $value=[string]$row[$field]
                $allowed=if($field -eq 'authenticationProtocol'){$allowedProtocols}else{$allowedClients}
                if($value -cnotin $allowed){$value='Unknown'}
                $bucket=if($field -eq 'authenticationProtocol'){$summary.Protocols}else{$summary.ClientTypes}
                if(-not $bucket.Contains($value)){$bucket[$value]=0};$bucket[$value]++
            }
            foreach($field in @('clientCredentialType','incomingTokenType')){
                $value=[string]$row[$field]
                $allowed=if($field -eq 'clientCredentialType'){$allowedCredentials}else{$allowedIncoming}
                if($value -cnotin $allowed){$value='Unknown'}
                $bucket=if($field -eq 'clientCredentialType'){$summary.CredentialTypes}else{$summary.IncomingTokenTypes}
                if(-not $bucket.Contains($value)){$bucket[$value]=0};$bucket[$value]++
            }
            $methods=@($row['authenticationMethodsUsed']|ForEach-Object {if($_ -cin $allowedMethods){$_}else{'Unknown'}}|Sort-Object -Unique)
            foreach($value in $methods){if(-not $summary.AuthenticationMethods.Contains($value)){$summary.AuthenticationMethods[$value]=0};$summary.AuthenticationMethods[$value]++}
            foreach($value in @($row['signInEventTypes']|Where-Object {$_ -cin @('interactiveUser','nonInteractiveUser','servicePrincipal','managedIdentity')}|Sort-Object -Unique)){if(-not $summary.EventTypes.Contains($value)){$summary.EventTypes[$value]=0};$summary.EventTypes[$value]++}
            $resource=[guid]::Empty
            if([guid]::TryParse([string]$row['resourceId'],[ref]$resource) -and $resource -ne [guid]::Empty){$resourceKey=$resource.ToString();if(-not $summary.Resources.Contains($resourceKey)){$summary.Resources[$resourceKey]=0};$summary.Resources[$resourceKey]++}
            $status=$row['status'];$errorCode=0
            $outcome=if($status -is [Collections.IDictionary] -and $status.Contains('errorCode') -and [int]::TryParse([string]$status['errorCode'],[ref]$errorCode)){if($errorCode -eq 0){'Succeeded'}else{'Failed'}}else{'Unknown'}
            $summary.Outcomes[$outcome]++
        }
        Write-Verbose "Sign-in extraction: $pages pages, $records records, $($counts.Count) unique client IDs."
        $next=[string]$response['@odata.nextLink'];$response=$null;$row=$null
        & $save $(if($next){'Partial'}else{'Complete'})
    }
    $known=@{};foreach($app in $Inventory.Applications){$known[$app.AppId]=$app}
    [pscustomobject]@{
        SchemaVersion=1;CapturedAt=$capturedAt;TenantFingerprint=$claims.TenantFingerprint
        Since=$Since.ToUniversalTime().ToString('o');Until=$Until.ToUniversalTime().ToString('o');EventTypes=@($EventTypes|Sort-Object -Unique)
        Enumeration='Complete';PageCount=$pages;RequestCount=$requestCount;RecordCount=$records;InvalidAppIdCount=$invalid
        Coverage=[pscustomobject]@{WindowEnumeration='Complete';RequestedEventTypes=@($EventTypes|Sort-Object -Unique);ObservedEventTypes=@($eventCoverage.Keys|Where-Object {$eventCoverage[$_].RecordCount -gt 0}|Sort-Object);Retention='RequestedWindowOnly_NotProofOfAvailableTenantRetention';RawEventsRetained=$false;ByEventType=$eventCoverage;RetentionAvailability='Unknown_NotEstablishedByQueryCompletion'}
        IdentifierObservations=@($identifierCounts.Keys|Sort-Object|ForEach-Object {[pscustomobject]$identifierCounts[$_]})
        Resources=@($resourceCounts.Keys|Sort-Object|ForEach-Object {[pscustomobject]$resourceCounts[$_]})
        ResourceCountsSemantics='LegacyRawSignInResourceId_NotAssumedAppId'
        ServicePrincipalIdSemantics='RawSignInServicePrincipalId_NotAssumedObjectId'
        TokenAudiences=@()
        Applications=@(foreach($id in @($counts.Keys|Sort-Object)){
            [pscustomobject]@{AppId=$id;SignInCount=$counts[$id];KnownInInventory=$known.Contains($id);RegisteredMicrosoft=($known.Contains($id) -and $known[$id].Registration -eq 'Present' -and $known[$id].Ownership -eq 'VerifiedMicrosoftOwner');Evidence='ObservedSignInNotOwnership';ProtocolCounts=@(foreach($v in @($summaries[$id].Protocols.Keys|Sort-Object)){[pscustomobject]@{Value=$v;Count=$summaries[$id].Protocols[$v]}});ClientTypeCounts=@(foreach($v in @($summaries[$id].ClientTypes.Keys|Sort-Object)){[pscustomobject]@{Value=$v;Count=$summaries[$id].ClientTypes[$v]}});EventTypeCounts=@(foreach($v in @($summaries[$id].EventTypes.Keys|Sort-Object)){[pscustomobject]@{Value=$v;Count=$summaries[$id].EventTypes[$v]}});ResourceCounts=@(foreach($v in @($summaries[$id].Resources.Keys|Sort-Object)){[pscustomobject]@{Value=$v;Count=$summaries[$id].Resources[$v]}});CredentialTypeCounts=@(foreach($v in @($summaries[$id].CredentialTypes.Keys|Sort-Object)){[pscustomobject]@{Value=$v;Count=$summaries[$id].CredentialTypes[$v]}});IncomingTokenTypeCounts=@(foreach($v in @($summaries[$id].IncomingTokenTypes.Keys|Sort-Object)){[pscustomobject]@{Value=$v;Count=$summaries[$id].IncomingTokenTypes[$v]}});AuthenticationMethodCounts=@(foreach($v in @($summaries[$id].AuthenticationMethods.Keys|Sort-Object)){[pscustomobject]@{Value=$v;Count=$summaries[$id].AuthenticationMethods[$v]}});OutcomeCounts=@(foreach($v in @($summaries[$id].Outcomes.Keys|Sort-Object)){[pscustomobject]@{Value=$v;Count=$summaries[$id].Outcomes[$v]}})}
        })
    }
    }catch{throw} # The durable pre-dispatch checkpoint retains charged attempts and pre-page aggregates.
    finally{if($checkpointLock){$checkpointLock.Dispose()}}
}
