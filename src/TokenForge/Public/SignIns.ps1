function Get-TokenForgeSignInApplications {
    <# .SYNOPSIS
    Extract deduplicated client app IDs from sign-ins without returning or persisting sign-in records.
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
        [ValidateRange(1,10000)][int]$MaxPages=1000
    )
    if($Since -ge $Until -or ($Until-$Since).TotalDays -gt 31 -or $Until -gt [DateTimeOffset]::UtcNow.AddMinutes(5)){throw 'Choose an ordered sign-in window of at most 31 days, ending no later than now.'}
    if(-not $EventTypes.Count){throw 'Select at least one sign-in event type.'}
    $claims=Get-TokenForgeTokenClaims -AccessToken $GraphToken
    if(-not $claims.TenantFingerprint -or $claims.TenantFingerprint -ne $Inventory.TenantFingerprint){throw 'Graph token tenant does not match inventory.'}
    $filter="createdDateTime ge $($Since.UtcDateTime.ToString('yyyy-MM-ddTHH:mm:ssZ')) and createdDateTime le $($Until.UtcDateTime.ToString('yyyy-MM-ddTHH:mm:ssZ')) and signInEventTypes/any(t: $((@($EventTypes|Sort-Object -Unique|ForEach-Object {"t eq '$_'"})) -join ' or '))"
    $next='https://graph.microsoft.com/beta/auditLogs/signIns?$select=appId,resourceId,authenticationProtocol,clientAppUsed,signInEventTypes,authenticationMethodsUsed,clientCredentialType,incomingTokenType,status&$top=1000&$filter='+[uri]::EscapeDataString($filter)
    $allowedProtocols=@(Get-TokenForgeSignInSummaryValues ProtocolCounts);$allowedClients=@(Get-TokenForgeSignInSummaryValues ClientTypeCounts)
    $allowedCredentials=@(Get-TokenForgeSignInSummaryValues CredentialTypeCounts);$allowedIncoming=@(Get-TokenForgeSignInSummaryValues IncomingTokenTypeCounts);$allowedMethods=@(Get-TokenForgeSignInSummaryValues AuthenticationMethodCounts)
    $seen=[Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    $counts=@{};$summaries=@{};$records=0;$invalid=0;$pages=0
    while($next){
        $u=[uri]$next
        if($u.Scheme -ne 'https' -or $u.Host -ne 'graph.microsoft.com' -or $u.Port -ne 443 -or $u.UserInfo -or $u.Fragment -or $u.AbsolutePath -cne '/beta/auditLogs/signIns'){throw 'Sign-in pagination left its endpoint boundary.'}
        if($pages -ge $MaxPages -or -not $seen.Add($next)){throw 'Sign-in page limit or pagination loop reached; no complete discovery returned.'}
        $response=Invoke-TokenForgeGraph -AccessToken $GraphToken -Uri $u -IncludeUnknownEnumMembers;$pages++
        if($response -isnot [Collections.IDictionary] -or -not $response.Contains('value') -or $response['value'] -isnot [array]){throw 'Invalid sign-in collection response.'}
        foreach($row in $response['value']){
            $records++;$id=[guid]::Empty
            if($row -isnot [Collections.IDictionary] -or -not [guid]::TryParse([string]$row['appId'],[ref]$id) -or $id -eq [guid]::Empty){$invalid++;continue}
            $key=$id.ToString();if(-not $counts.ContainsKey($key)){$counts[$key]=0;$summaries[$key]=@{Protocols=@{};ClientTypes=@{};EventTypes=@{};Resources=@{};CredentialTypes=@{};IncomingTokenTypes=@{};AuthenticationMethods=@{};Outcomes=@{Succeeded=0;Failed=0;Unknown=0}}};$counts[$key]++
            $summary=$summaries[$key]
            foreach($field in @('authenticationProtocol','clientAppUsed')){
                $value=[string]$row[$field]
                $allowed=if($field -eq 'authenticationProtocol'){$allowedProtocols}else{$allowedClients}
                if($value -cnotin $allowed){$value='Unknown'}
                $bucket=if($field -eq 'authenticationProtocol'){$summary.Protocols}else{$summary.ClientTypes}
                if(-not $bucket.ContainsKey($value)){$bucket[$value]=0};$bucket[$value]++
            }
            foreach($field in @('clientCredentialType','incomingTokenType')){
                $value=[string]$row[$field]
                $allowed=if($field -eq 'clientCredentialType'){$allowedCredentials}else{$allowedIncoming}
                if($value -cnotin $allowed){$value='Unknown'}
                $bucket=if($field -eq 'clientCredentialType'){$summary.CredentialTypes}else{$summary.IncomingTokenTypes}
                if(-not $bucket.ContainsKey($value)){$bucket[$value]=0};$bucket[$value]++
            }
            $methods=@($row['authenticationMethodsUsed']|ForEach-Object {if($_ -cin $allowedMethods){$_}else{'Unknown'}}|Sort-Object -Unique)
            foreach($value in $methods){if(-not $summary.AuthenticationMethods.ContainsKey($value)){$summary.AuthenticationMethods[$value]=0};$summary.AuthenticationMethods[$value]++}
            foreach($value in @($row['signInEventTypes']|Where-Object {$_ -cin @('interactiveUser','nonInteractiveUser','servicePrincipal','managedIdentity')}|Sort-Object -Unique)){if(-not $summary.EventTypes.ContainsKey($value)){$summary.EventTypes[$value]=0};$summary.EventTypes[$value]++}
            $resource=[guid]::Empty
            if([guid]::TryParse([string]$row['resourceId'],[ref]$resource) -and $resource -ne [guid]::Empty){$resourceKey=$resource.ToString();if(-not $summary.Resources.ContainsKey($resourceKey)){$summary.Resources[$resourceKey]=0};$summary.Resources[$resourceKey]++}
            $status=$row['status'];$errorCode=0
            $outcome=if($status -is [Collections.IDictionary] -and $status.Contains('errorCode') -and [int]::TryParse([string]$status['errorCode'],[ref]$errorCode)){if($errorCode -eq 0){'Succeeded'}else{'Failed'}}else{'Unknown'}
            $summary.Outcomes[$outcome]++
        }
        Write-Verbose "Sign-in extraction: $pages pages, $records records, $($counts.Count) unique client IDs."
        $next=[string]$response['@odata.nextLink'];$response=$null;$row=$null
    }
    $known=@{};foreach($app in $Inventory.Applications){$known[$app.AppId]=$app}
    [pscustomobject]@{
        SchemaVersion=1;CapturedAt=[DateTimeOffset]::UtcNow.ToString('o');TenantFingerprint=$claims.TenantFingerprint
        Since=$Since.ToUniversalTime().ToString('o');Until=$Until.ToUniversalTime().ToString('o');EventTypes=@($EventTypes|Sort-Object -Unique)
        Enumeration='Complete';PageCount=$pages;RecordCount=$records;InvalidAppIdCount=$invalid
        Applications=@(foreach($id in @($counts.Keys|Sort-Object)){
            [pscustomobject]@{AppId=$id;SignInCount=$counts[$id];KnownInInventory=$known.ContainsKey($id);RegisteredMicrosoft=($known.ContainsKey($id) -and $known[$id].Registration -eq 'Present' -and $known[$id].Ownership -eq 'VerifiedMicrosoftOwner');Evidence='ObservedSignInNotOwnership';ProtocolCounts=@(foreach($v in @($summaries[$id].Protocols.Keys|Sort-Object)){[pscustomobject]@{Value=$v;Count=$summaries[$id].Protocols[$v]}});ClientTypeCounts=@(foreach($v in @($summaries[$id].ClientTypes.Keys|Sort-Object)){[pscustomobject]@{Value=$v;Count=$summaries[$id].ClientTypes[$v]}});EventTypeCounts=@(foreach($v in @($summaries[$id].EventTypes.Keys|Sort-Object)){[pscustomobject]@{Value=$v;Count=$summaries[$id].EventTypes[$v]}});ResourceCounts=@(foreach($v in @($summaries[$id].Resources.Keys|Sort-Object)){[pscustomobject]@{Value=$v;Count=$summaries[$id].Resources[$v]}});CredentialTypeCounts=@(foreach($v in @($summaries[$id].CredentialTypes.Keys|Sort-Object)){[pscustomobject]@{Value=$v;Count=$summaries[$id].CredentialTypes[$v]}});IncomingTokenTypeCounts=@(foreach($v in @($summaries[$id].IncomingTokenTypes.Keys|Sort-Object)){[pscustomobject]@{Value=$v;Count=$summaries[$id].IncomingTokenTypes[$v]}});AuthenticationMethodCounts=@(foreach($v in @($summaries[$id].AuthenticationMethods.Keys|Sort-Object)){[pscustomobject]@{Value=$v;Count=$summaries[$id].AuthenticationMethods[$v]}});OutcomeCounts=@(foreach($v in @($summaries[$id].Outcomes.Keys|Sort-Object)){[pscustomobject]@{Value=$v;Count=$summaries[$id].Outcomes[$v]}})}
        })
    }
}
