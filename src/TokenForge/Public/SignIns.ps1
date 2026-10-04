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
    $next='https://graph.microsoft.com/beta/auditLogs/signIns?$top=1000&$filter='+[uri]::EscapeDataString($filter)
    $seen=[Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    $counts=@{};$records=0;$invalid=0;$pages=0
    while($next){
        $u=[uri]$next
        if($u.Scheme -ne 'https' -or $u.Host -ne 'graph.microsoft.com' -or $u.Port -ne 443 -or $u.UserInfo -or $u.Fragment -or $u.AbsolutePath -cne '/beta/auditLogs/signIns'){throw 'Sign-in pagination left its endpoint boundary.'}
        if($pages -ge $MaxPages -or -not $seen.Add($next)){throw 'Sign-in page limit or pagination loop reached; no complete discovery returned.'}
        $response=Invoke-TokenForgeGraph -AccessToken $GraphToken -Uri $u;$pages++
        if($response -isnot [Collections.IDictionary] -or -not $response.Contains('value') -or $response['value'] -isnot [array]){throw 'Invalid sign-in collection response.'}
        foreach($row in $response['value']){
            $records++;$id=[guid]::Empty
            if($row -isnot [Collections.IDictionary] -or -not [guid]::TryParse([string]$row['appId'],[ref]$id) -or $id -eq [guid]::Empty){$invalid++;continue}
            $key=$id.ToString();if(-not $counts.ContainsKey($key)){$counts[$key]=0};$counts[$key]++
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
            [pscustomobject]@{AppId=$id;SignInCount=$counts[$id];KnownInInventory=$known.ContainsKey($id);RegisteredMicrosoft=($known.ContainsKey($id) -and $known[$id].Registration -eq 'Present' -and $known[$id].Ownership -eq 'VerifiedMicrosoftOwner');Evidence='ObservedSignInNotOwnership'}
        })
    }
}
