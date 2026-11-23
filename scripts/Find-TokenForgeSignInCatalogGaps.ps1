#Requires -Version 7.6
[CmdletBinding(DefaultParameterSetName='Graph')]
param(
    [Parameter(Mandatory,ParameterSetName='Graph')][guid]$TenantId,
    [Parameter(Mandatory,ParameterSetName='Replay')][string]$FixtureDirectory,
    [Parameter(Mandatory)][string]$CatalogRepository,
    [Parameter(Mandatory)][ValidatePattern('^[0-9a-f]{40}$')][string]$CatalogCommit,
    [Parameter(Mandatory)][DateTimeOffset]$Since,
    [Parameter(Mandatory)][DateTimeOffset]$Until,
    [ValidateRange(1,500)][int]$MaxPages = 100,
    [switch]$PreviewAllEventTypes
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$replay = $PSCmdlet.ParameterSetName -eq 'Replay'
$since = $Since.ToUniversalTime()
$until = $Until.ToUniversalTime()
if ($since -ge $until -or ($until - $since).TotalDays -gt 31 -or (-not $replay -and $until -gt [DateTimeOffset]::UtcNow)) {
    throw 'Choose an ordered UTC interval of at most 31 days. Live intervals must end in the past.'
}
if (-not $replay -and $TenantId -eq [guid]::Empty) { throw 'A nonzero tenant ID is required.' }

function Assert-SignInReadContext {
    try { $ctx = Get-MgContext -ErrorAction Stop -Debug:$false -Verbose:$false }
    catch { throw 'Could not read the existing Microsoft Graph context.' }
    $actual = [guid]::Empty
    if (-not $ctx -or -not [guid]::TryParse([string]$ctx.TenantId, [ref]$actual) -or
        $actual -ne $TenantId -or $ctx.AuthType -ne 'Delegated' -or $ctx.Environment -ne 'Global' -or
        'AuditLog.Read.All' -notin $ctx.Scopes) {
        throw 'The existing delegated Microsoft Graph context must match the requested tenant and have AuditLog.Read.All in the Global environment.'
    }
}

function ConvertTo-ObservedGuid($Value) {
    $parsed = [guid]::Empty
    if ($Value -is [string] -and [guid]::TryParseExact($Value, 'D', [ref]$parsed) -and $parsed -ne [guid]::Empty) {
        return $parsed.ToString()
    }
}

$known = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
foreach ($file in @('applications.json','applications.non-verified.json')) {
    $text = & git --no-replace-objects -C $CatalogRepository show ("${CatalogCommit}:$file") 2>$null
    if ($LASTEXITCODE -ne 0) { throw 'Both catalog partitions are required at the pinned Git commit.' }
    $catalog = $text | ConvertFrom-Json -AsHashtable -DateKind String
    $format = if ($file -eq 'applications.json') { 'TokenForgeApplicationMetadata' } else { 'TokenForgeNonVerifiedApplications' }
    $schema = if ($file -eq 'applications.json') { 2 } else { 1 }
    if ($catalog['Format'] -cne $format -or $catalog['SchemaVersion'] -ne $schema -or
        $catalog['Applications'] -isnot [Collections.IDictionary]) { throw 'Unexpected catalog format.' }
    foreach ($key in $catalog.Applications.Keys) {
        $id = ConvertTo-ObservedGuid $key
        if (-not $id -or $id -cne $key -or -not $known.Add($id)) { throw 'Malformed or overlapping catalog partitions.' }
    }
}
if (-not $replay) { Assert-SignInReadContext }

$version = if ($PreviewAllEventTypes) { 'beta' } else { 'v1.0' }
$path = "/$version/auditLogs/signIns"
$types = @('interactiveUser','nonInteractiveUser','servicePrincipal','managedIdentity')
$eventFilter = if ($PreviewAllEventTypes) {
    ' and (signInEventTypes/any(t: ' + (($types | ForEach-Object { "t eq '$_'" }) -join ' or ') + '))'
} else { '' }
$fields = if ($PreviewAllEventTypes) { 'id,appId,resourceId,createdDateTime,signInEventTypes' } else { 'id,appId,resourceId,createdDateTime,isInteractive' }
$observations = @{ AppId = @{}; GraphResourceId = @{} }
# Hashes stay in memory and are scoped to this run. Event IDs never appear in output.
$seenEvents = [Collections.Generic.Dictionary[string,string]]::new([StringComparer]::Ordinal)
$coverage = [Collections.Generic.List[object]]::new()
$pageCount = 0
$complete = $true
$stopReason = $null

function Add-Candidate($Kind, $Id, $When, $EventTypes) {
    if (-not $Id -or $known.Contains($Id)) { return }
    $bucket = $observations[$Kind]
    if (-not $bucket.ContainsKey($Id)) {
        $bucket[$Id] = @{ Count = 0; First = $When; Last = $When; Types = @{} }
    }
    $entry = $bucket[$Id]
    $entry.Count++
    if ($When -lt $entry.First) { $entry.First = $When }
    if ($When -gt $entry.Last) { $entry.Last = $When }
    foreach ($type in $EventTypes) { $entry.Types[$type] = 1 + [int]$entry.Types[$type] }
}

for ($start = $since; $start -lt $until; $start = $end) {
    $end = $start.AddDays(1)
    if ($end -gt $until) { $end = $until }
    $window = [ordered]@{
        Since = $start.ToString('o'); UntilExclusive = $end.ToString('o'); Pages = 0
        UniqueEvents = 0; DuplicateEvents = 0; MalformedEvents = 0; BoundaryEventsSkipped = 0
        UnusableAppIds = 0; UnusableGraphResourceIds = 0; Status = 'Complete'
    }
    $coverage.Add($window)
    if ($stopReason) { $window.Status = $stopReason; continue }
    if ($pageCount -ge $MaxPages) { $window.Status = 'PageLimit'; $complete = $false; continue }
    # Graph documents ge/le. Apply the exclusive upper bound locally.
    $filter = 'createdDateTime ge {0} and createdDateTime le {1}{2}' -f $start.UtcDateTime.ToString('o'),$end.UtcDateTime.ToString('o'),$eventFilter
    $next = 'https://graph.microsoft.com' + $path + '?$select=' + $fields + '&$top=1000&$filter=' + [uri]::EscapeDataString($filter)
    $seenPages = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    while ($next) {
        $uri = $null
        if ($next -isnot [string] -or $next.Length -gt 16384 -or
            -not [uri]::TryCreate($next,[UriKind]::Absolute,[ref]$uri) -or
            $next -notmatch '\Ahttps://graph\.microsoft\.com(?::443)?/' -or
            $uri.Scheme -ne 'https' -or $uri.Host -ne 'graph.microsoft.com' -or $uri.Port -ne 443 -or
            $uri.UserInfo -or $uri.Fragment -or $uri.AbsolutePath -ine $path) {
            $window.Status = 'InvalidNextLink'; break
        }
        if (-not $seenPages.Add($next)) { $window.Status = 'PaginationLoop'; break }
        if ($pageCount -ge $MaxPages) { $window.Status = 'PageLimit'; break }
        $pageCount++
        if (-not $replay) {
            try { Assert-SignInReadContext }
            catch { $window.Status = 'ContextChanged'; break }
        }
        try {
            if ($replay) {
                # Synthetic replay consumes the exact sequential page shape and the same next-link checks.
                $fixture = Join-Path $FixtureDirectory ('window-{0}-page-{1}.json' -f $coverage.Count,($window.Pages + 1))
                $source = Get-Item -LiteralPath $fixture
                if ($source.Length -gt 4194304) { throw 'Fixture size limit.' }
                $page = Get-Content -LiteralPath $fixture -Raw | ConvertFrom-Json -AsHashtable -DateKind String
            } else {
                $page = Invoke-MgGraphRequest -Method GET -Uri $uri -OutputType Hashtable -ErrorAction Stop -Debug:$false -Verbose:$false
            }
        } catch {
            $window.Status = if ($replay) { 'FixtureUnavailable' } else { 'GraphRequestFailed' }
            break
        }
        if ($page -isnot [Collections.IDictionary] -or $page['value'] -isnot [array] -or $page['value'].Count -gt 1000) {
            $window.Status = 'InvalidPage'; break
        }
        $window.Pages++
        foreach ($event in $page['value']) {
            $stamp = [DateTimeOffset]::MinValue
            if ($event -isnot [Collections.IDictionary] -or $event['id'] -isnot [string] -or
                [string]::IsNullOrWhiteSpace($event['id']) -or $event['id'].Length -gt 512) {
                $window.MalformedEvents++; continue
            }
            $eventTime = $event['createdDateTime']
            $hasTime = if ($eventTime -is [DateTimeOffset]) {
                $stamp = $eventTime; $true
            } elseif ($eventTime -is [DateTime] -and $eventTime.Kind -ne [DateTimeKind]::Unspecified) {
                $stamp = [DateTimeOffset]::new($eventTime); $true
            } else {
                $eventTime -is [string] -and $eventTime -match '(?:Z|[+-]\d{2}:\d{2})$' -and
                    [DateTimeOffset]::TryParse($eventTime,[Globalization.CultureInfo]::InvariantCulture,[Globalization.DateTimeStyles]::None,[ref]$stamp)
            }
            if (-not $hasTime -or $stamp -lt $start -or $stamp -gt $end) { $window.MalformedEvents++; continue }
            if ($stamp -eq $end) { $window.BoundaryEventsSkipped++; continue }
            $stamp = $stamp.ToUniversalTime()
            $eventTypes = if ($PreviewAllEventTypes -and $event['signInEventTypes'] -is [array]) {
                $event['signInEventTypes'] | Where-Object { $_ -cin $types } | Sort-Object -Unique
            } elseif (-not $PreviewAllEventTypes -and $event['isInteractive'] -is [bool]) {
                if ($event['isInteractive']) { 'interactiveUser' } else { 'nonInteractiveUser' }
            }
            $eventTypes = @($eventTypes | Where-Object { $_ })
            if (-not $eventTypes.Count -or ($PreviewAllEventTypes -and @($event['signInEventTypes'] | Where-Object { $_ -cnotin $types }).Count)) {
                $window.MalformedEvents++; continue
            }
            $app = ConvertTo-ObservedGuid $event['appId']
            $resource = ConvertTo-ObservedGuid $event['resourceId']
            $key = [Convert]::ToHexStringLower([Security.Cryptography.SHA256]::HashData([Text.Encoding]::UTF8.GetBytes($event['id'])))
            $projection = "$($stamp.ToString('o'))|$app|$resource|$($eventTypes -join ',')"
            $identity = [Convert]::ToHexStringLower([Security.Cryptography.SHA256]::HashData([Text.Encoding]::UTF8.GetBytes($projection)))
            if ($seenEvents.ContainsKey($key)) {
                if ($seenEvents[$key] -cne $identity) { $window.MalformedEvents++ } else { $window.DuplicateEvents++ }
                continue
            }
            $seenEvents.Add($key,$identity)
            $window.UniqueEvents++
            if (-not $app) { $window.UnusableAppIds++ }
            if (-not $resource) { $window.UnusableGraphResourceIds++ }
            Add-Candidate AppId $app $stamp $eventTypes
            Add-Candidate GraphResourceId $resource $stamp $eventTypes
        }
        $next = $page['@odata.nextLink']
        $page = $null
        $event = $null
        if ($null -ne $next -and ($next -isnot [string] -or [string]::IsNullOrWhiteSpace($next))) {
            $window.Status = 'InvalidNextLink'; break
        }
    }
    if ($window.Status -eq 'Complete' -and $window.MalformedEvents) { $window.Status = 'MalformedEvents' }
    if ($window.Status -ne 'Complete') { $complete = $false }
    if ($window.Status -in @('ContextChanged','GraphRequestFailed')) { $stopReason = 'NotAttemptedAfterReadFailure' }
}

$candidates = foreach ($kind in @('AppId','GraphResourceId')) {
    foreach ($id in ($observations[$kind].Keys | Sort-Object)) {
        $row = $observations[$kind][$id]
        $eventCounts = [ordered]@{}
        foreach ($type in ($row.Types.Keys | Sort-Object)) { $eventCounts[$type] = $row.Types[$type] }
        [ordered]@{ IdentifierKind = $kind; Identifier = $id; Disposition = 'Pending'; Count = $row.Count
            FirstObservedAt = $row.First.ToString('o'); LastObservedAt = $row.Last.ToString('o'); EventTypeCounts = $eventCounts }
    }
}
[ordered]@{
    Format = 'TokenForgeSignInCatalogGaps'; SchemaVersion = 1; CatalogCommit = $CatalogCommit
    Source = if ($replay) { 'SyntheticReplay' } else { 'MicrosoftGraph' }
    GraphVersion = $version
    CoverageScope = if ($PreviewAllEventTypes) { 'Retained Graph preview events for four explicitly filtered categories' } else { 'Retained user sign-ins returned by Graph v1.0' }
    EnumerationComplete = $complete; TenantHistoryComplete = $false; ActualAudience = 'UnknownFromSignInLogs'
    Since = $since.ToString('o'); UntilExclusive = $until.ToString('o')
    Windows = $coverage.ToArray(); Candidates = @($candidates)
} | ConvertTo-Json -Depth 12
if (-not $complete) { exit 2 }
