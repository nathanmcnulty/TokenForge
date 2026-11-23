#Requires -Version 7.6
[CmdletBinding(DefaultParameterSetName='Pages')]
param(
    [Parameter(Mandatory,ParameterSetName='Pages')][string]$FixtureDirectory,
    [Parameter(Mandatory,ParameterSetName='Snapshot')][string]$SnapshotPath,
    [Parameter(Mandatory,ParameterSetName='Memory')][AllowEmptyCollection()][object]$SnapshotRows,
    [Parameter(ParameterSetName='Memory')][ValidateRange(1,100000)][int]$MaxInMemoryRows = 1000,
    [Parameter(Mandatory)][string]$CatalogRepository,
    [Parameter(Mandatory)][ValidatePattern('^[0-9a-f]{40}$')][string]$CatalogCommit,
    [Parameter(Mandatory)][DateTimeOffset]$Since,
    [Parameter(Mandatory)][DateTimeOffset]$Until,
    [ValidateRange(1,500)][int]$MaxPages = 100,
    [switch]$PreviewAllEventTypes
)
$PSDefaultParameterValues = @{ Disabled = $true }
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$memory = $PSCmdlet.ParameterSetName -eq 'Memory'
$snapshot = $memory -or $PSCmdlet.ParameterSetName -eq 'Snapshot'
$maxRows = if ($memory) { $MaxInMemoryRows } else { 1000 }
$since = $Since.ToUniversalTime()
$until = $Until.ToUniversalTime()
if ($since -ge $until -or ($until - $since).TotalDays -gt 31) {
    throw 'Choose an ordered UTC interval of at most 31 days.'
}

function Read-ReplayJson([string]$Path) {
    $file = [IO.File]::Open($Path,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
    try {
        if ($file.Length -gt 4194304) { throw 'Replay file exceeds 4 MiB.' }
        $bytes = [byte[]]::new([int]$file.Length)
        $file.ReadExactly($bytes)
        if ($file.ReadByte() -ne -1) { throw 'Replay file grew during reading.' }
        $text = [Text.UTF8Encoding]::new($false,$true).GetString($bytes).TrimStart([char]0xFEFF)
        $options = [Text.Json.JsonDocumentOptions]::new()
        $options.AllowDuplicateProperties = $false
        $json = [Text.Json.JsonDocument]::Parse($text,$options)
        try {
            # Enforce duplicate-key rejection before PowerShell materializes the object.
            return ,(ConvertFrom-Json -InputObject $text -AsHashtable -DateKind String -NoEnumerate)
        } finally { $json.Dispose() }
    } finally { $file.Dispose() }
}

function ConvertTo-ObservedGuid($Value) {
    $parsed = [guid]::Empty
    if ($Value -is [string] -and [guid]::TryParseExact($Value, 'D', [ref]$parsed) -and $parsed -ne [guid]::Empty) {
        return $parsed.ToString()
    }
}

function Read-LocalCatalogGit([string[]]$Arguments) {
    $info = [Diagnostics.ProcessStartInfo]::new()
    $info.FileName = 'git'
    $info.UseShellExecute = $false
    $info.RedirectStandardOutput = $true
    $info.RedirectStandardError = $true
    $info.StandardOutputEncoding = [Text.UTF8Encoding]::new($false,$true)
    $info.Environment['GIT_NO_LAZY_FETCH'] = '1'
    $info.Environment['GIT_ALLOW_PROTOCOL'] = ''
    $info.Environment['GIT_TERMINAL_PROMPT'] = '0'
    foreach ($argument in (@('--no-replace-objects','-c','protocol.allow=never','-C',$CatalogRepository) + $Arguments)) {
        $info.ArgumentList.Add($argument)
    }
    $process = [Diagnostics.Process]::Start($info)
    try {
        $output = $process.StandardOutput.ReadToEndAsync()
        $diagnostics = $process.StandardError.ReadToEndAsync()
        if (-not $process.WaitForExit(30000)) {
            $process.Kill($true)
            throw 'Local Git catalog read timed out.'
        }
        if ($process.ExitCode -ne 0) { throw 'Pinned catalog objects must be available locally.' }
        $null = $diagnostics.GetAwaiter().GetResult()
        return $output.GetAwaiter().GetResult()
    } finally { $process.Dispose() }
}

$objectType = Read-LocalCatalogGit @('cat-file','-t',$CatalogCommit)
if ($objectType.Trim() -cne 'commit') { throw 'The pinned catalog object must be a Git commit.' }
$known = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
foreach ($file in @('applications.json','applications.non-verified.json')) {
    $text = Read-LocalCatalogGit @('cat-file','blob',"${CatalogCommit}:$file")
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
$version = if ($PreviewAllEventTypes) { 'beta' } else { 'v1.0' }
$path = "/$version/auditLogs/signIns"
$types = @('interactiveUser','nonInteractiveUser','servicePrincipal','managedIdentity')
$observations = @{ AppId = @{}; GraphResourceId = @{} }
# Hashes stay in memory and are scoped to this run. Event IDs never appear in output.
$seenEvents = [Collections.Generic.Dictionary[string,string]]::new([StringComparer]::Ordinal)
$coverage = [Collections.Generic.List[object]]::new()
$pageCount = 0
$complete = $true

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
    $end = if ($snapshot) { $until } else { $start.AddDays(1) }
    if ($end -gt $until) { $end = $until }
    $window = [ordered]@{
        Since = $start.ToString('o'); UntilExclusive = $end.ToString('o'); Pages = 0
        UniqueEvents = 0; DuplicateEvents = 0; MalformedEvents = 0; BoundaryEventsSkipped = 0
        UnusableAppIds = 0; UnusableGraphResourceIds = 0; Status = 'Complete'
    }
    $coverage.Add($window)
    if ($pageCount -ge $MaxPages) { $window.Status = 'PageLimit'; $complete = $false; continue }
    $next = $null
    $seenPages = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    do {
        if ($null -ne $next) {
            $uri = $null
            if ($next -isnot [string] -or $next.Length -gt 16384 -or
                -not [uri]::TryCreate($next,[UriKind]::Absolute,[ref]$uri) -or
                $next -notmatch '\Ahttps://graph\.microsoft\.com(?::443)?/' -or
                $uri.Scheme -ne 'https' -or $uri.Host -ne 'graph.microsoft.com' -or $uri.Port -ne 443 -or
                $uri.UserInfo -or $uri.Fragment -or $uri.AbsolutePath -ine $path) {
                $window.Status = 'InvalidNextLink'; break
            }
            if (-not $seenPages.Add($next)) { $window.Status = 'PaginationLoop'; break }
        }
        if ($pageCount -ge $MaxPages) { $window.Status = 'PageLimit'; break }
        $pageCount++
        try {
            if ($snapshot) {
                $rows = if ($memory) { ,$SnapshotRows } else { ,(Read-ReplayJson $SnapshotPath) }
                if ($rows -isnot [array]) { $window.Status = 'InvalidPage'; break }
                $page = @{ value = $rows }
            } else {
                $fixture = Join-Path $FixtureDirectory ('window-{0}-page-{1}.json' -f $coverage.Count,($window.Pages + 1))
                $page = Read-ReplayJson $fixture
            }
        } catch {
            $window.Status = 'FixtureUnavailable'
            break
        }
        if ($page -isnot [Collections.IDictionary] -or $page['value'] -isnot [array] -or $page['value'].Count -gt $maxRows) {
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
    } while ($null -ne $next)
    if ($window.Status -eq 'Complete' -and $window.MalformedEvents) { $window.Status = 'MalformedEvents' }
    if ($window.Status -ne 'Complete') { $complete = $false }
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
    Source = if ($memory) { 'InMemorySnapshot' } elseif ($snapshot) { 'LocalSnapshot' } else { 'LocalPageReplay' }
    GraphVersion = $version
    InputEventShape = if ($PreviewAllEventTypes) { 'GraphBetaEventTypes' } else { 'GraphV1IsInteractive' }
    ReplayComplete = $complete; SourceWindowCoverage = 'Unknown'; TenantHistoryComplete = $false
    ActualAudience = 'UnknownFromSignInLogs'
    Since = $since.ToString('o'); UntilExclusive = $until.ToString('o')
    Windows = $coverage.ToArray(); Candidates = @($candidates)
} | ConvertTo-Json -Depth 12
if (-not $complete) { exit 2 }
