#Requires -Version 7.6
[CmdletBinding()]
param(
    [Parameter(Mandatory)][guid]$TenantId,
    [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$Account,
    [Parameter(Mandatory)][string]$CatalogRepository,
    [Parameter(Mandatory)][ValidatePattern('\A[0-9a-f]{40}\z')][string]$CatalogCommit,
    [Parameter(Mandatory)][DateTimeOffset]$Since,
    [Parameter(Mandatory)][DateTimeOffset]$Until,
    [Parameter(Mandatory)][string]$CheckpointDirectory,
    [ValidateNotNullOrEmpty()][ValidateSet('interactiveUser','nonInteractiveUser')][string[]]$EventType = @('interactiveUser','nonInteractiveUser'),
    [ValidateSet(1,24)][int]$WindowHours = 24,
    [ValidateRange(1,100)][int]$MaxPagesPerWindow = 40,
    [ValidateRange(0,3)][int]$MaxRetries = 2,
    [ValidateRange(0,120)][int]$MaxRetryDelaySeconds = 30
)

$PSDefaultParameterValues = @{ Disabled = $true }
$ErrorActionPreference = 'Stop'
$DebugPreference = $VerbosePreference = $ProgressPreference = 'SilentlyContinue'
Set-StrictMode -Version Latest

$CatalogCommit = $CatalogCommit.ToLowerInvariant()
$EventType = @('interactiveUser','nonInteractiveUser') | Where-Object { $_ -in $EventType }
$Since = $Since.ToUniversalTime()
$Until = $Until.ToUniversalTime()
if ($Since -ge $Until -or ($Until - $Since).TotalDays -gt 31 -or $Until -gt [DateTimeOffset]::UtcNow) {
    throw 'Choose an ordered interval of at most 31 days, ending in the past.'
}
$folder = Get-Item -LiteralPath $CheckpointDirectory
if (-not $folder.PSIsContainer -or ($folder.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
    throw 'Use an existing private checkpoint directory.'
}
if (-not $IsWindows) {
    $privateMode = [IO.UnixFileMode]'UserRead,UserWrite,UserExecute'
    if ([IO.File]::GetUnixFileMode($folder.FullName) -ne $privateMode) { throw 'Use a checkpoint directory with mode 0700.' }
}

function Get-VerifiedContext {
    try {
        $context = Microsoft.Graph.Authentication\Get-MgContext -ErrorAction Stop
        $globalCloud = Microsoft.Graph.Authentication\Get-MgEnvironment -Name Global -ErrorAction Stop
        $checkEnd = $Since.AddHours(1)
        if ($checkEnd -gt $Until) { $checkEnd = $Until }
        $null = & "$PSScriptRoot/New-TokenForgeSignInReadPlan.ps1" -TenantId $TenantId -Context $context `
            -Environment $globalCloud -Since $Since -Until $checkEnd
        if ($context.Account -ine $Account) { throw 'Unexpected account.' }
    } catch {
        throw 'Use the expected account and tenant with an existing delegated process-scoped Global SDK context and AuditLog.Read.All.'
    }
}

function Get-RelativeSignInLink($Link) {
    if ($Link -isnot [string] -or $Link.Length -gt 16384 -or
        $Link -notmatch '\Ahttps://graph\.microsoft\.com(?::443)?(/beta/auditLogs/signIns\?[^#\s]+)\z') { return }
    $relative = $Matches[1]
    $uri = $null
    if ([uri]::TryCreate($Link,[UriKind]::Absolute,[ref]$uri) -and $uri.Scheme -ceq 'https' -and
        $uri.Host -ceq 'graph.microsoft.com' -and $uri.Port -eq 443 -and -not $uri.UserInfo -and
        -not $uri.Fragment -and $uri.AbsolutePath -ieq '/beta/auditLogs/signIns') { return $relative }
}

function Read-GraphPage([Net.Http.HttpResponseMessage]$Response) {
    $limit = 16 * 1024 * 1024
    $stream = $Response.Content.ReadAsStream()
    $memory = [IO.MemoryStream]::new()
    try {
        $buffer = [byte[]]::new(8192)
        while (($size = $stream.Read($buffer,0,$buffer.Length)) -ne 0) {
            if ($memory.Length + $size -gt $limit) { throw 'Page body exceeds limit.' }
            $memory.Write($buffer,0,$size)
        }
        $memory.Position = 0
        $options = [Text.Json.JsonDocumentOptions]::new()
        $options.AllowDuplicateProperties = $false
        $json = [Text.Json.JsonDocument]::Parse($memory,$options)
        try { return ,(ConvertFrom-Json -InputObject $json.RootElement.GetRawText() -AsHashtable -DateKind String -NoEnumerate) }
        finally { $json.Dispose() }
    } finally { $memory.Dispose(); $stream.Dispose() }
}

function Request-SignInPage([string]$Relative) {
    for ($attempt = 0; $attempt -le $MaxRetries; $attempt++) {
        $status = $null
        $retryAfter = $null
        $response = $null
        try {
            Get-VerifiedContext
        } catch { return @{ Status='ContextRejected'; Attempts=$attempt; HttpStatus=$null; RetryAfterSeconds=$null } }
        try {
            # A validated relative URI keeps the SDK bound to its built-in Global environment.
            $response = Microsoft.Graph.Authentication\Invoke-MgGraphRequest -Method GET -Uri $Relative `
                -OutputType HttpResponseMessage -SkipHttpErrorCheck -ErrorAction Stop -Debug:$false -Verbose:$false `
                -WarningAction SilentlyContinue -InformationAction Ignore
            if ($response -isnot [Net.Http.HttpResponseMessage]) { throw 'Expected an HTTP response.' }
            $status = [int]$response.StatusCode
            $effective = $response.RequestMessage.RequestUri
            if (-not (Get-RelativeSignInLink $effective.AbsoluteUri)) {
                return @{ Status='UnexpectedResponseOrigin'; Attempts=$attempt+1; HttpStatus=$status; RetryAfterSeconds=$null }
            }
            if ($status -eq 200) {
                try { $page = Read-GraphPage $response }
                catch { return @{ Status='InvalidPage'; Attempts=$attempt+1; HttpStatus=$status; RetryAfterSeconds=$null } }
                return @{ Status='Page'; Attempts=$attempt+1; HttpStatus=$status; RetryAfterSeconds=$null; Page=$page }
            }
            $header = $response.Headers.RetryAfter
            if ($null -ne $header) {
                $delta = if ($null -ne $header.Delta) { $header.Delta.TotalSeconds } elseif ($null -ne $header.Date) {
                    ($header.Date - [DateTimeOffset]::UtcNow).TotalSeconds
                } else { 0 }
                $retryAfter = [Math]::Max(0,[Math]::Ceiling($delta))
            }
        } catch {
            $failure = if ($_.Exception -is [OperationCanceledException]) { 'TransportTimeout' } else { 'TransportFailure' }
            return @{ Status=$failure; Attempts=$attempt+1; HttpStatus=$status; RetryAfterSeconds=$null }
        } finally {
            if ($response -is [Net.Http.HttpResponseMessage]) { $response.Dispose() }
        }
        if ($status -notin @(429,503)) {
            $failure = if ($status -in @(401,403)) { 'AccessDenied' } else { 'HttpFailure' }
            return @{ Status=$failure; Attempts=$attempt+1; HttpStatus=$status; RetryAfterSeconds=$retryAfter }
        }
        $delay = if ($null -ne $retryAfter) { $retryAfter } else { [Math]::Pow(2,$attempt) }
        if ($attempt -eq $MaxRetries -or $delay -gt $MaxRetryDelaySeconds) {
            return @{ Status='RetryDeferred'; Attempts=$attempt+1; HttpStatus=$status; RetryAfterSeconds=$delay }
        }
        if ($delay -gt 0) { Start-Sleep -Seconds $delay }
    }
}

function Get-CheckpointKey([string]$Kind,[DateTimeOffset]$Start,[DateTimeOffset]$End) {
    $key = "TokenForgeGraphSignInV1|${TenantId}|${CatalogCommit}|$Kind|$($Start.ToString('o'))|$($End.ToString('o'))"
    [Convert]::ToHexStringLower([Security.Cryptography.SHA256]::HashData([Text.Encoding]::UTF8.GetBytes($key)))
}

function Save-Checkpoint([string]$Path,$Receipt) {
    $temp = "$Path.$([guid]::NewGuid().ToString('N')).tmp"
    try {
        $options = [IO.FileStreamOptions]::new()
        $options.Mode = [IO.FileMode]::CreateNew
        $options.Access = [IO.FileAccess]::Write
        if (-not $IsWindows) { $options.UnixCreateMode = [IO.UnixFileMode]'UserRead,UserWrite' }
        $stream = [IO.FileStream]::new($temp,$options)
        try {
            $stream.Write([Text.Encoding]::UTF8.GetBytes((ConvertTo-Json -InputObject $Receipt -Depth 16)))
            $stream.Flush($true)
        } finally { $stream.Dispose() }
        [IO.File]::Move($temp,$Path)
    } finally { if ([IO.File]::Exists($temp)) { [IO.File]::Delete($temp) } }
}

Get-VerifiedContext
# Parse both catalog partitions before any Graph requests.
$aggregator = "$PSScriptRoot/Find-TokenForgeSignInCatalogGaps.ps1"
$null = & $aggregator -CatalogRepository $CatalogRepository -CatalogCommit $CatalogCommit -Since $Since -Until $Until -SnapshotRows @()
$ledger = [Collections.Generic.List[object]]::new()
$paused = $false
foreach ($kind in ($EventType | Sort-Object -Unique)) {
    for ($start = $Since; $start -lt $Until; $start = $end) {
        # Align to UTC midnight/hour; the initial or terminal window can be shorter.
        $aligned = if ($WindowHours -eq 24) { $start.UtcDateTime.Date.AddDays(1) } else {
            $start.UtcDateTime.Date.AddHours($start.Hour + 1)
        }
        $end = [DateTimeOffset]::new($aligned)
        if ($end -gt $Until) { $end = $Until }
        $key = Get-CheckpointKey $kind $start $end
        $filename = "window-$key.json"
        $path = Join-Path $folder.FullName $filename
        $window = [ordered]@{ EventType=$kind; Since=$start.ToString('o'); UntilExclusive=$end.ToString('o');
            Status='Pending'; Pages=0; Requests=0; HttpStatus=$null; RetryAfterSeconds=$null; Receipt=$null }
        $ledger.Add($window)
        if (Test-Path -LiteralPath $path) {
            try {
                $saved = Get-Item -LiteralPath $path
                if ($saved.PSIsContainer -or ($saved.Attributes -band [IO.FileAttributes]::ReparsePoint) -or $saved.Length -gt 33554432) { throw 'Invalid checkpoint file.' }
                $data = Get-Content -LiteralPath $path -Raw | ConvertFrom-Json -AsHashtable -DateKind String
                $savedAggregate = $data.Aggregate
                if ($data -isnot [Collections.IDictionary] -or $data.Count -ne 6 -or
                    $data.Format -cne 'TokenForgeGraphSignInWindow' -or $data.SchemaVersion -ne 1 -or $data.Key -cne $key -or
                    $data.EventType -cne $kind -or $data.Pages -isnot [long] -or $data.Pages -lt 1 -or $data.Pages -gt 100 -or
                    $savedAggregate -isnot [Collections.IDictionary] -or $savedAggregate.Count -ne 14 -or
                    $savedAggregate.Format -cne 'TokenForgeSignInCatalogGaps' -or $savedAggregate.SchemaVersion -ne 1 -or
                    $savedAggregate.GraphVersion -cne 'beta' -or $savedAggregate.InputEventShape -cne 'GraphBetaEventTypes' -or
                    $savedAggregate.Source -cne 'InMemorySnapshot' -or $savedAggregate.CatalogCommit -cne $CatalogCommit -or
                    $savedAggregate.Since -cne $window.Since -or $savedAggregate.UntilExclusive -cne $window.UntilExclusive -or
                    $savedAggregate.ReplayComplete -isnot [bool] -or -not $savedAggregate.ReplayComplete -or
                    $savedAggregate.TenantHistoryComplete -isnot [bool] -or $savedAggregate.TenantHistoryComplete -or
                    $savedAggregate.SourceWindowCoverage -cne 'Unknown' -or $savedAggregate.ActualAudience -cne 'UnknownFromSignInLogs' -or
                    $savedAggregate.Candidates -isnot [array] -or $savedAggregate.Windows -isnot [array] -or
                    $savedAggregate.Windows.Count -ne 1 -or $savedAggregate.Windows[0].Status -cne 'Complete' -or
                    $savedAggregate.Windows[0].Since -cne $window.Since -or
                    $savedAggregate.Windows[0].UntilExclusive -cne $window.UntilExclusive) { throw 'Invalid checkpoint envelope.' }
                $window.Status = 'Resumed'
                $window.Pages = $data.Pages
                $window.Receipt = $filename
                continue
            } catch { $window.Status = 'InvalidCheckpoint'; $paused = $true; continue }
        }
        if ($paused) { continue }

        $filter = "createdDateTime ge $($start.UtcDateTime.ToString('o')) and createdDateTime le $($end.UtcDateTime.ToString('o')) and signInEventTypes/any(t: t eq '$kind')"
        $next = '/beta/auditLogs/signIns?$top=250&$filter=' + [uri]::EscapeDataString($filter)
        $visited = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
        $rows = [Collections.Generic.List[object]]::new()
        do {
            if (-not $visited.Add($next)) { $window.Status = 'PaginationLoop'; break }
            if ($window.Pages -ge $MaxPagesPerWindow) { $window.Status = 'PageLimit'; break }
            $page = Request-SignInPage $next
            $window.Requests += $page.Attempts
            $window.HttpStatus = $page.HttpStatus
            $window.RetryAfterSeconds = $page.RetryAfterSeconds
            if ($page.Status -cne 'Page') { $window.Status = $page.Status; break }
            $payload = $page.Page
            if ($payload -isnot [Collections.IDictionary] -or $payload['value'] -isnot [array] -or $payload['value'].Count -gt 1000) {
                $window.Status = 'InvalidPage'; break
            }
            $window.Pages++
            foreach ($event in $payload['value']) {
                if ($event -isnot [Collections.IDictionary] -or $event['signInEventTypes'] -isnot [array] -or
                    $event['signInEventTypes'].Count -ne 1 -or $event['signInEventTypes'][0] -cne $kind) {
                    $window.Status = 'UnexpectedEventType'; break
                }
                $rows.Add(@{ id=$event['id']; appId=$event['appId']; resourceId=$event['resourceId'];
                    createdDateTime=$event['createdDateTime']; signInEventTypes=@($kind) })
            }
            if ($window.Status -ceq 'UnexpectedEventType') { break }
            if (-not $payload.Contains('@odata.nextLink')) { $window.Status = 'TerminalPage'; break }
            $next = Get-RelativeSignInLink $payload['@odata.nextLink']
            if (-not $next) { $window.Status = 'InvalidNextLink'; break }
        } while ($true)
        $page = $null; $payload = $null; $event = $null

        if ($window.Status -ceq 'TerminalPage') {
            try {
                $aggregate = & $aggregator -CatalogRepository $CatalogRepository -CatalogCommit $CatalogCommit `
                    -Since $start -Until $end -SnapshotRows ($rows.ToArray()) -MaxInMemoryRows ($MaxPagesPerWindow * 1000) -PreviewAllEventTypes | ConvertFrom-Json -AsHashtable -DateKind String
                if (-not $aggregate.ReplayComplete) { $window.Status = 'InvalidEvents' }
                else {
                    Save-Checkpoint $path ([ordered]@{ Format='TokenForgeGraphSignInWindow'; SchemaVersion=1; Key=$key;
                        EventType=$kind; Pages=$window.Pages; Aggregate=$aggregate })
                    $window.Status = 'Complete'
                    $window.Receipt = $filename
                }
            } catch { $window.Status = 'AggregateOrCheckpointFailure' }
        }
        $rows.Clear()
        if ($window.Status -cne 'Complete') { $paused = $true }
    }
}
$complete = @($ledger | Where-Object Status -NotIn @('Complete','Resumed')).Count -eq 0
[ordered]@{ Format='TokenForgeGraphSignInCollection'; SchemaVersion=1; GraphVersion='beta'; CatalogCommit=$CatalogCommit;
    Since=$Since.ToString('o'); UntilExclusive=$Until.ToString('o'); CollectionComplete=$complete;
    SourceWindowCoverage='Unknown'; TenantHistoryComplete=$false; ActualAudience='UnknownFromSignInLogs';
    SignInOutcome='NotInferred'; Windows=$ledger.ToArray() } | ConvertTo-Json -Depth 10
if (-not $complete) { exit 2 }
