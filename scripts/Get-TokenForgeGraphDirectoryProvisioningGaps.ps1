#Requires -Version 7.6
[CmdletBinding()]
param(
    [Parameter(Mandatory)][guid]$TenantId,
    [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$Account,
    [Parameter(Mandatory)][string]$CatalogRepository,
    [Parameter(Mandatory)][ValidatePattern('\A[0-9a-f]{40}\z')][string]$CatalogCommit,
    [Parameter(Mandatory)][DateTimeOffset]$Since,
    [Parameter(Mandatory)][DateTimeOffset]$Until,
    [ValidateRange(1,100)][int]$MaxPagesPerWindow = 40
)

$PSDefaultParameterValues = @{ Disabled = $true }
$ErrorActionPreference = 'Stop'
$DebugPreference = $VerbosePreference = $ProgressPreference = 'SilentlyContinue'
Set-StrictMode -Version Latest

$since = $Since.ToUniversalTime()
$until = $Until.ToUniversalTime()
$CatalogCommit = $CatalogCommit.ToLowerInvariant()
if ($since -ge $until -or ($until - $since).TotalDays -gt 31 -or $until -gt [DateTimeOffset]::UtcNow) {
    throw 'Choose an ordered interval of at most 31 days, ending in the past.'
}
$known = & "$PSScriptRoot/Read-TokenForgePinnedCatalogAppIds.ps1" -CatalogRepository $CatalogRepository -CatalogCommit $CatalogCommit
$endpoint = '/v1.0/auditLogs/directoryAudits'
$origin = 'https://graph.microsoft.com'

function Test-ReadContext([DateTimeOffset]$Start,[DateTimeOffset]$End) {
    try {
        $context = Microsoft.Graph.Authentication\Get-MgContext -ErrorAction Stop
        $cloud = Microsoft.Graph.Authentication\Get-MgEnvironment -Name Global -ErrorAction Stop
        $null = & "$PSScriptRoot/New-TokenForgeSignInReadPlan.ps1" -TenantId $TenantId -Context $context -Environment $cloud -Since $Start -Until $End
        return $context.Account -is [string] -and $context.Account -ieq $Account
    } catch { return $false }
}

function Get-RelativeDirectoryLink($Link) {
    if ($Link -isnot [string] -or $Link.Length -gt 16384 -or
        $Link -notmatch '\Ahttps://graph\.microsoft\.com(?::443)?(/v1\.0/auditLogs/directoryAudits\?[^#\s\p{Cc}]+)\z') { return }
    $relative = $Matches[1]
    $uri = $null
    if ([uri]::TryCreate($Link,[UriKind]::Absolute,[ref]$uri) -and $uri.Scheme -ceq 'https' -and
        $uri.Host -ceq 'graph.microsoft.com' -and $uri.Port -eq 443 -and -not $uri.UserInfo -and
        -not $uri.Fragment -and $uri.AbsolutePath -ieq $endpoint) { return $relative }
}

function Read-DirectoryPage([string]$Relative) {
    $response = $null
    $graphStatus = $null
    try {
        $request = @{ Method='GET'; Uri=$Relative; OutputType='HttpResponseMessage'; StatusCodeVariable='graphStatus';
            SkipHttpErrorCheck=$true; ErrorAction='Stop'; Debug=$false; Verbose=$false;
            WarningAction='SilentlyContinue'; InformationAction='Ignore' }
        $response = Microsoft.Graph.Authentication\Invoke-MgGraphRequest @request
        $validStatus = $graphStatus -is [int] -and $graphStatus -ge 100 -and $graphStatus -le 599
        if ($response -isnot [Net.Http.HttpResponseMessage]) {
            $failure = if ($validStatus -and $graphStatus -ne 200) { 'HttpFailure' } else { 'InvalidPage' }
            return @{ Status=$failure; HttpStatus=if ($validStatus) { $graphStatus } }
        }
        $status = [int]$response.StatusCode
        if ($status -lt 100 -or $status -gt 599 -or ($null -ne $graphStatus -and (-not $validStatus -or $graphStatus -ne $status))) {
            return @{ Status='InvalidHttpStatus'; HttpStatus=$null }
        }
        $effective = ($response.RequestMessage)?.RequestUri
        if ($null -eq $effective -or -not $effective.IsAbsoluteUri -or
            ([uri]($origin + $Relative)).AbsoluteUri -cne $effective.AbsoluteUri) {
            return @{ Status='UnexpectedResponseUri'; HttpStatus=$status }
        }
        if ($status -ne 200) { return @{ Status='HttpFailure'; HttpStatus=$status } }
        $stream = $response.Content.ReadAsStream()
        $memory = [IO.MemoryStream]::new()
        try {
            $buffer = [byte[]]::new(8192)
            while (($size = $stream.Read($buffer,0,$buffer.Length)) -ne 0) {
                if ($memory.Length + $size -gt 16MB) { return @{ Status='PageBodyLimit'; HttpStatus=$status } }
                $memory.Write($buffer,0,$size)
            }
            $memory.Position = 0
            $settings = [Text.Json.JsonDocumentOptions]::new()
            $settings.AllowDuplicateProperties = $false
            $json = [Text.Json.JsonDocument]::Parse($memory,$settings)
            try { $page = ConvertFrom-Json -InputObject $json.RootElement.GetRawText() -AsHashtable -DateKind String -NoEnumerate }
            finally { $json.Dispose() }
        } catch { return @{ Status='InvalidPage'; HttpStatus=$status } }
        finally { $stream.Dispose(); $memory.Dispose() }
        if ($page -isnot [Collections.IDictionary] -or $page['value'] -isnot [array] -or $page['value'].Count -gt 1000) {
            return @{ Status='InvalidPage'; HttpStatus=$status }
        }
        return @{ Status='Page'; HttpStatus=$status; Payload=$page }
    } catch {
        return @{ Status='TransportFailure'; HttpStatus=$null }
    } finally {
        if ($response -is [Net.Http.HttpResponseMessage]) { $response.Dispose() }
    }
}

function Get-CanonicalGuid($Value) {
    $id = [guid]::Empty
    if ($Value -is [string] -and $Value -cmatch '\A[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}\z' -and
        [guid]::TryParseExact($Value,'D',[ref]$id) -and $id -ne [guid]::Empty) { return $id.ToString('D') }
}

function Get-TargetAppId($Event) {
    $targets = $Event['targetResources']
    if ($targets -isnot [array] -or $targets.Count -ne 1 -or $targets[0] -isnot [Collections.IDictionary] -or
        $targets[0]['type'] -isnot [string] -or $targets[0]['type'] -cne 'ServicePrincipal') { return }
    $objectId = Get-CanonicalGuid $targets[0]['id']
    if (-not $objectId -or $targets[0]['id'] -cne $objectId -or $Event['additionalDetails'] -isnot [array]) { return }
    $appFields = @($Event['additionalDetails'] | Where-Object { $_ -is [Collections.IDictionary] -and
        $_['key'] -is [string] -and $_['key'] -ieq 'AppId' })
    if ($appFields.Count -eq 1 -and $appFields[0]['key'] -ceq 'AppId') { Get-CanonicalGuid $appFields[0]['value'] }
}

$windows = [Collections.Generic.List[object]]::new()
$observed = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
$paused = $false
for ($start = $since; $start -lt $until; $start = $end) {
    $end = [DateTimeOffset]::new($start.UtcDateTime.Date.AddDays(1))
    if ($end -gt $until) { $end = $until }
    $window = [ordered]@{ Since=$start.ToString('o'); UntilExclusive=$end.ToString('o'); Status='NotAttempted';
        Pages=0; HttpStatus=$null; SuccessfulTargetAppIdRows=0; UnresolvedSuccessfulRows=0; OtherResultRows=0 }
    $windows.Add($window)
    if ($paused) { continue }
    $filter = "activityDisplayName eq 'Add service principal' and activityDateTime ge $($start.UtcDateTime.ToString('o')) and activityDateTime le $($end.UtcDateTime.ToString('o'))"
    $next = $endpoint + '?$top=250&$filter=' + [uri]::EscapeDataString($filter)
    $seen = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    $pending = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    do {
        if (-not $seen.Add($next)) { $window.Status='PaginationLoop'; break }
        if ($window.Pages -ge $MaxPagesPerWindow) { $window.Status='PageLimit'; break }
        if (-not (Test-ReadContext $start $end)) { $window.Status='ContextRejected'; break }
        $result = Read-DirectoryPage $next
        $window.HttpStatus = $result.HttpStatus
        if ($result.Status -cne 'Page') { $window.Status=$result.Status; break }
        $window.Pages++
        $payload = $result.Payload
        foreach ($event in $payload['value']) {
            $timestamp = [DateTimeOffset]::MinValue
            if ($event -isnot [Collections.IDictionary] -or $event['activityDisplayName'] -isnot [string] -or
                $event['activityDisplayName'] -cne 'Add service principal' -or
                $event['activityDateTime'] -isnot [string] -or
                $event['activityDateTime'] -cnotmatch '\A[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,7})?(?:Z|\+00:00)\z' -or
                -not [DateTimeOffset]::TryParse($event['activityDateTime'],[cultureinfo]::InvariantCulture,[Globalization.DateTimeStyles]::None,[ref]$timestamp) -or
                $timestamp -lt $start -or $timestamp -gt $end) { $window.Status='InvalidEvent'; break }
            if ($timestamp -eq $end) { continue }
            if ($event['result'] -isnot [string] -or $event['result'] -cne 'success') { $window.OtherResultRows++; continue }
            $app = Get-TargetAppId $event
            if (-not $app) { $window.UnresolvedSuccessfulRows++; continue }
            $window.SuccessfulTargetAppIdRows++
            if (-not $known.Contains($app)) { $null = $pending.Add($app) }
            if ($pending.Count -gt 1000) { $window.Status='CandidateLimit'; break }
        }
        if ($window.Status -cin @('InvalidEvent','CandidateLimit')) { break }
        if (-not $payload.Contains('@odata.nextLink')) {
            if (($observed.Count + @($pending | Where-Object { -not $observed.Contains($_) }).Count) -gt 1000) {
                $window.Status='CandidateLimit'; break
            }
            $observed.UnionWith($pending)
            $window.Status='Complete'; break
        }
        $next = Get-RelativeDirectoryLink $payload['@odata.nextLink']
        if (-not $next) { $window.Status='InvalidNextLink'; break }
    } while ($true)
    $payload = $null; $event = $null; $result = $null
    if ($window.Status -cne 'Complete') { $paused = $true }
}
[ordered]@{ Format='TokenForgeGraphDirectoryProvisioningGaps'; SchemaVersion=1; GraphVersion='v1.0';
    CatalogCommit=$CatalogCommit; Since=$since.ToString('o'); UntilExclusive=$until.ToString('o');
    RequestedWindowTraversalComplete=(-not $paused); ProviderRetention='Unknown';
    Windows=$windows.ToArray(); CandidateAppIds=@($observed | Sort-Object) } | ConvertTo-Json -Depth 8
if ($paused) { exit 2 }
