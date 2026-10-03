# All Graph requests share a strict host boundary, bounded retry and validated paging.
function Invoke-TokenForgeGraph {
    param(
        [Parameter(Mandatory)][securestring]$AccessToken,
        [Parameter(Mandatory)][uri]$Uri,
        [ValidateSet('GET','POST','DELETE')][string]$Method = 'GET',
        [hashtable]$Body,
        [switch]$AllowNotFound
    )
    if ($Uri.Scheme -ne 'https' -or $Uri.Host -ne 'graph.microsoft.com' -or $Uri.Port -ne 443 -or $Uri.UserInfo -or $Uri.Fragment -or $Uri.AbsolutePath -notmatch '^/(v1\.0|beta)/') { throw 'Graph URI is outside the supported boundary.' }
    $handler = [Net.Http.HttpClientHandler]::new(); $handler.AllowAutoRedirect = $false
    $client = [Net.Http.HttpClient]::new($handler); $client.Timeout = [TimeSpan]::FromSeconds(30)
    try {
        for ($attempt = 0; $attempt -lt 4; $attempt++) {
            $request = [Net.Http.HttpRequestMessage]::new([Net.Http.HttpMethod]::new($Method), $Uri)
            $response = $null
            try {
                $request.Headers.Authorization = [Net.Http.Headers.AuthenticationHeaderValue]::new('Bearer', [Net.NetworkCredential]::new('', $AccessToken).Password)
                if ($Body) { $request.Content = [Net.Http.StringContent]::new(($Body | ConvertTo-Json -Depth 20 -Compress), [Text.Encoding]::UTF8, 'application/json') }
                try { $response = $client.SendAsync($request).GetAwaiter().GetResult() } catch { throw 'Graph transport failed; details suppressed.' }
                $status = [int]$response.StatusCode
                if ($status -eq 404 -and $AllowNotFound) { return $null }
                if ($status -in @(429,502,503,504) -and $attempt -lt 3) {
                    $delay = [math]::Pow(2,$attempt)
                    if ($response.Headers.RetryAfter) {
                        if ($response.Headers.RetryAfter.Delta) { $delay = $response.Headers.RetryAfter.Delta.TotalSeconds }
                        elseif ($response.Headers.RetryAfter.Date) { $delay = ($response.Headers.RetryAfter.Date - [DateTimeOffset]::UtcNow).TotalSeconds }
                    }
                    if ($delay -gt 60) { throw "Graph throttled (HTTP $status); Retry-After exceeds the per-call budget. Resume later." }
                    Start-Sleep -Seconds ([math]::Max(1,$delay))
                    continue
                }
                if ($status -lt 200 -or $status -ge 300) { throw "Graph request failed (HTTP $status); response details suppressed." }
                if ($status -eq 204) { return $null }
                $content = $response.Content.ReadAsStringAsync().GetAwaiter().GetResult()
                try { return ConvertFrom-Json -InputObject $content -AsHashtable -ErrorAction Stop } catch { throw 'Graph returned invalid JSON; details suppressed.' }
            } finally { if ($response) { $response.Dispose() }; $request.Dispose() }
        }
    } finally { $client.Dispose(); $handler.Dispose() }
}

function Get-TokenForgeGraphCollection {
    param([securestring]$AccessToken, [uri]$Uri, [int]$MaxPages = 1000)
    $seen = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    $items = [Collections.Generic.List[object]]::new()
    $next = $Uri.AbsoluteUri
    for ($page = 0; $next -and $page -lt $MaxPages; $page++) {
        if (-not $seen.Add($next)) { throw 'Graph pagination loop detected; no complete inventory returned.' }
        $response = Invoke-TokenForgeGraph -AccessToken $AccessToken -Uri $next
        if ($response -isnot [Collections.IDictionary] -or -not $response.Contains('value') -or $response['value'] -isnot [array]) { throw 'Invalid Graph collection response.' }
        foreach ($item in $response['value']) { $items.Add($item) }
        $next = [string]$response['@odata.nextLink']
    }
    if ($next) { throw 'Graph page limit reached; no complete inventory returned.' }
    return ,$items.ToArray()
}

function Get-TokenForgeFingerprint {
    param([string]$Value)
    [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData([Text.Encoding]::UTF8.GetBytes($Value))).ToLowerInvariant()
}

$script:MicrosoftOwnerTenants = @('f8cdef31-a31e-4b4a-93e4-5f571e91255a','72f988bf-86f1-41af-91ab-2d7cd011db47','cdc5aeea-15c5-4db6-b079-fcadd2505dc2')

function ConvertFrom-TokenForgeJwtPayload {
    param([securestring]$AccessToken)
    $text = [Net.NetworkCredential]::new('', $AccessToken).Password
    try {
        $parts = $text.Split('.')
        if ($parts.Count -ne 3 -or $parts[1].Length -gt 1048576 -or $parts[1] -notmatch '^[A-Za-z0-9_-]+$') { return $null }
        $encoded = $parts[1].Replace('-','+').Replace('_','/')
        $encoded += '=' * ((4 - $encoded.Length % 4) % 4)
        try {
            $payload = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($encoded)) | ConvertFrom-Json -AsHashtable -ErrorAction Stop
            if ($payload -is [Collections.IDictionary]) { return $payload }
        } catch { return $null }
    } finally { $text = $null }
}
