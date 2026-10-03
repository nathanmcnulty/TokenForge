function Get-TokenForgeEstsCookie {
    <#
    .SYNOPSIS
    Obtain a SecureString ESTS cookie using the existing XDRInternals software-passkey implementation.
    .DESCRIPTION
    This adapter does not connect to Defender or persist credentials. Run in a dedicated process
    without transcripts. XDRInternals is an optional authentication dependency only.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$PasskeyPath, [Parameter(Mandatory)][string]$XdrModulePath)
    $item = Get-Item -LiteralPath $PasskeyPath -Force -ErrorAction Stop
    if ($item.LinkType -or $item.PSIsContainer) { throw 'Passkey must be a regular file, not a link.' }
    if (-not $IsWindows -and ([int]$item.UnixFileMode -band 63)) { throw 'Passkey file permissions must exclude group and other access.' }
    $plain = $null
    try {
        $null = Import-Module -Name $XdrModulePath -ErrorAction Stop 3>$null 4>$null 5>$null 6>$null
        $module = Get-Module XDRInternals
        if (-not $module) { throw 'XDRInternals not loaded.' }
        $plain = & $module { param($path) Invoke-XdrPasskeyAuthentication -KeyFilePath $path -ErrorAction Stop } $PasskeyPath 3>$null 4>$null 5>$null 6>$null
        if ([string]::IsNullOrWhiteSpace($plain)) { throw 'No cookie returned.' }
        ConvertTo-SecureString $plain -AsPlainText -Force
    } catch { throw 'Software passkey authentication failed; dependency details suppressed.' }
    finally { $plain = $null }
}

function Test-TokenForgeTokenAccess {
    <# .SYNOPSIS
    Check one read-only Graph or ARM API using a matching-resource token; return status only.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Token, [Parameter(Mandatory)][uri]$Uri)
    $allowedHost = switch ($Token.ResourceId) {
        '00000003-0000-0000-c000-000000000000' { 'graph.microsoft.com' }
        '797f4846-ba00-4fd7-ba43-dac1f8f63013' { 'management.azure.com' }
        default { throw 'No API host mapping is defined for this resource.' }
    }
    if ($Uri.Scheme -ne 'https' -or $Uri.Host -ne $allowedHost -or $Uri.Port -ne 443 -or $Uri.UserInfo -or $Uri.Fragment) { throw 'API URI does not match the token resource boundary.' }
    $handler = [Net.Http.HttpClientHandler]::new(); $handler.AllowAutoRedirect = $false
    $client = [Net.Http.HttpClient]::new($handler); $client.Timeout = [TimeSpan]::FromSeconds(30)
    $response = $null
    try {
        $client.DefaultRequestHeaders.Authorization = [Net.Http.Headers.AuthenticationHeaderValue]::new('Bearer', [Net.NetworkCredential]::new('', $Token.AccessToken).Password)
        try { $response = $client.GetAsync($Uri,[Net.Http.HttpCompletionOption]::ResponseHeadersRead).GetAwaiter().GetResult() } catch { throw 'API check transport failed; details suppressed.' }
        [pscustomobject]@{ ResourceId = $Token.ResourceId; Status = [int]$response.StatusCode; Accepted = $response.IsSuccessStatusCode; Evidence = 'ReadOnlyApiResponse'; CheckedAt = [DateTimeOffset]::UtcNow.ToString('o') }
    } finally { if ($response) { $response.Dispose() }; $client.Dispose(); $handler.Dispose() }
}
