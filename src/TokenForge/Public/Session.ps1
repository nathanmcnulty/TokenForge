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
    $plain = $null; $lease = $null
    try {
        [Management.Automation.ProviderInfo]$fileProvider = $null
        [Management.Automation.PSDriveInfo]$fileDrive = $null
        $providerPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($PasskeyPath,[ref]$fileProvider,[ref]$fileDrive)
        if ($fileProvider.Name -cne 'FileSystem') { throw 'A local credential file is required.' }
        $resolvedPath = [TokenForge.Core.V0220.PrivateFiles]::Resolve($providerPath,$false)
        $lease = [TokenForge.Core.SoftwarePasskeyFileLease]::Open($resolvedPath)
        $imported = @(Import-Module -Name $XdrModulePath -PassThru -ErrorAction Stop 3>$null 4>$null 5>$null 6>$null)
        if ($imported.Count -ne 1 -or $imported[0] -isnot [Management.Automation.PSModuleInfo] -or $imported[0].Name -ine 'XDRInternals') { throw 'Unexpected authentication provider.' }
        $module = $imported[0]
        $plain = & $module { param($path) Invoke-XdrPasskeyAuthentication -KeyFilePath $path -ErrorAction Stop } $resolvedPath 3>$null 4>$null 5>$null 6>$null
        if ([string]::IsNullOrWhiteSpace($plain)) { throw 'No cookie returned.' }
        $lease.ConfirmUnchanged()
        ConvertTo-SecureString $plain -AsPlainText -Force
    } catch { throw 'Software passkey authentication failed; dependency details suppressed.' }
    finally { if ($lease) { $lease.Dispose() }; $plain = $null }
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
