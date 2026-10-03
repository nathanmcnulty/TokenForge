#Requires -Version 7.4
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$PasskeyPath,
    [Parameter(Mandatory)][string]$XdrModulePath,
    [Parameter(Mandatory)][string]$CatalogPath,
    [string]$ReportPath
)

# Run in a dedicated pwsh process. Never emit bootstrap output or identity response contents.
$ErrorActionPreference = 'Stop'
$VerbosePreference = 'SilentlyContinue'
$DebugPreference = 'SilentlyContinue'
$ProgressPreference = 'SilentlyContinue'
$InformationPreference = 'SilentlyContinue'
$WarningPreference = 'SilentlyContinue'
$cookie = $null
$token = $null
$refreshed = $null
$results = [Collections.Generic.List[object]]::new()
$failed = $false

function Invoke-LiveApiCheck {
    param([securestring]$AccessToken, [object[]]$Endpoints)
    $handler = [Net.Http.HttpClientHandler]::new()
    $handler.AllowAutoRedirect = $false
    $client = [Net.Http.HttpClient]::new($handler)
    $client.Timeout = [TimeSpan]::FromSeconds(30)
    try {
        $client.DefaultRequestHeaders.Authorization = [Net.Http.Headers.AuthenticationHeaderValue]::new('Bearer', [Net.NetworkCredential]::new('', $AccessToken).Password)
        foreach ($endpoint in $Endpoints) {
            # Only fixed read-only API endpoints from the matrix below are used.
            $response = $null
            try {
                $response = $client.GetAsync($endpoint.Uri, [Net.Http.HttpCompletionOption]::ResponseHeadersRead).GetAwaiter().GetResult()
                [pscustomobject]@{ Check = $endpoint.Label; Status = [int]$response.StatusCode }
            } finally { if ($response) { $response.Dispose() } }
        }
    } finally { $client.Dispose(); $handler.Dispose() }
}

try {
    $keyItem = Get-Item -LiteralPath $PasskeyPath -Force
    if ($keyItem.LinkType -or $keyItem.PSIsContainer) { throw 'Unsafe passkey file.' }
    if (-not $IsWindows -and ([int]$keyItem.UnixFileMode -band 63)) { throw 'Passkey permissions are too broad.' }
    Import-Module $XdrModulePath -Force *> $null
    Import-Module (Join-Path $PSScriptRoot '../src/TokenForge/TokenForge.psd1') -Force *> $null
    $catalog = Get-TokenForgeCatalog -Path $CatalogPath
    try {
        $plainCookie = & (Get-Module XDRInternals) {
            param($keyPath)
            Invoke-XdrPasskeyAuthentication -KeyFilePath $keyPath -ErrorAction Stop
        } $PasskeyPath 3>$null 4>$null 5>$null 6>$null
        if ([string]::IsNullOrWhiteSpace($plainCookie)) { throw 'No cookie.' }
        $cookie = ConvertTo-SecureString $plainCookie -AsPlainText -Force
        $plainCookie = $null
    } catch { throw 'Bootstrap failed.' }

    $graph = '00000003-0000-0000-c000-000000000000'
    $me = @{ Label = 'CurrentUser'; Uri = 'https://graph.microsoft.com/v1.0/me?$select=id' }
    $audit = @{ Label = 'AuditLogs'; Uri = 'https://graph.microsoft.com/v1.0/auditLogs/directoryAudits?$top=1&$select=id' }
    $apps = @{ Label = 'Applications'; Uri = 'https://graph.microsoft.com/v1.0/applications?$top=1&$select=id' }
    $cases = @(
        @{ Label = 'NativeCLI'; ClientId = '04b07795-8ddb-461a-bbee-02f9e1bf7b46'; RedirectUri = 'https://login.microsoftonline.com/common/oauth2/nativeclient'; Scope = @('User.Read.All','AuditLog.Read.All'); ResourceId = $graph; ResourceUri = 'https://graph.microsoft.com'; Spa = $false; Endpoints = @($me,$audit) },
        @{ Label = 'MySigninsSPA'; ClientId = '19db86c3-b2b9-44cc-b339-36da233a3be2'; RedirectUri = 'https://mysignins.microsoft.com/'; Scope = @('User.Read'); ResourceId = $graph; ResourceUri = 'https://graph.microsoft.com'; Spa = $true; Endpoints = @($me) },
        @{ Label = 'SecuritySPA'; ClientId = '80ccca67-54bd-44ab-8625-4b79c4dc7775'; RedirectUri = 'https://security.microsoft.com/Blank'; Scope = @('Application.Read.All','AuditLog.Read.All'); ResourceId = $graph; ResourceUri = 'https://graph.microsoft.com'; Spa = $true; Endpoints = @($apps,$audit) },
        @{ Label = 'ARMNative'; ClientId = '04b07795-8ddb-461a-bbee-02f9e1bf7b46'; RedirectUri = 'https://login.microsoftonline.com/common/oauth2/nativeclient'; Scope = @('user_impersonation'); ResourceId = '797f4846-ba00-4fd7-ba43-dac1f8f63013'; ResourceUri = '797f4846-ba00-4fd7-ba43-dac1f8f63013'; Spa = $false; Endpoints = @(@{ Label = 'Subscriptions'; Uri = 'https://management.azure.com/subscriptions?api-version=2022-12-01' }) }
    )
    foreach ($case in $cases) {
        $watch = [Diagnostics.Stopwatch]::StartNew()
        $token = $null; $refreshed = $null
        try {
            $plan = New-TokenForgeRequest -Catalog $catalog -ClientId $case.ClientId -ResourceId $case.ResourceId -Scope $case.Scope -RedirectUri $case.RedirectUri -ResourceUri $case.ResourceUri -OfflineAccess -Spa:$case.Spa
            $token = Get-TokenForgeToken -Request $plan -EstsAuth $cookie
            $initialChecks = @(Invoke-LiveApiCheck -AccessToken $token.AccessToken -Endpoints $case.Endpoints)
            if (-not $token.RefreshToken) { throw 'No refresh token.' }
            $refreshed = Get-TokenForgeToken -Request $plan -RefreshToken $token.RefreshToken
            $refreshChecks = @(Invoke-LiveApiCheck -AccessToken $refreshed.AccessToken -Endpoints $case.Endpoints)
            $passed = $token.ScopeEvidence -eq 'TokenResponse' -and $refreshed.ScopeEvidence -eq 'TokenResponse' -and @($initialChecks + $refreshChecks | Where-Object Status -ne 200).Count -eq 0
            if (-not $passed) { $failed = $true }
            $results.Add([pscustomobject]@{
                Case = $case.Label; Passed = $passed
                RequestedScopeCount = @($token.RequestedScopes).Count
                GrantedScopeCount = @($token.GrantedScopes).Count
                AdditionalApiScopeCount = @($token.AdditionalScopes).Count
                ScopeEvidence = $token.ScopeEvidence; RefreshScopeEvidence = $refreshed.ScopeEvidence
                RefreshTokenReturned = $true; RotatedRefreshTokenReturned = $null -ne $refreshed.RefreshToken
                InitialApiChecks = $initialChecks; RefreshApiChecks = $refreshChecks
                ElapsedSeconds = [math]::Round($watch.Elapsed.TotalSeconds,2)
            })
        } catch {
            $failed = $true
            $codes = @([regex]::Matches($_.Exception.Message, '\bAADSTS([0-9]{4,9})\b') | ForEach-Object { $_.Groups[1].Value } | Sort-Object -Unique)
            $results.Add([pscustomobject]@{ Case = $case.Label; Passed = $false; ErrorCodes = $codes; Outcome = 'AcquisitionOrApiCheckFailed'; ElapsedSeconds = [math]::Round($watch.Elapsed.TotalSeconds,2) })
        } finally {
            foreach ($item in @($token,$refreshed)) {
                if ($item) { $item.AccessToken.Dispose(); if ($item.RefreshToken) { $item.RefreshToken.Dispose() } }
            }
            $token = $null; $refreshed = $null
        }
    }

    # Failure cases are bounded and never submit passwords or change consent/policy.
    $plan = New-TokenForgeRequest -Catalog $catalog -ClientId $cases[0].ClientId -ResourceId $graph -Scope $cases[0].Scope -RedirectUri $cases[0].RedirectUri -ResourceUri 'https://graph.microsoft.com'
    $invalid = ConvertTo-SecureString 'synthetic-invalid-credential' -AsPlainText -Force
    try {
        foreach ($kind in @('Cookie','Refresh')) {
            $negativePassed = $false; $unexpected = $null
            try {
                if ($kind -eq 'Cookie') { $unexpected = Get-TokenForgeToken -Request $plan -EstsAuth $invalid }
                else { $unexpected = Get-TokenForgeToken -Request $plan -RefreshToken $invalid }
            } catch {
                $negativePassed = if ($kind -eq 'Cookie') { $_.Exception.Message -match 'Silent authorization|Identity request failed' } else { $_.Exception.Message -match 'Token request failed.*HTTP 400' }
            } finally {
                if ($unexpected) { $unexpected.AccessToken.Dispose(); if ($unexpected.RefreshToken) { $unexpected.RefreshToken.Dispose() } }
            }
            if (-not $negativePassed) { $failed = $true }
            $results.Add([pscustomobject]@{ Case = "Invalid$kind"; Passed = $negativePassed; NoTokenReturned = $null -eq $unexpected })
        }
    } finally { $invalid.Dispose() }

    $portalPlan = New-TokenForgeRequest -Catalog $catalog -ClientId 'c44b4083-3bb0-49c1-b47d-974e53cbdf3c' -ResourceId $graph -Scope User.Read -RedirectUri 'https://portal.azure.com/signin/index/' -ResourceUri 'https://graph.microsoft.com' -Spa
    $negativePassed = $false; $unexpected = $null
    try { $unexpected = Get-TokenForgeToken -Request $portalPlan -EstsAuth $cookie }
    catch { $negativePassed = $_.Exception.Message -match 'AADSTS50011.*Entra rejected the redirect URI' }
    finally { if ($unexpected) { $unexpected.AccessToken.Dispose(); if ($unexpected.RefreshToken) { $unexpected.RefreshToken.Dispose() } } }
    if (-not $negativePassed) { $failed = $true }
    $results.Add([pscustomobject]@{ Case = 'PublishedRedirectRejected'; Passed = $negativePassed; ExpectedErrorCode = '50011'; NoTokenReturned = $null -eq $unexpected })

    $report = [pscustomobject]@{
        SchemaVersion = 1; ValidatedAtUtc = [DateTimeOffset]::UtcNow.ToString('o')
        ModuleVersion = (Get-Module TokenForge).Version.ToString()
        CatalogContentSha256 = $catalog.ContentSha256
        PasskeyBootstrap = 'Succeeded'; Passed = -not $failed; Results = @($results.ToArray())
    }
    $json = $report | ConvertTo-Json -Depth 8
    if ($ReportPath) { $json | Set-Content -LiteralPath $ReportPath -Encoding utf8 }
    Write-Output $json
} catch {
    # Do not echo exception messages: dependencies may include credentials or identities.
    Write-Output '{"Passed":false,"Outcome":"BootstrapOrSetupFailed","Details":"Suppressed"}'
    $failed = $true
} finally {
    if ($cookie) { $cookie.Dispose() }
    $plainCookie = $null; $cookie = $null
    Remove-Module XDRInternals,TokenForge -ErrorAction SilentlyContinue *> $null
    $Error.Clear()
}
if ($failed) { exit 1 }
