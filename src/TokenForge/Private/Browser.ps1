function Open-TokenForgeBrowser {
    param([uri]$Uri)
    try {
        $info = [Diagnostics.ProcessStartInfo]::new($Uri.AbsoluteUri)
        $info.UseShellExecute = $true
        $null = [Diagnostics.Process]::Start($info)
    } catch { throw 'Unable to open the system browser. Browser request details suppressed.' }
}

function Invoke-TokenForgeBrowserAuthorization {
    param($Request, [string]$Authority, [string]$LoginHint, [int]$TimeoutSeconds, [switch]$NoConsent)
    $published = [uri]$Request.RedirectUri
    if ($Request.Spa -or $published.Scheme -cne 'http' -or $published.Host -cne 'localhost' -or $published.AbsolutePath -cne '/' -or $published.Query -or $published.Fragment -or $published.UserInfo) {
        throw 'Browser authentication requires a published http://localhost root redirect for a public native client.'
    }
    $plan = [TokenForge.Core.V0180.OAuthRequest]::new()
    foreach ($field in @('ClientId','ResourceId','ResourceUri','Tenant','RedirectUri','Scopes','OAuthScopes','Spa','Discovery','Protocol')) {
        $plan.$field = $Request.$field
    }
    $expectedAuthority = "https://login.microsoftonline.com/$([uri]::EscapeDataString($plan.Tenant))/oauth2/v2.0"
    if ($Authority -cne $expectedAuthority) { throw 'Browser authorization authority does not match the request.' }
    $launch = [Action[uri]] { param($uri) Open-TokenForgeBrowser -Uri $uri }
    try {
        return [TokenForge.Core.OAuthBrowserAuthorization]::Authorize($plan,$launch,$LoginHint,$TimeoutSeconds,[bool]$NoConsent)
    } catch {
        $errorException = $_.Exception
        while ($errorException.InnerException) { $errorException = $errorException.InnerException }
        throw $errorException.Message
    }
}
