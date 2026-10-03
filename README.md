# TokenForge

PowerShell toolkit for finding Microsoft Entra first-party applications that publish the delegated scopes you need, then requesting access tokens using an authorized ESTSAUTH session or refresh token.

Initial version: PowerShell 7.4+ on Windows, Linux, and macOS. The repository is private. Authentication is experimental: offline protocol tests pass, but issuance has not yet been validated with a real tenant session.

## Workflow

1. Load scope metadata from ROADtools (the source used by EntraScopes), or a compatible local JSON file.
2. Find clients publishing **all** your required scopes for **one** resource.
3. Select a client and one of its published redirect URIs; inspect a credential-free request plan.
4. Request tokens using an ESTSAUTH/ESTSAUTHPERSISTENT cookie with authorization code + PKCE, or an existing refresh token.
5. Use the token against the intended API to confirm access.

Published metadata is discovery evidence. It does not establish tenant consent, current server-side preauthorization, API acceptance, or that a given client supports the chosen flow. Entra decides what it issues based on the client, session, permissions, user privileges, and policy. TokenForge does not create grants. Requests use explicit API scopes rather than `.default`.

## Quick start

```powershell
Import-Module ./src/TokenForge/TokenForge.psd1

# Downloads metadata only. Default location: ~/.cache/TokenForge on Unix,
# or %LOCALAPPDATA%/TokenForge on Windows.
$catalog = Update-TokenForgeCatalog
# Later, reuse it without network access:
# $catalog = Get-TokenForgeCatalog

$graph = '00000003-0000-0000-c000-000000000000'
$required = @('Application.Read.All', 'AuditLog.Read.All')
$candidates = @(Find-TokenForgeApplication -Catalog $catalog `
    -ResourceId $graph -Scope $required)
$candidates | Select-Object Name, ClientId, PublicClient, Foci, RedirectUris
```

Choose deliberately; results do not rank clients by likelihood of success. `PublicClient` and `Foci` report upstream metadata, and do not guarantee redemption. This version supports flows without client secrets. Some clients require a confidential-client credential, broker, device binding, or browser interaction.

```powershell
# Supply a client and exact redirect URI from the selected candidate.
$selectedClientId = Read-Host 'Selected client ID'
$selectedRedirectUri = Read-Host 'Published redirect URI'
$plan = New-TokenForgeRequest -Catalog $catalog `
    -ClientId $selectedClientId -ResourceId $graph -Scope $required `
    -RedirectUri $selectedRedirectUri -Tenant 'organizations' -OfflineAccess
$plan | Format-List

# Enter only the cookie value; keep it out of command history.
$cookie = Read-Host 'ESTSAUTH cookie value' -AsSecureString
$token = Get-TokenForgeToken -Request $plan -EstsAuth $cookie
$token | Select-Object ClientId, ResourceId, GrantedScopes, ScopeEvidence, ExpiresAt

# A rotated refresh token is returned when Entra supplies one.
# Preserve the returned token in your own secret store if needed.
$nextToken = Get-TokenForgeToken -Request $plan -RefreshToken $token.RefreshToken
```

Use `-CookieName ESTSAUTHPERSISTENT` when that is the cookie you provide. The cookie is added under the selected name only. Use `-Spa` on `New-TokenForgeRequest` only for a redirect registered as SPA: it sends the redirect's HTTPS origin during token redemption. Upstream metadata does not establish the redirect's platform type. This version supports the public-cloud `login.microsoftonline.com` host only.

By default, OAuth scopes use the resource application ID as their prefix. To use an API URI, supply `-ResourceUri 'https://graph.microsoft.com'`; the URI must map to the resource ID in the catalog's `resourceidentifiers`. Each plan targets one resource. Build another plan for a different API.

## Scope evidence

`Get-TokenForgeToken` compares requested API scopes with the OAuth token response's `scope` field. A partial response fails without returning tokens. If `scope` is omitted, the result is marked `Unverified` and a warning is emitted. The module treats Microsoft access tokens as opaque; it does not claim that decoding a JWT proves signature validity, permissions, or API acceptance.

Tokens are returned as `SecureString` properties. Convert the access token to plaintext only when constructing the intended API request:

```powershell
$bearer = [System.Net.NetworkCredential]::new('', $token.AccessToken).Password
try {
    # Use the documented endpoint for your API and requested scopes.
    $headers = @{ Authorization = "Bearer $bearer" }
    # Invoke-RestMethod -Uri $apiUri -Headers $headers
} finally {
    $headers = $null
    $bearer = $null
}
```

## Catalogs and additional sources

`Get-TokenForgeCatalog -Path ./catalog.json` accepts the ROADtools/EntraScopes shape: `apps` keyed by client GUID, with application metadata and `scopes` keyed by resource GUID. Optional `resourceidentifiers` maps API URI to resource GUID. See the synthetic [fixture](tests/fixtures/catalog.json).

`Update-TokenForgeCatalog -SourceUri <https-url> -Path <path>` downloads a compatible source and validates it before replacing the catalog. Pin the URL to an upstream commit for reproducible research. Snapshots retain the source URL, fetch time, and a SHA-256 of the loaded snapshot. The default URL follows the upstream branch; the hash is content provenance, not a commit ID or publisher signature. Refresh is explicit; the module never silently refreshes or falls back to stale data.

No upstream dataset is committed here. ROADtools is MIT-licensed; upstream datasets retain their own terms. References: [EntraScopes](https://github.com/f-bader/entrascopes.com), [ROADtools dataset](https://github.com/dirkjanm/ROADtools/blob/master/roadtx/roadtools/roadtx/firstpartyscopes.json), [research-passkeys](https://github.com/nathanmcnulty/research-passkeys), [mcp-entrascopes](https://github.com/nathanmcnulty/mcp-entrascopes).

## Development

```powershell
Install-Module Pester -RequiredVersion 5.7.1 -Scope CurrentUser -Force
./scripts/Test-TokenForge.ps1
```

CI runs the same tests on Windows, Linux, and macOS. Tests use synthetic credentials and mock identity responses. No live cookies or tokens are required. Read [SECURITY.md](SECURITY.md), [architecture and roadmap](docs/architecture.md), and the [live validation procedure](docs/live-validation.md).
