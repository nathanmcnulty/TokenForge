# Architecture and roadmap

The first version keeps five public PowerShell functions:

| Function | Responsibility |
| --- | --- |
| `Update-TokenForgeCatalog` | Download and validate a compatible metadata snapshot. |
| `Get-TokenForgeCatalog` | Read and normalize a snapshot or upstream JSON file. |
| `Find-TokenForgeApplication` | Match every required scope against one resource. |
| `New-TokenForgeRequest` | Validate an explicit selection and return a credential-free plan. |
| `Get-TokenForgeToken` | Execute cookie/PKCE or refresh-token acquisition and return secret-bearing results. |

Catalogs and request plans contain ordinary structured data. A future standalone CLI can keep their meanings while replacing the execution host. Authentication stays separate from discovery so a catalog provider never receives session credentials. The one private HTTP function is a test boundary shared by authorization and redemption; it disables automatic redirects and returns responses to the protocol logic.

The CLI is future work, not a shipped executable. PowerShell itself already runs on the three target operating systems.

## Initial boundaries

- One explicitly selected client, resource, and set of delegated scopes per request.
- ESTSAUTH or ESTSAUTHPERSISTENT input; authorization code + S256 PKCE, query callback, silent `prompt=none`.
- Refresh-token input; no promise that a refresh token can be redeemed by another client. FOCI metadata is informational.
- Explicit SPA mode; no inference of redirect platform type from its URL.
- Public-cloud endpoints only; no HTML form processing or interactive authentication.
- No access-token-to-access-token conversion, PRT handling, tenant grant enumeration, app-role requests, confidential-client secrets, or token persistence.
- Token response scope evidence is separate from published catalog evidence and actual API access.

## Next work

1. Validate representative native/public and SPA clients using authorized live sessions; keep only aggregate results.
2. Add sanitized OAuth error classification and carefully bounded support for observed ESTS form-post flows where needed.
3. Add optional tenant grant verification using an independently supplied Graph token, with a clear distinction between preauthorization, delegated grants, and user privileges.
4. Aggregate additional metadata sources with per-record provenance and conflict reporting; do not silently union claims into asserted consent.
5. Define a versioned JSON interface for `catalog`, `find`, `plan`, and `token`; prototype a packaged CLI. Provide deliberate secret input/output and exit-code behavior before adding persistence.

## Research references

- [Microsoft authorization code + PKCE flow](https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth2-auth-code-flow)
- [Microsoft scopes and consent](https://learn.microsoft.com/en-us/entra/identity-platform/scopes-oidc)
- The ESTSAUTH-to-code sequence in `research-passkeys/powershell/scripts/entra/reference/Register-EntraKeyVaultPasskeyViaEstsAuth.ps1` informed this implementation. Passkey registration and browser-page handling were not copied into TokenForge.
- `mcp-entrascopes` informed the distinction between published scope metadata and tenant-specific evidence.
