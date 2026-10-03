# Live validation

On October 2, 2026 (America/Anchorage), passkey-backed validation on Linux passed all seven cases below. The session was obtained in memory using XDRInternals' internal software-passkey login function. No Defender portal connection was needed. The [sanitized report](live-validation-2026-10-02.json) contains only scope counts, outcomes, HTTP statuses, timings, and the catalog content hash.

| Case | Requested API scopes | Returned scopes, including OIDC | Extra API scopes | Acquisition and refresh | Read-only API checks, initial and refreshed |
| --- | ---: | ---: | ---: | --- | --- |
| Azure CLI → Microsoft Graph | 2 | 12 | 7 | Passed | Current user and audit logs: HTTP 200 |
| My Signins SPA → Microsoft Graph | 1 | 14 | 10 | Passed | Current user: HTTP 200 |
| Security and Compliance Center SPA → Microsoft Graph | 2 | 38 | 33 | Passed | Applications and audit logs: HTTP 200 |
| Azure CLI → Azure Resource Manager | 1 | 1 | 0 | Passed | Subscriptions: HTTP 200 |
| Invalid synthetic ESTSAUTH cookie | — | — | — | Rejected | No token returned |
| Invalid synthetic refresh token | — | — | — | Rejected | No token returned |
| Azure Portal published redirect | — | — | — | AADSTS50011 | No token returned; diagnostic identified the rejected redirect |

The Graph scope sets were `User.Read.All` + `AuditLog.Read.All`, `User.Read`, and `Application.Read.All` + `AuditLog.Read.All`, respectively. ARM requested `user_impersonation` using the resource application ID as the scope prefix. All four successful cases had requested-scope evidence from the OAuth token response and returned refresh tokens on initial acquisition and refresh.

These checks demonstrate issuance and API acceptance for the tested clients, resource audiences, session, and tenant. They do not establish support for every published client/scope, other tenants, other clouds, MFA/policy interrupts, or live authentication on Windows/macOS. Offline tests run on all three operating systems.

Two observations changed the module:

- Entra returned more API scopes than requested for all three Graph clients. `AdditionalScopes` and a warning now make this visible. Explicit requests do not guarantee a token limited to the selected scopes.
- A redirect listed in the catalog was rejected by Entra. Authorization and token failures now preserve bounded numeric AADSTS codes without retaining or printing response contents. AADSTS50011 has a specific redirect-mismatch explanation.

## Repeat the proof

Run in a dedicated PowerShell process using your authorized passkey, an XDRInternals module checkout, and a loaded catalog:

```powershell
pwsh -NoProfile -File ./scripts/Invoke-TokenForgeLiveValidation.ps1 `
    -PasskeyPath /path/to/credential.passkey `
    -XdrModulePath /path/to/XDRInternals/XDRInternals.psd1 `
    -CatalogPath /path/to/catalog.json `
    -ReportPath /path/to/sanitized-report.json
```

The script obtains the cookie in memory, validates native and SPA Graph acquisition, validates ARM acquisition, refreshes each token, and performs read-only API checks. API responses are requested with `ResponseHeadersRead` and disposed without reading their bodies. Invalid credentials and the observed rejected redirect are negative cases. The script exits nonzero if an expected check fails, and never prints raw exceptions from authentication dependencies.

The matrix is an explicit research fixture, not automatic client selection. Its expected AADSTS50011 result may change if Microsoft updates the registration or metadata; reassess that case rather than interpreting a newly accepted redirect as a product regression. No consent, tenant configuration, or access policy changes are made by the proof.

For a new client/resource:

1. Load a pinned catalog and record its content hash.
2. Select a small required scope set and a published redirect. Confirm its platform configuration before using SPA mode.
3. Inspect the plan and use an authorized completed session.
4. Check requested-scope evidence and extra API scopes, then call a documented read-only endpoint.
5. Refresh once if a refresh token was returned and repeat the API check.
6. Retain only aggregate outcomes. Keep credentials, codes, callback URLs, assertions, tenant/user identifiers, and page/API contents out of artifacts.

References: [Graph current-user access](https://learn.microsoft.com/en-us/graph/api/user-get?view=graph-rest-1.0), [Graph audit logs](https://learn.microsoft.com/en-us/graph/api/directoryaudit-list?view=graph-rest-1.0), [AADSTS50011](https://learn.microsoft.com/en-us/troubleshoot/entra/entra-id/app-integration/error-code-aadsts50011-redirect-uri-mismatch).
