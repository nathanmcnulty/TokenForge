# Tenant scope inventory

TokenForge distinguishes published scope metadata, verified Microsoft ownership, tenant-configured consent, and observed token `scp` claims. None establishes universal availability across customers. Role requirements, Conditional Access, broker binding, app enablement, redirect platform and API authorization can still prevent an assessment.

## Repeatable stages

Use a private state directory outside Git and a dedicated PowerShell process without transcripts. These commands accept credentials as `SecureString`; they never write credentials to state files.

```powershell
Import-Module ./src/TokenForge/TokenForge.psd1
$state = Join-Path $HOME '.local/share/TokenForge/assessment'
$runner = './scripts/Invoke-TokenForgeInventory.ps1'
& $runner -Action Discover -StatePath $state

# Optional software-passkey adapter; XDRInternals is an authentication dependency.
$cookie = Get-TokenForgeEstsCookie -PasskeyPath $passkeyPath -XdrModulePath $xdrModulePath
# Alternatively: $cookie = Read-Host 'ESTSAUTH cookie value' -AsSecureString

# Obtain a Graph token using your authorized client and scopes, then:
& $runner -Action Inventory -StatePath $state -GraphToken $graphToken.AccessToken
& $runner -Action Register -StatePath $state -GraphToken $graphToken.AccessToken -WhatIf
& $runner -Action Register -StatePath $state -GraphToken $graphToken.AccessToken
# Refresh inventory after registration, before probing.
& $runner -Action Inventory -StatePath $state -GraphToken $graphToken.AccessToken
& $runner -Action Probe -StatePath $state -EstsAuth $cookie -GraphOnly -MaxApplications 25
# Resume remaining clients or include known resource relationships:
& $runner -Action Probe -StatePath $state -EstsAuth $cookie
```

Inventory requires Graph permissions to list service principals and optionally delegated grants. Registration requires `Application.ReadWrite.All` and an appropriate tenant role. Bootstrap permissions belong to the operator's authorized Graph session; TokenForge does not grant them. Microsoft documents the [create service principal permissions](https://learn.microsoft.com/en-us/graph/api/serviceprincipal-post-serviceprincipals?view=graph-rest-1.0) and [list permission grants permissions](https://learn.microsoft.com/en-us/graph/api/oauth2permissiongrant-list?view=graph-rest-1.0).

Registration POSTs only an application ID, verifies its owner, and does not create consent grants, credentials or role assignments. By default it considers candidates with published Microsoft owner evidence. `-ResolvePublishedCandidates` can resolve further source-published IDs; owner verification remains mandatory, and a newly created principal with an unsupported owner is removed. Existing non-Microsoft principals are left alone. Registration may affect tenant inventory and audit logs.

Discovery aggregates ROADtools client/resource edges, merill/microsoft-info app candidates, EntraScopes resources, and verified Microsoft tenant principals. Candidate names and source membership do not establish ownership. The supported owner registry is in `Private/Graph.ps1`; an unknown owner is not accepted merely because its display name contains Microsoft. No source promises an exhaustive application universe.

The probe plan unions Graph probes, published resource relationships, current-principal configured grants, and resource definitions. It avoids a full speculative Cartesian product. Probe requests discover existing permissions using `.default` with PKCE, then state-checked v2/v1 implicit fallbacks when supported. Implicit issuance returns no refresh token. Exact published callbacks are intercepted locally and never followed. Browser policy and consent pages stop the attempt.

## Evidence, freshness and selection

Each terminal client/resource result checkpoints its outcome, numeric AADSTS codes, protocol, response scopes, readable `scp`, timing and public source hash. Tenant and principal IDs become SHA-256 namespace fingerprints; credentials, response bodies and raw identity IDs are omitted. Fingerprints remain private assessment metadata and can be correlated. One writer per database is required; the runner holds a directory lock. Direct module callers must enforce that rule themselves.

Resume skips completed outcomes, including failures. Use `-Refresh` for a new observation and `-RetryFailures` for registration retries. Refresh upstream discovery and tenant inventory explicitly. Acquire fresh credentials between bounded batches rather than assuming a long-running session never expires.

```powershell
$inventory = Get-Content (Join-Path $state 'inventory.json') -Raw | ConvertFrom-Json
$db = Get-TokenForgeScopeDatabase -Path (Join-Path $state 'scopes.json')
Get-TokenForgeAssessmentCoverage -Database $db -ResourceId $graph `
    -Scope Application.Read.All,AuditLog.Read.All `
    -TenantFingerprint $inventory.TenantFingerprint `
    -PrincipalFingerprint $inventory.PrincipalFingerprint
```

Coverage uses fresh observations in exactly this tenant/principal namespace and ranks clients by extra API scopes. A failed re-probe supersedes stale success for selection but does not prove scope removal. Save before/after database snapshots and use `Compare-TokenForgeScopeDatabase` for scope and availability changes.

For explicit assessment requests, `New-TokenForgeTenantRequest` checks requested scopes against enabled tenant resource definitions. This is a planning check, not evidence of client consent. Entra may issue extra permissions even for an explicit request; inspect actual scopes. An implicit-only client may support discovery of a broad permission set without supporting a narrower explicit PKCE request.

Readable JWT payloads are diagnostic evidence, with `SignatureValidated=false`. TokenForge does not validate Microsoft's access-token signatures or treat a decoded claim as proof of API acceptance. `Test-TokenForgeTokenAccess` performs a read-only Graph/ARM request and returns status without reading the response body. Test each assessment operation separately with the appropriate role and customer policy.

`Export-TokenForgeScopeDatabase` strips tenant/principal fingerprints and exports successful public app/resource scope observations. Review exports before publication: observation dates and unusual combinations can still reveal context. Exported observations are anonymous tenant evidence, not universal preconsent. The repository remains private; no live database or upstream datasets are committed.
