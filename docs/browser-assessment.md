# Browser authentication and assessment planning

TokenForge 0.3 adds a system-browser authorization-code flow with PKCE. It works without XDRInternals, a passkey adapter, or cookie extraction. The selected application must publish an HTTP `localhost` root redirect for native/public-client use. Entra still decides whether that client supports redemption and whether the user can obtain the requested scopes.

```powershell
# Use verified tenant metadata and select a published localhost client deliberately.
$request = New-TokenForgeTenantRequest -Inventory $inventory `
    -ClientId '14d82eec-204b-4c2f-b7e8-296a70dab67e' `
    -ResourceId '00000003-0000-0000-c000-000000000000' `
    -Scope User.Read -RedirectUri 'http://localhost' `
    -Tenant 'your-tenant.example' -OfflineAccess
$token = Get-TokenForgeToken -Request $request -Browser -LoginHint 'user@your-tenant.example'
Test-TokenForgeTokenAccess -Token $token -Uri 'https://graph.microsoft.com/v1.0/me'
```

`LoginHint` suggests an account; it does not require that account. Account selection and MFA happen in the system browser. Verify the account through the intended API before recording observer-specific evidence. Guest testing requires the target tenant authority, its registered-client metadata, and separate context evidence. A successful sign-in does not establish ordinary-user status or guest status.

The callback listens on IPv4 loopback at an allocated port. The request uses `http://localhost:<port>/`, PKCE S256, and a random state. Invalid host/state, duplicate or mixed code/error fields, and oversized requests are rejected. Header reads and the overall sign-in have finite deadlines. The code is redeemed against the same public-cloud authority and client; existing scope checks apply. Closing the tab leaves the operation waiting until its deadline or PowerShell cancellation. Tokens remain `SecureString` objects in the caller's process. No credential cache is written.

Protocol references: [Microsoft authorization-code flow](https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth2-auth-code-flow) and [localhost redirect rules](https://learn.microsoft.com/en-us/entra/identity-platform/reply-url). Browser UI and live redemption still need validation on each supported operating system.

The browser path passed live Linux validation with a second account using Microsoft Graph Command Line Tools: PKCE redemption, Graph `/me` identity verification, client/audience matching, and observer-specific assessment coverage succeeded. Entra returned 108 API scopes, including 107 beyond the requested `User.Read`. Role and guest status remain unchecked. The same request with Azure CLI returned AADSTS65002, so that client is not a working example for this scope. See the [bounded validation evidence](browser-validation-2026-10-03.json).

## Assessment manifests

`manifests/self-profile.json` is a small example. Each check declares an ID, resource, required scopes, a read-only Graph or ARM API URI, role requirements, licensing requirements, and an HTTPS reference. These are data fields; the manifest cannot execute PowerShell or initiate consent.

```powershell
$plan = Get-TokenForgeAssessmentPlan -ManifestPath ./manifests/self-profile.json `
    -Database $database -TenantFingerprint $tenantFingerprint `
    -PrincipalFingerprint $observerFingerprint -MaxAgeHours 24
$plan.Checks | Select-Object Id, ScopeStatus, BestClientId, ApiStatus
```

Candidates use only the latest fresh, namespace- and request-matched scope observation. A newer failed probe invalidates older successful coverage. Different UTC offsets are ordered by actual time. Future-dated evidence beyond five minutes is excluded. Candidates rank by extra API scopes, which can exceed explicitly requested scopes. Role, licensing, and API statuses remain `NotValidated` until separately checked. An empty roles/licensing list in a manifest is an author declaration, not independently verified evidence. Source requirements should be reviewed as API documentation changes.

## Maintenance

```powershell
./scripts/Invoke-TokenForge.ps1 -Action Maintain -StatePath $privateState `
    -PrincipalFingerprint $observerFingerprint -MaxAgeHours 24 -RefreshDiscovery
```

`Maintain` optionally refreshes public discovery under the inventory writer lock. It reports source hash changes, old discovery/inventory, an inventory/discovery hash mismatch, and a queue of missing, stale, failed, or unverified observations for one observer. `-BeforeDatabasePath` adds observation availability/scope drift. Output contains private namespace fingerprints; store it with private assessment state, not in the repository. Source hashes establish changes to snapshots, not signed publisher authenticity; fetch timestamps can also change snapshot hashes.

Run this command with a task scheduler or cron for metadata maintenance. It does not register applications, obtain credentials, or re-probe automatically. Use the existing `Inventory` stage with a fresh authorized Graph token, then the existing resumable `Probe -Refresh` stage with that observer's authorized session to process the queue. An unattended runner must supply credentials through its own secret store.

## Export review and packaging

The public export includes only client ID, resource ID, observation time, scopes, evidence label, and `SignatureValidated=false`. Export validates IDs, timestamps, and scalar scope names before replacing a file, and excludes unmatched observer/request evidence. It omits tokens, identity claims, names, namespace fingerprints, consent identifiers, errors, and registration history. Exact timestamps and uncommon scope combinations remain correlation risks; review and aggregate them before public sharing. Identity-field removal does not guarantee anonymity. No export was published by this change.

```powershell
./scripts/Build-TokenForgePackage.ps1
# Extract dist/TokenForge-0.3.0.zip; use PowerShell 7.4+.
./scripts/Invoke-TokenForge.ps1 -Action Connect -RequestPath ./request.json
```

The ZIP contains the module, runtime CLI scripts, manifests, and Markdown documentation. The build emits a SHA-256 sidecar. `Connect` returns tokens to the calling PowerShell session; `Plan` and `Maintain` return credential-free objects that may contain private assessment fingerprints. Existing discovery/inventory/registration/probe/merge/export actions remain in `Invoke-TokenForgeInventory.ps1`. PowerShell is still required. A standalone executable, package signing, and package publication remain future work; no package is automatically uploaded.
