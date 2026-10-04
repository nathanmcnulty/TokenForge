# Sign-in app discovery and account-specific token sweeps

Two tools work together: `SignIns` finds client app IDs observed in sign-in logs, and `Register` resolves missing candidates to Microsoft-owned service principals. `Probe` iterates the resulting registered Microsoft clients and checkpoints the scopes Entra actually issues. Published scopes, log activity, Microsoft ownership, configured consent, token scopes, and API access remain separate evidence.

## Extract and resolve app IDs

```powershell
$runner = './scripts/Invoke-TokenForgeInventory.ps1'

# $state already contains discovery.json and inventory.json.
# $graphToken is a caller-owned SecureString for the intended tenant.
$logs = & $runner -Action SignIns -StatePath $state -GraphToken $graphToken `
    -Since ([DateTimeOffset]::UtcNow.AddDays(-7))
$logs.Applications | Where-Object { -not $_.KnownInInventory }

# Refresh tenant evidence after adding the discovered IDs.
& $runner -Action Inventory -StatePath $state -GraphToken $graphToken

# Review the proposed registrations without changing the tenant.
& $runner -Action Register -StatePath $state -GraphToken $graphToken `
    -ResolveSignInCandidates -ClientId $logs.Applications.AppId -WhatIf

# Resolve the explicitly selected IDs, verify owner, and checkpoint each outcome.
& $runner -Action Register -StatePath $state -GraphToken $graphToken `
    -ResolveSignInCandidates -ClientId $logs.Applications.AppId -Confirm:$false
& $runner -Action Inventory -StatePath $state -GraphToken $graphToken
```

The module function is `Get-TokenForgeSignInApplications`. It bounds the window to 31 days and defaults to seven days and all four sign-in types: interactive users, non-interactive users, service principals, and managed identities. It uses the [Graph beta sign-in endpoint](https://learn.microsoft.com/en-us/graph/api/signin-list?view=graph-rest-beta) with an explicit event-type filter because an unfiltered request returns interactive sign-ins only. Beta behavior can change; no v1 fallback silently drops event types. The API supports `$top`, `$skiptoken`, and `$filter`, not `$select`. Full event pages exist temporarily in memory; only normalized client `appId` UUIDs and aggregate counts are returned or saved. Resource object IDs are not mistaken for client app IDs.

`signin-applications.json` records the selected window/types, completeness, tenant fingerprint, counts, and application IDs. Discovery is extended with unverified `ObservedSignInNotOwnership` evidence. `KnownInInventory` means present in the existing catalog/inventory, not necessarily registered. `RegisteredMicrosoft` describes prior verified tenant state. Refresh inventory to see current registration. No user names, user/object IDs, IPs, device data, raw events, or credential objects are persisted by this stage. Keep this metadata private.

Log reads require the Graph permission and user role described by Microsoft; an account may be able to request tokens but still receive 403 for tenant-wide logs. Authorization failures, malformed collections, off-endpoint next links, loops, and page limits fail the stage instead of reporting an empty/complete result. No partial discovery is returned. Choose smaller windows if necessary; repeat them explicitly and discovery merges IDs idempotently.

A log entry is **not** Microsoft ownership evidence. `ResolveSignInCandidates` explicitly permits resolution of these unverified IDs. Existing non-Microsoft principals are rejected and left untouched. When Graph creates a new principal, its returned application ID and Microsoft owner must match. A newly created exact candidate with a non-Microsoft owner is removed; an ambiguous response or failed cleanup stops registration with a `CleanupRequired` checkpoint. This is the only ownership-resolution rollback. Successful registration does not create consent grants, assign users, or grant roles.

## Iterate known Microsoft apps with each account

```powershell
# Acquire an authorized cookie without printing it.
$cookie = Get-TokenForgeEstsCookie -PasskeyPath $passkey -XdrModulePath $xdrModule
try {
    # Use the confirmed signed-in account's fingerprint, not the inventory admin's.
    # Keep each account's state directory/database separate.
    & $runner -Action Probe -StatePath $accountState -EstsAuth $cookie `
        -PrincipalFingerprint $confirmedAccountFingerprint -Tenant $tenant `
        -MaxApplications 100 -MaxRedirects 8
} finally { $cookie.Dispose() }
```

Place the refreshed `inventory.json` in each account state directory. To establish `$confirmedAccountFingerprint`, use the existing [scope-to-token workflow](scope-token-workflow.md), which confirms Graph `/me`; its `TokenClaims.PrincipalFingerprint` identifies the actual observer. Dispose that token before continuing. Never assume Nora has the inventory administrator's namespace.

Omitting `ClientId` selects all registered, enabled, ownership-verified Microsoft clients. The plan includes Graph for every client, published client/resource edges, applicable account-specific tenant grants, and an application's own resource when it exposes delegated scopes. `-GraphOnly` limits the sweep to Graph while still covering every eligible client. It does not enumerate the Cartesian product of every client and every API. Supply an explicit module `Plan` or `ResourceId` for other resource experiments.

Each client/resource pair tries published redirects, bounded by `MaxRedirects`, with PKCE and the supported discovery-only implicit flows. Discovery observes existing `.default`/resource permission sets; it never creates consent and stops at interactive requirements. The database records scopes, matching tenant/account/client/audience evidence, protocol/redirect fingerprint, bounded error codes, and structural outcomes such as `NoRedirect` or `BrokerRequired`. Tokens are disposed after each attempt. Decoded JWT scopes are diagnostic; signatures and API authorization are not established by the sweep.

Run the same command again to resume: completed pairs in that account/tenant namespace are skipped. `MaxApplications` counts pending clients, so repeated bounded batches advance. Use `-Refresh` only when you deliberately want to reattempt completed pairs. Failures are completed observations too; a fresh sweep can differ because sessions, assignments, policies, clients, and roles change. Registration has a separate `-RetryFailures` option.

`Get-TokenForgeProbePlan` shows the exact planned pairs. Compare that plan with the latest checkpoint per client/resource and observer to report coverage. “Complete” means a terminal result for every selected pair, not a usable token from every app or proof of all server-side preconsent. Some known source candidates cannot be registered, some registered apps have no supported public-client flow, and some tokens are opaque.
