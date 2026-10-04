# Single-command scope-to-token workflow

TokenForge 0.4 adds `Get-TokenForgeScopedToken` and `Invoke-TokenForge.ps1 -Action Token`. Both reuse tenant-verified inventory and fresh private observations. They identify the authenticated account, rank its candidates by extra observed API scopes, request explicit scopes with PKCE, and verify issued tenant/principal/client/audience and `scp` coverage. They do not grant consent or fall back to `.default` when an explicit request fails.

```powershell
$token = ./scripts/Invoke-TokenForge.ps1 -Action Token `
    -StatePath $privateState -DatabasePath $observerDatabase `
    -ResourceId '00000003-0000-0000-c000-000000000000' -Scope User.Read `
    -PasskeyPath $privatePasskey -XdrModulePath $xdrModule `
    -Tenant 'your-tenant.example' -MaxAdditionalScopes 0 -OfflineAccess `
    -ApiUri 'https://graph.microsoft.com/v1.0/me'

$token | Select-Object ClientId, RequestedScopes, GrantedScopes,
    ObservedAdditionalScopeCount, ApiCheck
try {
    # Token secrets are SecureString objects owned by this calling process.
    # Refresh with Get-TokenForgeToken -Request $token.Request -RefreshToken $token.RefreshToken.
} finally {
    $token.AccessToken.Dispose()
    if ($token.RefreshToken) { $token.RefreshToken.Dispose() }
}
```

Use `-EstsAuth $secureCookie` instead of passkey parameters for an existing session. Cookie inputs remain caller-owned. With no credential parameters, the CLI uses the system browser; `-Browser -LoginHint` is also explicit. Browser candidates require a published HTTP localhost root callback. Browser acquisition can prompt again for a different selected client. Passkey acquisition uses the existing XDRInternals adapter; no passkey registration is performed by this command. Refresh inputs remain supported through the existing lower-level token command because refresh tokens are client-specific; automatic cross-client refresh discovery is not claimed.

The temporary observer bootstrap requests Graph `User.Read` through Microsoft Graph Command Line Tools by default. Entra may return additional scopes for that temporary token. It is used for Graph `/me` identity confirmation and disposed before returning the selected token. `MaxAdditionalScopes` limits the returned token, not the bootstrap token. The module-level `BootstrapClientId` option (also available on the CLI) permits a verified alternative supporting the appropriate published native or localhost callback. A least-scope alternative may be suitable for passkey/cookie use in your tenant, but a working native callback does not establish browser compatibility.

The inventory's principal fingerprint is not assumed to describe the current account. Subsequent requests are pinned to the bootstrap tenant. Only fresh, context-matched observations for the authenticated observer are considered; stale inventory, missing observations, or unreadable context cause failure. The command does not automatically scan or register applications. Run the existing inventory/probe workflow to refresh missing coverage. Newer failed observations invalidate older successful ones.

Enabled ownership-verified candidates are bounded by `MaxCandidates` (default eight), with at most `MaxRedirects` published callbacks per client (default two). Cookie/passkey requests prefer the recorded successful callback and SPA setting. Issued context, scopes, and actual additional-scope limits are checked again before returning. Failure summaries contain public client IDs and bounded numeric Entra codes. Failed token objects and internally acquired cookies are disposed. JWT parsing remains diagnostic (`SignatureValidated=false`); Graph identity confirmation and optional API acceptance are independent live evidence.

`ApiCheck` is a separate read-only GET result. A valid token with HTTP 403 is returned with `Accepted=false`; the command does not switch clients or grant permissions to overcome an API authorization failure. The optional API URI is restricted to the selected Graph or ARM resource host, HTTPS port 443, and no redirects. Transport failure returns a bounded failed API result. No response body is returned by the access check.

## Assessment definitions

`manifests/core-readonly.json` contains eight source-referenced checks: self profile, service principals, directory audits, Conditional Access, directory roles, own licenses, security alerts, and Azure subscriptions.

```powershell
$token = ./scripts/Invoke-TokenForge.ps1 -Action Token `
    -StatePath $privateState -DatabasePath $observerDatabase `
    -ManifestPath ./manifests/core-readonly.json -CheckId directory-audits `
    -PasskeyPath $privatePasskey -XdrModulePath $xdrModule -Tenant 'your-tenant.example'
```

Each check declares explicit scopes, a read-only endpoint, documented role/license prerequisites, and its Microsoft API reference. Requirement strings describe alternatives and conditions; they are not automatically evaluated authorization rules. Successful license enumeration does not prove all product entitlements, and a 403 does not identify which prerequisite failed. The manifest preserves `NotValidated` role/license statuses until independently checked.

Additional requirement sources: [Graph log access licensing](https://learn.microsoft.com/en-us/entra/identity/monitoring-health/howto-download-logs), [Conditional Access licensing](https://learn.microsoft.com/en-us/entra/identity/conditional-access/overview). The API references are stored beside each check.

## Repeatable account comparison

`Invoke-TokenForgeLiveComparison.ps1` runs the manifest against each authorized observer using separate databases and passkeys. Supply short aliases, not identity values. It also reads direct active/eligible directory roles, visible transitive memberships and their role assignments/eligibilities, eligible PIM group memberships, and license service-plan status. Paging is bounded; inaccessible or incomplete results have null counts rather than being treated as zero. Group queries are capped, and hidden membership visibility and Azure RBAC are explicitly unestablished.

```powershell
$observers = @(
    @{ Alias='Admin'; DatabasePath=$adminDatabase; PasskeyPath=$adminPasskey },
    @{ Alias='User'; DatabasePath=$userDatabase; PasskeyPath=$userPasskey }
)
$comparison = ./scripts/Invoke-TokenForgeLiveComparison.ps1 `
    -InventoryPath "$privateState/inventory.json" -Observers $observers `
    -XdrModulePath $xdrModule -Tenant 'your-tenant.example'
```

The report omits tokens, cookies, credential paths, identity IDs, namespace fingerprints, group IDs, raw role assignments, and API bodies. Aliases, counts, and scope/client combinations can still describe a sensitive assessment; review any report before sharing.

Context references: [transitive membership](https://learn.microsoft.com/en-us/graph/api/user-list-transitivememberof?view=graph-rest-1.0), [directory-role eligibility](https://learn.microsoft.com/en-us/graph/api/rbacapplication-list-roleeligibilityscheduleinstances?view=graph-rest-1.0), and [PIM group eligibility](https://learn.microsoft.com/en-us/graph/api/privilegedaccessgroup-list-eligibilityscheduleinstances?view=graph-rest-1.0).

## Live result and stopping point

Linux passkey-backed single-command acquisition returned a zero-extra-scope `User.Read` token accepted by Graph. The comparison completed seven explicit-scope/API checks per observer. Admin API checks all returned 200; the second account's audit and Conditional Access APIs returned 403 while its tokens satisfied the requested scopes. Profile, applications, role assignments, own license details, and Azure subscription enumeration returned 200 for both.

The admin had two direct active roles and one direct eligible role. The second account had zero direct active/eligible roles, zero role assignments/eligibilities through its three visible transitive groups, and zero eligible PIM group memberships. Both accounts had enabled Entra Premium service plans. These findings support an ordinary-user comparison within the checked role paths; hidden memberships and Azure-resource permissions remain unestablished.

`SecurityAlert.Read.All` remained `NeedsObservation` for both observers. There was no fresh coverage for that exact least-privileged scope, and no consent was added or stronger scope silently substituted. This is an availability outcome, not an API denial. See [bounded comparison evidence](scope-workflow-validation-2026-10-04.json).

Work stops before another tenant, guest scenarios, or live Windows/macOS browser validation. Cross-platform CI verifies offline behavior. A standalone CLI executable remains future work.
