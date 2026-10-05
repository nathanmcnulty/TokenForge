# Profiles and the CLI

A profile remembers the tenant, account binding, evidence folder, bootstrap client, scope limits,
and session policy. It contains no cookie, token, vault passphrase, or passkey private material.
Create separate profiles for separate accounts. Login confirms the account with Graph `/me` and
pins the confirmed tenant ID; later sign-ins cannot silently switch the profile's account.

## Start in PowerShell

```powershell
Import-Module ./src/TokenForge/TokenForge.psd1
New-TokenForgeProfile -Name lab -Tenant example.onmicrosoft.com -StatePath /private/evidence
Connect-TokenForgeProfile -Name lab -Browser -Interactive
Get-TokenForgeProfileStatus -Name lab
Test-TokenForgeProfile -Name lab
$token = Get-TokenForgeProfileToken -Name lab -Resource graph -Scope User.Read
try {
    # Explicit credential handoff; caller owns these SecureStrings.
    Connect-MgGraph -AccessToken $token.AccessToken -NoWelcome
} finally {
    Disconnect-MgGraph
    $token.AccessToken.Dispose()
    if ($token.RefreshToken) { $token.RefreshToken.Dispose() }
}
Disconnect-TokenForgeProfile -Name lab
```

Use a private, fresh tenant-verified `inventory.json` in the state folder. Existing private
assessment state can be imported as `scopes.json`. `doctor` reports missing, stale, wrong-tenant,
and account-specific evidence. Inventory collection and service-principal registration remain
explicit administrative operations; normal token requests do not register applications.

The default bootstrap client is the narrow client validated in this lab, not a guarantee for
other tenants. Browser login needs an enabled, verified client with a published localhost
callback. Configure `-BootstrapClientId` when creating the profile. Software-passkey profiles
also take `-PasskeyPath` and `-XdrModulePath`; they reuse the existing optional XDR adapter.

## CLI commands

```powershell
./scripts/tokenforge.ps1 profile create -Profile lab -Tenant example.onmicrosoft.com -StatePath /private/evidence
./scripts/tokenforge.ps1 login -Profile lab -Browser -Interactive
./scripts/tokenforge.ps1 status -Profile lab -Json
./scripts/tokenforge.ps1 doctor -Profile lab
./scripts/tokenforge.ps1 scopes explain -Profile lab -Resource graph -Scope User.Read
./scripts/tokenforge.ps1 token get -Profile lab -Resource graph -Scope User.Read -Json
./scripts/tokenforge.ps1 logout -Profile lab
```

Invoke these commands inside the same PowerShell process for memory sessions. Separate `pwsh`
processes have separate memory sessions. PowerShell completes validated commands and operations;
module parameters also provide tab completion. CLI token output is metadata only. Use the module
API when handing a SecureString to another tool. Successful commands set exit code 0; failures
set 1 and emit a bounded error document in JSON mode. The older `Invoke-TokenForge.ps1` interface
remains available for explicit discovery and advanced operations.

For separate processes, explicitly choose encrypted persistence:

```powershell
New-TokenForgeProfile -Name persisted -Tenant example.onmicrosoft.com -Storage Passphrase -StatePath /private/evidence
$password = Read-Host 'Vault passphrase' -AsSecureString
Connect-TokenForgeProfile -Name persisted -VaultPassword $password -Browser -Interactive
$token = Get-TokenForgeProfileToken -Name persisted -VaultPassword $password -Scope User.Read
```

Never put a passphrase or raw credential on a shell command line. The vault remains the existing
passphrase-protected AES-GCM format with private filesystem permissions. Browser login establishes
an account binding but does not extract the browser cookie jar: new clients require continuing
browser SSO. A saved refresh credential can renew only its original client and exact request.
Status identifies this browser dependency. Memory storage persists no credentials; profile
configuration and private scope evidence still remain on disk.

## What a token request does

1. Read the profile and lock its operation; require an unexpired, matching local session.
2. Look for the exact resource and scope set. Validate the saved JWT account, tenant, client,
   audience, scopes, and known expiry before returning an independently owned cache copy.
3. If the access token expires, redeem its refresh credential through the saved canonical
   tenant and client. Reject a changed resource, scope set, protocol, or authority before sending it.
4. If no reusable credential exists, use fresh account observations. If none cover the scopes,
   try up to eight ownership-verified candidates supported by published hints or applicable tenant
   grants. These requests use explicit scopes and supported registered callbacks, with no consent,
   `.default`, broad sweep, or registration fallback. Successful evidence is checkpointed privately.
5. Validate the issued context, lifetime, and scope policy. The default permits zero additional
   API scopes; OIDC scopes are excluded. Explicit profile creation can set broader caps.
6. Save under a session revision check, replacing the selected record on rotation. Deleted,
   changed, or expired sessions cannot be resurrected by renewal. Preserve the original retention
   deadline and login-confirmation time. Only explicit login starts a new retention window.
7. If requested, perform one resource-bound GET API check. A 403 is separate authorization
   evidence and does not trigger wider scopes or another client. Cache hits rerun this check.

JWT inspection is diagnostic, not signature validation. API checks establish only the tested
operation. Local logout removes local credentials; it does not revoke the server session.
SecureString and private files reduce accidental exposure; a process running as the same user
can still read its own credentials. Encrypted vault plaintext necessarily exists transiently
while unlocked; the process cache retains only SecureStrings and nonsecret metadata.

## Graph PowerShell

Use a dedicated PowerShell process because Graph owns one process-wide authentication context.

```powershell
Find-TokenForgeGraphPermission -Command Get-MgUser
Connect-TokenForgeGraph -Name lab -Scope User.Read
Invoke-MgGraphRequest -Method GET -Uri 'https://graph.microsoft.com/v1.0/me'
Disconnect-TokenForgeGraph
```

The permission command preserves SDK alternatives rather than joining them into one broad
request. Choose an applicable set explicitly. The adapter refuses an existing SDK context and
refuses to disconnect a context replaced outside TokenForge. It holds an owned credential copy
through its connection lifetime. It neither replays SDK writes nor reconnects automatically;
disconnect and reconnect explicitly when changing scopes or renewing the SDK token.

The SDK supports [`Connect-MgGraph -AccessToken`](https://github.com/microsoftgraph/msgraph-sdk-powershell/blob/main/docs/authentication.md).
Its [context implementation](https://github.com/microsoftgraph/msgraph-sdk-powershell/blob/main/src/Authentication/Authentication/Cmdlets/GetMGContext.cs)
returns the process-wide context, so runspaces do not provide independent account isolation.

For teaching, the existing `Export-TokenForgeVaultView` produces an offline HTML view from whitelisted persisted-session metadata. It contains no cookie or token values and makes no network calls. See [Session vault](session-vault.md).
