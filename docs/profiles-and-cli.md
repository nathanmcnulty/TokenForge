# Profiles and the CLI

A profile remembers the tenant, account binding, evidence folder, bootstrap client, scope limits,
and session policy. It contains no cookie, token, vault passphrase, or passkey private material.
Create separate profiles for separate accounts. Login confirms the account with Graph `/me` and
pins the confirmed tenant ID; later sign-ins cannot silently switch the profile's account.

Version 0.20 validates the existing version 1/2 profile configuration through the shared C#
core before the PowerShell projection reads it. Field names and integer types are strict;
unknown, duplicate, escaped-duplicate, and case-colliding fields are rejected. Tenant/account
bindings, scope limits, storage/key-ID policy, and timestamp parsing remain enforced. Generated
profile formats remain compatible. File permissions, paths, locks, atomic writes, and login
remain in the PowerShell workflow; this milestone does not provide direct native profile commands.
See the [sanitized validation report](profile-core-validation-2026-10-10.json).

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
callback. Configure `-BootstrapClientId` when creating the profile. Use `-LoginHint` for browser login and token acquisition when multiple browser accounts exist; identity binding still controls the result. Software-passkey profiles
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
   `.default`, broad sweep, or registration fallback. Hinted scope names can be tried even when omitted from resource definitions; only a matching issued token confirms the request. Successful evidence is checkpointed privately.
5. Validate the issued context, lifetime, and scope policy. The default permits zero additional
   API scopes; OIDC scopes are excluded. Explicit profile creation can set broader caps.
6. For persisted profiles, save after comparing the original profile and complete vault ciphertext,
   replacing the selected record on rotation. Direct vault changes during network acquisition
   reject the result without overwriting those changes; retry against the current state. Memory
   sessions use their process-context revision check. Deleted,
   changed, or expired sessions cannot be resurrected by renewal. Preserve the original retention
   deadline and login-confirmation time. Only explicit login starts a new retention window and clears old cached credentials so a failed refresh can recover through the new session.
7. If requested, perform one resource-bound GET API check. A 403 is separate authorization
   evidence and does not trigger wider scopes or another client. Cache hits rerun this check.

JWT inspection is diagnostic, not signature validation. API checks establish only the tested
operation. Local logout removes profile-owned caches; it does not revoke the server session. Callers must dispose retrieved credential copies and disconnect Graph SDK connections separately.
SecureString and private files reduce accidental exposure; a process running as the same user
can still read its own credentials. Encrypted vault plaintext necessarily exists transiently
while unlocked; the process cache retains only SecureStrings and nonsecret metadata.

## Persisted lifecycle implementation

Version 0.28 uses the shared C# credential runtime in process for persisted cache selection,
same-client renewal, policy enforcement, and atomic persistence. Fresh candidate planning and
login remain PowerShell operations; Memory sessions remain process-local. A cache hit makes
no token request and does not rewrite the vault. Expired saved tokens must still pass identity,
client, audience, scope and known-expiry checks before their refresh credential can be used.
A failed renewal does not silently try another client. When renewal omits a replacement refresh
credential, the existing same-client credential is preserved.

The operation lock spans acquisition; the vault lock is released during network work and
reacquired before checking the original ciphertext and profile configuration. Session retention,
token lifetime and cancellation are checked again after encryption, immediately before commit.
Successful renewal preserves the original retention deadline and login-confirmation time.
Failure preserves the existing ciphertext. Owned plaintext byte buffers and failed results are
cleared or disposed; managed strings and library allocations cannot be guaranteed immediate
erasure. The checks inspect JWT payloads and do not verify token signatures.

Packages contain `src/TokenForge/lib/net10.0/TokenForge.Credentials.dll`, with no SQLite dependency.
Source imports compile the same sources together. Restart PowerShell after changing runtime
versions; mixed or incompatible credential types fail with a fresh-process instruction.

See the [both-account validation report](native-profile-lifecycle-validation-2026-10-11.json).

Version 0.29 shares coverage and candidate ranking with the native `scopes explain` command.
Published hints, applicable tenant grants and fresh matched observations remain separate.
Planner timestamps are emitted as UTC strings, and a later failed observation suppresses older
coverage, including the last input at an equal timestamp. Structural placeholder IDs remain
visible but ineligible. Request construction, bounded callback attempts and browser/passkey
login still use PowerShell. See [native scope explanation](native-cli.md#native-scope-explanation).

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

Explicit Windows/Linux OS-backed profile storage is documented in [OS-backed vault](os-backed-vault.md).

Fresh acquisition now shares explicit request construction with the native credential core.
Warm observation-based requests and cold hint-based requests retain different redirect rules;
see [shared explicit request planning](native-architecture.md#shared-explicit-request-planning).
This is an internal planning change. Profile login and fresh acquisition still use PowerShell.
