# Saved sessions and the native CLI path

TokenForge can now keep a named sign-in session and the tokens acquired with it in an **opt-in encrypted vault**. Memory-only operation remains the default. The vault is a file you unlock for each command, not a background service. It does not make Entra grant permissions: session validity, consent/preauthorization, roles, client support, and policy still decide what tokens and API access are available.

## What happens step by step

1. You explicitly create a vault and choose its unlock passphrase.
2. A passkey or supplied ESTS cookie authenticates the normal scoped workflow. A browser can also acquire tokens, but TokenForge never exports its cookies.
3. TokenForge requests a bootstrap Graph `User.Read` token and calls `/me` to confirm the actual signed-in account. This determines the account-specific candidate namespace.
4. It selects a first-party client from fresh evidence, requests the desired scopes through authorization code + PKCE with `prompt=none`, and checks the returned account, client, audience, scopes, and additional-scope limit. Any requested API check reports its result separately.
5. Only a successful scoped result is saved. The named record contains the ESTS cookie when supplied, the acquired access/refresh tokens, their request context, and metadata. All of this is encrypted together; inventory and observation JSON still contain no credentials.
6. A later vault-only command unlocks that named cookie, repeats bootstrap and `/me`, and checks that the confirmed account matches the saved namespace. It then requests a **new** scoped token and saves it. It does not silently return an old access token or try a refresh token against other clients.
7. You can explicitly retrieve an individual saved token, list metadata, remove entries, or export an offline teaching view. Retrieval is clearly labeled as saved evidence, not new issuance or proof of API authorization.

The vault saves the original selected `ESTSAUTH` or `ESTSAUTHPERSISTENT` value, not every response cookie or an entire browser cookie jar. This supports repeated requests while that credential remains accepted. It cannot bypass sign-in requirements or promise unlimited requests. Cookie rotation/full-jar synchronization remains future work. Lower-level vault commands do not rotate refresh credentials automatically; the [profile workflow](profiles-and-cli.md#what-a-token-request-does) supports managed same-client, exact-request renewal.

## PowerShell CLI examples

Use an owner-only directory for the vault. Creation protects a new immediate directory and file; existing insecure paths are rejected. Use physical directories with no linked ancestors: on macOS, use a home-directory path or `/private/var` instead of the `/var` system alias for temporary vaults. Choose a long, unique passphrase; the 12-character minimum is only an input floor. Do not put it in command arguments, transcripts, or environment variables.

```powershell
$cli = './scripts/Invoke-TokenForge.ps1'
$vault = Join-Path $HOME '.tokenforge-private/session.tfvault'
$unlock = Read-Host 'Vault passphrase' -AsSecureString

# Explicit initialization; refuses to replace an existing vault.
& $cli -Action VaultCreate -VaultPath $vault -VaultPassword $unlock

# First request: authenticate explicitly, then save under a deliberate name.
$first = & $cli -Action Token -StatePath $state -DatabasePath $database `
    -ResourceId '00000003-0000-0000-c000-000000000000' -Scope User.Read `
    -PasskeyPath $passkey -XdrModulePath $xdrModule -Tenant $tenant `
    -BootstrapClientId $bootstrapClient -MaxBootstrapAdditionalScopes 0 `
    -MaxAdditionalScopes 0 -OfflineAccess `
    -VaultPath $vault -VaultPassword $unlock -SessionName learning `
    -SessionRetentionHours 8

# Later: no passkey/cookie/browser argument means reuse this named vault cookie.
$next = & $cli -Action Token -StatePath $state -DatabasePath $database `
    -ResourceId '00000003-0000-0000-c000-000000000000' -Scope User.Read `
    -Tenant $tenant -BootstrapClientId $bootstrapClient `
    -MaxBootstrapAdditionalScopes 0 -MaxAdditionalScopes 0 `
    -VaultPath $vault -VaultPassword $unlock -SessionName learning

$metadata = & $cli -Action VaultList -VaultPath $vault -VaultPassword $unlock
$metadata.Sessions | Select-Object Name, HasCookie, RetainUntil, RetentionExpired

# Choose a token ID from metadata; this explicit action returns SecureStrings.
$saved = & $cli -Action VaultToken -VaultPath $vault -VaultPassword $unlock `
    -SessionName learning -TokenId $first.VaultTokenId -MaxAdditionalScopes 0

# Export a new metadata-only HTML file; open it in a browser without a server.
& $cli -Action VaultView -VaultPath $vault -VaultPassword $unlock `
    -OutputPath ./learning-view.html

# Remove one token, or omit TokenId to remove the session and all its tokens.
& $cli -Action VaultRemove -VaultPath $vault -VaultPassword $unlock `
    -SessionName learning -TokenId $first.VaultTokenId

# Dispose every returned credential and the caller-owned unlock password.
foreach ($t in @($first, $next, $saved)) {
    if ($t.AccessToken) { $t.AccessToken.Dispose() }
    if ($t.RefreshToken) { $t.RefreshToken.Dispose() }
}
$unlock.Dispose()
```

The variables `$state`, `$database`, `$passkey`, `$xdrModule`, `$tenant`, and `$bootstrapClient` come from your [scope-to-token setup](scope-token-workflow.md). A zero-extra bootstrap needs a client observed to satisfy that limit. For browser capture, replace the passkey arguments with `-Browser`; this saves returned tokens but creates no browser-derived cookie. If the name already holds an unexpired supplied cookie, it is preserved without extending its deadline. The CLI prompts securely if `VaultPath` is provided without `VaultPassword` and disposes only the password it prompted for.

Module equivalents are `New-TokenForgeVault`, `Get-TokenForgeVault`, `Get-TokenForgeVaultToken`, `Remove-TokenForgeVaultEntry`, and `Export-TokenForgeVaultView`. Persistence options are on `Get-TokenForgeScopedToken`; lower-level `Get-TokenForgeToken` does not automatically save tokens.

For manual renewal, `VaultToken -RefreshOnly` returns only the saved refresh credential and its same-client request plan, even if the access token expired. Submit that plan to `Get-TokenForgeToken -RefreshToken`, verify the returned tenant/principal against the expected fingerprints and its client/audience/scopes, and dispose both results. This path **does not update the vault or save a rotated refresh token**. Use [profile token acquisition](profiles-and-cli.md#what-a-token-request-does) for managed same-client refresh rotation, or vault-cookie acquisition for a new scoped request. Refresh tokens can expire or be revoked independently.

## Security and lifetime

| Boundary | Implemented behavior |
| --- | --- |
| At rest | AES-256-GCM authenticated encryption; PBKDF2-HMAC-SHA256 with 600,000 iterations; fresh 32-byte salt and 12-byte nonce for every write |
| Filesystem | Owner-only Unix directory/file creation and permission checks; protected Windows ACLs; linked/reparse paths and UNC paths rejected |
| Concurrent access | Exclusive lock across read/modify/write; encrypted-only temporary files; atomic replacement; revision checks reject stale in-flight saves after deletion or another update |
| Namespace | Explicit session name, confirmed tenant/account fingerprints; another account cannot replace that name |
| Local retention | Default 8 hours, configurable 1–168; reusing a saved cookie does not extend its deadline. A fresh explicit login can renew it |
| Access-token retrieval | Known expiry with a two-minute margin, actual JWT context/scope checks, caller-selected additional-scope limit |
| Output | Listing and HTML use a whitelist; raw credentials require an explicit retrieval command and return as `SecureString` |

A stolen encrypted file can be attacked offline, so passphrase entropy matters. There is no password recovery, OS-keystore integration, or stored unlock password in this version. Unlocking necessarily exposes plaintext to the current process; `SecureString` and clearing mutable byte buffers do not protect against a compromised process or guarantee erasure of managed strings. Permissions do not protect against the same user or a privileged administrator. The passkey file and browser profile remain separate stores with their own security.

Local retention is a client-side reuse rule, not the cookie's actual server expiry or cryptographic deletion. Expired records remain encrypted in the file until removed. Entra can reject any credential sooner. Removing an entry is local deletion, not server-side revocation or guaranteed erasure of backups. Keep vaults outside Git and ordinary shared folders; `.tfvault` and `.tfvault.lock` are ignored as a further guard.

The HTML viewer shows a snapshot of names, namespace fingerprints, app/resource IDs, requested/issued scopes, timestamps, refresh-token presence, and evidence labels. It contains no cookie, token, or passphrase, and has no network access, browser storage, or vault backend. Those metadata fields can still be private. Its content-security policy pins the embedded script/style hashes; all displayed values use text nodes. JWT payload inspection is diagnostic and does not validate signatures. API success is a separate observation.

## Portable format and migration

The v1 JSON envelope fixes `Format=TokenForgeVault`, `Version=1`, `Kdf=PBKDF2-SHA256`, and `Iterations=600000`. Salt, nonce, 16-byte tag, and ciphertext are base64. PBKDF2 derives 32 key bytes from the exact UTF-8 passphrase (no Unicode normalization). GCM authenticates the exact UTF-8 additional data `TokenForgeVault|1|PBKDF2-SHA256|600000|AES-256-GCM`. The encrypted JSON payload has `SchemaVersion=1` and named `Sessions`. Readers bound sizes and reject unsupported envelope/KDF versions before expensive derivation. This is a portable implementation format, not yet a promised external interoperability API. A keychain-backed format must use a new explicit version/provider, never a silent plaintext fallback.

## Recommended native path

Use a **shared .NET library**, a thin PowerShell wrapper, and a standalone CLI built from the same library. Move portable HTTP/PKCE, request validation, vault transactions, and metadata projection first; keep browser launch, passkey provider integration, and OS secret storage behind narrow platform adapters. This avoids maintaining two independently evolving security implementations.

| Option | Benefit | Cost / decision |
| --- | --- | --- |
| Shared .NET core + native CLI | Reuses the current .NET transport/crypto; PowerShell can load the library; one security implementation | Recommended. Ship self-contained per-OS CLI builds first, then assess Native AOT compatibility |
| Go binary | Good standalone distribution and explicit portable core | Viable if an independent rewrite is desired; reimplement auth/vault and replace current PowerShell/passkey integration |
| Separate platform scripts | Small initial packaging step | Duplicates security and feature work; retain only tiny OS adapters |

[Self-contained .NET deployments](https://learn.microsoft.com/en-us/dotnet/core/deploying/) do not require a separately installed runtime. [Native AOT](https://learn.microsoft.com/en-us/dotnet/core/deploying/native-aot/) eliminates JIT and separately installed runtime requirements, but has library restrictions and [target-specific build requirements](https://learn.microsoft.com/en-us/dotnet/core/deploying/native-aot/cross-compile); it is a later validated packaging milestone, not a current claim. PowerShell itself should remain an adapter, not be embedded as the native core.

Self-contained Windows, macOS, and Linux [CLI packages](native-cli.md), shared issued-token policy and SQLite evidence stores, explicit Windows Credential Manager/Linux Secret Service [key protection](os-backed-vault.md), and managed profile refresh rotation are implemented. Authentication still uses PowerShell 7.4+. Next milestones are portable native acquisition, signed macOS Keychain integration, durable signed releases, and live Windows/macOS authentication validation. Full cookie-jar synchronization remains separate work.

The current offline viewer establishes the teaching model now. A later GUI should consume this same sanitized projection by default. Any future credential operations must be a separately authorized CLI/provider action, not an unauthenticated local web endpoint.
