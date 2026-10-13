# Native CLI and evidence store

The native CLI is a self-contained .NET executable per OS and architecture. Evidence commands
run directly in the shared core with bundled SQLite. Implicit authentication adapters invoke the packaged PowerShell 7.4+ module;
install `pwsh` and keep `src/` and `scripts/` beside the executable for those commands.
Version 0.18 adds direct native `token acquire`, and PowerShell uses the same C# OAuth transport
and issued-token policy. Version 0.33 adds native system-browser PKCE to advanced `token acquire`. Version 0.36 adds native browser profile login and persisted browser profile acquisition. Explicit software-passkey acquisition and profile login are native; [same-account lab software-passkey enrollment](native-passkey-enrollment.md) is native; first-passkey TAP enrollment remains external and implicit passkey login uses PowerShell.
Version 0.19 also shares vault envelope encryption with the native core; profile storage and
login still use PowerShell. See [shared vault validation](vault-core-validation-2026-10-08.json).
Version 0.20 shares profile configuration validation between PowerShell and the native core.
See [profile policy validation](profile-core-validation-2026-10-10.json).
Version 0.21 runs `profile create` and `profile show` directly in the executable. These commands
need neither PowerShell nor the packaged scripts. Credential lifecycle and login still use PowerShell.
Version 0.23 runs `profile forget-key` directly in the executable on Windows and Linux.
It takes the same profile/vault locks, removes ciphertext before deleting its OS key, and
returns exit code 1 with retry metadata if the key store is unavailable or locked. The command
requires no PowerShell and preserves the profile configuration. It refuses non-OS profiles
and unsupported platforms before deletion. Forgetting local credentials does not revoke
already-issued tokens or erase copies held by other processes. See
[native key-removal validation](native-forget-key-validation-2026-10-10.json).

Version 0.26 runs `profile inspect-vault` natively. It unlocks the existing encrypted vault and returns only the selected profile session's metadata, after checking its account binding. It never returns credentials, renews tokens, creates an OS key, or changes ciphertext. Use the hidden native passphrase prompt for Passphrase profiles; explicit `--stdin` accepts a bounded passphrase followed by EOF. OS-backed profiles read the existing Windows/Linux key without accepting stdin. Memory profiles and unsupported OS stores are refused. Expired sessions are shown as expired rather than renewed.

```sh
tokenforge profile inspect-vault --profile lab --json
```

Inspection uses both operation and vault locks, validates decrypted records, and clears its owned plaintext buffer. Metadata reports stored lifetime and scope observations, not new issuance or API authorization. The underlying record validator can allocate managed strings; this is not a guarantee of immediate erasure of every in-memory copy. Normal login remains PowerShell-based; version 0.31 adds native saved-cookie profile acquisition.

Version 0.27 runs `logout` natively. It removes the selected persisted session, including its cookie and tokens, while preserving profile configuration, unrelated sessions, and the OS encryption key. Expired or stale account bindings do not prevent deliberate cleanup. Missing vaults and Memory profiles complete without unlocking or creating storage. Existing vaults require both locks and valid decrypted records before any write.

```sh
tokenforge logout --profile lab
```

Passphrase profiles use a hidden prompt, or explicit `--stdin` with a 12–1024 character passphrase followed by EOF. `--prompt-passphrase` remains accepted; it cannot be combined with `--stdin`. OS-backed profiles reject either credential-input flag. Logout emits only local-removal metadata. It does not revoke server sessions or clear credentials already held by another process. Owned plaintext and rewrite byte arrays are cleared; managed strings and library internals are not guaranteed immediate erasure. If rewriting exceeds the bounded record size, the operation fails without replacing ciphertext. See the [sanitized logout validation report](native-logout-validation-2026-10-11.json).

Version 0.28 moves persisted-profile cache selection, same-client renewal, issued-token checks,
and atomic credential writes into the shared native core. The module calls these operations
in process through `TokenForge.Credentials.dll`; credentials do not cross a subprocess JSON
boundary. Fresh candidate planning, browser/passkey login, Memory sessions, and the CLI
`token get` adapter still use PowerShell. See the [persisted lifecycle validation report](native-profile-lifecycle-validation-2026-10-11.json).

Packages include a BCL-only .NET 8 credential assembly, separate from SQLite evidence storage.
A source checkout compiles the same explicit source list once with `Add-Type`; it needs no SDK
for module import. Both package builders need the .NET SDK and validate that their compiled
source list matches the module list. A present invalid DLL fails without source fallback.
Restart PowerShell when changing credential runtime versions; already loaded legacy or mixed
credential assemblies are rejected rather than silently reused.

Version 0.22 also shares vault-file transactions: exclusive locks, bounded ciphertext reads,
private temporary files, and atomic publication. The transaction API handles ciphertext only;
callers still authenticate envelopes and validate credential records and account policy.
See [shared transaction validation](vault-file-validation-2026-10-10.json).
The module and native CLI share private-file permission and link checks. See
[native profile validation](native-profile-validation-2026-10-10.json) for both-account Linux proof
and configuration interoperability checks.

```sh
tokenforge profile create --profile lab --tenant example.onmicrosoft.com --state-path /private/evidence
tokenforge login --profile lab --browser --interactive --prompt-passphrase
tokenforge status --profile lab --json
tokenforge doctor --profile lab --json
tokenforge token get --profile lab --resource graph --scope User.Read,Mail.Read --prompt-passphrase --json
tokenforge logout --profile lab --prompt-passphrase
```

Use `--login-hint user@example.onmicrosoft.com` for browser login or token acquisition when the browser has multiple accounts. The hint helps account selection; the bound profile fingerprints still enforce identity.

Omitting `--profile` selects `default`. Creation refuses to overwrite an existing profile.
`profile show` validates configuration without creating missing directories. Creation stores
configuration only: selecting `--storage OperatingSystem` does not create or open a keystore key.
Use `--max-age-hours` and `--session-retention-hours` to configure inventory age and session retention.

Native profile creation defaults to explicit passphrase storage because each CLI invocation is
its own process. The module still defaults to memory storage. Passphrases are read without echo
by PowerShell, never passed in process arguments or environment variables. The native command
parser has no raw-cookie, token, or passphrase argument. Token output contains metadata only.
Use the in-process module API for Graph SDK handoff; an SDK connection in a finished child
process cannot authenticate the caller's PowerShell process.

## Native scope explanation

Version 0.29 runs `scopes explain` directly in the executable, using the same BCL planner
as `Get-TokenForgeScopeCandidates` and `Get-TokenForgeAssessmentCoverage`.

```sh
tokenforge scopes explain --profile lab --resource graph --scope User.Read,Mail.Read --json
```

The profile must already have a confirmed tenant/account binding. This command reads private
`inventory.json` and `scopes.sqlite` (preferred) or `scopes.json` from its state folder. Missing
or malformed evidence fails without creating a store. It accepts Graph and ARM resource aliases,
requires explicit API scope names, and accepts no authentication or passphrase options. It
unlocks no vault, requests no tokens, makes no network calls, and launches no PowerShell process.
SQLite uses an existing-file read-only connection; SQLite may manage its normal sidecar files.

The result separates published hints, grants applicable to the profile's observer, and fresh
matched scope observations. Confirmed observations rank first, then applicable grants, then
published hints, subject to fresh inventory and enabled Microsoft-owned client/resource records.
A newer unsuccessful observation, including the last input at an equal timestamp, suppresses
older coverage. Ordinal scope matching preserves case. Duplicate canonical app IDs and duplicate
JSON property names are rejected. `ClientEligible` describes structural eligibility; all-zero
placeholder IDs remain visible for learning but are never eligible clients or fresh coverage.
Neither hints nor observed scopes guarantee silent consent,
JWT signature validity, or API authorization. Explanation does not perform or confirm a new login.

The planner returns metadata only. Account fingerprints, arbitrary input properties, cookies,
and token values are excluded. Timestamps retain their instants across PowerShell projections and are emitted as UTC strings.
Saved-cookie profile acquisition, including warm/cold request planning, runs natively.
Passkey login still requires PowerShell. Browser profile login runs natively. Explanation itself
is offline and performs no authentication or token acquisition.

## Direct native acquisition

`token acquire` is an advanced validation and teaching command. Give it an explicit request
and the expected account context, then supply an existing ESTSAUTH cookie, refresh token, or choose system-browser authorization.
It runs entirely inside the native executable. It returns policy-checked metadata, disposes
the acquired tokens, and saves no credentials. Use `token get` and the module API for the
existing profile and Graph PowerShell workflows.

```sh
tokenforge token acquire --plan /private/native/request.json --credential cookie
tokenforge token acquire --plan /private/native/request.json --credential refresh
tokenforge token acquire --plan /private/native/browser-request.json --credential browser
tokenforge token acquire --plan /private/native/browser-request.json --credential browser --interactive --login-hint observer@example.test --timeout-seconds 300
```

Browser acquisition requires a published `http://localhost` root callback for a public
native client. It uses silent authorization by default; an existing browser session and
prior authorization are required. `--interactive` explicitly permits an account selection
prompt. No mode automatically retries interactively or approves consent. Browser cookies
stay with the user's browser; TokenForge receives the authorization code through its bounded
loopback listener, redeems it with PKCE, validates the expected context and scopes, and disposes
the tokens after printing metadata. Browser mode rejects `--stdin`; browser-only flags are
rejected for cookie and refresh acquisition. The browser timeout accepts 30–900 seconds.
The OS browser launcher has a separate ten-second bound and suppresses its child output.

The [0.33 validation report](native-browser-cli-validation-2026-10-11.json) records real Entra code redemption through the self-contained Linux CLI for Nora and secadmin, using a headless redirect fixture. Both responses included 107 additional API scopes. A plan allowing only 32 was rejected; the positive proof explicitly allowed 4096. Choose an additional-scope budget deliberately: requesting User.Read alone does not guarantee that Entra issues only that scope.

The credential prompt does not echo. An explicit `--stdin` accepts one credential followed
by EOF, optionally with trailing line endings; never put credentials in command arguments,
environment variables, shell history, or a plan file. Cancellation stops active network requests.
Each response has a 30-second deadline and a 2 MiB streamed size limit.

The JSON plan has `SchemaVersion: 1`, a `Request` containing selected fields from `New-TokenForgeRequest`,
`ExpectedTenantFingerprint`, `ExpectedPrincipalFingerprint`, and `MaximumAdditionalScopes`.
Fingerprints must come from your verified profile/account context. The request contains
ClientId, ResourceId, ResourceUri, Tenant, RedirectUri, Scopes, OAuthScopes, Spa, Discovery,
and Protocol; native CLI acquisition accepts explicit scopes with OAuth2V2Pkce and
Discovery=false. Prepare plans using verified inventory and published callback metadata.
Do not serialize the complete PowerShell request object into `Request`: its provenance fields
are not transport fields. Project the fields explicitly; Discovery defaults to false and Protocol
to OAuth2V2Pkce:

```powershell
$nativeRequest = $request | Select-Object ClientId,ResourceId,ResourceUri,Tenant,RedirectUri,Scopes,OAuthScopes,Spa
$nativePlan = @{
    SchemaVersion = 1
    Request = $nativeRequest
    ExpectedTenantFingerprint = $verifiedTenantFingerprint
    ExpectedPrincipalFingerprint = $verifiedPrincipalFingerprint
    MaximumAdditionalScopes = 0
}
# Serialize $nativePlan into your private request.json with ConvertTo-Json -Depth 8.
```

Plan fields cannot contain credentials. Duplicate or unknown fields are rejected. Store the
file and its immediate directory with current-user-only permissions: 0600/0700 on Unix or
protected owner-only ACLs on Windows. Linked paths are rejected; plan validation changes no files.

Before returning metadata, the command checks decoded account fingerprints, client, audience,
requested delegated scopes, known expiry with at least two minutes remaining, and the
additional-scope cap. A missing cap defaults to zero. Refresh uses the same client and exact
OAuth scopes in that plan; it has no acquisition fallback. Keep the same trusted plan when
renewing an existing credential. This command does not persist a refresh-to-plan binding;
the existing profile workflow provides that durable binding.

Entra may issue additional pre-consented scopes. A rejected scope request does not imply that
the transport failed or that every scope for the app is unavailable. Errors return a static
stage/category and bounded numeric HTTP/AADSTS codes, with response details suppressed.
Decoded JWT claims remain unverified; acquisition does not establish signature validity or
API authorization. Opaque tokens cannot satisfy this command's account/scope policy.

Credentials briefly exist as managed strings for HTTP encoding; disposing SecureStrings,
clearing request dictionaries, and zeroing byte buffers reduces lifetime but does not guarantee
that every immutable string is erased from process memory. An OS vault protects persisted
credentials separately. See [native validation](native-oauth-validation-2026-10-08.json).

## Native local software-passkey acquisition

Version 0.37 adds an explicit local software-passkey credential to advanced acquisition:

```sh
tokenforge token acquire --plan /private/request.json --credential passkey --passkey-file /private/Test.json
```

The plan follows the account, tenant, client, resource and scope policy described above.
The key file and its immediate parent must be private to the current user; linked paths
are rejected. The command validates the plan before opening the key or contacting Entra.
It runs without PowerShell, returns only the usual sanitized token metadata, and persists
neither the cookie nor access/refresh tokens. Explicit software-passkey profile login is described below; enrollment and implicit passkey login
use the existing PowerShell workflow.

The flow is:

1. Import the explicitly supplied local P-256 software key and credential metadata.
2. Obtain an Entra challenge for that credential's account and sign a WebAuthn assertion.
3. Complete the known account-selection and stay-signed-in pages to obtain an in-memory
   ESTS session cookie. Ambiguous accounts, consent pages and unknown interactions fail.
4. Use that cookie for the plan's explicit authorization-code/PKCE request. The cookie
   authenticates the session; Entra determines which scopes the selected app can receive.
5. Check the resulting token's decoded account, audience, client, scopes and lifetime
   against the plan, emit metadata, then dispose the owned key and credentials.

The [sanitized live report](native-software-passkey-validation-2026-10-11.json) records
Linux proofs for Nora and secadmin: native child acquisition with no PowerShell on
PATH, policy acceptance, and separate Graph `/me` HTTP 200 identity confirmation.
Temporary key copies were removed and the originals remained unchanged. This does
not establish live Windows/macOS authentication or other apps/resources. The proof
explicitly allowed up to 128 additional scopes; both responses reported 107. The
default cap of zero rejects such broader tokens rather than accepting them silently.

This adapter supports the public Microsoft cloud and `login.microsoft.com` RP, local
PKCS#8 P-256 credentials, and a zero signature counter. It never updates the key file.
It supports the existing `username`/`userName`, `credentialId`/`methodId` and
`privateKey`/`keyValue` formats, with required `userHandle`; conflicting aliases fail.
Nonzero counters, Key Vault references and other curves are unsupported.

This is a software authenticator for lab credentials. Its user-presence and
user-verification flags emulate the research authenticator; they do not prove a
hardware touch, biometric check or OS WebAuthn verification. Hardware passkeys and
native enrollment are separate work. Sensitive response bodies and assertions briefly
exist as managed strings; clearing owned buffers and disposing key handles reduces
lifetime but cannot guarantee immediate erasure of every string. The cookie stays in
this operation's memory rather than a saved browser cookie jar. Decoded token checks
are not JWT signature validation or a substitute for a resource API check.

## Durable private evidence

SQLite is an opt-in evidence workspace. Existing discovery still writes JSON and updates the
application metadata catalog. Import/export bridges the existing scope database without putting
credentials in SQLite or changing working CI discovery. It preserves validated observations and
registration outcomes and records each source path and latest import date. A repeated import
is idempotent. Import validation and writes occur within one transaction; one malformed row
rolls back the entire import. Exports use a consistent database snapshot.

```sh
tokenforge evidence import --database /private/native/evidence.sqlite --input /private/evidence/scopes.json
tokenforge evidence export --database /private/native/evidence.sqlite
tokenforge evidence export --database /private/native/evidence.sqlite --public
```

Normal export includes private tenant/account fingerprints and registration history. Explicit
`--public` removes the fingerprints and registration history. Both exports are metadata only.
Output goes to stdout; use private filesystem permissions when saving private exports.
Storage refuses linked paths and broadly accessible directories/files. New databases use a
private parent and file from creation. Windows uses a protected current-user ACL; Unix uses
0700 directories and 0600 files. SQLite WAL/SHM files remain inside that private directory.
This database is not encrypted and must never store credentials.

## Stable plans and checkpoints

Provide a JSON array of client GUIDs. A plan freezes sorted, unique membership and batch size
under a content hash. Adding applications or changing batch size creates a different plan.
Chunks are assigned before filtering completed clients, so resume does not move members.

```sh
tokenforge evidence plan --database /private/native/evidence.sqlite --input clients.json --batch-size 100
tokenforge evidence pending --database /private/native/evidence.sqlite --plan PLAN_HASH
tokenforge evidence checkpoint --database /private/native/evidence.sqlite --plan PLAN_HASH --client CLIENT_GUID --outcome Succeeded
```

Historical registration records can retain the legacy empty GUID from existing JSON; plans reject it and it supplies no application eligibility or authorization.

Checkpoints record terminal execution outcomes. They do not create successful scope evidence;
import the corresponding scope observations separately. Failed checkpoints preserve earlier
successful observations and their dates. The existing CI rotating discovery chunks are not
silently migrated to these plans; integration is a later explicit migration.

## Build and platform limits

```powershell
./scripts/Build-TokenForgeNative.ps1 -Runtime linux-x64
# Also supported: linux-arm64, win-x64, win-arm64, osx-x64, osx-arm64
```

.NET 10 SDK builds the executables; the shared core targets .NET 8 for PowerShell 7.4 compatibility.
Offline CI builds and exercises host executables on Linux, Windows, and macOS. Live auth proof
remains Linux and the two lab accounts. Native AOT, OS-protected encryption keys, removal of the
PowerShell authentication dependency, and a metadata visualization GUI remain separate milestones.
See [native architecture](native-architecture.md) for their boundaries and validation gates.

Explicit Windows/Linux OS-backed profile storage is documented in [OS-backed vault](os-backed-vault.md).

Offline `research report` and `research export-flows` commands are available through the packaged PowerShell adapter; see [Application research catalog](research-catalog.md).

## Individual flow checkpoints

Version 0.13 adds `flows import` and filtered `flows export`, plus individual transactional plan/attempt writes used by the probe adapter. See [SQLite flow evidence](sqlite-flow-evidence.md) for migration, private storage, namespace selection, and remaining JSON scale limits.

## Primary application catalog

Version 0.14 adds `catalog import/update/export` and direct transactional application-ledger updates from the existing producers. Research reports prefer `applications.sqlite` when it exists, and accept `--metadata-path`. See [SQLite application catalog](sqlite-application-catalog.md) for migration, filtered views, provenance, publication guards, and remaining scope-history limits.

Primary scope and registration checkpoints can use an existing `scopes.sqlite`. See [SQLite scope history](sqlite-scope-history.md) for migration, selected/latest reads, resume repair, and public exports.

Version 0.16 connects [frozen research cohorts](research-cohorts.md) to the inventory CLI and adds native `evidence cohort/cohort-export`. Contextual run recipes preserve namespace and chunk membership; selected scope reads also accept `--flow-plan` and `--client`.

## Encrypted maintenance backups

`tokenforge research backup --snapshot-path <maintenance.sealed> --backup-directory <private-directory> --json` saves an immutable ciphertext copy without loading an authentication profile. It runs natively and reports byte identity separately from authentication. See [private maintenance](private-maintenance.md) for key custody and restoration.

## Inspect weekly progress offline

Use a local checkout of the public `discovery-data` branch:

```text
tokenforge research weekly --state-path /path/to/discovery-data
tokenforge research weekly --state-path /path/to/discovery-data --json
```

The PowerShell entry point is `./scripts/tokenforge.ps1 research weekly -StatePath /path/to/discovery-data -Json`. No profile or login is required. The command reads the two frozen weekly recipe files, validates their hashes and coverage, and recomputes reports rather than relying on cached report files. It writes no files. Unrelated checkout files are not inspected or endorsed by this command.

Reports distinguish source catalog, selected applications, successful applications, and app/resource pairs. They include remaining applications/pairs, pending/exhausted batches, observation dates, and next-step guidance. An older recipe is marked `CurrentWeek=false`; refresh the checkout and inspect scheduling before assuming the current week has run. Future-week recipes and creation times more than five minutes ahead are rejected. Assessment includes structural exclusions, and successful token observations do not establish universal support or API authorization. The packaged native command uses its PowerShell adapter, so PowerShell 7.4+ is required.

The [v0.29 scope-planning validation report](native-scope-planning-validation-2026-10-11.json) records the sanitized two-account Linux proof and package checks.

## Native saved-cookie profile acquisition

Version 0.31 runs `token get` inside the executable for OperatingSystem profiles and for Passphrase profiles using explicit `--stdin`. It opens the encrypted session, validates its account binding and retention, then selects an exact-scope cached token or redeems its same-client refresh token. Fresh acquisition uses the saved ESTSAUTH cookie with bounded published callbacks and explicit scopes. It never requests consent.

```sh
tokenforge token get --profile lab --scope User.Read --api-uri https://graph.microsoft.com/v1.0/me --json
```

Passphrase input uses `--stdin`, with a 12–1024 character passphrase followed by EOF; it is never accepted in arguments or environment variables. OS-backed profiles reject stdin. `--resource graph|arm` selects the standard resources; `--resource-id GUID` selects another resource and cannot be combined with `--resource`. API checks are restricted to Graph or ARM HTTPS endpoints. `--max-candidates` (1–100, default 8) and `--max-redirects` (1–8, default 2) bound fresh requests. Output contains only metadata.

With fresh observed scope coverage, the tool first obtains a bounded Graph `User.Read` bootstrap token and confirms `/me.id` against its validated account. It disposes that bootstrap token before trying the observed clients. A failed warm bootstrap or acquisition stops; it does not switch to cold hints. Without matching coverage, enabled Microsoft-owned clients with published or configured hints form the cold candidate set. A successful cold token must satisfy identity, client, resource, exact scope case, expiry and additional-scope limits before metadata is checkpointed.

Cold checkpoint writes take the cooperating state writer lock and reread current JSON history or append transactionally to the existing SQLite store. A deleted or truncated existing SQLite store fails rather than being initialized again. Initially absent JSON history can be created. Checkpoint failure discards the token without trying another candidate. Credential persistence remains a separate final vault/profile comparison-and-swap: a successful metadata checkpoint can remain if subsequent cancellation, retention or concurrent profile changes prevent the credential commit.

Memory profiles, `--login-hint`, and `--prompt-passphrase` retain the existing PowerShell adapter. If an OS-backed session needs fresh browser authentication because it has no cookie, the native operation releases its locks before invoking that adapter. Explicit stdin cannot be replayed into a browser fallback; use the existing interactive/module workflow. Explicit browser and software-passkey login are native; same-account lab enrollment is native; first-passkey TAP enrollment remains external and implicit passkey login requires PowerShell. Windows and Linux OS stores are supported; macOS requires the existing signed-helper work. JWT payload checks do not establish signature verification.

The [sanitized live report](native-fresh-acquisition-validation-2026-10-11.json) records Linux native cold/warm/cache/renewal Graph `/me` checks with Nora and secadmin, each HTTP 200, with PowerShell absent from the native commands’ PATH. Both sessions and OS keys were removed afterward. This is bounded Graph evidence, not proof for every app/resource or live Windows/macOS authentication.

## Native encrypted maintenance backup

Version 0.34 runs research backup without PowerShell or an authentication profile:

~~~sh
tokenforge research backup --snapshot-path /private/maintenance.sealed --backup-directory /private/backups --json
~~~

The command copies ciphertext into a private directory under its SHA-256 content identity. Existing identical copies are reused; corrupt or conflicting files are never overwritten. Concurrent identical copies converge on one saved file. It rejects linked or broadly accessible paths, malformed envelope headers and oversized inputs. Output contains copy metadata and Authenticated=false: size, version and hash checks do not authenticate the encrypted payload. Keep the decryption key separately; account-bound authenticated restoration remains in the repository maintenance workflow. See [private maintenance](private-maintenance.md).

The [0.34 validation report](native-maintenance-backup-validation-2026-10-11.json) records native copies and deduplicated repeats of existing Nora and secadmin maintenance snapshots, plus bounded corruption, concurrency and private-path fixtures. The native child ran without PowerShell on its PATH. These copy proofs do not refresh metadata or authenticate the ciphertext.

## Native acquisition failure reasons

Version 0.35 keeps issued-token policy enforcement unchanged and distinguishes its failures in JSON. Use Code and Reason rather than parsing the suppressed diagnostic message.

| Code | Reason | Meaning |
| --- | --- | --- |
| TokenPolicyRejected | IdentityOrClientMismatch | The issued tenant, account, or client differs from the expected context. |
| TokenPolicyRejected | ScopeOrResourceMismatch | The audience or delegated scope claim does not satisfy the request. |
| TokenPolicyRejected | TokenLifetimeInsufficient | The token has unknown or insufficient remaining lifetime. |
| TokenPolicyRejected | AdditionalScopePolicyExceeded | Extra permissions exceed the plan's explicit allowance. |

Unknown failures retain ValidationFailed. Identity-service transport and authorization failure reasons remain separate. No raw exception, token, cookie, account identifier, or rejected claim is included in this diagnostic projection. An additional-scope rejection is a local policy decision after issuance, not evidence that Entra denied consent. Review scope observations and consider a narrower client before deliberately changing an allowance; the CLI never changes it automatically.

The [0.35 native policy diagnostic report](native-token-policy-validation-2026-10-11.json) records local rejection after actual Entra code redemption for both lab accounts. Neither proof returned tokens or changed consent.

## Browser profile login and acquisition

Version 0.36 runs `login --browser` directly in the executable. It requires an existing
profile and a private inventory within that profile's configured age limit. The bootstrap
client must be enabled, verified as Microsoft-owned, and publish a supported loopback
callback. The default cookie bootstrap client may not publish that callback; configure
an appropriate verified client explicitly when creating the profile. No client or scope
budget is changed automatically.

```sh
tokenforge login --browser --profile lab --prompt-passphrase --interactive --login-hint observer@example.test
tokenforge token get --profile lab --scope User.Read --prompt-passphrase --json
```

`--stdin` is an explicit alternative to the hidden passphrase prompt. Memory and OS-backed
profiles reject both passphrase options. OS-backed profiles use the existing Windows or
Linux key provider; macOS remains unsupported. `--timeout-seconds` accepts 30–900 seconds,
with 300 as the default. Login is silent unless `--interactive` is requested. Token get
always uses silent authorization; establish the browser session with explicit login first.
Consent is never automatically approved or retried.

Login validates the issued bootstrap context, confirms the principal through Graph `/me`,
binds the profile to that tenant/account, and resets this session's cached tokens. Persisted
sessions contain no browser cookie. Unrelated sessions are retained. Existing encrypted
vaults require their existing key; missing keys or held locks fail before authentication.
Token lifetime and session retention are checked again before saving. Memory login binds
configuration but does not persist a session across CLI processes; use persisted storage
for the cross-command workflow.

A fresh `token get` uses the system browser when the session has no cookie. `--browser`,
`--login-hint`, or `--timeout-seconds` explicitly select the browser for fresh acquisition.
Cache hits and same-client renewal keep their normal paths and do not launch a browser.
An existing saved cookie is not removed by selecting browser acquisition; explicit login
resets the session without a cookie. Cold acquisition checkpoints sanitized scope evidence
before its separate credential commit; warm acquisition confirms identity before requesting
the selected scopes. Neither path expands the configured additional-scope budget.

Vault and profile replacement are separate writes under the shared operation lock. A disk
failure after the vault commit can leave the profile configuration unchanged; the command
fails and same-account login can recover. There is no cross-file rollback journal. CLI output
contains metadata only; browser cookies remain in the browser, and credentials are encrypted
only in the opted-in vault. JWT claims inspection does not validate the signature.

The [sanitized v0.36 validation report](native-profile-browser-validation-2026-10-11.json)
records Linux cold/warm/cache and Graph identity proofs for both lab accounts. The headless
proof kept the passkey-derived cookie in its PowerShell driver and sent only authorization
URLs and completion signals over a private Unix socket; it did not exercise browser UI.
The inventory observation date was preserved under an explicit 168-hour lab age limit.


## Native software-passkey profile login

With a private local software passkey file, explicit login can establish an encrypted
saved ESTS session without PowerShell in the native process:

```text
tokenforge login --profile lab --passkey-file /private/Test.json --prompt-passphrase
```

Use `--stdin` instead of the hidden prompt for explicit redirected passphrase input.
Windows Credential Manager and Linux Secret Service profiles require neither flag.
Memory profiles authenticate and bind identity, but save no cookie or token across processes.
First-passkey TAP enrollment remains external. Login without the explicit `--passkey-file` option retains its
PowerShell adapters. Browser-only login options cannot accompany this option.

The native signer authenticates to the fixed Microsoft public-cloud authority. The resulting
ESTS cookie stays in an owned, temporary session while PKCE requests the configured Graph
bootstrap token. Token policy and Graph `/me` must confirm the tenant and principal before
cookie persistence. The commit rechecks token lifetime, retention, profile revision and
ciphertext. Persisted profiles encrypt the cookie in their opted-in vault; `CookieSaved`
reports success only after both local writes complete. Subsequent native `token get` commands
can use that saved cookie, cache or same-client renewal. Login resets this session's token
cache and preserves unrelated sessions.

This is software emulation of a passkey, without hardware user-presence guarantees.
Protect the private key file separately from the encrypted session vault. Existing
additional-scope limits apply unchanged; requesting User.Read can still produce extra scopes.
Use explicit policy limits appropriate to the application and inspect the resulting metadata.


The [sanitized v0.38 live report](native-profile-passkey-validation-2026-10-13.json)
records both lab accounts on Linux using passphrase-protected profiles. Login persisted
an encrypted cookie; fresh and cached native acquisition returned Graph HTTP 200, and a
separate identity read matched the expected user. Logout succeeded and owned private
state was removed. The original key files remained unchanged. The proof explicitly used
an additional-scope budget of 128 and preserved the original inventory observation under
a 168-hour lab age limit. It is not live Windows/macOS or OS-vault authentication evidence.


## Native Memory profile acquisition

A Memory profile can request tokens with an explicit software key in each native CLI process:

```text
tokenforge login --profile lab --passkey-file /private/credentials/Test.json
tokenforge token get --profile lab --scope User.Read --passkey-file /private/credentials/Test.json --api-uri https://graph.microsoft.com/v1.0/me
```

Create the profile with `profile create --storage Memory`, configure its private inventory,
bootstrap client and scope budgets, then log in to bind the tenant and principal. Each
`token get` above authenticates freshly and confirms that account through Graph before
requesting a candidate token. The first request checkpoints sanitized scope metadata;
a later request can use that observation for planning and still obtains a fresh token.
Memory mode stores no credential vault, cookie or token across commands. Profile policy
and identity fingerprints, inventory and sanitized scope observations remain private files.

`--passkey-file` on `token get` selects this explicit Memory route. It cannot accompany
browser options or vault passphrase flags. Persisted profiles use `login --passkey-file`
followed by ordinary `token get`; their existing cache and renewal paths are unchanged.
Memory acquisition without this explicit option retains its PowerShell adapter.

The service validates the identity-bound profile and metadata before opening the key.
The operation lock protects acquisition; configuration and token lifetime are checked
again before returning an owned result. Core results hold secure strings in process;
the CLI emits metadata and the optional bounded API-check status. Owned sessions and
credentials are disposed. Managed strings and library internals do not guarantee immediate
erasure. Existing additional-scope limits apply, with no automatic consent approval.

The [sanitized v0.39 report](native-memory-passkey-validation-2026-10-13.json) records Linux
proofs for both lab accounts: native login, cold and warm acquisition, Graph HTTP 200,
no vault creation, logout and removal of owned private state. The independent baseline
matched the expected username through Graph; native login and each acquisition matched
the principal against the profile. Both policy budgets were explicitly 128, and the original
inventory date was preserved under a 168-hour lab limit. No Windows/macOS live account
validation or general API authorization is claimed.


## On-demand native account validation

The [native lab authentication workflow](native-authentication-validation.md) uses existing
Nora repository secrets to exercise Memory and Passphrase profiles on all six packages.
It publishes only sanitized reports after private-state cleanup. The [completed hosted proof](native-authentication-hosted-validation-2026-10-13.json)
verified Nora on all six targets with 24 native Graph HTTP 200 checks. Offline core/package
checks and the separate two-account Linux proof remain distinct evidence.

Native `passkey enroll` enrolls another software credential for the confirmed account. See
[lab software-passkey enrollment](native-passkey-enrollment.md) for recovery files, companion
receipts, parameters and the boundary between software and hardware authentication.
