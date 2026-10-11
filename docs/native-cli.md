# Native CLI and evidence store

The native CLI is a self-contained .NET executable per OS and architecture. Evidence commands
run directly in the shared core with bundled SQLite. Profile login and `token get` currently invoke the packaged PowerShell 7.4+ module;
install `pwsh` and keep `src/` and `scripts/` beside the executable for those commands.
Version 0.18 adds direct native `token acquire`, and PowerShell uses the same C# OAuth transport
and issued-token policy. Native acquisition does not itself provide browser/passkey login or a keystore.
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

Inspection uses both operation and vault locks, validates decrypted records, and clears its owned plaintext buffer. Metadata reports stored lifetime and scope observations, not new issuance or API authorization. The underlying record validator can allocate managed strings; this is not a guarantee of immediate erasure of every in-memory copy. Normal login and `token get` still use PowerShell.

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

## Direct native acquisition

`token acquire` is an advanced validation and teaching command. Give it an explicit request
and the expected account context, then supply an existing ESTSAUTH cookie or refresh token.
It runs entirely inside the native executable. It returns policy-checked metadata, disposes
the acquired tokens, and saves no credentials. Use `token get` and the module API for the
existing profile and Graph PowerShell workflows.

```sh
tokenforge token acquire --plan /private/native/request.json --credential cookie
tokenforge token acquire --plan /private/native/request.json --credential refresh
```

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

`tokenforge research backup --snapshot-path <maintenance.sealed> --backup-directory <private-directory> --json` saves an immutable ciphertext copy without loading an authentication profile. It requires the bundled PowerShell adapter and reports byte identity separately from authentication. See [private maintenance](private-maintenance.md) for key custody and restoration.

## Inspect weekly progress offline

Use a local checkout of the public `discovery-data` branch:

```text
tokenforge research weekly --state-path /path/to/discovery-data
tokenforge research weekly --state-path /path/to/discovery-data --json
```

The PowerShell entry point is `./scripts/tokenforge.ps1 research weekly -StatePath /path/to/discovery-data -Json`. No profile or login is required. The command reads the two frozen weekly recipe files, validates their hashes and coverage, and recomputes reports rather than relying on cached report files. It writes no files. Unrelated checkout files are not inspected or endorsed by this command.

Reports distinguish source catalog, selected applications, successful applications, and app/resource pairs. They include remaining applications/pairs, pending/exhausted batches, observation dates, and next-step guidance. An older recipe is marked `CurrentWeek=false`; refresh the checkout and inspect scheduling before assuming the current week has run. Future-week recipes and creation times more than five minutes ahead are rejected. Assessment includes structural exclusions, and successful token observations do not establish universal support or API authorization. The packaged native command uses its PowerShell adapter, so PowerShell 7.4+ is required.
