# Native application direction

Use one shared .NET core with platform adapters, a CLI first, and a metadata-only visualization
surface later. Do not maintain separate OAuth policy implementations for each operating system.
The PowerShell workflow is the compatibility surface while code moves into the shared core. Shared timestamp projection and profile configuration and decrypted credential-record validation, private-file checks, vault-file transactions, issued-token policy, OAuth transport, vault envelope encryption, SQLite evidence import/export and checkpoints, and native CLI packages are implemented. Scope explanation, profile create/show, vault inspection, logout, OS-key forgetting, and direct token acquisition run natively; persisted-profile cache selection, same-client renewal, and credential writes also run in the shared native core. Saved-cookie persisted-profile acquisition and CLI token get now run natively, using shared request planning, Graph bootstrap confirmation and bounded candidate execution. Browser/passkey login, Memory sessions and browser/interactive adapters still use PowerShell. Coverage and candidate ranking use the shared native planner. See [Native CLI](native-cli.md) for current dependencies.

The security boundary is a credential service that exposes scoped acquisition operations and
metadata, not a general cookie jar export. Windows Credential Manager and Linux Secret Service adapters now protect a random vault password
key; encrypted credential records remain account-, tenant-, and client-bound. The modern macOS Keychain adapter remains deferred until signed helper packaging. See [OS-backed vault](os-backed-vault.md). Require explicit
passphrase storage when an OS store is unavailable; never silently fall back to plaintext.
OS stores protect credentials at rest but do not isolate every process running as the user.

The module loads one BCL-only .NET 8 credential assembly in process. Source checkouts compile
the same explicit sources together; distributed packages contain the prebuilt assembly. This
keeps SecureString handoff inside the caller and avoids coupling credential operations to SQLite.
A loaded incompatible runtime requires a fresh PowerShell process. The shared BCL scope planner
also supplies coverage and candidate ranking to both the module and native `scopes explain`;
SQLite history is read by the evidence core and passed as metadata.

Keep three interfaces small:

- `ICredentialStore`: load/store/delete versioned encrypted records and platform key handles.
- `IEvidenceStore`: transactional observations, sources, dates, request context, and checkpoints.
- `ITokenAcquirer`: explicit acquisition/renewal with policy and cancellation; no raw-secret logs.

SQLite now supports primary application-ledger updates, individual flow checkpoints, and individual scope/registration checkpoints. JSON remains the portable compatibility format; profiles and inventory runners use an existing migrated SQLite scope store. It provides a private evidence store with indices on namespace, resource, client,
and observation time. Keep JSON as deterministic import/export and the public application catalog
format. Freeze each discovery plan's membership, hash, and chunk assignments; resume from explicit
terminal checkpoints. Version 0.16 connects those frozen [research cohorts](research-cohorts.md) to chunk execution and metadata repair. Failed probes do not erase the previous successful evidence's date.

Build self-contained .NET executables per OS and architecture. Evaluate Native AOT after the
browser, interop, storage, and PowerShell handoff paths pass integration tests; self-contained
publishing and Native AOT are different milestones. A native launcher alone does not remove the
PowerShell dependency or create an OS credential boundary.

Before making native storage the default, verify unlock/lock behavior, cancellation, rotation,
permissions, damaged records, deletion races, and uninstall cleanup on each OS. Linux headless
systems need a deliberate passphrase option. Windows/macOS authentication still needs live
platform validation; cross-platform offline tests alone do not establish those behaviors.

A teaching GUI should consume a sanitized metadata API: token type, audience, scope set, expiry,
client, provenance, and flow stages. Raw tokens, refresh credentials, cookies, passkeys, and
identity claims should stay outside that API. Opening a visualization should never authenticate,
renew, request consent, or register an application.

### Shared explicit request planning

The shared credential assembly now builds the explicit request slots used by PowerShell
fresh acquisition. Warm planning uses fresh, matched scope observations, orders clients by
missing/extra scope coverage, and prioritizes the previously observed published redirect.
Other warm redirects use ordinal ordering. Cookie requests may use published HTTPS,
localhost HTTP, or URN callbacks; browser requests require a clean localhost root callback.
SPA is retained only for warm nonbrowser HTTPS requests.

Cold planning uses eligible published/configured hints, not a consent claim. Cookie requests
require the exact canonical Microsoft nativeclient redirect. Browser requests use clean
localhost root callbacks. Cold callback selection preserves inventory order, removing exact
duplicates. Only clients with a usable callback consume the candidate budget, and both client
and callback counts are bounded. Every emitted request is explicit OAuth v2 PKCE and is
validated by the shared transport before it reaches execution.

Scope names are case-sensitive. `User.Read` and `user.read` remain separate requested scopes;
exact duplicates are removed. This corrects the earlier PowerShell request builder's
case-insensitive deduplication. Neither planning nor a metadata fingerprint confirms the
current account. Version 0.31 moves saved-cookie profile bootstrap confirmation, fresh request execution,
issued-context checks and successful observation creation into the shared native acquisition service.
PowerShell retains the browser execution adapter. Each attempted request
rechecks inventory and, for warm requests, observation freshness. Native saved-cookie profile
execution is implemented; native browser/passkey login remains unfinished.

The [v0.30 validation report](native-request-planning-validation-2026-10-11.json) records the sanitized two-account cold/warm acquisition proof and checks.

The [v0.31 validation report](native-fresh-acquisition-validation-2026-10-11.json) records native saved-cookie cold/warm/cache/renewal proofs. Metadata checkpoints precede the separate final credential commit and may remain when that later commit fails. See [native CLI](native-cli.md#native-saved-cookie-profile-acquisition) for the supported storage modes and remaining adapters.
