# Native application direction

Use one shared .NET core with platform adapters, a CLI first, and a metadata-only visualization
surface later. Do not maintain separate OAuth policy implementations for each operating system.
The PowerShell workflow is the compatibility surface while code moves into the shared core. The first extraction is implemented: shared issued-token policy, SQLite evidence import/export and checkpoints, and native CLI packages. See [Native CLI](native-cli.md) for current dependencies.

The security boundary is a credential service that exposes scoped acquisition operations and
metadata, not a general cookie jar export. Windows Credential Manager and Linux Secret Service adapters now protect a random vault password
key; encrypted credential records remain account-, tenant-, and client-bound. The modern macOS Keychain adapter remains deferred until signed helper packaging. See [OS-backed vault](os-backed-vault.md). Require explicit
passphrase storage when an OS store is unavailable; never silently fall back to plaintext.
OS stores protect credentials at rest but do not isolate every process running as the user.

Keep three interfaces small:

- `ICredentialStore`: load/store/delete versioned encrypted records and platform key handles.
- `IEvidenceStore`: transactional observations, sources, dates, request context, and checkpoints.
- `ITokenAcquirer`: explicit acquisition/renewal with policy and cancellation; no raw-secret logs.

The optional SQLite workspace is implemented; integrating it as the primary discovery store is a separate migration. It provides a private evidence store with indices on namespace, resource, client,
and observation time. Keep JSON as deterministic import/export and the public application catalog
format. Freeze each discovery plan's membership, hash, and chunk assignments; resume from explicit
terminal checkpoints. Failed probes do not erase the previous successful evidence's date.

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
