# SQLite flow evidence

Version 0.13 adds a private SQLite backend for flow plans and individual attempts. It stores diagnostic metadata, never cookies, access tokens, refresh tokens, passkeys, or assertions. Authentication still uses the packaged PowerShell module. The native executable handles SQLite directly on Windows, macOS, and Linux.

## Use it

Choose a private assessment directory outside Git. Keep the complete native package together. From PowerShell:

```powershell
# Import an existing strict flows.json file; repeated imports are idempotent.
Import-TokenForgeFlowEvidence -Path "$state/flows.sqlite" `
  -InputPath "$state/flows.json" -NativeExecutablePath $native

Invoke-TokenForgeScopeProbe -Inventory $inventory -EstsAuth $cookie `
  -ResourceId 00000003-0000-0000-c000-000000000000 `
  -PrincipalFingerprint $principal -DatabasePath "$state/scopes.json" `
  -FlowDatabasePath "$state/flows.sqlite" -NativeExecutablePath $native `
  -MaxApplications 10 -MaxRedirects 1 -ExploreAllFlows

Get-TokenForgeResearchCoverage -MetadataPath "$state/applications.json" `
  -FlowPath "$state/flows.sqlite" -NativeExecutablePath $native `
  -TenantFingerprint $tenant -PrincipalFingerprint $principal -SummaryOnly
```

The inventory script accepts `-FlowPath` and `-NativeExecutablePath`. Its probe metadata update merges the current plans and committed attempts, including previously completed plans encountered on resume. It does not replay the complete SQLite history. Direct module users can merge a selected plan document using `Update-TokenForgeApplicationMetadata -Kind FlowAttempts`.

Native packages automatically locate their executable. Source-checkout PowerShell calls require an explicit executable path. JSON remains the default for existing scripts; selecting a `.sqlite` flow path opts into this backend. The simple/native research CLI prefers `flows.sqlite` when present, and accepts an explicit `--flow-path`.

```sh
tokenforge flows import --database /private/lab/flows.sqlite --input /private/lab/flows.json
tokenforge flows export --database /private/lab/flows.sqlite --tenant TENANT_HASH --principal ACCOUNT_HASH --latest
tokenforge flows export --database /private/lab/flows.sqlite --plan PLAN_HASH --latest
tokenforge research report --state-path /private/lab --tenant-fingerprint TENANT_HASH --principal-fingerprint ACCOUNT_HASH --summary-only --json
```

Private exports contain correlation fingerprints and callback hashes. Protect stdout when redirecting it. To share results use `Export-TokenForgeFlowEvidence`, or `research export-flows`, which emits only successful anonymous application/resource IDs, protocols, SPA flags, and scopes. The module export accepts tenant/principal selectors and `-Latest`; the simple CLI accepts namespace selectors. Historical success is an observation, not a current authorization guarantee.

## Checkpoints and validation

Each plan and attempt is written individually in a transaction. `Started` is saved before requesting a token. The same attempt may transition once to a terminal result; terminal records cannot be rewritten. A retry creates a new attempt ID. Resume reads only the exact plan and latest attempt per slot. A newer interrupted attempt supersedes an older terminal result. Reconstructing a missing scope summary can emit an observation without requesting another token.

Legacy plan hashes and the strict JSON schema remain compatible. Imports validate every row within one transaction and roll back on malformed data. A repeated equivalent import adds no attempts. Selected exports validate payloads against indexed context, dates, slots, and IDs. A foreign SQLite database is rejected. Namespace filters require both tenant and account fingerprints.

SQLite preserves history without rewriting it on every checkpoint. Selected-account reports fetch latest slot evidence; reports without account selection do not read flows. Exports are capped at 128 MiB before materializing the complete selected payload, so large histories require a namespace or plan selection. Very large numbers of distinct plans in one account may still need partitioning. The application ledger and scope summaries remain bounded JSON files; this release does not make those files indefinitely scalable.

## Storage security

The SQLite file is unencrypted diagnostic metadata. It uses a protected current-user ACL on Windows, or mode 0600 under a mode 0700 directory on Unix. Linked paths are rejected. WAL and SHM files reside inside the private directory. The adapter uses argument lists and private temporary metadata files; it removes those files after success, failure, or timeout and suppresses child-process error details. These protections do not defend against other code already running as the same user. Use disk encryption for confidential research state.

## Additional inventory fields

Tenant inventory now distinguishes published names from verified tenant display names and records service-principal type, preferred SSO mode, homepage, login/logout URLs, delegated scope IDs, and consent labels/descriptions. These are metadata from the [servicePrincipal schema](https://learn.microsoft.com/en-us/graph/api/resources/serviceprincipal?view=graph-rest-1.0), not credential material.

Sign-in summaries additionally count allowed authentication methods, incoming token types, and client credential types. Unknown values become `Unknown`; no raw authentication detail, principal identity, IP, device, or failure text is retained. A service principal's preferred SSO mode and observed sign-in methods provide evidence about usage, not a proof of the only authentication flow it requires.

## Validation

The [sanitized lab report](sqlite-flow-validation-2026-10-06.json) records both accounts, legacy migration, fresh SQLite checkpoints, exact-plan resumes with zero new token requests, and strict JSON round trips. Both accounts have 12 terminal slots across four clients and three protocols; Nora has three successful slots and secadmin four. Secadmin sign-in summaries include incoming-token and credential-type counts for 209 applications; authentication method arrays were absent or empty in this sample. Nora cannot read these logs (HTTP 403). No consent was granted or token persisted. Offline verification passed 247 PowerShell tests (two platform-specific skips), 57 native checks, and independent Sol review. Live testing ran on Linux; cross-platform CI verifies synthetic flow behavior separately.
