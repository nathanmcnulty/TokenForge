# Goal 3: four supported administrator workflows

Implementation starts from reviewed Goal 2 receipt `90528b0d3d5e446f1c6faed03085fa2b715574c5`, shared engine `08fb8e4a41c307b858476d877aa922c611a54683`, and roadmap handoff `19470aeba7a949e4204e4ecf5586a6ffb3171c69`. This is an implementation contract, not an acceptance receipt.

## Reconciliation and boundaries

The independent public lookup #118 is pinned at `2153779f7a1d5748dc14046f9d60f3ce2fa18837`; anonymous public `git ls-remote` confirmed that pull-request head and main `1be12d75c7e2a63eac8e14c32d54e79cec4a23ef`. Its branch is not an ancestor of this implementation. The draft adds `Find-TokenForgeApplicationEvidence` over public ledger and anonymous exports and accepts an explicit resource GUID in native scope explain. Its useful contracts are full public-history validation, separate source/anonymous rows, same-resource/all-scopes matching, source provenance/conflicts, and freshness as source age. Those facts never establish private current authorization or comparable request changes. No draft is merged or cherry-picked automatically. Goal 3 reuses these semantics in its shared explicit evidence explanation; public lookup remains one input rather than proof that a tool works.

Existing `ScopePlanning` is a metadata suggestion adapter. Its client/resource latest-row grouping does not establish exact Goal 2 request comparability. Existing profile/scoped-token candidate loops continue after errors, and the legacy scoped-token ceilings are unrestricted by default. Compatibility behavior must remain explicit. The new strict workflow selects exactly one approved concrete client/callback before dispatch, verifies current identity, applies independent zero-default bootstrap/final additional-API-scope ceilings, and stops after any failure. It must not retry a different callback/client, substitute stronger scopes, acquire an interactive session, or display credentials.

## Required deliverables and gates

1. Explain one manifest tool's exact resource/scopes with client constraints, published callbacks, source claims/conflicts, fresh or stale private evidence, visible configured grants, observed breadth, prerequisites and excluded alternatives. Unknown is an explicit result.
2. Execute a separately opted-in strict credential-free profile with an explicitly supplied existing session. Select one approved request, use only implemented silent PKCE, confirm current tenant/principal/client/resource/scopes/lifetime and bootstrap identity, show actual additional API scopes, optionally check one declared harmless GET, and return only sanitized result metadata. Counting fewer scope strings is not a privilege comparison.
3. Validate a strict versioned tool manifest containing named tools, clients, resource/scopes, protocol/callback class, optional operation checks and role/license prerequisites. Return `VerifiedWorking`, `AtRisk`, `NeedsObservation` or `Blocked` from matching evidence. Arbitrary script text is never a source of inferred requirements.
4. Recompute typed Goal 2 changes from validated before/after snapshots, map them to named tools, and prepare a bounded reproducible packet for human review. Private/security-sensitive details take a private-disclosure route. Packet preparation never sends, opens an issue, publishes or initiates communication.

Shared .NET logic owns schema, policy, explanation, tool health and packet behavior. Native/PowerShell consumers must agree on JSON and exit codes. Synthetic end-to-end examples must cover success, no silent route, excessive scopes, issuance followed by API denial, incomplete evidence and typed regression. Complete inputs validate before selection. Unknown fields, credential-bearing input, ambiguous history, namespace mismatch, unsafe paths, stale evidence and incompatible source data fail closed or remain explicitly unknown as appropriate.

Local Linux x64 only, Pester 6.2.0, independently reviewed local commits, and a matching complete package are required. No live service proof, authentication, tenant permission changes, Actions, remote publication, PR or merge is authorized. Stop before Goal 4. Offline acceptance will have its own requirement audit and exact source/package receipt.

## Use the shared contracts

The [example requirements](examples/admin-tool-requirements.json) use a synthetic client GUID. Replace it with a separately reviewed approved client; the example is not an authorization recommendation. A manifest declares requirements, not consent. Prerequisites are explicit role/license observations with account fingerprints, date and source digest; missing, stale or conflicting observations remain unknown. No arbitrary script inspection occurs.

PowerShell accepts complete in-memory metadata objects:

```powershell
# These variables are reviewed metadata, not secrets or session state.
$profile = New-TokenForgeStrictProfile -TenantId $tenantId `
  -PrincipalFingerprint $principalFingerprint -BootstrapClientId $bootstrapClientId `
  -ApprovedClientId @($bootstrapClientId, $toolClientId)
$explanation = Get-TokenForgeToolExplanation -Profile $profile -Requirements $requirements `
  -Inventory $inventory -Snapshot $snapshot -ToolId read-profile
$health = Test-TokenForgeTool -Profile $profile -Requirements $requirements `
  -Inventory $inventory -Snapshot $snapshot -ToolId read-profile
# Preserve the exact AsOf when reproducing either result.
```

Use explicit files protected by the account's private directory for the native consumers. File ingress refuses links, broad Unix permissions, duplicate JSON fields, oversized documents and credential-bearing metadata; it never discovers sibling sessions or initializes a store. Files must already exist. No command below authenticates:

```sh
tokenforge admin explain --profile-path profile.json --requirements-path requirements.json --inventory-path inventory.json --snapshot-path snapshot.json --tool read-profile --json
tokenforge admin check --profile-path profile.json --requirements-path requirements.json --inventory-path inventory.json --snapshot-path snapshot.json --tool read-profile --json
tokenforge admin evidence --acquisition-path saved-acquisition.json --json
tokenforge admin packet --requirements-path requirements.json --before-path before.json --after-path after.json --source-revision SOURCE_COMMIT --package-sha256 PACKAGE_MANIFEST_SHA256 --json
```

Health/explanation exit codes are `0` verified working in its dated exact context, `2` at risk, `3` needs observation, `4` blocked. Invalid input produces safe stderr JSON and exit `1`. A prepared packet exits `0` and retains typed uncertainty; that does not confirm a regression. Packet pins are caller-supplied and must be independently checked against the package/source receipt. Maximum retention is 128 entries and 1 MiB; omitted counts are explicit. It sends nothing. A private packet can still contain sensitive tenant/client/request metadata and is not a public export. Review its contents and disclosure route before separately authorizing any communication.

## Strict acquisition boundary

`TokenForgeStrictProfile` is a separate format. Legacy `TokenForgeProfile`, cached token, refresh, interactive sign-in and retry loops cannot consume this profile or supply its acquisition path. Existing compatibility behavior keeps its existing policy. Both bootstrap and final clients must be explicitly approved; independent additional-API-scope ceilings default to zero. `MaxSeconds` is one cooperative deadline for bootstrap issuance, identity check, final issuance and optional API proof; each existing transport also has its bounded timeout. It is not a hard process cutoff.

Only an already supplied session and OAuth 2.0 v2 PKCE with a supported published native/SPA callback are implemented here. Unsupported protocols or callback classes stop with a reason. Native URI suggestions do not prove platform support. A decline stops the single selected client/callback route; there is no alternate-client, callback, scope or interactive fallback. The bootstrap requests Graph `User.Read` and confirms current identity with `/me?$select=id`; see [Microsoft's delegated user-get contract](https://learn.microsoft.com/en-us/graph/api/user-get?view=graph-rest-1.0) and [PKCE/redirect documentation](https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth2-auth-code-flow).

`Invoke-TokenForgeStrictAcquisition` requires an explicitly supplied `SecureString` session. `tokenforge admin acquire` without `--cookie-stdin` performs metadata preflight and reports that an existing session is required, making zero requests. The explicit stdin option permits one supplied session only after metadata/route/prerequisite validation. Neither facade creates or renews a session, prints credentials, persists credentials or launches the named tool. Their outputs are metadata only; both dispose tokens after the attempt.

Trusted in-process integrations can use `AdminWorkflows.Acquire` and its disposable result's `Credential` directly, within a `using` block. They must not serialize credentials, hand them to arbitrary script text, or retain them beyond the operation. The JSON serializer excludes the credential; `ToJson()` is the supported receipt. `ConvertTo-TokenForgeToolEvidence` / native `admin evidence` converts that validated receipt into Goal 2 snapshots for saved tool-health checks. Every present receipt field and state invariant validates before projection. Hashes bind metadata context and reproducibility; they are not a signature or independent attestation of an untrusted supplied receipt.

The only optional operation is manifest-declared `GraphMeV1`, separately selected with `-OperationCheck` / `--operation-check`: fixed Graph v1.0 `GET /me?$select=id`, no redirect. Issuance remains distinct from API acceptance; a 403 discards the credential while preserving successful issuance metadata, and an unobserved response remains unknown. No JWT signature validation is claimed. Scope ceilings show actual additional names and response-reported extra counts; fewer scope strings do not establish lower privilege. Evidence must remain fresh at completion before returning an owned credential.

## Executable offline examples

`tests/AdminWorkflows.Tests.ps1` is the synthetic end-to-end recipe: it supplies explicit fake transports and identity/API delegates, never a real session. It exercises issuance-to-snapshot-to-health success; missing/unsupported silent routes; independent bootstrap/final/response scope ceilings; issuance with API 403; absent/ambiguous/stale evidence and prerequisites; deadlines and expiry; typed changes and lost visibility mapped to a bounded private packet. Public hints retain conflicts and source age; anonymous breadth stays separate from private authorization. `tests/NativeAdminWorkflows.Tests.ps1` uses private fixture files and an actual matching Linux executable to compare JSON and exit statuses to PowerShell with no PowerShell on its child PATH. Native acquisition fixtures never supply a cookie or invoke the network.

Run the focused offline gate in a fresh process:

```powershell
pwsh -NoProfile -File ./scripts/Invoke-TokenForgeLocalValidation.ps1 `
  -Preset Admin -NativeExecutable /path/to/verified/linux-x64/tokenforge
```

This milestone has no live service proof. Any future live canary needs separate approval for the exact account, client/callback, resource/scopes, existing-session handling, proof operation and finite request/time budget. Authentication, tenant permission changes and communications are outside the offline acceptance.
