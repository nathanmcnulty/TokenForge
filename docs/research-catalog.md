# Application research catalog

TokenForge tracks application IDs across public datasets, tenant inventory, sign-ins, registration attempts, and token probes. `applications.json` is the portable metadata ledger; version 0.14 adds a [primary SQLite application catalog](sqlite-application-catalog.md) for private maintenance. It records supported attributes, source, observation dates, and changes. This ledger is diagnostic: registration and token acquisition still require independently verified tenant metadata.

## The research loop

1. **Discover** refreshes published Microsoft application hints. An ID or a sign-in does not establish Microsoft ownership.
2. **Inventory** checks service principals against Microsoft owner organizations. It records availability, enabled/assignment flags, callbacks, client hints, scope definitions, and resource identifiers.
3. **SignIns** reads a selected window, extracts client IDs, and aggregates protocol, client type, event type, resource GUID, authentication method, credential type, incoming token type, and success/failure counts. It saves no individual sign-in events, account names, IP addresses, device details, or failure text. Newly seen IDs remain unverified candidates.
4. **Register** creates selected missing service principals, verifies ownership, and checkpoints each result before continuing. This does not grant consent. Resolving published or sign-in candidates requires the corresponding explicit option. Unexpected ownership triggers existing rollback/cleanup handling. HTTP 401/403 is recorded before stopping the invocation.
5. **Probe** asks Entra what it issues using the current account's existing session and consent. Its default behavior stops after the first token issuance for each client/resource pair. `-ExploreAllFlows` exercises every selected callback/protocol/SPA cell. It does not handle consent or policy interaction.
6. **Report** categorizes collected evidence and counts tested, successful, failed, interrupted, and untested cells. **ExportFlows** produces an explicit anonymous projection of matched successful observations.

The three implemented probe protocols are authorization code with PKCE, OAuth v2 implicit, and OAuth v1 implicit. Published broker callbacks are hints; TokenForge does not actively test broker/PRT, device code, password, SAML, or application-only flows in this matrix. Sign-in protocols may provide independent evidence about these other modes. The collector requests expanded enum members: newer logs can distinguish authorization code with/without PKCE, implicit modes, broker grants, and other protocols. A generic `oAuth2` value alone cannot make that distinction. See Microsoft's [signIn schema](https://learn.microsoft.com/graph/api/resources/signIn?view=graph-rest-beta).

## Run a bounded exhaustive batch

In a dedicated PowerShell session, supply the existing secure cookie and verified inventory. Start with a small selection; exhaustive probing can make many requests.

```powershell
# $cookie is a SecureString; $principal is the fingerprint of the account being tested.
./scripts/Invoke-TokenForgeInventory.ps1 -Action Probe -StatePath $state `
  -EstsAuth $cookie -PrincipalFingerprint $principal -GraphOnly `
  -ClientId $selectedIds -MaxApplications 10 -MaxRedirects 2 -ExploreAllFlows

./scripts/Invoke-TokenForgeInventory.ps1 -Action Report -StatePath $state `
  -PrincipalFingerprint $principal -SummaryOnly

./scripts/Invoke-TokenForgeInventory.ps1 -Action ExportFlows -StatePath $state `
  -ExportPath ./anonymous-flows.json
```

The simpler CLI supports offline visualization inputs:

```text
tokenforge research report --profile lab --summary-only --json
tokenforge research report --state-path /private/assessment --json
tokenforge research report --state-path /private/assessment --tenant-fingerprint <tenant-hash> --principal-fingerprint <account-hash> --summary-only --json
tokenforge research export-flows --state-path /private/assessment --export-path ./anonymous-flows.json --json
```

A logged-in profile selects its bound account for coverage. A bare state-path report shows catalog categories without selecting account-specific flow coverage. Use `--tenant-fingerprint` and `--principal-fingerprint`, the inventory CLI's `-PrincipalFingerprint`, or the module's explicit tenant/principal parameters to select coverage. Reports do not authenticate or modify the tenant.

## How checkpointing works

`flows.json` stores plans and individual attempts separately from the compatible `scopes.json` database. Direct module probes default to `<DatabasePath>.flows.json`; the inventory CLI uses `<StatePath>/flows.json`. Pass `-FlowDatabasePath` to select the module path.

A plan fingerprint binds tenant, principal, client, resource, authority, catalog hash, eligibility, verified resource aliases, and the ordered callback/protocol/SPA matrix. Callback URLs are represented by hashes. Each attempt is checkpointed as `Started` before issuance, then as a terminal outcome after issuance or failure. Only numeric Entra error codes survive. A newer interrupted retry supersedes an older terminal result for resume decisions. A changed plan is independently exercised; `-Refresh` deliberately repeats its cells. An account/client/resource mismatch halts the whole invocation.

Rerunning an exact completed plan makes no new token requests. Missing scope summaries can be reconstructed from the plan's terminal evidence after a crash. If catalog merging fails, the primary checkpoint survives: rerun to import it. Neither file is a credential store. Every acquired token is disposed after extracting allowed metadata.

`applications.json` records flow slots independently by plan/attempt key and preserves changes. Registration records retain state transitions and first/last observation dates; repeated identical results coalesce there. Every registration event remains in `scopes.json`'s `RegistrationAttempts`. Older scope databases can be imported with `Update-TokenForgeApplicationMetadata -Kind RegistrationAttempts`; `Merge` now imports registration history too.

## Interpret the categories carefully

- **PublishedFlowHints** describes callback shapes, without asserting a required flow.
- **RoleHint** is inferred from published client/resource attributes, and may be unknown.
- **FlowCoverage** counts only the latest plan for each resource in the explicitly selected account context. Older plans remain available in the raw evidence file.
- **Succeeded** requires readable delegated scopes and matching namespace/client/resource claims. Claims are diagnostic and signatures are not validated by this probe. API acceptance is a separate check.
- **Failed** means the exact tested request failed in that context. Consent, assignment, policy, disabled apps, unsupported callbacks, and session state can all affect the result. It does not prove universal lack of support or which flow is required.
- **Untested** and **Started** remain distinct from failures. First-success runs leave alternatives untested.

## Privacy and scale

Flow evidence paths enforce private permissions and reject links. On Unix use a mode-0700 parent and mode-0600 files; Windows uses the existing private-path ACL checks. Local application metadata contains private correlation fingerprints and is unencrypted. Keep assessment directories outside Git and encrypted at rest as appropriate. Public-only catalog validation rejects all tenant, sign-in, registration, scope, and flow origins, including history. The anonymous flow export includes only public application/resource IDs, protocol, SPA flag, and observed scopes, without namespaces, plan IDs, callback hashes, or timestamps.

JSON files have a 128 MiB limit and use locked atomic writes. Version 0.13 adds opt-in [SQLite flow checkpointing](sqlite-flow-evidence.md): individual transactional writes, current-plan resume reads, selected-account latest-slot reports, and bounded metadata updates. The application ledger can now use transactional SQLite updates and current-only reads. Version 0.15 adds [primary SQLite scope/registration checkpoints](sqlite-scope-history.md), selected current reads, and resume metadata repair. Portable scope JSON remains bounded to 64 MiB; partition oversized exports. The public scheduled workflow remains bounded first-success sampling and publishes only its existing anonymous scope schema; it does not register applications or collect private sign-ins.

## Validation on 2026-10-06

The [sanitized live report](research-catalog-validation-2026-10-06.json) records Nora and secadmin runs against the lab tenant. Each inventory contained 5,522 rows, representing 5,521 nonempty unique application IDs; empty placeholders are excluded from the ledger. Four registered Microsoft clients were tested for Graph with one callback each and all three implemented protocols: 12 terminal cells per account, seven matched successes and 17 failures overall. Both final exact-plan resumes returned zero observations and left attempt counts and flow files unchanged. Tokens/cookies were kept in memory and disposed; only private diagnostic metadata was saved.

Secadmin's 24-hour sign-in scan found 205 client IDs, 13 absent from inventory. Nora's sign-in and registration calls returned HTTP 403. A single selected published missing registration candidate returned HTTP 400 for secadmin; both registration outcomes were linked into the metadata catalog. This run demonstrates failure checkpointing, not successful service-principal creation. Registration creation/ownership/rollback paths also have offline tests. This is a bounded sample, not an exhaustive verification of every catalog ID or authentication flow.
