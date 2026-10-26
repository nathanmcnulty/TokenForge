# Goal 2: trustworthy change-report contract

Goal 2 follows Pester migration `63a782b4e54d84c0a947e78a3d6456d919748f9d`, Goal 1 implementation `f5df773c177cd11dcf3befc53b3e7507f08e2041`, and roadmap handoff `19470aeba7a949e4204e4ecf5586a6ffb3171c69`. This file defines the implementation and acceptance contract; completion requires the separate validation receipt.

A report compares saved evidence. It never authenticates, repeats issuance, calls an API, changes consent, infers authorization or publishes. Existing exact-resume hashes and historical rows remain unchanged. Source revision hashes are provenance, not comparison identities or publisher signatures.

## Required evidence domains

| Domain | Identity and comparable context | Meaning of a change |
| --- | --- | --- |
| PermissionDefinition | Resource, definition source/origin, delegated/application kind, stable ID; equivalent complete visible selection | Stable-ID rename/enablement differs from a definition appearing or disappearing from that source's visible vocabulary |
| PublicHint | Publisher/source selection, client/resource claims, callbacks and conflicts | Change in a source's claims, never consent or configured authorization |
| ConfiguredGrant | Tenant, observer, exact visible query/selection, client/resource, beneficiary and grant type | Change in a visible configured delegated edge; AllPrincipals differs from an unknown beneficiary |
| IssuedScopes | Tenant/principal, client/resource, authority, exact requested scopes, protocol, callback/SPA class, recipe and execution policy | Change in inspected scopes for this exact request; neither signature verification nor API authorization |
| ApiAcceptance | Complete issued-request/account context plus separately approved operation, method and API version | Observed response change for that saved operation; issuance alone supplies no API result |

A versioned saved snapshot contains strict typed collections, explicit visibility/completeness, collection context, allowlisted records and provenance. Source-observed time remains nullable and separate from local collection/observation times. Stable IDs, source locations/content hashes, record references and conflicting claims remain traceable. Private identifiers use fingerprints; credential fields and raw identity/API bodies are rejected.

The shared comparison engine and native/PowerShell adapters must support baseline, evidence-specific changes, lost visibility, incomparable, stale, unknown and attempt-status events. First evidence establishes a baseline, not permission availability. Missing input, partial paging, denied reads, failed issuance or a changed recipe cannot establish removal. Only equivalent complete visible sets or matched successful requests can establish their respective observed changes. Anonymous exports cannot establish tenant-specific removal or authorize an account. Public-only reports reject private inputs.

Each affected entry must explain before/after context, first collected observation, latest attempt status/date, preserved last-known success/date, uncertainty and provenance. Success → failure → success retains the earlier success instead of manufacturing removal or a new first-seen addition. Reports have an explicit AsOf/freshness policy and deterministic ordering. Suspected issuance regressions remain unreproduced observations until separate live authorization; reproduction alone does not establish root cause.

## Integration and acceptance

The ordinary `Compare-TokenForgeScopeDatabase` path must use the safe engine. Saved public permission snapshots, discovery source claims, tenant inventory/maintenance grants, scope/flow history, anonymous observations and optional saved API checks need real adapters. Missing legacy request, execution-policy, observer or query provenance stays unknown/incomparable. A versioned request descriptor for new observations must be persistently bound to the observation; unknown historical context cannot be reconstructed by assumption.

Fixtures must cover genuine comparable changes in all five domains, first-seen evidence, stable-ID rename, same names across permission kinds, source conflicts, changed recipe/request/account/observer, incomplete/denied/missing evidence, stale and unknown attempts, success/failure chronology, anonymous/private isolation, and all required legacy limitations. Complete inputs, including older history, must validate before results: duplicate keys/identities, credential/unknown fields, invalid dates, oversized documents and unsafe paths fail closed.

Changed native/core source requires a new local Linux x64 package from the existing approved toolchain and locked cached dependencies. An older binary cannot validate it. Native and PowerShell consumer output must agree. Actions remain disabled/manual-only; no live confirmation, tenant permission change, publication, push or Goal 3 work follows from this milestone.

## Use saved evidence

PowerShell provides `ConvertTo-TokenForgeChangeSnapshot`, `Compare-TokenForgeEvidence` for explicit objects, and `Get-TokenForgeChangeReport` for two explicit JSON paths. The ordinary `Compare-TokenForgeScopeDatabase` now returns these typed entries, including baseline/incomparable/unknown status entries. Consumers must inspect `EventType`; `AddedScopes`/`RemovedScopes` are populated only for comparable successful issued-scope or configured-edge value changes.

```powershell
Get-TokenForgeChangeReport -BeforePath /private/before.json -AfterPath /private/after.json -Kind FlowEvidence
Compare-TokenForgeEvidence -Before $beforeInventory -After $afterInventory -Kind Inventory
```

```sh
tokenforge research snapshot --input-path /private/permissions.json --kind PublicPermissions --json
tokenforge research changes --before-path /private/before.json --after-path /private/after.json --kind FlowEvidence --max-age-hours 24 --as-of 2026-10-22T00:00:00Z --json
```

Kinds are `Snapshot`, `PublicPermissions`, `Discovery`, `Inventory`, `ScopeDatabase`, `FlowEvidence`, `Anonymous`, `ApiChecks`, and `Maintenance`. File consumers require existing regular UTF-8 JSON files, at most 64 MiB, without links; files and their immediate directory must be private (0600/0700 on Linux). They read complete history before emitting output. They never create missing stores, discover profiles, unlock vaults or restore encrypted backups. `Maintenance` accepts an already available plaintext maintenance export; obtaining it is a separate operation. Redirect/API body/identity data are not copied into reports. Callback and operation details are represented by fingerprints.

An `ApiChecks` document wraps existing `Test-TokenForgeTokenAccess` results as `{Format:'TokenForgeApiChecks',SchemaVersion:1,CollectedAt:<local time>,Checks:[...]}`. Legacy results lack exact operation/account/request provenance and remain incomparable. An optional `ComparisonContext` must contain the full version-1 request context plus operation/method/API-version/approval fingerprints to compare responses. Supplying metadata authorizes no API call.

Inventory query receipts describe the actual unchanged Graph queries and visible Microsoft-owned aggregate edge projection. Grant `ClientId`/`ResourceId` here are public application IDs mapped by the collector from Graph service-principal object IDs. Individual Graph grant IDs were never collected, so reports explicitly compare aggregate visible edges, including beneficiary and consent type. The [Graph grant schema](https://learn.microsoft.com/en-us/graph/api/resources/oauth2permissiongrant?view=graph-rest-1.0) defines that distinction.

New bounded flow attempts retain their actual constructed OAuth request scope selection, authority, callback class, recipe and execution-policy fingerprints in `ComparisonContext`, before dispatch. OAuth v1 implicit carries an explicit empty requested-scope list because it selects the resource rather than a scope parameter. These descriptors persist through JSON, SQLite and metadata without altering legacy rows or exact-resume plan hashes. Different budget/recovery policies are intentionally incomparable. Aggregate scope observations retain the best inspected result; use full `FlowEvidence` for the latest attempt history and failed alternatives. Old scope/flow rows, anonymous exports, inventory without query coverage, and maintenance grant history without query receipts remain incomparable. No historical context is invented.

Definition fields that were not collected, or resources no longer verified/present, supply unknown coverage rather than an empty vocabulary. Conflicting same-time history is unknown; input order cannot resolve chronology. Publisher claim variants are combined per source/client, retaining the union of scope/callback claims and conflict-value hashes. No source-observed date is invented from local retrieval time. A raw-source digest, normalized-document digest, source commit and input digest have distinct meanings; none authenticates a publisher. Verify trusted expected file/package digests separately before operational use.

Run the focused Linux acceptance preset in a fresh process against the matching complete package:

```powershell
./scripts/Invoke-TokenForgeLocalValidation.ps1 -Preset Changes -NativeExecutable /path/to/package/tokenforge -ReportPath /private/new-changes-summary.json
```

This remains an offline diagnostic milestone. Important suspected issuance regressions require separate approval for a small bounded same-account, same-request confirmation. No such confirmation is performed by a report, and reproduction would still not establish Microsoft-side root cause.
