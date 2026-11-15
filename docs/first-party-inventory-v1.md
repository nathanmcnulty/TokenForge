# First-Party Inventory v1

Build a private inventory from the published historical catalog, pinned Graph permission definitions, an existing tenant inventory, retained sign-in summaries and historical flow evidence. The offline command validates inputs using the existing public-catalog and flow validators, then writes a deterministic inventory, review queue and report. It does not authenticate, create service principals, collect tokens or publish a catalog.

```bash
python3 scripts/New-TokenForgeFirstPartyInventory.py \
  --public-ledger "$PUBLIC_DATA/applications.json" \
  --graph-definitions "$PUBLIC_DATA/api-definitions/graph/b9a67f126ee562c9ff20645f8a4fb6c0928d0a7a.json" \
  --native "$ACCEPTED_PACKAGE/tokenforge" --pwsh "$PWSH" \
  --tenant-inventory "$PRIVATE_INPUT/inventory.json" \
  --signins "$PRIVATE_INPUT/signins.json" \
  --flows "$PRIVATE_INPUT/flows.json" \
  --api-evidence "$PRIVATE_INPUT/api-proofs.json" \
  --definitions docs/reference-data/first-party-identifier-definitions.json \
  --output "$PRIVATE_OUTPUT"
```

Omit optional evidence arguments when that evidence is unavailable; do not manufacture empty success proofs. The API evidence input contains retained, context-verified fixed-GET proof summaries, not new requests or raw responses.

Choose a new private output directory. Retain input files and the exact source/native identities recorded by the workflow. Repeat with the same inputs into a different directory to compare output hashes. To export a retained SQLite flow ledger without issuance, use the existing `Get-TokenForgeFlowEvidence -Path ... -NativeExecutablePath ...` and serialize the validated returned document privately. A lookup is always evidence-limited: no matching record means unresolved, not proof an application does not exist.

Append `--lookup "$IDENTIFIER"` to the same command with a new output directory to print every matching typed namespace. Inspect `EntityEvidence`, `OwnershipEvidence`, `ObservedSignIn`, `SuccessfulTokenIssuance`, `VerifiedApiAccess` and `ReviewReasons` in `inventory.json`; `review-queue.json` lists conflicts and missing evidence. The command still writes the complete private report. Do not publish the lookup output.

The inventory keeps entity type, Microsoft ownership, sign-in observation, matched token issuance and verified API access separate. A public owner hint cannot establish directory ownership. A successful sign-in is not a token issuance or API-access proof. A successful flow is account-, resource-, protocol- and observation-specific. Fixed endpoint acceptance proves only that tested request. An absent observed token audience stays absent; the requested resource is not substituted for it.

Application IDs, service-principal object IDs, resource identifiers and observed token audiences are separate namespaces. The Graph sign-in API describes `resourceId` as a resource identifier; only an actual directory mapping can resolve an ambiguous value. The collector separately retains `resourceServicePrincipalId`. Conflicting mappings remain in the review queue. See the [Graph sign-in schema](https://learn.microsoft.com/en-us/graph/api/resources/signin?view=graph-rest-beta).

Graph permission definitions and existing directory app-role definitions are positive evidence of non-application identifier use. The small source-bound reference file additionally demonstrates directory-role templates, Windows Hello AAGUIDs and a licensing SKU. It is a partial reference set, not a complete registry. Each fact names its source document and exact retrieved-byte hash; raw source snapshots stay local. Labels in MicrosoftApps alone are not authoritative type definitions. A positive non-app use does not erase a conflicting app claim for the same GUID.

For an approved read-only backfill, call existing `Get-TokenForgeTenantInventory -IncludeDirectoryObjects` with the current Graph token and discovery document. This opt-in retains an explicit private object-to-app mapping from the same directory enumeration; it performs no registration and adds no request. Pass that inventory to `Get-TokenForgeSignInApplications` with explicit `Since`, `Until`, all four event types and its private checkpoint path. Retain and resume the identical window and inventory; a partial or interrupted scan must not be described as complete. Requested coverage and observed event coverage are distinct. Empty categories and expired retention are not evidence of no activity.

A server-expired paging cursor (HTTP 410) is a failed attempt, not a completed query. Keep its charged request and partial checkpoint intact. If a fresh read is authorized within the remaining cumulative budget, choose a separate checkpoint for the identical frozen window and inventory. Its aggregates replace that window’s partial summary; never add the old partial counts to the replacement. Do not silently restart, widen the window or reset cumulative accounting.

Keep inventory, sign-in checkpoints, directory objects, flow documents, API receipts and all reports private. Publish only sanitized implementation and validation summaries. Old live assessment evidence retains its original source/compiled identities; using a later qualified offline binary to read it does not turn it into a new live test. Collection, token acquisition and publication are independent operations. This milestone does not authorize any of them automatically.

The sign-in timestamp reader preserves typed UTC and offset timestamps returned by PowerShell JSON parsing. It refuses timezone-free context and genuine out-of-window events. Do not convert a UTC `DateTime` to a culture-dependent string before parsing: that loses its timezone. A stopped attempt keeps partial coverage and charged requests; an offline correction does not authorize renewed authentication or reset a live envelope. Any later authorization changing the bounds remains distinct from the original stopped attempt.
