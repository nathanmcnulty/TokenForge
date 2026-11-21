# TokenForge app-addability proposal — 2026-11-21

This review proposal covers the complete pinned 5,470-ID discovery snapshot. It does not replace or activate TokenForge's current public catalog artifact.

## Current run state

No Microsoft Graph context matched the authorized lab account and tenant during offline preparation, so no Graph request was sent. The current classification is **0 confirmed, 0 couldn't-add, and 5,470 pending**. Historical failures are not classified as app-specific refusals because the retained October records contain no refusal code or message.

The private run checkpoint is prepared outside Git and contains the complete 5,470-ID queue. After a matching interactive Microsoft Graph sign-in is available, `scripts/Invoke-TokenForgeAppAddability.ps1` resumes that queue by exact AppId lookup. It only allows Graph `GET` and `POST`, disables SDK retries, and reconciles an uncertain POST with an exact lookup before any retry. It never grants consent, assigns app roles, signs in as catalog apps, collects logs, or deletes service principals.

## Pinned catalog and historical evidence

- Discovery snapshot: `nathanmcnulty/TokenForge` `discovery-data` commit `a5200c8172f8487ea01cadd5480d3f9f7610a521`, blob `53d3c52efa10287470047158c8d39eeef4fc9b5b`, SHA-256 `930413f4bef996dfa2b4dc6257ddabc77896de9a443d0ad693aea47e1510910b`.
- Snapshot size: 5,470 unique AppIds.
- October discovery (`2026-10-03`): 5,454 exact current-ID matches.
- October inventory (`2026-10-04`): 1,993 Present, 3,461 Missing, 1 OwnerMismatch, and 15 current IDs without an exact inventory row.
- October registration attempts (`2026-10-03`): latest outcomes for current IDs were 1,278 Created, 3,457 Failed, 4 OwnerRejected, and 731 with no attempt.
- The 1,993 distinct historical positive cases are retained separately from 3,271 positive evidence events (inventory presence plus successful creation events). All 1,278 historical Created IDs overlap October inventory Present. OwnerMismatch is not positive evidence.

The October snapshots and attempt log are private inputs and are not copied into this repository. `historical-evidence.json` contains only exact public AppIds, sanitized outcome metadata, capture dates, and input hashes.

## Review artifacts

- `catalog-proposal.json`: complete catalog metadata plus separate current disposition and dated historical evidence for every AppId.
- `confirmed.json`, `couldnt-add.json`, and `pending.json`: mutually exclusive current result lists.
- `existing-cross-tenant-evidence.json`: October evidence, kept separate from new Graph outcomes.
- `fresh-successful-creations.json`: service principals newly created and verified during the current run; empty before Graph work.
- `historical-evidence.json`: reproducible, sanitized October evidence covering all 5,470 IDs.
- `manifest.json`: pinned sources, classification rules, and full-snapshot counts.

## Reproduce the proposal

From the TokenForge repository root, use the pinned snapshot and the private October captures:

```bash
python3 scripts/Export-TokenForgeAppAddabilityProposal.py \
  --snapshot-path /path/to/private/applications.json \
  --october-discovery /path/to/private/discovery.json \
  --october-inventory /path/to/private/inventory.json \
  --october-attempts /path/to/private/scopes.json \
  --current-checkpoint /path/to/private/app-addability-full-20261121/checkpoint.json \
  --expected-current-tenant <approved-lab-tenant-id> \
  --expected-current-account <approved-account> \
  --write-history-evidence \
  --output-dir docs/app-addability-2026-11-21
```

## Resume after Microsoft sign-in

Use the supported Microsoft Graph PowerShell interactive sign-in on the parrot computer. Enter the Temporary Access Pass only in Microsoft's sign-in UI. Request no new permissions and do not accept a new-consent prompt. Then check `Get-MgContext` and continue only if `TenantId`, `Account`, and the already-authorized `Application.ReadWrite.All` scope match the approved run:

```powershell
Import-Module Microsoft.Graph.Authentication -RequiredVersion 2.38.1
Connect-MgGraph -TenantId <approved-lab-tenant-id> -Scopes Application.ReadWrite.All -NoWelcome
Get-MgContext | Format-List TenantId,Account,AuthType,Scopes
```

After that check, resume the prepared full-catalog run with the pinned private snapshot and a state root outside the checkout:

```powershell
./scripts/Invoke-TokenForgeAppAddability.ps1 `
  -SnapshotPath <path-to-pinned-applications.json> `
  -TenantId <approved-lab-tenant-id> `
  -ExpectedAccount <approved-account> `
  -StateRoot <private-state-directory-outside-the-checkout>
```

If account, tenant, or scope validation fails, stop. The runner checks the context before every Graph request and resumes from the private per-ID checkpoint.

## Local verification

The reproducible checks are:

```powershell
Invoke-Pester -Path ./tests/AppAddability.Tests.ps1
```

```bash
python3 tests/AppAddabilityProposal.test.py
```

They cover external non-Microsoft owners, exact-ID lookup/create/verification, ambiguous POST timeout reconciliation and retry, retry-delay handling, mismatch and permission stops, restart recovery, DELETE exclusion, and proposal sanitization.
