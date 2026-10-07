# Application metadata and scheduled discovery

Every successful `Discover` run now merges its results into `applications.json` next to `discovery.json`. The inventory CLI also updates that file after `Inventory`, `SignIns`, `Register`, `Probe`, and `Merge`. Override the location with `-MetadataPath`. Existing state continues to work: the first run creates the catalog. It does not automatically import older files.

```powershell
./scripts/Invoke-TokenForgeInventory.ps1 -Action Discover -StatePath $state
$catalog = Get-TokenForgeApplicationMetadata -Path "$state/applications.json"
$catalog.Applications['00000003-0000-0000-c000-000000000000']

# Import earlier metadata without authenticating again.
$old = Get-Content "$state/inventory.json" -Raw | ConvertFrom-Json
Update-TokenForgeApplicationMetadata -Path "$state/applications.json" -Document $old -Kind Inventory
```

`Applications` is a dictionary keyed by canonical application GUID. Each application has `FirstSeenAt`, `LastSeenAt`, and `Records`. Records are separated by collection kind, tenant fingerprint, account fingerprint, and resource ID where applicable. Published hints cannot overwrite tenant verification or a different account's scope observations.

Each record contains all supported attributes collected by that workflow, its source names/locations/evidence, observation dates, a content hash, and `PreviousVersions` when attributes change. This includes names, ownership evidence, public-client/family hints, callbacks, resource identifiers, published scopes, tenant availability/assignment flags, delegated scope definitions, application role definitions, and observed scope/protocol results. This is a normalized metadata model, not the entire Graph application schema. Credentials, raw sign-in events, user names, IP addresses, and tokens are excluded. Empty GUID placeholders from public datasets are counted and ignored.

`FirstSeenAt` and `LastSeenAt` describe source observations. `Runs[].RecordedAt` records when TokenForge imported them. Every successful run appends a run record, even if nothing changed. Public discovery run records also include source snapshot hashes. Hashes identify content, not publisher signatures.

Complete discovery, inventory, and sign-in snapshots mark disappeared records `PresentInLatestRun=false` while retaining their attributes and history. Partial scope batches never mark unseen records absent. Older imports cannot reverse a newer snapshot's presence status. Scope rows are processed chronologically; equal-date differing rows use input order. Imports older than an existing record can extend first-seen dates but do not backfill historical attribute versions. Import historical databases oldest first when full change history matters.

Writes use an exclusive per-file lock and an atomic replacement. On Unix, temporary files are created with mode 0600 before writing. Keep local state outside Git in a private directory; on Windows use a directory whose ACL admits only the intended user. This file is not encrypted and tenant/account fingerprints remain private correlation data. It is diagnostic evidence and is never consulted to authorize registration or token acquisition. Individual state files are atomic, but a workflow's several files are not one transaction: if a write fails, fix access/space and rerun. The catalog has a 128 MiB read/write limit; archive older history before exceeding it.

## GitHub Actions

`.github/workflows/discovery.yml` runs every six hours and supports manual runs. Code runs from `main`; PRs cannot trigger the credentialed job. Nora's software passkey values are stored separately as `NORA_PASSKEY_CREDENTIAL_ID`, `NORA_PASSKEY_USER_HANDLE`, `NORA_PASSKEY_PRIVATE_KEY`, and `NORA_PASSKEY_UPN` secrets. `NORA_TENANT_FINGERPRINT` and `NORA_PRINCIPAL_FINGERPRINT` pin the expected existing account; the bootstrap client, resource, namespace, and Graph `/me` identity must match before inventory is read. The login action is pinned to a reviewed commit. Application-intent confirmation is explicitly enabled only for the expected Azure CLI client; this is separate from OAuth permission consent. The action omits generated assertions and identity response bodies from diagnostics. It passes a masked ESTS cookie to the next step. No cookie jar is saved by CI.

The job refreshes public `applications.json`, reads enabled Microsoft-owned service principals using Nora's existing Graph permissions, and probes one rotating Graph batch. It defaults to 100 applications with at most two callbacks each. `chunk_index=-1` chooses `(run_number-1) % chunk_count`; manual runs/retries can repeat or skip batches, so this is bounded sampling rather than guaranteed full coverage. Explicit chunk indexes can complete a selected sweep. Registration and consent are never performed. The fixed Graph Command Line Tools bootstrap requests `User.Read`; Entra may return broader existing scopes needed for directory reads. The job fails if that session cannot read inventory.

Public-only catalog validation rejects mixed private origins, unexpected fields, and historical private records before and after the run. Anonymous scope export schemas are checked as well. Only public metadata and `scopes/chunk-NNNN.json` anonymous successful scope exports are committed to the separate `discovery-data` branch. Anonymous results describe one account/session's observed scopes, not universal preconsent or guaranteed API access. Private inventory and scope checkpoints exist only in a temporary runner directory and are deleted in `finally`. They are never uploaded as artifacts. Public CI does not collect sign-in logs: Nora's previously tested account lacks that permission. The richer local catalog can retain private sign-in and tenant attributes.

Use `public_only=true` to refresh public sources without authenticating. Concurrent data writers are serialized, pushes do not force, and failed stages do not publish partial runs. Dataset terms remain those of the upstream publishers. The data branch retains run/history growth; archive or rotate it as needed.

Anonymous scope batches retain earlier successful client/resource observations when a later batch fails. Their original observation dates remain visible; old success does not establish current availability. Hidden files, nested directories, and unexpected scope-export paths are rejected before publication.

For per-attempt flow evidence, registration history, richer sign-in summaries, and coverage categories, see [Application research catalog](research-catalog.md).
