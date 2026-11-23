# Report gaps in the published application catalog

Both commands read `applications.json` and `applications.non-verified.json` from a full Git commit ID. Novelty is measured against the union of those partitions. Keep any live sign-in report in private storage. These commands emit reports to standard output and leave Git and catalog verification state intact.

## Compare retained public source observations

```bash
python3 -B scripts/Diff-TokenForgePublicCatalog.py \
  --baseline-repo /path/to/discovery-data-checkout \
  --baseline-commit FULL_DATA_COMMIT \
  --observations /path/to/observations.json
```

Supply a JSON object keyed by `roadtools`, `microsoftApps` and `resources`. Each entry has an immutable file `revision`, UTC `checkedAt`, optional UTC `committedAt`, and optional `sha256` of the exact source bytes. Use `{"status":"Unavailable"}` when a source lookup fails. A missing source also yields an incomplete receipt. Compare observations from trusted retained source receipts.

Matching file revisions skip capture and projection. A new revision with the same recorded SHA-256 records the revision change without reprocessing the payload. For changed payloads, pass `--captures` with the matching local `<source>.json` files and `--native` with the reviewed package executable used by the public health tool. Each changed capture is checked against its supplied SHA-256 and projected using the existing public-source validator. The verified ledger is loaded only if a changed capture passes projection. The command makes no network requests.

The deterministic receipt identifies only previously unknown IDs and per-source claim differences for known IDs. Multiple sources for the same new ID are combined, and all additions are pending. Exit code 2 means at least one source was unavailable, conflicting or unvalidated. A complete receipt describes the supplied observations, including any source-level revision changes.

## Report IDs from Entra sign-ins

After an operator has separately established a delegated Microsoft Graph PowerShell SDK context, run the following in that same process with its existing permissions:

```powershell
./scripts/Find-TokenForgeSignInCatalogGaps.ps1 `
  -TenantId <approved-tenant-id> `
  -CatalogRepository /path/to/discovery-data-checkout `
  -CatalogCommit <full-data-commit> `
  -Since <utc-start> -Until <utc-exclusive-end>
```

The script requires an exact tenant match, the Global SDK environment, and an existing delegated `AuditLog.Read.All` scope before requests. Access also depends on the operator's existing Entra role. The script uses the SDK's read-only GET entry point and does not initiate sign-in or request permissions.

The default uses the documented v1.0 user-sign-in endpoint. `-PreviewAllEventTypes` opts into beta and explicitly filters for interactive user, non-interactive user, service principal and managed identity events. Both endpoints are constrained by Graph retention, available event categories and tenant permissions. The script walks one-day UTC windows oldest first and follows Graph's continuation URLs within the selected endpoint. It discards exact upper-bound events locally to keep adjacent windows disjoint. Pages are limited across the run. An invalid page or continuation, exhausted bound, or Graph failure yields an incomplete report and exit code 2. Even successful pagination does not establish complete tenant history. [Microsoft Graph v1.0](https://learn.microsoft.com/en-us/graph/api/signin-list?view=graph-rest-1.0) · [Microsoft Graph beta](https://learn.microsoft.com/en-us/graph/api/signin-list?view=graph-rest-beta)

The report distinguishes client `AppId` from Graph's GUID `resourceId`. Resource comparison is exact identifier equality, and the actual JWT audience remains unknown. Only nonzero GUIDs missing from both catalogs become pending candidates. Output contains aggregate counts, first and last observation times and event type counts. The script holds event deduplication in memory, suppresses raw errors and saves no raw events or continuation links.

For synthetic replay, replace `-TenantId` with `-FixtureDirectory`. Supply pages named `window-1-page-1.json`, `window-1-page-2.json`, and so on, using the Graph collection shape. Replay makes no SDK calls. Tests also mock the SDK context and GET paths:

```bash
TOKENFORGE_TEST_NATIVE=/path/to/reviewed/package/tokenforge python3 -B tests/CatalogCandidateImport.test.py
```
