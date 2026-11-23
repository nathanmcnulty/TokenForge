# Report gaps in the published application catalog

Both commands pin a full Git commit ID. When they compare identifiers, they use `applications.json` and `applications.non-verified.json` from that commit. Novelty is measured against the union of those partitions. Keep any live sign-in report in private storage. These commands emit reports to standard output and leave Git and catalog verification state intact.

## Compare retained public source observations

```bash
python3 -B scripts/Diff-TokenForgePublicCatalog.py \
  --baseline-repo /path/to/discovery-data-checkout \
  --baseline-commit FULL_DATA_COMMIT \
  --observations /path/to/observations.json
```

Supply a JSON object keyed by `roadtools`, `microsoftApps` and `resources`. Each entry has a reported file `revision`, UTC `checkedAt`, optional UTC `committedAt`, and optional `sha256` of the exact source bytes. Use `{"status":"Unavailable"}` when a source lookup fails. A missing source also yields an incomplete receipt. Use trusted retained source receipts. The tool compares the revision labels supplied by the caller and does not authenticate them against upstream Git. It records verified capture hashes separately.

Matching file revisions skip capture and projection. A different revision requires a local capture, even if its reported digest matches the baseline. For different revisions, pass `--captures` with the matching local `<source>.json` files and `--native` with the reviewed package executable used by the public health tool. Each changed capture is checked against its supplied SHA-256 and projected using the existing public-source validator. The stamp-only path reads the source receipts from the non-verified artifact. It does not enumerate either partition’s AppIds or load the verified artifact until a changed capture needs comparison. The command makes no network requests.

The deterministic receipt identifies only previously unknown IDs and per-source claim differences for known IDs. Multiple sources for the same new ID are combined, and all additions are pending. Exit code 2 means at least one source was unavailable, conflicting or unvalidated. A complete receipt describes the supplied observations, including any source-level revision changes.

## Replay local Entra sign-in data

```powershell
./scripts/Find-TokenForgeSignInCatalogGaps.ps1 `
  -FixtureDirectory /path/to/local-pages `
  -CatalogRepository /path/to/discovery-data-checkout `
  -CatalogCommit <full-data-commit> `
  -Since <utc-start> -Until <utc-exclusive-end>
```

Use local page files named `window-1-page-1.json`, `window-1-page-2.json`, and so on, with Graph's collection shape. Windows run oldest first in one-day UTC slices. Continuation URLs are checked for the expected Graph endpoint and loops, then used only as signals to read the next local page filename. Replay discards exact upper-bound events locally to keep adjacent windows disjoint. Use `-SnapshotPath` instead of `-FixtureDirectory` for one bare JSON array. Snapshot rows are evaluated against the requested interval as a single local input.

The default expects the Graph v1.0 `isInteractive` field. `-PreviewAllEventTypes` expects the beta `signInEventTypes` array. A complete replay means the supplied local records passed replay checks. The source's retained-window coverage remains unknown for both formats. Missing files, malformed events, invalid continuations, and exhausted bounds yield an incomplete report and exit code 2.

The report distinguishes client `AppId` from Graph's GUID `resourceId`. Resource comparison is exact identifier equality, and the actual JWT audience remains unknown. Only scalar strings containing nonzero GUIDs missing from both catalogs become pending candidates. Reports contain aggregate counts, first and last observation times, and event type counts. Deduplication state stays in memory. Replay saves no raw events or continuation links.

### Future operator-run collection

This milestone provides replay only. A future official Graph SDK collector would need an explicit operator-run flow, an exact tenant check, an existing delegated `AuditLog.Read.All` scope, and a supported Entra role. An existing SDK context can still refresh credentials or prompt. Before enabling such a collector, test it in an isolated invocation that disables inherited PowerShell parameter defaults, including SDK file output, headers, and session defaults. Request only the fields needed for in-memory aggregation, and treat retention and paging failures as limits on coverage.

Use v1.0 for retained user sign-ins. Beta is a separate preview option requiring explicit filters for interactive user, non-interactive user, service principal, and managed identity events. Keep client and resource identifiers labeled separately. [Microsoft Graph v1.0](https://learn.microsoft.com/en-us/graph/api/signin-list?view=graph-rest-1.0) · [Microsoft Graph beta](https://learn.microsoft.com/en-us/graph/api/signin-list?view=graph-rest-beta)

```bash
TOKENFORGE_TEST_NATIVE=/path/to/reviewed/package/tokenforge python3 -B tests/CatalogCandidateImport.test.py
```
