# Report gaps in the published application catalog

Both commands pin a full Git commit ID and require its relevant Git objects to be present locally. They fail if a partial clone is missing an object needed for the report. When they compare identifiers, they use `applications.json` and `applications.non-verified.json` from that commit. Novelty is measured against the union of those partitions. Keep any live sign-in report in private storage. These commands emit reports to standard output and leave Git and catalog verification state intact.

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

## Hand public changes to candidate review

Use the previous published snapshot as the baseline and supply newer retained captures with their observation stamps. Add `--review` to produce a review handoff alongside the existing delta. This example uses the post-review snapshot pinned by [B1](discovery-coverage.md).

```bash
python3 -B scripts/Diff-TokenForgePublicCatalog.py \
  --baseline-repo /path/to/local/catalog-repo \
  --baseline-commit ec3d72d75241c69bb9ca46528b32a1e7fd2a0b62 \
  --observations /path/to/observations.json --captures /path/to/captures \
  --native /path/to/reviewed-package/tokenforge --review > replay.json
```

The handoff emits at most one item per exact AppId, with all new evidence for that case. Each evidence entry supplies the source URL, previous and current revision and capture hashes, check time, and before and after claims. The reason identifies an AppId absent from both partitions, a source claim added or removed for a known AppId, or a change to existing claims. A verified catalog entry can receive a claim-review item.

Use the item in the [attended exact-AppId review](signin-review-provisioning-plan.md#combined-review). `Open` starts a case, `Update` adds evidence to a pending case, and `Reopen` adds evidence to an unresolved case. For B1's post-review pin, a first run without prior state seeds the 13 issue #151 cases without exact ownership receipts. Their issue number is retained so new evidence goes to the existing case. B1 could identify one managed identity only at aggregate level, so all 13 remain eligible for exact review.

Archive the replay receipt for provenance. Once the handoff is accepted, retain its `review.nextState` object in a separate JSON file and pass it with `--review-state` on subsequent runs, including when the catalog pin advances. Use one accepted state at a time. An operator can record a case as `Unresolved` and attach its issue number in that file. Carry forward its evidence IDs. Previously seen source claim transitions are deduplicated even if capture revisions or check times differ. Each emitted item has disposition `Pending`. Verified promotion requires the existing exact-AppId Microsoft ownership evidence and separate review.

A complete replay with no new evidence reports `reviewItemCount: 0`. A missing, invalid or timed-out capture yields exit code 2 with source statuses in `review.coverageGaps`. The review item count, items and next state are all JSON `null`; retain the previous state and retry once the gaps are filled. A handled SIGINT or SIGTERM during source comparison marks the comparison interrupted. If the process is killed outright or the receipt cannot be read as complete JSON, retain the previous state and rerun. The coverage receipt describes the supplied inputs. Upstream revision authenticity and global application coverage remain unknown.

### B2 local verification

Run from the TokenForge checkout on Linux x64 with the B1 capture directory and catalog Git objects available. The verification used the published `public-health-e2e-1d6617e` Linux package (archive SHA-256 `3e396f3486b9671ba5a71b6afd53a0e7a869fcb466e428beea30df596923446f`) and PowerShell 7.6.7.

```bash
export PATH="/tmp/tokenforge-b2-validation/powershell:$PATH"
export TOKENFORGE_TEST_NATIVE=/tmp/tokenforge-b2-validation/native/tokenforge
export TOKENFORGE_B1_CAPTURES=/tmp/tokenforge-b1-public-captures
python3 -B tests/CatalogCandidateImport.test.py -v
python3 -B tests/DiscoveryCoverage.test.py -v
git diff --check
```

Observed 18 candidate-import and six discovery-coverage passes, with zero skips or failures. The B1-pinned replay returned zero items for unchanged stamps. A synthetic newer resources capture derived from the retained B1 bytes produced three items across two new-to-catalog AppIds and one changed claim. One AppId reopened the existing issue #151 case. Replaying with accepted state produced zero items. A missing capture and a projector-triggered SIGTERM each exited 2 with coverage gaps and unknown review counts. The synthetic capture establishes replay behavior. Current upstream revisions, provider coverage and ownership for unresolved candidates still require separate evidence.

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

For an attended, bounded sample, use the [operator-owned Graph SDK process](operator-signin-gap-sample.md). The replay command also accepts an in-memory array through `-SnapshotRows` and reports its source-window coverage as unknown.

## Assemble multiple local sign-in gap reports

Save only the aggregate JSON from each successful or partial replay or operator sample to approved private storage. Use disjoint half-open UTC intervals and the same tenant, catalog commit, Graph version, and collection scope for all inputs. The aggregate intentionally contains no tenant or event IDs, so the assembler cannot independently establish that separate inputs came from the same tenant or deduplicate the same event if supplied with changed timestamps.

```bash
python3 -B scripts/Merge-TokenForgeSignInCatalogGaps.py \
  --catalog-repo /path/to/discovery-data-checkout \
  --catalog-commit FULL_DATA_COMMIT \
  --since 2026-01-05T00:00:00Z --until 2026-01-07T00:00:00Z \
  day-1.json day-2.json
```

Use `--graph-version beta` for a set of beta replay reports. The assembler accepts up to 128 regular aggregate files, each at most 8 MiB and at most 64 MiB combined. Each report is limited to 31 days. Page replay uses one-day slices, with a shorter final slice allowed. The assembled interval may be longer. The assembler reads both catalog partitions from local Git objects and rejects incompatible report pins, event shapes, candidate IDs, or counts.

The receipt records the requested interval and a disjoint ledger of supplied coverage. Equivalent reports count once, regardless of candidate order or equivalent UTC timestamp spelling. The receipt identifies them by SHA-256 of normalized canonical JSON after strict aggregate schema validation. Inputs with extra fields or invalid JSON values are refused. Any conflicting overlap excludes each entire affected report from candidate totals because a summarized report cannot be split without event-level data. The ledger shows both the overlap and excluded tails. Counts from nonoverlapping partial reports are retained and labeled incomplete, and missing intervals are shown explicitly. Exit code 0 and `InputCoverageComplete: true` mean complete local inputs represent all requested intervals. Exit code 2 means there are gaps, overlaps, or partial inputs. Exit code 1 refuses invalid or unavailable inputs without an aggregate.

When replaying multiple local pages for one window, a continuation on the last supplied page leaves the window incomplete if the next file is missing. Once a complete replay is available, submit only its aggregate for that window. Supplying the earlier interrupted aggregate too creates an overlap and excludes both. The replay checks the local sequence signaled by the supplied pages. It cannot establish that a terminal page came from the provider or that the files match the provider’s continuation chain.

Even with every requested interval represented, provider coverage and tenant history remain unknown. Counts summarize the included inputs. Client AppIds and Graph resource IDs remain separate, non-verified candidates. The actual JWT audience remains unknown.

## Sentinel aggregate handoff

The [offline Sentinel importer](sentinel-signin-aggregate.md) accepts a separate Azure Monitor aggregate format. Provider-specific resource fields remain separate from Graph replay fields.

```bash
TOKENFORGE_TEST_NATIVE=/path/to/reviewed/package/tokenforge python3 -B tests/CatalogCandidateImport.test.py
```

## Entra portal CSV handoff

Use the [offline Entra sign-in CSV adapter](entra-signin-csv-export.md) for a standard CSV from the Entra admin center. Its per-category reports preserve portal export semantics and record tenant coverage as unknown.
