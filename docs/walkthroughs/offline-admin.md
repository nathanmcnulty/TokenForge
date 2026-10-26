# Offline administrator walkthrough

Use saved synthetic metadata to explain one named tool, check its dated evidence, and prepare a typed before/after review packet. This walkthrough needs no tenant, credentials, session, sign-in, discovery, installation or network service. It runs the implemented native `admin explain`, `admin check` and `admin packet` commands. It never runs the named tool or acquires a token.

The example tool `read-profile` declares Graph `User.Read` for a fictional client. It deliberately declares **no API operation and no role/license prerequisite**. `VerifiedWorking` therefore means that its saved synthetic issuance evidence meets the declared policy at the fixed evaluation instant. It does not mean `/me` or any other API was called or accepted. All account/client identities, ownership statements and observations are fabricated. The Microsoft resource identifier and callback spelling only model the supported contract; they are not recommendations to use this client.

Observed scopes and metadata do not guarantee authorization or API access. Published hints, configured grants, observed issuance and API acceptance are different evidence. Even a real saved success describes its dated account/request context; scope counts do not rank privilege. These fixtures contain no signed token, signature verification or authenticated attestation. Changing a digest cannot turn invented observations into proof.

## Prepare a local replay

Use Linux, Python 3 standard library, and an already trusted, complete source-compatible Linux x64 package. Do not install, rebuild or download a package for this exercise. The replay consumes the owning package's `public-health-package.json` layout and verifies its source pin, manifest digest and all declared payload sizes/hashes before running the executable. A trusted expected hash must come from a separately reviewed receipt. Hash consistency alone does not establish authenticity or compatibility with a different source revision.

Run from the repository root, supplying **absolute** package and new output paths:

```sh
python3 examples/offline-admin/replay.py \
  --native-executable /absolute/reviewed-package/tokenforge \
  --source-revision REVIEWED_PACKAGE_SOURCE_COMMIT \
  --package-manifest-sha256 REVIEWED_MANIFEST_SHA256 \
  --output-directory /absolute/existing-private-parent/new-offline-admin-run
```

The output directory must not exist; its parent must already exist. Use a new private scratch location, never an operational account/state directory. For a self-contained .NET bundle under a stripped environment, supply a dedicated private `DOTNET_BUNDLE_EXTRACT_BASE_DIR`; otherwise the host may fail before command processing. The replay creates a 0700 directory, copies the JSON inputs as 0600 files, and retains actual stdout, stderr, argument/exit receipts and `summary.json`. Repository fixtures can be readable as ordinary source files; native private ingress requires the protected copies. Do not loosen permissions or use links to bypass ingress checks.

The runner is a small example replay, not a new TokenForge API. It uses explicit file paths, closes child stdin, sets the child PATH to a nonexistent adapter directory and bounds each command to 30 seconds. The selected native commands inspect local files only; their source paths do not call acquisition. PATH isolation is not an OS network sandbox. The runner does not inspect sessions, initialize a store, call an authentication command or read an operator's discovery data. The replay writes its inputs and receipts only to the new output directory; the .NET host may also write extracted libraries and temporary files to the explicitly supplied private scratch directories. An unexpected exit, stderr, status, reason or packet event fails the replay; inspect the saved command and output instead of treating exit 2/3/4 as a runner failure by itself.

For the final reviewed package used after local integration, the command was (run in a new network namespace with a clean environment):

```sh
# Existing dedicated 0700 parent; tmp/ and bundle/ are private scratch directories.
unshare -Urn env -i PATH=/usr/bin:/bin LANG=C.UTF-8 \
  TMPDIR=/home/nathan/.codex/worktrees/issue98-runtime-integration/TokenForge/.cache/offline-admin-final-replay/tmp \
  DOTNET_BUNDLE_EXTRACT_BASE_DIR=/home/nathan/.codex/worktrees/issue98-runtime-integration/TokenForge/.cache/offline-admin-final-replay/bundle \
  /usr/bin/python3 -I -B examples/offline-admin/replay.py \
  --native-executable /home/nathan/.codex/worktrees/issue98-runtime-integration/TokenForge/.cache/issue98/final-package-58203ec/linux-x64/tokenforge \
  --source-revision 58203ecdcee47c4bdaaef0801d0b496d22daa35f \
  --package-manifest-sha256 8c550f08b5632f13a48a07558574370bd4375794fe09b3fe9120d72de3efe0a7 \
  --output-directory /home/nathan/.codex/worktrees/issue98-runtime-integration/TokenForge/.cache/offline-admin-final-replay/run-02
```

That local path is an integration artifact, not a distributable prerequisite. If it is unavailable, finish source review and obtain a matching receipt/package from the owning session before claiming replay success. Do not substitute an older package or change runtime pins. After integration into a different baseline, replay with that baseline's reviewed complete package and retain a new receipt.

## Read the inputs and results

The complete [inputs](../../examples/offline-admin/inputs/) are intentionally small:

- `profile.json`: strict silent-only profile, approved fictional tool/bootstrap clients, zero additional API scopes at both stages, 24-hour evidence age and 180-second policy ceiling. This metadata grants no authorization to acquire anything.
- `requirements.json`: one tool with explicit resource, scope, protocol and callback class; empty operation/prerequisite arrays keep issuance and API proof distinct.
- `inventory.json`: fictional registrations and callback metadata at 11:00 UTC, with complete empty grant enumeration. Metadata alone cannot establish issuance.
- `before.json`: exact-context successful issuance at 11:40 UTC. `success.json` records the same scopes at 11:50 UTC. The other snapshots vary evidence quality or outcome as described below.
- [expected.json](../../examples/offline-admin/expected.json): fixed `AsOf`, every expected status/exit/reason, packet pair and typed event. The replay does not regenerate expectations from actual output.

Evaluate all cases at **2026-10-24T12:00:00Z**, not the wall clock. Fresh evidence is 10 minutes old; stale evidence is 48 hours 10 minutes old. Preserve the fixed instant when reproducing. Profile/tool canonical hashes bind the exact request policy and recipe. Editing any profile, requirement or callback can make old evidence cease to match. Do not relabel its context to force a match.

| Snapshot | Explain/check | Exit | Packet event | Operator interpretation |
| --- | --- | ---: | --- | --- |
| `success.json` | `VerifiedWorking` | 0 | no retained entries | Saved issuance satisfies this issuance-only declaration; no scope change from `before.json`. No API assurance. |
| `missing.json` | `NeedsObservation` | 3 | `LostVisibility` | No collections are present. Missing observations cannot prove removal or denial. |
| `stale.json` | `AtRisk` | 2 | `Stale` | Retain historical success, but do not treat it as fresh. This packet compares `stale.json` to itself to isolate age. |
| `incomplete.json` | `AtRisk` | 2 | `LostVisibility` | A success record remains, but incomplete collection coverage cannot support a current verified result or removal claim. |
| `incomparable.json` | `NeedsObservation` | 3 | `Incomparable` | Execution-policy fingerprint differs. The observation is outside the declared exact request; no comparable regression is established. |
| `excess-scopes.json` | `Blocked` | 4 | `MatchedRequestScopesChanged` | Same requested scopes/context, but observed issuance adds `Mail.Read`, exceeding the zero-additional-scope ceiling. |
| `request-blocked.json` | `Blocked` | 4 | `Unknown` | Fresh exact-request `RequestBlocked` evidence blocks health. The packet retains prior success as historical; it cannot infer a permission removal or root cause. |

Every packet except the stale pair uses `before.json` as its baseline. Pairing the newer `before.json` with the older `stale.json` would reverse chronology and produce `Incomparable`; it is not the stale-age experiment. Every packet here exits 0 because preparation succeeded, including packets with uncertainty. Health exit 1 means invalid/unsupported input, distinct from the valid health states above; safe error JSON goes to stderr. Do not turn an ingress/schema error into a health conclusion.

## Inspect individual native commands

After the replay, set `TF` to the same absolute reviewed executable and `RUN` to its new output directory. These are plain shell variables, not credentials:

```sh
TF=/absolute/reviewed-package/tokenforge
RUN=/absolute/existing-private-parent/new-offline-admin-run

"$TF" admin explain \
  --profile-path "$RUN/inputs/profile.json" \
  --requirements-path "$RUN/inputs/requirements.json" \
  --inventory-path "$RUN/inputs/inventory.json" \
  --snapshot-path "$RUN/inputs/excess-scopes.json" \
  --tool read-profile --as-of 2026-10-24T12:00:00Z --json
# Expected exit 4, Status=Blocked; inspect Clients[0].Reasons and ObservedAdditionalScopes.

"$TF" admin check \
  --profile-path "$RUN/inputs/profile.json" \
  --requirements-path "$RUN/inputs/requirements.json" \
  --inventory-path "$RUN/inputs/inventory.json" \
  --snapshot-path "$RUN/inputs/missing.json" \
  --tool read-profile --as-of 2026-10-24T12:00:00Z --json
# Expected exit 3, Status=NeedsObservation, ExactRequestNeedsObservation.

"$TF" admin packet \
  --requirements-path "$RUN/inputs/requirements.json" \
  --before-path "$RUN/inputs/before.json" \
  --after-path "$RUN/inputs/excess-scopes.json" \
  --source-revision REVIEWED_PACKAGE_SOURCE_COMMIT \
  --package-sha256 REVIEWED_MANIFEST_SHA256 \
  --as-of 2026-10-24T12:00:00Z --json
# Expected exit 0, PreparedForHumanReview, MatchedRequestScopesChanged.
```

Use the reviewed source/hash values from your replay command for the packet placeholders. Source/package pins are caller-supplied metadata: the product does not independently authenticate them. `explain` includes declared requirements, excluded alternatives, callbacks, evidence breadth and reasons. `check` returns the health projection. Both report `CurrentAcquisitionPerformed=false` and `AuthorizationEstablished=false`.

For a packet, inspect `Entries[].AffectedTools`, `Change`, `ImpactConclusion`, `BeforeSnapshotSha256`, `AfterSnapshotSha256`, `RequirementsSha256`, `AsOf`, `MaxAgeHours`, retained/omitted counts and disclosure route. A typed scope change is potential impact, not confirmed tool failure. The default packet is bounded to 64 entries (maximum 128) and 1 MiB; inspect truncation/omissions before treating a packet as complete. These examples retain at most one entry and omit none.

All packets here use `PrivateMaintainerReview`; marking a tool or packet security-sensitive selects `PrivateSecurityDisclosure`. Either route is private. Preparation neither sends anything nor opens an issue. `RootCauseEstablished=false`, `RegressionConfirmation=NotPerformed`, `AutomaticCommunication=false` and `CommunicationAuthorized=false` remain explicit. Review contents, provenance and disclosure separately before any communication. Real account/request metadata may be sensitive even without credentials.

For missing, stale or incomparable evidence, preserve the uncertainty and investigate the exact saved source/account/request/freshness context. Any new observation or API check requires a separately authorized collection path and budget. For excess scopes or request denial, stop and review the policy/evidence; do not increase ceilings, switch clients/callbacks or add a session to make this example green. No command in this walkthrough performs a live follow-up.

## Candidate evidence and integration

The [validation receipt](../../examples/offline-admin/validation.json) records the exact source, native build source, package/build receipt hashes, executable/runtime identity, fixture hashes and 21 actual command results. The [independent review](../../examples/offline-admin/review.md) records review scope and limits. This is a local guide/example candidate, with no product/runtime/test-baseline edits and no publication, PR mutation, merge or hosted run. It does not close #98 or #106.

Integrate only this guide and `examples/offline-admin/`. The original candidate's parent was `cbea33eca2dfde24f0c92b0385784876510e4ece`; local cherry-pick `911156e2175be78882a132611d4836214fd80a72` has parent `ccc14d843f53a35d5f15e69a986467f0b7381ce3`. The primary session owns runtime/package and baseline decisions. Reuse this receipt only while its inputs/package are unchanged; after integration into a changed source/package, replay the 21-command example with that reviewed package. The existing Admin validation preset may be run by the primary session when runtime integration needs broader contract coverage. This documentation change does not alter that suite or require cross-platform/hosted gates.
