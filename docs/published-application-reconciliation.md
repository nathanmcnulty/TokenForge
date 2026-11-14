# Published application ledger reconciliation (local review)

Reconcile into a **copy of the published ledger; do not replace it with collector output**. This work changes no CLI, collector, module, scope export, workflow or remote ref. It uses #127's supported public-health fixture, fixed bounded HTTP helper and collector/validators, the existing native catalog import/export, and `Export-TokenForgeCatalogDownload.ps1`. Only the missing offline union/diff adapter and its focused verifier are new.

## Frozen identities

- Main: `871f5b822370fcfa1ab37fe500a2014fedb994e7`.
- discovery-data: `9b08e26a0a871289c1983e02cf516fbed11d7615`.
- Published applications blob: `94b4e7dcef8f7a01cbf9198c8302a593dbfbbd06`; SHA-256 `a77104a55b37bdd4f57c3df23d3bcec1afcd503b0f2b60a31fe0b7a1b6457b6f`.
- Published download manifest: `downloads/applications-94b4e7dcef8f7a01cbf9198c8302a593dbfbbd06.manifest.json`. Its source, compressed and compact-content hashes all verified. Compact content SHA-256 `17554fc3134ef468b7912a442bb21806fb0bbe5c4584a32e6182e411680405e5` differs from formatted source bytes by design; parsed documents match.
- Adapter SHA-256: `32abd6e926674bb41971b7504c9e29652b729dabd1cc77ff96fdeffb37471b81`. This content hash identifies the validated adapter separately from the pinned main and accepted compiled runtime; later tooling-only commits do not retag the retained data candidate.

The accepted PowerShell 7.6.7 Linux x64 runtime and native executable/library pair were available. Ninety-one executed module/collector source files matched the retained accepted package; the existing download exporter was separately pinned to current main. Runtime hashes and complete executed-file inventory are in `runtime-equivalence.json`. No replacement runtime, build or dependency installation was used.

## Public acquisition and interpretation

Exactly three anonymous GETs, no retries, sign-in or token probes. The existing HTTP helper enforced the six-request/180-second acquisition ceiling, maximum two attempts per source, 30-second request waits, 8 MiB response limits and fixed raw.githubusercontent.com destinations. Each response and dispatch accounting receipt was retained before projection. The existing collector processed those frozen real responses via its file-input mode: this is **retained real public input, not synthetic fixture evidence**. Projection used zero additional requests.

| Source | Retrieved UTC | Raw bytes | SHA-256 |
| --- | --- | --- | --- |
| roadtools | 2026-11-14T05:49:00.9781397+00:00 | 2850287 | `4785005674c88780d0c055b4a5820ee6e8bca6a74a93df5885ea7c25a2d02b0e` |
| microsoftApps | 2026-11-14T05:49:01.4136321+00:00 | 843055 | `639df4125260c10ce78983caa7f059baf425f4b5ccca96319850542f63047f31` |
| resources | 2026-11-14T05:49:01.8855074+00:00 | 230402 | `a20ea8fadb3668f86c1e352697b6b456c5928684c5e820543b5d5cc59ea82bb7` |

The supported synthetic fixture first returned 3 candidates, 1 disagreement and zero HTTP requests (`checkpoint-01-fixture.json`). The real source projection returned 5,470 admissible candidates and 201 disagreements. MicrosoftApps accounting is 4,465 raw rows = 4,463 admitted + one zero-ID placeholder + one quarantine; 17 admitted spellings normalized. The quarantine is zero-based row 2,230, parsed-row hash `642a35288f00dd666fc2e7a9dbdbe1a86e5231335d9c2177874fe49cf4734152`; its raw ID has the suffix `\u00c2\u00a0`. No suffix was guessed away or promoted into an app ID. `diff.json` retains its exact escaped raw ID.

Raw retrievals occurred at the times above. The combined capture ended at `2026-11-14T05:49:01.8960836+00:00`; this fixed date supplies the new ledger observations. The collector's later projection time, `2026-11-14T05:49:36.1788975+00:00`, and its actual RecordedAt values remain separate. Normalization occurs only in a private copy of the new observation projection: the frozen exchange, older incoming history and all published historical dates remain intact. A later replay cannot substitute its wall-clock date for capture time.

The historical 5,455-record ledger and #127's older 5,467 local candidates are different datasets. Today's projection is 5,470. ID-set reconciliation, not subtraction of those headline counts, establishes the actual 15 additions, 6 content changes and zero removals. All published IDs were observed in this particular pass. The synthetic omission case additionally checks retained records when an ID is absent.

## Local candidate and diff

Artifacts are retained locally under `$TF_RECONCILIATION_ROOT` (not included in this tooling PR):

- `candidate-final/discovery-data/applications.json`: 19,930,075 bytes; SHA-256 `4e681b39da4f0b779d5d01d5f6b5caabcc682f2f6fa72fbcd031cc71d1b9011e`.
- `candidate-final/diff.json`: SHA-256 `8e4ada878ff0af374f9f6c4cba279765e1715b1032771b40813d19584ee94acf`. Contains all additions, before/after changed attributes, preserved omissions, source disagreements, cross-source overlaps, quarantine and unresolved classifications.
- `candidate-final/review.md`: readable additions and changed-field tables.
- `candidate-final/candidate-download.json.gz`: SHA-256 `e8836717f1c2732fc959c7e80e7ab72ed1765d70afeb02d15a7413167954208c`, created by the existing public exporter; semantic roundtrip and byte-stable replay are checked.
- `baseline-pin.json`: exact data commit, published manifest and every baseline file's hash/size. The source baseline is immutable in this procedure.

Counts: 5,470 final records; 15 additions; 6 content changes; 5,449 reobservations with unchanged content; zero removals, duplicate application keys, duplicate run IDs or duplicate exact historical versions. All original runs, historical versions and first-seen dates survive. Every non-applications path in the copied data tree, including all scope exports and historical downloads, is byte-identical to the baseline. The new gzip is separate; no historical download is overwritten.

Classifications are conservative public-source descriptions:

| Class | IDs |
| --- | ---: |
| CorroboratedPublicIdentity | 67 |
| CorroboratedPublicIdentityWithDisagreements | 35 |
| DocumentationOnlyCandidate | 3510 |
| ResourceOnlyCandidate | 663 |
| SinglePublicIdentityClaim | 1095 |
| UnresolvedMixedCandidate | 100 |

Independent corroboration requires application-identity claims from at least two distinct approved source locations. Documentation/resource-only claims cannot supply that proof; Graph and GitHub labels inside one MicrosoftApps file are not independent sources. Even corroborated public metadata is not tenant resolution, ownership, consent, issuance or API-access proof. The 1,046 existing permission-ID overlaps (1,047 definitions) are retained as a classification signal, **never a deletion list**. Unknown and conflicting identities remain visibly unresolved.

## Luna's one-command verification

Run from the worktree in a fresh output directory. It uses only frozen inputs and existing local runtimes; no network or authentication occurs. The optional reuse flag below verifies and reuses the two successful fixture outputs from the initial independent attempt rather than repeating them. Omit that flag for a completely new fixture execution.

```bash
# Set these to the retained evidence directory and existing accepted runtimes.
# No path below downloads, builds, authenticates, or publishes.
export TF_RECONCILIATION_ROOT=/absolute/path/to/retained-reconciliation
export TF_NATIVE=/absolute/path/to/accepted-package/tokenforge
export TF_PWSH=/absolute/path/to/powershell-7.6.7/pwsh
PYTHONDONTWRITEBYTECODE=1 python3 tests/PublishedApplicationReconciliation.test.py \
  --input-root "$TF_RECONCILIATION_ROOT" \
  --expected-output "$TF_RECONCILIATION_ROOT"/candidate-final \
  --work-root "$TF_RECONCILIATION_ROOT"/luna-review-new \
  --reuse-fixture-from "$TF_RECONCILIATION_ROOT"/luna-verification-01 \
  --native "$TF_NATIVE" \
  --pwsh "$TF_PWSH"
```

Pass/fail checklist (the verifier exits nonzero on failure):

- Fixture addition/change/omission produces the historical union, retaining old dates/versions and scope bytes.
- Two frozen fixture replays produce identical candidate/diff hashes with no duplicate IDs/runs/versions.
- An incomplete valid exchange preserves the exact baseline bytes and observation dates; omissions never become removals.
- Invalid member/hash input cannot promote an output candidate.
- Capture/projection date binding rejects false freshening and leaves the original frozen exchange untouched.
- Duplicate JSON identities are refused before filtering or selection.
- Documentation and same-source Graph/GitHub labels remain distinct from independently corroborated claims.
- Frozen real-input replay matches the final candidate, diff and existing public gzip export byte for byte.
- Every original baseline file and all scope exports remain unchanged.

The initial independent verifier stopped at a **test setup** error: copied fixture files retained mode 0400 and could not be mutated for negative tests. Only task-created copies were made writable; successful fixture/replay receipts and original logs were retained. The successful fixture/replay receipts remain in `luna-verification-01`; the second command used `--reuse-fixture-from` to verify them before continuing. `verification.json` records the combined checks, not a fresh execution of every fixture. Preliminary reconciliation attempts remain local and superseded by `candidate-final`; none is silently relabeled as final evidence.

Checkpoint files preserve fixture, captured responses, validated collection, and reconciliation phases. A quota interruption must resume from retained files/process state, not reacquire public inputs or reset a running operation. Incomplete/empty inputs retain baseline bytes, and invalid input never receives a completed candidate receipt. No application-universe completeness is claimed. This guide describes local evidence generation. Candidate publication, merges and workflow activation require separate authorization; publishing this tooling source does not publish the data candidate.

Independent acceptance: Luna completed 9/9 combined checks with zero verification network requests. Sol independently inspected the final artifacts, all 73 baseline paths, the 64 preserved historical runs plus one new run, dates/history multiplicities and source hashes. Both accepted the local candidate for review; no publication approval is implied.
