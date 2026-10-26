# Public metadata health review and proposed finishing goal

Review date: 2026-10-25. Reviewer: dot.

## Decision

The practical architecture fits Nathan's sole-trusted-admin model: short public-metadata collection on an ordinary GitHub-hosted runner, private transactional state and deeper work on the workstation, and untrusted contributions kept in quarantine until reviewed. Goal 6's original-ZIP, custody and activation research stays deferred.

The source and receipt chain are consistent, but full offline correctness acceptance is withheld for two medium-priority defects: an older distinct imported payload is omitted from SQLite history, and some schema-accepted source data aborts projection rather than producing an incomplete exchange. Existing database facts and immutable exchange evidence are not overwritten by either case. These are focused repairs, not reasons to add another deployment framework.

This is a source review, not a fresh test pass or hosted approval. The proposed goal below requires Nathan's adoption. No implementation, publication, collector requests, credential access or workflow execution was performed for this review.

## Exact reviewed evidence

- Owning checkpoint: [`bee9ad1f0240965840b8aa93a6e5acae1dba82f2`](https://github.com/nathanmcnulty/TokenForge/commit/bee9ad1f0240965840b8aa93a6e5acae1dba82f2), branch `codex/goal6-reusable-sealer`.
- Tested executable and package source: [`e93cdcc9764cf43347321b783f23c36526c60030`](https://github.com/nathanmcnulty/TokenForge/commit/e93cdcc9764cf43347321b783f23c36526c60030).
- Adopted practical design: [`50bb94bc38531834a73c3b8e46e3bebfde9ee467`](https://github.com/nathanmcnulty/TokenForge/blob/50bb94bc38531834a73c3b8e46e3bebfde9ee467/docs/tokenforge-runner-workstation-design.md), SHA256 `95ce7b6b421120434795d5c097dae89baba6df68d5f3eb17c5a82ee1248a9987`.
- [Producer validation receipt](https://github.com/nathanmcnulty/TokenForge/blob/bee9ad1f0240965840b8aa93a6e5acae1dba82f2/docs/public-metadata-health-validation.json), SHA256 `679c14e2f7edf4e8225e423337fb516150fbe33771cfcee76766da4e59f75ed9`.

Independently verified from repository bytes:

1. The ancestry from `91f858f8b7b70722223f4baa225a6cfc2ac340b6` runs through `64d259b07d84ea8c38381371e017e51dc9f25628`, `823bc65d5837e5d3f3b54291d0d209234b025cdc`, `d6041957b0a5b7cb1664e238e8f56c0bb7585676`, `b3549ccd268394cbbc6275be5316c605c7093e5f`, and `e93cdcc9764cf43347321b783f23c36526c60030`, then the reviewed checkpoint.
2. The receipt commit changes only `docs/HANDOFF.md`, the new validation receipt and the dormant workflow's package-hash value. Executable and test bytes are unchanged from the tested source. All 16 source hashes listed in the receipt match. The workflow hash describes the final dormant template, not its earlier placeholder.
3. The adopted design is unchanged. Active `.github/workflows` files remain unchanged from the starting owning checkpoint. Comparison of 57 native-related repository paths with the stated native baseline found only the two disclosed packaging-helper changes, not compiled-source changes.

Producer-reported, not independently rerun here: 123 tests passed with zero failures/skips; 167 package payload files and 93 current source bindings; 100 native-input comparisons; and the exact-package synthetic performance run. The private package, raw logs and full baseline manifest were not independently obtained for this review.

The performance report describes 5,502 candidates and 100,000 scope edges: collection 60.165 seconds, initial import 131.830 seconds, repeated import 39.704 seconds, saved status 0.146 seconds, total 231.850 seconds against a 300-second fixture gate. The 0.146-second result is status, not repeated import. Reported memory is the parent PowerShell process only, not total process-tree memory. These are synthetic measurements, not current-source or hosted performance.

The available reviewer installation is PowerShell 7.6.6; the candidate requires exactly 7.6.7 on Linux x64. No pin was bypassed, substitute runtime installed or candidate test executed. Static findings below were independently traced in the actual source. The reported test results remain producer evidence; the findings identify coverage gaps, not fabricated test results.

## Material findings

### M1 Older distinct payloads disappear from the SQLite history projection

In [`ApplicationCatalogStore.Import`](https://github.com/nathanmcnulty/TokenForge/blob/e93cdcc9764cf43347321b783f23c36526c60030/native/TokenForge.Core/ApplicationCatalogStore.cs#L97-L112), an incoming current record goes through `MergeRecord`; only its explicit `PreviousVersions` are then inserted as history. The [older-record branch](https://github.com/nathanmcnulty/TokenForge/blob/e93cdcc9764cf43347321b783f23c36526c60030/native/TokenForge.Core/ApplicationCatalogStore.cs#L172-L193) adjusts first-seen/presence data but does not save a differing older current payload as a historical version.

Safe synthetic regression specification: collect independent complete exchange A at t1 and changed exchange B at t2 for the same application and origin, each with no previous exchange. Import B, then A, then A again. B correctly remains current, but A's payload currently never appears in SQLite history, despite both run receipts being imported. The immutable A exchange receipt survives, so this is missing database history rather than destruction of all evidence. The existing out-of-order test uses a partial exchange retaining the same payload and does not exercise this case.

Required outcome: retain the older distinct payload as deduplicated history without regressing current values, presence or freshness. Repeating A must not multiply historical versions. Check the normal A-then-B order and unchanged private origins as well.

### M2 Accepted source data can bypass incomplete-exchange handling

The [health source validator](https://github.com/nathanmcnulty/TokenForge/blob/e93cdcc9764cf43347321b783f23c36526c60030/scripts/TokenForgePublicHealth.ps1#L109-L117) permits up to 4,096 scopes per resource. A valid ROADtools fixture with 1,001 distinct names such as `Scope0001` through `Scope1001` passes that check and survives catalog deduplication. The [native source-claim projector](https://github.com/nathanmcnulty/TokenForge/blob/e93cdcc9764cf43347321b783f23c36526c60030/src/TokenForge/Core/DiscoverySourceClaims.cs#L132-L155) refuses arrays over 1,000.

The source is already marked successful when [combined projection runs outside source-error handling](https://github.com/nathanmcnulty/TokenForge/blob/e93cdcc9764cf43347321b783f23c36526c60030/scripts/Invoke-TokenForgePublicHealth.ps1#L34-L79). Its exception deletes the staging directory, so no incomplete health exchange is emitted. The prior exchange and database remain intact, but the documented invalid-source fallback is missing.

Required outcome: align source acceptance with the actual projection contract before claiming source success, without weakening catalog validation. Recognized source/projection validation failures must produce sanitized incomplete health evidence and preserve the previous metadata bytes and dates; without previous evidence, use the existing empty incomplete contract. Do not disguise unrelated runtime, storage or programmer failures as valid source results. Exercise the real fixture entry point with the 1,001-distinct-scope case and the boundary success case.

## Boundaries and honest limitations

The reviewed path uses three fixed public URLs, no inferred account credentials, charged request budgets, capped streams, fixed REST User-Agent and no automatic source redirects. Incoming exchanges undergo full public-only validation before transactional import into a mixed private database. The import does not replace inventory, cohort, plan or flow evidence. Locks and pending evidence support competing-writer refusal and idempotent reconciliation. Contributions remain reports, not imported truth or additional collection URLs.

Named artifact transfer checks independently selected repository/workflow/run/source/ref values. It accepts attempt one only, rejects ambiguous selection, does not forward REST authorization to the artifact capability URL, and validates exactly three bounded members. This practical contract concerns member bytes and schemas, not equality with a producer-created outer ZIP. No live transfer or archive experiment was performed for this review.

Keep these limits visible:

- The dormant hosted template supplies no previous exchange. Standalone snapshots are additive and do not propagate source removals into destination-wide tombstones. A linked complete history can represent absence; an unlinked empty snapshot intentionally cannot erase destination records. Do not present the current hosted proposal as an authoritative latest-membership reconciliation service.
- The collection timer starts after initialization/previous-exchange validation. Network waits are cancelled within request/remaining budgets, but synchronous projection and validation are not preempted mid-step. Describe the 600-second collection and 180-second transfer limits as cooperative acceptance budgets, with separate native-call limits and the proposed outer job timeout, not exact wall-clock termination guarantees.
- Producer evidence explicitly does not claim a complete fresh three-source snapshot. Current upstream freshness and actual hosted transfer remain unverified.
- The workflow is outside `.github/workflows`, its job condition is literally false, package public delivery is absent, and its workflow ID is an intentionally invalid pending-registration placeholder. A local green gate is not permission or proof for a hosted run.

## Proposed consolidated finishing goal

This is one goal for Nathan to adopt, not authorization already granted by this review. Start from owning checkpoint `bee9ad1f0240965840b8aa93a6e5acae1dba82f2`, not the older source on the documentation handoff branch.

1. Repair M1 and M2 with the concrete regressions above. Keep all private-domain and source-policy boundaries intact. Clarify cooperative timing and standalone-snapshot semantics in the operator guide and final receipt.
2. Produce a matching exact-source package and run the PublicHealth validation preset, including its existing catalog, claims, SQLite, download and CLI coverage, plus the new regressions. Recheck bounded synthetic performance against the final kit. M1 changes native code: rebuild and verify the affected native payload with the approved toolchain, update exact pins and package provenance, and replace the old unchanged-native claim. Do not relabel the old binary as fixed. Use already approved dependencies/runtimes; report a missing toolchain explicitly instead of installing or bypassing a pin without authorization.
3. Complete independent review and one sanitized source/test/docs checkpoint on the existing owning branch `codex/goal6-reusable-sealer`. On adoption of this goal, that final source checkpoint push may use existing Git authentication/signing only as needed, with no new credentials or permissions, no force, PR, merge or workflow dispatch. Preserve private receipts and raw responses outside the public repository. Return the exact pushed revision, tested-source/package hashes, counts and any remaining limitations in one consolidated result.
4. End with one decision-ready manual hosted-trial proposal, not another abstract fake layer. Name the exact reviewed package and delivery method, runner/runtime and action pins, trusted source revision, proposed default-branch/workflow registration diff, concrete workflow identity procedure, read-only permissions, public output/log contents, retention and stop procedure. Address how legacy workflows remain unmodified and are neither enabled nor dispatched, verifying actual platform state before the separately approved trial, and how the tested runtime is provided without a surprise install. The first trial is one public-only job, one matrix-free Linux runner, a ten-minute job timeout and exactly three explicitly named public-safe output files. Its useful observation is whether the real fixed sources and normal artifact path work under these limits, including an honest incomplete-source result.

The finishing goal does not authorize publishing a binary package/release, changing default-branch workflows/settings, merging, enabling or dispatching Actions, adding a schedule, using real runtime/account credentials, performing external collection/transfer or operational signing/publication. Those concrete trial actions require a separate bundled approval after the repaired checkpoint is reviewed. Public source collection needs no Entra or account credentials; GitHub artifact read authorization, if required, is a separate explicit minimum-read decision. A daily schedule follows a successful approved manual trial and a separate scheduling decision.

Acceptance of the repaired offline loop is not Goal 6 completion, a universal GitHub feasibility claim, or approval to run deeper account discovery on hosted runners.
