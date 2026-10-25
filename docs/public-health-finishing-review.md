# Public health finishing review and bounded trial decision

Review date: 2026-10-25. Reviewer: dot.

## Conclusion

The original two medium-priority findings are fixed at the reviewed source: standalone older distinct payloads are retained, and recognized source/projection failures produce honest incomplete exchanges. The public-health architecture remains proportionate to Nathan's sole-admin model. No dedicated runner, signed-plan framework or revival of Goal 6 custody research is warranted.

Accept the original corrective milestone by source review, with the evidence limits and narrower history-occurrence issue below. Do not describe the generic importer as preserving every possible historical occurrence. The manual-trial packet also needs an explicit branch correction before it can be approved as written. This is not another broad implementation milestone: the corrected finite trial scope is specified below.

No candidate execution, runtime installation, external collection/transfer, credential access, workflow operation, publication or merge was performed in this review.

## Exact evidence and verification limits

Reviewed owning checkpoint: [`3c1e274af04c22c8ef6db651dd025c2ad6739217`](https://github.com/nathanmcnulty/TokenForge/commit/3c1e274af04c22c8ef6db651dd025c2ad6739217).

Tested and rebuilt source: [`c7d0b255612280e05605eca2e9ccfb44d5d68e18`](https://github.com/nathanmcnulty/TokenForge/commit/c7d0b255612280e05605eca2e9ccfb44d5d68e18), directly descending from `bee9ad1f0240965840b8aa93a6e5acae1dba82f2`.

The reviewed checkpoint directly follows c7d0b25 and changes only `docs/HANDOFF.md`, the finishing receipt, the manual-trial proposal and the dormant workflow template. Executable/test inputs remain those of c7d0b25. All 12 SHA256 values in the [finishing receipt](https://github.com/nathanmcnulty/TokenForge/blob/3c1e274af04c22c8ef6db651dd025c2ad6739217/docs/public-metadata-health-finishing-validation.json) independently match fetched repository bytes. The adopted review is unchanged. Active workflow files are unchanged from bee9ad1. The tracked native-input selector resolves to 100 files, and current module plus health entry points account for 93 source bindings.

The package builder now requires a complete tracked native-input inventory, matching source revision and payload bytes, rejects untracked extra data and links, and independently enforces the new native/DLL pins. The old unchanged-native assertion is no longer used for the new kit. This verifies the source of those checks; this reviewer did not obtain or independently hash the private archives and their build receipts.

Producer-reported evidence: 141 Pester tests, zero failures/skips; 1,157 native checks; and a frozen 5,502-candidate/100,000-edge exact-package run totaling 274.479 seconds against 300 seconds. Collection was 92.136 seconds, import 143.894, repeated import 38.298 and saved status 0.145. That leaves 25.521 seconds in the synthetic gate, not a hosted throughput guarantee. Memory covers the parent PowerShell process only. The native result is reported from the implementer's transcript, without a persisted raw log. The other reviewer independently ran the combined-claims regression and audited the kit; that is not an independent rerun of the entire suite.

This review's available PowerShell installation and wrapper resolve to 7.6.6; the candidate still requires exactly 7.6.7 on Linux x64. No pin was bypassed and no candidate suite was executed here. Current upstream completeness, Ubuntu compatibility, real artifact interoperability and actual Actions/settings state remain unproved, as the receipt states.

## Repair verification and residual finding

### Original M1 is fixed with a narrower occurrence limitation

The [older-current merge branch](https://github.com/nathanmcnulty/TokenForge/blob/c7d0b255612280e05605eca2e9ccfb44d5d68e18/native/TokenForge.Core/ApplicationCatalogStore.cs#L191-L198) now saves an older differing current payload as a historical version. Native and actual sync regressions cover standalone B then A then repeated A, normal order, current/presence/freshness preservation, private-origin isolation and reconciliation with explicit linked history.

One low-severity corner remains: an older linked ledger A(t1), C(t1), A(t1), with the exact same observation timestamp, imported beneath newer B(t2), should retain A, C, A beneath B. Instead the new automatic save requests occurrence one for current A, and the [explicit-history loop](https://github.com/nathanmcnulty/TokenForge/blob/c7d0b255612280e05605eca2e9ccfb44d5d68e18/native/TokenForge.Core/ApplicationCatalogStore.cs#L105-L112) independently starts its occurrence count at one. The historical A is then treated as already saved. Both distinct values survive, but one legitimate occurrence is omitted. The new equal-date test exercises a newer linked import, not this older-linked case.

This is a static source finding, not an executed reproduction. A future narrow repair should count explicit incoming history and the retained older current payload together, then verify that repeating the import adds nothing. It is not a privacy or authority escape, and does not block the proposed first public collection trial, whose collector generates fresh observation timestamps. Keep it recorded rather than making an unrestricted history-completeness claim.

### Original M2 is fixed

The [health source contract](https://github.com/nathanmcnulty/TokenForge/blob/c7d0b255612280e05605eca2e9ccfb44d5d68e18/scripts/TokenForgePublicHealth.ps1#L113-L118) now limits raw scopes to 1,000. Each source and the combined input pass the actual projection before the collection is accepted. Narrow typed input failures become incomplete output, while unrelated storage and programmer failures remain fatal. Regressions cover 1,000/1,001 scopes, with and without previous evidence, malformed shapes, userinfo-bearing URI rejection, and 257 combined claims. Previous metadata bytes and dates are preserved rather than falsely refreshed.

## Correct the trial revision plan

The [current packet](https://github.com/nathanmcnulty/TokenForge/blob/3c1e274af04c22c8ef6db651dd025c2ad6739217/docs/public-metadata-health-manual-trial.md#L20-L33) proposes one workflow-only addition on the default branch and dispatching that branch, while requiring its code and ancestry to match the reviewed owning checkpoint. Current main is `1be12d75c7e2a63eac8e14c32d54e79cec4a23ef`; c7d0b25 is 68 commits ahead. Main lacks the health scripts and has different CLI/module bytes. A workflow-only main change cannot satisfy those requirements; the checked-in source-binding gate would correctly refuse.

GitHub requires the manually dispatchable workflow to exist on the default branch, but permits selecting another branch for the run. The workflow version is taken from the event ref. Therefore default-branch registration does not require silently promoting all 68 product commits. See [manual workflow dispatch](https://docs.github.com/en/actions/how-tos/manage-workflow-runs/manually-run-a-workflow) and [workflow ref semantics](https://docs.github.com/en/actions/concepts/workflows-and-actions/workflows).

The minimum corrected proposal is:

1. Register `.github/workflows/public-metadata-health.yml` on main with the job still false. Preserve every existing main file. Read the registered numeric workflow ID; never treat the placeholder as valid.
2. Create proposed trial branch `codex/public-health-manual-trial-20261025` from exact checkpoint `3c1e274af04c22c8ef6db651dd025c2ad6739217`, then add the same workflow path, bound numeric ID and enabled trial job, with no executable/module/health-script changes. Inspect any existing branch rather than overwriting it. Record the exact resulting commit. Main's job can remain false. Do not merge the product branch into main for this trial.
3. Dispatch that named branch once, after verifying its head equals the reviewed trial commit. Check the observed run's head SHA and ref before accepting results; a branch move or mismatch stops acceptance rather than authorizing an unreviewed revision. Workstation sync uses that exact observed run/source/ref, not main or an arbitrary latest run.

This recommendation is a proposed replacement for the packet's contradictory default-branch dispatch instructions. It grants no permission to make those changes now. Selecting and registering the final branch/ID must be included in the eventual reviewed approval scope.

## Minimal separate approval scope

After ordinary read-only settings, branch-rule and archive checks, request one bounded authorization package covering:

- Publish only the exact product archive, SHA256 `2b92b0d0662809f3aeaf4992935cc38323c78d8223430b5f58eb9216156ef3e8`, 33,630,055 bytes, and repackaged PowerShell archive, SHA256 `3da36d92808db25aa2466422b1b765da792adc159d890512fbae852e2b495d3b`, 75,877,688 bytes, under the named `public-health-offline-20261024` release in public `nathanmcnulty/TokenForge`. No replacement of conflicting existing assets. The publishing executor must verify complete archive inventories, safe paths, notices and absence of private material before upload, especially for the repackaged installed runtime tree. This is ordinary publication hygiene, not a custody framework or an assertion that unsafe contents were found.
- The exact two-ref workflow-only registration and trial changes described above, through the permitted branch-protection path without weakening repository rules. If a workflow-only PR/merge is required, identify that exact additional action in the approval rather than inferring broad merge authority. Read current workflow/settings state first. Any security-sensitive Actions setting change needs its own explicit, concrete approval at the time; broad permission for unspecified settings is not sufficient. Do not enable or dispatch legacy workflows.
- One matrix-free Ubuntu 24.04 Linux x64 job with a ten-minute outer timeout, the exact reviewed action/runtime/package pins, no installation fallback, read-only contents permission, no Entra/account credentials or identity-token permission, and only the three fixed public sources. Keep six charged requests, two attempts per source, 30 seconds per request and the 480-second cooperative collection budget. Failure or an incomplete-source result does not authorize another run or broader collection.
- Public output limited to `manifest.json`, `health.json` and `metadata.json` in `tokenforge-public-health`, requested retention 14 days, with sanitized logs and no raw responses or private state. Record the actual platform visibility/retention and exact run identity. Include permission to cancel only this trial if needed; other cleanup or settings operations remain separately scoped.

Normal artifact download/sync and any required minimum GitHub artifact-read authorization remain an explicit additional choice, separable from the credential-free collection job. Neither collection nor sync needs Entra authentication. A successful upload alone does not establish the unrun workstation download path. No automatic schedule, account discovery, broad main promotion, unrelated merge or Goal 6 activation is included.

No new general fake layer is recommended. The next decision is the corrected, finite trial scope, with the low-severity importer corner recorded and the existing evidence limits kept honest.
