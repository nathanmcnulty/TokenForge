# Public health: isolate the MicrosoftApps input rejection

## Consolidated next goal

Prepare one reviewable milestone that isolates the MicrosoftApps input-contract rejection, adds bounded diagnostics and focused regressions, and preserves the existing incomplete-exchange behavior. Review candidate source independently before executing it. Finish with one exact-source receipt and handoff, not another hosted run.

This is a proposed consolidated work scope for the owning TokenForge session. Honor the user's existing authority there for ordinary anonymous public-source reading, investigation, corrections and local offline testing; no separate approval is introduced for each harmless read or already-authorized test. The document itself does not grant new privileged authority. Explicit adoption may bundle a sanitized source/result checkpoint publication within the agreed scope, while the separate operational boundaries below remain in force.

Intended review-document branch: `codex/dot-goal6-review-handoff-20261024`.

## Verified checkpoint and result

- Owning result checkpoint: [`4b95c76f3a7eccf4fafc67d9e76d7563a12e5c74`](https://github.com/nathanmcnulty/TokenForge/blob/4b95c76f3a7eccf4fafc67d9e76d7563a12e5c74/docs/HANDOFF.md).
- Reviewed product checkpoint: `3c1e274af04c22c8ef6db651dd025c2ad6739217`; tested native/package source: `c7d0b255612280e05605eca2e9ccfb44d5d68e18`.
- Exact hosted trial head: `04e89350b74e1a600c233aa43572a80a6f3ea642`, branch `codex/public-health-manual-trial-20261025`. Its parent is `589357448104ca6f5d0239138d0094dff57057db`; the commit changes only the reviewed workflow shell wrapper.
- [Run 40161542664](https://github.com/nathanmcnulty/TokenForge/actions/runs/40161542664), attempt 1, workflow ID `395612174`, repository ID `1402673320`, completed successfully. The single Ubuntu 24.04 job passed runtime/package checks and artifact upload.
- Aggregate result: `CollectionComplete=false`, `ExchangeComplete=true`, `ImportComplete=false`, `OperationalPublication=false`, `CandidateCount=0`, `ConflictCount=0`, three requests, 33.429 seconds.

The approved private artifact inspection independently verified artifact `12586302492`, named `tokenforge-public-health`, from that exact run:

- Archive size: 1,472 bytes.
- Archive SHA-256: `944b5ac4d1632f72b423c7abde37c7d86e07e2855b8be01b5a06474774129618`.
- Exactly three regular, unencrypted members: `manifest.json` (803 bytes), `health.json` (1,304 bytes), `metadata.json` (227 bytes). Expected names, member types, bounded sizes, unique membership and CRC checks passed; no extraction or member execution was needed.
- Manifest size/hash bindings and exact repository/workflow/run/attempt/head/branch context matched independently observed run metadata.
- `health.json` SHA-256: `9da8359275bfd51cbb394cbf10afda36d4f759532afb5bc0426039734ba46995`.
- `metadata.json` SHA-256: `6d69757781376f9ba93d10db15fe93fe834139a5790d8e9b6795e44ecd69a8fd`.
- Independent static JSON shape, date, status, count and empty-ledger checks passed. These were not executions of the product validator or importer.

Source observations, each with one attempt:

| Source | Status | Source record count | Retained source hash |
| --- | --- | ---: | --- |
| ROADtools | Success | 506 | `4785005674c88780d0c055b4a5820ee6e8bca6a74a93df5885ea7c25a2d02b0e` |
| MicrosoftApps | Invalid | 0 | None |
| Resource candidates | Success | 1,753 | `a20ea8fadb3668f86c1e352697b6b456c5928684c5e820543b5d5cc59ea82bb7` |

Collection time is `2026-10-25T04:21:02.3604975+00:00`. `lastCompleteAt` is null. The metadata ledger has empty Applications, Origins and Runs. The successful source counts are source observations, not a merged catalog count.

## What this establishes, and what it does not

The failure is localized to MicrosoftApps parsing/input validation or its single-source projection. The collector classifies transport/non-success response failures as `Unavailable`; this source instead reports `Invalid`. A combined-projection failure would invalidate all sources, which did not happen here.

The exact offending field, record and reason remain unknown. The artifact contains neither failed-source raw bytes nor their hash nor a precise reason code. Its source schema contains only name, URI, status, attempts, last-success date, hash, candidate count and changed. Correct the result receipt's implication that detailed failure reasons already exist in the artifact.

With no previous exchange and one invalid source, the collector intentionally emits an empty ledger. Zero combined candidates does not establish empty upstream sources. The valid exchange/upload proves the incomplete-result path, not a complete fresh catalog, workstation import or operational readiness.

A current fetch cannot recover the historical response. Even if a new MicrosoftApps document reproduces the failure, label it current-input reproduction, not proof of the bytes received by run 40161542664. Do not infer a timeout, malformed GUID or any other particular cause from aggregate timing.

## One bounded diagnostic and correction milestone

1. Inspect the existing MicrosoftApps parser, validator and single-source projection without executing candidate changes. Enumerate the exact acceptance contracts and the points currently collapsed into `Invalid`.
2. Prepare a bounded diagnostic proposal for only the already fixed MicrosoftApps URL: `https://raw.githubusercontent.com/merill/microsoft-info/main/_info/MicrosoftApps.json`. Use the owning session's existing authority for ordinary read-only public retrieval. Prefer one anonymous GET, no redirects or automatic retries, existing 8 MiB/30-second request bounds, no credentials and no additional sources. If it fails or exceeds bounds, stop with a sanitized result rather than broadening collection.
3. If fetched, keep the response private and immutable, record acquisition time, exact URL and SHA-256, and distinguish this new evidence from the historical trial. Use bounded parsing and contract inspection to identify the rejected contract. Do not publish raw responses or arbitrary upstream strings.
4. Add a small fixed allowlist of diagnostic reason codes distinguishing transport/HTTP, JSON decoding, source shape/identity validation and source projection failures. Preserve `Success`/`Unavailable`/`Invalid` semantics. Never emit exception messages, raw field values, URLs supplied by input, tokens, account data or unrestricted free text. If the public exchange schema changes, update producer, strict reader, fixtures and compatibility documentation together. A private diagnostic-only result is also acceptable if it solves the goal without changing the exchange contract.
5. Fix only demonstrated contract mismatches that are safe and intentional. Do not silently repair malformed identifiers, drop invalid records to manufacture completeness, weaken private-field rejection or broaden accepted sources. A valid outcome may be a precise rejection with useful diagnostics rather than acceptance of the source.
6. Add focused regression coverage for the demonstrated input category, fixed reason codes, redaction and the existing contract boundaries. Preserve successful ROADtools/resources observations, no transient retry for schema-invalid input, all-sources-required complete catalog creation, empty initial incomplete ledger, and byte/date preservation of a previous complete ledger. Unexpected storage/programmer errors must remain visible failures, not be converted into input-health status.
7. Submit the candidate source and test diff for independent source review before candidate execution. Resolve findings first. Under the owning session's existing or adopted execution scope, run the local offline regressions and applicable acceptance checks against the exact candidate revision/package; do not use an automatic live collector or hosted workflow as a test shortcut.
8. Return one consolidated exact-source receipt and handoff. Separate independently checked facts from producer-run test results, and identify anything not run. Record source/parent revisions, changed files, diagnostic input hash/time if acquired, fixed reason codes, regression and acceptance results, package/native inventory implications, outstanding findings and authorization boundaries.

Acceptance means the failure class is explained at the precision supported by the available evidence, diagnostics are bounded and safe, regressions preserve prior behavior, and the exact candidate is independently reviewed. It does not require making invalid upstream data pass, or claiming historical-byte reproduction.

## Stop boundaries

No automatic hosted dispatch or rerun; no artifact sync/import or saved-evidence reuse; no Entra sign-in, grants, credentials or tenant changes; no legacy workflow activation, scheduling or repository Actions setting changes; no release assets, operational publication, PR, merge or deployment without the applicable separate approval. A sanitized source/result checkpoint may be published when explicitly included in the adopted milestone scope; do not include private evidence. The original strict Goal 6 custody/ZIP experiment remains deferred. Do not fetch other sources or expand the investigation without a separately justified decision.

The completed inspection downloaded only the approved artifact privately. It did not execute its members, execute the product validator, extract files, import, sync, probe upstream sources, modify repository state or rerun collection. Do not commit the downloaded archive or private diagnostic evidence.

## Sources

- [Sanitized trial receipt](https://github.com/nathanmcnulty/TokenForge/blob/4b95c76f3a7eccf4fafc67d9e76d7563a12e5c74/docs/public-health-manual-trial-result.json)
- [Exact trial shell-only change](https://github.com/nathanmcnulty/TokenForge/commit/04e89350b74e1a600c233aa43572a80a6f3ea642)
- [Exact collector source](https://github.com/nathanmcnulty/TokenForge/blob/04e89350b74e1a600c233aa43572a80a6f3ea642/scripts/Invoke-TokenForgePublicHealth.ps1)
- [Exact shared validators and transport](https://github.com/nathanmcnulty/TokenForge/blob/04e89350b74e1a600c233aa43572a80a6f3ea642/scripts/TokenForgePublicHealth.ps1)
