# Goal 2 offline acceptance

Goal 2 is **offline-ready** at source `08fb8e4a41c307b858476d877aa922c611a54683` on `codex/goal2-trustworthy-change-reports`. The Pester 6.2.0 migration is complete at `63a782b4e54d84c0a947e78a3d6456d919748f9d`. This is saved-evidence comparison acceptance, not live/production validation or a Microsoft-side root-cause claim.

The roadmap handoff `19470aeba7a949e4204e4ecf5586a6ffb3171c69` remains preserved as `handoff/goal1-19470ae`. Goal 1 canary completion remains documented at `68ae5749bbc609937290e2209a5cda89375d7313`; this milestone performed no new authentication, live discovery, API acceptance check, tenant permission change or remote publication. Goal 3 was not started.

## Acceptance evidence

| Gate | Result |
| --- | --- |
| Actual `scripts/Test-TokenForge.ps1` entrypoint, fresh PowerShell process | 1041 passed, 0 failed, 4 platform skips, 0 failed containers; 1045 cases across 66 test files |
| Goal 2 focused selection | 80 passed, 0 failed, 0 skipped; native/PowerShell parity, actual bounded producer, JSON/SQLite/metadata persistence, descriptor tampering, no-PowerShell PATH, private-file and full-input rejection fixtures |
| Native core harness | 1,086 checks passed, including flow and application catalog transactions |
| Existing native workflow selection | 340 passed, 0 failed, 3 platform skips across 21 files, derived from the actual full-suite per-file results; pinned expected 340 unchanged |
| Complete package | 137 payload files plus manifest; all 76 module source files byte-match the source checkpoint; 86 build inputs and 68 validation files verified |
| Independent review | Findings fixed with adversarial fixtures; final static audit found no outstanding material issue. Archive, exact member set, all payload/input hashes and module source bytes independently verified; final counts, evidence hashes and requirement audit independently reconciled |
| Execution boundary | Linux x64 only; all seven workflow files unchanged and manual-only; no hosted run dispatched |

Build used the existing approved .NET SDK **10.0.401**, PowerShell **7.6.7**, and Pester **6.2.0**. Restore was locked with all feeds cleared; the build confirmed cached dependencies were up to date. No dependency installation was needed. Changed shared/native source was rebuilt; the older Goal 1 binary was not used to validate it.

The initial uncommitted v1/v2 drafts exercised the new executable and DLL but were excluded as acceptance packages because the tracked-files copier omitted four then-untracked module files. The final package was built after the reviewed source checkpoint; completeness and packaged-only consumer smoke then passed.

## Exact package provenance

| Artifact | Revision or SHA-256 |
| --- | --- |
| Source | `08fb8e4a41c307b858476d877aa922c611a54683` |
| Local package manifest | `ee67dff9df60064cf6abafda9905609a841c96346d58b52467df9aa3a0d85875` |
| Linux x64 archive | `ffaae9c7b1e297886a3723414e4771f0e216cf5764bc99aaccc0b25bda538df2` |
| Native executable | `a58ea6a623662474b3a1c0490d4ef8b55b3bbd19181d41807ac8f4c712e73dbb` |
| Shared net8.0 credential/core DLL | `fae3f09ce49251982177bccfc3f32425565983e045d0f85aaa2825d0510e6437` |
| Native build-input aggregate | `7dac8e7b96617f34a8f9a9bc2d959f5f5ebc781e645f09e558abd4aeeccca8d3` |
| Validation-input aggregate | `a000c247caddd17017fa07cfcec80707096897cbcbdbb4c4209207fb2bf4fae5` |

Local archive: `.cache/goal2/TokenForge-0.48.0-goal2-linux-x64.tar.gz`. Complete extracted package: `.cache/goal2/package/linux-x64`. These local ignored artifacts are unpublished. The manifest enumerates the complete payload and build inputs; [the JSON receipt](goal2-validation.json) pins the package and validation evidence hashes.

## Requirement audit

| Requirement | Accepted evidence |
| --- | --- |
| G2.1 — Five typed evidence domains and versioned events | 65 shared-engine/source-adapter fixtures; 15 native consumer/persistence cases; strict version-1 typed snapshots and reports. |
| G2.2 — Stable permission IDs, kind, name, enabled state and origin; rename distinct from addition/removal | Stable-ID rename and absence fixtures; same ID/name across delegated and application kinds remain separate; private namespace/origin checks. |
| G2.3 — Source-specific public hints and conflicting claims remain separate from consent/grants | Discovery source adapter aggregates source/client variants, retains claims and conflict hashes, and downgrades missing/mixed legacy projections. |
| G2.4 — Visible configured grants retain tenant/observer, query coverage, beneficiary and consent type | Inventory coverage receipts describe unchanged queries. Genuine aggregate-edge scope changes compare; unknown beneficiary, changed observer and inaccessible coverage cannot remove. |
| G2.5 — Issued-scope comparison uses exact verified request and execution context | Bounded producer saves constructed scope selection, authority, protocol, callback/SPA class, recipe and execution-policy fingerprints before dispatch; JSON/native stores prevent descriptor changes through completion. |
| G2.6 — Optional API response evidence requires operation/version/account and separate approval context | Saved ApiChecks adapter; complete operation context compares response changes, legacy missing operation context stays incomparable. Reports execute no API check. |
| G2.7 — No false removal from baseline, changed recipe, incomplete/missing/denied collection, failure, stale or unknown evidence | Adverse fixtures cover all statuses, changed request fields, reversed/future chronology, conflicting simultaneous histories, empty collections and missing projected definitions. |
| G2.8 — Latest attempts, retained last success and original dates remain distinct | Success/failure/recovery and maintenance interval fixtures; context/source-bound success reference; failed collection does not refresh last success; source-observed date remains independently nullable. |
| G2.9 — Anonymous evidence cannot establish private removal or authorization; provenance and uncertainty remain reviewable without credentials | Public-only rejection, anonymous incomparability, strict full-input validation, record/source hashes and locations, explicit per-entry reasons, no root-cause or authorization claim. |
| G2.10 — Important suspected issuance regression confirmation remains separately authorized | Reports always mark RegressionConfirmation=NotPerformed and RootCauseEstablished=false. Synthetic changes are not live regressions. No Goal2 live confirmation performed or required for this offline milestone. |
| G2.11 — Shared native and PowerShell saved-evidence consumers and a matching complete Linux package | Ordinary scope database comparison uses the shared engine; native and PowerShell explicit-path parity, package-only consumer smoke, no-PowerShell PATH tests, SQLite/metadata persistence and verified complete package. |

## Limits and follow-up approval

There are no remaining offline blockers. Legacy rows missing full request/query/observer provenance stay unknown or incomparable; no historical context was invented. Public hints and anonymous observations establish neither configured tenant grants nor account authorization. Maintenance history preserves its original success dates alongside the latest run status. New `ComparisonContext` receipts are immutable through Started-to-terminal completion and do not alter legacy resume hashes.

Important suspected issuance regressions would require separately authorized confirmation under the same verified request and a finite request/time budget. No real regression was identified or confirmed by these synthetic fixtures, and no new live canary is necessary to accept this offline reporting milestone. Any new live confirmation needs explicit approval of the account, exact saved request, and bounded execution policy; reproduction would still not establish root cause.

Use the commands and focused local `Changes` preset documented in [the change-report contract](goal2-change-reports.md). All requested work remains in local commits; no push, PR, merge or release was performed.
