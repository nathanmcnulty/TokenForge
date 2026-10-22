# Goal 1 canary: collection finished, assessment includes two declines

**The ambiguous pause is fixed and all ten frozen pairs have terminal evidence.** Eight succeeded, one is request-blocked and one failed. Nothing remains pending, paused or in-flight unknown. Fresh-process status intentionally reports `Failed`, exit 1, because one pair failed; collection completion does not mean every request succeeded. API acceptance, universal application support and production readiness are not established.

## Confirmed cause and scoped fix

The fourth pair's token endpoint returned HTTP 400 `invalid_request` with `AADSTS9002327`: a token issued for a SPA callback can only be redeemed in its required cross-origin context. The frozen canary uses the non-SPA PKCE request mode. Published callback hints alone did not establish the platform configuration of that callback. Microsoft documents the [SPA/non-SPA and Origin restriction](https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth2-auth-code-flow#redirect-uris-for-single-page-apps-spas); the exact numeric description is available from the [official error lookup](https://login.microsoftonline.com/error?code=9002327).

The collector's narrow numeric allowlist discarded this code and its conservative fallback called the result `SessionPaused`. Renewing the session could not fix this request/platform mismatch. `Private/ProbeFailure.ps1` now retains exact codes `9002325`, `9002326`, and `9002327` as request-scoped `RequestBlocked` evidence. These codes can also indicate caller/configuration errors; they do not prove that every collector parameter is correct. Budget, transport uncertainty and evidenced session failures retain priority, and unknown failures still pause.

No Origin header, SPA mode, callback, protocol, cohort membership or tenant permission was changed. No legacy row was rewritten. The renewed frozen request produced a new primary attempt with exact code `9002327`, confirming the diagnosis before any of the remaining six pairs were dispatched. The three earlier completed cells were skipped and their original attempt IDs, dates and content hashes were preserved.

A separate selected pair failed with `AADSTS7000218`, requiring a confidential-client credential for that request. None was supplied or sought. It remains an explicit failed assessment rather than a missing cell or an invitation to change permissions. Making either declined request succeed would require a separately scoped flow/client-credential decision; it is not required to finish collecting this frozen canary's outcomes.

## Evidence and boundaries

| Saved result | Pairs / known cells |
| --- | --- |
| Succeeded | 8 |
| RequestBlocked, code 9002327 | 1 |
| Failed, code 7000218 | 1 |
| Pending / Paused / InFlightUnknown | 0 / 0 / 0 |
| Frozen pairs / materialized cells / terminal cells | 10 / 10 / 10 |
| Completed clients / remaining clients | 10 / 0 |

The same authorized account and tenant were verified on renewed-session bootstrap before collection. The final invocation took 82.349 seconds under a fresh 900-second cooperative deadline, used 48 HTTP requests and eight issuance attempts including bootstrap, and had no in-flight overrun. Each of two standalone diagnostics was limited to one target issuance attempt, two issuance attempts including bootstrap, 30 total HTTP requests and 900 seconds. The first emitted only finite metadata and identified the token-endpoint decline; the second used a pinned published-code allowlist that still omitted this code. Neither raw identity bodies nor arbitrary exception text were persisted. The final reviewed hook added the three exact platform codes and confirmed the cause during recovery; no third standalone diagnostic ran.

Across all attempts, including the original inventory-budget stop and both diagnostics, consumption was **203 HTTP requests and 20 issuance attempts**. This comprises 42 bootstrap HTTP exchanges, 133 inventory/API exchanges and 28 selected-pair identity exchanges. Inventory pages were 127; source refresh requests, transport retries, reserved unknown requests and overruns were zero. There were six explicit passkey sign-ins and no automatic sign-in retry. Aggregate ceilings were 30 issuance attempts, 60 bootstrap HTTP exchanges, 350 inventory HTTP requests, 300 pages, zero source requests and 500 total HTTP requests. All previous consumption was retained. Public technical-document lookups are separate from collector catalog refresh and authenticated identity/API traffic.

Before/after count and hash comparisons matched for the checked fields of 2,327 service principals, 186 application registrations and 85 delegated grants. These checks cover the selected visibility, not every possible tenant setting or permission. The harness invoked zero permission-changing API operations. The previously approved local credential-directory protection change remains separate from tenant permissions. Owned session/token/key objects were disposed; credential material was not printed or persisted, and no credential file was copied.

Saved-evidence export performed no issuance. The final exact seven-file candidate's manifest SHA-256 is `8583f0b60e24b67d3165060ee8e77538c81f85973496f18c995b145e2130654e`. It contains eight anonymous success observations, all ten terminal outcomes and no missing matrices. Independent integrity/privacy review passed the real verifier, checked recipe/scope/flow agreement and confirmed the original three exported observation dates. That review read the seven candidate files rather than raw stores or the tenant snapshots; those latter invariants were separately checked by the operator harness. Artifact review remains `Pending`; no publication approval is claimed. All private state and both candidates remain outside Git.

## Source, package and validation

Implementation is `f5df773c177cd11dcf3befc53b3e7507f08e2041` on `codex/goal1-bounded-collector`, following `3bf93cbcee318e8758005d12258808ec7184394f`. Main base remains `1be12d75c7e2a63eac8e14c32d54e79cec4a23ef`; handoff remains `19470aeba7a949e4204e4ecf5586a6ffb3171c69`. Independent source review found no remaining must-fix findings after the explicit-retry, always-cleanup and first-cell exact-code guard corrections.

The complete 0.48.0 Linux x64 package contains 133 payload files plus its manifest. Only the PowerShell classifier changed in the module. Every recorded native/core/build input was verified unchanged, so the verified native binary and adjacent libraries were reused without rebuilding. Exact source/package verification ran before executable imports and authentication. Independent package review confirmed the exact file inventory and native-input equality.

| Artifact | SHA-256 |
| --- | --- |
| Updated package manifest | `6e203055aa9414d894ef7763f488479b2c1f8d19ca4cbfc17a5503f54d19aa15` |
| Updated package archive | `71d2dc939219b18fbe53ec8d377a6623920b571e6aca41a89a36dfe07c0b8c9b` |
| Reused native executable | `d65f1686542444dcfab9fe1bb38eb5989a815a2e743fc04a6276648fcf7de196` |
| Reused credential DLL | `13590ca58fc86b195525ac25507620366b86413d477040416398f10914a7f460` |

PowerShell is now 7.6.7, rather than the earlier receipt's 7.6.0. The complete Collector file selection passed **116 tests, zero failures and zero skips** on available Pester 6.2.0, including all four real process-kill boundaries. The first focused run exposed an existing conditional mock's missing fallback under Pester 6; its explicit real-function fallback was corrected and the full selection passed. Diagnostic hooks passed five synthetic checks per version; the exact-code continuation guard passed four fixtures, including refusal of unrelated outcomes. No arbitrary synthetic secret was echoed.

The required repository runner passed **116 tests, zero failures and zero skips** with restored Pester **5.7.1** on PowerShell 7.6.7, using the updated verified complete package. This completes the changed-source offline gate and retains Goal 1 offline-ready status.

The repository runner initially returned `SetupFailed` before executing tests because pinned Pester 5.7.1 was absent. The operator authorized restoring that exact dependency from PowerShell Gallery. The repository's Pester pin remains unchanged; its final successful gate result is recorded in the [machine-readable completion receipt](goal1-live-canary-completion.json). Earlier offline results remain historical evidence for their exact source/package/runtime and are not relabeled as tests of this change.

No Actions were enabled or used. No push, PR, merge, publication, scheduling, new protocol, tenant mutation or Goal 2 work occurred.

## Next-session status

```text
Goal 1 frozen ten-pair canary collected completely: 8success,1request-blocked,1failed.
Fresh saved assessment status Failed exit1; zero pending/paused/unknown cells.
Cause confirmed AADSTS9002327; classifier fixed without changing the frozen flow.
Original3 completed cells/dates preserved; checked before/after visibility equal.
Pinned Collector gate116/0/0 on5.7.1; supplemental116/0/0 on6.2.0. Offline-ready.
Source f5df773c177cd11dcf3befc53b3e7507f08e2041; branch codex/goal1-bounded-collector.
Workspace /home/nathan/GitHub/TokenForge-goal1-2rQ8rilR
Private state /home/nathan/.local/share/TokenForge/goal1-secadmin-canary-2F7Tr2oi
Candidate-final verified; review pending; no publication or production/API claim.
Do not retry completed cells, provide confidential credentials or change tenant permissions implicitly.
Actions disabled. Goal 2 untouched.
```
