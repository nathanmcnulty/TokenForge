# Goal 1 authorized bounded canary and renewal

**Offline-ready; live acceptance paused.** Ten Graph-only client/resource pairs were frozen with one published callback and PKCE per client. Three pairs succeeded. The fourth returned an ambiguous session failure; the collector stopped with six pairs untouched. One explicitly renewed, identity-verified same-account session retried that paused pair once and received the same pause. Authentication stopped. No additional recovery is implicit in this receipt.

The operator authorized authentication, the earlier credential-directory permission correction, and discretionary finite budget increases. The reviewed envelope counts the first attempt rather than resetting consumption. Source remains `3bf93cbcee318e8758005d12258808ec7184394f`; package, native binary and offline tests are unchanged from [the offline receipt](goal1-offline-validation.json). Handoff remains `19470aeba7a949e4204e4ecf5586a6ffb3171c69`; implementation base remains `1be12d75c7e2a63eac8e14c32d54e79cec4a23ef`.

| Aggregate measurement, including the earlier attempt | Consumed / ceiling |
| --- | --- |
| Issuance attempts, including bootstrap and recovery | 8 / 30 |
| Bootstrap HTTP exchanges, including native sign-in | 21 / 40 |
| Inventory/API HTTP requests | 104 / 300 |
| Inventory pages | 101 / 250 |
| Identity HTTP exchanges for selected pairs | 10 |
| Total HTTP requests | 135 / 400 |
| Public source requests | 0 / 0 |
| Explicit passkey sign-ins / automatic sign-in retries | 3 / 0 |
| Current canary window shared across Start and Resume | 900 seconds; deadline 2026-10-22T06:47:15 UTC |
| In-flight overruns / reserved unknown requests | 0 / 0 |

The new Start invocation consumed 67 requests in 69.452 seconds; renewal/resume consumed 10 in 9.520 seconds. The earlier stopped attempt consumed 58 in 52.475 seconds under its separate window. Active durations are not a substitute for the shared Start/Resume wall-clock deadline. The renewed session passed the same-account/tenant checks before reaching collection. The only selected-pair retry was the paused cell; the three completed cells were not reissued.

The page telemetry explains why the first 50-page ceiling was too small. This run's before snapshot took 26 pages (24 for 2,327 service principals, one for 186 registrations, one for 85 delegated grants), and inventory took another 25. The server returned 24 service-principal pages despite the requested top size. Full inventory and grant enumeration completed; the later session pause is distinct from the earlier inventory-budget stop. No permission-changing API operation was invoked. An after snapshot was not reached, so unchanged grants/registrations within checked visibility remains unverified.

A fresh credential-free process reports `Paused`, exit 3: ten selected pairs, three complete, one paused, six pending without a materialized matrix. The four known cells contain three terminal successes and one pause; no in-flight unknown, request-blocked, transient-exhausted or failed cells. The paused pair has two historical attempts, both nonterminal; it is counted once in current coverage. No allowlisted numeric identity diagnostic was available. This does not establish app-wide incapability, current consent, signature validity or API acceptance.

Saved-evidence export ran offline and passed the real independent verifier. The exact seven-file candidate has manifest SHA-256 `fea3cf1c7c2f46f48e0cdaaad126e88fba7cf63e2564be9296cd05f8a2639366`. It contains three anonymous success observations and explicit partial coverage. Original terminal IDs, observation dates and content hashes remained unchanged after renewal; authoritative plans/attempts remained unchanged during export. An operator-script assertion initially included the native export's current `UpdatedAt` envelope timestamp; it was corrected to compare authoritative Plans/Attempts, consistent with the candidate implementation, and the already sealed candidate was reverified without recollection or overwrite. No production code was changed.

Independent review found and resolved a harness budget-file issue before authentication: strict private-path reading and schema/type/exact-value validation now occur under the run lock, and an envelope hash binds Start to Resume. Review found no remaining must-fix issues in the revised harness or its recovery delta. A separate seven-file-only candidate review confirmed hashes, reconstructed validation, recipe/scope/flow agreement and absence of credential/private identity fields. It did not inspect raw stores; source-store binding and original-evidence preservation were checked by the operator harness. The artifact retains `ReviewStatus: Pending`; this inspection is not publication approval.

Private state and the sealed candidate remain outside Git under the established private-path policy. Owned key/session/token objects were disposed. No cookie, token, assertion or credential was printed or persisted. Only normalized evidence, inventory and bounded receipts were saved. Local script hashes and sanitized counts are in [the machine-readable receipt](goal1-live-canary-attempt2.json). No Actions, push, PR, merge, publication, tenant mutation or Goal 2 work occurred.

## Remaining gate and next-session status

Live acceptance is incomplete: six pairs remain untouched, the fourth pair remains paused after its single recovery, and after-visibility equality was not checked. Completing offline gates does not override these results. The next useful step is offline diagnosis and a reviewed bounded diagnostic plan for the ambiguous response. Do not expand the cohort, change permissions, infer a fresh recovery allowance or automatically sign in again. The existing single recovery is consumed; another live retry needs an explicit new recovery decision and finite envelope.

```text
Goal 1 offline-ready; live canary paused, not production complete.
Workspace /home/nathan/GitHub/TokenForge-goal1-2rQ8rilR
Branch codex/goal1-bounded-collector; implementation 3bf93cbcee318e8758005d12258808ec7184394f
Private current state /home/nathan/.local/share/TokenForge/goal1-secadmin-canary-2F7Tr2oi
Saved status Paused exit3: 3complete,1paused,6untouched; same cohort and dates preserved.
Single paused-cell recovery consumed. No further automatic authentication/retry.
Partial candidate verified; review pending; no publication.
Actions disabled. Stop before Goal 2.
```
