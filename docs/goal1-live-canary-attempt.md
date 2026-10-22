# Goal 1 live preflight attempt

**Passkey authentication and secadmin identity verification succeeded. Live acceptance remains pending.** The collector stopped at its approved inventory-page ceiling before freezing or probing any client/resource pair. Offline acceptance is unchanged.

The operator-authorized permission correction changed the supplied credential's containing directory from 0775 to 0700; the credential remains 0600. The existing native software-passkey implementation accepted it. No credential copy, cookie, token, assertion or raw identity response was printed or persisted. Owned session/token/key objects were disposed when the process stopped.

Source/package remains implementation `3bf93cbcee318e8758005d12258808ec7184394f`, TokenForge 0.48.0 Linux x64; executable SHA-256 `d65f1686542444dcfab9fe1bb38eb5989a815a2e743fc04a6276648fcf7de196`. The private execution harness was independently reviewed, verified the exact source/package before importing executable code, and took an exclusive run lock. Authentication reserved a finite request envelope durably; an event counter observed request starts without retaining HTTP payloads. Synthetic counter and concurrent-start refusal checks passed before live execution.

| Measurement | Result |
| --- | --- |
| Explicit passkey sign-ins | 1; no automatic retry |
| Sign-in HTTP exchanges | 5 |
| Graph bootstrap token acquisitions | 1 (2 OAuth HTTP exchanges) |
| Bootstrap HTTP exchanges including sign-in | 7 / 20 |
| Inventory/API HTTP requests | 51 / 100 |
| Inventory collection pages | 50 / 50; stop reason InventoryPages |
| Total HTTP requests | 58 / 300 |
| Source refresh requests | 0 |
| Elapsed / cooperative deadline | 52.475 seconds / 900 seconds; no overrun |
| Frozen pairs / client discovery probes | 0 / 0 |

Before-check visibility was complete for 2,327 service principals, 186 application registrations and 85 delegated grants. Only aggregate counts and hashes were retained; these are visibility observations, not permission assertions. The subsequent inventory operation exhausted the shared page budget. Optional grant enumeration returned incomplete/failed after that budget stop, and the harness refused to proceed. No cohort or public export was created. Before/after equality, stop/restart and renewed-session collection remain unproven by this attempt. No registration/consent/permission-changing operation was invoked; an after snapshot was not taken, so unchanged tenant state is not claimed.

The exact sanitized machine-readable receipt is [goal1-live-canary-attempt.json](goal1-live-canary-attempt.json). Private operational receipts remain outside Git. No automatic sign-in retry or budget reset follows from this stop.

Continuing needs explicit approval to increase the aggregate inventory-page ceiling from 50 to 100, while retaining the existing ceilings of 100 inventory HTTP requests, 20 bootstrap HTTP exchanges, 30 issuance attempts and 300 total HTTP requests, with no public refresh. Since 51 inventory HTTP requests have already been consumed, at most 49 remain. A higher page ceiling does not guarantee completion; a targeted ten-client inventory plan may be needed if full preflight cannot fit. Execution must also fit the original 15-minute deadline, or receive approval for a new window after it expires. No limit has been raised yet.

Subsequent operator authorization delegated finite budget selection and a fresh canary window. The bounded continuation and repeated session pause are recorded in [attempt 2](goal1-live-canary-attempt2.md); this earlier receipt remains historical.
