# Goal 4 bounded live canary

The separately authorized secadmin canary **passed its scoped acquisition, Graph proof and saved-evidence reuse gates**, with an explicit process HTTP attribution limit. It used the documented ZTNA route and completed the authentication/acquisition/projection/reuse harness in **107.264 seconds**, within the 180-second cooperative deadline. This is one dated route, not production completion.

## Approved route and observed result

Both bootstrap and final issuance used ZTNA Network Access Client `038ddad9-5bbe-4f64-b0cd-12434d1e633b`, callback `https://login.microsoftonline.com/common/oauth2/nativeclient`, native PKCE and explicit Graph `User.Read`. The account name was checked privately and the frozen tenant/principal context confirmed against current Graph identity. Both returned `User.Read` plus `email`, `openid` and `profile`, with **zero additional API scopes and zero response-reported extras**. The separately selected Graph v1.0 `GET /me?$select=id` returned **200**; saved health is `VerifiedWorking`.

| Measure | Observed | Bound |
| --- | ---: | ---: |
| Explicit authentication attempts | 1 | 1 |
| Bootstrap issuance attempts | 1 | 1 |
| Final issuance attempts | 1 | 1 |
| Total issuance attempts | 2 | 2 |
| Harness elapsed seconds | 107.264 | 180 |
| Journaled refresh HTTP requests | 6 | 24 |
| Bootstrap OAuth HTTP requests | 2 | 11 |
| Selected Graph proof GET | 1 | 1 |
| Transient/recovery retries | 0 / 0 | 0 / 0 |
| Uncertain/pending requests after completion | 0 / 0 | 0 / 0 |
| Additional requests during measured saved reuse | 0 | 0 |

The journal's six HTTP operations are two bootstrap OAuth exchanges, one mandatory bootstrap identity GET, two final OAuth exchanges and the one selected proof GET. Durable terminal evidence preceded completion; the session was disposed before saved-evidence projection. No alternate client/callback, fallback, renewal or tenant permission mutation was invoked. The original inventory retained its `2026-10-22T06:33:02.6003045+00:00` observation time and was within the 24-hour policy at acquisition; it was neither refreshed nor relabeled.

## HTTP attribution limitation

The process-wide observer recorded **13 HTTP RequestStart events: 5 during authentication, 6 represented by the refresh journal, and 2 unattributed**. All 13 are retained in accounting; they are not rewritten as 11. The scalar original observer did not retain destinations, so complete original HTTP attribution is unproven.

A separate bare PowerShell process in a network-isolated `unshare -Urn` namespace reproduced two `dc.services.visualstudio.com` Application Insights request attempts, with no TokenForge import, credentials or remote connectivity. This makes background host telemetry a plausible explanation, not proof of the original two events' destinations. Static review found no additional TokenForge dispatch path. No further authentication or issuance was attempted to investigate. Future live launches should disable PowerShell telemetry/update checks before startup and retain bounded, sanitized operation categories if complete host attribution is required.

## Saved-evidence proof and integrity

Projection was idempotent. Replanning the same frozen cohort produced **SelectedCount=0, ReusedCount=1, HasIssuancePlan=false, ExitCode=0**. Both the original completed-plan facade and the new all-fresh facade returned no work without a supplied credential. The measured reuse phase made zero HTTP requests and left the primary journal byte-for-byte unchanged.

Both original issuance/API observation references retain their exact source/record IDs, context hashes and dates in history and reuse origins. Native `status`, `project`, `capture`, `plan` and `validate` executed against saved artifacts with expected exits and matching PowerShell JSON (plan comparison excludes timing metrics). Original saved native/PowerShell status matched exactly, including `DeadlineReached=false`; later wall-clock evaluation reports true without changing the completed journal. Final saved-output revalidation ran with telemetry disabled in a network-isolated namespace.

The saved-only verification helper initially used an object-only fingerprint API on reference arrays; its local wrapper was corrected. A second comparison explicitly accounted for deadline status changing with read time. Original logs remain preserved. Neither correction changed runtime code, evidence or issuance.

Runtime source: `8d625be62ef70a43a765e37faf29b3f4c9e780d4`. Operator/documentation checkpoint before this run: `a9a5e923dac918838dd862f5c3d883f84126a3ac`. The exact previously accepted Linux 0.48.0 package was reused; manifest SHA-256 `1cee964b74fe63c8ffffecec8d2ed4075963d217c28d9554e3da5196f3caceea`. Complete payload/source/build/validation inputs were reverified. No rebuild or dependency installation was needed; unchanged Pester 6.2 gates (1217 full passes, 97 Refresh passes, 1086 native core checks) were reused.

Evidence remains at `/home/nathan/.local/share/TokenForge/goal4-secadmin-canary-dpX5D8ig`, mode 0700 with 0600 nonsymlink files, containing credential-free metadata only. Tokens, session, passkey objects and leases were disposed; no credential values were serialized or displayed. The original inventory digest and all 12 pinned prior Goal 3 artifacts remain unchanged. The [structured receipt](goal4-live-canary.json) records every private evidence hash and local validation artifact. Independent review confirmed the exact route, scopes, account/API binding, budgets, terminal durability and original-reference reuse, with the HTTP limitation above retained.

No blocker remains for the scoped acquisition/API/reuse proof. Complete HTTP attribution remains a documented limitation. No JWT signature verification, tenant-wide permission comparison, arbitrary-tool success or production completion is claimed. Actions stayed unchanged and manual-only. No tenant permission change, publication, push, PR, merge or Goal 5 work occurred.
