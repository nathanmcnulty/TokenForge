# Goal 3 second live canary: approved zero-extra-scope route passed

The separately authorized canary **passed** for the declared read-profile route. Bootstrap and final issuance both reported only `User.Read` as an API scope, with zero additional API scopes and zero response-reported extras. The expected frozen tenant/principal context was confirmed against current Graph identity, and the separately selected Graph v1.0 `GET /me?$select=id` returned **HTTP 200**. Saved tool health is `VerifiedWorking`, exit 0, for this dated exact request.

## Selection and bounds

The selected client is **ZTNA Network Access Client**, `038ddad9-5bbe-4f64-b0cd-12434d1e633b`, with published callback `https://login.microsoftonline.com/common/oauth2/nativeclient`, native PKCE and explicit Graph `User.Read`. It was selected for both stages before authentication and was the strict profile's only approved client. This configuration choice was explained before execution and independently reviewed. No runtime client/callback substitution or fallback occurred.

The prior approved candidate's scope file has SHA-256 `7c99bba99023c175c5ac5ee7bf20b1b49d844e0910014309dffe9ac4f5a5c399`, verified against its original manifest. Its one matching observation reported `User.Read` and three OIDC scope strings, which supported candidate selection but did not guarantee the live outcome or establish authorization by itself.

| Observed measure | Result |
| --- | ---: |
| Explicit secadmin passkey authentication | 1 |
| Bootstrap / final issuance attempts | 1 / 1 |
| Total issuance attempts / ceiling | 2 / 2 |
| Active elapsed seconds, including authentication | 12.53 |
| Cooperative deadline seconds | 180 |
| Authentication HTTP requests | 5 |
| Bootstrap / current-identity / final / selected-proof requests | 2 / 1 / 2 / 1 |
| Total HTTP requests | 11 |
| Bootstrap / final additional API scopes | 0 / 0 |
| Bootstrap / final response-reported extras | 0 / 0 |
| Selected Graph GET status | 200 |

Both tokens reported `User.Read`, `email`, `openid` and `profile`: one API scope and three OIDC scope strings, as separated by the existing policy. No scope ceiling was increased. The current-account proof and selected-operation proof are distinct GETs; both are fixed read-only requests. No tenant permission-changing operation was invoked. No broad before/after permission inventory was taken, so no tenant-wide state-comparison claim is made.

## Exact source, package and evidence

Runtime source remains `6b9921c514fda88c41d9e0f54f9dc8fd8c5a5b13`. The unchanged reviewed Linux package was reused; no rebuild or dependency installation was needed. Its 146 payload files, 83 committed module source files, 93 native inputs, archive and complete source/test pins were verified again. Existing Pester 6.2.0 checks **Admin 76/0/0** and **Changes 83/0/0** were reused because their source/package/test inputs did not change.

- Package manifest SHA-256: `afb5bfa1cf438462739496873e4cab3b484850e7560db95a121a1da89c9bd9c5`.
- Executable SHA-256: `05c06dc040ae6f34c4d22d7f78aed454a4b3e3cfb12eb2cf7a7972be0e964718`.
- Credential DLL SHA-256: `9ee633c1720b08cec9137fb901c4817b34fa7e7c2541757784a9aab101a908a8`.
- Archive SHA-256: `081e2dfed35088a072ce3b45b132dd639c0c7e0ff986e68bac294aa0ec4f3176`.

The new configuration passed dry preflight before authentication. After the live run, native `admin evidence` and `admin check` reproduced the saved PowerShell snapshot and health JSON exactly at the same `AsOf`, with no PowerShell on the native child PATH and no further network calls. Native health returned exit 0. Independent review recomputed the profile/tool hashes and API approval fingerprint and verified the exact operation/method/version/account/request binding, scope ceilings, budget counts and privacy checks.

Private evidence remains at `/home/nathan/.local/share/TokenForge/goal3-secadmin-canary2-gochvx6g`. Twelve credential-free artifacts are pinned in the [structured receipt](goal3-live-canary2.json), including the fixed intent/profile/requirements/plan, acquisition/snapshot/health/result, native parity outputs and reviewed harness. Files are 0600 under a 0700 directory. Owned tokens/session/key objects were disposed. The complete original inventory hash and every prior stopped-canary artifact hash remain unchanged.

The [first trial](goal3-live-canary.md) remains stopped for its original Graph PowerShell bootstrap's 107 extra API scopes. This new approved client/profile context is not a comparable authorization regression experiment, and the old evidence was not rewritten.

## Acceptance limits

No blocker remains for **this bounded live canary**. It validates the dated approved client, expected account context, explicit `User.Read` request and selected Graph GET. It does not establish arbitrary-tool support, other clients/scopes/tenants, JWT signature validation or production readiness. Actions stayed unchanged and manual-only. No tenant permission change, publication, push, PR, merge or Goal 4 work occurred.
