# Goal 3 live canary: stopped by the strict scope policy

The authorized canary ran once and **stopped safely at bootstrap**. It did not establish a working live tool route. The approved Microsoft Graph PowerShell bootstrap requested only Graph `User.Read`, but its returned token reported **107 additional API scopes**. The independent bootstrap ceiling was zero, so the credential was discarded before identity confirmation, final issuance or either Graph GET. No alternate client/callback, broader ceiling or automatic reauthentication was attempted.

This is an observed token-scope result for this dated account/request, not a JWT signature validation, universal client capability, tenant permission inventory or Microsoft-side root-cause claim. Token scope strings and actual authorization remain different evidence. Full scope names are preserved in private `acquisition.json`; repository evidence records counts and their digest.

A separately authorized later trial using another approved client passed; see the [second live canary](goal3-live-canary2.md). This first trial retains its original stopped result.

## Approved request and observed consumption

- Bootstrap client: `14d82eec-204b-4c2f-b7e8-296a70dab67e` (Microsoft Graph PowerShell).
- Selected final client: `04b07795-8ddb-461a-bbee-02f9e1bf7b46` (Azure CLI); it was never attempted.
- Published callback for both: `https://login.microsoftonline.com/common/oauth2/nativeclient`.
- Resource: Microsoft Graph; explicit `User.Read`; native PKCE; both additional-API-scope ceilings zero.
- Selected proof: fixed Graph v1.0 `GET /me?$select=id`; never dispatched.

| Observed measure | Result |
| --- | ---: |
| Explicit passkey authentication attempts | 1 |
| Bootstrap issuance attempts | 1 |
| Final issuance attempts | 0 |
| Issuance ceiling | 2 |
| Elapsed active canary seconds, including authentication | 11.952 |
| Cooperative deadline seconds | 180 |
| Authentication / bootstrap HTTP requests | 5 / 2 |
| Total canary HTTP requests | 7 |
| Graph GET requests | 0 |
| Reported scope strings / API scopes / OIDC strings | 111 / 108 / 3 |
| Additional API scopes / response-reported extras | 107 / 107 |

One anonymous public realm-metadata lookup occurred during preflight, separately from the seven active-canary requests. It matched the frozen tenant fingerprint. The expected credential account name was checked privately; preliminary token request/tenant/principal/client/resource/lifetime validation passed before diagnostic scope projection. Full current identity confirmation remained false because the ceiling rejected the token before `/me`.

The acquisition receipt is `Blocked` with original reason `BootstrapSilentAttemptOrPolicyFailed`. The saved metadata and code ordering establish the narrower derived stop reason `BootstrapAdditionalApiScopesExceedZeroCeiling`. The converted snapshot correctly has no final observation, so saved tool health remains `NeedsObservation`. These states must not be relabeled as successful live acquisition or API acceptance.

## Preflight compatibility fix and Linux checks

Preflight initially rejected the unmodified saved full inventory before credentials or issuance. Its own legacy producer emits 64 source labels with exactly `Name=TenantDiscovery` and `Evidence=VerifiedMicrosoftOwner`, omitting `Location`. The narrow adapter fix adds an explicit unknown location only in a deep clone of that exact Inventory shape, then retains all existing strict validation. It does not filter unselected history, discard unknown fields, invent URLs or refresh dates. The entire original inventory now validates, and its file hash remains unchanged.

Source is `6b9921c514fda88c41d9e0f54f9dc8fd8c5a5b13`. Three regression fixtures cover known legacy input/date preservation and rejection of unknown source names or credential fields. Independent source/harness/package review passed. Fresh Pester **6.2.0** gates against the matching rebuilt Linux package passed **Admin 76/0/0** and **Changes 83/0/0**. Historical full-suite results at `8b989dc` remain in the [offline receipt](goal3-validation.md); they were not rerun or relabeled as tests of this narrow change.

The real saved acquisition snapshot and health report also matched native/PowerShell JSON exactly with no PowerShell on the native child PATH. Native health returned exit 3 (`NeedsObservation`); these saved-evidence checks made no external requests.

- Package manifest SHA-256: `afb5bfa1cf438462739496873e4cab3b484850e7560db95a121a1da89c9bd9c5`.
- Executable SHA-256: `05c06dc040ae6f34c4d22d7f78aed454a4b3e3cfb12eb2cf7a7972be0e964718`.
- Credential DLL SHA-256: `9ee633c1720b08cec9137fb901c4817b34fa7e7c2541757784a9aab101a908a8`.
- Archive SHA-256: `081e2dfed35088a072ce3b45b132dd639c0c7e0ff986e68bac294aa0ec4f3176`.
- Exact package: 146 payload files plus manifest, 83 committed module sources, 93 verified native inputs.

The approved SDK 10.0.401 used locked cached dependencies with all feeds disabled. No installation, hosted compute, extra architecture, permission-changing API operation, publication, push, PR, merge or Goal 4 work occurred. No before/after permission inventory was collected under this narrow scope, so this receipt does not claim a tenant-wide state comparison. Owned credentials/session/key objects were disposed; none was displayed or persisted. Private metadata files are 0600 under a 0700 directory; original Goal 1 evidence remains untouched.

## Evidence and next decision

Private evidence is retained at `/home/nathan/.local/share/TokenForge/goal3-secadmin-canary-4l0j9apq`. It includes the immutable intent, exact profile/requirements/plan, acquisition/snapshot/health/result, public realm metadata and reviewed operator harness. Independent actual-evidence review confirmed the policy stop, scope counts, request/time accounting, private permissions and absence of credential fields. The [structured receipt](goal3-live-canary.json) pins all artifact hashes and package/source revisions.

The live-working gate remains **blocked** for this observed bootstrap route. Continuing requires separate approval for a new bounded run and an explicit alternative bootstrap client/callback that can satisfy the zero-extra ceiling. No tenant permission change or ceiling increase is proposed. The unused attempt was not spent trying alternatives.
