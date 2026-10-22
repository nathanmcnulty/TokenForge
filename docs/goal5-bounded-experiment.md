# Goal 5: one bounded callback experiment

## Preregistered protocol

This study starts from reviewed Goal 4 receipt `9476bb952e1d4fb0896781991eb794ad308a1b13`, on `codex/goal5-bounded-experiment`. Roadmap handoff `19470aeba7a949e4204e4ecf5586a6ffb3171c69` is preserved. This protocol and cohort must be checkpointed and independently reviewed before the recorded experiment runs. No result or promotion is assumed.

**Hypothesis:** for warm explicit scope acquisition, retaining only the previously observed published callback reduces logical issuance attempts by at least 10% while preserving every baseline verified client/resource pair on both discovery and holdout cases.

**Primary outcome:** first require no lost baseline success in either partition; only then consider attempt savings. Any comparable lost success rejects the candidate. Budget, safety or harness interruption is inconclusive, never a successful cheaper run. Favorable synthetic results alone cannot approve promotion. A rejected or inconclusive disposition closes this one experiment without changing production.

The unchanged implemented `ProfileScopeAcquisition.Acquire` runs both arms, including its real warm planning, bootstrap identity binding, token validation, zero API-extra-scope ceiling, callback fallback and disposal. Baseline `maxRedirects=2`; candidate `maxRedirects=1`; both use `maxCandidates=1`, native OAuth2V2Pkce and explicit Graph `User.Read`. This core also requests `offline_access`; both arms retain that exact OAuth request. It is not an additional API permission in the comparison, and is not silently removed. No refresh tokens are synthesized or persisted.

Every case has the same original matched warm observation. Before any synthetic issuance, validate all 12 inputs and assert baseline requests are exactly `[observed callback, fallback callback]`, candidate exactly `[observed callback]`, and that the recorded callback fingerprint is still published. Published input order deliberately differs from observed preference. Bootstrap uses a distinct synthetic client, current synthetic principal and `User.Read`; every final returned token must pass the existing account/request/scope/lifetime checks. No JWT signature validation or API acceptance is claimed.

The fixed case file is `tests/fixtures/lab/callback-cap-v1.json`, SHA-256 `36a2b88ae045959f41637f82ce000cfa9e64f2b5a8a5f07fa16ca3a7e3a25547`. It has eight discovery and four holdout cases. It is a predeclared synthetic challenge set designed to expose fallback-dependent failures, not a blind holdout, random sample or estimate of service prevalence. No model tuning follows discovery results. Each case is run once per arm, alternating AB/BA order by case; discovery precedes holdout. There is no live drift inference.

Synthetic responses are keyed only by case, phase and concrete callback, never arm or call ordinal. Challenges include healthy primary, primary rejection with working fallback, scope excess, opaque token, wrong principal, throttling, both rejected, session loss and a prompt-required interrupt. Injected labels remain separate from observed core result (`VerifiedScopedToken`, `NoVerifiedToken`, `Cancelled`). The executor models throttle as a failed issuance with no retry wait; it does not prove actual HTTP 429 classification. Session loss and prompt-required scenarios cancel the trial token; they do not prove actual service prompt detection or invoke a prompt.

## Boundaries and stop conditions

Agent inputs are only the versioned synthetic case allowlist, this protocol and source/package metadata. No production gap/store/profile/session/credential file is read. The laboratory script is outside the module, is not imported by production, and cannot update a production recipe or approve/publish its own findings.

Bounds: 24 trials; at most 72 synthetic logical issuance attempts total (bootstrap and each failed/invalid final token charged before executor dispatch); one concurrent trial; 60 seconds for the trial phase and five seconds per trial; zero authentication, external requests, prompt invocations, permission mutations, source fetches or database operations. Immutable package/input validation precedes the trial clock. The callback executor and identity adapter are in-memory synthetic functions. Run local validation and the experiment inside `unshare -Urn`, with PowerShell telemetry disabled, so remote connectivity is unavailable even if a future regression reaches transport.

Any unexpected request, cold checkpoint, unexpected cancellation, leaked token owner, accepted extra API scope, runtime budget expiration or global counter stop invalidates completion. The report must say `Stopped`/`Inconclusive` and retain completed trial records. No stop is recoded as an ordinary denied pair. No additional cases, retries, concurrency or live follow-up are implied.

Use only the exact reviewed Linux 0.48.0 package: runtime source `8d625be62ef70a43a765e37faf29b3f4c9e780d4`, manifest SHA-256 `1cee964b74fe63c8ffffecec8d2ed4075963d217c28d9554e3da5196f3caceea`. Full payload membership, hashes and the loaded DLL must match before execution. No native source change or rebuild is proposed. The frozen synthetic namespace, per-case profile/inventory/history/request lists and time anchor are saved separately with a content digest. Replays regenerate a clearly synthetic fresh time anchor because this existing core enforces wall-clock freshness; no real observation is relabeled.

## Evidence and disposition

Record exact experiment source/script/cohort/package/input hashes; both partitions' denominators, paired lost/new successes and issuance counts; all 24 per-trial results and injected traces; cancellation, throttling and invalid-token cases; accepted extra scopes and token disposal; local elapsed and shared-process peak memory. Source/inventory network requests, database I/O, child starts and retry waits are absent and explicitly zero. Logical synthetic issuance counts are not measured HTTP request savings. One fixed synthetic cohort cannot demonstrate live/network latency, production coverage, population effect size or a memory improvement.

Production remains unchanged regardless of the experiment's disposition. Any later promotion requires independent review, demonstrated benefit without privacy/correctness/scope/prompt regression, a new policy version and any separately needed live authorization. Hosted Actions, authentication, tenant permissions, publication, push, PR, merge and Goal 6 are outside this milestone.

Run the `Lab` preset in a fresh PowerShell process with the existing exact package. The recorded experiment then invokes the same script function once in a separate isolated process, using new report paths. Validation replays the same frozen protocol; it is not a second hypothesis or a live A/B trial. Final reviewed acceptance will record actual results and the keep/discard disposition.
