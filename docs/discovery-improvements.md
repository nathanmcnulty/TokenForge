# Discovery improvement plan

This is the canonical outcome-driven delivery roadmap and supporting engineering backlog for a trustworthy application/permission evidence database and useful admin CLI. It is a plan, not a claim that proposed features or validation have shipped. Keep operational instructions in [Run discovery locally](discovery.md). Start with the [trustworthy bounded collector goal and portable VM handoff](goals/01-trustworthy-bounded-collector.md).

Review baseline: 2026-10-22, main `1be12d75c7e2a63eac8e14c32d54e79cec4a23ef`. This change is documentation only. Source inspection and architecture review did not build, test, authenticate, provision a VM, run discovery or Actions, publish evidence, merge, or release software. The source reconciliation table in the first goal pins the draft building blocks separately from main.

## Starting point

The local assessment completed on 2026-10-16 finished its frozen cohort: 2,030 Graph client/resource pairs, with 238 successful acquisitions, 1,213 `NoRedirect`, 155 `BrokerRequired`, and 424 `Failed` outcomes. It used first-success exploration and at most one eligible callback. Completion means every selected pair was checkpointed; it does not mean all 5,455 public candidate IDs, every resource, or every authentication flow was tested. Other protocol/callback cells remain untested. These counts describe one account and recipe.

Already implemented:

- Standalone PowerShell discovery with no model/API dependency, private SQLite working stores, frozen cohorts, checkpoints, and bounded runs.
- Exact-plan resume that skips completed work, primary-evidence recovery, typed transient retries, and sanitized progress/failure summaries.
- Optional combined pending-client batches that reduce process and metadata-projection overhead without parallel token requests.
- Read-only cohort status and account-selected coverage reports; full-history validation before report filtering.
- Separate public metadata, permission definitions, anonymous observations, and private tenant evidence. Compact gzip catalog export preserves existing JSON compatibility.
- Explicit Microsoft ownership checks for registration. Documentation-only GUIDs require separate opt-in because permission IDs, examples, and tenant IDs can resemble applications.

The [PowerShell-to-native SQLite reporting shortcut](native-research-coverage.md#powershell-sqlite-reports) preserves report output while reducing expansion overhead. Continue measuring against larger histories before extending it to other operations.

## Product outcome and finite v1

Keep the shared .NET core, native Linux CLI, PowerShell compatibility layer, private SQLite evidence, frozen plans and portable sanitized exports. The product promise is: given a supported administrative task and an authorized account, explain which known client/request can perform it without adding consent, acquire only within explicit policy, and distinguish threatening changes from missing or incomparable evidence.

This does not promise universal preconsent, a Conditional Access bypass or API authorization. Delegated client permission and user authorization are separate; `prompt=none` returns an error when interaction is required. See [Microsoft permissions and consent](https://learn.microsoft.com/en-us/entra/identity-platform/permissions-consent-overview) and [authorization-code protocol](https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth2-auth-code-flow).

V1 supports Linux x64 native CLI plus the existing PowerShell adapter on one documented runtime/package baseline; versioned public metadata with provenance; private account-bound collection using implemented delegated flows; four admin workflows below; and reproducible recovery and independently reviewed publication. Its declared validation matrix includes an admin and ordinary-user account only where authorized. Unsupported cases return unknown/unsupported. Guests, more tenants/clouds, device-code/broker/app-only flows, exhaustive callbacks, GUI, OS signing and broader platform authentication are expansion work, not conditions that indefinitely delay v1.

Production should eventually use bounded software-passkey-authenticated discovery in GitHub Actions, feeding validated metadata and separately reviewed change packets. Ordinary collection/status must work without a model. Actions remain disabled and manual-only; roadmap approval does not authorize enabling, dispatching, rerunning or scheduling them. Dedicated lab VMs/containers do not imply permission for authentication or experiments. Every live or hosted acceptance gate needs separate authorization.

## Findings that drive the sequence

- **Comparison correctness:** current `Compare-TokenForgeScopeDatabase` groups latest rows by tenant/principal/client/resource. It avoids removals after failed probes, but successful different requests/flows can appear to remove scopes, and first observations produce additions. Goal 2 must compare like with like. See [current comparison source](../src/TokenForge/Public/Database.ps1).
- **Session loss:** the probe handles recognized transients but other exceptions can become terminal failed cells that resume skips. Goal 1 must pause expired/invalid or ambiguous session context and stop on account mismatch. Well-evidenced client-specific consent, assignment or policy declines remain request-blocked evidence; `interaction_required` alone is not a global session-expiry classification. See [probe source](../src/TokenForge/Public/Probe.ps1).
- **Budgets:** local time checks are between chunks; outer authentication/source/inventory work starts before that timer. Goal 1 must include preflight/network work in explicit budgets and report cooperative overrun. See [runner](../src/TokenForge/Public/DiscoveryRun.ps1) and [bootstrap wrapper](../scripts/Invoke-TokenForgeDiscoveryRun.ps1).
- **Identity versus reuse:** existing hashes bind catalog/cohort context. Retain exact-resume identity; Goal 4 adds a separately versioned compatibility key rather than weakening hashes. See [flow identity](../src/TokenForge/Private/FlowEvidence.ps1).
- **Draft #120:** it already transports selection snapshots and gates no-plan results. It is a public Deep queue stacked on #119, not private account freshness. Its sidecar is replaced/removed before corresponding state is saved: interruption fails closed but needs generation/manifest storage or deterministic recovery. Original-target package/runtime validation is pending.
- **Admin policy:** current PowerShell bootstrap/final additional-scope ceilings default to effectively unrestricted. Goal 3 introduces an opt-in strict profile with independent zero-additional-API-scope defaults; compatibility behavior must not silently change. See [scope workflow](../src/TokenForge/Public/ScopedToken.ps1).

## Six delivery goals

### Goal 1: A trustworthy bounded collector

**Outcome:** start one small approved run, interrupt it, inspect status without authentication, resume safely and create a reviewable export without recollecting. The [copyable first goal](goals/01-trustworthy-bounded-collector.md) defines offline implementation and the portable VM handoff.

Reconcile source/package/runtime and preserve useful #117 operational and #119 publication contracts without merging them automatically. Keep a protected account-specific state directory, frozen inventory/identity and complete package/dependency pins. Candidate creation is separate from approval/publication.

Proposed live canary, only after separate authorization: one account, Graph only, ten selected client/resource pairs, one published callback per client, serial existing-flow recipe, no registration/consent mutation, 15-minute cooperative deadline, at most 30 issuance attempts including retries, and explicit separate bootstrap/inventory/source ceilings. All network work appears in the report; these are starting limits, not service guarantees.

**Done when:** stable JSON distinguishes complete, structurally excluded, pending, paused, transient-exhausted, in-flight unknown and failed; pair/cell counts differ explicitly; durable completed cells are never replayed and dates remain original. Synthetic kill tests cover before request, simulated remote result before checkpoint, primary checkpoint before projection, and export interruption. Expired/invalid or ambiguous sessions pause; account mismatch stops; well-evidenced client-specific consent/assignment/policy declines are request-blocked for that context. Neither proves app-wide incapability. Cancellation/deadline checks and bounded transport timeouts constrain safe operations without claiming a hard process cutoff. Corrupt history, mismatched namespace, tampered plans/private paths/exports fail closed. Allowlisted candidates bind hashes, producer/source/recipe; retrying export/publication consumes saved evidence without collection. Exact changed-source Linux checks pass with a matching package where required. A separately authorized canary then proves stop/restart, explicitly renewed same-account session continuation (never automatic reauthentication), safe export and unchanged checked tenant grants/registrations. Without that live evidence, stop at **offline-ready, live acceptance pending**.

### Goal 2: Change reports administrators can trust

**Outcome:** each change has a precise evidence type, comparable before/after context and traceable provenance. Contract work can proceed beside Goal 1's offline tests; trustworthy operational claims depend on Goal 1.

| Evidence | Required separation and comparison context |
| --- | --- |
| Permission definition | Resource scope/app-role vocabulary, stable ID, name, enabled state and definition origin; rename differs from add/remove |
| Public hint | Source-specific client/resource/scopes/callback claims and conflicts; not consent or a grant |
| Visible configured grant | Tenant/observer visibility, subject and grant type; configured delegated authorization differs from resource definitions |
| Observed issued scopes | Tenant/principal, client, resource/authority, exact requested scopes, protocol, callback/SPA class, recipe and execution policy; inspection is diagnostic |
| Optional API acceptance | Separately approved operation, API version and account context; token issuance alone does not prove access |

Use versioned typed events for baseline/first-seen, definition/hint/grant/matched-request/API changes, lost visibility, incomparable, stale and unknown. Missing collection, incomplete paging, denied visibility, failed issuance or changed recipe is not removal. First evidence establishes a baseline, not when permissions became available. Preserve last-known success and its dates alongside latest attempt status. Public anonymous observations cannot establish tenant-specific removal or authorize an account. Keep source-observed and locally-collected timestamps separate; retain IDs, locations/hashes and conflicts. Confirm important suspected issuance regressions with the same verified request under separate authorization; reproduced behavior does not establish root cause. See [Graph delegated grant schema](https://learn.microsoft.com/en-us/graph/api/resources/oauth2permissiongrant?view=graph-rest-1.0).

**Done when:** fixtures reject false removal for first-seen/different recipe/incomplete/failed/inaccessible evidence and detect genuine comparable changes. Every entry explains context and uncertainty without showing credentials. A failed request alone never means Microsoft removed permission.

### Goal 3: Four useful admin workflows

**Outcome:** apply the database to supported tools. Depends on Goals 1-2; reconcile independent #118 public lookup without assuming private freshness or change detection is solved.

1. **Explain this request:** clients, callbacks, source conflicts, freshness, visible grants, observed scope breadth, prerequisites and excluded alternatives for exact resource/scopes; unknown is valid.
2. **Acquire without broadening authorization:** opt-in strict profile, approved clients, explicit scopes, silent-only operation, independent bootstrap/final ceilings defaulting to zero additional API scopes, verified current context and optional selected read-only API proof. Show actual additional scopes; fewer strings alone do not prove lower privilege. No stronger-scope substitution or alternate client to evade denial; stop and explain if no route exists.
3. **Check my tool before it breaks:** versioned requirements manifest names client constraints, resource/scopes, flow/callback class, optional operation checks and role/license prerequisites. Return verified working, at risk, needs observation or blocked. Do not infer requirements from arbitrary script text.
4. **Explain change and prepare a report:** map typed changes to affected named tools and prepare bounded reproducible evidence for Microsoft/maintainers. Security-sensitive findings take a private disclosure path. Communications remain separately reviewed and explicitly authorized; nothing sends automatically.

**Done when:** end-to-end examples cover success, no silent route, excess scopes, issuance with API denial, incomplete evidence and a typed regression. Shared native/PowerShell contracts agree; JSON/exit codes have consumer tests. Exclude credential display, GUI and unsupported authentication shortcuts.

### Goal 4: Refresh useful evidence within predictable cost

**Outcome:** select tool-critical changed, missing and stale evidence instead of replaying the catalog. Depends on Goals 1-3; reconcile #119 before stacked #120. Private account planning is separate from the public weekly queue.

Retain immutable source/package/schema/account/inventory/cohort/request identity and legacy hashes. Add a versioned compatibility key over relevant namespace, exact request recipe, relevant app/resource metadata, execution policy and collector semantics. Reuse references original observation IDs/dates; it never relabels evidence as newly collected. Relevant changes invalidate reuse; an unrelated display-name change need not. Migration tests preserve legacy exact resume.

Deterministic priority: tool-critical changes, missing evidence, bounded unresolved failures, overdue refresh, exploration, with reasoned deferrals and a bounded fairness share. Proposed defaults: daily tool-relevant public definitions/metadata, private planning evidence at most 24 hours old, broader research seven days; stable-failure cooldown starts at 24 hours and backs off to seven days, reconsidered immediately on relevant changes. Revalidate actual issued tokens on each acquisition. Use at most three recognized transient retries within global budgets. Freshness is a measured policy, not evidence-validity or authorization lifetime.

Count issuance, retries, bootstrap, inventory pages, sources and all other external operations in separate counters and the total. Persist intent before dispatch, conservatively charge uncertain attempts, and retain durable terminal evidence before completion. Crash after remote issuance but before local durability leaves unknown, not proof of no request. In the next authorized run, an existing non-mutating collection operation may receive one explicitly recorded recovery retry within budget. No automatic retry of sign-in, registration, consent, publication or other mutations; no exactly-once remote guarantee. Projection/export/publication recover independently without issuance.

Make #120 selection-sidecar/state crash-consistent; preserve its existing transport/no-plan gates. Measure source/inventory time, process starts, projection, database I/O, requests/retries/waits, peak memory and useful new/refreshed facts before adding concurrent requests.

**Done when:** all-fresh input yields no issuance plan; relevant/unrelated changes invalidate/preserve eligible reuse correctly; fairness/cooldown/crash tests pass; selection is reproducible; measured cost falls against the frozen baseline without dropping validation/completeness. Report freshness misses when budget prevents targets; do not silently relax either.

### Goal 5: A bounded discovery-improvement laboratory

**Outcome:** improve coverage/cost while deterministic production remains independent of agents. Depends on collector and evidence contracts; one experiment is sufficient for v1, further research must not block release.

An agent receives only allowlisted sanitized gaps, public research and synthetic cases. It may propose hypotheses/tests/patches and interpret reports; it cannot access production credentials/private stores, improvise live authentication, expand authorization, change an active recipe or approve/publish its own findings. Dedicated VMs/containers preserve these boundaries.

Start with implemented protocols: first-success versus targeted cells, published callback count/order, supported explicit versus `.default` requests, narrowly justified resources or native batching/projection. Broker hints remain hypotheses. Record hypothesis, primary outcome, frozen cohort, source/package, private namespace, recipe difference, budgets and stop condition. Separate local performance replay from authorized live A/B tests; counterbalance order when service drift matters, retain a holdout, and report effect size/sample limits, failures, unknowns, session loss, throttling and extra scopes.

**Done when:** one separately authorized bounded experiment completes with reproducible evidence and a reviewed promoted, rejected or inconclusive disposition. Promotion requires demonstrated benefit, no privacy/correctness/scope/prompt regression, bounded cost, fixtures, review and a new policy version. A valid rejected or inconclusive result completes this goal; a new success is not required. No open-ended live sweep is implied.

### Goal 6: Release the supported product

**Outcome:** a fresh administrator can install, operate, recover and upgrade the declared v1. Depends on Goals 1-4, one closed Goal 5 experiment, and separately authorized service/hosted proofs where needed.

Exact release source, matching full package, locked dependencies, migration rollback, SQLite-aware backup/restore, consumer contracts, privacy and support boundaries must agree. No supported-matrix correctness/security blocker remains. Exports bind schema/version, source/recipe, time bounds, counts and hashes; preserve portable consumers or version migration. New storage/sharding needs measured justification.

Use #119's exact immutable reviewed candidate, validated producer/source origin, separately authorized reviewer/main permissions and expected-old data parent. Reviewer text alone is not authorization. Test tampering, stale parents, expired artifacts, lost acknowledgement, retry and recovery. Verify actual hosted permissions/API behavior separately before relying on publication; artifact retention is not backup. Production workers and publication writer have separate privileges.

Software passkeys are exportable signing credentials and ESTS cookies are session credentials, not hardware isolation. Keep both out of logs/evidence/exports/agent inputs; pin dependencies, use protected secret storage and document rotation, revocation and cleanup. A historical login does not prove today's pipeline. Guide operators through costs, pause/expiry, corrupt stores, restore/upgrades and decommissioning without an agent.

**Done when:** a fresh operator completes all four admin workflows and collector recovery from published instructions on the supported matrix with matching receipts. Missing required live evidence leaves a release candidate. Scheduling/Actions enabling remain separately authorized.

## Sequence and progress scoreboard

Ship Goal 1 first; Goal 2's comparison contract can proceed alongside offline tests. Complete Goal 3 before widening the catalog, Goal 4 before recurring refresh, one bounded Goal 5 experiment, then Goal 6. Keep #117/#119/#120 as scoped draft building blocks until integration/runtime/live gates pass; #119 precedes #120. Do not silently merge draft code as roadmap work.

Track validated tool workflows, comparable changes and false-change fixture rate, fresh context-matched evidence, recovery correctness and pending/unknown work, useful facts per request/minute including throttling, provenance, consumer compatibility and privacy gates. Always show denominators: candidate IDs, verified apps, pairs, exact cells, exclusions, completed failures, successful issuance and API checks differ. Catalog size or one coverage percentage is not product completion.

## Supporting engineering backlog

The detailed guidance below is retained from the existing plan. Its priority numbers organize supporting work; the six goals above own delivery order. Expansion ideas and performance experiments are not extra v1 release gates.

| Priority | Improvement | Evidence required before shipping |
| --- | --- | --- |
| 1 | Remove avoidable full-history expansion, repeated native process starts, and repeated metadata projection | Same reports/checkpoints, corrupt history still rejected, measured elapsed time and peak memory |
| 2 | Make unattended resume and failure handling predictable | Kill/restart and expired-session tests; bounded retries; no duplicated completed requests |
| 3 | Plan incremental refreshes from freshness and missing evidence | Stable selection manifest, explicit budgets, changed-source and overdue-item tests |
| 4 | Broaden targeted evidence collection | Separate account/resource/flow results; documented permission and interaction requirements |
| 5 | Partition public exports and improve lookup | Round-trip parity, compatible schema, bounded memory, deterministic ordering and manifests |
| 6 | Improve CLI inspection and teaching views | Clear evidence labels and useful diagnostics without displaying credentials |

## Make the existing work cheaper

Measure each stage separately: source download/validation, inventory paging, planning, native process startup, database reads/writes, token requests, metadata projection, reporting, and export. Record elapsed time, request/process counts, retry waits, bytes read/written, and peak memory. Summaries should be bounded and contain no response bodies or credentials. Distinguish CPU cost, service latency, and intentional pacing before optimizing.

Prefer narrow projections for frequent status checks. Keep full validation for imports, publication, and authoritative reports. Do not gain speed by dropping historical validation, hiding malformed records, or treating incomplete work as complete.

Measure inventory sorting and canonical hashing separately: the frozen recipe currently binds the complete inventory, so a small selected batch can still pay for a large snapshot. Any cached digest must be bound to verified content and schema, preserve existing cohort identity, and invalidate on content changes. File modification time alone is insufficient.

Reduce repeated serialization and native invocations. Consider a bounded native batch operation only if measurements show startup or serialization dominates. Preserve per-attempt durability: metadata projection may lag and be repaired, but an issued observation must not disappear because a large batch crashes. Test crash boundaries before increasing transaction size.

Size processing batches from measured latency and memory. Preserve frozen membership and recipe identity when changing runtime batch size. Time budgets need clear stopping behavior between requests or clients; today a processing batch can extend the requested budget. Report this honestly, and consider a cooperative deadline/cancellation check at smaller safe boundaries.

Do not start with broad parallel token requests. First eliminate local overhead. If parallelism later proves useful, use small explicit concurrency, per-tenant/service limits, shared throttling/backoff, one coordinated writer, and bounded queues. Compare throughput and throttling against serial collection. More workers do not inherently reduce runner-minute cost.

## Run without model supervision

Provide one documented start/resume command and one cheap offline status command. Report stable exit codes or structured reasons for completion, budget stop, transient exhaustion, expired session, authorization failure, configuration error, and required human interaction. Include selected/completed/pending counts and a meaningful progress timestamp.

Use an ordinary local scheduler or service for repeated runs; the collector must not require an agent to poll it. A supervisor should use an exclusive lock and durable run identity rather than trusting a saved PID alone. Support cancellation, stale-run detection, restart after a machine reboot, and explicit session renewal policy. Credentials stay in the existing protected storage/session mechanisms. Do not turn a transient retry into repeated automatic sign-ins or consent prompts.

Keep one private state directory per account. Pin the source/package/schema versions and capture the frozen recipe before work starts. Distinguish primary collection completion from metadata projection, export, publication, and backup completion. A failed publication must be retryable without new authentication or token requests.

GitHub Actions remain disabled and manual-only. Any future hosted run needs separate authorization, an explicit runtime/concurrency budget, Linux-only scope for now, and no automatic build matrix. A local scheduled run should remain fully usable when hosted or model quota is exhausted.

## Refresh only what needs evidence

Build deterministic queues for newly discovered IDs, missing inventory, newly registered applications, changed public metadata, changed callbacks/resources, stale successes, unresolved transient failures, and targeted deep-flow research. Preserve the previous cohort as history; create a new one when membership or recipe changes.

Use separate freshness policies by evidence type. A public name, an application registration, a session-dependent successful scope set, and a failed request should not share one expiry rule. Apply a retry cooldown to stable repeated failures while retaining eventual rechecks. An HTTP 400 is not proof of permanent unavailability. Expose why each item was selected or deferred.

Refresh sign-ins with an explicit overlapping time window and deduplicate aggregate evidence. Investigate service-supported paging/delta/caching only where the endpoint actually supports it. Keep published sources pinned or content-hashed and record both source observation and local collection dates. Treat documentation GUIDs as typed candidates rather than automatically attempting thousands of registrations.

Any service principal created after an inventory was frozen needs a fresh inventory and a narrow follow-up cohort. Do not rewrite a historical cohort to include later registrations.

## Collect more useful evidence

Prioritize evidence that answers a concrete question:

- **Application identity:** verified owner organization, enabled state, assignment requirement, client/public-client hints, identifier URIs, callback types, and conflicting source claims. Separate application IDs, permission IDs, role IDs, tenant IDs, and unresolved identifiers.
- **API definitions:** delegated scope names/IDs, application roles, enabled state, consent classification and published descriptions where available, plus definition origin. Keep application-defined roles distinct from service-principal-local roles and published definitions distinct from grants.
- **Consent context:** distinguish published client/resource relationships, tenant grants visible to the observer, and scopes actually issued for an exact account/request. A first-party app or successful observation does not establish universal preconsent.
- **Flow coverage:** selectively expand callbacks and the three implemented protocols after first-success coverage. Keep tested, failed, interrupted, excluded, and untested cells separate. Investigate broker/device-code or other flows as separate research features only when their interaction and security requirements are understood; callback hints alone do not establish support.
- **Failure categories:** preserve safe numeric codes and typed categories for assignment, interaction, consent, policy, unsupported request, transient service failure, and unknown. Only assert a cause when evidence supports it; never retain raw identity error bodies.
- **Token diagnostics:** allowlisted claim-field presence, issuer/audience match, scope/role values, token version, and lifetime summaries may help. Evaluate privacy before retaining extra claims. Never save raw JWTs, account names, object IDs, device details, session IDs, or cookie contents in the catalog.
- **API acceptance:** offer a separate, explicit, harmless read-only validation for a selected API where appropriate. Keep issuance, signature verification, and API acceptance as distinct evidence levels. Do not silently call every resource API during bulk discovery.
- **Account comparison:** compare the same recipe across authorized accounts without merging their private namespaces. Explain differences as context-dependent observations rather than app-wide capabilities.

## Storage and publication

Keep SQLite as the private operational database. Benchmark indexes against actual pending-work, latest-plan, client/resource, namespace, and freshness queries. Add migrations with rollback/recovery tests before changing the schema. Use SQLite-aware backups rather than copying a live database without its transactional state. Define retention and compaction for superseded observations while preserving provenance needed to reproduce conclusions.

For growth, evaluate normalized immutable facts referenced by stable keys instead of repeating large source, application, and scope arrays in every observation. Separate current views from historical evidence; current views must be rebuildable. Do not introduce a new format until size/read/write measurements justify migration cost.

Keep public exports credential-free and independently validated. Partition large exports by stable application-ID ranges or prefixes, not mutable display names. A manifest could record schema version, source commit, collection bounds, shard counts, byte sizes, and content hashes. Consumers should download only needed shards and detect missing/incompatible pieces. Specify canonical ordering, UTF-8 encoding, newline rules, and whether hashes identify compressed or decompressed bytes. Retain existing JSON compatibility during migration; compact JSON/gzip is the immediate proven option. JSON Lines or columnar downloads are optional analysis formats, not replacements for the source ledger by default.

Automate export deduplication, catalog-membership checks, privacy/schema checks, hash verification, and publication receipts. Keep public-source facts separate from anonymous session observations. Public dates and provenance should explain when and how a fact was learned without identifying the account. Publish counts of excluded/unknown candidates so a large catalog is not mistaken for exhaustive successful discovery.

## CLI and validation

Build on the existing native implementation and PowerShell adapter before considering a language rewrite. Keep collection, planning, reporting, and export contracts reusable by a future GUI. A teaching view should explain evidence and token fields using sanitized metadata or synthetic examples; showing stored credentials must never be its default.

Useful CLI additions include a dry-run plan with estimated work, filters for missing/stale/changed evidence, concise status, a per-application evidence explanation, comparison between runs, and export selection. Route errors to safe actionable categories and make JSON output stable for schedulers.

Require focused tests for exact resume, interruption after issuance/checkpoint/projection, corrupt historical data, mismatched indexed/payload fields, missing files, private-path violations, identity mismatches, throttling, and export privacy. Use synthetic fixtures for broad cases and a small authorized live proof for changed service paths. Benchmark the same frozen inputs and trusted package; record correctness, memory, then time. Do not rebuild native packages or rerun unchanged suites merely to get another green result.

Use deterministic scripts for bulk execution and analysis. Delegate bounded script execution or read-only output checks to Luna Maximum; keep production coding and architectural/security reviews with the primary agent or Sol, with Astra for critical trust-boundary changes when warranted. Review one concrete milestone at a time.
