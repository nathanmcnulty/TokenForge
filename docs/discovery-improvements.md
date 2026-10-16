# Discovery improvement plan

This is the engineering backlog for making long discovery runs cheaper, more complete, and easier to operate. It is a plan, not a claim that every feature exists. Keep operational instructions in [Run discovery locally](discovery.md), rather than adding run logs to the README.

## Starting point

The local assessment completed on 2026-10-16 finished its frozen cohort: 2,030 Graph client/resource pairs, with 238 successful acquisitions, 1,213 `NoRedirect`, 155 `BrokerRequired`, and 424 `Failed` outcomes. It used first-success exploration and at most one eligible callback. Completion means every selected pair was checkpointed; it does not mean all 5,455 public candidate IDs, every resource, or every authentication flow was tested. Other protocol/callback cells remain untested. These counts describe one account and recipe.

Already implemented:

- Standalone PowerShell discovery with no model/API dependency, private SQLite working stores, frozen cohorts, checkpoints, and bounded runs.
- Exact-plan resume that skips completed work, primary-evidence recovery, typed transient retries, and sanitized progress/failure summaries.
- Optional combined pending-client batches that reduce process and metadata-projection overhead without parallel token requests.
- Read-only cohort status and account-selected coverage reports; full-history validation before report filtering.
- Separate public metadata, permission definitions, anonymous observations, and private tenant evidence. Compact gzip catalog export preserves existing JSON compatibility.
- Explicit Microsoft ownership checks for registration. Documentation-only GUIDs require separate opt-in because permission IDs, examples, and tenant IDs can resemble applications.

The PowerShell-to-native SQLite reporting shortcut is currently under validation. Its benefit must be measured before adoption.

## Priority order

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
