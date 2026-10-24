# Consolidated offline protocol-boundary milestone

Nathan adopted [Dot's review and milestone](goal6-dot-offline-transaction-review.md) from `codex/dot-goal6-review-handoff-20261024`, exact source `18a617f`. The review was copied unchanged into this branch; its closing unpublished statement describes its preparation state, not the adopted branch's current status. This milestone completes the adopted **offline** scope only. It adds no real HTTPS dispatcher, credential reader, runner action entry point, hosted operation, signing or operational authority.

## Shared clock correction (M1)

`prepare` and `open` require the transaction's clock to be exactly the fake transport's timing domain before any store or lock is created. Distinct fake handles and fake/default mixtures refuse without changing saved evidence. Both omitted clocks select local Linux wall/monotonic/boot timing; simulated delays require a shared branded fake clock. Shared request/total boundaries, response watermarks, rollback, boot identity, durable-charge expiry and no-reset rules remain enforced.

Timing is rechecked after serialization/validation and immediately before the recording fake logs an exchange. Tests advance the shared clock inside serialization and fsync instrumentation: the durable charge remains, the result is conservative unknown, and zero late exchanges are recorded. These are deterministic fake boundary tests, not real HTTP abort or scheduler guarantees.

## Serialized original-byte flow

`TokenForgeArtifactProtocol.mjs` contains pure constructors/validators. `TokenForgeOfflineSchema.mjs` provides complete duplicate-free bounded JSON parsing and strict scalar/identity validation. The transaction uses them through its module-private, deny-by-default recording fake; arbitrary callbacks are still refused.

- Create/Finalize use POST and pinned Twirp service paths. Wire fields are snake_case, backend routing is a pair of synthetic GUID strings, Create version is numeric 4, Finalize size is a signed-int64 decimal string, and its hash is a scalar string. Optional retention is omitted by this profile; it does not claim a one-day-retention request was made.
- Block contains **only the original C**, with explicit content length. Its dummy signed query is preserved byte for byte while fixed `comp=block` and a URL-encoded Base64 block ID are appended. Commit uses one explicit `Uncommitted` XML entry; no Latest or previously committed fallback exists.
- REST observer requests have fixed method/path/API-version and credential-slot placement. One redirect response plans a separate download-capability request with no Read bearer slot. A second redirect refuses. No URL is followed or resolved by this implementation.
- URL policy accepts only reserved `.invalid` fixture origins and exact dummy capability values. It rejects unknown origins/ports/userinfo/fragments/path normalization, duplicate or encoded operation keys, unsupported query keys and altered capabilities. This is not approval of real service origins or production SAS handling.
- Twirp IDs are signed-int64 decimal strings. REST integer tokens become BigInt before normalization, preserving IDs above JavaScript's safe-number range; quoted numbers, decimal/exponent coercions and signed64 overflow refuse. Journal IDs use the same domain.
- Response bodies/status/header schemas are bounded and deliberately narrow. Create/Finalize accept exactly one snake_case or camelCase response alias and reject conflicting aliases. The compatibility policy is a design choice, not an observed service response. Unknown schema/header fields refuse rather than being silently accepted; this will need separate review against real responses.

Serialization failures occur after durable reservation in the state-machine dispatch path. They consume their fixed charge, retain C and cannot replay mutations or replenish budgets. Invalid response/JSON errors are static reason codes, including native decoder/escape failures; raw bodies, queries, capability values and error text do not enter journal/result summaries. A submitted or echoed digest never proves independent authority.

## Evidence actually observed

The observer reports artifact provenance only as `observedContext={repositoryId,runId,source}`. These are fields in the selected REST artifact profile. It does not fabricate artifact-own attempt, workflow ID or repository name from expected inputs. Separate Run reads compare the current workflow/attempt before and after download. A changed current Run fails; a missing artifact-own attempt field remains missing. Tests deliberately show that unrepresented artifact-own attempt/workflow changes cannot be claimed as observed.

Every result remains `OfflineFakeTransactionObservation` with false service-interoperability, operational-emission, privacy-approval and artifact-own-attempt/workflow observation flags. Exact byte equality and structural ZIP validation are not the existing content/business-schema or privacy decision. No operational subject or policy is emitted.

## Source provenance and validation

The [provenance dossier](goal6-offline-provenance.json) pins the reference artifact distribution, generated schemas, runner source and Node source by exact commit/hash. It documents the source-supported future JavaScript action context, conditional Results URL injection and unresolved credential/runtime facts. Public source was read anonymously; no candidate dependency was installed or executed for source inspection. Existing local Node/Python/PowerShell/Pester tools perform synthetic Linux checks only. A source/version match is not a reproducible-build or selected-runner attestation.

The focused command is:

```sh
node --test tests/ArtifactTransaction.test.mjs tests/ArtifactProtocol.test.mjs
```

The final exact-source receipt records this suite, the existing Pester 6.2 Sealer preset from the matching immutable-source kit, source/runtime pins and independent review. The new kit is a private review/test bundle, not a release or published artifact. Its native/module/build inputs must match the existing pinned runtime; none is rebuilt unless they change. Producer-run suites and independent static/hash review are identified separately.

Stale-lock refusal is unchanged. An actual process exit leaves evidence and a lock that prevents automatic reopening. No takeover, cleanup, power-loss durability, SIGKILL-at-every-write or cross-job recovery claim is added. Older journal evidence is preserved and refused rather than migrated.

The final authorized push contains only scoped source/tests/sanitized documentation. Private kits, archives, raw test logs, evidence, credential material and local account paths are excluded from newly pushed content. Existing historical evidence is retained without rewriting history. No Actions setting, workflow trigger, production sealer, native source, tenant permission, PR or merge is changed.

## Remaining live prerequisites

Offline acceptance cannot resolve real service schema/header variations, actual backend IDs/capability scope, exact hosted runner/action/Node distribution provenance, real origin/version compatibility, wire replay/TLS/proxy behavior, raw ZIP preservation or artifact-own attempt binding through trusted content. Any later implementation or hosted experiment needs its own reviewed scope and explicit authorization. Hosted control limits, source-ref exclusion, Actions restoration and operational activation remain unimplemented and unauthorized. These are future live prerequisites, not claims of live or production completion from this milestone.
