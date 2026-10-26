# Bounded MicrosoftApps input diagnostics

This milestone follows the MicrosoftApps handoff at `ebdaa42fd7021456071b4bd61dfffb785b449740` from owning result `4b95c76f3a7eccf4fafc67d9e76d7563a12e5c74`. The coordinated dependency handoff is pinned at `b7831a35680b5dd917b4d07eaee25f947c2a2f59`, indexed by `61b0536e4090b58fe610e04dcfe3aa6b83fc5b30`; all three task file hashes were checked against its manifest. Private coordination prose and raw responses are not copied into this public checkpoint.

## Evidence and authority

Dot's independently performed private inspection localized the historical trial's rejection to MicrosoftApps. ROADtools and resource candidates succeeded; MicrosoftApps was Invalid after one attempt. Its artifact provides source statuses and counts, but **no detailed rejection reason, failed-source raw bytes or failed-source response hash**. Those facts come from Dot's handoff; they were not established by downloading the artifact in this session. Historical bytes cannot be recovered by a current GET.

The adopted scope permits one anonymous GET of the existing fixed MicrosoftApps URL, no redirects or retries, 8 MiB maximum and 30 seconds. Acquisition uses the already reviewed helper only after verifying the pinned archive and complete extracted execution inventory. Response bytes and acquisition facts stay in a fresh private directory as immutable files. Acquisition codes are the fixed literals `Retrieved`, `Transport` and `HttpStatus`. Acquisition failure ends collection without another GET or another source. A current response is current-input evidence, never proof of the historical response.

## Offline diagnostic command

Run the repository-only adjunct with existing PowerShell 7.6.7 and the matching approved Linux package:

```powershell
./scripts/Test-TokenForgeMicrosoftAppsInput.ps1 `
  -InputPath /private/path/source.json `
  -NativeExecutablePath /private/path/reviewed-package/tokenforge `
  -OutputPath /private/path/new-diagnostic-directory
```

The command performs **zero network requests**. It reads at most 8 MiB, applies the existing strict UTF-8/JSON reader, whole-source validator and actual single-source projection, and writes only `diagnostic.json` in a new mode-0700 directory. The result file is created exclusively and made mode 0400 after flushing. Storage/runtime/programmer failures remain fatal; unfinished output owned by this invocation is removed while the input and sibling evidence remain untouched.

The existing validator and projector decide acceptance. An explanatory locator runs only after a recognized whole-source rejection; it uses the same field guards to identify the first refused contract. A disagreement can report generic `SourceContract`, never acceptance. No invalid row is dropped, identifier repaired, private field admitted or alternate source followed.

| Reason code | Meaning |
| --- | --- |
| `Accepted` | Existing whole-source validator and actual projection accepted the input |
| `Utf8` | Strict UTF-8 decoding refused the bytes |
| `JsonSyntax` | JSON syntax/depth refusal |
| `JsonStructure` | Structural JSON refusal, including duplicate keys |
| `SourceShape` | Wrong root/record shape, fields or source record limit |
| `ApplicationIdentity` | Strict published application-ID spelling refused |
| `OwnerIdentity` | Owner hint type or strict nonzero GUID refused |
| `PublicText` | Public text type/length/privacy guard refused |
| `DuplicateIdentity` | Duplicate normalized AppId plus exact Source identity |
| `SourceContract` | Recognized source refusal not localized by the explanatory locator |
| `SourceProjection` | Existing single-source claim projection refused otherwise validated input |

Output contains only fixed literals, a source-document hash/size, timestamp, numeric record index/count and booleans. It does not contain field values, exception text, caller paths or input-supplied URLs. The numeric index locates a record in the separately held private response; it does not make that record suitable for publication.

The public three-file exchange schema, producer, reader, source status semantics and import behavior are unchanged. The diagnostic emits no exchange and performs no import. Existing all-sources-required completeness, initial empty incomplete ledger and previous-byte/date fallback remain authoritative. Schema refusals still receive no transient retry. Existing tests and new actual-entry cases preserve successful ROADtools/resources observations independently from the incomplete merged catalog.

## Dependency and package maintenance

No production, build/bootstrap or test dependency is added or removed. The diagnostic and regressions use the existing PowerShell/.NET/Pester stack; no Python, Node, package manager, parser package or runtime installation is introduced. Native CLI/transactional SQLite architecture, project references and locks remain unchanged.

The diagnostic is deliberately repository-only: the package builder's fixed copy list does not include it. The existing product archive remains SHA256 `2b92b0d0662809f3aeaf4992935cc38323c78d8223430b5f58eb9216156ef3e8`, source `c7d0b255612280e05605eca2e9ccfb44d5d68e18`. Its native executable pin is `48f51ba4a7ce275f0d2235437620a04aff8141bf692fbfbb741d3ce157a668a0`; Credentials DLL pin is `461eaec7702d1850207cdab50423f78db4c47b59b5c211a8b8124df43af83af6`. No compiled/module/packaged-health input change requires a native rebuild or replacement asset for this adjunct. The final receipt binds the new diagnostic's exact source separately from the unchanged kit used to execute it.

The approved PowerShell 7.6.7 archive remains SHA256 `3da36d92808db25aa2466422b1b765da792adc159d890512fbae852e2b495d3b`. Both exact archives still carry patching obligations: a future runtime/product update must revisit runtime version/architecture, executable and DLL pins, complete source/build/archive inventories, dependency locks where affected, notices, bootstrap delivery hashes and relevant local/hosted qualification. Do not substitute latest downloads or relax a pin to make an input pass. SDK 10.0.401 and existing SQLite dependencies remain the established build baseline; this diagnostic does not invoke a build.

Older Goal 6 helpers are retained for their deferred lane, not ported or deleted here. Verified executable consumers include `TokenForgeSealerPolicy.ps1` invoking `Test-TokenForgeSealerCaller.py`, whose source requires PyYAML 6.0.2; installed availability and installation provenance were not tested. `Sealer.Tests.ps1`, `ArtifactProtocol.test.mjs`, `ArtifactTransaction.test.mjs` and `LocalTlsTransport.test.mjs` consume the independent Python ZIP encoder/mutator. That differential-validation capability is purposeful; removal requires a separate bounded consumer/parity decision. Historical receipt links alone are not executable consumers. No YAML parser is replaced by regular expressions.

## Boundaries

No new hosted dispatch, artifact download/sync/import, Entra authentication, tenant change, dependency installation, Actions setting change, release asset, PR, merge or deployment is part of this milestone. Sanitized source/results may be checkpointed on the existing owning branch. The original Goal 6 custody/ZIP experiment, the low-severity equal-timestamp history-occurrence corner and helper retirement remain deferred. The final receipt separates the current-input diagnosis, synthetic tests, independent source review and historical observations.
