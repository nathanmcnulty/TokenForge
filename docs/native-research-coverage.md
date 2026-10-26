# Understand catalog and flow coverage

Version 0.42 runs `research report` directly in the native CLI. It reads
JSON or SQLite metadata and does not need PowerShell, authenticate, request tokens,
register applications, or open an encryption key. The PowerShell report uses the same
coverage engine.

```powershell
# Catalog categories and conflicts; no account-specific flow conclusions.
tokenforge research report --metadata-path /private/applications.json

# Select one account's flow observations and include application details as JSON.
tokenforge research report --metadata-path /private/applications.sqlite `
  --flow-path /private/flows.sqlite `
  --tenant-fingerprint <tenant-hash> --principal-fingerprint <account-hash> --json

# Restrict the report to one app, or return only aggregate counts.
tokenforge research report --state-path /private/research --app <app-id> --json
tokenforge research report --state-path /private/research --summary-only --json
```

With no explicit metadata or state path, the command reads the selected profile's
state path and expected account fingerprints. It reads profile configuration, never
the profile's credential storage. `--profile` and `--root` select that configuration.
An explicit state path prefers `applications.sqlite` and `flows.sqlite` when present.
Explicit `--metadata-path` and `--flow-path` override those defaults. Missing optional
state flow evidence means no selected plans; a missing explicit flow path is an
error. JSON inputs are capped at 128 MiB, matching the catalog and flow policies. Files
and their parent directories must meet the existing private-path rules.

The text view summarizes counts. `--json` includes application rows unless
`--summary-only` is supplied. `--app` selects one canonical application ID;
`--max-age-hours` changes the freshness window from its default of 24 hours.

## PowerShell SQLite reports

`Get-TokenForgeResearchCoverage` delegates directly to the existing native report
when metadata is SQLite, flow evidence is absent or SQLite, and at most one
application is selected. It passes explicit paths and account selectors; it does
not discover a profile or sibling flow file. JSON, mixed-format, and multiple-app
requests retain the existing adapter.

This avoids expanding and serializing the complete ledgers through PowerShell.
Both paths still validate complete history before filtering. Native reporting is
bounded to five minutes, suppresses child-process diagnostics on failure, and uses
the same private-path checks without creating missing stores or directories.

A local comparison on the completed assessment (5,515 catalog applications and
2,030 selected plans) produced identical detailed report fields and values.
Elapsed time changed from 188.4 to 48.8 seconds; maximum resident memory per run
changed from 819,748 to 446,212 KiB. These are one local comparison using the same
saved inputs and existing Linux package, not a throughput guarantee or a sum of
concurrent process memory. See the [validation summary](sqlite-report-adapter-validation-2026-10-16.json).

## Read the evidence in order

1. **Published role and callback hints** describe source metadata. A broker-shaped
   callback does not demonstrate broker authentication. No required flow is inferred.
2. **Metadata conflicts** preserve differing published names or owner hints. They do
   not decide which source is right or authorize service-principal registration.
3. **Inventory and registration** describe the selected tenant. A later registration
   attempt can require a fresh inventory read before treating the inventory as current.
4. **Flow coverage** selects the newest plan for each client/resource in the explicitly
   selected tenant and account. Older plans remain historical, not additional current
   coverage.
5. **Attempts** distinguish terminal, interrupted, and untested slots. A newer failed
   or Started attempt replaces an older success for that slot. Fresh success is checked
   against one captured UTC clock and the configured age limit. Token issuance does
   not establish signature verification or successful API operations.

Reports compare parsed timestamp instants, including their offsets, and return report
timestamps in UTC. Literal names that resemble dates remain unchanged strings. Equal plan instants
use the ordinal greatest plan fingerprint for deterministic selection. Equal attempt
instants use later input order, matching checkpoint append order; SQLite exports order
by observation time and recorded sequence. This replaces the earlier report's string
ordering and unspecified plan ties.

The adapters validate complete input documents before selecting an app or account,
including historical metadata, source conflicts, flow hashes, and plan/attempt context.
Duplicate JSON fields are rejected. Flow timestamps use the existing SQLite policy's
explicit ISO offset format. SQLite opens read-only and is never upgraded by a
report. Output contains diagnostic metadata, not credentials, callback URLs, or raw
authentication responses. Local report JSON can still contain private correlation
fingerprints and sanitized sign-in summaries; keep it in private storage.

The [sanitized validation report](native-research-coverage-validation-2026-10-13.json)
records native checks, package parity, and reporting across 5,455 published applications.
It also records the isolated rerun after a local timezone-fixture timeout. These
checks do not establish live authentication or additional protocol support.

Version 0.44.2 classifies published callbacks by parsed URI structure in the shared
native and PowerShell report engine. HTTP/HTTPS callbacks with an exact `localhost`
host, URNs, and HTTPS paths ending in the case-sensitive `/oauth2/nativeclient`
suffix receive `NativeCallbackPublished`. Broker schemes receive a broker hint;
other HTTPS callbacks receive a browser hint. `nativeclient-help`, `/localhost`,
and `localhost.example.test` do not turn an ordinary HTTPS callback into a native hint.

Malformed callbacks, other custom schemes, and callbacks containing userinfo,
query or fragment receive `OtherCallbackPublished`. This category does not establish
unusability. A native-client path on an arbitrary host does not establish trusted
ownership or planner eligibility. Labels describe source metadata only; actual flow
observations and the planner's execution restrictions remain separate. Reports do
not return callback URLs or change their catalog inputs.
