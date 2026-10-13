# Understand catalog and flow coverage

Development version 0.42 runs `research report` directly in the native CLI. It reads
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
error. Files and their parent directories must meet the existing private-path rules.

The text view summarizes counts. `--json` includes application rows unless
`--summary-only` is supplied. `--app` selects one canonical application ID;
`--max-age-hours` changes the freshness window from its default of 24 hours.

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

Reports compare parsed timestamp instants, including their offsets. Equal plan instants
use the ordinal greatest plan fingerprint for deterministic selection. Equal attempt
instants use later input order, matching checkpoint append order; SQLite exports order
by observation time and recorded sequence. This replaces the earlier report's string
ordering and unspecified plan ties.

The adapters validate complete input documents before selecting an app or account,
including historical metadata, source conflicts, flow hashes, and plan/attempt context.
Duplicate JSON fields are rejected. SQLite opens read-only and is never upgraded by a
report. Output contains diagnostic metadata, not credentials, callback URLs, or raw
authentication responses. Local report JSON can still contain private correlation
fingerprints and sanitized sign-in summaries; keep it in private storage.

Synthetic checks and public-catalog scale validation are in progress on the feature
branch. This guide does not claim live authentication or additional protocol support.
