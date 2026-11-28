# TokenForge roadmap

The first release lets an operator use the CLI or a local MCP client to answer “Which Microsoft applications match these attributes, and what evidence supports each match?” Discovery runs alongside product development. Subsequent milestones connect search to an operator-run token request and qualify additional platforms.

## Starting point

At discovery-data revision `ec3d72d`, the published partitions contain 5,500 distinct identifiers. The verified partition has 2,066 IDs with matching evidence records. Of these, 1,837 record a newly added service principal, 227 an existing one, and two an owner observed in sign-in data. The other 3,434 IDs are non-verified. The total population of Microsoft-owned multi-tenant applications is unknown.

Ownership, observation in a tenant outside the owner's tenant, and configured sign-in audience answer different questions. The verified evidence records mark the owner as outside the target tenant. The reviewed catalog snapshot has no configured sign-in-audience attribute in its verified application records. Search results should preserve that distinction.

At main revision `f7bf35e`, PowerShell supports offline evidence lookup, and the native CLI has SQLite reporting and token acquisition code. The documented release candidate supports Linux x64 offline use. The first combined discovery run covered five sources over a 30-day window and found 17 previously uncataloged IDs. Review verified four, identified one managed identity, and left 12 unresolved. See the [existing lookup](../README.md#get-started), [native CLI support](native-cli.md), and [discovery milestone evidence](signin-review-provisioning-plan.md#milestone-evidence).

## Parallel milestones

Start A1 and B1 together. Agent A owns the CLI query, MCP adapter, and parity tests. Agent B owns the discovery scripts, reports, and replay fixtures. Both use the pinned catalog revision and a small shared query fixture maintained by A. B can propose additional fields with examples independently of the first release.

### A1 · Search the published catalog from the native CLI

Provide a documented command for search and exact-ID detail. Default to verified applications and allow explicit inclusion of non-verified entries. Support ID, name, resource, scope, and tenancy-evidence filters.

Acceptance criteria

- The pinned snapshot returns 2,066 distinct IDs by default and 5,500 with both partitions included.
- Stable JSON identifies the catalog revision, partition, matching evidence, source, observation date, and unknown fields.
- Fixtures cover missing audience, conflicting metadata, no match, and multiple requested scopes. All requested scopes must match one evidence row for the same resource.

### A2 · Release searchable CLI and MCP interfaces

After A1, expose the same query implementation through a local stdio MCP server with `search_applications` and `get_application`. Ship a Linux walkthrough that uses one catalog snapshot through both interfaces.

Acceptance criteria

- A fresh local MCP client can list the tools, search with bounded pagination in deterministic order, and retrieve an exact record.
- CLI and MCP return the same IDs, catalog revision, and supporting evidence for the shared fixture. Both complete the walkthrough offline without credentials.

### B1 · Measure discovery coverage

Build a deterministic offline report from pinned partitions, upstream captures, and retained review receipts. Measure distinct IDs, overlap and unique contributions by source, review dispositions, and gaps in ownership and tenancy evidence.

Acceptance criteria

- A second run on the same inputs reproduces the report. The report reconciles both partitions and accounts separately for all 17 candidates in the recorded review batch.
- The report attributes new candidates to sources wherever the retained evidence permits and labels missing inputs and unknown coverage explicitly.

### B2 · Automate the next discovery increment

After B1, extend the [existing delta and review workflow](catalog-candidate-ingestion.md) to compare a previous snapshot with a newer retained capture. Emit deduplicated additions, changed claims, provenance, and reasons for review.

Acceptance criteria

- An unchanged replay adds zero review items. A changed capture identifies the source of each change and reopens an unresolved case when new evidence arrives.
- An interrupted or incomplete replay records its coverage gap. Verified promotion follows the existing exact-AppId ownership review.

## After the searchable release

### M3 · Hand off a token request to the local CLI

Add an MCP planning tool that gives the operator a local CLI handoff for a resource and requested scopes using an explicitly configured, authorized client. Reuse the [existing scoped-token workflow](scope-token-workflow.md). The CLI checks the issued result and retains responsibility for handling credentials.

Acceptance criteria

- Mocked identity responses exercise success, missing scopes, wrong audience, and required user interaction through the handoff.
- MCP receives neither access nor refresh credentials. Any separately authorized live qualification has its own receipt.

### M4 · Qualify cross-platform distribution

Apply the A2 walkthrough and M3 configured-client scenarios to each platform, starting with Linux x64. Windows and macOS qualification begins on explicit request.

Acceptance criteria

- Track installation, offline query, MCP stdio startup, and authorization separately for each OS and architecture tested.
- Each published support claim identifies the package revision and a passing receipt for that capability. Untested capabilities remain marked as such.

## Agent handoff and completion

Use one issue per milestone with its owner, dependencies, pinned inputs, deliverable, and acceptance cases. Start from current main. Commit and push scoped changes after the smallest relevant local Linux checks. Record the revision, command, outcome, and remaining unknowns in the milestone receipt. Reuse retained evidence for discovery replay. Hosted runs, live tenant activity, and additional platform runs require separate authorization.
