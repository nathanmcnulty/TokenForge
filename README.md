# TokenForge

TokenForge researches Microsoft Entra applications and the permissions available through them. It collects application metadata, tests supported token flows using an authorized account, and records the results for later comparison.

The project provides a PowerShell module and a native CLI. The [supported baseline](docs/runtime-baseline.md) is PowerShell 7.6+, .NET 10 and Pester 6.2 for tests; the native CLI supplies SQLite storage and offline reporting.

## Public health and private workstation work

Use [public metadata health and workstation sync](docs/public-metadata-health.md) for the credential-free collection → validated exchange → private SQLite loop. `pwsh scripts/tokenforge.ps1 health collect`, `health sync` and `health status` provide the command path; start with the checked-in synthetic fixtures. Status reports collection/import separately, freshness, conflicts and retention gaps. Account-bound discovery and exact-plan deep resume remain workstation operations under their existing authorization boundaries.

The proposed Linux workflow is dormant outside active workflows. Actions, live credentials and operational data publication remain blocked. Goal 6's original-ZIP/sealer experiment remains parked; historical receipts are not evidence of hosted completion. The [current handoff](docs/HANDOFF.md) identifies the reviewed source and local validation.

## Application database

The [public application catalog](https://github.com/nathanmcnulty/TokenForge/blob/discovery-data/applications.json) tracks candidate IDs, published metadata, sources, and observation dates. [Observed scopes](https://github.com/nathanmcnulty/TokenForge/tree/discovery-data/scopes) are published separately.

Documentation sources can also contain permission IDs and other GUIDs; catalog inclusion does not establish application identity. The [offline identifier comparison](docs/public-permissions.md#compare-identifiers-with-the-application-catalog) helps distinguish permission-ID overlaps.

Published permissions and observed token scopes are evidence, not a guarantee of consent or API access. Results depend on the account, tenant, application, resource, and authentication flow. Missing metadata means unknown; it does not mean an application has no permissions.

## Get started

```powershell
Import-Module ./src/TokenForge/TokenForge.psd1
# Download the public ledger, or use an existing local copy.
Invoke-WebRequest 'https://raw.githubusercontent.com/nathanmcnulty/TokenForge/discovery-data/applications.json' `
    -OutFile ./applications.json
Find-TokenForgeApplicationEvidence -Path ./applications.json -Name 'Azure'
Find-TokenForgeApplicationEvidence -Path ./applications.json `
    -ResourceId '00000003-0000-0000-c000-000000000000' `
    -Scope 'User.Read'
```

This read-only lookup reports published metadata with provenance, observation date, freshness, and evidence type. Add `-ObservationPath ./public-scopes.json` (or multiple paths) to search downloaded anonymous [scope exports](https://github.com/nathanmcnulty/TokenForge/tree/discovery-data/scopes) alongside published hints. It needs no profile, private history, or login. Filter by `-AppId`, `-Name`, `-ResourceId`, and/or `-Scope`; all scopes must match one evidence row. No match means unknown, not unsupported. See [lookup details](docs/application-metadata.md#public-evidence-lookup).

The older `Update-TokenForgeCatalog` / `Find-TokenForgeApplication` commands remain available for ROADtools published grants only.

To collect and test application metadata, follow the [discovery guide](docs/discovery.md). Runs use private SQLite databases for checkpoints and can resume after interruption. They run on your machine without Codex or GitHub Actions.

To acquire a token for a specific task, follow the [scope-to-token guide](docs/scope-token-workflow.md). For the authentication walkthrough and credential handling, see [login to token](docs/authentication-flow.md) and [security](SECURITY.md).

## Guides

- [Native CLI](docs/native-cli.md): installation, commands, and supported workflows.
- [Inventory](docs/inventory.md): public sources, tenant inventory, and explicit registration.
- [Research cohorts](docs/research-cohorts.md): frozen membership and resumable requests.
- [Application metadata](docs/application-metadata.md): provenance and history.
- [Public permissions](docs/public-permissions.md): API definitions and offline queries.
- [Private maintenance](docs/private-maintenance.md): encrypted backups and recovery.
- [Local validation](docs/local-validation.md): focused development checks.

## Development

Use local Linux validation. GitHub Actions are disabled; hosted runs require explicit approval. Windows and macOS builds are deferred.

Keep credentials and private tenant evidence outside Git. Public exports omit credentials and account namespaces. Tests use synthetic credentials and mocked identity responses; live validation is a separate step.
