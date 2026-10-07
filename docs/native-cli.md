# Native CLI and evidence store

The native CLI is a self-contained .NET executable per OS and architecture. Evidence commands
run directly in the shared core with bundled SQLite. Authentication commands currently invoke
the packaged PowerShell 7.4+ module; install `pwsh` and keep `src/` and `scripts/` beside the
executable. This is the migration bridge, not a standalone native OAuth engine or an OS keystore.
The actual issued-token policy is shared C# used by PowerShell and the native core.

```sh
tokenforge profile create --profile lab --tenant example.onmicrosoft.com --state-path /private/evidence
tokenforge login --profile lab --browser --interactive --prompt-passphrase
tokenforge status --profile lab --json
tokenforge doctor --profile lab --json
tokenforge token get --profile lab --resource graph --scope User.Read,Mail.Read --prompt-passphrase --json
tokenforge logout --profile lab --prompt-passphrase
```

Use `--login-hint user@example.onmicrosoft.com` for browser login or token acquisition when the browser has multiple accounts. The hint helps account selection; the bound profile fingerprints still enforce identity.

Native profile creation defaults to explicit passphrase storage because each CLI invocation is
its own process. The module still defaults to memory storage. Passphrases are read without echo
by PowerShell, never passed in process arguments or environment variables. The native command
parser has no raw-cookie, token, or passphrase argument. Token output contains metadata only.
Use the in-process module API for Graph SDK handoff; an SDK connection in a finished child
process cannot authenticate the caller's PowerShell process.

## Durable private evidence

SQLite is an opt-in evidence workspace. Existing discovery still writes JSON and updates the
application metadata catalog. Import/export bridges the existing scope database without putting
credentials in SQLite or changing working CI discovery. It preserves validated observations and
registration outcomes and records each source path and latest import date. A repeated import
is idempotent. Import validation and writes occur within one transaction; one malformed row
rolls back the entire import. Exports use a consistent database snapshot.

```sh
tokenforge evidence import --database /private/native/evidence.sqlite --input /private/evidence/scopes.json
tokenforge evidence export --database /private/native/evidence.sqlite
tokenforge evidence export --database /private/native/evidence.sqlite --public
```

Normal export includes private tenant/account fingerprints and registration history. Explicit
`--public` removes the fingerprints and registration history. Both exports are metadata only.
Output goes to stdout; use private filesystem permissions when saving private exports.
Storage refuses linked paths and broadly accessible directories/files. New databases use a
private parent and file from creation. Windows uses a protected current-user ACL; Unix uses
0700 directories and 0600 files. SQLite WAL/SHM files remain inside that private directory.
This database is not encrypted and must never store credentials.

## Stable plans and checkpoints

Provide a JSON array of client GUIDs. A plan freezes sorted, unique membership and batch size
under a content hash. Adding applications or changing batch size creates a different plan.
Chunks are assigned before filtering completed clients, so resume does not move members.

```sh
tokenforge evidence plan --database /private/native/evidence.sqlite --input clients.json --batch-size 100
tokenforge evidence pending --database /private/native/evidence.sqlite --plan PLAN_HASH
tokenforge evidence checkpoint --database /private/native/evidence.sqlite --plan PLAN_HASH --client CLIENT_GUID --outcome Succeeded
```

Historical registration records can retain the legacy empty GUID from existing JSON; plans reject it and it supplies no application eligibility or authorization.

Checkpoints record terminal execution outcomes. They do not create successful scope evidence;
import the corresponding scope observations separately. Failed checkpoints preserve earlier
successful observations and their dates. The existing CI rotating discovery chunks are not
silently migrated to these plans; integration is a later explicit migration.

## Build and platform limits

```powershell
./scripts/Build-TokenForgeNative.ps1 -Runtime linux-x64
# Also supported: linux-arm64, win-x64, win-arm64, osx-x64, osx-arm64
```

.NET 10 SDK builds the executables; the shared core targets .NET 8 for PowerShell 7.4 compatibility.
Offline CI builds and exercises host executables on Linux, Windows, and macOS. Live auth proof
remains Linux and the two lab accounts. Native AOT, OS-protected encryption keys, removal of the
PowerShell authentication dependency, and a metadata visualization GUI remain separate milestones.
See [native architecture](native-architecture.md) for their boundaries and validation gates.

Explicit Windows/Linux OS-backed profile storage is documented in [OS-backed vault](os-backed-vault.md).

Offline `research report` and `research export-flows` commands are available through the packaged PowerShell adapter; see [Application research catalog](research-catalog.md).

## Individual flow checkpoints

Version 0.13 adds `flows import` and filtered `flows export`, plus individual transactional plan/attempt writes used by the probe adapter. See [SQLite flow evidence](sqlite-flow-evidence.md) for migration, private storage, namespace selection, and remaining JSON scale limits.

## Primary application catalog

Version 0.14 adds `catalog import/update/export` and direct transactional application-ledger updates from the existing producers. Research reports prefer `applications.sqlite` when it exists, and accept `--metadata-path`. See [SQLite application catalog](sqlite-application-catalog.md) for migration, filtered views, provenance, publication guards, and remaining scope-history limits.

Primary scope and registration checkpoints can use an existing `scopes.sqlite`. See [SQLite scope history](sqlite-scope-history.md) for migration, selected/latest reads, resume repair, and public exports.

Version 0.16 connects [frozen research cohorts](research-cohorts.md) to the inventory CLI and adds native `evidence cohort/cohort-export`. Contextual run recipes preserve namespace and chunk membership; selected scope reads also accept `--flow-plan` and `--client`.

## Encrypted maintenance backups

`tokenforge research backup --snapshot-path <maintenance.sealed> --backup-directory <private-directory> --json` saves an immutable ciphertext copy without loading an authentication profile. It requires the bundled PowerShell adapter and reports byte identity separately from authentication. See [private maintenance](private-maintenance.md) for key custody and restoration.

## Inspect weekly progress offline

Use a local checkout of the public `discovery-data` branch:

```text
tokenforge research weekly --state-path /path/to/discovery-data
tokenforge research weekly --state-path /path/to/discovery-data --json
```

The PowerShell entry point is `./scripts/tokenforge.ps1 research weekly -StatePath /path/to/discovery-data -Json`. No profile or login is required. The command reads the two frozen weekly recipe files, validates their hashes and coverage, and recomputes reports rather than relying on cached report files. It writes no files. Unrelated checkout files are not inspected or endorsed by this command.

Reports distinguish source catalog, selected applications, successful applications, and app/resource pairs. They include remaining applications/pairs, pending/exhausted batches, observation dates, and next-step guidance. An older recipe is marked `CurrentWeek=false`; refresh the checkout and inspect scheduling before assuming the current week has run. Future-week recipes and creation times more than five minutes ahead are rejected. Assessment includes structural exclusions, and successful token observations do not establish universal support or API authorization. The packaged native command uses its PowerShell adapter, so PowerShell 7.4+ is required.
