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
