# Linux x64 offline release-candidate operator runbook

The current declared support set is **Linux x64, offline release-candidate use**. This guide defines the operator path; the matching acceptance receipt must identify which checks actually passed. Documentation, a successful build or an older live report does not establish current release readiness, production completion or live authorization. Other operating systems and architectures are outside this candidate's acceptance.

No step in offline acceptance signs in, reads a credential store, supplies a session, changes a tenant, sends a packet, dispatches Actions or publishes. Existing authentication features remain available only for separately authorized use. The older milestone guides preserve their historical boundaries; this runbook describes the current package entry points.

## Verify and install the complete package

Obtain the archive and independently trusted expected source/archive/payload hashes through an approved channel before starting offline installation. A locally calculated hash or matching version alone does not authenticate the package. A local candidate has a local source/package receipt; it does not have GitHub provenance unless that separate publication process actually occurred. See [release verification](native-releases.md).

For an already available Linux x64 archive, verify its expected digest and extract into a new versioned directory. Substitute the reviewed paths and expected hash:

```sh
archive=/absolute/reviewed/TokenForge-VERSION-linux-x64.tar.gz
expected_archive_sha256=TRUSTED_EXPECTED_SHA256
printf '%s  %s\n' "$expected_archive_sha256" "$archive" | sha256sum --check --status
package="$HOME/.local/opt/tokenforge/VERSION-linux-x64"
# Choose a new destination; do not overlay an existing installation.
mkdir -p "$(dirname "$package")"
mkdir "$package"
tar -xzf "$archive" -C "$package"
"$package/tokenforge" --version
```

Stop if verification or extraction fails. Compare the extracted package membership and dependency hashes against the trusted receipt. Keep the complete directory together, including adjacent runtime libraries, `src/TokenForge/lib/net8.0/TokenForge.Credentials.dll`, `scripts/`, examples and guides. Native commands are self-contained; the packaged PowerShell adapters require existing PowerShell 7.4+. Ordinary use requires neither a .NET SDK nor Pester. Developer validation uses its separately pinned toolchain and test version.

In a fresh PowerShell process, import the extracted module:

```powershell
$package = '/absolute/installed/VERSION-linux-x64'
Import-Module "$package/src/TokenForge/TokenForge.psd1" -ErrorAction Stop
Get-Command Get-TokenForgeToolExplanation,Test-TokenForgeTool,Get-TokenForgeCollectorStatus
```

The packaged smoke runner uses only the extracted package, existing PowerShell and synthetic inputs. Choose a new private workspace; it neither needs Pester/compiler tools nor discovers account state:

```powershell
pwsh -NoProfile -File "$package/scripts/Test-TokenForgeOfflinePackage.ps1" `
    -NativeExecutable "$package/tokenforge" -Workspace /private/new-offline-smoke
```

It exercises synthetic administrator workflows, acquisition refusal without a session, a never-dispatched pending cohort with empty saved flow history, repeated candidate export, refresh reuse and database snapshot behavior. The pending-cohort smoke is not proof of collector recovery: interrupted requests, paused/unknown state, terminal-checkpoint repair and actual process-kill recovery have separate synthetic acceptance suites and receipts. Retain its structured result with the exact source/package receipt. An example command is not a recorded pass: consult the completed receipt for results and skipped/blocked gates.

Never mix an executable from one package with source, a credential DLL or dependencies from another. Restart PowerShell after changing packages; already loaded incompatible credential runtimes fail closed. Use a new current-user-only scratch directory for synthetic examples. Keep operational account state in a stable separate directory outside the installation and Git, with 0700 directories and 0600 files on Linux. Do not change an existing shared directory's permissions as an installation shortcut. Paths containing links are refused by private-file consumers.

## Four administrator workflows using saved metadata

See the packaged [administrator guide](goal3-admin-workflows.md) and [change-report guide](goal2-change-reports.md). `TokenForgeStrictProfile` is a credential-free policy format, distinct from a compatibility `TokenForgeProfile`. The packaged `examples/admin-tool-requirements.json` uses a synthetic client and is not an authorization recommendation. A requirements file alone is not a complete runnable account context: commands also require a matching strict profile, inventory, saved snapshot and, where declared, role/license or operation evidence.

For offline acceptance, use the packaged smoke runner's complete synthetic inputs in a new protected scratch directory. For operational reporting, select already reviewed saved metadata explicitly; do not discover a sibling profile/session. Preserve the fixed evaluation instant when reproducing dated results. These examples assume the explicit files below already exist with private permissions and `$TF` identifies the installed executable:

```sh
umask 077
TF=/absolute/installed/VERSION-linux-x64/tokenforge
as_of=FIXED_ISO_INSTANT_WITH_TIMEZONE

# 1. Explain exact requirements, sources, scope breadth and unknowns.
"$TF" admin explain --profile-path profile.json --requirements-path requirements.json --inventory-path inventory.json --snapshot-path snapshot.json --tool read-profile --as-of "$as_of" --json

# 2. Preflight one strict route WITHOUT providing a session.
"$TF" admin acquire --profile-path profile.json --requirements-path requirements.json --inventory-path inventory.json --tool read-profile --json

# Convert an explicitly saved sanitized acquisition receipt, when available.
"$TF" admin evidence --acquisition-path saved-acquisition.json --json

# 3. Check a named tool against dated exact saved evidence.
"$TF" admin check --profile-path profile.json --requirements-path requirements.json --inventory-path inventory.json --snapshot-path snapshot.json --tool read-profile --as-of "$as_of" --json

# 4. Prepare a bounded private review packet; nothing is sent.
"$TF" admin packet --requirements-path requirements.json --before-path before.json --after-path after.json --source-revision REVIEWED_SOURCE_COMMIT --package-sha256 REVIEWED_PACKAGE_MANIFEST_SHA256 --as-of "$as_of" --json
```

With a supported route and no session, acquisition preflight returns exit 4, `ExistingSilentSessionRequired`, and zero bootstrap/final attempts. It neither obtains nor renews a session. Other metadata failures can stop earlier. Do not add `--cookie-stdin` during offline acceptance. Real strict acquisition needs separately approved account/client/callback/resource/scopes, an explicitly supplied existing session and finite scope/time policy. Optional `GraphMeV1` proof additionally requires an explicit operation-check decision; declaring it in a manifest does not authorize its execution.

Explain/check exit 0 means `VerifiedWorking` for the dated declared context; 2 means `AtRisk`, 3 `NeedsObservation`, 4 `Blocked`, and 1 invalid input. The included sample declares `GraphMeV1`; issuance-only evidence cannot satisfy its operation requirement. A packet can exit 0 while retaining unknown/incomparable changes. Packet source/package pins are caller-attested metadata and need independent verification. Packets remain private until separately reviewed for disclosure. Legacy profile token commands can use fallback/cache/renewal behavior and must not be substituted for these strict workflows.

PowerShell equivalents are `New-TokenForgeStrictProfile`, `Get-TokenForgeToolExplanation`, `Invoke-TokenForgeStrictAcquisition`, `ConvertTo-TokenForgeToolEvidence`, `Test-TokenForgeTool` and `New-TokenForgeToolChangePacket`. Only the acquisition operation can use a separately supplied existing session. The facade returns sanitized metadata and disposes its owned credentials; it does not launch the named tool.

## Bounded collection, status, pause and recovery

The [collector contract](goal1-collector.md) separates pair and exact-cell coverage, and preserves legacy frozen identities. Offline acceptance uses synthetic transports; no collection example below grants permission to execute against a service.

Read existing collector state without a session:

```powershell
pwsh -NoProfile -File ./scripts/Get-TokenForgeCollectorStatus.ps1 `
    -StatePath /private/account -NativeExecutablePath /absolute/package/tokenforge
```

Run this from the package root, or use the absolute packaged script path. It reads `discovery-run.json`; specify `-CohortId <saved-hash>` when selecting an explicitly saved cohort. Exit codes are 0 complete/structurally excluded, 1 failed/invalid saved evidence, 2 pending, 3 paused, 4 request-blocked, 5 transient-exhausted, 6 in-flight unknown and 7 account mismatch. Completed clients mean processed checkpoints, not successful authorization. Unmaterialized pairs have unknown cell denominators. Concurrent status comprises separate validated reads, not one cross-store transaction.

Before any separately authorized collection, freeze the approved selection and record finite issuance/bootstrap/inventory/page/source/total-request and wall-clock ceilings. Batch size or `MaxPendingClients` is a processing cap, not a cohort-size guarantee. Preserve reviewed saved sources; a zero source ceiling cannot create missing discovery input.

The following PowerShell pattern is for a future separately authorized invocation. `$approvedBounds` is an explicit reviewed parameter table containing `StatePath`, `NativeExecutablePath` and the approved remaining ceilings; `$existingApprovedSession` is an already supplied SecureString, never a command-line/environment/file credential:

```powershell
# These statements can make requests. Do not run during offline acceptance.
& "$package/scripts/Invoke-TokenForgeDiscoveryRun.ps1" @approvedBounds -EstsAuth $existingApprovedSession

# After a separately authorized same-account renewal, continue paused work:
& "$package/scripts/Invoke-TokenForgeDiscoveryRun.ps1" @approvedBounds -EstsAuth $renewedApprovedSession -ResumePaused

# Only after reviewing a particular uncertain supported operation:
& "$package/scripts/Invoke-TokenForgeDiscoveryRun.ps1" @approvedRecoveryBounds -EstsAuth $existingApprovedSession -RecoverUnknown
```

The wrapper supplies finite budgets and rejects passkey sign-in mode. Budgets count each invocation including preflight; restarting does not replenish a separately approved aggregate envelope. Allocate remaining allowance across invocations using durable receipts. Bootstrap uncertainty consumes the previous uncertain attempt too: a specifically approved bootstrap recovery needs at least two bootstrap-attempt slots in that invocation and must still fit every total ceiling. Recognized transient retries are capped within those budgets. Low-level compatibility APIs are not bounded merely by shipping in this package.

An expired/ambiguous session pauses; a well-evidenced request-specific policy/consent decline remains request-blocked. Wrong-account evidence stops. A remote result without a durable terminal checkpoint remains unknown. Do not delete intent/journal files, select a fresh state directory or rewrite outcomes to bypass these stops. At most one recorded supported uncertainty recovery is allowed; another uncertainty requires inspection. Cancellation is cooperative and overrun is reported. None of these outcomes establishes app-wide incapability, consent or API access.

For [Goal 4 refresh](goal4-bounded-refresh.md), keep one stable account directory with its namespace marker and canonical `refresh-run.json`. Offline commands include `refresh plan --input-path <private-input.json> --as-of <instant> --json`, `refresh validate --plan-path <private-plan.json> --json`, and `refresh status --plan-path <private-plan.json> --state-path <existing-refresh-run.json> --json`. `Get-TokenForgeRefreshStatus` and `Export-TokenForgeRefreshHistory` inspect/project saved journals without acquisition. `Move-TokenForgeRefreshPlan` may advance only after every started request has a durable terminal snapshot and prior history is retained. These refresh rules do not offer a force/reset shortcut for unknown issuance; supported explicit recovery is limited to read-only GET operations. Real `Invoke-TokenForgeRefresh` and optional API checks remain separately authorized operations.

## Export and retain receipts without recollection

From the package root, use [saved candidate export](goal1-export.md):

```powershell
. ./scripts/TokenForgeDiscoveryCandidate.ps1
$saved = [TokenForge.Core.DiscoverySourceClaims]::ReadMetadataJson(
    (Get-Content -LiteralPath /private/account/discovery-run.json -Raw))
$hash = New-TfDiscoveryCandidate -ScopePath /private/account/scopes.sqlite `
    -FlowPath /private/account/flows.sqlite -CohortId $saved.CohortId `
    -OutputPath /private/review/new-candidate -NativeExecutablePath /absolute/package/tokenforge `
    -SourceCommit $reviewedSourceCommit -ProducerRunId 1 -ProducerAttempt 1
Assert-TfDiscoveryCandidate -CandidatePath /private/review/new-candidate -CandidateHash $hash
```

Choose an existing private parent and a new output directory. Retain the returned manifest digest in a separate trusted export receipt with the source/package pins and evaluation context. Producer labels do not authenticate their owner. Integrity/privacy verification is separate from semantic approval and publication. Export rebuilds missing aggregate projections from primary flow history with original dates, without authenticating, issuing tokens or rewriting authoritative checkpoints.

After interruption, rerun from the same saved stores into a new destination; never overwrite a sealed candidate. A private `.NAME.partial-GUID` orphan can remain after process termination. It is not a published final output; inspect it only after confirming its process stopped, then apply the explicit retention/cleanup decision. Do not replace checkpoints with an export receipt. Preserve collection, projection, export, backup, approval and publication receipts separately.

For typed changes, `tokenforge research changes --before-path <private-before.json> --after-path <private-after.json> --kind FlowEvidence --as-of <instant> --json` consumes full saved history. Missing/partial/incomparable evidence is not proof of removal. Private packets, plaintext inventories, snapshots and journals are not anonymous candidate exports.

## Snapshot, back up and restore metadata

The candidate `storage snapshot` command requires its matching source/package acceptance receipt before relying on it. Its declared interface uses SQLite's backup API, validates typed store contents and creates a new 0600 destination on Linux. Check the exact receipt before relying on this operation for recovery:

```sh
"$TF" storage snapshot --database /private/account/scopes.sqlite --output-path /private/backup/scopes.sqlite --domain scopes --json
"$TF" storage snapshot --database /private/account/flows.sqlite --output-path /private/backup/flows.sqlite --domain flows --json
"$TF" storage snapshot --database /private/account/applications.sqlite --output-path /private/backup/applications.sqlite --domain applications --json

# Restore a saved store into another new private location; never overwrite live state.
"$TF" storage snapshot --database /private/backup/scopes.sqlite --output-path /private/restored/scopes.sqlite --domain scopes --json
```

Use private existing parent directories and distinct new destinations. The command refuses an existing destination or SQLite sidecar, including dangling links. Cancellation is cooperative: synchronous backup, integrity checks and typed validation may delay cancellation; no hard wall-clock completion bound is claimed. An existing destination or any SQLite `-wal`, `-shm` or `-journal` companion, including a broken link, is refused. A main-file copy alone can omit committed WAL data. A SQLite-aware per-store copy includes committed data but is not a transaction across scopes, flows, application metadata and JSON files. Quiesce all account writers for a coordinated recovery cut. Preserve `discovery-run.json`, frozen inventory/discovery inputs, bootstrap and budget intents, refresh namespace/journal/history and source/package receipts alongside the corresponding stores. Do not omit unresolved intent because an anonymous export looks complete. Retain originals until restored copies pass typed validation and saved status/export checks.

Treat these full database copies as private bytes, including account/request linkage. Typed validation checks the supported logical records; the SQLite backup API is not credential redaction or secure erasure of freed pages or other copied bytes. Do not infer that arbitrary or tampered input is credential-free, or use a database snapshot as an anonymous/public export. The operation does not separately collect profile files, encrypted credential vaults or OS keys. Any separately approved credential backup needs its own custody/retention plan. A hash establishes byte identity against a trusted expected value, not encryption or current authorization. No power-failure durability across the account's separate files is claimed.

Existing `research backup --snapshot-path <maintenance.sealed> --backup-directory <private-directory> --json` copies only an encrypted maintenance envelope. `research inspect-backup`/`restore-backup` need its separately protected original key and expected account fingerprints. They are not SQLite backups and cannot recover omitted cohort/refresh intents. See [private maintenance](private-maintenance.md) for those separate contracts.

## Upgrade, rollback and decommission

For an upgrade, stop writers, save the coordinated metadata recovery cut and record the old package/source/hash receipt. Extract and verify the new complete package beside the old one. Start a fresh PowerShell process and run the new package's offline checks against copied synthetic or explicitly selected scratch metadata before changing operational paths. Keep the original stores and prior package intact until the upgrade is accepted.

Older readers can reject newer catalog schemas or evidence outcomes; catalog writes may advance schema markers. Do not point an old executable at a store already written by newer code and call that rollback. Roll back using the prior complete verified package with a compatible pre-upgrade recovery cut restored into a new private directory. An uncertain request remains uncertain across rollback; never resume a backup to erase charged remote consumption. If compatible recovery cannot be established, stop for inspection rather than editing hashes, schema markers or namespace files.

Software passkeys are exportable signing credentials, not hardware isolation; ESTS cookies are session credentials. Keep either out of command arguments, environment variables, transcripts, logs, evidence, exports and agent inputs. Use separately approved protected secret storage with restricted ownership/access, an explicit retention period and an account-specific rotation/revocation procedure. Replacing a local file does not revoke a registered server credential or session. Credential rotation or server revocation requires separate authorization and verification through the appropriate account administration process; neither is part of this offline milestone.

Offline acceptance performs no credential removal. During a separately authorized local decommission, stop collectors/tools and dispose in-process credentials and owned SDK connections. For a compatibility persisted profile, `tokenforge logout --profile <name>` removes the selected local session while preserving profile configuration, unrelated sessions and OS keys. Unlock requirements still apply. `tokenforge profile forget-key --profile <name>` applies only to OS-backed profiles: ciphertext is removed before attempting key deletion; inspect its result and deliberately retry a failed key removal. See [profiles and CLI](profiles-and-cli.md).

Local logout/key deletion does not revoke server sessions or erase credentials held by other processes. It does not delete metadata, configuration, private exports or backups, and it does not promise secure erasure of storage media. Decide their retention separately, identify only the intended account paths, and preserve required uncertainty/audit receipts before explicit removal. Deleting a package directory is not account decommissioning.

## Cost and acceptance boundaries

Record the exact source commit, complete package/dependency hashes, runtime/test inputs, fixture selection, counts, skips, elapsed time and remaining gates. Run the smallest relevant local validation selection in a fresh process; do not rebuild unchanged inputs or repeat green checks merely for another success. Full input/history validation remains required even when a saved plan avoids requests.

Compare synthetic request avoidance separately from local process, CPU, memory and I/O costs. Stages absent from a benchmark are unmeasured or zero for that benchmark, not production savings. Budget-limited stale work stays explicitly missed; neither a plan nor a manual cadence guarantees daily freshness. Historical reports do not fill a missing current gate. Only a matching completed offline acceptance receipt can label this candidate offline-ready; live acceptance, hosted compute, publication, PRs and merging remain separately authorized.

## Publication remains quarantined

The legacy discovery workflow writer is disabled in source as well as Actions remaining disabled. It must not publish a `validated-data` artifact that bypasses the immutable seven-file [candidate contract](goal1-export.md). The source-only `scripts/TokenForgePublicationRecovery.ps1` models compare-and-swap and lost-acknowledgement recovery with synthetic inputs; it performs no publication and always returns `AuthorizationEstablished=false`. Its candidate envelope must bind `ContentSha256` to the reviewed seven-file manifest digest; the future hosted adapter must independently run `Assert-TfDiscoveryCandidate` against that trusted digest. The envelope is not a replacement export schema.

Before reconnecting a writer, a separately authorized adapter must verify the exact producer repository/workflow/source/run/attempt and immutable artifact bytes, reviewer identity and current reviewer/main permissions independently of review text, validity/retention and trusted prepared journal, proposed commit contents/ancestry and the actual expected-old data parent. Workers must not receive writer privileges. An expired new write stops; an observed proposed commit can support lost-acknowledgement diagnosis only with the exact bound transaction journal and independently verified remote commit. Coherent caller-supplied hashes establish consistency, not authenticity. Offline planner tests do not exercise actual GitHub permissions, APIs or race handling. Hosted proof, Actions enabling and publication each require separate approval. Artifact retention is not a backup.
