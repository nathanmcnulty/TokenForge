# Private metadata maintenance

A public repository's artifacts are downloadable by readers. This workflow therefore uploads **only authenticated-encrypted metadata**, using artifacts as recovery snapshots. Keep a separate protected backup for authoritative long-term history; artifact retention is not a durable database.

Every Monday, or on manual dispatch, the main-only workflow:

1. Downloads the newest unexpired `maintenance-snapshot-v1` artifact from a main-branch run. Missing artifacts start a new catalog; damaged or incompatible snapshots stop restoration rather than silently discarding history.
2. Signs Nora in using repository-secret software passkey values. It obtains a fresh Graph token through the fixed Graph Command Line Tools client using existing authorization, checks the expected tenant/account/client/audience, and verifies the account through Graph `/me`.
3. Authenticates and decrypts the prior snapshot inside a temporary private directory. The encryption context binds `private-maintenance/v1`, the tenant fingerprint, and the account fingerprint.
4. Refreshes public source discovery and preserves private candidates previously observed in sign-ins. A sign-in observation does not establish Microsoft ownership. Fresh inventory separately checks tenant service-principal registration, ownership, configuration, API definitions, and configured grants.
5. Reads at most 20 pages of sign-ins from the preceding seven days and retains only app IDs and bounded authentication summaries. It stores no raw events, usernames, IP addresses, cookies, or tokens. Manual `skip_signins` permits inventory-only maintenance; `sign_in_days` (1–31) and `max_pages` (1–1000) bound log volume.
6. Updates the application catalog's provenance, observation dates, changed attributes, prior versions, and successful query windows. Distinct complete configured-grant snapshots retain their first/last observation dates. Failed or forbidden enumerations preserve the previous successful history and dates; the new attempt receives a separate status.
7. Encrypts the projected catalog, grant history, and latest run status; writes the ciphertext atomically; disposes credentials; removes temporary plaintext; and uploads only `maintenance.sealed`.

The workflow never registers applications, grants consent, or probes a matrix of tokens. Administrative registration remains a separate explicit CLI stage. No private metadata is committed to `discovery-data`, and no privileged secadmin passkey is added to Actions.

## Interpreting status

`Complete` means the selected read stages completed, not that every app supports every authentication flow. `Partial` means inventory completed but grants or sign-ins were unavailable, including HTTP 403. Prior evidence remains historical and does not become fresh. `Failed` means a required stage or bounded sign-in enumeration failed; when possible the workflow still uploads encrypted recovery metadata. Pagination limits do not produce an empty complete sign-in snapshot. The encrypted latest status records a bounded failure category such as `EnumerationBounded` or `TransientTransport`, without retaining exception bodies.

Successful sign-in query windows remain in `Metadata.Runs[].Window`. `LastRun.SignInSince/Until` describe the latest attempted window, which can differ from the last successful window. `GrantHistory` contains only complete sanitized grant sets, with hashed principal identifiers; a later forbidden grant read leaves them intact.

## Storage and recovery

`TOKENFORGE_CHECKPOINT_KEY` is a random 256-bit repository **secret**, shared with research checkpoints. Independent random AES-GCM nonces and different authenticated contexts separate the payloads. The encrypted envelope is capped at 128 MiB. It contains diagnostic metadata only; authentication profiles and credential directories are excluded. The code rejects credential-bearing restore fields and mismatched account namespaces.

Snapshots have 15-day retention, enough to bridge one missed weekly run. Two missed runs, artifact deletion, or loss of the key can still lose recovery history. Back up the ciphertext and key separately in protected storage. Key rotation requires an intentional migration or a fresh catalog; old ciphertext cannot be decrypted with the new key. Use short retention for artifacts and a dedicated private store when longer retention, audit guarantees, or multiple observers become necessary.

Only aggregate stage statuses appear in runner logs. Detailed IDs, counts, configured grants, and history are inside the encrypted payload. GitHub's passkey login action necessarily handles credentials during authentication; its values remain repository secrets and are never part of the metadata snapshot.

## Weekly plan portability

Recipe hashes now normalize parsed dates to UTC offsets, so a plan created on a UTC runner verifies on Windows, macOS, or Linux in another timezone. Existing UTC CI hashes remain unchanged. Recipes generated outside UTC by the earlier hashing implementation may require rebuilding; this does not change the meaning of historical anonymous scope observations.

## Bounded validation on 2026-10-07

The [sanitized report](private-maintenance-validation-2026-10-07.json) covers encrypted maintenance and restored-history proofs with both Nora and secadmin. Nora completed inventory and grant reads while sign-in access was forbidden. Secadmin completed a one-day sign-in read with a 50-page cap; the initial five-page limit correctly refused incomplete enumeration. Neither proof registered applications, granted consent, or persisted credentials. Hosted runs [37685631049](https://github.com/nathanmcnulty/TokenForge/actions/runs/37685631049) and [37685952513](https://github.com/nathanmcnulty/TokenForge/actions/runs/37685952513) subsequently passed initial snapshot upload and encrypted restoration. Downloaded artifacts verified the expected account context, preserved catalog history, and contained no credential fields.

## Keeping a durable local backup

After downloading `maintenance.sealed` into a private local directory, save an immutable copy outside the repository:

```powershell
./scripts/Export-TokenForgeMaintenanceBackup.ps1 `
  -SnapshotPath /private/path/maintenance.sealed `
  -BackupDirectory /private/path/maintenance-backups
```

The command also ships in the PowerShell CLI ZIP. It creates private backup storage when needed, rejects links and broadly accessible source or destination directories, and uses the ciphertext SHA-256 as the filename. Identical snapshots reuse the existing file; corrupt or different bytes at that filename cause failure. `-WhatIf` reads no snapshot and writes nothing. No key, passkey, cookie, or decrypted metadata is needed or copied.

The hash checks copied bytes; it does not authenticate the encrypted payload. The output explicitly reports `Authenticated=false`. Restoration currently requires a repository checkout; its CI scripts are not included in the CLI ZIP. Restore a saved `.sealed` file through `Invoke-TokenForgeCiMaintenance.ps1 -CheckpointInputPath <backup-file>` with the original separately protected key and expected account context. Restoration verifies AES-GCM authentication and fresh account identity before using history; a wrong key or account fails. Keep periodic copies on an independently protected backup medium and keep the key separately. A local copy alone does not protect against loss of the same disk, and the command deliberately does not upload keys or select an external storage provider.

The same copy is available through both CLI entry points without an authentication profile:

```powershell
./scripts/tokenforge.ps1 research backup -SnapshotPath /private/path/maintenance.sealed -BackupDirectory /private/path/maintenance-backups -Json
tokenforge research backup --snapshot-path /private/path/maintenance.sealed --backup-directory /private/path/maintenance-backups --json
```

The native CLI uses its bundled PowerShell adapter for this command, so PowerShell 7.4+ remains required. The backup command handles ciphertext only and performs no login or token request.
