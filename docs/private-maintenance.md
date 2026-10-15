# Private metadata maintenance

Use encrypted CI artifacts as short-lived recovery snapshots, with a separate protected backup for long-term history. Artifacts in this public repository are downloadable by readers, so upload only `maintenance.sealed`, never plaintext metadata or credentials.

GitHub Actions are currently disabled. The workflow is manual-only and requires a new explicit instruction before enabling or dispatching it. Use [local discovery](discovery.md) for collection that does not consume runner minutes.

## What a maintenance run does

When explicitly approved, the main-branch Linux workflow:

1. Downloads the newest unexpired `maintenance-snapshot-v1` artifact from a main-branch run. A missing artifact starts a new catalog; a damaged or incompatible snapshot stops restoration.
2. Uses Nora's repository-secret software passkey values to obtain a fresh Graph session through the fixed Graph Command Line Tools client. It checks the tenant, account, client, audience, and Graph `/me` identity before accepting saved history.
3. Authenticates and decrypts the prior snapshot in a temporary private directory.
4. Refreshes public application sources and tenant inventory, retaining private candidates previously observed in sign-ins. It records registration, ownership, configuration, API definitions, and configured grants.
5. Reads a bounded sign-in window and retains app IDs and authentication summaries. It excludes raw events, usernames, IP addresses, cookies, and tokens.
6. Encrypts the catalog, grant history, and run status, removes temporary plaintext, and uploads only the encrypted snapshot.

The default sign-in window is seven days with a 20-page limit. Manual inputs allow 1–31 days and 1–1000 pages; `skip_signins` selects inventory-only maintenance. Reaching a page limit fails the enumeration rather than saving an incomplete result as complete.

Maintenance does not register applications, grant consent, or request a token matrix. Registration is a separate explicit [inventory stage](inventory.md). Sign-in observations identify candidates; they do not establish Microsoft ownership. Private metadata is never committed to `discovery-data`, and the secadmin passkey is not added to Actions.

## Read the results

| Status | Meaning |
| --- | --- |
| `Complete` | The selected read stages completed. This does not prove support for every authentication flow. |
| `Partial` | Inventory completed, but grants or sign-ins were unavailable, including HTTP 403. |
| `Failed` | A required stage or bounded sign-in enumeration failed. An encrypted recovery snapshot is still saved when possible. |

Failed or forbidden reads preserve prior successful observations and their dates. They record a separate attempt status instead of making historical data appear fresh. Complete configured-grant snapshots retain their first and last observation dates.

`Metadata.Runs[].Window` records successful sign-in query windows. `LastRun.SignInSince/Until` records the latest attempted window, which may differ. Only aggregate stage statuses appear in runner logs; detailed metadata and bounded failure categories remain encrypted.

## Protect the snapshot and key

`TOKENFORGE_CHECKPOINT_KEY` is a random 256-bit repository **secret**, shared with research checkpoints. AES-GCM uses independent random nonces and an authenticated context containing `private-maintenance/v1`, the tenant fingerprint, and the account fingerprint. Restoration rejects a mismatched context or credential-bearing fields. The encrypted envelope is limited to 128 MiB plus its 29-byte framing.

The snapshot contains diagnostic metadata, not authentication profiles or credential directories. Passkey values also belong in repository **secrets**. Neither the key nor the passkey belongs in an artifact.

Artifacts expire after 15 days. This can bridge one missed weekly run, but deletion, a longer gap, or loss of the key can lose recovery history. Save ciphertext on an independently protected backup medium and keep the key separately. Key rotation requires an intentional migration or a fresh catalog; the new key cannot decrypt old snapshots.

## Save and verify a local backup

Download `maintenance.sealed` into a private directory outside the repository, then create an immutable copy:

```sh
tokenforge research backup --snapshot-path /private/maintenance.sealed --backup-directory /private/backups --json
```

The PowerShell equivalent is:

```powershell
./scripts/Export-TokenForgeMaintenanceBackup.ps1 `
    -SnapshotPath /private/maintenance.sealed `
    -BackupDirectory /private/backups
```

Backup runs offline without an authentication profile or key. It names the copy by its ciphertext SHA-256, reuses identical bytes, and refuses conflicting content. It rejects links and broadly accessible source or destination directories. Unix backup storage must support hard links for atomic publication. The hash verifies byte identity; `Authenticated=false` means this copy operation has not authenticated the encrypted payload.

Authenticate the snapshot with the original separately protected Base64 key file and both expected account fingerprints:

```sh
tokenforge research inspect-backup --snapshot-path /private/maintenance.sealed --key-file /private/key.txt --tenant-fingerprint <expected-tenant-hash> --principal-fingerprint <expected-account-hash> --json
```

For offline plaintext restoration, use `research restore-backup` with a new `--output-path`; see [native CLI recovery](native-cli.md#encrypted-maintenance-backups) for the full command and key-file requirements. Inspection and restoration validate the complete historical envelope. They report `FreshAuthenticationPerformed=false`: authenticating saved ciphertext does not establish current account authorization.

Restoration never overwrites an existing destination. Keep restored plaintext private and delete it when finished. If the result reports `CleanupFailed=true`, inspect the private directory for leftovers before retrying.

To refresh account maintenance using a backup, pass `-CheckpointInputPath <backup-file>` to the repository's `Invoke-TokenForgeCiMaintenance.ps1` with its required credentials and original expected context. It verifies fresh account identity before reusing history. The CI maintenance script is not included in the CLI ZIP; the backup script is.

## Validation evidence

These reports record bounded historical checks, not a claim that a current maintenance run has completed:

- [Private maintenance](private-maintenance-validation-2026-10-07.json): encrypted maintenance and preserved history with Nora and secadmin.
- [Native backup](native-maintenance-backup-validation-2026-10-11.json) and [atomic publication](native-backup-publication-validation-2026-10-11.json): copies, deduplication, corruption, concurrency, and private-path checks.
- [Native recovery](native-maintenance-recovery-validation-2026-10-13.json): complete-envelope validation and offline restoration of both account snapshots.

For research recipe portability and scheduling, see [weekly discovery](weekly-ci.md).
