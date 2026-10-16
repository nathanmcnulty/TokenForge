# Bounded Linux VM discovery cycle

This is the offline-tested operational slice of [#115](https://github.com/nathanmcnulty/TokenForge/issues/115). It is **not an authenticated VM deployment proof**. Nothing installs/enables a scheduler, signs in, renews credentials, requests consent, or publishes files. GitHub Actions remain disabled and manual-only.

## Prepare once, resume frozen inputs

Use PowerShell 7.6+ on .NET 10 with a trusted matching Linux package. The repository runtime baseline and validation work remains tracked in #98/#106. Prepare and review a small cohort with the existing [discovery runner](discovery.md). Keep one private directory per account outside the checkout (0700 directory, 0600 files), containing `inventory.json`, `discovery-run.json`, and the working SQLite databases. Back up with the existing SQLite-aware maintenance backup tooling, not raw copies of a running database.

Pin the source checkout commit and the entire trusted package externally; record the expected SHA-256 of its native executable in your protected launcher configuration. The wrapper checks that executable hash, records the module version, and requires a valid existing cohort ID. An executable hash alone does not attest to adjacent libraries or PowerShell source. Do not calculate an expected hash afresh on every scheduled launch; compare against the reviewed pin.

The VM cycle never rewrites the saved inventory. It stops with `InventoryStale` before collection when the capture is older than 24 hours (or more than five minutes in the future), preserving the collector’s existing freshness gate. A long-running cohort therefore cannot be assumed resumable indefinitely or after a late reboot. It never downloads sources, refreshes inventory, creates a cohort, or supplies `NewRun`. Existing collector checks still reject an inventory/account/catalog mismatch with the frozen recipe. For a stale stop, pause the schedule, retain the old cohort and its evidence, and perform a separately approved inventory refresh/review. If membership or recipe inputs differ, prepare a new cohort. An unchanged reviewed refresh may be resumed only if the existing exact recipe checks pass. Never edit the capture timestamp or relax the freshness gate to force resume.

Run from a private PowerShell process with an already authorized SecureString session:

```powershell
./scripts/Invoke-TokenForgeVmCycle.ps1 `
    -StatePath /private/tokenforge/account `
    -NativeExecutablePath /opt/tokenforge/linux-x64/tokenforge `
    -NativeSha256 $reviewedExecutableSha256 `
    -EstsAuth $existingSession `
    -SessionExpiresAt $conservativeSessionDeadline `
    -MaxChunks 1 -MaxMinutes 15
```

The session is supplied in memory; do not put cookies/tokens in command arguments, environment variables, logs, timer files, or this directory. The wrapper copies and disposes its own SecureString. It never disposes the caller's original session. The deadline is an operator/session-provider safety bound, **not a claim that the service will accept the session until then**. No automated session provider or protected reboot-time session loading is implemented here.

## One cycle and scheduler contract

The wrapper takes the same `.discovery.lock` as the interactive bootstrap, then the collector takes its existing `.writer.lock`. It writes a private, atomically replaced `vm-cycle.json` receipt before collection and after a clean return. Each invocation has a fresh cycle ID and the same frozen cohort ID. Receipts contain bounded statuses, times, package hash/module version, and final counts; no errors or credentials are copied into them. The latest receipt replaces the prior receipt; this is not an audit-history ledger.

- `Complete`: selected clients are checkpointed. It does not mean every probe succeeded.
- `BudgetReached`: repeat the same command with the same frozen inputs and a still-valid session.
- `SessionExpired`: stop scheduling collection until an operator supplies a renewed authorized session and deadline.
- `Cancelled`: stop scheduling; an operator must remove the stop marker to resume.
- `Stopped`: inspect `Reason`. `Busy` means another process holds the orchestration lock; `Configuration` means preconditions/pins failed; `InventoryStale` requires a reviewed inventory refresh; `TransientExhausted` means the collector's bounded retries were exhausted; `CollectionFailed` means another failure, with details suppressed. Do not automatically sign in or blindly restart failures.

Exit 0 accompanies `Complete`/`BudgetReached`; exit 2 accompanies `SessionExpired`/`Cancelled`; exit 1 accompanies other stops. Structured status distinguishes the successful cases. PowerShell's in-process `$LASTEXITCODE` can retain an older value after success; a process scheduler should use the process exit code, and an in-process caller should use the JSON status.

The collector checks expiry and a private `stop.requested` marker between chunks and avoids a retry wait that reaches the session deadline. To request a cooperative stop, create an empty 0600 `stop.requested` file in the state directory. Cancellation, elapsed-time budgets, and the session deadline are **not hard request-level cutoffs**: an active chunk can finish later. Smaller frozen batches provide shorter boundaries. Stable or untyped failures never become automatic login attempts. A service-side revocation/expiry before the supplied deadline is not reliably classified by this wrapper; existing probe failures may be recorded as failed cells. Validate that behavior before approving unattended authenticated use.

An ordinary local service/timer may call a protected launcher, but activation is a separate operator decision. Use one account/service identity, one state directory, a bounded cadence, and no blanket `Restart=always`. Continue budget stops only; disable repeated collection on completion, cancellation, expiry, or non-transient failures. There is no built-in perpetual polling loop. A complete cohort must not trigger creation of a new one. Reboot scheduling and protected session provision are still deployment responsibilities and must pass the live checklist below.

## Interruption, status, and recovery

After kill or reboot the receipt can remain `Running`. That is a last recorded state, not proof of a live process, and its `UpdatedAt` is the last receipt write, not a per-request heartbeat. Do not trust a PID or delete lock files to recover. Restarting the same command must acquire the OS lock; a live holder refuses it. After the OS releases the lock, the collector loads durable checkpoints and skips completed work. An issued request that died before its primary evidence was durable can still be repeated; this wrapper does not claim exactly-once network issuance.

Use the existing offline status command for authoritative selected/completed/pending counts, including while collection is active:

```powershell
./scripts/Invoke-TokenForgeInventory.ps1 -Action CohortStatus `
    -StatePath /private/tokenforge/account `
    -NativeExecutablePath /opt/tokenforge/linux-x64/tokenforge `
    -SummaryOnly | ConvertTo-Json -Compress
```

After an interruption or unknown failure, inspect offline status first, then resume the same cohort only when the session and frozen inputs remain approved. A receipt-write failure can leave an older receipt; database checkpoints remain authoritative. Publication/export/backup state cannot be inferred from collection completion.

## Staged publication dependency

Every receipt reports `Publication: NotAttempted`. The review, privacy/schema validation, staged-publication decision, and publication receipt are the separate [#113 gate](https://github.com/nathanmcnulty/TokenForge/issues/113). Do not wire collection directly to publication or interpret `Complete` as publication approval. Integrate that gate only after its contract is reviewed; publication retries must consume saved collection output without authenticating or issuing tokens again. This change adds no competing publication implementation.

## Evidence and remaining live VM checklist

Offline Linux tests cover lock exclusion, pin/manifest refusal, private sanitized receipts, retained checkpoints after failure, expiry before a chunk and before retry delay, cooperative cancellation, and a real child-process kill/restart. The kill test uses synthetic request/checkpoint functions with the actual collector and wrapper locks; separate existing native SQLite tests cover real checkpoint resume with mocked issuance. Neither is an authenticated VM/reboot proof.

Before declaring unattended VM operation validated, record the source commit, trusted full-package identity, PowerShell/.NET versions, selected cohort and approved budgets, then complete all of these in an explicitly authorized VM session:

1. Run a small authorized frozen cohort; record receipt and offline status counts without retaining session material or identity response bodies.
2. Launch a second cycle while the first holds its lock; verify `Busy`, unchanged receipt, and no second issuer.
3. Interrupt once after durable primary evidence, once after client checkpoint, and once during metadata projection. Restart the same cohort and verify checkpoint repair and no repeated completed requests. Distinguish possible pre-durability reissuance.
4. Request a cooperative stop during a chunk; verify the next boundary stops and resume requires removal of the marker. Measure overrun rather than claiming a hard deadline.
5. Exercise both a deliberately short declared deadline and actual service-side expiration/revocation. Verify the observed failure categories, no automatic sign-in/consent, and no excessive failing-cell sweep; tighten the session provider/preflight policy if actual expiry is not detected safely.
6. Renew the session through existing approved protection mechanisms, manually resume, and verify the account/recipe boundary and completed-cell skipping. Test rejection of a different account without exporting private details.
7. Only with separate scheduling approval, configure a local bounded timer/launcher and reboot the VM. Verify exclusive lock reacquisition, same frozen recipe, protected session availability or safe stop when unavailable or inventory is stale, terminal-stop handling, and no automatic new cohort. Record successful restart and session-expiry evidence before calling it unattended-ready.
8. After #113 is integrated, review a staged export independently, simulate publication failure, and retry publication without new collection/authentication. Confirm publication and backup receipts separately.

No live authentication, credential access, VM scheduling, reboot, or hosted runners are part of the offline implementation checks.
