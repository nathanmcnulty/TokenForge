# Native lab authentication validation

The **Native lab authentication validation** workflow exercises an existing software
passkey on six native packages: Windows, macOS and Linux, each on x64 and ARM64.
It runs only on manual dispatch from `main` in this repository. Pull requests receive
offline tests and no account credentials. Two live workers run at a time.

The workflow uses Nora's existing repository **secrets**:

- `NORA_PASSKEY_CREDENTIAL_ID`, `NORA_PASSKEY_USER_HANDLE`, `NORA_PASSKEY_PRIVATE_KEY`
- `NORA_PASSKEY_UPN`, `NORA_TENANT_FINGERPRINT`, `NORA_PRINCIPAL_FINGERPRINT`

No checkpoint key or privileged account is required. It uses existing authorization
and performs no enrollment, application registration or consent grant.

## What each worker checks

1. Run the shared core checks and build the package for the selected architecture.
2. Create an owned private copy of the software key. Remove input secrets from the
   driver's environment; native children receive a cleared environment and a PATH
   containing no PowerShell.
3. Sign in and acquire the fixed Microsoft Graph Command Line Tools `User.Read`
   bootstrap. Check the expected tenant/account fingerprints, then independently
   confirm the account's object ID and UPN through Graph `/me`.
4. Read fresh tenant inventory and configured grants. Retain only the fixed Graph
   client and resource, and require an eligible cold request. A failed or forbidden
   grant read stops validation; the driver creates no substitute consent evidence.
5. Create a Memory profile, run native software-passkey login, and acquire a cold
   and warm token with `token get --passkey-file`. Both acquisitions must be fresh
   and pass Graph `/me`. The profile must create no credential vault.
6. Create a separate Passphrase profile with a random temporary password. Run native
   login, acquire a cold token, then repeat the request. The repeat must use the
   validated token cache and both API checks must return HTTP 200.
7. Log out both profiles. Inspect the Passphrase vault to confirm it contains no
   credential sessions; logout preserves its encrypted container. Remove all owned
   keys, profile state, metadata and extracted runtime files.
8. Write a fixed sanitized report only after cleanup succeeds. Upload that report
   with one-day retention. No private state or authentication response body is uploaded.

The script is `scripts/Test-TokenForgeNativeAuthentication.ps1` in the checkout.
Its public report records runtime/version, package hashes, source commit, run attempt,
storage outcomes and API statuses. It omits usernames, tenant/account fingerprints,
cookies, keys and tokens. Attempt-specific artifact names prevent a rerun from silently
reusing a prior report; inspect each report's source and attempt when comparing runs.

## Running and interpreting it

After the reviewed change is merged and the nine main validation gates pass:

```sh
gh workflow run native-authentication.yml --ref main
```

All six matrix jobs must succeed before claiming complete platform coverage. A successful
run proves the selected Graph operation for Nora on those packages; it does not establish
universal app/flow support, hardware user presence or local JWT signature validation.
The PowerShell driver provides test orchestration and a separate baseline; the measured
login, token, cache, inspection and logout commands execute in native child processes.

The fixture deliberately permits up to **128 additional API scopes**, and the same
bootstrap budget, for this lab's existing Graph client. `User.Read` requests can return
other already authorized scopes. This explicit lab budget does not change the product's
zero-extra-scope defaults. Candidate and callback limits are one each, and inventory
freshness is limited to one hour.

The [sanitized Linux report](native-authentication-validation-2026-10-13.json) records
successful Memory and Passphrase checks with both lab accounts, using the verified published
0.39.0 Linux package. This live evidence remains separate from synthetic platform checks. The [hosted six-platform report](native-authentication-hosted-validation-2026-10-13.json)
records completed live validation for Nora on Windows, macOS and Linux, each on x64 and
ARM64. OS-backed stores, browser UI, hardware passkeys and
other resource operations require separate proofs.


## Hosted proof on 2026-10-13

[Run 38377160936](https://github.com/nathanmcnulty/TokenForge/actions/runs/38377160936)
completed all six targets from source `a26caf60b81d4ae15728f0feb46e3c362263ac77`.
Independent downloads verified each report's runtime, version, source, attempt, storage
behavior, expected-account confirmation and private cleanup. Twelve profile cases
produced 24 native Graph HTTP 200 checks. Memory repeats acquired fresh tokens;
Passphrase repeats used the validated cache. No consent or registration was performed,
and no credentials or identity fingerprints appeared in the report projection.

This proves the fixed Graph operation for one lab account on those source-bound packages.
It adds Windows/macOS live evidence to the separate two-account Linux proof. It does not
add macOS Keychain support, signed/notarized releases, hardware presence or general
application/resource authorization. Each report includes package hashes and its downloaded
artifact hash; these workflow reports are separate from release-package attestations.
