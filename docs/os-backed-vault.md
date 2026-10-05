# OS-backed profile storage

`OperatingSystem` is an explicit persistent storage option. Windows uses the current user's
Credential Manager; Linux uses libsecret and the desktop's Secret Service. The OS store holds
one random 32-byte vault password. Cookies, refresh credentials, and access tokens remain in
the existing encrypted `session.tfvault`, with the same tenant, account, client, retention, and
issued-token checks as passphrase profiles. No secret is passed through command arguments or
environment variables. OS-backed profile contexts retain session metadata, not a cached key or cookie;
credential operations reopen the protected store and dispose their owned key afterward.

```powershell
./scripts/tokenforge.ps1 profile create -Profile lab -Tenant example.onmicrosoft.com -Storage OperatingSystem
./scripts/tokenforge.ps1 login -Profile lab -Browser -Interactive
./scripts/tokenforge.ps1 token get -Profile lab -Resource graph -Scope User.Read -Json
./scripts/tokenforge.ps1 logout -Profile lab
```

The native CLI supports the same mode:

```text
tokenforge profile create --profile lab --tenant example.onmicrosoft.com --storage OperatingSystem
tokenforge login --profile lab --browser --interactive
tokenforge token get --profile lab --resource graph --scope User.Read --json
tokenforge profile forget-key --profile lab --json
```

Login still requires a fresh verified tenant inventory; see [Profiles and CLI](profiles-and-cli.md).
Profile creation writes configuration only. An explicit login creates a key when both the key
and vault are absent. Existing keys are reused; a missing, malformed, unavailable, or locked
key never triggers replacement of an existing vault. Supplied passphrases are rejected for
OS-backed profiles. Status and doctor do not access or unlock the OS store. A new process can
report `Locked` until an explicit login or token operation opens it; this is a passive local
state, not a test of OS-store availability or server validity.

On Linux, install your distribution's libsecret runtime and enable a compatible Secret Service
in the user's desktop session. Authentication operations can trigger the store's unlock prompt.
A 30-second cooperative cancellation request limits normal prompt/transport waits; a faulty
native backend can still take longer to return. Headless systems should explicitly create
`Passphrase` profiles. There is no automatic fallback.

macOS currently rejects this storage option. Its intended Data Protection Keychain adapter
needs signed helper packaging and platform validation. Passphrase storage remains available
on macOS. Existing profiles and CLI defaults remain unchanged.

## Logout, forgetting, and recovery

Logout removes the local session and cached tokens while retaining the OS key for the next
explicit login. `profile forget-key` / `Remove-TokenForgeProfileKey` deletes the encrypted vault
first, then the key, under profile and vault locks. It leaves profile configuration and evidence
intact. If deletion cannot be confirmed, the result says `KeyRemoved: false` and directs you to
retry. Linux verifies that matching locked or unlocked items are absent before reporting success.
Neither operation revokes credentials at Microsoft.

A random profile key ID and the absolute profile directory determine the key handle. Copying
or moving a profile does not migrate its OS key. If the store/key is lost, explicitly forget the
local vault and log in again; TokenForge will not silently make old ciphertext readable with a
replacement key. Back up or export metadata separately. OS-backed profiles are not portable
credential backups.

OS protection is scoped to the user. Other processes with that user's rights may retrieve the
key or inspect credentials in memory; this is not application isolation, a hardware-bound key,
or protection against a compromised desktop. Managed secret strings can exist briefly during
interop; unmanaged key buffers are wiped and released. Encrypted files still require private
paths and permissions. No raw secret export is added.

## Validation

The hosted native workflow tests Windows Credential Manager with disposable synthetic keys.
Linux integration tests start an isolated D-Bus session and disposable GNOME keyring, test
create/reopen/reuse/corruption/delete, missing-key ciphertext preservation, and locked-key failures, then remove fixtures. macOS runs the existing offline
suite and tests rejection of unsupported OS storage. These checks do not perform live Windows
or macOS account authentication.

Linux live validation uses the two authorized lab accounts, tests cold acquisition, reopening
from a separate PowerShell process, same-client renewal, Graph SDK handoff, and local logout/forget.
The renewal proof changes local expiry metadata to exercise a real refresh credential; it does
not claim that the server token actually expired.

Implementation references: [Credential Manager](https://learn.microsoft.com/en-us/windows/win32/api/wincred/nf-wincred-credwritew),
[libsecret storage](https://gnome.pages.gitlab.gnome.org/libsecret/func.password_storev_sync.html),
[locked-item searches](https://gnome.pages.gitlab.gnome.org/libsecret/method.Service.search_sync.html), and
[Apple keychain accessibility](https://developer.apple.com/documentation/security/ksecattraccessiblewhenunlockedthisdeviceonly).
