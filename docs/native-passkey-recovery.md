# Recover a pending software passkey

An interrupted enrollment can leave a private key marked `PendingRemoteVerification`.
Saving the file does not establish that Microsoft registered it. Normal TokenForge
authentication refuses a pending file unless a matching private receipt exists.

Run recovery from PowerShell using the native executable:

```powershell
./tokenforge passkey recover --passkey-file /private/Test.passkey `
  --identity-file /private/inventory.json --json
```

The identity file must contain the expected `TenantFingerprint` and
`PrincipalFingerprint`, as recorded in your private TokenForge inventory. Both
files and their parent directories must satisfy the existing private-file policy.

Recovery does the following:

1. Locks recovery for that credential and opens the pending software key.
2. Starts a fresh Microsoft sign-in with an empty in-memory cookie jar and that key.
3. Requests a Graph `User.Read` token using the fixed bootstrap client and PKCE.
4. Checks the expected tenant, principal, client, audience, delegated scope and expiry.
5. Calls Graph `GET /me?$select=id` and checks the returned identity against the token.
6. Rechecks token policy and the exact saved key bytes, then atomically writes
   `<key>.registered.json` without replacing an existing receipt.

No registration or authentication-method deletion request occurs. Sign-in still
creates normal Microsoft authentication logs. Recovery never changes the key.
Tokens and cookies remain in memory and are disposed when the operation ends.
Output contains only the result, proof label, or a sanitized failure stage.

The default allowance for additional scopes is zero. If your tenant returns broader
existing grants, deliberately set `--max-extra-scopes N` (0–512). This permits
checking that already-issued token; it does not request those extra scopes or grant
consent. Inspect your lab's grants before choosing an allowance.

Recovery receipts use schema 2 and state
`FreshSoftwarePasskeyAuthenticationAndGraphIdentity`. Schema 1 enrollment receipts
remain readable. Both schemas bind to the credential's exact SHA-256 and credential
ID. These are private local evidence, not server-signed or manufacturer
attestations; a local owner can edit the receipt. A successful recovery establishes
usability at the time of the check, not future usability or broader API authorization.

A failed operation preserves the key and any existing receipt. If `ReceiptSaved`
is true in an error, publication succeeded but subsequent temporary-file cleanup
failed; inspect the private receipt before trying again. Pending keys that fail
sign-in remain unresolved. Do not assume they are registered or automatically
retry enrollment. Legacy passkey files without the pending marker retain their
existing authentication formats.

## The PowerShell adapter

Version 0.43 introduced the native receipt gate. Version 0.44 also applies it to
`Get-TokenForgeEstsCookie` and the implicit profile login that uses that function.
The adapter validates the key before importing XDRInternals, invokes the module
returned by the requested import, and confirms the current pathname, exact key
bytes and pending receipt again before converting the returned cookie to a
`SecureString`. File handles and temporary byte buffers are disposed on failure.

All adapter key files now require the same private-file policy as native keys:
on Unix, keep the directory at `0700` and file at `0600`; on Windows, use the
documented owner/SYSTEM/Administrators-only ACL policy. Links and linked ancestors
are rejected. Inputs must be UTF-8 JSON objects of at most 65,536 bytes and depth
16, with no duplicate fields. Unmarked local and Key Vault reference formats
remain supported, including legacy UTF-8 files with a byte-order mark.

The adapter still delegates authentication and Key Vault token handling to the
chosen XDRInternals module. Receipt checking does not replace the caller's account
and token validation or add Graph identity verification to a bare cookie request.
Use a trusted provider in a dedicated PowerShell process without transcripts.

The read lease and final pathname check detect persistent file changes or
replacement. They cannot guarantee the provider read the leased bytes if another
process belonging to the same owner temporarily swaps the pathname and restores
it during authentication. Private directories exclude other local users; the
owner of the file and provider remains trusted. Receipts are local evidence,
not a security boundary against that owner editing them.
