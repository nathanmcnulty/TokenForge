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
existing behavior.
