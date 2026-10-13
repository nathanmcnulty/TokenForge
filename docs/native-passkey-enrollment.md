# Enroll another lab software passkey

This feature is under development on a draft branch. Live enrollment has not yet been confirmed; it is not included in the released 0.39.0 packages.

The draft native CLI and PowerShell module command attempts enrollment of another
software passkey for the same account as an explicitly supplied existing local passkey. This is a lab software
authenticator: its key is exportable, its certificate is self-signed, and it does not
establish hardware presence or hardware attestation. The command changes that account's
authentication methods. It creates no consent grants and registers no applications.

First-key enrollment through a Temporary Access Pass remains an external PowerShell
workflow. This command does not accept a TAP, administrator targeting, arbitrary endpoints,
or policy changes. Tenant policy and My Sign-ins still decide whether registration succeeds.

```powershell
# identity.json contains the expected TenantFingerprint and PrincipalFingerprint.
# A private TokenForge inventory snapshot can also supply these fields.
tokenforge passkey enroll --passkey-file /private/existing.passkey `
  --identity-file /private/identity.json --output-path /private/new.passkey `
  --name Test --json

Register-TokenForgeSoftwarePasskey -PasskeyPath /private/existing.passkey `
  -IdentityPath /private/identity.json -OutputPath /private/new.passkey `
  -DisplayName Test

./scripts/tokenforge.ps1 passkey enroll -PasskeyPath /private/existing.passkey `
  -IdentityPath /private/identity.json -OutputPath /private/new.passkey -Json
```

The module command supports `-WhatIf`, which performs no file reads or authentication.
An existing output key or registration receipt prevents enrollment before sign-in. Paths
must be private local paths without links; Unix files use owner-only access and Windows
uses private ACLs. The JSON command result contains registration/recovery flags rather
than key material, account identities, tokens or session cookies.

## What happens

1. Open the existing private credential and complete native software-passkey login.
2. Use its in-memory ESTS cookie to request Graph `User.Read` through the fixed Graph
   Command Line Tools client. Compare token context with the expected account fingerprints
   and independently confirm its object ID through Graph `/me`.
3. Use cookie authorization-code/PKCE to request the fixed My Sign-ins SPA's self token.
   Its client, audience, tenant and principal must match the confirmed account.
4. Authorize the My Sign-ins session. When requested, refresh only that client's token
   with the fixed NGC MFA claims request, then recheck its account context before use.
5. Request the FIDO challenge. Validate its provisioning and postback destinations against
   fixed hosts, paths, tenant and bounded query parameters. Generate a P-256 credential,
   credential ID, packed software attestation and zero-AAGUID authenticator data.
6. Flush and publish the private recovery key without overwriting another file. Only then
   send `fido/create` and `newfido`. Parse their bounded context and validated callback
   fragment without navigating it; obtain the fixed methods context and reauthorize the
   session before a single final verification request.
7. Require verified state and the new credential's ID/name. Leave the key bytes unchanged;
   publish a separate private `new.passkey.registered.json` receipt that binds confirmation
   to the key file's SHA-256 and credential ID.

Credentials are routed by role. Bearer tokens and session context are used only on the
fixed My Sign-ins API paths; the ESTS cookie remains on its identity host. Redirects are
refused, responses are bounded, and the native command has a five-minute operation deadline
plus per-request timeouts. It performs no automatic registration retries.

## Keep the key and receipt together

Enrollment-marked keys require their matching `.registered.json` receipt for login. Move
or back up both files together, preserving private permissions and the receipt filename.
A receipt for different key bytes is rejected. Legacy passkey files without an enrollment
marker continue to use their existing format. The authentication validation driver copies
and checks the private pair when supplied through its local `-PasskeyPath` option.

If enrollment fails before recovery publication, the error reports `RecoveryFileSaved=false`.
If it fails after publication, preserve the recovery key and check the account's Security
info before doing anything else. A timeout or malformed response can leave a remotely
registered key even though local confirmation did not finish. Such a key remains unusable
by TokenForge until confirmed; the command does not automatically retry, delete the remote
method, overwrite its local recovery file, or fabricate a receipt. Successful publication
remains reported even if temporary-file cleanup subsequently fails.

The receipt is local evidence of the completed enrollment response, not a signature from
Microsoft or a hardware attestation. It does not revoke a remote method when deleted.
Deleting the local files alone can lose a registered credential; manage remote methods
through Security info when cleanup is needed.

Implementation validation is in progress on the feature branch. Successful builds and
synthetic checks alone do not establish successful live enrollment.

The [sanitized experiment report](native-passkey-enrollment-validation-2026-10-13.json)
records the successful identity/MFA prerequisites, the stopped live attempts for both
accounts, and preservation of their unresolved recovery keys. It does not claim completed enrollment.
