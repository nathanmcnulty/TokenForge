# Discovery observations

These snapshots describe what worked for a tested session, account, and request. They do not establish a required flow, universal consent, JWT signature validation, or API authorization.

- [Successful flows](flows-602600edb5a1.json): 238 Graph client/resource observations exported with `Export-TokenForgeFlowEvidence`. Records contain public application and resource IDs, protocol, SPA redemption flag, and observed scopes.
- [Additional scopes](scopes-d9db20fc7bfe.json): one successful scope observation exported with `Export-TokenForgeScopeDatabase` that was absent from the existing [weekly scope chunks](../scopes/). The other 237 scope sets were already published.

The flow snapshot excludes account and tenant fingerprints, private plan IDs, callback URLs, timestamps, credentials, and failed-attempt diagnostics. The scope snapshot includes its observation timestamp. All exported application and resource IDs occur in the public application catalog.

The source run stopped each client/resource pair after its first successful issuance and used at most one eligible callback. Absence from these snapshots does not prove a flow is unsupported. Other protocols and callbacks may remain untested.

Snapshots are immutable compact JSON. Each filename suffix is the first 12 characters of the file's SHA-256, including its final newline. Git history records publication dates. These supplemental snapshots are separate from the numbered weekly scope chunks.
