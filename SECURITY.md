# Credential handling

Use TokenForge with sessions and tenants you are authorized to access. ESTSAUTH cookies and refresh tokens are credentials with potentially broad reach.

The [authentication walkthrough](docs/authentication-flow.md) explains the complete credential lifecycle. TokenForge has no persistent cookie jar or broker cache; browser profiles and local software-passkey files are separate credential stores with their own protections.

- Inputs and returned tokens use `SecureString`. Requests necessarily contain plaintext in process memory; SecureString is not a portable encrypted vault, and this module does not guarantee memory erasure.
- The module writes discovery metadata and whitelisted tenant/scope observations to disk, including tenant/principal fingerprints. Keep these private. It has no token cache, browser scraping, telemetry, or automatic token export. The optional passkey adapter returns a cookie in memory.
- Avoid transcripts, HTTP tracing, debugging secrets, shell arguments containing credentials, and logging full result objects. PowerShell error history and external instrumentation may retain runtime information even when outward messages are sanitized.
- Use `Read-Host -AsSecureString` or a trusted secret store. Never commit sessions, tokens, authorization URLs, HTML pages, or response bodies.
- Automatic HTTP redirects are disabled for identity requests. Authorization follows at most ten HTTPS redirects on the exact public-cloud identity host. The registered callback is captured locally and never contacted. PKCE and callback state are checked before code redemption; implicit discovery validates state before returning a locally captured fragment token.
- Cookie/passkey token requests and scoped browser requests use `prompt=none`; consent, MFA, and other interactive requirements stop acquisition. Scoped browser requests never retry interactively. Lower-level `Get-TokenForgeToken -Browser` and CLI `Connect` allow interactive sign-in and can present consent unless `-NoConsent` is supplied.
- Catalogs are untrusted discovery input. HTTPS and content hashes provide transport/provenance information, not proof that a client or scope is available in your tenant. Do not put credentials in catalog source URLs.

Report issues privately to the repository owner. Include sanitized reproduction steps and synthetic fixtures, not live credential material.

Tenant registration creates service principals and checks supported Microsoft owner tenants; it never creates permission grants or role assignments. Read the [inventory workflow](docs/inventory.md) before enabling source-published candidate resolution. Graph paging stays on the exact Graph host. Direct database callers must coordinate a single writer; the CLI runner locks its state directory.
