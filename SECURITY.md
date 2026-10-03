# Credential handling

Use TokenForge with sessions and tenants you are authorized to access. ESTSAUTH cookies and refresh tokens are credentials with potentially broad reach.

- Inputs and returned tokens use `SecureString`. Requests necessarily contain plaintext in process memory; SecureString is not a portable encrypted vault, and this module does not guarantee memory erasure.
- The module writes only public catalog metadata to disk. It has no token cache, cookie import, browser scraping, telemetry, or automatic token export.
- Avoid transcripts, HTTP tracing, debugging secrets, shell arguments containing credentials, and logging full result objects. PowerShell error history and external instrumentation may retain runtime information even when outward messages are sanitized.
- Use `Read-Host -AsSecureString` or a trusted secret store. Never commit sessions, tokens, authorization URLs, HTML pages, or response bodies.
- Automatic HTTP redirects are disabled for identity requests. Authorization follows at most ten HTTPS redirects on the exact public-cloud identity host. The registered callback is captured locally and never contacted. PKCE and callback state are checked before code redemption.
- Browser pages, consent, MFA, federation, App Control proxies, and other policy interrupts stop the flow. TokenForge does not attempt to satisfy or bypass them.
- Catalogs are untrusted discovery input. HTTPS and content hashes provide transport/provenance information, not proof that a client or scope is available in your tenant. Do not put credentials in catalog source URLs.

Report issues privately to the repository owner. Include sanitized reproduction steps and synthetic fixtures, not live credential material.
