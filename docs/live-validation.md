# Live validation

Authentication issuance is unverified in this initial version. Automated protocol tests and a live metadata download are not proof that Entra will issue tokens for any particular client.

Run a small proof using an authorized test account and an existing completed session:

1. Load a pinned catalog and record its content hash.
2. Choose one resource, a small required scope set, and a client publishing those scopes. Confirm its redirect platform configuration before using SPA mode.
3. Inspect the request plan. Enter the matching cookie name/value with `Read-Host -AsSecureString`.
4. Acquire the token; record only success/failure, scope evidence, requested/granted scope counts, and elapsed time.
5. Call a documented read-only endpoint on the intended API. Record only HTTP status and a success/failure outcome. Do not retain payloads or identities.
6. If a refresh token was returned, try one refresh request and repeat the API check. Retain the rotated token only in an intentional secret store.
7. Confirm that an insufficient or expired session stops cleanly. Do not change tenant consent, Conditional Access, or MFA policy for the test.

Keep cookies, tokens, codes, callback URLs, assertions, tenant/user identifiers, and page contents out of test artifacts. Browser interaction or an unsupported flow is an incomplete proof, not successful issuance.
