# Scope inventory validation — 2026-10-02

This is aggregate evidence from one authorized tenant/session on Linux. Raw identity IDs, credentials, token payloads, API bodies and tenant inventories are not committed.

The discovery union contains 5,448 candidate application/resource IDs across ROADtools, merill/microsoft-info and EntraScopes. Published metadata identifies 753 candidates with supported Microsoft owner IDs. Source membership is not verified ownership; the tenant inventory checks ownership separately.

The first registration stages created 205 service principals, including a one-app smoke test. Twelve additional candidates failed registration. No permission grants, app roles or client credentials were created. A broader resolution stage for published candidates with unknown ownership is underway; its results are not included in these counts.

The first broad Graph probe completed 305 new observations: 88 readable delegated `scp` successes, 199 failures and 18 broker-required clients. Three earlier pilot successes also remain in the private database. Protocol failures include confidential-client requirements, origin/platform restrictions, preauthorization/consent constraints, disabled apps and server-rejected published callbacks. Successful claims are tenant/session-specific observations and are not universal preconsent or API authorization proofs.

The optional software-passkey adapter successfully obtained an in-memory cookie. Four confidential-client candidates were tested with implicit-only discovery; none returned a usable token, and three returned AADSTS700051 (implicit response type disabled). Implicit fallback has synthetic protocol coverage and live negative evidence; successful implicit acquisition is not yet established.

Local validation passed 70 tests. They cover multi-client matrices, bounded-batch resumption, owner mismatch handling and rollback, Graph paging boundaries, secret-free checkpoints/exports, tenant/principal evidence isolation, stale/failed observations, least-extra-scope selection, and state validation for implicit callbacks. Earlier [native/SPA/refresh/API validation](live-validation.md) remains separate evidence.

A separate sample of 20 non-Graph resource relationships returned seven readable delegated-scope tokens, one opaque token and twelve failures. These observations are kept in a separate private checkpoint database during parallel registration to avoid concurrent writers.

The experiment continues across further candidates and resources. The private database is resumable and preserves failure outcomes; the published figures above describe this completed batch only.

The fresh coverage-ranking proof selected the smallest observed set covering `Application.Read.All` and `AuditLog.Read.All` from the available successful candidates. Explicit acquisition returned both requested scopes, and a read-only Graph service-principal request returned HTTP 200. The token also contained 29 additional API scopes (34 total `scp` entries including OIDC scopes), so this proves usable assessment access in this session, not a two-scope token.
