# Scope inventory validation — 2026-10-02

This is aggregate evidence from one authorized tenant/session on Linux. Raw identity IDs, credentials, token payloads, API bodies and tenant inventories are not committed.

The discovery union contains 5,448 candidate application/resource IDs across ROADtools, merill/microsoft-info and EntraScopes. Published metadata identifies 753 candidates with supported Microsoft owner IDs. Source membership is not verified ownership; the tenant inventory checks ownership separately.

The first registration stages created 205 service principals, including a one-app smoke test. Twelve additional candidates failed registration. No permission grants, app roles or client credentials were created. A broader resolution stage for published candidates with unknown ownership is underway; its results are not included in these counts.

The first broad Graph probe completed 305 new observations: 88 readable delegated `scp` successes, 199 failures and 18 broker-required clients. Three earlier pilot successes also remain in the private database. Protocol failures include confidential-client requirements, origin/platform restrictions, preauthorization/consent constraints, disabled apps and server-rejected published callbacks. Successful claims are tenant/session-specific observations and are not universal preconsent or API authorization proofs.

The optional software-passkey adapter successfully obtained an in-memory cookie. Four confidential-client candidates were tested with implicit-only discovery; none returned a usable token, and three returned AADSTS700051 (implicit response type disabled). Implicit fallback has synthetic protocol coverage and live negative evidence; successful implicit acquisition was not established by that initial sample.

Local validation passed 79 tests on Linux locally and on Windows, Linux, and macOS CI. They cover multi-client matrices, bounded-batch resumption, owner mismatch handling and rollback, Graph paging boundaries, secret-free checkpoints/exports, tenant/principal evidence isolation, stale/failed observations, least-extra-scope selection, and state validation for implicit callbacks. Earlier [native/SPA/refresh/API validation](live-validation.md) remains separate evidence.

A separate sample of 20 non-Graph resource relationships returned seven readable delegated-scope tokens, one opaque token and twelve failures. These observations are kept in a separate private checkpoint database during parallel registration to avoid concurrent writers.

The experiment continues across further candidates and resources. The private database is resumable and preserves failure outcomes; the published figures above describe this completed batch only.

The fresh coverage-ranking proof selected the smallest observed set covering `Application.Read.All` and `AuditLog.Read.All` from the available successful candidates. Explicit acquisition returned both requested scopes, and a read-only Graph service-principal request returned HTTP 200. The token also contained 29 additional API scopes (34 total `scp` entries including OIDC scopes), so this proves usable assessment access in this session, not a two-scope token.

Discovery now also retains resource IDs found only in catalog scope edges, expanding the candidate union to 5,455 IDs (1,780 resource candidates). Six previously unsuccessful family-client candidates rejected redemption of an authorized Azure CLI refresh token; no additional refresh-discovery coverage is claimed. New context checks prevent recording a different tenant/principal token as the inventory user and require fresh matching evidence for assessment selection. Earlier observations remain history pending re-probe.

The first fresh Graph re-probe confirmed tenant/principal fingerprints for all 91 earlier successful clients. A further pass is collecting client/audience consistency evidence as well. Scope selection and public export now require that request evidence; legacy records are retained as history.

The further Graph pass confirmed all 91 successful clients with matching tenant/principal, issued-client and resource-audience evidence. Ten source-published resource-only candidates were registered successfully and verified as Microsoft-owned without grants; expansion to the remaining resource-only candidates is underway. A same-client refresh control returned 12 scp entries, while the six cross-client family attempts remained rejected.

The resource-only expansion completed 567 further attempts: 559 created and eight failed. Combined with its ten-app smoke test, this stage registered 569 verified Microsoft resource candidates. The CLI probe successfully exercised explicit principal fingerprint and tenant-authority parameters against the current authorized user, returning 12 Graph scp entries with matched context and request evidence. Alternate-user/guest cases have synthetic coverage only. Ownership rollback failures are checkpointed and halt registration rather than claiming cleanup occurred.

During the expanded Graph scan, two further clients succeeded using v2 implicit discovery with matched tenant/principal, issued-client and resource-audience evidence. Both were reacquired and accepted by a read-only Graph `/me` request with HTTP 200, carrying five and four scp entries respectively. Implicit acquisition now has live positive API evidence for these two clients, alongside the earlier negative sample. The broader Graph and resource-matrix scans remain active; partial counts are not presented as exhaustive coverage.
