# Tenant inventory validation — 2026-10-03

This records a completed experiment in one authorized tenant using one software-passkey account on Linux. The repository contains aggregate evidence only. Credentials, token payloads, API bodies, raw identity IDs, tenant inventories and live scope databases are kept out of Git.

## Discovery and registration

Fresh ROADtools, merill/microsoft-info and EntraScopes sources produce 5,455 candidate app/resource IDs, including 1,780 resource candidates. The final refresh returned the same candidate IDs and planning metadata as the assessment snapshot. Source hashes and retrieval dates are retained separately; unchanged modeled metadata does not mean identical source bytes. Source membership is not proof of Microsoft ownership or universal availability.

A fresh Graph inventory contains 2,051 verified Microsoft service principals. Registration history contains 5,346 attempts, including recovery after a long-running Graph token expired. Every eligible missing candidate has a result: 3,458 remain unavailable after failed registration, and four newly created candidates were rejected and removed after ownership verification. There are no unresolved cleanup checkpoints. TokenForge creates only service principals; it does not create permission grants, roles or credentials. The latest before/after inventories both enumerate 18 configured grants.

## Completed token coverage

All workers exited successfully. The fresh tenant plan has 14,709 distinct enabled-client/resource pairs; every pair has an outcome in the matching tenant/principal namespace. The matrix includes Graph, published relationships, applicable configured grants and apps' own resources, rather than a speculative Cartesian product.

| Latest outcome | Pairs |
| --- | ---: |
| Readable delegated `scp` success | 8,424 |
| Failed acquisition | 1,307 |
| Broker required | 2,326 |
| No usable redirect | 1,796 |
| Opaque token | 856 |
| Total | 14,709 |

The successful pairs span 325 clients and 1,455 resources. Every latest success has matched tenant/principal, issued-client and resource-audience evidence. Readable claims are diagnostic: `SignatureValidated=false`. Opaque tokens are not treated as verified scope evidence.

Broad scans tested up to two published callbacks with PKCE and discovery-only v2/v1 implicit flows. A further eight-callback pass covered all 98 Graph clients with callback/platform failures and found five additional successes. Other failure outcomes remain recorded. This is complete coverage of the planned pairs with these tested callback bounds, not proof that every callback, protocol, resource API or Microsoft application is usable.

The durable database contains 15,355 historical observations and 5,346 registration attempts. Its anonymous export contains 8,515 request-matched success records, including history; these are not unique pairs. Export records contain only public client/resource IDs, observation dates, scopes, an evidence label and `SignatureValidated=false`. The final audit found zero pending pairs, zero unattempted eligible missing candidates, zero invalid latest-success context/request records and no export-whitelist violations. Private state uses an owner-only directory and owner-only files on Unix.

## Explicit requests and API proofs

Fresh observed scope evidence can now drive `New-TokenForgeTenantRequest -Database`, including permission names absent from enabled tenant definitions. A live explicit request for one such scope succeeded on the first sampled candidate and returned exactly one `scp` entry, with matching namespace, client and audience. That resource has token evidence only; its API authorization was not tested.

Four fresh Graph candidates covered `Application.Read.All` and `AuditLog.Read.All`. Explicit requests received both scopes. All four returned HTTP 200 from read-only service-principal and directory-audit API checks; their extra API scope counts were 29, 35, 42 and 106. The smallest token therefore contained 31 API scopes, rather than only the two requested scopes. Extra counts exclude standard OIDC scopes. Compare actual issued scopes after acquisition rather than assuming an explicit request narrows every first-party token.

One callback-retry client was reacquired using PKCE/SPA, returned 26 `scp` entries, and passed a read-only Graph `/me` request with HTTP 200. Earlier positive native/SPA/refresh and Graph/ARM checks are recorded in [live validation](live-validation.md). Two implicit-discovery clients were also reacquired and accepted by Graph `/me`, carrying five and four `scp` entries respectively. Six cross-client family refresh attempts were rejected; a same-client refresh control succeeded. No cross-client refresh-discovery capability is claimed.

## Tests and limits

All 89 offline tests passed locally and in Windows, Linux and macOS CI. They cover identity transport boundaries, callback/state validation, registration ownership and rollback, expired-session stops, bounded resumption, private checkpoints and merges, evidence isolation, fresh scope ranking, explicit requests from observed scopes, opaque/malformed responses, and export privacy.

These results describe one tenant, account and source snapshot. Alternate-user and guest cases have synthetic coverage only. Customer roles, licensing, consent, Conditional Access, client credentials, broker/device binding, cloud authorities and API-specific authorization remain independent requirements. Failed registration does not establish ownership, and readable scopes do not establish universal preconsent. The repository stays private; no live database or upstream dataset is committed.
