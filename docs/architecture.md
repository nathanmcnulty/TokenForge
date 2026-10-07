# Architecture and roadmap

TokenForge separates credential-free planning, identity protocol execution, Graph tenant administration and persisted evidence. The PowerShell 7.4 module and script CLI run on Windows, Linux and macOS; self-contained native CLI packages are available, with PowerShell still required for authentication.

| Layer | Functions | Evidence boundary |
| --- | --- | --- |
| Public metadata | Catalog update/read, discovery update/aggregate, application matching | Source claims; not tenant consent |
| Tenant state | Tenant inventory, registration, registration synchronization | Microsoft owner verified through Graph; configured grants distinct from preauthorization |
| Planning | Explicit catalog/tenant requests, discovery requests, probe matrix | One client/resource; definitions do not establish client permission |
| Acquisition | ESTS cookie PKCE, refresh redemption, discovery-only implicit flows | State checked, callback never contacted, exact identity host only |
| Observations | Claims inspection, resumable probes, database, diff, coverage, export | Diagnostic scp; no signature or API authorization claim |
| Session vault / teaching view | Opt-in encrypted sessions and tokens; metadata-only offline HTML | Named account isolation, explicit unlock, no background broker or implicit cache hits |
| Authentication/API checks | Optional XDRInternals passkey adapter, read-only Graph/ARM status check | Credentials memory-only by default; optional encrypted vault; response bodies not retained |

Private identity and Graph transports disable automatic redirects. Graph pagination validates every next link. Public source providers receive no session credentials. Graph credentials and cookies are separate explicit inputs. Registering service principals is an administrative operation, while token probing uses existing authorization and stops at policy or consent pages.

Versioned JSON discovery/inventory/database documents preserve provenance and evidence labels. The runner serializes state-directory writers; observations checkpoint individually. No token or identity response is serialized into these evidence files. The separate opt-in vault encrypts credentials and context together. Scope history is partitioned by tenant/principal fingerprints; public exports omit those namespaces.

An explicit assessment request cannot silently switch to broad implicit discovery. Discovery tries published callbacks and supported flows but cannot satisfy secret, broker or device-binding requirements. Scope selection minimizes observed extra permissions, with no guarantee Entra will issue only requested scopes. Customer role and policy requirements remain independent.

See [the repeatable inventory workflow](inventory.md) for stages and examples. Next work includes a portable authentication provider interface independent of XDRInternals, additional supported cloud authorities, packaged CLI/JSON interfaces, more source conflict handling, and further tenants/resources/operation-specific API proofs. These require evidence and are not advertised as shipped capabilities.

References: [authorization code + PKCE](https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth2-auth-code-flow), [scopes and consent](https://learn.microsoft.com/en-us/entra/identity-platform/scopes-oidc), [implicit flow](https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth2-implicit-grant-flow). The ESTS sequence in research-passkeys informed acquisition; browser policy processing and passkey registration were not copied into TokenForge.

The [session vault and native CLI plan](session-vault.md) recommends extracting a shared .NET core with PowerShell and standalone CLI adapters, followed by explicit OS key-protection providers. It includes the Go tradeoff and the implemented offline teaching viewer.
