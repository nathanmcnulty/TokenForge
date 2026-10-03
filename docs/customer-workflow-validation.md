# Customer workflow validation — 2026-10-03

The prior live-validation and inventory PRs were merged to `main`. This candidate adds browser authentication independent of XDRInternals, observer-specific assessment manifests, maintenance reporting, and a PowerShell CLI ZIP build.

## Completed evidence

- 105 offline tests pass on Linux, including actual loopback HTTP callbacks with synthetic authorization codes, PKCE challenge/verifier matching, duplicate/mixed callback rejection, bounded slow-header handling, sanitized declines, and shared token-redemption validation.
- Review identified and fixed timestamp ordering across UTC offsets and future-dated freshness. A newer failed observation cannot revive older successful coverage.
- Live public discovery refresh completed. Maintenance generated a private report with 6,285 queued client/resource records and one changed source snapshot hash. Inventory capture remained within the freshness window; its discovery snapshot hash now differs from the refreshed source. A snapshot-hash change alone does not establish changed published permission data.
- The self-profile manifest found 147 fresh candidates in the existing observer namespace. This is existing-account scope evidence, not new browser or Nora evidence.
- The reviewed export contains 8,515 historical observations, all with exactly the six permitted public fields. Two observed leading-dot scope names are preserved as scalar observations. Nested data is rejected before replacing an export. No export was published.
- The 0.3.0 ZIP was built, extracted, and imported successfully with 26 exported commands. It contains only the runtime CLI scripts, module, manifests, and reviewed documentation. PowerShell 7.4+ remains required.

## Live second-account evidence

The browser-control connector failed initialization (`CUA_REPL_ENABLED_SURFACES is required`), so account selection/MFA used the system browser, Edge. The initial request expired. A subsequent Azure CLI request for Graph `User.Read` returned AADSTS65002 following the reported app-assignment issue. This is app/API preauthorization failure, not proof of user roles or API privileges.

The Microsoft Graph Command Line Tools client completed browser authorization-code + PKCE on Linux. Graph `/me` returned HTTP 200 and its identity matched the requested observer inside the process. Client and audience matched; the observer was in the same tenant as the existing inventory but had a different principal fingerprint. A separate private scope database supplied fresh `User.Read` assessment coverage for that observer and client.

The token contained 111 `scp` entries: 108 API scopes and three OIDC scopes. It included 107 API scopes beyond the single requested `User.Read`. These are scope observations; `/me` was the only API operation checked with this token. No additional API privilege, role, license, or guest status is inferred. The [bounded JSON proof](browser-validation-2026-10-03.json) omits raw identity values, namespace fingerprints, authorization codes, and tokens. Returned access/refresh token objects were disposed after validation, and TokenForge persisted no credentials. Private scope observations remain outside Git.

## Remaining evidence

Ordinary-user role status, guest behavior, and a separate customer-like tenant still need validation. A second account alone does not establish any of those conditions.

Windows/macOS CI verifies offline behavior. Synthetic callback clients connect directly to IPv4 loopback while preserving the expected localhost Host header, avoiding Windows DNS fallback delays; the slow-header deadline test remains bounded. Real browser UI, localhost resolution, and token redemption on each platform remain distinct live evidence. Package signing, publication, and a standalone executable are future work.
