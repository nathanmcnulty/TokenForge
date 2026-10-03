# Customer workflow validation — 2026-10-03

The prior live-validation and inventory PRs were merged to `main`. This candidate adds browser authentication independent of XDRInternals, observer-specific assessment manifests, maintenance reporting, and a PowerShell CLI ZIP build.

## Completed evidence

- 105 offline tests pass on Linux, including actual loopback HTTP callbacks with synthetic authorization codes, PKCE challenge/verifier matching, duplicate/mixed callback rejection, bounded slow-header handling, sanitized declines, and shared token-redemption validation.
- Review identified and fixed timestamp ordering across UTC offsets and future-dated freshness. A newer failed observation cannot revive older successful coverage.
- Live public discovery refresh completed. Maintenance generated a private report with 6,285 queued client/resource records and one changed source snapshot hash. Inventory capture remained within the freshness window; its discovery snapshot hash now differs from the refreshed source. A snapshot-hash change alone does not establish changed published permission data.
- The self-profile manifest found 147 fresh candidates in the existing observer namespace. This is existing-account scope evidence, not new browser or Nora evidence.
- The reviewed export contains 8,515 historical observations, all with exactly the six permitted public fields. Two observed leading-dot scope names are preserved as scalar observations. Nested data is rejected before replacing an export. No export was published.
- The 0.3.0 ZIP was built, extracted, and imported successfully with 26 exported commands. It contains only the runtime CLI scripts, module, manifests, and reviewed documentation. PowerShell 7.4+ remains required.

## Pending evidence

The browser-control connector failed initialization (`CUA_REPL_ENABLED_SURFACES is required`). A system-browser sign-in was launched with Nora's login hint, using the tenant domain and a published native localhost callback. The system's default browser is Edge. Account selection/MFA requires human interaction. The sign-in deadline expired without a callback; no second-account access or ordinary-user/guest status is claimed.

The live proof must compare Graph `/me` identity with the requested observer inside the process, check client/audience/context, and save only bounded noncredential results. Tokens, codes, cookies, raw identity responses, and browser session state must remain out of Git. Validate a second ordinary-user or customer-like tenant separately; a second email address alone does not establish either condition.

Windows/macOS CI verifies offline behavior. Synthetic callback clients connect directly to IPv4 loopback while preserving the expected localhost Host header, avoiding Windows DNS fallback delays; the slow-header deadline test remains bounded. Real browser UI, localhost resolution, and token redemption on each platform remain distinct live evidence. Package signing, publication, and a standalone executable are future work.
