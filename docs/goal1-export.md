# Goal 1 saved-evidence candidate

`scripts/TokenForgeDiscoveryCandidate.ps1` adapts the immutable manifest, strict file allowlist, content hashes, producer/source binding and independent review contract from draft #119 (`e2aab00b2079dc1e99dc38aa1a994d4877b1bbf5`). It does not incorporate that draft's publication function or workflows. The Goal 1 format is a separate saved-cohort format rather than the draft's weekly publication artifact.

Dot-source the helper in a fresh PowerShell process. Supply existing private SQLite stores and an independently verified, source-compatible complete Linux package:

```powershell
. ./scripts/TokenForgeDiscoveryCandidate.ps1
$hash = New-TfDiscoveryCandidate -ScopePath /private/run/scopes.sqlite `
    -FlowPath /private/run/flows.sqlite -CohortId $savedCohortId `
    -OutputPath /review/new-candidate -NativeExecutablePath /trusted/package/tokenforge `
    -SourceCommit $implementationCommit -ProducerRunId 1 -ProducerAttempt 1
Assert-TfDiscoveryCandidate -CandidatePath /review/new-candidate -CandidateHash $hash
```

The helper accepts no credentials. It uses the established private-path policy without changing existing permissions, takes the cooperating run and cohort locks, reads the frozen cohort, and performs full unfiltered native history reads before selecting its namespace and cohort-bound flow plans. Corruption in unrelated older history therefore fails the full read. Selected flow plans must match the frozen namespace, authority, catalog, pair membership and protocols. Multiple flow matrices for one cohort pair fail closed for explicit review. Existing scope and flow files must exist; no empty store is silently created.

Terminal flow evidence is primary. The existing anonymous scope serializer projects successful matched flow attempts with their original observation dates, even when a previous aggregate projection was interrupted. The existing anonymous flow serializer receives a temporary private cohort-filtered snapshot. Neither path runs the collector, obtains tokens or updates authoritative checkpoints or metadata. Historical successes remain historical observations when a newer Started attempt is unknown; coverage separately reports that uncertainty.

Each candidate contains exactly `recipe.json`, `coverage.json`, `scopes.json`, `flows.json`, `validation.json`, `review.md` and `manifest.json`. Public recipes omit private namespaces, callbacks, redirect fingerprints, attempt IDs and private flow/cohort plan IDs. Pair and known-cell denominators are distinct. A pair whose flow matrix has never been saved is counted in `UnknownMatrixPairs`; its exact cell denominator is not invented. Coverage records each known cell's most recent saved outcome, preserving Started as `InFlightUnknown`. SessionPaused, RequestBlocked and TransientFailure remain separate counters; paused and transient cells are not terminal. Anonymous exports retain historical matched successes and do not claim current consent, universal support or API authorization.

The manifest binds the six payload hashes, public recipe bytes, source commit, producer run and attempt, and opaque hashes of the frozen recipe and full evidence snapshots. These hashes detect substitution against a trusted externally retained candidate digest; they do not prove producer identity or source provenance on their own. Private paths and raw evidence are not copied into the manifest. Verification independently validates every public schema, reconstructs the numeric validation receipt and fixed review text, checks recipe membership and agreement of anonymous flow/scope projections, and rejects extra files, duplicate JSON keys, duplicate manifest entries, traversal, links and changed bytes.

An export writes into its own newly created private sibling staging directory. The private filtered snapshot is removed before sealing. Normal failures remove that invocation's staging directory and release locks. The final directory appears only after integrity/privacy verification and a second full evidence snapshot check. A changed source fails without publishing a candidate. The atomic directory move never overwrites an existing output; retry uses saved evidence and a new staging directory. After abrupt process termination an orphan `.NAME.partial-GUID` directory may remain private. It is not a candidate and is never accepted or resumed as one; an operator can remove it after confirming the original process has stopped. Repeating export does not authenticate or recollect.

The returned manifest digest is the export receipt. Failure to return or separately save that receipt does not modify authoritative checkpoints. The sealed directory can be reverified using its manifest digest; an interrupted export can be reconstructed from the stores. Collection, projection, export, backup, approval and publication remain separate operations. This helper writes no backup, approval, Git commit, branch or publication receipt.

If an independent approval document is supplied to `Assert-TfDiscoveryCandidate -ReviewPath`, it must contain exactly `SchemaVersion`, `CandidateHash`, `SourceCommit`, `ProducerRunId`, `ProducerAttempt`, `Decision`, `Reviewer`, `ReviewedAt` and `Notes`. It must bind this exact candidate/source/producer, use `Decision: Approved`, include nonempty reviewer/notes and a nonfuture timestamp. The candidate itself always records review as Pending. No approval or publication is performed by this helper.

`tests/DiscoveryCandidate.Tests.ps1` uses synthetic private fixtures and mocks only the native cohort/store reads. The real anonymous serializers and independent verifier execute; authentication is forbidden by a mock assertion. These focused tests establish offline adapter behavior, not native package integrity or live acceptance. Original-target package validation remains a separate gate.

`tests/DiscoveryCandidateNative.Tests.ps1` separately exercises real native cohort/store operations with synthetic issuance and an omitted aggregate projection, a paused zero-success run, and another valid cohort in the same stores. It skips when `TOKENFORGE_TEST_NATIVE` is absent; a skipped test is not a package pass. Set that variable only to an independently verified complete original-target package.
