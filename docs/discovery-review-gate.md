# Discovery candidate review and publication

Discovery collection no longer writes `discovery-data`. It has read-only contents
permission and seals an immutable, content-addressed candidate after the existing
public schema and receipt checks. Validation-only runs remain isolated.

## Candidate contract

The artifact is named `discovery-candidate-<attempt>-<sha256>` and retained for 30
days (subject to repository retention policy). The digest is the SHA256 of the
exact `manifest.json` bytes. The manifest binds every payload and review-packet
file by its exact byte hash, the frozen data parent, collecting source commit,
producer run ID and attempt, recipe ID and mode.

- `data/`: only allowlisted public catalog, recipe, coverage and scope files
- `request.json`: frozen normal publication request
- `changes.json`: complete semantic JSON Pointer diff, with before/after values;
  object property order is ignored and arrays are compared by index
- `review.md`: human-readable preview of up to 200 changed values, with an explicit
  truncation warning and pointer to the full diff
- `validation.json`: schema-check result and pending review status; this is not
  semantic approval

Candidate creation refuses to overwrite an existing destination. Verification
rejects missing, changed, linked, duplicate, traversing, or unexpected files.
Candidate files are data and are never executed. Public-only metadata validation
is repeated before publication. Account observations do not establish universal
support; partial batch completion must not be described as complete coverage.

## Explicit review and trust boundary

No Luna, agent, or external semantic reviewer is configured. The candidate stays
pending until a repository maintainer reviews the complete semantic diff and
validation evidence and explicitly commits this record on **main** at
`discovery-reviews/<candidate-sha256>.json`:

```json
{
  "SchemaVersion": 1,
  "CandidateHash": "<64 lowercase hex characters>",
  "BaseCommit": "<40 lowercase hex characters>",
  "SourceCommit": "<40 lowercase hex characters>",
  "ProducerRunId": "123456789",
  "ProducerAttempt": "1",
  "Decision": "Approved",
  "Reviewer": "<actual reviewer identity>",
  "ReviewedAt": "2026-10-16T12:00:00Z",
  "Notes": "<what was reviewed, noteworthy changes and limitations>"
}
```

The JSON `Reviewer` string is an audit label, not a signature. Authorization comes
from the separately committed approval on main, not from the collecting artifact
or a self-supplied review path. Restrict main writes and review-file changes to
trusted maintainers using repository rules. This change does not configure or
assert that branch protection, required reviewers, or Actions are enabled. Anyone
able to change trusted main workflow code can change the gate; this is not a
cryptographic third-party attestation system. No approval records are included by
default, so publication fails closed.

## Publication and retry

After explicit authorization to use hosted runners, manually run **Publish
reviewed discovery candidate** on main with the existing collecting run ID,
attempt and candidate digest. The publisher:

1. Requires a completed manual discovery attempt on main in this repo and a
   successful candidate-sealing job in that exact attempt. Failed workers may
   produce explicitly reviewed partial coverage; overall success is not required.
2. Downloads the exact retained artifact and matches its producer/source identity.
3. Verifies every file and the separate main-branch approval.
4. Requires the current data branch to equal the reviewed parent, then stages
   only public files (including reviewed deletions), verifies the new commit is
   a direct single-parent child of the reviewed base, and performs an exact
   expected-old push lease. This compare-and-swap also rejects branch deletion
   or reset-to-ancestor races between fetch and push.

A failed download, commit or push can be retried by running this publisher with
the same identifiers. It never signs in, requests tokens for discovery, runs
workers, refreshes sources, or recollects observations. A lost acknowledgement
after a successful push is recognized only when the candidate commit marker and
all reviewed public file hashes match. A changed parent fails closed; reconcile
and review a new candidate rather than rebasing an approval or overwriting divergent history. The explicit
`--force-with-lease=refs/heads/discovery-data:<reviewed-base>` is a strict
compare-and-swap; it never permits replacing a different remote parent.
Expired or deleted artifacts cannot be retried; retain the sealed review packet
before expiration when needed. Hosted execution is still manual-only and is not
enabled or exercised by this implementation.

## Offline validation

Dot-source `scripts/TokenForgeDiscoveryCandidate.ps1` in PowerShell 7.4 or newer.
`New-TfDiscoveryCandidate` seals already collected, artifact-shaped public data
and its baseline. `Assert-TfDiscoveryCandidate` verifies integrity alone, or also
verifies an explicit review with `-ReviewPath`. The latter is a local contract
validator, not a stand-alone authorization mechanism; only the workflow fixes the
review source to its trusted main checkout. Neither function performs network
operations or acquisition. Run `tests/DiscoveryCandidate.Tests.ps1` with Pester.
