# Offline discovery coverage

Run the report from a TokenForge checkout that already has both pinned discovery-data commits and their partition blobs. Python 3.10 or later and Git are sufficient. Use `--catalog-repo /path/to/local/catalog-repo` if the objects are in a separate local repository.

```sh
python3 -B scripts/Measure-TokenForgeDiscoveryCoverage.py
```

If the three public captures are retained locally, pass the directory containing `microsoftApps.json`, `resources.json` and `roadtools.json`. Their expected revisions and SHA-256 hashes come from the post-review catalog's `Upstream` stamps. The report reads local files and refuses a supplied capture whose bytes fail the pinned hash check.

```sh
python3 -B scripts/Measure-TokenForgeDiscoveryCoverage.py --captures /tmp/tokenforge-b1-public-captures
```

## B1 milestone plan

- Reconcile both catalog partitions before and after review issue #151, verify that every published verified ID has matching evidence, and compare ownership and audience evidence gaps.
- Measure distinct IDs, overlaps and unique contributions for the three public sources. Replay capture membership when the bytes are available and compare each ID with the retained source claims.
- Account for all 17 new review candidates using their original source and labels, exact ownership receipts where available, and aggregate outcomes where the individual mapping is missing.

B1 excludes new collection, candidate ingestion, publication, tenant or authentication operations, generalizing the report to later batches, and hosted or cross-platform validation. Global Microsoft-owned multi-tenant application coverage remains unknown.

### Reproduce the local checks

Validation host was `paseo-lxc`, Linux x86_64, with Python 3.13.5. From the repository root with the two catalog commits and three captures retained on that host, run:

```sh
TOKENFORGE_B1_CAPTURES=/tmp/tokenforge-b1-public-captures python3 -B tests/DiscoveryCoverage.test.py -v
git diff --check
```

The five tests cover byte-stable JSON with and without raw captures, both pinned partitions, 17 review candidates, source overlap and unique IDs, missing versus empty sets, rejection of hash mismatch, and zero per-source membership differences with all three captures. Omit the environment variable if the public captures are unavailable. The pinned catalog replay and all four core tests still run, and the raw replay test is skipped.

## Reading the report

- **Catalog.** The pre-review catalog holds 2,062 verified and 3,434 non-verified IDs. The post-review catalog holds 2,066 verified and 3,434 non-verified IDs. The four added IDs have exact ownership review evidence. An owner tenant recorded in discovery attributes is a published hint. The separate verified evidence ledger records an owner outside the target tenant for 2,064 application service-principal results and two sign-in owner observations. The absence of a recorded sign-in audience leaves tenancy undetermined by that attribute.
- **Public sources.** `retainedCatalogClaims` counts membership by source URL across both post-review partitions. It is derived from retained catalog claims. `rawCaptureReplay` counts membership from locally available hash-verified captures. The compact ID projection uses application keys, resource identifier values and scope resource keys for ROADtools, the public MicrosoftApps ID normalization and quarantine rules for EntraDocs rows, and resource IDs for entrascopes.com. It emits membership only. The exact pinned inputs give 5,471 distinct public-source IDs, leaving 29 catalog IDs outside the public-source union. Pairwise counts include IDs present in all sources. A source's unique count excludes IDs shared with any other source.
- **Missing inputs.** JSON `null` marks an unknown count or value. A count of zero means the available evidence establishes zero. With only some captures, the raw union covers those captures and is a lower bound for the full union. Pairwise overlap is available when both inputs are present. All-source overlap, per-source unique contributions and catalog IDs outside the full union require all three captures.
- **Review candidates.** The two issue edits in the [sanitized receipt](discovery-coverage-issue-151.json) identify the 17 additions, each absent from both pre-review partitions. There were 12 provisioning-only candidates, three sign-in-only candidates and two shared candidates. The two multi-tenant labels and 15 unknown audience labels reflect the issue at discovery time. Sign-in attribution is available only at group level. The hosted run documents terminal pagination across five sources for a requested 30 days. The detailed receipt, source populations and provider retention are unknown. [Issue #151](https://github.com/nathanmcnulty/TokenForge/issues/151) · [Run 45735818610](https://github.com/nathanmcnulty/TokenForge/actions/runs/45735818610)
- **Review outcomes.** Exact service-principal reads verified two owners and exact sign-in records verified two more. The other 13 candidates are absent from both post-review partitions. The retained aggregate documents one managed identity and 12 unresolved owners after lab creation refusals. The managed identity's exact AppId is unknown. Creation refusals leave ownership and tenancy unresolved. [Service-principal review](https://github.com/nathanmcnulty/TokenForge/pull/158) · [Sign-in owner review](https://github.com/nathanmcnulty/TokenForge/pull/160) · [Milestone evidence](signin-review-provisioning-plan.md#milestone-evidence)
