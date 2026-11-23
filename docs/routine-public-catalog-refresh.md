# Routine public catalog refresh

For the current split catalog, use the [candidate-only delta and sign-in reports](catalog-candidate-ingestion.md). The legacy refresh below accepts historical single-ledger baselines.

Run the refresh locally with the existing reviewed Linux x64 native package and PowerShell 7.6.7. The command reads only the three approved public metadata sources. It performs no tenant authentication, token collection, hosted execution, publication or CLI changes.

```bash
python3 scripts/Refresh-TokenForgePublicCatalog.py \
  --baseline /absolute/path/to/clean-discovery-data-checkout \
  --expected-baseline-commit FULL_DATA_COMMIT \
  --work-root /absolute/path/to/new-private-refresh-directory \
  --native /absolute/path/to/accepted-package/tokenforge \
  --pwsh /absolute/path/to/powershell-7.6.7/pwsh
```

Use a clean checkout of the exact published `discovery-data` revision. Start with `be10da62595013477c13c3a693a257f6da22be1d` or explicitly pin its successor. Keep the working directory private: it retains raw responses and diagnostic receipts that do not belong in the release.

The command composes the existing public collector, historical reconciliation adapter, permission identifier comparator and catalog download exporter. The frozen baseline, executed source and existing runtime identities remain distinct from the new captured input identities. A timestamp update by itself is not a meaningful catalog change.

The result must distinguish a complete no-change pass, a complete changed candidate awaiting review, and an incomplete or refused pass. A complete no-change result creates no release. A source failure cannot remove historical entries or claim a fresh observation. Documentation, resource and single-source identity claims retain their evidence labels; public metadata is not verified application identity, tenant consent, successful token issuance or API access.

Resume using the same arguments and working directory. Completed raw captures are reused without requests. Uncertain dispatched requests remain charged. Never delete an intent to manufacture another attempt. The capture deadline and request ceiling belong to the original operation and do not reset on resume. After all inputs and the validated exchange are retained, append `--offline` to verify/resume without HTTP. Add `--offline --replay-output /absolute/path/to/new-replay-directory` to execute the existing reconciliation path from the retained exchange again. Compare candidate, diff and gzip hashes to the first reconciliation receipt; choose a fresh replay directory each time. A resumed projection can run later than capture: observation freshness remains bound to the actual retained capture finish; projection and recorded times remain separate. A moved or edited baseline or altered retained input requires investigation; do not overwrite its receipts or quietly substitute another baseline.

For a meaningful change, review the readable additions/changes/uncertainty summary and independently inspect the exact release tree. The ledger, new blob-named gzip, adjacent manifest, index and matching permission-overlap report must agree. The manifest's source commit identifies an immutable ledger ancestor; source bytes, decompressed compact content and gzip bytes have separate hashes. Preserve historical IDs, observation history, old downloads, old overlap reports and all scope exports. Publication is a separate operation against the exact expected data parent; collection is never part of publication retry.

Only approved release paths may be published. Exclude raw responses, acquisition journals, exchange files, SQLite databases, private paths and test evidence. Verify final remote index/manifest/gzip bytes after any separately approved publication, and reconcile uncertain outcomes before retrying.

The acquisition ceiling is six requests within one 180-second operation, with 30-second per-request waits and 8 MiB per source. This command currently performs one dispatch per source and refuses automatic retry after uncertain or failed dispatch. No request limit or deadline is reset by restarting the command.

Completed acquisition seals are checked before any possible request. If a frozen exchange is missing while its inventory remains, restore the exact retained exchange or investigate; the command refuses to regenerate it. Work-directory aliases resolving inside the baseline are rejected before initialization. New releases move the single **Current reviewed snapshot** pointer to the new bundle and keep previous snapshot links as historical.
