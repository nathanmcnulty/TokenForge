# Inventory to database review

Prepare an offline review from an accepted, retained First-Party Inventory and exact pinned public inputs. This does not collect, authenticate, rebuild, modify the published database or start CLI work.

```bash
PYTHONDONTWRITEBYTECODE=1 python3 -B scripts/New-TokenForgeInventoryDatabaseReview.py \
  --inputs "$PRIVATE_REVIEW/inputs.json" \
  --output "$PRIVATE_REVIEW/new-output"
```

The local input manifest pins each file by SHA-256 and length, the published baseline commit and complete file inventory, and an already qualified local release and its file inventory. Inputs include the retained private inventory and acceptance receipt; baseline and prepared application ledgers; both exact Merill snapshots; the sealed anonymous public acquisition; existing adapter output and qualified health accounting; pinned Graph definitions; typed public reference facts and their retained raw source snapshots; and the prior public reconciliation diff/receipt. Keep this manifest private: it contains local paths and private evidence identities. Local pins check consistency under trusted host custody; they are not signed attestation or a general data-loss-prevention mechanism.

Use a new output directory. An input, tree or source mismatch refuses completion. The final success receipt is written last after rechecking immutable inputs, executed source, both data trees and every copied release file. A failed new output gets `FAILED`; preserve it for inspection. An existing historical output is never overwritten or relabeled.

The retained inventory's historical source identity remains separate from this generator and from the later #132 exact-window correction. The inventory is reused by its reviewed byte identity, not described as recollected or revalidated live under newer source.

## Private review

`review.md` contains all app/non-app and public-claim conflict rows, their priority, typed evidence, ownership status and established roles. `private-review.json` partitions every retained AppId exactly once, preserving each original evidence row:

1. App/non-app conflicts: hold identity promotion, retain both claims.
2. Public-claim conflicts: retain current and historical disagreement, even when ownership is verified.
3. Verified Microsoft ownership with an established client/resource role and no outstanding conflict.
4. Verified Microsoft ownership with unresolved client/resource role.
5. Observed-only IDs whose ownership remains unverified.
6. Other unresolved IDs.

Ownership, client/resource role, sign-in activity, historical matched issuance and historical fixed-GET API acceptance remain separate facts. A successful sign-in or token issuance does not verify Microsoft ownership. A name that sounds like a permission is not positive non-app evidence. Other namespaces and original history remain preserved by the retained inventory binding.

Current claim/conflict `FirstSeenAt` is the payload's `CurrentVersionFirstSeenAt`; `RecordFirstSeenAt` records its separate lifetime. Historical version dates remain their original dates. Neither a replay nor preparation time becomes an observation date.

## Sanitized candidate

The `candidate/` tree reuses all prepared public release files exactly and adds `identifier-classifications/inventory-v1.json`. `candidate-diff.json` lists every changed/added path with old/new hashes and lengths, the retained public application change, quarantine and classification counts. `candidate-manifest.json` enumerates the entire proposed tree. These are local review artifacts, not publication authorization.

Public generation takes only public inputs. It does not redact the private review or export a tenant-derived decision. The sidecar includes public application claims, positive public non-app definitions, separate current/historical claim conflicts and unresolved cases. It excludes private ownership verification, private-only identifiers or definitions, directory object mappings, tenant additions, activity, issuance/API joins, private paths and private input hashes. The private report and success receipt must stay private.

The prepared application ledger is a historical union, not a replacement with the inventory or Merill export. Application IDs, first-seen dates, historical versions and runs are preserved. Positive permission/role/AAGUID/SKU evidence creates an app/non-app conflict; it is never a deletion instruction. The application schema, reader and CLI remain unchanged. **The current reader does not consume this proposed sidecar**; review acceptance does not claim runtime filtering or automatic identity promotion.

## Exact retained public inputs

The published baseline remains `be10da62595013477c13c3a693a257f6da22be1d`. Its application bytes SHA-256 is `4e681b39da4f0b779d5d01d5f6b5caabcc682f2f6fa72fbcd031cc71d1b9011e`. The reused, unpublished public release is `6fcd8e91969c74069bc7bf6e415401b724974f6a`, with application bytes SHA-256 `930413f4bef996dfa2b4dc6257ddabc77896de9a443d0ad693aea47e1510910b`. Existing native catalog validation, download export and historical reconciliation for those exact bytes are reused.

The inventory-era Merill export is SHA-256 `639df4125260c10ce78983caa7f059baf425f4b5ccca96319850542f63047f31` (843,055 bytes). The later sealed export used for the next-update candidate is `81f9c620a6e798b95ae2a356f01cdfe56dbf0499470be928b7c882c9625ebe51` (843,052 bytes). Both are successive snapshots of the same MicrosoftApps URL, not independent corroboration. Their one changed name/source pair is preserved explicitly. The existing adapter retains its zero-ID placeholder accounting and malformed-ID quarantine; no suffix is guessed away.

Public inputs reproduce 1,049 app/non-app conflicts: 1,046 pinned Graph permission/app-role overlaps and three typed documentation overlaps. There are 201 current public-claim conflicts and two historical conflicts, with one historical-only case. These views can overlap. The original 5,470 application claims remain; unresolved records stay visible.

## Focused checks

```bash
PYTHONDONTWRITEBYTECODE=1 python3 -B tests/InventoryDatabaseReview.test.py
```

Twenty-two fixtures cover conflict precedence, ownership versus observation, private-only definitions, public-output noninterference, namespace separation, exact version dates, history preservation, malformed/placeholder IDs, duplicate keys, input tampering, copied-file and prepared-data-tree mutation, late failure marking and preservation of historical outputs. Actual retained-input checks compare the entire 82-file candidate, all baseline history and the seven-path diff. Public-only replay and a separately labeled synthetic private-input mutation produce byte-identical public sidecar, diff, manifest and candidate files. Earlier local outputs remain superseded evidence; they are not relabeled as final acceptance.

All checks are local Linux/Python or the existing offline PowerShell adapter. No compiled inputs changed, and no broad collector suite, collection, sign-in, tenant API request, hosted workflow, merge or catalog publication is part of this task.
