# Complete original-ZIP container contract

`CanonicalStoredOriginalZipV1` closes the demonstrated ZIP-container metadata/extra-byte gap for one explicitly supported representation. The original service archive must equal a deterministic reconstruction of the validated seven file bytes, byte for byte and in exact length. It is never replaced by the reconstruction. Operational policy emission and hosted activation remain blocked, with no override.

This is an offline contract, not proof of ordinary GitHub artifact compatibility or release completion. Default .NET compressed ZIPs are explicitly unsupported. A future reviewed producer must demonstrate that GitHub preserves this original representation before activation can be considered. The exact source, review-kit/runtime composition and extracted-package gates are recorded in [the canonical-ZIP receipt](goal6-canonical-zip-validation.json).

## Accepted representation

The files appear in this fixed order: `coverage.json`, `flows.json`, `manifest.json`, `recipe.json`, `review.md`, `scopes.json`, `validation.json`. Existing candidate validation reconstructs the schema, hashes, manifest, review text and permitted content. Every file must also decode as strict UTF-8; JSON is parsed in full with duplicate-key rejection. The seven nonempty payloads together and the complete archive are each bounded to 8 MiB; original download limits may reduce usable payload size by header overhead.

The canonical ZIP32 records are little-endian:

| Field | Value |
|---|---|
| Local signature / central signature / end signature | `04034b50` / `02014b50` / `06054b50` |
| Version needed / version made by | 20 / 788 (Unix, version 20) |
| General flags / method | 2048 (UTF-8 names) / 0 (stored) |
| DOS time / date | 0 / 33 (1980-01-01) |
| Local and central filename | Exact fixed ASCII name |
| CRC32 / compressed and uncompressed size | Derived from the exact file bytes; sizes equal |
| Local offsets / central offset and length | Derived from record positions |
| Entry counts / disk numbers | 7 / 0 |
| Attributes, extras, comments and other lengths | Zero |

There are no data descriptors, compression streams, encryption, ZIP64, optional records, prefixes, trailers, gaps or variable filesystem metadata. The BCL calculates CRC32 over a private scratch stream; the formatter manually writes the final expected records from fixed constants and validated payloads. Scratch ZIP headers are not used as the expected archive, so a BCL metadata-format change cannot widen this profile. Linux PowerShell 7.6 is required; the tested baseline is 7.6.7 on .NET 10.

The acceptance argument is: let `F` be the seven extracted, content-validated raw file byte sequences and `Canonical(F)` the fixed construction above. Acceptance requires `original == Canonical(F)`, not merely equal decompressed entries or a matching service digest. Every accepted container byte is therefore either a fixed constant or a deterministic function of those validated payloads. Opaque compressed bits and ignored metadata cannot enter the accepted subject. The accepted subject retains its original artifact ID, size, SHA256 and bytes; approval, attestation and publication identity rules are unchanged.

This is not general DLP or proof that arbitrary permitted JSON field values/representations cannot convey sensitive information. It combines complete container coverage with the existing candidate schema/privacy contract; semantic approval and operational authority remain separate. An input outside this profile is refused, not silently normalized or re-signed under a different identity.

## Review and evidence boundaries

All seven formerly accepted marker-bearing variants now refuse sealing: archive and entry comments, extra fields, appended bytes, adjusted prefixes and both gap locations. The malformed unadjusted prefix still refuses. Additional regressions cover local/central CRCs, sizes, names and offsets, timestamps/attributes, encryption, descriptors, ZIP64 extras, unsupported/deflate methods, order/duplicate entries, strict UTF-8 and filesystem-independent determinism. Positive fixtures are produced independently with Python struct/CRC code, rather than only by the production formatter.

Successful subject receipts state the evaluated `ArchiveProfile` and `CompleteOriginalZipPrivacyValidated=true` for this contract. Review plans evaluate no artifact, so their corresponding flag remains false. `OfflineArchiveProfileImplemented` is derived from `publication/zip-profile.json` and the exact pinned sealer/helper hashes, not from the currently running planner's capabilities. Missing or mismatched declarations report false. `PinnedInputs` includes the helper and declaration hashes. Operational policy emission always refuses even for active, fully bound synthetic inputs.

The [review-kit builder](../scripts/New-TokenForgeSealerReviewKit.py) creates a distinct `TokenForgeOfflineSealerReviewKit`, not a production release. It reads literal local Git blobs with lazy fetch, transports and credential helpers disabled, verifies object identity, rejects links/special files and uses only new destinations. Every module-source blob must match the accepted runtime package before its CLI/DLL can be reused. The CLI, DLL, old package manifest and runtime source are pinned; unchanged native code is not rebuilt. A manifest records every kit file hash. The deterministic archive is extracted into a fresh private directory, verified in full, then tested using its own scripts/tests and exact included runtime in a fresh externally isolated process. The receipt links both source provenance and archive/manifest hashes. No new full release package or production readiness is implied.

Remaining gates include independent review of this contract/checkpoint, an approved interoperable producer route, genuine hosted origin/certificate proof, final release-source/package integration, trusted identities/current permissions, approved publication recovery proof and fresh-operator acceptance. No authentication, tenant change, data publication, hosted validation, PR or merge is authorized by this checkpoint. Actions and the reusable workflow remain disabled/quarantined.
