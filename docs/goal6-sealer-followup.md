# Sealer follow-up to Dot review of fb6d260

Current checkpoint: [the canonical original-ZIP contract](goal6-canonical-zip.md) implements fail-closed container coverage and converts the prior unsafe characterizations into rejection regressions. Historical findings/receipts below remain unchanged; operational emission and hosted activation are still blocked.

At the previous checkpoint, the temporary-directory defect was corrected and complete-original-ZIP privacy was confirmed as an unresolved activation blocker. This checkpoint is ready for further offline review, not signing, publication or hosted acceptance. Exact source/workflow/package hashes and results are in [the follow-up receipt](goal6-sealer-followup-validation.json). The earlier receipt remains historical.

## Temporary-directory correction

The hosted bridge calls `New-TfSealerOutputPath` before invoking the subject validator. The helper checks the existing temporary root and its ancestors for links without traversing unrelated temporary contents, creates a dedicated `tokenforge-sealer-private` directory with mode 0700, verifies that mode, then resolves `sealed` inside that private parent. It does not tighten the runner root or adopt/modify an existing parent. An existing parent, including prior completed evidence, causes refusal.

Validation output, the signing action's fixed subject and uploaded evidence now agree on `RUNNER_TEMP/tokenforge-sealer-private/sealed/{candidate.zip,subject.json}`. Five regression checks cover an initial 0755 root, resulting directory/file permissions, existing private evidence, an existing nonprivate parent, linked roots and workflow/bridge path consistency. The workflow is still literally quarantined and unconnected.

## Confirmed privacy boundary

`Expand-TfPublicationArchive` and `Assert-TfDiscoveryCandidate` validate the seven extracted regular files, their hashes/schema, reconstructed content and allowed fields. They do not validate every byte in the original archive. The original archive is the proposed signing subject and is also an upload input. Checking its digest binds bytes; it does not establish that those bytes are safe to disclose.

An independent offline probe using the exact package reproduced these results:

| Synthetic archive mutation | Subject validation | Marker in unchanged subject |
|---|---|---|
| Baseline .NET ZIP | Accepted | Absent |
| Archive comment | Accepted | Retained |
| Entry comment | Accepted | Retained |
| Local and central extra fields | Accepted | Retained |
| Bytes after end record | Accepted | Retained |
| Prefix with corrected offsets | Accepted | Retained |
| Gap before central directory | Accepted | Retained |
| Gap before end record | Accepted | Retained |
| Prefix without corrected offsets | Rejected | No retained subject |

All markers are fixed synthetic text, not credentials or tenant evidence. Each altered fixture has matching synthetic service digest/size metadata, so the probe tests the missing privacy boundary rather than a simple hash mismatch. Accepted archives retain the exact original bytes and report structural validation success. No signing or upload was performed.

The checked-in [mutator](../tests/fixtures/publication/MutateSealerZip.py) and `KnownPrivacyGap` characterization cases in [Sealer.Tests.ps1](../tests/Sealer.Tests.ps1) reproduce this evidence. Passing those assertions means the known unsafe acceptance was reproduced; it is **not** a passing privacy gate. The acceptance receipt separates these nine characterizations from normal checks. No comprehensive compressed-stream, metadata, extra-byte or general data-loss-prevention claim is made.

Subject receipts and policy plans now state `CompleteOriginalZipPrivacyValidated=false`. Policy plans include a blocking reason and required gate. `-Operational` always refuses runtime policy emission, including otherwise active, fully bound synthetic sources; there is no bypass switch. The job remains `if: false`. This prevents treating the temporary-directory fix or a green test count as activation approval.

## Required next review

Choose and implement a reviewed original-archive privacy contract before activation: reject or otherwise account for all unvalidated metadata/bytes without silently replacing the original artifact identity. Evaluate local/central records, comments, extra fields, prefix/trailer/gaps, descriptors, compression stream boundaries, ZIP64 and byte-level consumer differences. If canonicalization is chosen, explicitly revise the original-artifact/attestation/publication binding contract and prove producer compatibility. Recompressing a ZIP silently or allowing only a few metadata fields would not by itself establish complete-byte coverage or general privacy.

A future remediation must turn the known-gap characterizations into fail-closed safety regressions, preserve the seven-file semantics and budgets, receive independent review and update exact immutable source/workflow pins. Only then can operational-policy emission be reconsidered. Existing hosted origin/certificate, final source/package, independent identity/permissions, publication recovery and fresh-human-operator gates remain open. No authentication, data publication, hosted validation, tenant permission change, PR or merge occurred during this follow-up.
