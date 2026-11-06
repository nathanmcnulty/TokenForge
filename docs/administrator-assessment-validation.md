# Administrator assessment: offline qualification

This record qualifies the Linux x64 implementation, not live Graph/ARM acceptance. The public catalog adapter is already merged in #127; its checks are retained in `microsoftapps-adapter-validation.json` and are not counted again here. Package binaries, test XML, build logs, inventories and operational receipts remain local. No authentication, tenant request, hosted job, schedule or package publication was performed for this qualification.

## Exact identities

| Identity | Value |
| --- | --- |
| Base main | `ff56a4995719e7ca1f92bfa5ffc765c88876577c` |
| Reviewed implementation and package source | `9c02b2af51b1c02cbb0ef62aeac55c15f2caf362` |
| Native and credential compilation source | `6c053524510a3c4aaf9e372b927079c754db47f0` |
| Archive SHA-256 | `eb85b7b1451c8cae3a804aaef46ce591587de705b2c3daafcc91eecf5ef5b177` |
| Archive bytes | `33660005` |
| Manifest SHA-256 | `03d1a86dd9d2853256b2f1f27efdfd08c7fa701471139a456c672da3fb83f5de` |
| Native executable SHA-256 | `d76e2ebbedde15e9fd962d3977f02516cf731cfacda55d72ef3ab7f145bf7dc8` |
| Credential DLL SHA-256 | `77ce122e7d7bde9b3bd6dccbd6539eec8f80cabae274b5c304c87d19dc3e5837` |
| Original build receipt SHA-256 | `b3f83cbb61356de9a3a9f9bbd97b3dc8c630b1807d634167e9e62bf09b5246f6` |
| Source-overlay receipt SHA-256 | `30274eaaf07630617ba2163977c4c2636b753095cafb62dcbd9901cbd60d878c` |

The original build output/receipt were preserved. The separate overlay changes the public-health runtime pair pins; all 100 compilation inputs and both compiled binaries remain byte-equivalent to the original build. The final documentation-only commit carrying this record is not the archive source.

The existing SDK 10.0.401 and PowerShell 7.6.7/Pester 6.2.0 were used. Restore used locked metadata and the existing local NuGet cache; no dependencies were installed or downloaded. Only Linux x64 was compiled/tested. The native self-contained runtime is 10.0.12; PowerShell's framework runtime is 10.0.13. Restoring declared lock metadata for other RIDs is not validation of those platforms.

## Package inspection

The actual archive and extracted files were inspected: safe paths/member types, membership, all payload hashes/sizes, all source mappings, complete compilation provenance and paired executable/DLL pins. There are 186 tar members (174 regular files, 12 directories), 173 manifest payload entries, 171 source mappings, 100 native input records and 48 credential input records including inherited `native/Directory.Build.props`.

Compared with the older 267-payload/265-mapping package, the fresh build omits 100 redundant documentation/example copies and adds six required root guide/JSON files. No runtime source or script was removed. The full member delta is retained locally. The old receipt remains unchanged; the new credential inventory makes the inherited props input explicit, while that file was already covered by the complete native input inventory.

## Focused results

There are **205 distinct passing cases** in this qualification: 38 new/changed cases and 167 existing cases executed for affected components. Overlapping reruns are not added to that total. This is not a new full-suite run.

| Receipt group | Actual result and boundary |
| --- | --- |
| Admin/refresh source | 152 passed, including existing admin, refresh and grant validation cases; later ARM coverage finishes at 18/18 |
| Unknown API outcome | One targeted corrected case passed: charged unknown outcome prevents reacquisition/reset; 60 unrelated cases not run |
| Selected cohort | 14 passed; path and runner-binding follow-ups passed four and one respectively, overlapping existing cases |
| Runtime pairs | Five synthetic hash-gate cases passed; hybrid pairs refused |
| Actual compiled runtime | 16/16 passed against the new executable and explicitly loaded credential DLL (13 native admin, three native refresh) |
| Extracted package | 35/35 affected cases passed against byte-verified extracted payload and compiled DLL, with no compile fallback; 81 unrelated cases not run |
| Packaging guards | 12/12 passed, including actual historical-package compilation-input refusal; one unavailable older baseline case not run |

The manifest SHA beginning `093` identifies the actual accepted historical fixture used for the refusal test. The unavailable older `0a17` fixture is neither counted as passed nor claimed as reused. Test harnesses contain selected tests/fixtures added alongside a byte-verified extracted payload; these additions are not represented as archive members.

Initial failures and corrections remain in local receipts: omitted-history parsing (product fix); a test directory permission setup failure; an incorrect test assumption that same-plan unknown-outcome refusal must throw; scalar native argument splatting before compilation; and an initial locked restore specifying an incompatible single RID. The final build used typed argument arrays and the original declared lock metadata. A private packaging test launcher also failed before test execution and was corrected. None of these attempts is relabeled as a passing run.

## Review and limits

An independent reviewer accepted exact source `9c02b2af51b1c02cbb0ef62aeac55c15f2caf362` after directly inspecting source, actual archive/extracted payload, original and derivative receipts, build logs and test XML. Findings about provider-relative paths, exact database naming, guide dependencies, runtime pair pins, omitted-history export and historical-package refusal coverage were resolved before acceptance.

The existing frozen collector and refresh journal are reused. ARM proof is restricted to the approved fixed GET `/subscriptions?api-version=2022-12-01` with explicit `user_impersonation`; Graph retains its existing fixed self-profile proof. Additional-scope ceilings are unchanged. A successful ARM status, including an empty visible subscription set, would prove endpoint acceptance only.

New live Graph/ARM assessment, its supervised stop/resume and incremental follow-up are not established by these offline tests. Retained earlier collector safety evidence is historical and separate. Unsafe uncertainty and relevant-change cases use offline evidence rather than tenant mutations. Keep #115/#116 open where acceptance remains incomplete; #113 production publication is a separate milestone. See [the operator flow](administrator-assessment.md).
