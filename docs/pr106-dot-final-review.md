# PR 106: final pre-merge review for Dot

Prepared on 2026-10-26 for [PR #106](https://github.com/nathanmcnulty/TokenForge/pull/106). Review branch `dot/upgrade-dotnet10-lts-20261015`; do not merge. Nathan authorized pushing the reviewed source and opening the PR for review. Final approval by Dot is pending. No hosted compute, authentication, live collection, package publication or operational activation is authorized by this handoff.

## Exact checkpoints and scope

- Runtime implementation tested and independently reviewed: `58203ecdcee47c4bdaaef0801d0b496d22daa35f`.
- Prior published acceptance checkpoint: `ccc14d843f53a35d5f15e69a986467f0b7381ce3`.
- Original separately reviewed walkthrough: `113b6c1c56608a9229d6b746a4018f433fbce9a7`, parent `cbea33eca2dfde24f0c92b0385784876510e4ece`.
- Local cherry-pick: `911156e2175be78882a132611d4836214fd80a72`.
- Final walkthrough replay and independent evidence review checkpoint: `7a0417dc17517880156f1dff26e1223b5c4210d5`.
- The containing checkpoint adds this handoff and updates the current handoff pointer only. Use its immutable commit from the final response as the complete review head.

Above `ccc14d8`, the functional additions are limited to `docs/walkthroughs/offline-admin.md` and `examples/offline-admin/`: seven synthetic scenarios exercised through 21 native `admin explain/check/packet` commands. No runtime, workflow or dependency changes were added in this final supplement. The earlier runtime integration preserves main `4c9865185977033e110e8eaaf71fb8f649ec18f2`, prior PR draft `b35461a6aeeb8f614f9d3592e0890af10a957843` and owning checkpoint `9f6b4f2fea2e7afb9b80dfb14a707a47ff9ed0c7`.

## Evidence to inspect

Start with [runtime acceptance](runtime-baseline-validation.md), [exact runtime/package receipt](runtime-baseline-validation.json) and [supported baseline and exceptions](runtime-baseline.md). Then read [the offline administrator walkthrough](walkthroughs/offline-admin.md), [actual replay receipt](../examples/offline-admin/validation.json), [expected outcomes](../examples/offline-admin/expected.json) and [independent review and limits](../examples/offline-admin/review.md).

Prior completed Linux offline acceptance (reused, not rerun for documentation): full Pester **1663 passed / 0 failed / 4 platform skips**, native core **1157 passed**, Sealer **224/0/0**, extracted-package operator walkthrough **33 checks**. Parser:190 files/0 errors. Analyzer:9 unchanged baseline findings/0 new. Existing SDK10.0.401, PowerShell7.6.7 and Pester6.2.0 were used; no dependencies were installed. Earlier failures and interrupted attempts are disclosed in the runtime receipt.

The final administrator replay passed **21/21** against this exact existing Linux package:

| Identity | Value |
| --- | --- |
| Package source | `58203ecdcee47c4bdaaef0801d0b496d22daa35f` |
| Native compilation source | `c32cd7b27e98fdeac9f376807999205d99133a38` |
| Archive SHA256 | `975a8407cc0e7c90939fc630f48b7da2b92947ee2c8d11435944cc1c15e5ea7d` |
| Manifest SHA256 | `8c550f08b5632f13a48a07558574370bd4375794fe09b3fe9120d72de3efe0a7` |
| Executable SHA256 | `42773ca3e048d5d29dd3edf488ca33ace5116d47afdd4513fa8df95b24a3047e` |
| Credential DLL SHA256 | `a96664feb04f767cd48360a706292e2577e36472a1b27ac282c6e67899fa1a52` |

Preflight verified complete staged membership, no symlinks, archive/manifest identity, all166 payload hashes/sizes, all100 native build inputs and87 packaged module source files. The source pin names the reviewed package source, not the later documentation commit. The replay used `unshare -Urn`, `env -i`, private scratch/bundle directories, 0700 run directories and0600 files. All75 retained run receipts have recorded hashes. The first attempt failed during bundle startup because the clean environment lacked a writable extraction path; its evidence remains intact. A new output directory with an explicit private extraction path passed. No runtime defect was found. Optimized Python mode was also verified to fail before native execution.

Raw receipts and packages remain private and local at the absolute paths recorded in `validation.json`; only sanitized source, hashes and summaries are pushed. Dot can inspect committed receipts remotely, but must not claim an independent raw-byte or execution check without access to those local artifacts. Independent source/evidence review verified the retained results without rerunning producer suites. Its two guide findings (original/integrated commit parentage and host scratch writes) were corrected and rechecked; no actionable findings remained.

## Requested final decision

Review the complete PR, using the exact head, and return either approval for Nathan to authorize merge or focused findings with file/line references. In particular verify:

1. Runtime/dependency migration retains newer owning work, preserves lock versions/content hashes/RIDs and states deliberate SDK roll-forward and deferred Goal6 exceptions accurately.
2. Exact compiled-source/package overlay provenance supports reused validation; full-suite failures/skips and independent review limits are disclosed.
3. The walkthrough preserves uncertainty and distinguishes observed synthetic issuance from authorization/API assurance; its expected outcomes were not weakened to obtain passing results.
4. Publication and activation boundaries remain intact. No workflow dispatch, automatic trigger, credentials, artifact sync/import or package release is part of this handoff.

No merge or automatic merge is authorized. The walkthrough does not itself close #98 or #106. The original Goal6 activation and MicrosoftApps malformed-ID blocker remain deferred; merging this runtime/docs PR must not be represented as live/production completion.
