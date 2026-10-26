# Goal 3 offline acceptance

Goal 3 is **offline-ready** at source `8b989dc1e22abfa7383f966fb425eecaffea91f1` on `codex/goal3-admin-workflows`. This validates synthetic supported workflows and saved evidence; it is not live or production completion. Goal 4 remains untouched.

## Exact revisions and package

- Roadmap handoff: `19470aeba7a949e4204e4ecf5586a6ffb3171c69` (preserved tag).
- Reviewed Goal 2 parent receipt: `90528b0d3d5e446f1c6faed03085fa2b715574c5`.
- Pester 6.2.0 migration: `63a782b4e54d84c0a947e78a3d6456d919748f9d`; historical receipts keep their actual versions.
- Independent #118 head: `2153779f7a1d5748dc14046f9d60f3ce2fa18837`, reconciled without merging.
- Package: `.cache/goal3/package/linux-x64`, version 0.48.0; 146 payload files plus manifest; all 83 module sources byte-match committed blobs.
- Manifest SHA-256: `717327dc14da5bfc804922b449f959f1f59092bca1d8a23659653ead80ed5a72`.
- Executable SHA-256: `dc646281b6fbcde3d2b57e85cdb6540fa54d6e16136218b1518083425ae0e41b`.
- Credential DLL SHA-256: `299e42298d26b9be4f97733e79a7ace391eeb9f01f458777448dc356903f9be4`.
- Archive SHA-256: `938670e14bb5cc9421ec2e36bf272219f3c05a28388a9665a462ca871add6913`.
- Native-input aggregate SHA-256: `c8c732d5af1b59504fcc3a77056bcb72f1c48583f268fb3e10bb604099aa6c91`.

Changed source was built locally with approved SDK 10.0.401, PowerShell 7.6.7 and locked cached dependencies with all NuGet feeds cleared. No dependency installation was needed. Independent review verified every package/archive hash, complete membership, source/build/validation inputs and bundled workflow documentation. All seven workflow files remain unchanged and manual-only.

## Linux validation

| Check | Passed | Failed | Skipped |
| --- | ---: | ---: | ---: |
| Focused `Admin` runner, Pester 6.2.0 |76|0|0|
| Full actual `scripts/Test-TokenForge.ps1` entry point, Pester 6.2.0 |1117|0|4|
| Existing native workflow selection, derived from full run |340|0|3|
| Native core harness |1086|0|0|

The full suite ran 1121 cases across 68 files in 489.97 seconds with zero failed containers. The four skips remain platform-specific Windows ACL/macOS tests; native prerequisites were present. Counts overlap: focused and workflow selections are subsets, not additional unique coverage. No Windows, macOS or other architecture was compiled or tested. The unchanged native selection was reconciled from the full run rather than rerun for another green result.

## Requirement audit

- **Explain exact request — passed offline:** Approved/declared clients, published callback fingerprints/classes, source hashes/conflicts/age and same-resource/all-scope annotations, visible subject-bound grants, anonymous/private breadth separation, exact context and role/license prerequisites; uncertainty retained.
- **Acquire without broadening authorization — passed offline:** Separate opt-in format, explicit approved bootstrap/final clients, explicit scopes, silent PKCE only, no alternate request after denial, independent zero-default ceilings, current-account check, cooperative total deadline and freshness at completion; optional fixed separately selected Graph GET.
- **Check declared tools — passed offline:** Strict versioned named requirements; four dated statuses and shared exit codes; no arbitrary-script inference or credential display.
- **Prepare report — passed offline:** Recomputed Goal 2 typed changes mapped to tools, including collection-level visibility loss; caller-supplied source/package and input hashes; max 128 entries / 1 MiB with omission counts; private disclosure and no sending.
- **End-to-end examples — passed offline:** Synthetic acquisition to typed snapshot to health success/API 403; no route; bootstrap/final/response excess; unknown/expired/unsatisfied prerequisites and contradictory saved scope evidence; deadline/expiry; typed scope/grant changes and bounded packet.
- **Consumer agreement — passed offline:** Actual Linux native and PowerShell explanation/health JSON equality and exit 0/2/3/4; invalid 1; evidence/packet equality; no-cookie and blocked preflight; unsafe file/argument/credential rejection with no PowerShell on native PATH.
- **Reconcile dependencies — passed offline:** Stacked on reviewed Goal 2 receipt 90528b0; #118 pinned 2153779f7a1d5748dc14046f9d60f3ce2fa18837, unmerged; useful public/anonymous/source contracts reused without private authorization claims.
- **Local reviewed checkpoint and gates — passed offline:** Independent static review and separate package/source/archive integrity review passed; focused Admin, native core and full Linux suite passed; Actions unchanged, no auth/tenant changes/publication/PR/merge.

Independent static review found the evidence-bridge, API-context, freshness, historical report and visibility mapping gaps listed in the structured receipt. Fixes and regression fixtures passed; final review found no outstanding material finding. Separate independent package review passed.

## Remaining limits and live authorization

No remaining offline gate blocker. Only supported silent PKCE native/SPA routes and the optional fixed GraphMeV1 GET are implemented. Unsupported routes stop. Metadata-only facades dispose tokens; trusted in-process consumers must use the owned disposable result. Token inspection is diagnostic, not JWT signature verification; saved receipts are not independent service attestations. Packet producer pins are caller-supplied. A packet is private review material and does not establish root cause or authorize communication.

A future live canary requires separate approval for the exact account, approved bootstrap and final client/callback, Graph User.Read, existing-session handling, and optional GraphMeV1 GET. Scope: one bootstrap plus one final issuance, no retry/alternate route, zero additional-API-scope ceilings, a cooperative 180-second deadline and existing bounded transport/redirect caps. Authentication needs separate approval. No tenant permission change or publication is included. This turn performed no authentication, live collection, tenant mutation, hosted compute, publication, push, PR or merge.

See [workflow usage and executable examples](goal3-admin-workflows.md) and [structured acceptance receipt](goal3-validation.json). Detailed logs and package/archive artifacts remain local under `.cache/goal3/`.
