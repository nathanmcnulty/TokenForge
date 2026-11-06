# Current-package public metadata trial: approval proposal

Status: **approved and executed** at source
`6ab34622928b500f068984f75153b17c5fc2a9d8`, run `42266672386`, attempt 1.
The code-only prerelease was published with the exact approved digest. The single
job succeeded; three source GETs took 34.453 seconds, producing a valid incomplete
exchange. Artifact `13526823949` (1467 bytes, SHA256
`309876960dc29a1698b9117bb1257ee5648298fbffe8db421c061547c6cd3c64`)
was transferred and imported through the normal receiver. Local repeat import
left SQLite bytes unchanged; real name/ID lookup each returned zero. MicrosoftApps
remained Invalid; a complete fresh catalog and its precise hosted refusal cause
are not proven. Raw inputs/receipts remain private and the prior 69 scoped checks
were reused. The completed trial job is now quarantined with `if: false`.

The original approved proposal follows for traceability. It is not permission for
another publication or dispatch. Main, settings and permissions were unchanged;
PR #126 remains unmerged and #113/#115/#116 remain open.

## Exact inputs and destination

- Repository: public `nathanmcnulty/TokenForge`, ID `1402673320`.
- Registered workflow: `395612174`, `.github/workflows/public-metadata-health.yml`.
- Trial branch: `codex/public-health-current-trial`; the exact reviewed full commit
  is supplied in the approval request. Publish and dispatch only that commit.
- Package source: `1d6617e6f724fc27fc6e7e64b3ea3dbd407b7168`.
- Existing local code archive: `TokenForge-public-health-linux-x64.tar.gz`,
  33,936,560 bytes, SHA256
  `3e396f3486b9671ba5a71b6afd53a0e7a869fcb466e428beea30df596923446f`.
  It has 268 members, 267 payloads and 265 verified source mappings; it contains
  source and accepted binaries, never local catalogs, source responses or receipts.
- Proposed new **public prerelease**: tag `public-health-e2e-1d6617e`, targeting
  the package source above, containing only that one archive. Do not replace any
  existing release/tag/asset or mark it latest. Abort on a conflicting existing
  tag, release or asset. No runtime package publication or compilation is needed.
- CLI compilation source remains `0eb5e60fe0ecbfc7312e681dc9ce60ffdd5906ea`;
  credential compilation source remains `c32cd7b27e98fdeac9f376807999205d99133a38`.
  All 100 CLI and 47 credential input blobs were matched, and the binaries remain
  pinned independently by the existing runtime initializer.
- Reuse the already published PowerShell 7.6.7 Linux x64 runtime from
  `public-health-offline-20261024`, SHA256
  `3da36d92808db25aa2466422b1b765da792adc159d890512fbae852e2b495d3b`.

The trial changes only the manual job's exact branch/repository/attempt guard,
the code-package URL/hash/source binding, and a public package-source log field.
Every executed module/health script must match checkout bytes before collection.
Package source and workflow/run source are distinct and recorded separately;
the workflow-only overlay is not relabeled as a new compiled package.

## Approved operation, if Nathan accepts

1. Recheck exact source/package identities and existing workflow state. Use the
   existing GitHub sign-in for the expressly approved release/dispatch/read calls;
   do not authenticate anew or change access. Normal-push the reviewed trial
   source branch. Leave PR #126 and main unmerged.
2. Publish the one new public code-package prerelease/asset described above,
   verifying the uploaded asset digest/size. Preserve all historical assets.
3. Dispatch **one** manual attempt on the exact trial ref. Observe that run ID;
   never redispatch because a response or observation times out. The job requires
   attempt 1 and refuses all other refs, events and repositories.
4. After successful output upload, independently select the actual run ID/source/
   attempt and named `tokenforge-public-health` artifact. Transfer through the
   normal receiver using the explicitly supplied existing read credential if
   needed, validate all three members, import into the existing private health
   workstation, repeat the retained local import, and inspect status/lookup.
   No credential is forwarded to the artifact-service redirect.
5. Independently review actual retained artifact/import evidence and publish only
   a sanitized source/result summary on PR #126. Leave #113/#115/#116 open.

## Bounds, outputs and stop conditions

One Ubuntu 24.04 Linux x64 job, no matrix, ten-minute outer timeout. Its sole
permission is `contents: read`. Existing action pins, ordinary upload-artifact,
runtime/source guards and public-only validation remain. No Entra credentials,
OIDC signing, tenant APIs, collection plans, permissions or protected branches
are involved. No package manager, binary rebuild, fallback or scheduler is added.

Runtime and package downloads each have a 60-second/100,663,296-byte ceiling and
at most three HTTPS redirects; both archive hashes are checked before execution.
Collection has a 480-second cooperative ceiling, at most six fixed-source HTTPS
GETs (at most two per source) and at most 8 MiB per source. Its only three URLs
are the existing ROADtools, MicrosoftApps and resources endpoints. No schema
refusal is retried. The ten-minute job is the final stop for synchronous work.

Only `manifest.json`, `health.json` and `metadata.json` are uploaded, with 14-day
retention. Package/source/runtime identifiers, aggregate counts and sanitized
status may appear in the public job log. Raw source responses, tenant/account
data, local SQLite, private receipts, tokens and capability URLs stay private.
MicrosoftApps may still be invalid: record incomplete status and original dates;
do not trim/drop records or present successful upload as a complete catalog.

Named-run transfer has its existing four-GET/180-second ceiling, one attempt and
no retries. Local repeat import performs no network request or recollection.
Release/dispatch operations are one prerelease, one code-asset upload and one
dispatch, followed by bounded observation of that same run; they are not hidden
inside the receiver's four-request count. Observe at most 24 times, approximately
30 seconds apart, with a hard wall-clock cutoff twelve minutes after dispatch
acknowledgement, including queue time. Stop earlier on a terminal result or the
observation-count limit. If still nonterminal at either limit, cancel the named
run once and make at most one additional status read to confirm cancellation;
never redispatch. Stop on an identity/digest mismatch,
unexpected access requirement, unapproved output, ambiguity, exhausted bound or
failed job. Cancel the named run if needed; preserve partial local evidence.
Do not retry publication, dispatch or transfer without a new decision.

No repository Actions setting, old credentialed workflow, default-branch job
guard, permission/protection, schedule, issue state or merge is changed. The
write-capable synthetic publication experiment remains quarantined. A failed or
incomplete trial is reported accurately and never converted into broad acceptance.
