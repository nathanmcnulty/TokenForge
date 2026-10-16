# Incremental deep evidence queue

New automatic Deep weekly recipes select at most `DeepMaxApplications` (1–100)
public callback candidates. `TokenForgeCiEvidenceQueue.ps1` is an offline,
credential-free planner; it does not authenticate, fetch tokens, or enable a
scheduler. The Prepare bundle contains `evidence-queue.json` with the UTC
`EvaluatedAt`, evidence type, reasons, priorities, observed and expiry timestamps,
and pending/deferred counts. Explicit targeted validation remains available.

Priority is changed public hints, missing evidence, then stale evidence. Ties
use oldest observation, oldest selection week (never selected first), and AppId.
Only a validated completed Deep receipt covering both Graph and Azure management
resources establishes `CompletedDeepAssessment`. Failed/pending work, selection
history, shallow assessment, and anonymous token observations cannot fill this
evidence requirement. Assessment is not proof of token issuance or universal
access. Freshness defaults to seven days; the exact expiry instant is stale.
Future observations, observations before recipe creation, and completed receipts
without an attempt fail closed.

The planner conservatively uses the previous frozen Deep state's receipts.
Evidence absent from that retained state is missing, even if an older report once
mentioned an assessment. It does not infer per-application evidence from aggregate
archives. Fresh candidates are excluded; if all candidates are fresh, Prepare
emits `has_work=False` and `has_plan=False`, and preserves the previous state
without creating an empty recipe. Workflow publication and recipe uploads skip
that no-plan outcome; existing completed recipes still emit `has_plan=True`.
The frozen selection is retained as `selection-deep.json` next to weekly state,
with its plan ID, canonical selected IDs, and complete queue policy and reasons.
The state's optional `EvidenceSelectionSha256` binds the full snapshot. Prepare,
worker, and public-data validation reject missing or corrupt snapshots for marked
states; legacy states without the marker remain supported. Resume copies the
original snapshot unchanged into the worker bundle. An unbound public snapshot
is rejected. The queue is not another mutable checkpoint.

Selection runs only when creating a new weekly recipe. Existing current-week
recipes keep their exact membership, resources, hash, and checkpoints regardless
of newer public hints or freshness. Workers resume their frozen plans. The
existing weekly rollover policy is unchanged. The recipe schema and plan hash
stay unchanged; native report readers accept the optional state digest marker.
Live authenticated execution and publication remain separate,
explicitly authorized operations; offline tests establish planning behavior only.
