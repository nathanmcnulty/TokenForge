#!/usr/bin/env python3
"""Build a public, reproducible app-addability proposal from pinned catalog and evidence."""

from __future__ import annotations

import argparse
import collections
import datetime as dt
import hashlib
import json
import pathlib
import subprocess
import sys
import uuid

PINNED_COMMIT = "a5200c8172f8487ea01cadd5480d3f9f7610a521"
PINNED_PATH = "applications.json"
PINNED_BLOB = "53d3c52efa10287470047158c8d39eeef4fc9b5b"
PINNED_SHA256 = "930413f4bef996dfa2b4dc6257ddabc77896de9a443d0ad693aea47e1510910b"
PINNED_COUNT = 5470
AS_OF_UTC = "2026-11-21"
INITIAL_PENDING_REASON = "No matching Microsoft Graph context was available during preparation; current Graph queries have not run."


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def git_blob_sha1(data: bytes) -> str:
    header = f"blob {len(data)}\0".encode()
    return hashlib.sha1(header + data).hexdigest()


def canonical_app_id(value: object) -> str:
    return str(uuid.UUID(str(value))).lower()


def read_json_bytes(path: pathlib.Path) -> tuple[dict, bytes]:
    raw = path.read_bytes()
    return json.loads(raw), raw


def read_pinned_snapshot(repo: pathlib.Path, snapshot_path: pathlib.Path | None) -> tuple[dict, dict]:
    if snapshot_path:
        document, raw = read_json_bytes(snapshot_path)
        origin = str(snapshot_path)
    else:
        result = subprocess.run(
            ["git", "show", f"{PINNED_COMMIT}:{PINNED_PATH}"],
            cwd=repo,
            check=True,
            stdout=subprocess.PIPE,
        )
        raw = result.stdout
        document = json.loads(raw)
        origin = f"git:{PINNED_COMMIT}:{PINNED_PATH}"
    blob = git_blob_sha1(raw)
    digest = sha256(raw)
    if blob != PINNED_BLOB or digest != PINNED_SHA256:
        raise ValueError("Snapshot bytes do not match the pinned blob and SHA-256.")
    applications = document.get("Applications")
    if not isinstance(applications, dict) or len(applications) != PINNED_COUNT:
        raise ValueError("Pinned snapshot does not contain exactly 5,470 application IDs.")
    ids = [canonical_app_id(key) for key in applications]
    if len(set(ids)) != PINNED_COUNT:
        raise ValueError("Pinned snapshot contains duplicate canonical AppIds.")
    source = {
        "repository": "nathanmcnulty/TokenForge",
        "branch": "discovery-data",
        "commit": PINNED_COMMIT,
        "path": PINNED_PATH,
        "gitBlobSha1": blob,
        "sha256": digest,
        "appIdCount": len(applications),
        "loadedFrom": origin,
    }
    return document, source


def read_capture(path: pathlib.Path, expected_list: str) -> tuple[dict, bytes, list]:
    document, raw = read_json_bytes(path)
    records = document.get(expected_list)
    if not isinstance(records, list):
        raise ValueError(f"{path} has no {expected_list} array.")
    return document, raw, records


def build_history_from_private_sources(
    snapshot_ids: set[str], discovery_path: pathlib.Path, inventory_path: pathlib.Path, attempts_path: pathlib.Path
) -> tuple[dict, dict]:
    discovery_doc, discovery_raw, discovery_rows = read_capture(discovery_path, "Applications")
    inventory_doc, inventory_raw, inventory_rows = read_capture(inventory_path, "Applications")
    attempts_doc, attempts_raw = read_json_bytes(attempts_path)
    attempts_rows = attempts_doc.get("RegistrationAttempts")
    if not isinstance(attempts_rows, list):
        raise ValueError(f"{attempts_path} has no RegistrationAttempts array.")

    discovery_ids = {canonical_app_id(row["AppId"]) for row in discovery_rows if row.get("AppId")}
    inventory_by_id = {
        canonical_app_id(row["AppId"]): row
        for row in inventory_rows
        if row.get("AppId") and canonical_app_id(row["AppId"]) in snapshot_ids
    }
    latest_attempt: dict[str, dict] = {}
    for row in attempts_rows:
        if not row.get("AppId"):
            continue
        app_id = canonical_app_id(row["AppId"])
        if app_id not in snapshot_ids:
            continue
        if app_id not in latest_attempt or str(row.get("AttemptedAt", "")) > str(latest_attempt[app_id].get("AttemptedAt", "")):
            latest_attempt[app_id] = row

    discovery_at = discovery_doc.get("FetchedAt")
    inventory_at = inventory_doc.get("CapturedAt")
    if not discovery_at or not inventory_at:
        raise ValueError("Historical captures must include their UTC capture dates.")

    rows: dict[str, dict] = {}
    for app_id in sorted(snapshot_ids):
        inv = inventory_by_id.get(app_id)
        attempt = latest_attempt.get(app_id)
        item = {
            "AppId": app_id,
            "OctoberDiscovery": {"Seen": app_id in discovery_ids, "CapturedAtUtc": discovery_at},
            "OctoberInventory": {
                "Registration": inv.get("Registration") if inv else None,
                "CapturedAtUtc": inventory_at,
            },
            "OctoberRegistrationAttempt": None,
        }
        if attempt:
            item["OctoberRegistrationAttempt"] = {
                "Outcome": attempt.get("Outcome"),
                "AttemptedAtUtc": attempt.get("AttemptedAt"),
                "HttpStatus": attempt.get("HttpStatus"),
                "SpecificGraphReasonRetained": False,
            }
        rows[app_id] = item

    sources = {
        "octoberDiscovery": {
            "capturedAtUtc": discovery_at,
            "path": discovery_path.name,
            "sha256": sha256(discovery_raw),
            "recordCount": len(discovery_rows),
        },
        "octoberInventory": {
            "capturedAtUtc": inventory_at,
            "path": inventory_path.name,
            "sha256": sha256(inventory_raw),
            "recordCount": len(inventory_rows),
        },
        "octoberRegistrationAttempts": {
            "dateRangeUtc": [
                min((r.get("AttemptedAt") for r in attempts_rows if r.get("AttemptedAt")), default=None),
                max((r.get("AttemptedAt") for r in attempts_rows if r.get("AttemptedAt")), default=None),
            ],
            "path": attempts_path.name,
            "sha256": sha256(attempts_raw),
            "attemptCount": len(attempts_rows),
        },
    }
    return {"sources": sources, "applications": rows}, {"discovery": discovery_doc, "inventory": inventory_doc, "attempts": attempts_doc}


def load_history(args: argparse.Namespace, snapshot_ids: set[str]) -> tuple[dict, dict]:
    if args.historical_evidence:
        evidence, raw = read_json_bytes(args.historical_evidence)
        if evidence.get("snapshot", {}).get("sha256") != PINNED_SHA256:
            raise ValueError("Sanitized historical evidence belongs to a different snapshot.")
        rows = evidence.get("applications")
        if not isinstance(rows, dict) or set(rows) != snapshot_ids:
            raise ValueError("Sanitized historical evidence does not cover the pinned 5,470-ID set exactly.")
        return {"sources": evidence["sources"], "applications": rows}, {"sanitizedHistorySha256": sha256(raw)}
    if not (args.october_discovery and args.october_inventory and args.october_attempts):
        raise ValueError("Provide --historical-evidence or all three October source files.")
    history, raw_docs = build_history_from_private_sources(
        snapshot_ids, args.october_discovery, args.october_inventory, args.october_attempts
    )
    return history, raw_docs


def source_metadata(snapshot_record: dict) -> dict:
    records = snapshot_record.get("Records", {})
    attributes = {}
    if isinstance(records, dict):
        for record in records.values():
            candidate = record.get("Attributes") if isinstance(record, dict) else None
            if isinstance(candidate, dict) and candidate.get("AppId"):
                attributes = candidate
                break
    return {
        "Name": attributes.get("Name") or "",
        "PublishedOwnership": attributes.get("Ownership") or "Unverified",
        "PublishedOwnerTenantId": attributes.get("OwnerTenantId"),
        "Sources": attributes.get("SourceClaims") or [],
        "PublicClient": attributes.get("PublicClient"),
        "Foci": attributes.get("Foci"),
        "RedirectUris": attributes.get("RedirectUris") or [],
        "PreferredRedirectUri": attributes.get("PreferredRedirectUri") or "",
        "Grants": attributes.get("Grants") or [],
        "IsResourceCandidate": bool(attributes.get("IsResourceCandidate")),
        "IdentifierUris": attributes.get("IdentifierUris") or [],
        "MetadataConflicts": attributes.get("MetadataConflicts") or [],
    }


def public_reason(bucket: str, entry: dict | None, blocker_reason: str = INITIAL_PENDING_REASON) -> str:
    if bucket == "Confirmed":
        return "Current exact AppId lookup verified an Application service principal with an external owner."
    if bucket == "CouldntAdd":
        text = str((entry or {}).get("Reason") or "").lower()
        if "single-tenant" in text or "single tenant" in text or "not multi-tenant" in text or "not multi tenant" in text:
            return "Microsoft Graph explicitly stated that this application is single-tenant."
        if "cannot be added" in text or "can't be added" in text or "cannot be instantiated" in text:
            return "Microsoft Graph explicitly stated that this application cannot be added to another tenant."
        return "Microsoft Graph explicitly refused this AppId for an app-specific reason recorded in the private checkpoint."
    if not entry:
        return blocker_reason
    text = str(entry.get("Reason") or "").lower()
    if "throttl" in text or "retry-after" in text:
        return "Graph throttling; pending until the recorded retry delay passes."
    if "permission" in text or "authentication" in text or "context" in text or "account" in text or "tenant" in text:
        return "Graph account, tenant, or permission context needs review; pending."
    if "service error" in text or "transport" in text or "timeout" in text or "timed out" in text:
        return "Graph transport or service error; pending."
    if "specific graph" in text or "historical failure" in text:
        return "Historical failure has no app-specific Graph reason; pending."
    return "Current Graph verification is incomplete or inconclusive; pending."


def public_current_evidence(bucket: str, entry: dict | None) -> dict | None:
    if not entry:
        return None
    result = {
        "Result": entry.get("Result") or ("CouldntAdd" if bucket == "CouldntAdd" else "Pending"),
        "EvidenceSource": entry.get("Source") or "Microsoft Graph exact AppId lookup",
        "ObservedAtUtc": entry.get("UtcDate"),
        "GraphErrorCode": entry.get("GraphErrorCode") or None,
    }
    principal = entry.get("ServicePrincipal")
    if bucket == "Confirmed" and isinstance(principal, dict):
        result["ServicePrincipalType"] = principal.get("servicePrincipalType")
        result["OwnerOutsideTargetTenant"] = None
    return result


def current_checkpoint(
    path: pathlib.Path | None, expected_tenant_id: str | None, expected_account: str | None
) -> tuple[dict[str, dict], dict, str | None]:
    categories: dict[str, dict] = {"Confirmed": {}, "CouldntAdd": {}, "Pending": {}}
    checkpoint_meta = {"createdServicePrincipalCount": 0, "status": "NotStarted"}
    if not path:
        return categories, checkpoint_meta, None
    if not expected_tenant_id or not expected_account:
        raise ValueError("Current checkpoint export requires the expected tenant ID and account for provenance validation.")
    checkpoint, _raw = read_json_bytes(path)
    if checkpoint.get("Format") != "TokenForgeAppAddabilityCheckpoint" or checkpoint.get("SchemaVersion") != 1:
        raise ValueError("Current results checkpoint format is not supported.")
    if checkpoint.get("SnapshotSha256") != PINNED_SHA256:
        raise ValueError("Current results checkpoint does not match the pinned snapshot.")
    if canonical_app_id(checkpoint.get("TenantId")) != canonical_app_id(expected_tenant_id):
        raise ValueError("Current results checkpoint tenant does not match the expected tenant.")
    if str(checkpoint.get("ExpectedAccount", "")).casefold() != expected_account.casefold():
        raise ValueError("Current results checkpoint account does not match the expected account.")
    for bucket in categories:
        entries = checkpoint.get("Results", {}).get(bucket, [])
        if not isinstance(entries, list):
            raise ValueError(f"Current checkpoint {bucket} list is invalid.")
        for entry in entries:
            categories[bucket][canonical_app_id(entry["AppId"])] = entry
    checkpoint_meta = {
        "status": checkpoint.get("Status"),
        "queueCount": len(checkpoint.get("Queue", [])),
        "createdServicePrincipalCount": len(checkpoint.get("CreatedServicePrincipals", [])),
    }
    return categories, checkpoint_meta, checkpoint.get("TenantId")


def historical_positive_events(history_row: dict) -> list[dict]:
    events = []
    inventory = history_row.get("OctoberInventory", {})
    if inventory.get("Registration") == "Present":
        events.append(
            {
                "Source": "October tenant inventory",
                "ObservedAtUtc": inventory.get("CapturedAtUtc"),
                "Result": "PresentWithVerifiedMicrosoftOwner",
            }
        )
    attempt = history_row.get("OctoberRegistrationAttempt")
    if isinstance(attempt, dict) and attempt.get("Outcome") == "Created":
        events.append(
            {
                "Source": "October service-principal registration attempt",
                "ObservedAtUtc": attempt.get("AttemptedAtUtc"),
                "Result": "CreatedWithVerifiedMicrosoftOwner",
            }
        )
    return events


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=pathlib.Path, default=pathlib.Path(__file__).resolve().parents[1])
    parser.add_argument("--snapshot-path", type=pathlib.Path)
    parser.add_argument("--historical-evidence", type=pathlib.Path)
    parser.add_argument("--october-discovery", type=pathlib.Path)
    parser.add_argument("--october-inventory", type=pathlib.Path)
    parser.add_argument("--october-attempts", type=pathlib.Path)
    parser.add_argument("--current-checkpoint", type=pathlib.Path)
    parser.add_argument("--expected-current-tenant")
    parser.add_argument("--expected-current-account")
    parser.add_argument("--blocker-reason", default=INITIAL_PENDING_REASON)
    parser.add_argument("--output-dir", type=pathlib.Path, required=True)
    parser.add_argument("--write-history-evidence", action="store_true")
    args = parser.parse_args()

    repo = args.repo.resolve()
    snapshot, source = read_pinned_snapshot(repo, args.snapshot_path)
    snapshot_apps = snapshot["Applications"]
    canonical = {canonical_app_id(key): value for key, value in snapshot_apps.items()}
    snapshot_ids = set(canonical)
    history, raw_history = load_history(args, snapshot_ids)
    current, checkpoint_meta, private_target_tenant = current_checkpoint(
        args.current_checkpoint, args.expected_current_tenant, args.expected_current_account
    )

    output_dir = args.output_dir.resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    hist_document = {
        "schemaVersion": 1,
        "snapshot": {k: v for k, v in source.items() if k != "loadedFrom"},
        "sources": history["sources"],
        "applications": history["applications"],
    }
    if args.write_history_evidence or not args.historical_evidence:
        (output_dir / "historical-evidence.json").write_text(
            json.dumps(hist_document, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )

    catalog_rows = []
    pending = []
    confirmed = []
    couldnt_add = []
    existing_evidence = []
    fresh_creations = []
    historical_counts = collections.Counter()
    for app_id in sorted(snapshot_ids):
        metadata = source_metadata(canonical[app_id])
        hist = history["applications"].get(app_id) or {"AppId": app_id}
        if hist.get("OctoberDiscovery", {}).get("Seen"):
            historical_counts["discoverySeen"] += 1
        inventory_status = hist.get("OctoberInventory", {}).get("Registration")
        if inventory_status:
            historical_counts[f"inventory{inventory_status}"] += 1
        attempt = hist.get("OctoberRegistrationAttempt")
        if isinstance(attempt, dict) and attempt.get("Outcome"):
            historical_counts[f"latestAttempt{attempt['Outcome']}"] += 1
        events = historical_positive_events(hist)
        if events:
            existing_evidence.append({"AppId": app_id, "Name": metadata["Name"], "Evidence": events})

        bucket = next((b for b in ("Confirmed", "CouldntAdd", "Pending") if app_id in current[b]), "Pending")
        entry = current[bucket].get(app_id)
        current_record = public_current_evidence(bucket, entry)
        if bucket == "Confirmed" and current_record:
            # The private result includes ownerOrganizationId; compare it to the private run tenant before export.
            principal = entry.get("ServicePrincipal") or {}
            current_record["OwnerOutsideTargetTenant"] = bool(
                principal.get("appOwnerOrganizationId")
                and private_target_tenant
                and principal.get("appOwnerOrganizationId", "").lower() != private_target_tenant.lower()
            )
        row = {
            "AppId": app_id,
            **metadata,
            "CurrentDisposition": bucket,
            "CurrentReason": public_reason(bucket, entry, args.blocker_reason),
            "CurrentEvidence": current_record,
            "HistoricalEvidence": hist,
        }
        catalog_rows.append(row)
        summary_row = {"AppId": app_id, "Name": metadata["Name"], "Reason": row["CurrentReason"], "Evidence": row["CurrentEvidence"], "HistoricalEvidence": hist}
        if bucket == "Confirmed":
            confirmed.append(summary_row)
            if current_record and current_record.get("Result") == "NewlyAdded":
                fresh_creations.append(summary_row)
        elif bucket == "CouldntAdd":
            couldnt_add.append(summary_row)
        else:
            pending.append(summary_row)

    existing_by_id = {row["AppId"]: row for row in existing_evidence}
    for row in confirmed:
        evidence = row.get("Evidence") or {}
        result = evidence.get("Result")
        if result in ("AlreadyPresent", "AlreadyPresentAfterReconciliation"):
            app_id = row["AppId"]
            target = existing_by_id.get(app_id)
            if target is None:
                target = {"AppId": app_id, "Name": row.get("Name", ""), "Evidence": []}
                existing_by_id[app_id] = target
            target["Evidence"].append(
                {
                    "Source": evidence.get("EvidenceSource") or "Current Microsoft Graph exact AppId lookup",
                    "ObservedAtUtc": evidence.get("ObservedAtUtc"),
                    "Result": result,
                    "ServicePrincipalType": evidence.get("ServicePrincipalType"),
                    "OwnerOutsideTargetTenant": evidence.get("OwnerOutsideTargetTenant"),
                }
            )
    existing_evidence = [existing_by_id[app_id] for app_id in sorted(existing_by_id)]

    historical_status_counts = collections.Counter(
        row.get("OctoberInventory", {}).get("Registration") or "NoExactMatch"
        for row in history["applications"].values()
    )
    attempt_counts = collections.Counter(
        (row.get("OctoberRegistrationAttempt") or {}).get("Outcome") or "NoAttempt"
        for row in history["applications"].values()
    )
    summary = {
        "snapshotAppIdCount": len(catalog_rows),
        "current": {
            "confirmed": len(confirmed),
            "couldntAdd": len(couldnt_add),
            "pending": len(pending),
            "currentResultsRecordedCount": sum(len(entries) for entries in current.values()),
        },
        "historical": {
            "octoberDiscoveryMatches": sum(1 for row in history["applications"].values() if row["OctoberDiscovery"]["Seen"]),
            "octoberInventoryStatusCounts": dict(sorted(historical_status_counts.items())),
            "octoberLatestRegistrationOutcomeCounts": dict(sorted(attempt_counts.items())),
            "distinctAppsWithHistoricalPositiveCrossTenantEvidence": len(existing_evidence),
            "historicalPositiveEvidenceEvents": sum(len(row["Evidence"]) for row in existing_evidence),
        },
        "currentCheckpoint": checkpoint_meta,
    }
    manifest = {
        "schemaVersion": 1,
        "generatedForUtcDate": AS_OF_UTC,
        "classificationSemantics": {
            "currentConfirmed": "Only a current exact AppId Graph lookup or successful create followed by exact verification.",
            "historicalPositiveEvidence": "Dated October observations kept separate from current results.",
            "couldntAdd": "Only an explicit app-specific refusal; historical failures without a specific reason remain pending.",
            "pending": "Current outcome is unverified, inconclusive, throttled, permission/session blocked, or historically failed without a specific reason.",
        },
        "sourceSnapshot": {k: v for k, v in source.items() if k != "loadedFrom"},
        "historicalSources": history["sources"],
        "currentCheckpoint": checkpoint_meta,
        "summary": summary,
    }
    proposal = {
        "schemaVersion": 1,
        "generatedForUtcDate": AS_OF_UTC,
        "sourceSnapshot": {k: v for k, v in source.items() if k != "loadedFrom"},
        "historicalSources": history["sources"],
        "summary": summary,
        "applications": catalog_rows,
    }
    outputs = {
        "manifest.json": manifest,
        "catalog-proposal.json": proposal,
        "confirmed.json": confirmed,
        "couldnt-add.json": couldnt_add,
        "pending.json": pending,
        "existing-cross-tenant-evidence.json": existing_evidence,
        "fresh-successful-creations.json": fresh_creations,
    }
    for name, value in outputs.items():
        (output_dir / name).write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"App-addability export failed: {exc}", file=sys.stderr)
        raise SystemExit(2)
