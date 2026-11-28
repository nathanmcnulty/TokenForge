"""A1 acceptance against the pinned Git blobs and an isolated synthetic snapshot."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

PIN = "ec3d72d75241c69bb9ca46528b32a1e7fd2a0b62"
FILES = {
    "applications.json": ("TokenForgeApplicationMetadata", 2),
    "applications.non-verified.json": ("TokenForgeNonVerifiedApplications", 1),
    "applications.verified-evidence.json": ("TokenForgeVerifiedApplicationEvidence", 1),
}
APP = "12345678-0000-0000-0000-000000000001"
RESOURCE = "12345678-0000-0000-0000-000000000002"
OTHER = "12345678-0000-0000-0000-000000000003"


def run(snapshot, operation, *options, revision=PIN):
    return subprocess.check_output([
        *sys.argv[1:], "catalog", operation, "--snapshot", str(snapshot),
        "--revision", revision, *options,
    ])


def search(snapshot, *options):
    return json.loads(run(snapshot, "search", *options))


def fixture(snapshot, *claim_grants, owner_outside=True):
    claims = [
        {"SourceName": f"fixture-{i}", "Name": f"Sample {i}", "Grants": [
            {"ResourceId": resource, "Scopes": scopes} for resource, scopes in grants
        ]} for i, grants in enumerate(claim_grants)
    ]
    record = {
        "LastSeenAt": "2026-11-22T12:00:00Z",
        "Attributes": {"SourceClaims": claims,
                       "MetadataConflicts": [{"Field": "Name", "Values": ["Sample 0", "Sample 1"]}]},
    }
    evidence = {
        "EvidenceSource": "fixture exact lookup",
        "ObservedAtUtc": "2026-11-22",
    }
    if owner_outside is not ...:
        evidence["OwnerOutsideTargetTenant"] = owner_outside
    for (file, (kind, version)), applications in zip(FILES.items(), [
        {APP: {"AppId": APP, "Records": {"Discovery///": record}}},
        {},
        {APP: evidence},
    ]):
        (snapshot / file).write_text(json.dumps({
            "Format": kind, "SchemaVersion": version, "Applications": applications,
        }), encoding="utf-8")


def check():
    git_env = dict(os.environ, GIT_NO_LAZY_FETCH="1", GIT_ALLOW_PROTOCOL="")
    with tempfile.TemporaryDirectory() as directory:
        snapshot = Path(directory)
        for file in FILES:
            data = subprocess.check_output(
                ["git", "--no-replace-objects", "show", f"{PIN}:{file}"], env=git_env)
            (snapshot / file).write_bytes(data)

        expected = json.loads((snapshot / "applications.verified-evidence.json").read_bytes())["Applications"]
        non_verified_ids = json.loads((snapshot / "applications.non-verified.json").read_bytes())["Applications"]
        for count, options in [(2066, []), (5500, ["--include-non-verified"])]:
            raw = run(snapshot, "search", *options)
            result = json.loads(raw)
            assert raw == run(snapshot, "search", *options)
            assert result == json.loads(json.dumps(result))
            results = result["Applications"]
            ids = [row["AppId"] for row in results]
            assert result["CatalogRevision"] == PIN
            assert result["Count"] == len(ids) == len(set(ids)) == count
            assert ids == sorted(ids)
            verified = [row for row in results if row["Partition"] == "Verified"]
            assert {row["AppId"]: row["VerificationEvidence"] for row in verified} == expected
            other = {row["AppId"] for row in results if row["Partition"] == "NonVerified"}
            assert other == (set(non_verified_ids) if options else set())
            assert all(row["VerificationEvidence"]["OwnerOutsideTargetTenant"] is True
                       and row["VerificationEvidence"]["ObservedAtUtc"]
                       and row["VerificationEvidence"]["EvidenceSource"]
                       and "SignInAudience" in row["UnknownFields"] for row in verified)

        verified_id = "00000001-0000-0000-c000-000000000000"
        detail = json.loads(run(snapshot, "get", "--id", verified_id.upper()))
        assert detail == search(snapshot, "--id", verified_id)
        assert detail["Count"] == 1
        non_verified = "00000000-0000-0000-0000-000000000001"
        assert json.loads(run(snapshot, "get", "--id", non_verified))["Count"] == 0
        detail = json.loads(run(snapshot, "get", "--id", non_verified, "--include-non-verified"))
        assert detail["Applications"][0]["Partition"] == "NonVerified"
        assert detail["Applications"][0]["VerificationEvidence"]["Result"] == "ExplicitAppRejection"
        assert search(snapshot, "--include-non-verified", "--tenancy-evidence", "unknown")["Count"] == 3434
        assert search(snapshot, "--tenancy-evidence", "owner-outside-target-tenant")["Count"] == 2066

        negative_tenancy = ["--tenancy-evidence", "owner-not-outside-target-tenant"]
        assert search(snapshot, "--include-non-verified", *negative_tenancy)["Count"] == 0

        fixture(snapshot, owner_outside=False)
        negative, = search(snapshot, *negative_tenancy)["Applications"]
        assert negative["VerificationEvidence"]["OwnerOutsideTargetTenant"] is False
        assert negative["UnknownFields"] == ["SignInAudience"]
        assert search(snapshot, "--tenancy-evidence", "owner-outside-target-tenant")["Count"] == 0
        assert search(snapshot, "--tenancy-evidence", "unknown")["Count"] == 0

        for unknown_value in (None, ...):
            fixture(snapshot, owner_outside=unknown_value)
            unknown, = search(snapshot, "--tenancy-evidence", "unknown")["Applications"]
            assert "OwnerOutsideTargetTenant" in unknown["UnknownFields"]
            assert search(snapshot, *negative_tenancy)["Count"] == 0

        filters = ["--resource", RESOURCE, "--scope", "Read", "--scope", "Write"]
        fixture(snapshot, [(RESOURCE, ["Read"])], [(RESOURCE, ["Write"])])
        assert search(snapshot, *filters)["Count"] == 0  # Two claims, same resource.
        fixture(snapshot, [(RESOURCE, ["Read"]), (RESOURCE, ["Write"])])
        assert search(snapshot, *filters)["Count"] == 0  # Two rows, same claim and resource.
        fixture(snapshot, [(RESOURCE, ["Read"]), (OTHER, ["Write"])])
        assert search(snapshot, "--scope", "Read", "--scope", "Write")["Count"] == 0
        assert search(snapshot, *filters)["Count"] == 0

        fixture(snapshot, [(RESOURCE, ["Read", "Write"]), (OTHER, ["Read"])], [(RESOURCE, ["Read"])])
        result = search(snapshot, *filters, "--name", "sAMPLE 0",
                        "--tenancy-evidence", "owner-outside-target-tenant")
        assert result["Count"] == 1
        row = result["Applications"][0]
        assert row["VerificationEvidence"]["EvidenceSource"] == "fixture exact lookup"
        assert row["VerificationEvidence"]["ObservedAtUtc"] == "2026-11-22"
        assert "SignInAudience" in row["UnknownFields"]
        metadata, = row["MatchingEvidence"]
        assert metadata["ObservedAtUtc"] == "2026-11-22T12:00:00Z"
        assert metadata["MetadataConflicts"] == [{"Field": "Name", "Values": ["Sample 0", "Sample 1"]}]
        claim, = metadata["Claims"]
        assert claim["Source"] == "fixture-0"
        assert claim["MatchingGrants"] == [{"ResourceId": RESOURCE, "Scopes": ["Read", "Write"]}]
        assert search(snapshot, *filters, "--name", "Sample 1")["Count"] == 0
        assert search(snapshot, "--scope", "read")["Count"] == 0
        assert search(snapshot, "--name", "no such name")["Applications"] == []
        assert search(snapshot, "--id", OTHER)["Count"] == 0
        assert search(snapshot, "--tenancy-evidence", "unknown")["Count"] == 0
    print("A1 passed: 2066 verified, 5500 total, 3434 unknown tenancy; exact detail, provenance, "
          "explicit false vs. missing/null tenancy, byte-stable JSON round-trip, audience, "
          "conflicts, no-match and scope isolation.")


if __name__ == "__main__":
    check()
