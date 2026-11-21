import importlib.util
import json
import pathlib
import unittest
from unittest import mock


SCRIPT = pathlib.Path(__file__).resolve().parents[1] / "scripts" / "Export-TokenForgeAppAddabilityProposal.py"
SPEC = importlib.util.spec_from_file_location("app_addability_proposal", SCRIPT)
EXPORTER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(EXPORTER)


class AppAddabilityProposalTests(unittest.TestCase):
    def test_historical_created_and_present_evidence_are_separate_events(self):
        row = {
            "OctoberInventory": {"Registration": "Present", "CapturedAtUtc": "2026-10-04T18:22:30Z"},
            "OctoberRegistrationAttempt": {"Outcome": "Created", "AttemptedAtUtc": "2026-10-03T08:00:00Z"},
        }
        events = EXPORTER.historical_positive_events(row)
        self.assertEqual(len(events), 2)
        self.assertEqual(events[0]["Result"], "PresentWithVerifiedMicrosoftOwner")
        self.assertEqual(events[1]["Result"], "CreatedWithVerifiedMicrosoftOwner")

    def test_owner_mismatch_is_not_positive_cross_tenant_evidence(self):
        row = {"OctoberInventory": {"Registration": "OwnerMismatch", "CapturedAtUtc": "2026-10-04T18:22:30Z"}}
        self.assertEqual(EXPORTER.historical_positive_events(row), [])

    def test_historical_failure_without_specific_reason_stays_pending(self):
        entry = {"Reason": "Historical failure has no app-specific Graph reason; pending."}
        self.assertIn("Historical failure", EXPORTER.public_reason("Pending", entry))

    def test_cannot_add_reason_is_normalized_without_private_graph_message(self):
        entry = {"Reason": "Application is single-tenant and cannot be added to another tenant in lab 11111111-1111-1111-1111-111111111111"}
        reason = EXPORTER.public_reason("CouldntAdd", entry)
        self.assertEqual(reason, "Microsoft Graph explicitly stated that this application is single-tenant.")
        self.assertNotIn("11111111", reason)

    def test_private_owner_id_is_not_exported_as_public_evidence(self):
        entry = {
            "Result": "AlreadyPresent",
            "UtcDate": "2026-11-21",
            "Source": "Microsoft Graph exact AppId lookup",
            "ServicePrincipal": {
                "id": "33333333-3333-3333-3333-333333333333",
                "appId": "11111111-1111-1111-1111-111111111111",
                "appOwnerOrganizationId": "22222222-2222-2222-2222-222222222222",
                "servicePrincipalType": "Application",
            },
        }
        public = EXPORTER.public_current_evidence("Confirmed", entry)
        text = json.dumps(public)
        self.assertIn("Application", text)
        self.assertNotIn("appOwnerOrganizationId", text)
        self.assertNotIn("22222222-2222-2222-2222-222222222222", text)

    def test_current_checkpoint_requires_matching_tenant_and_account(self):
        checkpoint = {
            "Format": "TokenForgeAppAddabilityCheckpoint",
            "SchemaVersion": 1,
            "SnapshotSha256": EXPORTER.PINNED_SHA256,
            "TenantId": "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
            "ExpectedAccount": "operator@example.test",
            "Queue": [],
            "Results": {"Confirmed": [], "CouldntAdd": [], "Pending": []},
            "CreatedServicePrincipals": [],
        }
        path = pathlib.Path("private-checkpoint.json")
        with mock.patch.object(EXPORTER, "read_json_bytes", return_value=(checkpoint, b"private")):
            with self.assertRaisesRegex(ValueError, "expected tenant ID and account"):
                EXPORTER.current_checkpoint(path, None, None)
            with self.assertRaisesRegex(ValueError, "tenant does not match"):
                EXPORTER.current_checkpoint(path, "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb", "operator@example.test")
            categories, _metadata, private_tenant = EXPORTER.current_checkpoint(
                path, "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa", "OPERATOR@example.test"
            )
        self.assertEqual(categories["Pending"], {})
        self.assertEqual(private_tenant, "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa")

    def test_sanitized_history_must_cover_the_pinned_id_set(self):
        evidence = {"snapshot": {"sha256": EXPORTER.PINNED_SHA256}, "sources": {}, "applications": {}}
        path = pathlib.Path("history-fixture.json")
        args = type("Args", (), {"historical_evidence": path, "october_discovery": None, "october_inventory": None, "october_attempts": None})()
        with mock.patch.object(EXPORTER, "read_json_bytes", return_value=(evidence, json.dumps(evidence).encode())):
            with self.assertRaisesRegex(ValueError, "does not cover"):
                EXPORTER.load_history(args, {"11111111-1111-1111-1111-111111111111"})


if __name__ == "__main__":
    unittest.main()
