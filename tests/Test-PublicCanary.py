"""Offline checks of verified-certificate bindings, using synthetic metadata only."""
import copy
import importlib.util
import json
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location(
    "attestation", Path(__file__).resolve().parents[1] / "scripts/Verify-TokenForgeCanaryAttestation.py")
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class CertificateBindings(unittest.TestCase):
    def setUp(self):
        self.source = "a" * 40
        self.subject = {"ProducerRunId": "123", "ProducerAttempt": "1", "OriginalArchiveSha256": "b" * 64}
        cert = {
            "issuer": "https://token.actions.githubusercontent.com",
            "sourceRepositoryURI": "https://github.com/nathanmcnulty/TokenForge",
            "sourceRepositoryIdentifier": "1402673320",
            "sourceRepositoryDigest": self.source,
            "sourceRepositoryRef": "refs/heads/codex/issue113-publication-acceptance",
            "buildSignerURI": "https://github.com/nathanmcnulty/TokenForge/.github/workflows/ci.yml@refs/heads/codex/issue113-publication-acceptance",
            "buildSignerDigest": self.source,
            "runnerEnvironment": "github-hosted",
            "runInvocationURI": "https://github.com/nathanmcnulty/TokenForge/actions/runs/123/attempts/1",
        }
        self.data = [{"verificationResult": {
            "signature": {"certificate": cert},
            "statement": {"subject": [{"digest": {"sha256": "b" * 64}}]},
            "verifiedTimestamps": [{"type": "Tlog"}],
        }}]

    def test_valid(self):
        self.assertEqual(module.validate_result(self.data, self.subject, self.source)["buildSignerDigest"], self.source)

    def test_every_certificate_binding(self):
        for key in self.data[0]["verificationResult"]["signature"]["certificate"]:
            with self.subTest(key=key):
                changed = copy.deepcopy(self.data)
                changed[0]["verificationResult"]["signature"]["certificate"][key] = "wrong"
                with self.assertRaises(ValueError):
                    module.validate_result(changed, self.subject, self.source)

    def test_attempt_and_run(self):
        for key in ("ProducerRunId", "ProducerAttempt"):
            changed = dict(self.subject, **{key: "2"})
            with self.subTest(key=key), self.assertRaises(ValueError):
                module.validate_result(self.data, changed, self.source)

    def test_subject(self):
        self.data[0]["verificationResult"]["statement"]["subject"][0]["digest"]["sha256"] = "c" * 64
        with self.assertRaises(ValueError):
            module.validate_result(self.data, self.subject, self.source)

    def test_single_result(self):
        for data in ([], self.data * 2):
            with self.assertRaises(ValueError):
                module.validate_result(data, self.subject, self.source)

    def test_witness(self):
        self.data[0]["verificationResult"]["verifiedTimestamps"] = []
        with self.assertRaises(ValueError):
            module.validate_result(self.data, self.subject, self.source)


if __name__ == "__main__":
    unittest.main()
