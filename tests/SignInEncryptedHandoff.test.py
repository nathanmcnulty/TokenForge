from contextlib import redirect_stdout
from io import StringIO
import json
from pathlib import Path
import subprocess
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'examples' / 'signin-review'))
import collect
import handoff

APP = '33333333-3333-4333-8333-333333333333'
ENV = {'GITHUB_REPOSITORY': 'nathanmcnulty/TokenForge', 'GITHUB_REPOSITORY_ID': '1402673320',
       'GITHUB_REF': 'refs/heads/main', 'GITHUB_EVENT_NAME': 'schedule',
       'GITHUB_RUN_ID': '17', 'GITHUB_RUN_ATTEMPT': '2',
       'GITHUB_SHA': 'e' * 40, 'GITHUB_WORKFLOW_REF': collect.WORKFLOW_REF}


def pair():
    key = subprocess.run(['age-keygen'], capture_output=True, text=True, timeout=10, check=True)
    return key.stderr.strip().removeprefix('Public key: '), key.stdout.splitlines()[-1]


def envelope(ids, **overrides):
    return json.dumps(collect.handoff_identity(ENV) | {
                       'since': '2026-01-01T00:00:00Z', 'until': '2026-01-03T00:00:00Z',
                       'categories': ['interactiveUser', 'nonInteractiveUser'],
                       'coverage': 'requested-windows-terminal;retention-unknown', 'appIds': ids} | overrides).encode()


class EncryptedHandoffTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.public, cls.private = pair()

    def test_roundtrip_has_fixed_public_length_and_no_plaintext_or_logs(self):
        output = StringIO()
        with redirect_stdout(output):
            populated = handoff.seal(envelope([APP]), ENV, self.public)
            empty = handoff.seal(envelope([]), ENV, self.public)
            repeated = handoff.seal(envelope([APP]), ENV, self.public)
            self.assertEqual(handoff.open_envelope(populated, ENV, self.private), envelope([APP]))
            self.assertEqual(handoff.open_envelope(empty, ENV, self.private), envelope([]))
        self.assertEqual(output.getvalue(), '')
        self.assertEqual(len(populated), len(empty))
        self.assertNotEqual(repeated, populated)
        for value in (APP, 'catalogCommit', '2026-01-01', 'interactiveUser'):
            self.assertNotIn(value.encode(), populated)

    def test_tamper_wrong_recipient_and_replay_are_rejected(self):
        sealed = handoff.seal(envelope([APP]), ENV, self.public)
        _, wrong = pair()
        tampered = sealed[:-1] + bytes([sealed[-1] ^ 1])
        for candidate, context, key in ((sealed, ENV, wrong), (tampered, ENV, self.private),
                                         (sealed, ENV | {'GITHUB_RUN_ATTEMPT': '3'}, self.private),
                                         (sealed, ENV | {'GITHUB_RUN_ID': '18'}, self.private),
                                         (sealed, ENV | {'GITHUB_SHA': 'a' * 40}, self.private),
                                         (sealed, ENV | {'GITHUB_REPOSITORY_ID': '2'}, self.private),
                                         (sealed, ENV | {'GITHUB_REPOSITORY': 'other/TokenForge'}, self.private),
                                         (sealed, ENV | {'GITHUB_WORKFLOW_REF': collect.WORKFLOW_REF + 'other'}, self.private)):
            with self.assertRaises(ValueError):
                handoff.open_envelope(candidate, context, key)

    def test_rejects_malformed_envelopes_identity_and_recipient(self):
        for data in (b'{}', envelope(['not-a-guid']), envelope([], catalogCommit='a' * 40),
                     envelope([], sourceCommit='f' * 40), b'x' * (handoff.MAX_PAYLOAD + 1)):
            with self.assertRaises(ValueError):
                handoff.seal(data, ENV, self.public)
        with self.assertRaises(ValueError):
            handoff.seal(envelope([]), ENV, self.public + '\n')
        with self.assertRaises(ValueError):
            handoff.open_envelope(envelope([]), ENV, self.private)
        with self.assertRaises(ValueError):
            handoff.open_envelope(handoff.seal(envelope([]), ENV, self.public), ENV, self.private + '\n')


if __name__ == '__main__':
    unittest.main()
