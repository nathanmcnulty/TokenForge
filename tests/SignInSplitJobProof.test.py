import base64
import os
from pathlib import Path
import subprocess
import sys
from tempfile import TemporaryDirectory
import unittest

import yaml

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / 'examples' / 'signin-review'
sys.path.insert(0, str(SOURCE))
from handoff_proof import CANDIDATE, KNOWN, PROOF_REF

ENV = {
    'PATH': os.environ['PATH'], 'GITHUB_REPOSITORY': 'nathanmcnulty/TokenForge',
    'GITHUB_REPOSITORY_ID': '1402673320', 'GITHUB_REF': 'refs/heads/main',
    'GITHUB_EVENT_NAME': 'workflow_dispatch', 'GITHUB_WORKFLOW_REF': PROOF_REF,
    'GITHUB_RUN_ID': '17', 'GITHUB_RUN_ATTEMPT': '1', 'GITHUB_SHA': 'e' * 40,
}


class SplitJobProofTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        key = subprocess.run(['age-keygen'], capture_output=True, text=True, check=True, timeout=10)
        cls.recipient = key.stderr.strip().removeprefix('Public key: ')
        cls.identity = key.stdout.splitlines()[-1]

    def command(self, operation, env):
        return subprocess.run(
            [sys.executable, '-B', str(SOURCE / 'handoff_proof.py'), operation],
            env=env, capture_output=True, timeout=25,
        )

    def produce(self, filename):
        read = self.command('collect', ENV | {
            'TF_PROOF_AGE_RECIPIENT': self.recipient, 'GITHUB_OUTPUT': str(filename),
        })
        self.assertEqual((read.returncode, read.stdout, read.stderr), (0, b'', b''))
        record = filename.read_text(encoding='ascii').splitlines()
        self.assertEqual(len(record), 1)
        key, value = record[0].split('=', 1)
        self.assertEqual(key, 'ciphertext')
        return value

    def test_template_is_inert_and_only_ciphertext_crosses_jobs(self):
        self.assertFalse((ROOT / '.github/workflows/signin-review-handoff-proof.yml').exists())
        source = yaml.safe_load((SOURCE / 'handoff-proof.yml').read_text())
        self.assertEqual(source['on'], {'workflow_dispatch': None})
        self.assertEqual(source['permissions'], {})
        self.assertFalse(source['concurrency']['cancel-in-progress'])
        self.assertEqual(set(source['jobs']), {'collect', 'issue-proof'})
        collect, issue = (source['jobs'][name] for name in ('collect', 'issue-proof'))
        self.assertEqual(collect['outputs'], {'ciphertext': '${{ steps.fixture.outputs.ciphertext }}'})
        self.assertEqual(issue['needs'], 'collect')
        self.assertEqual(issue['environment'], 'entra-audit-handoff-proof')
        self.assertNotIn('environment', collect)
        for job in (collect, issue):
            self.assertEqual(job['permissions'], {'contents': 'read'})
            self.assertIn("github.ref == 'refs/heads/main'", job['if'])
            self.assertIn("github.repository_id == '1402673320'", job['if'])
            self.assertEqual(len(job['steps']), 3)
            self.assertEqual(job['steps'][1]['run'], 'bash examples/signin-review/install-proof-age.sh')
        self.assertEqual(collect['steps'][2]['env'], {
            'TF_PROOF_AGE_RECIPIENT': '${{ vars.TOKENFORGE_SYNTHETIC_AGE_RECIPIENT }}',
        })
        self.assertEqual(issue['steps'][2]['env'], {
            'TF_PROOF_CIPHERTEXT': '${{ needs.collect.outputs.ciphertext }}',
            'TF_PROOF_AGE_IDENTITY': '${{ secrets.TOKENFORGE_SYNTHETIC_AGE_IDENTITY }}',
        })

    def test_process_separation_and_public_output_have_no_plaintext(self):
        with TemporaryDirectory() as tmp:
            first = self.produce(Path(tmp) / 'first')
            other = self.produce(Path(tmp) / 'other')
            self.assertEqual(len(first), len(other))
            self.assertNotEqual(first, other)
            # Simulate the runner rendering the full value in step debug output.
            debug = b'Set output ciphertext = ' + first.encode('ascii')
            writer = self.command('issue-proof', ENV | {
                'TF_PROOF_CIPHERTEXT': first, 'TF_PROOF_AGE_IDENTITY': self.identity,
            })
            public = debug + base64.b64decode(first, validate=True) + writer.stdout + writer.stderr
            self.assertEqual((writer.returncode, writer.stdout, writer.stderr),
                             (0, b'Synthetic handoff proof passed.\n', b''))
            for forbidden in (KNOWN, CANDIDATE, self.identity, 'appIds', 'catalogCommit',
                              'candidate count', '2026-01-01T00:00:00Z'):
                self.assertNotIn(forbidden.encode(), public)

    def test_wrong_context_and_failed_input_do_not_reach_writer_proof(self):
        with TemporaryDirectory() as tmp:
            value = self.produce(Path(tmp) / 'output')
            context = ENV | {'TF_PROOF_CIPHERTEXT': value, 'TF_PROOF_AGE_IDENTITY': self.identity}
            for change in ({'GITHUB_RUN_ATTEMPT': '2'}, {'GITHUB_RUN_ID': '18'}, {'GITHUB_SHA': 'f' * 40},
                           {'GITHUB_WORKFLOW_REF': PROOF_REF.replace('/main', '/other')},
                           {'TF_PROOF_CIPHERTEXT': 'not base64'}, {'TF_PROOF_AGE_IDENTITY': self.recipient}):
                result = self.command('issue-proof', context | change)
                self.assertEqual((result.returncode, result.stdout, result.stderr),
                                 (1, b'', b'Synthetic handoff proof stopped.\n'))

    def test_reader_rejects_writer_identity_and_creates_no_output(self):
        with TemporaryDirectory() as tmp:
            path = Path(tmp) / 'output'
            read = self.command('collect', ENV | {
                'TF_PROOF_AGE_RECIPIENT': self.recipient, 'TF_PROOF_AGE_IDENTITY': self.identity,
                'GITHUB_OUTPUT': str(path),
            })
            self.assertEqual((read.returncode, read.stdout, read.stderr),
                             (1, b'', b'Synthetic handoff proof stopped.\n'))
            self.assertFalse(path.exists())


if __name__ == '__main__':
    unittest.main()
