import json
import os
from pathlib import Path
import subprocess
import sys
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import Mock, patch

import yaml

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / 'examples' / 'signin-review'
sys.path.insert(0, str(SOURCE))
from collect import CATALOG_COMMIT, GRAPH_EVENTS, WORKFLOW_REF, handoff_identity
from report import OWNER_ID, body_for
import review_ci

KNOWN = '22222222-2222-4222-8222-222222222222'
APP = '33333333-3333-4333-8333-333333333333'
ENV = {
    'GITHUB_REPOSITORY': 'nathanmcnulty/TokenForge', 'GITHUB_REPOSITORY_ID': '1402673320',
    'GITHUB_REF': 'refs/heads/main', 'GITHUB_EVENT_NAME': 'workflow_dispatch',
    'GITHUB_WORKFLOW_REF': WORKFLOW_REF, 'GITHUB_SHA': 'e' * 40, 'GITHUB_RUN_ID': '17', 'GITHUB_RUN_ATTEMPT': '2',
}


def envelope(ids):
    return json.dumps(handoff_identity(ENV) | {
        'since': '2026-01-01T00:00:00Z', 'until': '2026-01-31T00:00:00Z',
        'categories': list(GRAPH_EVENTS), 'coverage': 'requested-windows-terminal;retention-unknown', 'appIds': ids,
    }).encode()


class ActivationCandidateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        key = subprocess.run(['age-keygen'], capture_output=True, text=True, check=True, timeout=10)
        cls.recipient = key.stderr.strip().removeprefix('Public key: ')
        cls.identity = key.stdout.splitlines()[-1]

    def test_template_separates_environments_and_permissions_without_a_schedule(self):
        source = yaml.safe_load((SOURCE / 'activation.yml').read_text())
        self.assertEqual(source['on'], {'workflow_dispatch': None})
        self.assertEqual(source['permissions'], {})
        self.assertFalse(source['concurrency']['cancel-in-progress'])
        reader, writer = (source['jobs'][key] for key in ('collect', 'issue'))
        self.assertEqual(reader['permissions'], {'contents': 'read', 'id-token': 'write'})
        self.assertEqual(reader['environment'], 'entra-audit')
        self.assertEqual(writer['permissions'], {'issues': 'write'})
        self.assertEqual(writer['environment'], 'entra-audit-issue')
        self.assertEqual(writer['needs'], 'collect')
        self.assertIn("needs.collect.result == 'success'", writer['if'])
        self.assertEqual(reader['outputs'], {'ciphertext': '${{ steps.collect.outputs.ciphertext }}'})
        self.assertIn(CATALOG_COMMIT, reader['steps'][-1]['run'])
        self.assertNotIn('GH_TOKEN', reader['steps'][-1]['env'])
        self.assertTrue(all('uses' not in step for step in writer['steps']))
        self.assertEqual(writer['steps'][-1]['env']['TF_HANDOFF_CIPHERTEXT'], '${{ needs.collect.outputs.ciphertext }}')
        self.assertEqual(writer['steps'][-1]['env']['TF_HANDOFF_IDENTITY'], '${{ secrets.TOKENFORGE_AGE_IDENTITY }}')
        self.assertNotIn('TF_HANDOFF_IDENTITY', reader['steps'][-1]['env'])
        self.assertNotIn('TOKENFORGE_AUDIT_', str(writer))
        self.assertTrue(all('artifact' not in str(job) for job in (reader, writer)))

    def test_mocked_reader_and_issue_writer_update_only_new_fixture_ids(self):
        with TemporaryDirectory() as temp:
            output = Path(temp) / 'github-output'
            read = ENV | {'GITHUB_OUTPUT': str(output), 'TF_HANDOFF_RECIPIENT': self.recipient}
            with patch.object(review_ci, 'graph_reader'), patch.object(review_ci, 'collect_envelope', return_value=envelope([KNOWN, APP])):
                review_ci.collect_job(read)
            encoded = output.read_text().removeprefix('ciphertext=').strip()
            self.assertNotIn(APP, encoded)
        write = ENV | {'TF_HANDOFF_CIPHERTEXT': encoded, 'TF_REVIEW_ISSUE': '57',
                       'TF_REVIEW_ISSUE_NODE': 'I_synthetic'}
        fixture = {'number': 57, 'node_id': 'I_synthetic', 'state': 'open',
                   'user': {'id': OWNER_ID}, 'body': body_for([KNOWN])}
        updated = fixture | {'body': body_for([KNOWN, APP])}
        api = Mock(side_effect=[fixture, updated, updated])
        review_ci.report_job(write, self.identity, api)
        review_ci.report_job(write, self.identity, api)
        self.assertEqual(api.call_count, 3)
        self.assertEqual(api.call_args_list[1].args,
                         ('--method', 'PATCH', 'repos/nathanmcnulty/TokenForge/issues/57', '--input', '-'))
        self.assertEqual(json.loads(api.call_args_list[1].kwargs['body']), {'body': updated['body']})
        for delta in ({'GITHUB_RUN_ATTEMPT': '3'}, {'ACTIONS_ID_TOKEN_REQUEST_TOKEN': 'not-live'},
                      {'TF_AUDIT_CLIENT_ID': 'not-live'}):
            rejected = Mock()
            with self.assertRaises(ValueError):
                review_ci.report_job(write | delta, self.identity, rejected)
            rejected.assert_not_called()

    def test_failed_collection_creates_no_output_and_no_issue_auth_is_accepted(self):
        with TemporaryDirectory() as temp:
            output = Path(temp) / 'github-output'
            context = ENV | {'GITHUB_OUTPUT': str(output), 'TF_HANDOFF_RECIPIENT': self.recipient}
            with patch.object(review_ci, 'graph_reader'), patch.object(review_ci, 'collect_envelope', side_effect=ValueError('fixture failure')) as gather:
                with self.assertRaises(ValueError):
                    review_ci.collect_job(context | {'GH_TOKEN': 'fixture'})
                gather.assert_not_called()
                with self.assertRaises(ValueError):
                    review_ci.collect_job(context)
            self.assertFalse(output.exists())

    def test_issue_requests_are_fixed_route_and_never_get_provider_auth(self):
        with patch.dict(os.environ, {'GH_TOKEN': 'synthetic-only', 'ACTIONS_ID_TOKEN_REQUEST_TOKEN': 'not-live'}, clear=True):
            with patch.object(review_ci, 'request_json', return_value={'number': 57}) as request:
                target = 'repos/nathanmcnulty/TokenForge/issues/57'
                self.assertEqual(review_ci.issue_call(target), {'number': 57})
                self.assertEqual(request.call_args.args, ('https://api.github.com/' + target,))
                self.assertEqual(request.call_args.kwargs['method'], 'GET')
                self.assertEqual(request.call_args.kwargs['headers']['Authorization'], 'Bearer synthetic-only')
                for unsafe in ('https://example.invalid/', 'repos/other/TokenForge/issues/57', target + '/comments'):
                    with self.assertRaises(ValueError):
                        review_ci.issue_call(unsafe)
                self.assertEqual(request.call_count, 1)


if __name__ == '__main__':
    unittest.main()
