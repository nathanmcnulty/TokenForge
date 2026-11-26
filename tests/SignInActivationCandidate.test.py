from datetime import datetime
import json
import os
import runpy
from pathlib import Path
import subprocess
import sys
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import Mock, patch
from urllib.parse import parse_qs, urlsplit

import yaml

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / 'examples' / 'signin-review'
sys.path.insert(0, str(SOURCE))
from collect import CATALOG_COMMIT, GRAPH_EVENTS, WORKFLOW_REF, handoff_identity
from report import OWNER_ID, body_for, validate_handoff
import collect as collector
import review_ci

KNOWN = '22222222-2222-4222-8222-222222222222'
APP = '33333333-3333-4333-8333-333333333333'
PROMOTED = '44444444-4444-4444-8444-444444444444'
PREVIOUS_CATALOG = '8bdce9ca411c340284c4df76d70924365db6ae14'
TENANT = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa'
LABELS = ['sign-in', 'audience unknown', 'publisher unknown']
ENV = {
    'GITHUB_REPOSITORY': 'nathanmcnulty/TokenForge', 'GITHUB_REPOSITORY_ID': '1402673320',
    'GITHUB_REF': 'refs/heads/main', 'GITHUB_EVENT_NAME': 'workflow_dispatch',
    'GITHUB_WORKFLOW_REF': WORKFLOW_REF, 'TF_CATALOG_TIP': CATALOG_COMMIT, 'GITHUB_SHA': 'e' * 40, 'GITHUB_RUN_ID': '17', 'GITHUB_RUN_ATTEMPT': '2',
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
        self.assertEqual(source['on'], {'workflow_dispatch': {'inputs': {'mode': {
            'description': 'Run sign-in review, combined review, or the one-time directory audit validation',
            'type': 'choice', 'default': 'sign-in',
            'options': ['sign-in', 'directory-validation', 'sign-in-and-directory'],
        }}}})
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
        fetches = [line.split() for line in reader['steps'][-1]['run'].splitlines()
                   if ' fetch ' in line]
        self.assertEqual(fetches, [[
            'git', '-c', 'credential.helper=', 'fetch', '--quiet', '--no-tags', '--depth=1',
            'https://github.com/nathanmcnulty/TokenForge.git', 'refs/heads/discovery-data',
        ]])
        self.assertNotIn('GH_TOKEN', reader['steps'][-1]['env'])
        self.assertNotIn('GH_TOKEN', writer['steps'][0]['env'])
        self.assertEqual(writer['steps'][-1]['env']['TF_CATALOG_TIP'], '${{ steps.source.outputs.catalog-tip }}')
        self.assertIn('ls-remote --exit-code https://github.com/nathanmcnulty/TokenForge.git refs/heads/discovery-data',
                      writer['steps'][0]['run'])
        self.assertTrue(all('uses' not in step for step in writer['steps']))
        self.assertEqual(writer['steps'][-1]['env']['TF_HANDOFF_CIPHERTEXT'], '${{ needs.collect.outputs.ciphertext }}')
        self.assertEqual(writer['steps'][-1]['env']['TF_HANDOFF_IDENTITY'], '${{ secrets.TOKENFORGE_AGE_IDENTITY }}')
        self.assertNotIn('TF_HANDOFF_IDENTITY', reader['steps'][-1]['env'])
        self.assertNotIn('TOKENFORGE_AUDIT_', str(writer))
        self.assertTrue(all('artifact' not in str(job) for job in (reader, writer)))

    def test_writer_source_only_accepts_one_exact_catalog_ref(self):
        workflow = yaml.safe_load((SOURCE / 'activation.yml').read_text())
        step = workflow['jobs']['issue']['steps'][0]
        script = r"""git() {
  case "$*" in
    'rev-parse FETCH_HEAD') printf '%s\n' "$GITHUB_SHA" ;;
    *' ls-remote --exit-code '*)
      printf '%s\n' "$FIXTURE_CATALOG_REF"
      return "$FIXTURE_GIT_EXIT"
      ;;
  esac
}
bash() { test "$*" = 'examples/signin-review/install-proof-age.sh'; }
""" + step['run']
        tip = 'b' * 40
        good = f'{tip}\trefs/heads/discovery-data'
        cases = ((good, 0, True), (good, 1, False), ('', 0, False),
                 (f'{tip}\trefs/heads/main', 0, False),
                 (f'{tip[:-1]}Z\trefs/heads/discovery-data', 0, False),
                 (f'{good}\n{good}', 0, False))
        for response, git_exit, accepted in cases:
            with self.subTest(response=response, git_exit=git_exit), TemporaryDirectory() as folder:
                output = Path(folder) / 'github-output'
                env = os.environ | {'GITHUB_SHA': ENV['GITHUB_SHA'], 'RUNNER_TEMP': folder,
                                    'GITHUB_OUTPUT': str(output), 'FIXTURE_CATALOG_REF': response,
                                    'FIXTURE_GIT_EXIT': str(git_exit)}
                result = subprocess.run(['bash', '-c', script], env=env, capture_output=True, timeout=10, check=False)
                self.assertEqual(result.returncode == 0, accepted)
                self.assertEqual(output.exists(), accepted)
                if accepted:
                    self.assertEqual(output.read_text(), f'catalog-tip={tip}\n')

    def test_combined_mode_routes_only_the_matching_reader_and_writer(self):
        workflow = yaml.safe_load((ROOT / '.github/workflows/signin-review-candidates.yml').read_bytes())
        self.assertEqual(workflow, yaml.safe_load((SOURCE / 'activation.yml').read_bytes()))
        for key in ('collect', 'issue'):
            job = workflow['jobs'][key]
            self.assertIn("inputs.mode == 'sign-in-and-directory'", job['if'])
            self.assertIn("github.ref == 'refs/heads/main'", job['if'])
            step = job['steps'][-1]
            self.assertEqual(step['env']['TF_REVIEW_MODE'], '${{ inputs.mode }}')
            with TemporaryDirectory() as folder:
                (Path(folder) / 'tokenforge-public-source').mkdir()
                for mode, command in (('sign-in', key), ('sign-in-and-directory', key + '-directory'),
                                      ('directory-validation', None), ('unknown', None)):
                    script = r"""git() { if [[ "$1" == 'rev-parse' ]]; then printf 'fixture-tip'; fi; }
python3() { printf '%s:%s\n' "${TF_CATALOG_TIP:-}" "$*"; }
""" + step['run']
                    result = subprocess.run(['bash', '-c', script], cwd=folder,
                                            env=os.environ | {'RUNNER_TEMP': folder, 'TF_REVIEW_MODE': mode},
                                            capture_output=True, text=True, timeout=10, check=False)
                    tip = 'fixture-tip' if key == 'collect' else ''
                    self.assertEqual((result.returncode, result.stdout, result.stderr),
                                     (0, f'{tip}:-B examples/signin-review/review_ci.py {command}\n', '') if command
                                     else (2, '', ''))

    def test_current_catalog_excludes_promoted_ids_and_rejects_a_previous_handoff(self):
        def get(url):
            predicate = parse_qs(urlsplit(url).query)['$filter'][0]
            if ("createdDateTime ge 2026-01-01T00:00:00Z" in predicate
                    and "t eq 'interactiveUser'" in predicate):
                return {'value': [{'appId': app, 'createdDateTime': '2026-01-01T10:00:00Z',
                                   'signInEventTypes': ['interactiveUser']}
                                  for app in (PROMOTED, KNOWN, APP)]}
            return {'value': []}

        current_tip = 'b' * 40
        env = ENV | {'TF_CATALOG_TIP': current_tip}
        catalog = Mock()
        catalog.partition.side_effect = [{'Applications': {PROMOTED: {}}}, {'Applications': {KNOWN: {}}}]
        catalog.app_ids = collector.OfflineCatalog.app_ids
        with (patch.object(collector, 'OfflineCatalog', return_value=catalog) as load,
              patch.object(collector, 'datetime', wraps=datetime) as clock):
            clock.now.return_value = datetime.fromisoformat('2026-01-31T00:00:00Z')
            raw = collector.collect_envelope(env, get)
        load.assert_called_once_with(collector.ROOT, current_tip)
        candidate = json.loads(raw)
        self.assertEqual(candidate['catalogCommit'], current_tip)
        self.assertEqual(validate_handoff(raw, env, categories=GRAPH_EVENTS), {APP})
        with self.assertRaises(ValueError):
            validate_handoff(json.dumps(candidate | {'catalogCommit': PREVIOUS_CATALOG}).encode(),
                             env, categories=GRAPH_EVENTS)

    def test_failed_cli_reports_only_a_fixed_message_without_a_handoff(self):
        from collect import IncompleteCategory
        with TemporaryDirectory() as tmp:
            output = Path(tmp) / 'github-output'
            env = ENV | {'GITHUB_OUTPUT': str(output)}
            with (patch.dict(os.environ, env, clear=True), patch.object(sys, 'argv', ['review_ci.py', 'collect']),
                  patch('collect.pinned_catalog_app_ids', return_value=set()),
                  patch('workload_http.graph_reader', side_effect=IncompleteCategory(
                      'Graph coverage incomplete for servicePrincipal (HTTP 403). synthetic-private-canary'))):
                with self.assertRaises(SystemExit) as result:
                    runpy.run_path(str(SOURCE / 'review_ci.py'), run_name='__main__')
            self.assertEqual(result.exception.code, 'Sign-in candidate review stopped.')
            self.assertFalse(output.exists())

    def test_mocked_reader_and_issue_writer_update_only_new_fixture_ids(self):
        with TemporaryDirectory() as temp:
            output = Path(temp) / 'github-output'
            read = ENV | {'GITHUB_OUTPUT': str(output), 'TF_HANDOFF_RECIPIENT': self.recipient, 'TF_AUDIT_TENANT_ID': TENANT}
            get = Mock(side_effect=review_ci.HTTPFailure(404))
            with (patch.object(review_ci, 'graph_reader', return_value=get) as auth,
                  patch.object(review_ci, 'pinned_catalog_app_ids', return_value={KNOWN}) as load,
                  patch.object(review_ci, 'scan_directory') as directory,
                  patch.object(review_ci, 'collect_envelope', return_value=envelope([KNOWN, APP])) as collect):
                review_ci.collect_job(read)
            auth.assert_called_once_with(read)
            load.assert_called_once_with(CATALOG_COMMIT)
            collect.assert_called_once_with(read, get, {KNOWN})
            directory.assert_not_called()
            encoded = output.read_text().removeprefix('ciphertext=').strip()
            self.assertNotIn(APP, encoded)
        write = ENV | {'TF_HANDOFF_CIPHERTEXT': encoded, 'TF_REVIEW_ISSUE': '57',
                       'TF_REVIEW_ISSUE_NODE': 'I_synthetic'}
        fixture = {'number': 57, 'node_id': 'I_synthetic', 'state': 'open',
                   'user': {'id': OWNER_ID}, 'body': body_for({KNOWN: LABELS}, labeled=True)}
        updated = fixture | {'body': body_for({KNOWN: LABELS, APP: LABELS}, labeled=True)}
        api = Mock(side_effect=[fixture, updated, updated])
        review_ci.report_job(write, self.identity, api)
        review_ci.report_job(write, self.identity, api)
        self.assertEqual(api.call_count, 3)
        self.assertEqual(api.call_args_list[1].args,
                         ('--method', 'PATCH', 'repos/nathanmcnulty/TokenForge/issues/57', '--input', '-'))
        self.assertEqual(json.loads(api.call_args_list[1].kwargs['body']), {'body': updated['body']})
        for delta in ({'GITHUB_RUN_ATTEMPT': '3'}, {'TF_CATALOG_TIP': 'b' * 40}, {'ACTIONS_ID_TOKEN_REQUEST_TOKEN': 'not-live'},
                      {'TF_AUDIT_CLIENT_ID': 'not-live'}):
            rejected = Mock()
            with self.assertRaises(ValueError):
                review_ci.report_job(write | delta, self.identity, rejected)
            rejected.assert_not_called()

    def test_failed_collection_creates_no_output_and_no_issue_auth_is_accepted(self):
        with TemporaryDirectory() as temp:
            output = Path(temp) / 'github-output'
            context = ENV | {'GITHUB_OUTPUT': str(output), 'TF_HANDOFF_RECIPIENT': self.recipient}
            with (patch.object(review_ci, 'graph_reader'), patch.object(review_ci, 'pinned_catalog_app_ids', return_value=set()),
                  patch.object(review_ci, 'collect_envelope', side_effect=ValueError('fixture failure')) as gather):
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
