from contextlib import redirect_stdout
from datetime import datetime, timezone
from hashlib import sha256
import io
import os
import subprocess
from pathlib import Path
import sys
import unittest
from unittest.mock import patch
from urllib.parse import parse_qs, urlsplit

import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'examples' / 'signin-review'))
import candidate_metadata
import collect
from directory_provisioning import valid_directory_link
import validate_directory as probe
import workload_http as http


TENANT = '11111111-1111-4111-8111-111111111111'
CLIENT = '22222222-2222-4222-8222-222222222222'
KNOWN = '33333333-3333-4333-8333-333333333333'
TARGET = '44444444-4444-4444-8444-444444444444'
FIXTURE_DIGEST = sha256(f'{TENANT}:{CLIENT}'.encode('ascii')).hexdigest()
ENV = {
    'GITHUB_REPOSITORY': collect.REPOSITORY, 'GITHUB_REPOSITORY_ID': collect.REPOSITORY_ID,
    'GITHUB_REF': 'refs/heads/main', 'GITHUB_EVENT_NAME': 'workflow_dispatch',
    'GITHUB_WORKFLOW_REF': collect.WORKFLOW_REF, 'GITHUB_RUN_ID': '17', 'GITHUB_RUN_ATTEMPT': '1',
    'TF_AUDIT_TENANT_ID': TENANT, 'TF_AUDIT_CLIENT_ID': CLIENT, 'TF_VALIDATION_MODE': 'directory-validation',
}
ENDPOINT = 'https://graph.microsoft.com/v1.0/auditLogs/directoryAudits'
NEXT = ENDPOINT + '?$skiptoken=fixture-only'
TOKEN = {'token_type': 'Bearer', 'access_token': 'fixture-token'}
EVENT = {'activityDisplayName': 'Add service principal', 'activityDateTime': '2026-11-24T01:01:00Z',
         'result': 'success', 'targetResources': [{'type': 'ServicePrincipal', 'id': TARGET}],
         'additionalDetails': [{'key': 'AppId', 'value': KNOWN}], 'id': 'fixture-event'}
AFTER = datetime(2026, 11, 24, 3, tzinfo=timezone.utc)


class DirectoryValidationTests(unittest.TestCase):
    def test_exact_workflow_routes_and_privileges(self):
        workflow = yaml.safe_load((ROOT / '.github/workflows/signin-review-candidates.yml').read_bytes())
        self.assertEqual(set(workflow['on']), {'workflow_dispatch', 'schedule'})
        self.assertEqual(workflow['on']['workflow_dispatch']['inputs']['mode']['default'], 'sign-in')
        self.assertEqual(workflow['permissions'], {})
        jobs = workflow['jobs']
        self.assertEqual(set(jobs), {'collect', 'issue', 'directory_validation'})
        guard = ("github.repository == 'nathanmcnulty/TokenForge' && "
                 "github.repository_id == '1402673320' && github.ref == 'refs/heads/main'")
        review_mode = ("((github.event_name == 'workflow_dispatch' && "
                       "(inputs.mode == 'sign-in' || inputs.mode == 'sign-in-and-directory')) || "
                       "(github.event_name == 'schedule' && vars.TOKENFORGE_SIGNIN_SCHEDULE_ENABLED == 'true'))")
        self.assertEqual(jobs['collect']['if'].strip(), f'{guard} && {review_mode}')
        self.assertEqual(jobs['issue']['if'].strip(), f"needs.collect.result == 'success' && {guard} && {review_mode}")
        self.assertEqual(jobs['directory_validation']['if'].strip(),
                         f"inputs.mode == 'directory-validation' && {guard} && github.event_name == 'workflow_dispatch'")
        self.assertEqual(jobs['issue']['needs'], 'collect')
        self.assertEqual(jobs['issue']['permissions'], {'issues': 'write'})
        self.assertEqual(jobs['collect']['permissions'], {'contents': 'read', 'id-token': 'write'})
        job = jobs['directory_validation']
        self.assertEqual(job['permissions'], {'contents': 'read', 'id-token': 'write'})
        self.assertEqual(job['environment'], 'entra-audit')
        self.assertEqual(job['timeout-minutes'], 10)
        self.assertFalse({'needs', 'outputs'}.intersection(job))
        self.assertEqual(len(job['steps']), 2)
        checkout, validation = job['steps']
        self.assertEqual(checkout['with'], {'ref': '${{ github.sha }}', 'persist-credentials': False})
        self.assertEqual(set(validation['env']), {'TF_VALIDATION_MODE', 'TF_AUDIT_TENANT_ID', 'TF_AUDIT_CLIENT_ID'})
        self.assertEqual(validation['env']['TF_VALIDATION_MODE'], '${{ inputs.mode }}')
        self.assertEqual(validation['run'].splitlines()[-1], 'python3 -B examples/signin-review/validate_directory.py')
        self.assertIn(collect.CATALOG_COMMIT, validation['run'])
        self.assertNotIn('artifact', str(job))

    def test_probe_pages_through_terminal_and_prints_only_fixed_status(self):
        out = io.StringIO()
        with (patch.dict(os.environ, ENV, clear=True), patch.object(probe, 'EXPECTED_WORKLOAD', FIXTURE_DIGEST),
              patch.object(probe, 'datetime', wraps=datetime) as clock,
              patch.object(probe, 'pinned_catalog_app_ids', return_value={KNOWN}),
              patch.object(http, 'get_assertion', return_value=('fixture-assertion', {})),
              patch.object(http, 'check', return_value={'matched': True}),
              patch.object(http, 'request_json',
                           side_effect=[TOKEN, {'value': [], '@odata.nextLink': NEXT}, {'value': [EVENT]}]) as request,
              redirect_stdout(out)):
            clock.now.return_value = AFTER
            probe.main()
        self.assertEqual(out.getvalue(), probe.PASSED + '\n')
        login, first, second = request.call_args_list
        self.assertEqual(login.args[0], f'https://login.microsoftonline.com/{TENANT}/oauth2/v2.0/token')
        self.assertEqual(login.kwargs['method'], 'POST')
        self.assertEqual(first.args[0].split('?')[0], ENDPOINT)
        self.assertEqual(parse_qs(urlsplit(first.args[0]).query)['$filter'],
                         ["activityDisplayName eq 'Add service principal' and activityDateTime ge "
                          "2026-11-24T01:00:00Z and activityDateTime le 2026-11-24T02:00:00Z"])
        self.assertEqual(second.args, (NEXT,))
        for read in (first, second):
            self.assertEqual(read.kwargs.get('method', 'GET'), 'GET')
            self.assertNotIn('data', read.kwargs)

    def test_directory_transport_rejects_other_graph_or_write_destinations(self):
        with (patch.object(http, 'get_assertion', return_value=('fixture-assertion', {})),
              patch.object(http, 'check', return_value={'matched': True}),
              patch.object(http, 'request_json', side_effect=[TOKEN, {'value': []}]) as request):
            get = http.graph_reader(ENV, directory_only=True)
            for url in ('https://graph.microsoft.com/beta/auditLogs/signIns?$top=1',
                        candidate_metadata.principal_url(KNOWN), 'https://api.github.com/repos/test/issues/151',
                        'https://wrong.invalid/v1.0/auditLogs/directoryAudits?x=1'):
                with self.assertRaises(ValueError):
                    get(url)
            self.assertEqual(request.call_count, 1)
            self.assertEqual(get(NEXT), {'value': []})

    def test_malformed_continuations_are_rejected_before_transport(self):
        self.assertTrue(valid_directory_link(ENDPOINT + '?%24skiptoken=fixture%2Fopaque%3D'))
        for tail in ('\x00', '\t', '\x1f', '\x7f', 'é', '%00', '%1f', '%7F', '%', '%0', '%GG', '#', '\\'):
            with self.subTest(tail=repr(tail)):
                graph = lambda url: {'value': [], '@odata.nextLink': NEXT + tail}
                with (patch.object(probe, 'EXPECTED_WORKLOAD', FIXTURE_DIGEST),
                      patch.object(probe, 'datetime', wraps=datetime) as clock,
                      patch.object(probe, 'pinned_catalog_app_ids', return_value={KNOWN}),
                      patch.object(probe, 'graph_reader') as reader):
                    clock.now.return_value = AFTER
                    reader.return_value.side_effect = graph
                    with self.assertRaisesRegex(ValueError, 'Invalid directory audit continuation'):
                        probe.validate(ENV)
                    self.assertEqual(reader.return_value.call_count, 1)

    def test_cli_sanitizes_real_http_parser_and_deep_json_failures(self):
        # Run the actual CLI boundary in a child interpreter so stderr is measured.
        # The stdlib HTTP parser runs normally, with its connection call blocked.
        harness = r"""
import http.client
import json
import sys
from unittest.mock import patch
sys.path.insert(0, 'examples/signin-review')
import validate_directory as probe

def fail(_env):
    if sys.argv[1] == 'http':
        try:
            http.client.HTTPConnection('fixture.invalid').request('GET', '/continuation?private-canary\x7f')
        except http.client.InvalidURL as exc:
            assert 'private-canary' in str(exc)
            raise
        raise AssertionError('Expected the actual HTTP parser to reject the continuation')
    if sys.argv[1] == 'json':
        json.loads('[' * 4000 + '"private-canary"' + ']' * 4000)
        raise AssertionError('Expected the actual JSON parser to hit its recursion bound')
    raise RuntimeError('private-canary upstream error')

with patch.object(http.client.HTTPConnection, 'connect', side_effect=AssertionError('Socket forbidden')) as network:
    with patch.object(probe, 'validate', side_effect=fail):
        try:
            probe.main()
        finally:
            network.assert_not_called()
"""
        for fault in ('http', 'json', 'unexpected'):
            with self.subTest(fault=fault):
                result = subprocess.run([sys.executable, '-B', '-c', harness, fault], cwd=ROOT,
                                        text=True, capture_output=True, check=False, timeout=10)
                self.assertEqual(result.returncode, 1)
                self.assertEqual(result.stdout, '')
                self.assertEqual(result.stderr, probe.INCOMPLETE + '\n')

    def test_scope_or_writer_material_fails_before_any_authentication(self):
        with (patch.object(probe, 'EXPECTED_WORKLOAD', FIXTURE_DIGEST),
              patch.object(probe, 'graph_reader') as graph):
            for bad in ({'TF_VALIDATION_MODE': 'sign-in'}, {'GITHUB_EVENT_NAME': 'schedule'},
                        {'GITHUB_REF': 'refs/heads/feature'}, {'GITHUB_WORKFLOW_REF': 'wrong-workflow'},
                        {'TF_AUDIT_TENANT_ID': TARGET}, {'TF_AUDIT_CLIENT_ID': TARGET},
                        {'GH_TOKEN': 'fixture'}, {'TF_REVIEW_ISSUE': '151'}, {'TF_HANDOFF_RECIPIENT': 'fixture'}):
                with self.assertRaises(ValueError):
                    probe.validate(ENV | bad)
            graph.assert_not_called()

    def test_incomplete_empty_and_page_cap_fail_without_public_data(self):
        next_pages = [{'value': [EVENT], '@odata.nextLink': ENDPOINT + f'?$skiptoken=page-{i}'}
                      for i in range(probe.MAX_PAGES)]
        for responses in ([{'value': []}],
                          [{'value': [EVENT], '@odata.nextLink': NEXT}, http.HTTPFailure(403)],
                          next_pages):
            out = io.StringIO()
            with (patch.dict(os.environ, ENV, clear=True), patch.object(probe, 'EXPECTED_WORKLOAD', FIXTURE_DIGEST),
                  patch.object(probe, 'datetime', wraps=datetime) as clock,
                  patch.object(probe, 'pinned_catalog_app_ids', return_value={KNOWN}),
                  patch.object(probe, 'graph_reader') as graph, redirect_stdout(out)):
                clock.now.return_value = AFTER
                graph.return_value.side_effect = responses
                with self.assertRaises(SystemExit) as failure:
                    probe.main()
                self.assertEqual(failure.exception.code, probe.INCOMPLETE)
                self.assertEqual(graph.return_value.call_count, len(responses))
            self.assertEqual(out.getvalue(), '')


if __name__ == '__main__':
    unittest.main()
