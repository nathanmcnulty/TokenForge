import base64
from contextlib import redirect_stdout
from datetime import datetime, timezone
from io import StringIO
import json
import os
import runpy
from pathlib import Path
import subprocess
import sys
from tempfile import TemporaryDirectory
import unittest
from urllib.parse import parse_qs, urlsplit
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'examples' / 'signin-review'))
from candidate_metadata import principal_url
from collect import CATALOG_COMMIT, GRAPH_EVENTS, REPOSITORY, REPOSITORY_ID, WORKFLOW_REF, handoff_identity, intervals, utc
from directory_provisioning import DIRECTORY_PATH, valid_directory_link
from handoff import open_envelope
from report import OWNER_ID, body_for, validate_handoff
import review_ci

TENANT = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa'
ENV = {'GITHUB_REPOSITORY': REPOSITORY, 'GITHUB_REPOSITORY_ID': REPOSITORY_ID, 'GITHUB_REF': 'refs/heads/main',
       'GITHUB_WORKFLOW_REF': WORKFLOW_REF, 'TF_CATALOG_TIP': CATALOG_COMMIT, 'GITHUB_SHA': 'e'*40, 'GITHUB_RUN_ID': '17',
       'GITHUB_RUN_ATTEMPT': '2', 'GITHUB_EVENT_NAME': 'workflow_dispatch', 'TF_AUDIT_TENANT_ID': TENANT}
END = datetime(2026, 1, 31, tzinfo=timezone.utc)
VERIFIED = '11111111-1111-4111-8111-111111111111'
NONVERIFIED = '22222222-2222-4222-8222-222222222222'
BOTH = '33333333-3333-4333-8333-333333333333'
ONLY_AUDIT = '44444444-4444-4444-8444-444444444444'
ONLY_SIGNIN = '55555555-5555-4555-8555-555555555555'
TARGET = '66666666-6666-4666-8666-666666666666'
EXTERNAL = 'abcdef01-7777-4777-8777-777777777777'
EXTERNAL_OWNER = '88888888-8888-4888-8888-888888888888'
INITIATOR = '99999999-9999-4999-8999-999999999999'
DIRECTORY_NEXT = f'https://graph.microsoft.com{DIRECTORY_PATH}?$skiptoken=synthetic'


def signins():
    return json.dumps(handoff_identity(ENV) | {
        'since': '2026-01-01T00:00:00Z', 'until': '2026-01-31T00:00:00Z',
        'categories': list(GRAPH_EVENTS), 'coverage': 'requested-windows-terminal;retention-unknown',
        'appIds': [BOTH, ONLY_SIGNIN],
    }).encode()


def event(app):
    return {'activityDisplayName': 'Add service principal', 'activityDateTime': '2026-01-01T00:00:00Z',
            'result': 'success', 'targetResources': [{'type': 'ServicePrincipal', 'id': TARGET}],
            'additionalDetails': [{'key': 'AppId', 'value': app}], 'id': 'synthetic-private-canary'}


class DirectoryHostedHandoffTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        key = subprocess.run(['age-keygen'], capture_output=True, check=True, text=True, timeout=10)
        cls.public = key.stderr.strip().removeprefix('Public key: ')
        cls.private = key.stdout.splitlines()[-1]

    def test_terminal_audit_scan_filters_catalog_union_and_tags_each_origin(self):
        lookups = []
        requests = []
        end = datetime.fromisoformat('2026-01-31T04:05:06Z')

        def get(url):
            if url == DIRECTORY_NEXT:
                success = [event(app) for app in (VERIFIED, NONVERIFIED, BOTH, ONLY_AUDIT, 'bad-value')]
                unresolved = event(ONLY_AUDIT) | {'additionalDetails': [], 'initiatedBy': {'app': {'appId': INITIATOR}}}
                rows = [*success, event(ONLY_AUDIT), unresolved, event(INITIATOR) | {'result': 'failure'}]
                for row in rows:
                    row['activityDateTime'] = '2026-01-01T10:00:00Z'
                return {'value': rows}
            if valid_directory_link(url):
                predicate = parse_qs(urlsplit(url).query)['$filter'][0]
                requests.append(('directory', predicate))
                if 'activityDateTime ge 2026-01-01T04:05:06Z' in predicate:
                    return {'value': [], '@odata.nextLink': DIRECTORY_NEXT}
                return {'value': []}
            if urlsplit(url).path == '/beta/auditLogs/signIns':
                predicate = parse_qs(urlsplit(url).query)['$filter'][0]
                requests.append(('sign-in', predicate))
                if ('createdDateTime ge 2026-01-01T04:05:06Z' in predicate
                        and "t eq 'interactiveUser'" in predicate):
                    return {'value': [{'appId': app, 'signInEventTypes': ['interactiveUser'],
                                       'createdDateTime': '2026-01-01T10:00:00Z'}
                                      for app in (BOTH, ONLY_SIGNIN, NONVERIFIED)]}
                return {'value': []}
            lookups.append(url)
            raise review_ci.HTTPFailure(404)

        with TemporaryDirectory() as folder:
            output = Path(folder) / 'github-output'
            summary = Path(folder) / 'github-step-summary'
            context = ENV | {'GITHUB_OUTPUT': str(output), 'TF_HANDOFF_RECIPIENT': self.public,
                             'GITHUB_STEP_SUMMARY': str(summary)}
            log = StringIO()
            with (redirect_stdout(log), patch.object(review_ci, 'graph_reader', return_value=get) as auth,
                  patch.object(review_ci, 'pinned_catalog_app_ids', return_value={VERIFIED, NONVERIFIED}),
                  patch.object(review_ci, 'collection_end', return_value=end)):
                review_ci.collect_job(context, directory=True)
            text = summary.read_text()
            self.assertIn('Requested 30 days ending at 2026-01-31T04:05:06Z', text)
            self.assertIn('| Directory provisioning | 2026-01-01T04:05:06Z | 2026-01-02T00:00:00Z | Terminal page, unresolved AppIds |', text)
            self.assertNotIn(BOTH, text)
            self.assertNotIn(BOTH, log.getvalue())
            prefix = 'Graph discovery coverage receipt '
            self.assertTrue(log.getvalue().startswith(prefix))
            receipt = json.loads(log.getvalue()[len(prefix):])
            self.assertEqual(receipt, {
                'catalogCommit': CATALOG_COMMIT, 'since': '2026-01-01T04:05:06Z',
                'until': '2026-01-31T04:05:06Z', 'providerRetention': 'unknown',
                'windowCounts': {
                    'interactiveUser': {'Terminal page': 1, 'Terminal page, no rows': 30},
                    **{category: {'Terminal page, no rows': 31} for category in GRAPH_EVENTS[1:]},
                    'Directory provisioning': {'Terminal page, unresolved AppIds': 1, 'Terminal page, no rows': 30},
                },
            })
            auth.assert_called_once_with(context, include_directory_audit=True)
            encoded = output.read_text().removeprefix('ciphertext=').strip()
            raw = open_envelope(base64.b64decode(encoded), ENV, self.private, categories=GRAPH_EVENTS, labeled=True, directory=True)
        expected = [
            ('sign-in', f"createdDateTime ge {utc(start)} and createdDateTime le {utc(stop)} "
                        f"and signInEventTypes/any(t: t eq '{category}')")
            for start, stop in intervals(end, 30) for category in GRAPH_EVENTS
        ] + [
            ('directory', f"activityDisplayName eq 'Add service principal' and activityDateTime ge {utc(start)} "
                          f"and activityDateTime le {utc(stop)}")
            for start, stop in intervals(end, 30)
        ]
        self.assertEqual(requests, expected)
        obj = json.loads(raw)
        self.assertEqual(obj['appIds'], [BOTH, ONLY_AUDIT, ONLY_SIGNIN])
        coverage = obj['directoryCoverage']
        self.assertEqual(coverage['status'], 'requested-windows-terminal;retention-unknown')
        windows = coverage['windows']
        self.assertEqual(len(windows), 31)
        self.assertEqual(windows[0], {
            'since': '2026-01-01T04:05:06Z', 'until': '2026-01-02T00:00:00Z', 'unresolvedAppIdRows': 2,
        })
        self.assertEqual(windows[-1], {
            'since': '2026-01-31T00:00:00Z', 'until': '2026-01-31T04:05:06Z', 'unresolvedAppIdRows': 0,
        })
        self.assertTrue(all(a['until'] == b['since'] for a, b in zip(windows, windows[1:])))
        self.assertEqual(obj['labels'], {
            app: [source, 'audience unknown', 'publisher unknown']
            for app, source in ((BOTH, 'sign-in and provisioning'), (ONLY_AUDIT, 'provisioning'),
                                (ONLY_SIGNIN, 'sign-in'))
        })
        self.assertEqual(lookups, [principal_url(app) for app in (BOTH, ONLY_AUDIT, ONLY_SIGNIN)])
        for secret in (VERIFIED, NONVERIFIED, TARGET, INITIATOR, 'synthetic-private-canary'):
            self.assertNotIn(secret, raw.decode())
        for bad in (windows[:-1], [windows[0], windows[0], *windows[2:]],
                    [windows[0] | {'unresolvedAppIdRows': True}, *windows[1:]]):
            changed = obj | {'directoryCoverage': coverage | {'windows': bad}}
            with self.assertRaises(ValueError):
                validate_handoff(json.dumps(changed).encode(), ENV, categories=GRAPH_EVENTS, labeled=True, directory=True)

        writer = {k: v for k, v in ENV.items() if k.startswith('GITHUB_') or k == 'TF_CATALOG_TIP'}
        writer.update(TF_HANDOFF_CIPHERTEXT=encoded, TF_REVIEW_ISSUE='151', TF_REVIEW_ISSUE_NODE='I_fixture151')
        prior_labels = ['sign-in', 'audience unknown', 'publisher unknown']
        initial = {'number': 151, 'node_id': 'I_fixture151', 'state': 'open', 'user': {'id': OWNER_ID},
                   'body': body_for({BOTH: prior_labels}, labeled=True)}
        expected = {BOTH: prior_labels, ONLY_AUDIT: obj['labels'][ONLY_AUDIT], ONLY_SIGNIN: obj['labels'][ONLY_SIGNIN]}
        updated = initial | {'body': body_for(expected, labeled=True)}
        rejected = Mock()
        with self.assertRaises(ValueError):
            review_ci.report_job(writer, self.private, rejected)
        rejected.assert_not_called()

        stale = Mock()
        with self.assertRaisesRegex(review_ci.CatalogMismatch, 'does not match the current published catalog'):
            review_ci.report_job(writer | {'TF_CATALOG_TIP': 'b' * 40}, self.private, stale, directory=True)
        stale.assert_not_called()

        api = Mock(side_effect=[initial, updated, updated])
        review_ci.report_job(writer, self.private, api, directory=True)
        review_ci.report_job(writer, self.private, api, directory=True)
        self.assertEqual(api.call_count, 3)
        self.assertEqual(api.call_args_list[1].args,
                         ('--method', 'PATCH', 'repos/nathanmcnulty/TokenForge/issues/151', '--input', '-'))
        self.assertEqual(json.loads(api.call_args_list[1].kwargs['body']), {'body': updated['body']})
        for wrong in (initial | {'node_id': 'I_wrong'}, initial | {'user': {'id': 99}}):
            rejected = Mock(return_value=wrong)
            with self.assertRaises(ValueError):
                review_ci.report_job(writer, self.private, rejected, directory=True)
            rejected.assert_called_once_with('repos/nathanmcnulty/TokenForge/issues/151')

    def test_daily_coverage_preserves_non_midnight_edges(self):
        finish = datetime.fromisoformat('2026-01-31T04:05:06Z')
        windows = [{'since': utc(start), 'until': utc(stop), 'unresolvedAppIdRows': 0}
                   for start, stop in intervals(finish, 30)]
        self.assertEqual(len(windows), 31)
        self.assertEqual((windows[0]['since'], windows[0]['until']),
                         ('2026-01-01T04:05:06Z', '2026-01-02T00:00:00Z'))
        self.assertEqual((windows[-1]['since'], windows[-1]['until']),
                         ('2026-01-31T00:00:00Z', '2026-01-31T04:05:06Z'))
        row = json.loads(signins()) | {
            'since': windows[0]['since'], 'until': windows[-1]['until'], 'appIds': [], 'labels': {},
            'directoryCoverage': {'status': 'requested-windows-terminal;retention-unknown', 'windows': windows},
        }
        self.assertEqual(validate_handoff(json.dumps(row).encode(), ENV, categories=GRAPH_EVENTS,
                                         labeled=True, directory=True), {})
        windows[0]['since'] = '2026-01-01T00:00:00Z'
        with self.assertRaises(ValueError):
            validate_handoff(json.dumps(row).encode(), ENV, categories=GRAPH_EVENTS, labeled=True, directory=True)

    def test_partial_provisioning_scan_stops_before_issue_handoff(self):
        with TemporaryDirectory() as folder:
            output = Path(folder) / 'github-output'
            get = Mock(side_effect=[
                {'value': [event(ONLY_AUDIT)], '@odata.nextLink': DIRECTORY_NEXT},
                review_ci.HTTPFailure(403),
            ])
            with (patch.object(review_ci, 'graph_reader', return_value=get),
                  patch.object(review_ci, 'pinned_catalog_app_ids', return_value=set()),
                  patch.object(review_ci, 'collection_end', return_value=END),
                  patch.object(review_ci, 'collect_envelope', return_value=signins())):
                with self.assertRaises(review_ci.HTTPFailure):
                    review_ci.collect_job(
                        ENV | {'GITHUB_OUTPUT': str(output), 'TF_HANDOFF_RECIPIENT': self.public}, directory=True)
            self.assertFalse(output.exists())
            self.assertEqual(get.call_count, 2)
            self.assertEqual(get.call_args.args, (DIRECTORY_NEXT,))

    def test_failed_app_only_sighting_produces_only_observed_signin_source(self):
        def get(url):
            if url == principal_url(EXTERNAL):
                return {'appId': EXTERNAL, 'servicePrincipalType': 'Application',
                        'signInAudience': 'AzureADandPersonalMicrosoftAccount',
                        'appOwnerOrganizationId': EXTERNAL_OWNER, 'verifiedPublisher': None}
            if valid_directory_link(url):
                return {'value': []}
            query = parse_qs(urlsplit(url).query)['$filter'][0]
            if "createdDateTime ge 2026-01-01T00:00:00Z" in query and "t eq 'servicePrincipal'" in query:
                row = {'appId': EXTERNAL, 'createdDateTime': '2026-01-01T10:00:00Z',
                       'signInEventTypes': ['servicePrincipal'], 'isInteractive': False,
                       'status': {'errorCode': 7000215, 'failureReason': 'synthetic-failure-canary'},
                       'resourceId': TARGET, 'appDisplayName': 'synthetic-external-workload'}
                return {'value': [row, row]}
            return {'value': []}

        class FixedDateTime(datetime):
            @classmethod
            def now(cls, tz):
                return datetime(2026, 1, 31, tzinfo=timezone.utc)

        with TemporaryDirectory() as folder:
            output = Path(folder) / 'github-output'
            reader = ENV | {'GITHUB_OUTPUT': str(output), 'TF_HANDOFF_RECIPIENT': self.public}
            with (patch.object(review_ci, 'graph_reader', return_value=get),
                  patch.object(review_ci, 'pinned_catalog_app_ids', return_value=set()),
                  patch('collect.datetime', FixedDateTime)):
                review_ci.collect_job(reader, directory=True)
            ciphertext = base64.b64decode(output.read_text().removeprefix('ciphertext=').strip())
            raw = open_envelope(ciphertext, ENV, self.private, categories=GRAPH_EVENTS, labeled=True, directory=True)
        labels = ['sign-in', 'multi-tenant and personal', 'publisher unknown']
        obj = json.loads(raw)
        self.assertEqual(obj['appIds'], [EXTERNAL])
        self.assertEqual(obj['labels'], {EXTERNAL: labels})
        self.assertTrue(all(w['unresolvedAppIdRows'] == 0 for w in obj['directoryCoverage']['windows']))
        issue_body = body_for(obj['labels'], labeled=True)
        for private in (EXTERNAL_OWNER, TARGET, '7000215', 'synthetic-failure-canary', 'synthetic-external-workload'):
            self.assertNotIn(private, raw.decode())
            self.assertNotIn(private, issue_body)
        for unsupported_claim in ('successful', 'microsoft', 'consent', 'provisioning'):
            self.assertNotIn(unsupported_claim, issue_body.casefold())

    def test_combined_cli_sanitizes_upstream_failures_without_a_handoff_or_issue_call(self):
        harness = r"""
import http.client
import json
import os
import runpy
import sys
from unittest.mock import patch

sys.path.insert(0, 'examples/signin-review')
import collect
import handoff
import report
import workload_http
from directory_provisioning import DIRECTORY_PATH

fault, app, canary = sys.argv[1:]
sys.argv = ['review_ci.py', 'collect-directory']
origin = 'https://graph.microsoft.com'
link = origin + DIRECTORY_PATH + '?$skiptoken=' + canary
event = {
    'activityDisplayName': 'Add service principal', 'activityDateTime': '2026-01-01T00:00:00Z',
    'result': 'success', 'targetResources': [{'type': 'ServicePrincipal', 'id': app}],
    'additionalDetails': [{'key': 'AppId', 'value': app}], 'id': canary,
}
seen = []
parser_raised = []

def read(url):
    seen.append(url)
    if len(seen) == 1:
        return {'value': [event], '@odata.nextLink': (link + '\x7f') if fault == 'continuation' else link}
    if fault == 'http':
        try:
            http.client.HTTPConnection('fixture.invalid').request('GET', '/?' + canary + app + '\x7f')
        except http.client.InvalidURL as error:
            parser_raised.append(type(error))
            assert canary in str(error)
            raise
    if fault == 'recursion':
        try:
            decoder = json.JSONDecoder()
            decoder.scan_once = json.scanner.py_make_scanner(decoder)
            return decoder.decode('[' * 4000 + json.dumps(canary) + ']' * 4000)
        except RecursionError as error:
            parser_raised.append(type(error))
            raise
    if fault == 'page' and url == link:
        return {'value': canary}
    if fault in ('page', 'continuation') and DIRECTORY_PATH in url:
        return {'value': []}
    raise AssertionError('Unexpected network route')

env = os.environ
raw = json.dumps(collect.handoff_identity(env) | {
    'since': '2026-01-01T00:00:00Z', 'until': '2026-01-31T00:00:00Z',
    'categories': list(collect.GRAPH_EVENTS), 'coverage': 'requested-windows-terminal;retention-unknown',
    'appIds': [app],
}).encode()
with (patch.object(http.client.HTTPConnection, 'connect', side_effect=AssertionError('Socket forbidden')) as network,
      patch.object(workload_http, 'graph_reader', return_value=read),
      patch.object(collect, 'collection_end', return_value=collect.datetime.fromisoformat('2026-01-31T00:00:00Z')),
      patch.object(collect, 'collect_envelope', return_value=raw),
      patch.object(collect, 'pinned_catalog_app_ids', return_value=set()),
      patch.object(handoff, 'seal') as seal, patch.object(report, 'report') as write_issue):
    try:
        runpy.run_path('examples/signin-review/review_ci.py', run_name='__main__')
    finally:
        network.assert_not_called()
        seal.assert_not_called()
        write_issue.assert_not_called()
        assert len(seen) == {'continuation': 30, 'page': 31, 'http': 2, 'recursion': 2}[fault]
        if fault == 'http':
            assert parser_raised == [http.client.InvalidURL]
        elif fault == 'recursion':
            assert parser_raised == [RecursionError]
"""
        with TemporaryDirectory() as folder:
            output = Path(folder) / 'github-output'
            for fault in ('http', 'recursion', 'page', 'continuation'):
                with self.subTest(fault=fault):
                    result = subprocess.run(
                        [sys.executable, '-B', '-c', harness, fault, ONLY_AUDIT, 'synthetic-private-canary'],
                        cwd=ROOT, env=ENV | {'GITHUB_OUTPUT': str(output), 'TF_CATALOG_TIP': CATALOG_COMMIT},
                        timeout=10, capture_output=True, text=True,
                        check=False)
                    self.assertEqual((result.returncode, result.stdout, result.stderr),
                                     (1, '', 'Sign-in candidate review stopped.\n'))
                    self.assertFalse(output.exists())

    def test_directory_cli_requires_an_explicit_command_on_manual_runs(self):
        entry = ROOT / 'examples' / 'signin-review' / 'review_ci.py'
        for command, kwargs in (('collect', {}), ('collect-directory', {'include_directory_audit': True})):
            for event_name, called in (('workflow_dispatch', True), ('schedule', False)):
                env = ENV | {'GITHUB_EVENT_NAME': event_name, 'TF_CATALOG_TIP': CATALOG_COMMIT}
                with (patch.dict(os.environ, env, clear=True), patch.object(sys, 'argv', [str(entry), command]),
                      patch('workload_http.graph_reader', side_effect=ValueError('synthetic-private-canary')) as reader):
                    with self.assertRaises(SystemExit) as result:
                        runpy.run_path(str(entry), run_name='__main__')
                    self.assertEqual(result.exception.code, 'Sign-in candidate review stopped.')
                    if called:
                        reader.assert_called_once_with(os.environ, **kwargs)
                    else:
                        reader.assert_not_called()

    def test_combined_cli_requires_a_catalog_commit_before_authentication_or_issue_update(self):
        entry = ROOT / 'examples' / 'signin-review' / 'review_ci.py'
        for command in ('collect-directory', 'issue-directory'):
            for tip in ('', 'not-a-commit'):
                env = ENV | {'TF_CATALOG_TIP': tip}
                if command == 'issue-directory':
                    env['TF_HANDOFF_IDENTITY'] = 'fixture'
                with (patch.dict(os.environ, env, clear=True),
                      patch.object(sys, 'argv', [str(entry), command]),
                      patch('workload_http.graph_reader') as reader,
                      patch('report.report') as writer):
                    with self.assertRaisesRegex(SystemExit, 'Sign-in candidate review stopped'):
                        runpy.run_path(str(entry), run_name='__main__')
                reader.assert_not_called()
                writer.assert_not_called()

    def test_combined_summary_marks_empty_unresolved_incomplete_and_unattempted_windows(self):
        def get(url):
            if valid_directory_link(url):
                predicate = parse_qs(urlsplit(url).query)['$filter'][0]
                if 'activityDateTime ge 2026-01-02' in predicate:
                    raise review_ci.HTTPFailure(503)
                return {'value': [event('private-unresolved-canary')]} if 'activityDateTime ge 2026-01-01' in predicate else {'value': []}
            predicate = parse_qs(urlsplit(url).query)['$filter'][0]
            if "t eq 'servicePrincipal'" in predicate:
                raise review_ci.HTTPFailure(403)
            if "t eq 'nonInteractiveUser'" in predicate and 'createdDateTime ge 2026-01-02' in predicate:
                raise review_ci.HTTPFailure(503)
            if "t eq 'managedIdentity'" in predicate and 'createdDateTime ge 2026-01-01' in predicate:
                return {'value': [{'signInEventTypes': ['managedIdentity'], 'appId': 'private-unresolved-canary',
                                   'createdDateTime': '2026-01-01T10:00:00Z'}]}
            return {'value': []}

        with TemporaryDirectory() as folder:
            output = Path(folder) / 'github-output'
            summary = Path(folder) / 'github-step-summary'
            context = ENV | {'GITHUB_OUTPUT': str(output), 'GITHUB_STEP_SUMMARY': str(summary)}
            log = StringIO()
            with (redirect_stdout(log), patch.object(review_ci, 'graph_reader', return_value=get),
                  patch.object(review_ci, 'collection_end', return_value=END),
                  patch.object(review_ci, 'pinned_catalog_app_ids', return_value=set())):
                with self.assertRaises(review_ci.HTTPFailure) as failure:
                    review_ci.collect_job(context, directory=True)
            self.assertEqual(failure.exception.status, 503)
            self.assertFalse(output.exists())
            result = summary.read_text()
        self.assertEqual(result.count('2026-01-31T00:00:00Z |'), 5)
        for source, day, status in (
            ('interactiveUser', 1, 'Terminal page, no rows'),
            ('nonInteractiveUser', 2, 'Incomplete traversal (HTTP 503)'),
            ('nonInteractiveUser', 3, 'Terminal page, no rows'),
            ('servicePrincipal', 1, 'Incomplete traversal (HTTP 403)'),
            ('servicePrincipal', 2, 'Unattempted'),
            ('managedIdentity', 1, 'Terminal page, unresolved AppIds'),
            ('managedIdentity', 30, 'Terminal page, no rows'),
            ('Directory provisioning', 1, 'Terminal page, unresolved AppIds'),
            ('Directory provisioning', 2, 'Incomplete traversal (HTTP 503)'),
            ('Directory provisioning', 30, 'Terminal page, no rows'),
        ):
            self.assertIn(f'| {source} | 2026-01-{day:02d}T00:00:00Z | 2026-01-{day+1:02d}T00:00:00Z | {status} |', result)
        self.assertNotIn('private-unresolved-canary', result)
        self.assertIn('Provider retention is unknown', result)
        self.assertNotIn('private-unresolved-canary', log.getvalue())
        receipt = json.loads(log.getvalue().removeprefix('Graph discovery coverage receipt '))
        self.assertEqual(receipt['windowCounts']['servicePrincipal'],
                         {'Incomplete traversal (HTTP 403)': 1, 'Unattempted': 29})
        self.assertEqual(receipt['windowCounts']['Directory provisioning'],
                         {'Incomplete traversal (HTTP 503)': 1, 'Terminal page, unresolved AppIds': 1,
                          'Terminal page, no rows': 28})


if __name__ == '__main__':
    unittest.main()
