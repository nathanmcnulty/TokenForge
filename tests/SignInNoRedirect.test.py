from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import sys
from tempfile import TemporaryDirectory
from threading import Thread
import unittest
from unittest.mock import Mock, patch
from urllib.parse import parse_qs, unquote

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'examples' / 'signin-review'))
from collect import GRAPH_EVENTS, IncompleteCategory, gather
import collect
import review_ci
import workload_http as http

WORKLOAD = {
    'TF_AUDIT_TENANT_ID': 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
    'TF_AUDIT_CLIENT_ID': 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb',
}
ENV = WORKLOAD | {
    'GITHUB_REPOSITORY': collect.REPOSITORY, 'GITHUB_REPOSITORY_ID': collect.REPOSITORY_ID,
    'GITHUB_REF': 'refs/heads/main', 'GITHUB_EVENT_NAME': 'workflow_dispatch',
    'GITHUB_WORKFLOW_REF': collect.WORKFLOW_REF, 'GITHUB_SHA': 'e' * 40,
    'GITHUB_RUN_ID': '17', 'GITHUB_RUN_ATTEMPT': '2', 'TF_HANDOFF_RECIPIENT': 'unused-on-failure',
}
NEXT = 'https://graph.microsoft.com/beta/auditLogs/signIns?$skiptoken=fixture'
END = datetime(2026, 1, 5, tzinfo=timezone.utc)


class NoRedirectTests(unittest.TestCase):
    def test_actual_http_opener_rejects_redirects_without_forwarding_headers(self):
        requests = []

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                requests.append((self.path, self.headers.get('Authorization')))
                if self.path == '/sink':
                    self.send_response(200)
                    self.end_headers()
                    self.wfile.write(b'{}')
                    return
                self.send_response(int(self.path[1:]))
                self.send_header('Location', '/sink')
                self.end_headers()

            def log_message(self, *_):
                pass

        with ThreadingHTTPServer(('127.0.0.1', 0), Handler) as server:
            thread = Thread(target=server.serve_forever, kwargs={'poll_interval': 0.01}, daemon=True)
            thread.start()
            codes = (301, 302, 303, 307, 308)
            try:
                for code in codes:
                    with self.assertRaises(http.HTTPFailure) as error:
                        http.request_json(f'http://127.0.0.1:{server.server_port}/{code}',
                                          headers={'Authorization': 'Bearer fixture-only'})
                    self.assertEqual(error.exception.status, code)
            finally:
                server.shutdown()
                thread.join(timeout=2)
        self.assertEqual(requests, [(f'/{code}', 'Bearer fixture-only') for code in codes])

    def test_same_workload_endpoint_and_graph_retry_delay(self):
        token = {'token_type': 'Bearer', 'access_token': 'fixture-only'}
        with (patch.object(http, 'get_assertion', return_value=('fixture-assertion', {})),
              patch.object(http, 'check', return_value={'exact': True}),
              patch.object(http, 'request_json', side_effect=[token, http.HTTPFailure(429, '2'), {'value': []}]) as request,
              patch.object(http.time, 'sleep') as sleep):
            fetch = http.graph_reader(WORKLOAD)
            with self.assertRaises(ValueError):
                fetch('https://example.invalid/beta/auditLogs/signIns?x=y')
            self.assertEqual(fetch(NEXT), {'value': []})
        auth, first, again = request.call_args_list
        self.assertEqual(auth.args, (f"https://login.microsoftonline.com/{WORKLOAD['TF_AUDIT_TENANT_ID']}/oauth2/v2.0/token",))
        self.assertEqual(auth.kwargs['method'], 'POST')
        fields = parse_qs(auth.kwargs['data'].decode())
        self.assertEqual(fields['scope'], ['https://graph.microsoft.com/.default'])
        self.assertEqual(fields['grant_type'], ['client_credentials'])
        self.assertEqual(first, again)
        self.assertEqual(first.kwargs['headers']['Authorization'], 'Bearer fixture-only')
        sleep.assert_called_once_with(2)

    def test_all_four_categories_and_distinct_endpoint_reads(self):
        get = Mock(return_value={'value': []})
        self.assertEqual(gather(get, END, 1, set()), [])
        self.assertEqual(get.call_count, 4)
        for call, category in zip(get.call_args_list, GRAPH_EVENTS):
            q = unquote(call.args[0]).replace('+', ' ')
            self.assertIn(f"signInEventTypes/any(t: t eq '{category}')", q)
            self.assertIn('createdDateTime ge ', q)
            self.assertNotIn('appOwnerTenantId', q)

    def test_initial_or_paged_redirect_fails_with_no_handoff_output(self):
        for responses in ([http.HTTPFailure(302)], [{'value': [], '@odata.nextLink': NEXT}, http.HTTPFailure(307)]):
            get = Mock(side_effect=responses)
            with TemporaryDirectory() as temp:
                path = Path(temp) / 'github-output'
                catalog = Mock()
                catalog.partition.return_value = {'Applications': {}}
                catalog.app_ids.return_value = set()
                with patch.object(review_ci, 'graph_reader', return_value=get), patch.object(collect, 'OfflineCatalog', return_value=catalog):
                    with self.assertRaises(IncompleteCategory):
                        review_ci.collect_job(ENV | {'GITHUB_OUTPUT': str(path)})
                self.assertFalse(path.exists())
                self.assertEqual(get.call_count, len(responses))

    def test_provider_denial_stays_an_explicit_incomplete_category(self):
        get = Mock(side_effect=[{'value': []}, {'value': []}, http.HTTPFailure(403)])
        with self.assertRaisesRegex(IncompleteCategory, r'servicePrincipal \(HTTP 403\)'):
            gather(get, END, 1, set())
        self.assertEqual(get.call_count, 3)

    def test_rejects_noncanonical_base64_before_decryption(self):
        issue = Mock()
        with patch.object(review_ci, 'open_envelope') as decrypt:
            with self.assertRaisesRegex(ValueError, 'Noncanonical'):
                writer = {key: value for key, value in ENV.items() if key.startswith('GITHUB_')}
                review_ci.report_job(writer | {'TF_HANDOFF_CIPHERTEXT': 'Zh=='}, 'unused', issue)
            decrypt.assert_not_called()
        issue.assert_not_called()


if __name__ == '__main__':
    unittest.main()
