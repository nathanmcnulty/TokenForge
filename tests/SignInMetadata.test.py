from datetime import datetime
import json
from pathlib import Path
import sys
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import Mock, patch
from urllib.parse import parse_qs, urlsplit

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'examples' / 'signin-review'))
import candidate_metadata as meta
from collect import GRAPH_EVENTS, REPOSITORY, REPOSITORY_ID, WORKFLOW_REF, handoff_identity, intervals, utc
import report
import review_ci

APP = '33333333-3333-4333-8333-333333333333'
TENANT = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa'
ENV = {'GITHUB_REPOSITORY': REPOSITORY, 'GITHUB_REPOSITORY_ID': REPOSITORY_ID, 'GITHUB_REF': 'refs/heads/main',
       'GITHUB_WORKFLOW_REF': WORKFLOW_REF, 'GITHUB_SHA': 'e' * 40, 'GITHUB_RUN_ID': '17',
       'GITHUB_RUN_ATTEMPT': '2', 'GITHUB_EVENT_NAME': 'workflow_dispatch',
       'TF_REVIEW_ISSUE': '57', 'TF_REVIEW_ISSUE_NODE': 'I_synthetic'}


def principal(**more):
    return {'appId': APP, 'appOwnerOrganizationId': TENANT, 'servicePrincipalType': 'Application',
            'verifiedPublisher': {'verifiedPublisherId': '123456', 'displayName': 'private-canary'}} | more


def raw(labels=None):
    obj = handoff_identity(ENV) | {
        'since': '2026-01-01T00:00:00Z', 'until': '2026-01-31T00:00:00Z',
        'categories': list(GRAPH_EVENTS), 'coverage': 'requested-windows-terminal;retention-unknown',
        'appIds': [APP],
    }
    if labels is not None:
        obj['labels'] = {APP: labels}
    return json.dumps(obj).encode()


class SignInMetadataTests(unittest.TestCase):
    def test_exact_read_only_alternate_key_and_select(self):
        url = meta.principal_url(APP)
        self.assertTrue(meta.is_principal_url(url))
        parsed = urlsplit(url)
        self.assertEqual(parsed.netloc, 'graph.microsoft.com')
        self.assertEqual(parsed.path, f"/v1.0/servicePrincipals(appId='{APP}')")
        self.assertEqual(parse_qs(parsed.query), {
            '$select': ['appId,signInAudience,appOwnerOrganizationId,servicePrincipalType,verifiedPublisher']})
        for wrong in (url + '&$top=1', url.replace('v1.0', 'beta'), url.replace('graph.microsoft.com', 'example.invalid')):
            self.assertFalse(meta.is_principal_url(wrong))

    def test_local_owner_multitenant_single_tenant_missing_and_conflicting(self):
        classify = lambda value: meta.classify_principal(APP, TENANT, value, 'sign-in')
        self.assertEqual(classify(principal(signInAudience='AzureADMultipleOrgs')),
                         ['sign-in', 'multi-tenant', 'verified publisher'])
        self.assertIsNone(classify(principal(signInAudience='AzureADMyOrg')))
        self.assertEqual(classify(principal(verifiedPublisher={'displayName': 'private-canary'})),
                         ['sign-in', 'audience unknown', 'publisher unknown'])
        self.assertEqual(classify(principal(signInAudience=['AzureADMyOrg', 'AzureADMultipleOrgs']))[1],
                         'audience unknown')
        self.assertIsNone(classify(principal(servicePrincipalType='ManagedIdentity')))
        self.assertEqual(classify(principal(servicePrincipalType='ManagedIdentity', signInAudience='AzureADMultipleOrgs'))[1],
                         'audience unknown')
        self.assertEqual(classify(None), ['sign-in', 'audience unknown', 'publisher unknown'])
        with self.assertRaises(ValueError):
            classify({'appId': TENANT})

    def test_explicit_unrecognized_and_conflicting_audiences_stay_visible_for_local_types(self):
        for principal_type in ('ManagedIdentity', 'Legacy'):
            for raw in ('', 'unrecognized', ['AzureADMyOrg', 'AzureADMultipleOrgs'], [], {}):
                value = principal(servicePrincipalType=principal_type, signInAudience=raw)
                result = meta.classify_principal(APP, TENANT, value, 'sign-in')
                self.assertEqual(result[1], 'audience unknown')
            for raw in (None, 'AzureADMyOrg'):
                value = principal(servicePrincipalType=principal_type, signInAudience=raw)
                self.assertIsNone(meta.classify_principal(APP, TENANT, value, 'sign-in'))

    def test_encrypted_labels_and_issue_validation_reject_raw_values(self):
        api = Mock()
        for bad in ([TENANT, 'multi-tenant', 'verified publisher'], ['sign-in', 'unknown-canary', 'publisher unknown'],
                    ['sign-in', 'audience unknown', 'private-canary']):
            with self.assertRaises(ValueError):
                report.report(ENV, raw(bad), api, categories=GRAPH_EVENTS, labeled=True)
        api.assert_not_called()
        labels = ['sign-in', 'multi-tenant', 'verified publisher']
        receipt = {'number': 57, 'node_id': 'I_synthetic', 'state': 'open', 'user': {'id': report.OWNER_ID},
                   'body': report.body_for({}, labeled=True)}
        api.side_effect = [receipt, receipt | {'body': report.body_for({APP: labels}, labeled=True)}]
        report.report(ENV, raw(labels), api, categories=GRAPH_EVENTS, labeled=True)
        self.assertEqual(json.loads(api.call_args.kwargs['body']), {'body': report.body_for({APP: labels}, labeled=True)})

    def test_lookup_transient_failure_produces_no_output(self):
        with TemporaryDirectory() as tmp:
            path = Path(tmp) / 'output'
            get = Mock(side_effect=review_ci.HTTPFailure(503))
            with (patch.object(review_ci, 'graph_reader', return_value=get),
                  patch.object(review_ci, 'pinned_catalog_app_ids', return_value=set()),
                  patch.object(review_ci, 'scan_directory', return_value={'appIds': [], 'windows': [
                      {'since': utc(start), 'until': utc(stop), 'counts': {}}
                      for start, stop in intervals(datetime.fromisoformat('2026-01-31T00:00:00Z'), 30)
                  ]}),
                  patch.object(review_ci, 'collect_envelope', return_value=raw())):
                with self.assertRaises(review_ci.HTTPFailure):
                    review_ci.collect_job(ENV | {'TF_AUDIT_TENANT_ID': TENANT, 'GITHUB_OUTPUT': str(path)})
            get.assert_called_once_with(meta.principal_url(APP))
            self.assertFalse(path.exists())


if __name__ == '__main__':
    unittest.main()
