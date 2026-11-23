from datetime import datetime, timezone
import json
import os
from pathlib import Path
import sys
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import Mock, patch
from urllib.parse import unquote

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'examples' / 'signin-review'))
import directory_provisioning as provisioning
import workload_http as http

APP = '33333333-3333-4333-8333-333333333333'
OTHER = '44444444-4444-4444-8444-444444444444'
THIRD = '55555555-5555-4555-8555-555555555555'
FOURTH = '66666666-6666-4666-8666-666666666666'
FIFTH = '77777777-7777-4777-8777-777777777777'
VERIFIED = '11111111-1111-4111-8111-111111111111'
NONVERIFIED = '22222222-2222-4222-8222-222222222222'
END = datetime(2026, 1, 5, tzinfo=timezone.utc)
START = datetime(2026, 1, 4, tzinfo=timezone.utc)
NEXT = 'https://graph.microsoft.com/v1.0/auditLogs/directoryAudits?$skiptoken=fixture'
ENV = {'TF_AUDIT_TENANT_ID': 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
       'TF_AUDIT_CLIENT_ID': 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb'}


def event(**extra):
    return {'activityDisplayName': 'Add service principal', 'activityDateTime': '2026-01-04T12:00:00Z',
            'result': 'success', 'initiatedBy': {'app': {'appId': APP}},
            'targetResources': [{'type': 'ServicePrincipal', 'id': OTHER, 'displayName': THIRD,
                                 'modifiedProperties': [{'displayName': 'AppId', 'newValue': FOURTH}]}],
            'additionalDetails': [{'key': 'AppOwnerOrganizationId', 'value': FIFTH},
                                  {'key': 'ServicePrincipalProvisioningType', 'value': 'private-canary'}]} | extra


def evidence(*rows):
    return {'format': 'TokenForgeAttendedTargetAppIdEvidenceV1', 'rows': list(rows)}


def row(app, audiences=None, local=False):
    return {'targetAppId': app, 'audiences': audiences or [], 'localManagedIdentity': local}


class ProvisioningTests(unittest.TestCase):
    def test_only_successful_in_window_and_unproven_fields_are_never_ids(self):
        get = Mock(side_effect=[{'value': [], '@odata.nextLink': NEXT}, {
            'value': [event(), event(targetResources=[]), event(result='failure'),
                      event(result=None), event(activityDateTime='2026-01-05T00:00:00Z')],
        }])
        report = provisioning.scan_directory(get, END, 1)
        self.assertEqual(report['appIdMapping'], 'unproven')
        self.assertEqual(report['windows'][0]['counts'], {'successfulUnresolvedAppId': 2, 'ambiguousPrincipalTarget': 1,
                         'notSuccessful': 1, 'unknownResult': 1, 'ownerCluePresent': 2, 'provisioningTypePresent': 2})
        self.assertIn("activityDisplayName eq 'Add service principal'", unquote(get.call_args_list[0].args[0]).replace('+', ' '))
        for hidden in (APP, OTHER, THIRD, FOURTH, FIFTH, 'private-canary', NEXT):
            self.assertNotIn(hidden, json.dumps(report))

    def test_untrusted_continuation_or_wrong_interval_never_counts_complete(self):
        for bad in (NEXT.replace('graph.microsoft.com', 'example.invalid'), NEXT.replace('/v1.0', '/beta'), NEXT + '#frag'):
            get = Mock(return_value={'value': [], '@odata.nextLink': bad})
            with self.assertRaises(ValueError):
                provisioning.scan_window(get, START, END)
            self.assertEqual(get.call_count, 1)
        with self.assertRaises(ValueError):
            provisioning.scan_window(Mock(return_value={'value': [event(activityDateTime='2026-01-05T00:00:00.0000001Z')]}), START, END)

    def test_directory_endpoint_is_explicit_opt_in_and_uses_same_transport(self):
        token = {'token_type': 'Bearer', 'access_token': 'fixture-only'}
        with (patch.object(http, 'get_assertion', return_value=('fixture-assertion', {})),
              patch.object(http, 'check', return_value={'exact': True}),
              patch.object(http, 'request_json', side_effect=[token, token, {'value': []}]) as request):
            restricted = http.graph_reader(ENV)
            with self.assertRaises(ValueError):
                restricted(NEXT)
            opt_in = http.graph_reader(ENV, include_directory_audit=True)
            self.assertEqual(opt_in(NEXT), {'value': []})
        self.assertEqual(request.call_count, 3)
        self.assertEqual(request.call_args.args, (NEXT,))
        self.assertEqual(request.call_args.kwargs['headers']['Authorization'], 'Bearer fixture-only')

    def test_attended_dedupe_union_and_conservative_audience_rules(self):
        report = provisioning.normalize_replay(evidence(
            row(VERIFIED), row(NONVERIFIED), row(APP, ['AzureADMultipleOrgs']), row(APP, ['AzureADMultipleOrgs']),
            row(OTHER, ['AzureADMyOrg']), row(THIRD),
            row(FOURTH, ['AzureADMyOrg']), row(FOURTH, ['AzureADMultipleOrgs']),
            row(FIFTH, local=True),
        ), {VERIFIED, NONVERIFIED}, [APP])
        self.assertEqual(report['candidates'], {
            APP: ['sign-in and provisioning', 'multi-tenant', 'publisher unknown'],
            THIRD: ['provisioning', 'audience unknown', 'publisher unknown'],
            FOURTH: ['provisioning', 'audience unknown', 'publisher unknown'],
        })

    def test_raw_fields_malformed_ids_and_special_files_are_rejected(self):
        for raw in (event(), row([APP]), row(APP) | {'initiatedBy': THIRD}, row(APP) | {'appOwnerOrganizationId': APP}):
            with self.assertRaises(ValueError):
                provisioning.normalize_replay(evidence(raw), set())
        with TemporaryDirectory() as directory:
            path = Path(directory) / 'sample.pipe'
            os.mkfifo(path)
            with self.assertRaises(ValueError):
                provisioning.main([str(path), directory, 'a' * 40])


if __name__ == '__main__':
    unittest.main()
