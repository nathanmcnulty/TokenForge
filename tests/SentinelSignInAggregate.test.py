import importlib.util
import json
import os
from pathlib import Path
import subprocess
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('catalog_fixtures', ROOT / 'tests/CatalogCandidateImport.test.py')
fixtures = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixtures)
SAMPLE = ROOT / 'tests/fixtures/sentinel-signin/aggregate.json'


class SentinelAggregateTests(unittest.TestCase):
    setUp = fixtures.CatalogCandidateTests.setUp
    git = fixtures.CatalogCandidateTests.git
    unchanged = fixtures.CatalogCandidateTests.unchanged

    def run_import(self, path=SAMPLE, commit=None):
        return subprocess.run(
            ['python3', '-B', str(ROOT / 'scripts/Import-TokenForgeSentinelSignInAggregate.py'),
             '--catalog-repo', str(self.repo), '--catalog-commit', commit or self.commit, str(path)],
            text=True, capture_output=True, timeout=10)

    def test_synthetic_aggregate_checks_both_partitions_and_keeps_resource_namespaces(self):
        result = self.run_import()
        self.assertEqual(result.returncode, 0, result.stderr)
        report = json.loads(result.stdout)
        self.assertEqual(report['CatalogCommit'], self.commit)
        self.assertEqual(report['ActualAudience'], 'UnknownFromSentinelSignInLogs')
        self.assertFalse(report['TenantHistoryComplete'])
        self.assertEqual(report['WorkspaceAvailability'], 'Unknown')
        self.assertEqual(report['RetentionCoverage'], 'Unknown')
        self.assertEqual(report['Candidates'], [{
            'AppId': fixtures.NEW, 'Disposition': 'Pending',
            'Observations': [{'Table': 'AADNonInteractiveUserSignInLogs', 'Count': 4},
                             {'Table': 'AADServicePrincipalSignInLogs', 'Count': 1}],
        }])
        fields = {(r['Table'], r['SourceField']): r['ExactCatalogAppIdMatch'] for r in report['ObservedResources']}
        self.assertEqual(fields, {
            ('AADNonInteractiveUserSignInLogs', 'ResourceIdentity'): 'Verified',
            ('SigninLogs', 'ResourceId'): 'NonVerified',
            ('SigninLogs', 'ResourceIdentity'): 'NoExactMatch',
            ('SigninLogs', 'ResourceServicePrincipalId'): 'NotComparable',
        })
        self.assertNotIn('GraphResourceId', result.stdout)
        self.assertTrue(all(row['Availability'] == 'Unknown' for row in report['Tables']))
        self.unchanged()

    def test_table_receipts_distinguish_empty_unavailable_and_missing_aggregates(self):
        value = json.loads(SAMPLE.read_bytes())
        value['Tables'] = [
            {'Table': 'SigninLogs', 'State': 'Supplied', 'Rows': []},
            {'Table': 'AADManagedIdentitySignInLogs', 'State': 'Unavailable', 'Rows': []},
        ]
        path = self.repo / 'partial.json'
        path.write_text(json.dumps(value))
        result = self.run_import(path)
        self.assertEqual(result.returncode, 0, result.stderr)
        report = json.loads(result.stdout)
        self.assertEqual({row['Table']: row['InputState'] for row in report['Tables']},
                         {'SigninLogs': 'Supplied', 'AADManagedIdentitySignInLogs': 'Unavailable',
                          'AADServicePrincipalSignInLogs': 'NotProvided', 'AADNonInteractiveUserSignInLogs': 'NotProvided'})
        self.assertEqual(report['Candidates'], [])
        self.assertTrue(all(row['Availability'] == 'Unknown' for row in report['Tables']))
        self.unchanged()

    def test_deterministic_output_and_managed_identity_uses_its_actual_app_id(self):
        value = json.loads(SAMPLE.read_bytes())
        value['Tables'][-1].update(State='Supplied', Rows=[
            {'Field': 'AppId', 'Identifier': fixtures.NEW, 'Count': 2},
            {'Field': 'ResourceServicePrincipalId', 'Identifier': fixtures.NEW, 'Count': 2},
        ])
        path = self.repo / 'aggregate.json'
        path.write_text(json.dumps(value))
        first = self.run_import(path)
        self.assertEqual(first.returncode, 0, first.stderr)
        value['Tables'].reverse()
        for table in value['Tables']:
            table['Rows'].reverse()
        path.write_text(json.dumps(value, sort_keys=True))
        second = self.run_import(path)
        self.assertEqual(first.stdout, second.stdout)
        report = json.loads(first.stdout)
        managed = report['Candidates'][0]['Observations'][0]
        self.assertEqual(managed, {'Table': 'AADManagedIdentitySignInLogs', 'Count': 2})
        self.assertEqual(report['ObservedResources'][0]['ExactCatalogAppIdMatch'], 'NotComparable')
        self.unchanged()

    def test_invalid_or_private_fields_are_refused_without_partial_output(self):
        path = self.repo / 'invalid.json'
        for case in ('private-field', 'unsupported-resource', 'spoofed-app', 'duplicate-row',
                     'duplicate-table', 'unavailable-with-rows', 'invalid-count', 'invalid-interval'):
            with self.subTest(case=case):
                value = json.loads(SAMPLE.read_bytes())
                first = value['Tables'][0]
                rec = first['Rows'][0]
                if case == 'private-field':
                    rec['UnrecognizedField'] = 'synthetic-reject-canary'
                elif case == 'unsupported-resource':
                    value['Tables'][1]['Rows'][0]['Field'] = 'ResourceId'
                elif case == 'spoofed-app':
                    rec['Identifier'] = [fixtures.NEW]
                elif case == 'duplicate-row':
                    first['Rows'].append(rec)
                elif case == 'duplicate-table':
                    value['Tables'].append(first)
                elif case == 'unavailable-with-rows':
                    first['State'] = 'Unavailable'
                elif case == 'invalid-count':
                    rec['Count'] = True
                else:
                    value['UntilExclusive'] = value['Since']
                path.write_text(json.dumps(value))
                result = self.run_import(path)
                self.assertEqual(result.returncode, 1)
                self.assertEqual(result.stdout, '')
                self.assertNotIn('synthetic-reject-canary', result.stderr)
        self.unchanged()

    def test_pinned_catalog_and_regular_file_input(self):
        tree = self.git('rev-parse', 'HEAD^{tree}').stdout.strip()
        self.assertEqual(self.run_import(commit=tree).returncode, 1)
        fifo = self.repo / 'nonregular'
        os.mkfifo(fifo)
        self.assertEqual(self.run_import(fifo).returncode, 1)
        self.unchanged()


if __name__ == '__main__':
    unittest.main()
