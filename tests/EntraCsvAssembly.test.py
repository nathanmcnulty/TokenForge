import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import unittest


ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('csv_fixtures', ROOT / 'tests/EntraSignInCsv.test.py')
csv_fixtures = importlib.util.module_from_spec(spec)
spec.loader.exec_module(csv_fixtures)
fixtures = csv_fixtures.fixtures
START = '2026-01-05T00:00:00Z'
MID = '2026-01-05T12:00:00Z'
END = '2026-01-06T00:00:00Z'


class EntraCsvAssemblyTests(unittest.TestCase):
    setUp = csv_fixtures.EntraCsvTests.setUp
    git = csv_fixtures.EntraCsvTests.git
    unchanged = csv_fixtures.EntraCsvTests.unchanged
    export = csv_fixtures.EntraCsvTests.export

    def report(self, name, start=START, end=MID, kind='InteractiveUser'):
        path = self.export([
            (start, fixtures.NEW, fixtures.TARGET),
            (start, fixtures.TARGET, fixtures.NONVERIFIED),
            (start, fixtures.VERIFIED, fixtures.VERIFIED),
        ], header=csv_fixtures.HEADER[:3])
        result = subprocess.run(
            ['python3', '-B', str(ROOT/'scripts/Import-TokenForgeEntraSignInCsv.py'),
             '--catalog-repo', str(self.repo), '--catalog-commit', self.commit,
             '--since', start, '--until', end, '--export-kind', kind,
             '--export-status', 'PortalReportedSuccess', str(path)], text=True, capture_output=True, timeout=10,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        report = self.repo / name
        report.write_text(result.stdout)
        return report

    def merge(self, *reports, no_file=None):
        options = ['--no-file-receipts', str(no_file)] if no_file else []
        return subprocess.run(
            ['python3', '-B', str(ROOT/'scripts/Merge-TokenForgeEntraSignInCsvReports.py'),
             '--catalog-repo', str(self.repo), '--catalog-commit', self.commit,
             '--since', START, '--until', END, *options, *map(str, reports)],
            text=True, capture_output=True, timeout=10,
        )

    def test_equivalent_receipts_count_once_with_separate_category_observations(self):
        first = self.report('synthetic-absolute.json')
        following = self.report('synthetic-adjacent.json', MID, END)
        different_category = self.report('synthetic-service.json', START, END, 'ServicePrincipal')
        same = self.repo/'synthetic-duplicate.json'
        equivalent = json.loads(first.read_text())
        equivalent['Since'] = START
        equivalent['Candidates'].reverse()
        equivalent['ObservedResources'].reverse()
        same.write_text(json.dumps(equivalent))
        result = self.merge(first, following, different_category, same)
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertEqual(result.stdout, self.merge(different_category, same, following, first).stdout)
        assembled = json.loads(result.stdout)
        self.assertEqual(assembled['Inputs'][0]['DuplicateCopiesIgnored'], 1)
        self.assertEqual(assembled['Inputs'][0]['ExactInputSha256'],
                         sorted(hashlib.sha256(p.read_bytes()).hexdigest() for p in (first, same)))
        expected = [{'ExportKind': 'InteractiveUser', 'CsvRows': 2},
                    {'ExportKind': 'ServicePrincipal', 'CsvRows': 1}]
        self.assertEqual(assembled['Candidates'][0]['Observations'], expected)
        resources = {row['Identifier']: row for row in assembled['ObservedResources']}
        self.assertEqual(resources[fixtures.TARGET]['Observations'], expected)
        self.assertEqual(resources[fixtures.NONVERIFIED]['ExactCatalogAppIdMatch'], 'NonVerified')
        self.assertEqual(assembled['CountUnit'], 'CsvRows')
        self.assertEqual(assembled['SourceWindowCoverage'], 'Unknown')
        self.assertEqual(assembled['ActualAudience'], 'UnknownFromEntraSignInExport')
        self.assertNotIn('synthetic-', result.stdout)
        self.unchanged()

    def test_overlap_exclusion_and_cap_failure_missing_ledger(self):
        part = self.report('synthetic-absolute.json')
        relative = self.report('synthetic-preset-envelope.json', '2026-01-05T06:00:00Z', END)
        capped = self.report('synthetic-cap.json', START, END, 'ManagedIdentity')
        large = json.loads(capped.read_text())
        large['Counts'].update(CsvRows=100_000, RowsInWindow=100_000)
        large['ObservedResources'][0]['CsvRows'] += 99_997
        large['IncompleteReasons'] = ['DocumentedRowCapReached']
        capped.write_text(json.dumps(large))
        failed = dict(ExportKind='NonInteractiveUser', Since=START, UntilExclusive=MID, State='Incomplete')
        no_file = self.repo/'synthetic-failures.json'
        no_file.write_text(json.dumps([failed, failed]))
        result = self.merge(part, relative, capped, no_file=no_file)
        self.assertEqual(result.returncode, 2, result.stderr)
        assembled = json.loads(result.stdout)
        ledger = {kind: [w for w in assembled['Windows'] if w['ExportKind'] == kind] for kind in
                  ('InteractiveUser', 'NonInteractiveUser', 'ServicePrincipal', 'ManagedIdentity')}
        self.assertEqual([r['Status'] for r in ledger['InteractiveUser']],
                         ['ExcludedOverlap', 'OverlappingAggregates', 'ExcludedOverlap'])
        self.assertEqual([r['Status'] for r in ledger['NonInteractiveUser']], ['NoAggregate', 'Missing'])
        self.assertEqual([r['Status'] for r in ledger['ManagedIdentity']], ['ParsedWithIssues'])
        self.assertEqual(assembled['NoFileReceipts'][0]['DuplicateCopiesIgnored'], 1)
        self.assertEqual([p['Included'] for p in assembled['Inputs']], [False, False, True])
        self.assertEqual(assembled['Inputs'][-1]['IncompleteReasons'], ['DocumentedRowCapReached'])
        self.assertEqual(assembled['Candidates'][0]['Observations'], [{'ExportKind': 'ManagedIdentity', 'CsvRows': 1}])
        self.unchanged()

    def test_refuses_invalid_provenance_extra_fields_and_impossible_counts(self):
        path = self.report('synthetic-good.json')
        original = path.read_text()
        rejected = self.repo/'synthetic-rejected.json'
        for field, value in (
            ('CatalogCommit', '1'*40), ('Format', 'TokenForgeSignInCatalogGaps'), ('DocumentedRowCap', 100000.0),
            ('SourceWindowCoverage', 'Complete'), ('Unsafe', 'synthetic-private-canary'),
            ('Candidates', [{'AppId': fixtures.NONVERIFIED, 'Disposition': 'Pending', 'CsvRows': 1}]),
            ('ObservedResources', []), ('IncompleteReasons', ['DocumentedRowCapReached']),
        ):
            with self.subTest(field=field):
                data = json.loads(original)
                data[field] = value
                rejected.write_text(json.dumps(data))
                result = self.merge(path, rejected)
                self.assertEqual(result.returncode, 1, result.stderr)
                self.assertFalse(result.stdout)
                self.assertNotIn('synthetic-', result.stderr)
        result = self.merge(path, '/dev/null')
        self.assertEqual(result.returncode, 1)
        self.assertFalse(result.stdout)

    def test_complete_local_inputs_leave_provider_coverage_unknown(self):
        reports = [self.report(kind, START, END, kind) for kind in
                   ('InteractiveUser', 'NonInteractiveUser', 'ServicePrincipal', 'ManagedIdentity')]
        result = self.merge(*reports)
        self.assertEqual(result.returncode, 0, result.stderr)
        assembled = json.loads(result.stdout)
        self.assertTrue(all(row['Status'] == 'ParsedInput' for row in assembled['Windows']))
        self.assertFalse(assembled['TenantHistoryComplete'])
        self.assertEqual(assembled['SourceWindowCoverage'], 'Unknown')
        self.unchanged()


if __name__ == '__main__':
    unittest.main()
