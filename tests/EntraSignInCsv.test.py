import csv
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
START = '2026-01-05T00:00:00Z'
END = '2026-01-06T00:00:00Z'
HEADER = ('Date (UTC)', 'Application ID ', 'Resource ID ', 'Status', 'Username', 'IP address', 'Request ID',
          'Incoming token type', 'Incoming token type')
PRIVATE = ('synthetic-user', 'synthetic-ip', 'synthetic-request', 'synthetic-token-type', 'synthetic-token-type')


class EntraCsvTests(unittest.TestCase):
    setUp = fixtures.CatalogCandidateTests.setUp
    git = fixtures.CatalogCandidateTests.git
    unchanged = fixtures.CatalogCandidateTests.unchanged

    def export(self, rows, header=HEADER):
        path = self.repo / 'synthetic-private-input.csv'
        with path.open('w', newline='', encoding='utf-8-sig') as output:
            writer = csv.writer(output)
            writer.writerow(header)
            writer.writerows(rows)
        return path

    def run_adapter(self, path, *options):
        return subprocess.run(
            ['python3', '-B', str(ROOT / 'scripts/Import-TokenForgeEntraSignInCsv.py'),
             '--catalog-repo', str(self.repo), '--catalog-commit', self.commit,
             '--since', START, '--until', END, '--export-kind', 'InteractiveUser', *options, str(path)],
            text=True, capture_output=True, timeout=10,
        )

    def test_both_catalogs_and_resource_namespace_with_privacy(self):
        path = self.export([
            (START, fixtures.VERIFIED, fixtures.TARGET, 'Failure', *PRIVATE),
            ('2026-01-05 12:00:00', fixtures.NONVERIFIED, fixtures.VERIFIED, 'Success', *PRIVATE),
            ('2026-01-05T23:59:59.9999999Z', fixtures.NEW.upper(), fixtures.NONVERIFIED, 'Failure', *PRIVATE),
            ('2026-01-05T23:59:59Z', fixtures.NEW, fixtures.TARGET, 'Success', *PRIVATE),
            (END, fixtures.TARGET, fixtures.TARGET, 'Success', *PRIVATE),
        ])
        result = self.run_adapter(path)
        self.assertEqual(result.returncode, 0, result.stderr)
        report = json.loads(result.stdout)
        self.assertEqual(report['Counts']['UpperBoundaryRowsSkipped'], 1)
        self.assertEqual(report['Counts']['RowsInWindow'], 4)
        self.assertEqual(report['Candidates'], [{'AppId': fixtures.NEW, 'Disposition': 'Pending', 'CsvRows': 2}])
        self.assertEqual([(r['Identifier'], r['CsvRows'], r['ExactCatalogAppIdMatch']) for r in report['ObservedResources']],
                         [(fixtures.VERIFIED, 1, 'Verified'), (fixtures.NONVERIFIED, 1, 'NonVerified'),
                          (fixtures.TARGET, 2, 'NoExactMatch')])
        self.assertEqual(report['SourceWindowCoverage'], 'Unknown')
        self.assertFalse(report['TenantHistoryComplete'])
        self.assertEqual(report['ActualAudience'], 'UnknownFromEntraSignInExport')
        self.assertEqual(report['SignInOutcome'], 'NotEvaluated')
        self.assertNotRegex(result.stdout, 'synthetic-|Username|IP address|Request ID')
        self.assertEqual(self.run_adapter(path).stdout, result.stdout)
        self.unchanged()

    def test_operator_incomplete_date_and_invalid_id_are_accounted_for(self):
        path = self.export([
            ('synthetic-private-invalid-date', fixtures.VERIFIED, fixtures.TARGET, 'Failure', *PRIVATE),
            ('2026-01-06T00:00:00.0000001Z', fixtures.NEW, fixtures.TARGET, 'Success', *PRIVATE),
            (START, '', fixtures.TARGET, 'Success', *PRIVATE),
        ])
        result = self.run_adapter(path, '--export-kind', 'ManagedIdentity', '--export-status', 'PortalReportedIncomplete')
        self.assertEqual(result.returncode, 2, result.stderr)
        report = json.loads(result.stdout)
        self.assertEqual(report['ExportKind'], 'ManagedIdentity')
        self.assertEqual(report['IncompleteReasons'],
                         ['OperatorReportedIncompleteExport', 'UnusableOrOutOfWindowDates', 'UnusableIdentifiers'])
        self.assertEqual(report['Counts']['RowsOutsideWindow'], 1)
        self.assertEqual(report['Counts']['MalformedDates'], 1)
        self.assertEqual(report['Counts']['UnusableApplicationIds'], 1)
        self.assertEqual(report['Candidates'], [])
        self.assertEqual(report['ObservedResources'][0]['CsvRows'], 1)
        self.assertNotIn('synthetic-', result.stdout)
        self.unchanged()

    def test_cap_is_incomplete_even_after_operator_reports_success(self):
        row = (START, fixtures.NEW, fixtures.TARGET)
        path = self.export((row for _ in range(100_000)), header=HEADER[:3])
        command = self.run_adapter(path, '--export-status', 'PortalReportedSuccess')
        self.assertEqual(command.returncode, 2, command.stderr)
        results = json.loads(command.stdout)
        self.assertEqual(results['IncompleteReasons'], ['DocumentedRowCapReached'])
        self.assertEqual(results['Counts']['CsvRows'], 100_000)
        self.assertEqual(results['Candidates'][0]['CsvRows'], 100_000)

    def test_rejects_ambiguous_schema_and_unsafe_files_without_partial_output(self):
        cases = [
            self.export([], header=('Date (UTC)', 'Application ID', 'Application ID ', 'Resource ID')),
        ]
        fifo = self.repo / 'synthetic-fifo.csv'
        os.mkfifo(fifo)
        symlink = self.repo / 'synthetic-link.csv'
        symlink.symlink_to(cases[0])
        bad = self.repo / 'synthetic-width.csv'
        bad.write_text('Date (UTC),Application ID,Resource ID\nsynthetic-private-extra\n')
        for path in [*cases, fifo, symlink, bad]:
            with self.subTest(path=path.name):
                result = self.run_adapter(path)
                self.assertEqual(result.returncode, 1, result.stderr)
                self.assertFalse(result.stdout)
                self.assertNotIn('synthetic-', result.stderr)
        self.unchanged()


if __name__ == '__main__':
    unittest.main()
