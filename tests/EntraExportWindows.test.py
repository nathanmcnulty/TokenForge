import importlib.util
from pathlib import Path
import subprocess
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / 'scripts/Plan-TokenForgeEntraExportWindows.py'
sys.path.insert(0, str(ROOT / 'scripts'))
spec = importlib.util.spec_from_file_location('entra_export_windows', SCRIPT)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
START = '2026-01-05T00:00:00Z'
MID = '2026-01-06T00:00:00Z'
END = '2026-01-06T03:00:00Z'


class ExportWindowTests(unittest.TestCase):
    def plan(self, entries=()):
        return module.plan(module.instant(START), module.instant(END), 24, entries)

    def test_all_categories_have_disjoint_windows_and_a_short_final_slice(self):
        output = self.plan()
        self.assertEqual(len(output['Windows']), 8)
        for category in module.CATEGORIES:
            rows = [row for row in output['Windows'] if row['ExportKind'] == category]
            self.assertEqual([(r['Since'], r['UntilExclusive'], r['Status']) for r in rows],
                             [(START, MID, 'Missing'), (MID, END, 'Missing')])
        self.assertEqual(output['SourceWindowCoverage'], 'Unknown')
        self.assertFalse(output['TenantHistoryComplete'])

    def test_duplicate_statuses_are_counted_once_and_conflicts_are_explicit(self):
        first = dict(ExportKind='InteractiveUser', Since=START, UntilExclusive=MID, State='PortalReportedSuccess')
        conflict = dict(first, State='Incomplete')
        short = dict(first, Since=MID, UntilExclusive=END, State='Unavailable')
        result = self.plan((first, conflict, first, short))
        self.assertEqual(result, self.plan((short, first, first, conflict)))
        self.assertEqual(result['Windows'][0]['Status'], 'ConflictingReceipts')
        self.assertEqual(result['Windows'][0]['DuplicateReceiptsIgnored'], 1)
        self.assertEqual(result['Windows'][4]['Status'], 'Unavailable')
        self.assertEqual(result['Windows'][1]['Status'], 'Missing')

    def test_rejects_overlapping_and_extra_fields(self):
        first = dict(ExportKind='InteractiveUser', Since=START, UntilExclusive=MID, State='PortalReportedSuccess')
        for bad in (dict(first, UntilExclusive=END), dict(first, User='synthetic-private'),
                    dict(first, State='FullCoverage')):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                self.plan([bad])

    def test_cli_refuses_nonregular_input(self):
        result = subprocess.run(['python3', '-B', str(SCRIPT), '--since', START, '--until', END, '--receipts', '/dev/null'],
                                text=True, capture_output=True, timeout=10)
        self.assertEqual(result.returncode, 1)
        self.assertFalse(result.stdout)


if __name__ == '__main__':
    unittest.main()
