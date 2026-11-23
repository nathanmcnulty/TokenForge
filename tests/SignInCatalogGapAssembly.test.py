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
SINCE = '2026-01-05T00:00:00Z'
MIDDLE = '2026-01-06T00:00:00Z'
UNTIL = '2026-01-07T00:00:00Z'


class AssemblyTests(unittest.TestCase):
    setUp = fixtures.CatalogCandidateTests.setUp
    git = fixtures.CatalogCandidateTests.git
    unchanged = fixtures.CatalogCandidateTests.unchanged

    def report(self, name, start, end, observed=None, failed=False):
        event = {'id': 'synthetic-private-event-' + name, 'appId': fixtures.NEW, 'resourceId': fixtures.TARGET,
                 'createdDateTime': observed or start, 'isInteractive': True,
                 'userPrincipalName': 'synthetic-private-user'}
        page = {'value': [event]}
        if failed:
            page['@odata.nextLink'] = 'https://graph.microsoft.com/v1.0/auditLogs/signIns?$skiptoken=synthetic-private-link'
        folder = self.repo / name
        folder.mkdir()
        (folder / 'window-1-page-1.json').write_text(json.dumps(page))
        producer = subprocess.run(
            ['pwsh', '-NoProfile', '-File', str(ROOT/'scripts/Find-TokenForgeSignInCatalogGaps.ps1'),
             '-CatalogRepository', str(self.repo), '-CatalogCommit', self.commit,
             '-Since', start, '-Until', end, '-FixtureDirectory', str(folder)],
            text=True, capture_output=True)
        self.assertEqual(producer.returncode, 2 if failed else 0, producer.stderr)
        report = self.repo / (name + '.json')
        report.write_text(producer.stdout)
        return report

    def merge(self, *reports, start=SINCE, end=UNTIL, version='v1.0'):
        return subprocess.run(
            ['python3', '-B', str(ROOT/'scripts/Merge-TokenForgeSignInCatalogGaps.py'),
             '--catalog-repo', str(self.repo), '--catalog-commit', self.commit, '--since', start,
             '--until', end, '--graph-version', version, *map(str, reports)], text=True, capture_output=True, timeout=10)

    def test_adjacent_reports_and_duplicate_copy_are_deterministic(self):
        first = self.report('first', SINCE, MIDDLE, '2026-01-05T23:59:59.9999999Z')
        second = self.report('second', MIDDLE, UNTIL)
        copy = self.repo/'copy.json'
        equivalent = json.loads(first.read_bytes().replace(b'+00:00', b'Z'))
        equivalent['Candidates'].reverse()
        copy.write_text(json.dumps(equivalent, sort_keys=True))
        result = self.merge(first, second, copy)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.merge(copy, second, first).stdout, result.stdout)
        report = json.loads(result.stdout)
        self.assertTrue(report['InputCoverageComplete'])
        self.assertEqual(report['SourceWindowCoverage'], 'Unknown')
        self.assertFalse(report['TenantHistoryComplete'])
        self.assertEqual(report['ActualAudience'], 'UnknownFromSignInLogs')
        self.assertEqual([row['DuplicateCopiesIgnored'] for row in report['Inputs']], [1, 0])
        self.assertEqual([row['UniqueEvents'] for row in report['Inputs']], [1, 1])
        self.assertEqual([(r['IdentifierKind'], r['Identifier'], r['Count']) for r in report['Candidates']],
                         [('AppId', fixtures.NEW, 2), ('GraphResourceId', fixtures.TARGET, 2)])
        self.assertEqual(report['Candidates'][0]['FirstObservedAt'], '2026-01-05T23:59:59.9999999Z')
        self.assertEqual(report['Candidates'][0]['LastObservedAt'], '2026-01-06T00:00:00.0000000Z')
        self.assertNotIn('synthetic-private', result.stdout)
        self.unchanged()

    def test_missing_and_incomplete_windows_are_explicit(self):
        first = self.report('first-partial', SINCE, MIDDLE, failed=True)
        result = self.merge(first)
        self.assertEqual(result.returncode, 2, result.stderr)
        report = json.loads(result.stdout)
        self.assertEqual([row['Status'] for row in report['Windows']], ['ReplayIncomplete', 'Missing'])
        self.assertEqual(report['Windows'][0]['Inputs'][0]['WindowStatus'], 'FixtureUnavailable')
        self.assertFalse(report['InputCoverageComplete'])
        self.assertEqual([r['Count'] for r in report['Candidates']], [1, 1])
        self.assertNotIn('synthetic-private', result.stdout)
        self.unchanged()

    def test_overlapping_inputs_are_excluded_including_their_tails(self):
        first = self.report('first', SINCE, MIDDLE)
        second = self.report('second', '2026-01-05T12:00:00Z', '2026-01-06T12:00:00Z')
        last = self.report('last', '2026-01-06T12:00:00Z', UNTIL)
        result = self.merge(first, second, last)
        self.assertEqual(result.returncode, 2, result.stderr)
        report = json.loads(result.stdout)
        self.assertEqual([row['Status'] for row in report['Windows']],
                         ['ExcludedOverlap', 'OverlappingReports', 'ExcludedOverlap', 'ReplayComplete'])
        self.assertEqual([row['Included'] for row in report['Inputs']], [False, False, True])
        self.assertEqual([r['Count'] for r in report['Candidates']], [1, 1])
        self.unchanged()

    def test_wrong_commit_known_ids_and_forged_coverage_are_rejected(self):
        original = self.report('original', SINCE, MIDDLE)
        modified = self.repo / 'altered.json'
        for field, value in [('CatalogCommit', '1'*40), ('SourceWindowCoverage', 'Complete'),
                             ('TenantHistoryComplete', True)]:
            with self.subTest(field=field):
                payload = json.loads(original.read_bytes())
                payload[field] = value
                modified.write_text(json.dumps(payload))
                result = self.merge(modified)
                self.assertEqual(result.returncode, 1, result.stderr)
                self.assertFalse(result.stdout)
        for identifier in (fixtures.VERIFIED, fixtures.NONVERIFIED):
            payload = json.loads(original.read_bytes())
            payload['Candidates'][0]['Identifier'] = identifier
            modified.write_text(json.dumps(payload))
            self.assertEqual(self.merge(modified).returncode, 1)
        self.assertEqual(self.merge(original, version='beta').returncode, 1)
        self.assertEqual(self.merge(original, start=MIDDLE).returncode, 1)
        self.unchanged()

    def test_extra_fields_and_nonstandard_json_never_affect_fingerprints(self):
        original = self.report('original', SINCE, MIDDLE)
        baseline = self.merge(original, end=MIDDLE)
        self.assertEqual(baseline.returncode, 0, baseline.stderr)
        invalid = self.repo / 'invalid.json'
        for target in ('report', 'window', 'candidate', 'event_counts', 'wrong_nested_shape'):
            with self.subTest(target=target):
                value = json.loads(original.read_bytes())
                locations = {'report': value, 'window': value['Windows'][0], 'candidate': value['Candidates'][0],
                             'event_counts': value['Candidates'][0]['EventTypeCounts']}
                if target == 'wrong_nested_shape':
                    value['Windows'][0] = ['synthetic-private-extra']
                else:
                    locations[target]['synthetic-private-extra'] = {'payload': 'synthetic-private-value'}
                invalid.write_text(json.dumps(value))
                result = self.merge(original, invalid, end=MIDDLE)
                self.assertEqual(result.returncode, 1)
                self.assertEqual(result.stdout, '')
                self.assertNotIn('synthetic-private', result.stderr)
        for broken in ('NaN', 'Infinity', '-Infinity', '1e999', 'true'):
            value = json.loads(original.read_bytes())
            value['Candidates'][0]['Count'] = 'REPLACE_TEST_VALUE'
            invalid.write_text(json.dumps(value).replace('"REPLACE_TEST_VALUE"', broken))
            result = self.merge(original, invalid, end=MIDDLE)
            self.assertEqual(result.returncode, 1)
            self.assertEqual(result.stdout, '')
        self.assertEqual(self.merge(original, end=MIDDLE).stdout, baseline.stdout)
        self.unchanged()

    def test_impossible_candidate_and_snapshot_counts_are_refused(self):
        original = self.report('original', SINCE, MIDDLE)
        changed = self.repo / 'changed.json'
        mutations = ('over_total', 'snapshot_pages', 'per_kind_unusable', 'byCatalog')
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                value = json.loads(original.read_bytes())
                if mutation == 'over_total':
                    value['Candidates'].append({**value['Candidates'][0], 'Identifier': fixtures.TARGET})
                elif mutation == 'snapshot_pages':
                    value['Source'] = 'LocalSnapshot'
                    value['Windows'][0]['Pages'] = 2
                elif mutation == 'per_kind_unusable':
                    value['Windows'][0]['UnusableAppIds'] = 1
                else:
                    value['byCatalog'] = {'Verified': 999999}
                changed.write_text(json.dumps(value))
                result = self.merge(changed)
                self.assertEqual(result.returncode, 1, result.stderr)
                self.assertEqual(result.stdout, '')
        self.unchanged()

    def test_candidate_endpoint_cannot_be_attributed_to_empty_or_unusable_window(self):
        original = self.report('original', SINCE, MIDDLE)
        changed = self.repo/'two-windows.json'
        value = json.loads(original.read_bytes())
        value['UntilExclusive'] = UNTIL
        value['Windows'].append({**value['Windows'][0], 'Since': MIDDLE, 'UntilExclusive': UNTIL, 'UniqueEvents': 0})
        changed.write_text(json.dumps(value))
        self.assertEqual(self.merge(changed).returncode, 0)
        value['Candidates'][0].update(FirstObservedAt=MIDDLE, LastObservedAt=MIDDLE)
        for count, unusable in ((0, 0), (1, 1)):
            value['Windows'][1].update(UniqueEvents=count, UnusableAppIds=unusable)
            changed.write_text(json.dumps(value))
            result = self.merge(changed)
            self.assertEqual(result.returncode, 1)
            self.assertEqual(result.stdout, '')
        self.unchanged()

    def test_candidates_cannot_compete_for_the_same_endpoint_capacity(self):
        original = self.report('original', SINCE, MIDDLE)
        changed = self.repo / 'two-candidates.json'
        value = json.loads(original.read_bytes())
        value['UntilExclusive'] = UNTIL
        value['Windows'].append({**value['Windows'][0], 'Since': MIDDLE, 'UntilExclusive': UNTIL})
        # Global count two fits two events, but both candidates claim the first window's only AppId event.
        value['Candidates'].append({**value['Candidates'][0], 'Identifier': fixtures.TARGET})
        changed.write_text(json.dumps(value))
        rejected = self.merge(changed)
        self.assertEqual(rejected.returncode, 1)
        self.assertEqual(rejected.stdout, '')
        value['Candidates'][-1].update(FirstObservedAt=MIDDLE, LastObservedAt=MIDDLE)
        changed.write_text(json.dumps(value))
        self.assertEqual(self.merge(changed).returncode, 0)
        self.unchanged()

    def test_candidate_interior_counts_must_fit_between_observed_endpoints(self):
        original = self.report('original', SINCE, MIDDLE)
        changed = self.repo / 'three-windows.json'
        third = '2026-01-08T00:00:00Z'
        value = json.loads(original.read_bytes())
        value['UntilExclusive'] = third
        for start, end in ((MIDDLE, UNTIL), (UNTIL, third)):
            value['Windows'].append({**value['Windows'][0], 'Since': start, 'UntilExclusive': end})
        candidate = value['Candidates'][0]
        candidate.update(Count=3, LastObservedAt=UNTIL, EventTypeCounts={'interactiveUser': 3})
        changed.write_text(json.dumps(value))
        self.assertEqual(self.merge(changed, end=third).returncode, 0)
        candidate['LastObservedAt'] = MIDDLE
        changed.write_text(json.dumps(value))
        result = self.merge(changed, end=third)
        self.assertEqual(result.returncode, 1)
        self.assertEqual(result.stdout, '')
        self.unchanged()

    def test_nonregular_reports_fail_without_reading(self):
        fifo = self.repo / 'not-a-file'
        os.mkfifo(fifo)
        real = self.report('original', SINCE, MIDDLE)
        link = self.repo / 'linked.json'
        link.symlink_to(real)
        for path in (fifo, link, self.repo):
            result = self.merge(path)
            self.assertEqual(result.returncode, 1)
            self.assertEqual(result.stdout, '')
        self.unchanged()

    def test_no_reports_yields_one_missing_interval(self):
        result = self.merge()
        self.assertEqual(result.returncode, 2, result.stderr)
        report = json.loads(result.stdout)
        self.assertFalse(report['InputCoverageComplete'])
        self.assertEqual(report['Inputs'], [])
        self.assertEqual(report['Candidates'], [])
        self.assertEqual([row['Status'] for row in report['Windows']], ['Missing'])
        self.unchanged()

    def test_same_interval_with_different_reports_is_an_overlap(self):
        first = self.report('first', SINCE, MIDDLE)
        second = self.report('second', SINCE, MIDDLE, '2026-01-05T12:00:00Z')
        result = self.merge(first, second, end=MIDDLE)
        self.assertEqual(result.returncode, 2)
        receipt = json.loads(result.stdout)
        self.assertEqual(receipt['Candidates'], [])
        self.assertEqual([row['Status'] for row in receipt['Windows']], ['OverlappingReports'])
        self.unchanged()


if __name__ == '__main__':
    unittest.main()
