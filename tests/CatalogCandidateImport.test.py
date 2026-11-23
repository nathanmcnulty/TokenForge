import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('delta', ROOT / 'scripts/Diff-TokenForgePublicCatalog.py')
delta = importlib.util.module_from_spec(spec)
spec.loader.exec_module(delta)
VERIFIED = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'
NONVERIFIED = 'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb'
NEW = 'cccccccc-cccc-cccc-cccc-cccccccccccc'
TARGET = 'dddddddd-dddd-dddd-dddd-dddddddddddd'
OLD = '1' * 40
NEW_REVISION = '2' * 40
OLD_HASH = 'a' * 64
NEW_HASH = 'b' * 64
TIME = '2026-01-06T00:00:00Z'
NAMES = ('roadtools', 'microsoftApps', 'resources')
URLS = {n: 'https://raw.githubusercontent.com/example/catalog/main/' + n + '.json' for n in NAMES}


def claim(name, label):
    return {'Location': URLS[name], 'Evidence': 'PublishedMetadata', 'Name': label}


def record(claims):
    return {'Records': {'Discovery///': {'Attributes': {'SourceClaims': claims}}}}


class CatalogCandidateTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.repo = Path(self.temp.name)
        subprocess.run(['git', 'init', '-q', str(self.repo)], check=True)
        self.verified = {'Format': 'TokenForgeApplicationMetadata', 'SchemaVersion': 2,
                         'Applications': {VERIFIED: record([claim('roadtools', 'verified')])}}
        self.nonverified = {'Format': 'TokenForgeNonVerifiedApplications', 'SchemaVersion': 1,
                            'Applications': {NONVERIFIED: {'Disposition': 'Pending',
                                'CatalogRecord': record([claim('roadtools', 'old')])}},
                            'Upstream': [{'source': n, 'url': URLS[n], 'revision': OLD, 'sha256': OLD_HASH}
                                         for n in NAMES]}
        self.catalog_files = [self.repo / 'applications.json', self.repo / 'applications.non-verified.json']
        for path, doc in zip(self.catalog_files, (self.verified, self.nonverified)):
            path.write_text(json.dumps(doc))
        self.before = [p.read_bytes() for p in self.catalog_files]
        self.git('add', '--', *(p.name for p in self.catalog_files))
        self.git('-c', 'user.name=Synthetic', '-c', 'user.email=test@example.invalid',
                 '-c', 'commit.gpgsign=false', 'commit', '-qm', 'Fixture catalog')
        self.commit = self.git('rev-parse', 'HEAD').stdout.strip()

    def git(self, *args):
        return subprocess.run(['git', '-C', str(self.repo), *args], text=True, capture_output=True, check=True)

    def unchanged(self):
        self.assertEqual(self.before, [p.read_bytes() for p in self.catalog_files])

    def observations(self):
        return {name: {'revision': OLD, 'checkedAt': TIME} for name in NAMES}

    def test_unchanged_stamps_skip_projection_and_ledger(self):
        def unexpected(*args):
            self.fail('Unexpected capture or ledger access')
        result = delta.compare(self.nonverified, self.observations(), unexpected, unexpected)
        self.assertTrue(result['complete'])
        self.assertEqual(result['newApplications'], [])
        self.assertEqual({s['status'] for s in result['sources'].values()}, {'Unchanged'})
        self.unchanged()

    def test_changed_provenance_against_both_catalogs_and_deduped_addition(self):
        stamps = self.observations()
        for name in ('roadtools', 'resources'):
            stamps[name].update(revision=NEW_REVISION, sha256=NEW_HASH)
        ledger = {VERIFIED: [claim('roadtools', 'verified')], NONVERIFIED: [claim('roadtools', 'old')]}
        captures = {
            'roadtools': {VERIFIED: ledger[VERIFIED], NONVERIFIED: [claim('roadtools', 'revised')],
                          NEW: [claim('roadtools', 'new')]},
            'resources': {NEW: [claim('resources', 'new')]}}
        result = delta.compare(self.nonverified, stamps, lambda: ledger, lambda name, _: captures[name])
        self.assertEqual(result['newApplications'], [{'appId': NEW, 'sources': ['resources', 'roadtools'],
                                                     'disposition': 'Pending'}])
        self.assertEqual([r['appId'] for r in result['sources']['roadtools']['provenanceChanges']], [NONVERIFIED])
        self.assertEqual(result['sources']['resources']['provenanceChanges'], [])
        self.unchanged()

    def test_incomplete_and_stamp_only_changes_avoid_reads(self):
        stamps = self.observations()
        stamps['roadtools'].update(revision=NEW_REVISION)
        stamps['microsoftApps'] = {'status': 'Unavailable'}
        stamps['resources'].update(revision=NEW_REVISION, sha256=OLD_HASH)
        result = delta.compare(self.nonverified, stamps, self.fail, self.fail)
        self.assertFalse(result['complete'])
        self.assertEqual({k: v['status'] for k, v in result['sources'].items()},
                         {'roadtools': 'NeedsCapture', 'microsoftApps': 'Unavailable',
                          'resources': 'RevisionChangedSameContent'})
        self.unchanged()

    def test_delta_cli_reads_pinned_git_not_worktree(self):
        self.catalog_files[0].write_text('uncommitted unrelated data')
        before = [p.read_bytes() for p in self.catalog_files]
        stamps = self.repo / 'stamps.json'
        stamps.write_text(json.dumps(self.observations()))
        command = ['python3', '-B', str(ROOT / 'scripts/Diff-TokenForgePublicCatalog.py'),
                   '--baseline-repo', str(self.repo), '--baseline-commit', self.commit, '--observations', str(stamps)]
        first = subprocess.check_output(command)
        self.assertEqual(subprocess.check_output(command), first)
        self.assertEqual(json.loads(first)['baselineCommit'], self.commit)
        self.assertEqual(before, [p.read_bytes() for p in self.catalog_files])

    def test_legacy_refresh_and_reconcile_refuse_split_catalog(self):
        spec = importlib.util.spec_from_file_location('refresh', ROOT / 'scripts/Refresh-TokenForgePublicCatalog.py')
        refresh = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(refresh)
        with self.assertRaisesRegex(ValueError, 'Split catalog baseline'):
            refresh.checked_baseline(self.repo, self.commit)
        (self.repo / 'baseline').mkdir()
        (self.repo / 'baseline/applications.non-verified.json').touch()
        with self.assertRaisesRegex(ValueError, 'Split catalog baseline'):
            refresh.adapter.reconcile(self.repo, self.repo / 'output', None, None)
        self.unchanged()

    @unittest.skipUnless(shutil.which('pwsh'), 'PowerShell required')
    def test_changed_capture_uses_existing_public_projector(self):
        native = os.environ.get('TOKENFORGE_TEST_NATIVE')
        if not native:
            self.skipTest('Set TOKENFORGE_TEST_NATIVE to a reviewed local package')
        stamps = self.observations()
        source = self.repo / 'resources.json'
        source.write_text(json.dumps([{'resourceId': NEW, 'displayName': 'Synthetic resource'}]))
        # Pin real source location without contacting it.
        self.nonverified['Upstream'][2]['url'] = 'https://raw.githubusercontent.com/f-bader/entrascopes.com/main/resources.json'
        self.catalog_files[1].write_text(json.dumps(self.nonverified))
        self.git('add', 'applications.non-verified.json')
        self.git('-c', 'user.name=Synthetic', '-c', 'user.email=test@example.invalid',
                 '-c', 'commit.gpgsign=false', 'commit', '-qm', 'Use public source location')
        stamps['resources'].update(revision=NEW_REVISION, sha256=hashlib.sha256(source.read_bytes()).hexdigest())
        observations = self.repo / 'stamps.json'
        observations.write_text(json.dumps(stamps))
        command = ['python3', '-B', str(ROOT / 'scripts/Diff-TokenForgePublicCatalog.py'),
                   '--baseline-repo', str(self.repo), '--baseline-commit', self.git('rev-parse','HEAD').stdout.strip(),
                   '--observations', str(observations), '--captures', str(self.repo), '--native', native]
        result = subprocess.run(command, capture_output=True, check=True)
        self.assertEqual(json.loads(result.stdout)['newApplications'],
                         [{'appId': NEW, 'disposition': 'Pending', 'sources': ['resources']}])
        before = [p.read_bytes() for p in self.catalog_files]
        source.write_text('[]')
        rejected = subprocess.run(command, capture_output=True)
        self.assertEqual(rejected.returncode, 2)
        self.assertEqual(json.loads(rejected.stdout)['sources']['resources']['status'], 'InvalidCapture')
        self.assertEqual(before, [p.read_bytes() for p in self.catalog_files])

    def page(self, filename, rows, link=None):
        data = {'value': rows}
        if link is not None:
            data['@odata.nextLink'] = link
        (self.repo / filename).write_text(json.dumps(data))

    def replay(self, *extra):
        return subprocess.run(['pwsh', '-NoProfile', '-File', str(ROOT / 'scripts/Find-TokenForgeSignInCatalogGaps.ps1'),
                               '-CatalogRepository', str(self.repo), '-CatalogCommit', self.commit,
                               '-Since', '2026-01-05T00:00:00Z', '-Until', '2026-01-07T00:00:00Z',
                               '-FixtureDirectory', str(self.repo), *extra], text=True, capture_output=True)

    def test_signin_replay_union_paging_dedupe_and_privacy(self):
        row = {'id': 'private-event-id', 'appId': NEW.upper(), 'resourceId': TARGET,
               'createdDateTime': '2026-01-05T23:59:00Z', 'isInteractive': True,
               'userPrincipalName': 'private-user', 'ipAddress': 'private-ip', 'sessionId': 'private-session'}
        known = {**row, 'id': 'private-known-event', 'appId': VERIFIED, 'resourceId': NONVERIFIED}
        later = {**row, 'id': 'private-later-event', 'createdDateTime': TIME, 'isInteractive': False}
        self.page('window-1-page-1.json', [row, known], 'https://graph.microsoft.com/v1.0/auditLogs/signIns?$skiptoken=hidden')
        self.page('window-1-page-2.json', [row, later])
        self.page('window-2-page-1.json', [later])
        result = self.replay()
        self.assertEqual(result.returncode, 0, result.stderr)
        value = json.loads(result.stdout)
        self.assertTrue(value['EnumerationComplete'])
        self.assertFalse(value['TenantHistoryComplete'])
        self.assertEqual(value['ActualAudience'], 'UnknownFromSignInLogs')
        self.assertEqual(value['Windows'][0]['DuplicateEvents'], 1)
        self.assertEqual(value['Windows'][0]['BoundaryEventsSkipped'], 1)
        self.assertEqual([(r['IdentifierKind'],r['Identifier'],r['Disposition'],r['Count']) for r in value['Candidates']],
                         [('AppId',NEW,'Pending',2),('GraphResourceId',TARGET,'Pending',2)])
        self.assertNotRegex(result.stdout, r'private-|skiptoken|userPrincipalName|ipAddress|sessionId')
        self.unchanged()

    def test_signin_incomplete_link_page_limit_and_preview(self):
        bad_link = 'https://graph.microsoft.com/beta/auditLogs/signIns?$skiptoken=private-next-link'
        self.page('window-1-page-1.json', [], bad_link)
        self.page('window-2-page-1.json', [])
        for extra, status in (([], 'InvalidNextLink'), (['-PreviewAllEventTypes'], 'FixtureUnavailable')):
            result = self.replay(*extra)
            self.assertEqual(result.returncode, 2, result.stderr)
            self.assertEqual(json.loads(result.stdout)['Windows'][0]['Status'], status)
            self.assertNotIn('private-next-link', result.stdout)
        row = {'id': 'synthetic-event', 'appId': NEW, 'resourceId': TARGET, 'createdDateTime': '2026-01-05T12:00:00Z',
               'signInEventTypes': ['servicePrincipal','managedIdentity']}
        self.page('window-1-page-1.json', [row], bad_link)
        result = self.replay('-PreviewAllEventTypes', '-MaxPages', '1')
        self.assertEqual(result.returncode, 2, result.stderr)
        value = json.loads(result.stdout)
        self.assertEqual(value['GraphVersion'], 'beta')
        self.assertEqual(value['Candidates'][0]['EventTypeCounts'], {'managedIdentity': 1, 'servicePrincipal': 1})
        self.assertEqual([row['Status'] for row in value['Windows']], ['PageLimit','PageLimit'])
        self.unchanged()

    def test_signin_pagination_loop_and_conflicting_duplicate_are_incomplete(self):
        first = {'id': 'for-dedupe-only', 'appId': NEW, 'resourceId': TARGET,
                 'createdDateTime': '2026-01-05T12:00:00Z', 'isInteractive': True}
        link = 'https://graph.microsoft.com/v1.0/auditLogs/signIns?$skiptoken=loop'
        self.page('window-1-page-1.json', [first], link)
        self.page('window-1-page-2.json', [{**first, 'resourceId': NEW}], link)
        self.page('window-2-page-1.json', [])
        result = self.replay()
        self.assertEqual(result.returncode, 2, result.stderr)
        value = json.loads(result.stdout)
        self.assertEqual(value['Windows'][0]['Status'], 'PaginationLoop')
        self.assertEqual(value['Windows'][0]['MalformedEvents'], 1)
        self.assertEqual(value['Candidates'][0]['Count'], 1)
        self.assertNotIn('for-dedupe-only', result.stdout)
        self.unchanged()

    def test_sdk_context_and_get_sequence_are_mocked(self):
        wrapper = self.repo / 'mock-sdk.ps1'
        wrapper.write_text("""param($Script,$Repo,$Commit,$Scenario)
$tid = [guid]'11111111-2222-3333-4444-555555555555'
function Get-MgContext {
    param($ErrorAction,$Debug,$Verbose)
    $scopes = if ($Scenario -eq 'Scope') { @('User.Read') } else { @('AuditLog.Read.All') }
    [pscustomobject]@{ TenantId = if ($Scenario -eq 'Tenant') { [guid]::Empty } else { $tid }
        AuthType = 'Delegated'; Environment = 'Global'; Scopes = $scopes }
}
function Invoke-MgGraphRequest {
    param($Method,$Uri,$OutputType,$ErrorAction,$Debug,$Verbose)
    if ($Scenario -in 'Tenant','Scope') { throw 'GET called with invalid context' }
    if ($Method -ne 'GET' -or $Uri.Host -ne 'graph.microsoft.com' -or $OutputType -ne 'Hashtable' -or
        $Uri.AbsolutePath -ne '/beta/auditLogs/signIns') { throw 'Unexpected SDK request' }
    $q=[uri]::UnescapeDataString($Uri.Query)
    if ($q -notmatch 'createdDateTime ge .+ and createdDateTime le ') { throw 'Missing date bounds' }
    foreach ($category in @('interactiveUser','nonInteractiveUser','servicePrincipal','managedIdentity')) {
        if ($q -notlike "*'$category'*") { throw 'Filter incomplete' }
    }
    if ($Scenario -eq 'Error') { throw 'private diagnostic sentinel' }
    @{ value=@() }
}
& $Script -TenantId $tid -CatalogRepository $Repo -CatalogCommit $Commit -Since '2026-01-05Z' -Until '2026-01-07Z' -PreviewAllEventTypes
exit $LASTEXITCODE
""")
        cmd = ['pwsh','-NoProfile','-File',str(wrapper),str(ROOT/'scripts/Find-TokenForgeSignInCatalogGaps.ps1'),
               str(self.repo),self.commit]
        for scenario in ('Tenant','Scope'):
            result = subprocess.run([*cmd, scenario], capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('AuditLog.Read.All', result.stderr)
            self.assertNotIn('GET called', result.stderr)
        result = subprocess.run([*cmd, 'Good'], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(json.loads(result.stdout)['EnumerationComplete'])
        result = subprocess.run([*cmd, 'Error'], capture_output=True, text=True)
        self.assertEqual(result.returncode, 2)
        self.assertEqual([w['Status'] for w in json.loads(result.stdout)['Windows']],
                         ['GraphRequestFailed','NotAttemptedAfterReadFailure'])
        self.assertNotIn('private diagnostic sentinel', result.stdout + result.stderr)
        self.unchanged()


if __name__ == '__main__':
    unittest.main()
