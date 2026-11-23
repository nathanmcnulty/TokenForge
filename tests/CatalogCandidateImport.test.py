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
        def missing(*args):
            raise FileNotFoundError

        result = delta.compare(self.nonverified, stamps, self.fail, missing)
        self.assertFalse(result['complete'])
        self.assertEqual({k: v['status'] for k, v in result['sources'].items()},
                         {'roadtools': 'NeedsCapture', 'microsoftApps': 'Unavailable',
                          'resources': 'NeedsCapture'})
        result = delta.compare(self.nonverified, stamps, self.fail, lambda *_: {})
        self.assertEqual(result['sources']['resources']['status'], 'RevisionChangedSameContent')
        self.assertEqual(result['sources']['resources']['verifiedCaptureSha256'], OLD_HASH)
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
        self.assertFalse(json.loads(first)['revisionLabelsVerified'])
        self.assertEqual(before, [p.read_bytes() for p in self.catalog_files])

    def test_both_importers_reject_tree_as_commit(self):
        tree = self.git('rev-parse', 'HEAD^{tree}').stdout.strip()
        stamps = self.repo / 'stamps.json'
        stamps.write_text(json.dumps(self.observations()))
        public = subprocess.run(
            ['python3', '-B', str(ROOT / 'scripts/Diff-TokenForgePublicCatalog.py'),
             '--baseline-repo', str(self.repo), '--baseline-commit', tree, '--observations', str(stamps)],
            text=True, capture_output=True)
        self.assertNotEqual(public.returncode, 0)
        self.assertIn('must be a Git commit', public.stderr)
        self.commit = tree
        replay = self.replay()
        self.assertNotEqual(replay.returncode, 0)
        self.assertIn('must be a Git commit', replay.stderr)
        self.unchanged()

    def test_missing_promisor_blob_fails_without_remote_helper_or_env_mutation(self):
        # The positive control only reaches a synthetic local helper. It attempts no network access.
        helper_dir = self.repo / 'helpers'
        helper_dir.mkdir()
        marker = self.repo / 'helper-called'
        helper = helper_dir / 'git-remote-probe'
        helper.write_text('#!/bin/sh\nprintf called > "$TOKENFORGE_PROBE_MARKER"\nexit 1\n')
        helper.chmod(0o700)
        env = {**os.environ, 'PATH': str(helper_dir) + os.pathsep + os.environ['PATH'],
               'GIT_ALLOW_PROTOCOL': 'probe', 'GIT_NO_LAZY_FETCH': '0',
               'TOKENFORGE_PROBE_MARKER': str(marker)}
        self.git('config', 'core.repositoryformatversion', '1')
        self.git('config', 'extensions.partialClone', 'origin')
        self.git('config', 'remote.origin.url', 'probe::fixture')
        self.git('config', 'remote.origin.promisor', 'true')
        self.git('config', 'protocol.probe.allow', 'always')
        path = 'applications.non-verified.json'
        blob = self.git('rev-parse', 'HEAD:' + path).stdout.strip()
        (self.repo / '.git/objects' / blob[:2] / blob[2:]).unlink()
        control = subprocess.run(['git', '-C', str(self.repo), 'cat-file', 'blob', self.commit + ':' + path],
                                 env=env, capture_output=True)
        self.assertNotEqual(control.returncode, 0)
        self.assertTrue(marker.exists(), control.stderr)
        marker.unlink()

        stamps = self.repo / 'stamps.json'
        stamps.write_text(json.dumps(self.observations()))
        public = subprocess.run(
            ['python3', '-B', str(ROOT / 'scripts/Diff-TokenForgePublicCatalog.py'),
             '--baseline-repo', str(self.repo), '--baseline-commit', self.commit, '--observations', str(stamps)],
            env=env, capture_output=True, text=True)
        self.assertNotEqual(public.returncode, 0)
        self.assertIn('must be available locally', public.stderr)
        self.assertFalse(marker.exists())

        wrapper = self.repo / 'parent-environment.ps1'
        wrapper.write_text("""param($Script,$Repo,$Commit)
$ErrorActionPreference = 'Stop'
try {
    & $Script -FixtureDirectory $Repo -CatalogRepository $Repo -CatalogCommit $Commit -Since '2026-01-05Z' -Until '2026-01-06Z'
    throw 'Missing blob accepted'
} catch {
    if ($_.Exception.Message -notlike '*must be available locally*') { throw }
}
if ($env:GIT_ALLOW_PROTOCOL -cne 'probe' -or $env:GIT_NO_LAZY_FETCH -cne '0') { throw 'Parent environment changed' }
'Local failure, environment preserved'
""")
        replay = subprocess.run(
            ['pwsh', '-NoProfile', '-File', str(wrapper), str(ROOT / 'scripts/Find-TokenForgeSignInCatalogGaps.ps1'),
             str(self.repo), self.commit], env=env, capture_output=True, text=True)
        self.assertEqual(replay.returncode, 0, replay.stderr)
        self.assertIn('environment preserved', replay.stdout)
        self.assertFalse(marker.exists())
        self.unchanged()

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
        self.assertTrue(value['ReplayComplete'])
        self.assertFalse(value['TenantHistoryComplete'])
        self.assertEqual(value['SourceWindowCoverage'], 'Unknown')
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

    def test_bare_snapshot_does_not_claim_window_coverage_or_coerce_arrays(self):
        snapshot = self.repo / 'snapshot.json'
        event = {'id': 'do-not-retain-this-event-id', 'appId': [NEW], 'resourceId': [TARGET],
                 'createdDateTime': '2026-01-06T12:00:00Z', 'isInteractive': True}
        scalar = {**event, 'id': 'do-not-retain-this-second-id', 'appId': NEW, 'resourceId': TARGET}
        snapshot.write_text(json.dumps([event, scalar]))
        command = ['pwsh', '-NoProfile', '-File', str(ROOT / 'scripts/Find-TokenForgeSignInCatalogGaps.ps1'),
                   '-CatalogRepository', str(self.repo), '-CatalogCommit', self.commit,
                   '-Since', '2026-01-05T00:00:00Z', '-Until', '2026-01-07T00:00:00Z',
                   '-SnapshotPath', str(snapshot)]
        result = subprocess.run(command, text=True, capture_output=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        value = json.loads(result.stdout)
        self.assertTrue(value['ReplayComplete'])
        self.assertEqual(value['Source'], 'LocalSnapshot')
        self.assertEqual(value['SourceWindowCoverage'], 'Unknown')
        self.assertFalse(value['TenantHistoryComplete'])
        self.assertEqual(len(value['Windows']), 1)
        self.assertEqual(value['Windows'][0]['UnusableAppIds'], 1)
        self.assertEqual(value['Windows'][0]['UnusableGraphResourceIds'], 1)
        self.assertEqual([row['Count'] for row in value['Candidates']], [1, 1])
        self.assertNotIn('do-not-retain', result.stdout)
        snapshot.write_text(json.dumps([scalar]))
        result = subprocess.run(command, text=True, capture_output=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)['Windows'][0]['UniqueEvents'], 1)
        self.unchanged()

    def test_duplicate_json_keys_cannot_hide_incomplete_pages(self):
        (self.repo / 'window-1-page-1.json').write_text('{"value":[1],"value":[]}')
        self.page('window-2-page-1.json', [])
        result = self.replay()
        self.assertEqual(result.returncode, 2, result.stderr)
        value = json.loads(result.stdout)
        self.assertFalse(value['ReplayComplete'])
        self.assertEqual(value['Windows'][0]['Status'], 'FixtureUnavailable')
        self.unchanged()

    def test_replay_ignores_hostile_defaults_and_has_no_sdk_calls(self):
        wrapper = self.repo / 'hostile-defaults.ps1'
        raw_output = self.repo / 'unexpected.json'
        wrapper.write_text("""param($Script,$Repo,$Commit,$RawOutput)
$PSDefaultParameterValues = @{
    'Invoke-MgGraphRequest:OutputFilePath' = $RawOutput
    'Invoke-MgGraphRequest:InferOutputFileName' = $true
    'Invoke-MgGraphRequest:Headers' = @{ Forced = 'NeverSend' }
    'Invoke-MgGraphRequest:GraphRequestSession' = 'NeverUse'
    'ConvertFrom-Json:Depth' = 1
}
function Get-MgContext { throw 'Unexpected context read' }
function Invoke-MgGraphRequest { throw 'Unexpected request' }
& $Script -FixtureDirectory $Repo -CatalogRepository $Repo -CatalogCommit $Commit -Since '2026-01-05Z' -Until '2026-01-06Z'
exit $LASTEXITCODE
""")
        self.page('window-1-page-1.json', [])
        result = subprocess.run(
            ['pwsh', '-NoProfile', '-File', str(wrapper), str(ROOT / 'scripts/Find-TokenForgeSignInCatalogGaps.ps1'),
             str(self.repo), self.commit, str(raw_output)], text=True, capture_output=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(json.loads(result.stdout)['ReplayComplete'])
        self.assertFalse(raw_output.exists())
        self.unchanged()


class OperatorRunbookTests(unittest.TestCase):
    setUp = CatalogCandidateTests.setUp
    git = CatalogCandidateTests.git
    unchanged = CatalogCandidateTests.unchanged

    def test_attended_runbook_uses_only_mocked_sdk_and_minimizes_report(self):
        docs = (ROOT / 'docs/operator-signin-gap-sample.md').read_text()
        connect, recipe = (block.split('```', 1)[0] for block in docs.split('```powershell\n')[1:])
        operator = self.repo / 'operator.ps1'
        operator.write_text("""param($TokenForge,$CatalogRepository,$CatalogCommit,$Scenario)
$ErrorActionPreference = 'Stop'
$global:FixtureScenario = $Scenario
$global:FixtureReadPath = Join-Path $CatalogRepository 'read-called'
$global:FixtureConnectPath = Join-Path $CatalogRepository 'connect-called'
$TenantId = [guid]'11111111-2222-3333-4444-555555555555'
$Since = [DateTimeOffset]'2026-01-05T00:00:00Z'
$Until = if ($Scenario -eq 'Long') { $Since.AddDays(2) } elseif ($Scenario -eq 'Reverse') { $Since.AddDays(-1) } else { $Since.AddDays(1) }
if ($Scenario -eq 'Future') { $Since = [DateTimeOffset]::UtcNow.AddMinutes(1); $Until = $Since.AddMinutes(1) }
$PSDefaultParameterValues = @{
    'Get-MgAuditLogSignIn:All' = $true
    'Get-MgAuditLogSignIn:Headers' = @{ 'Fixture' = 'never-send' }
    'Get-MgAuditLogSignIn:Debug' = $true
    'Connect-MgGraph:UseDeviceAuthentication' = $true
    'Connect-MgGraph:ClientId' = 'unexpected'
    'Connect-MgGraph:Debug' = $true
}
New-Module -Name Microsoft.Graph.Authentication {
    function Connect-MgGraph {
        [CmdletBinding()] param($TenantId,$Scopes,$Environment,$ContextScope,[switch]$NoWelcome,
                               [switch]$UseDeviceAuthentication,$ClientId)
        if ($TenantId -ne [guid]'11111111-2222-3333-4444-555555555555' -or
            $Scopes -ne 'AuditLog.Read.All' -or $Environment -ne 'Global' -or $ContextScope -ne 'Process' -or
            -not $NoWelcome -or $UseDeviceAuthentication -or $ClientId -or
            $PSBoundParameters['Debug'] -or $PSBoundParameters['Verbose']) {
            throw 'Unexpected SDK sign-in arguments'
        }
        [IO.File]::WriteAllText($global:FixtureConnectPath, 'mock')
    }
    function Get-MgContext {
        [CmdletBinding()] param()
        if ($global:FixtureScenario -eq 'NoContext') { return }
        [pscustomobject]@{
            TenantId = if ($global:FixtureScenario -eq 'WrongTenant') { 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa' } elseif ($global:FixtureScenario -eq 'ArrayTenant') { ,@('11111111-2222-3333-4444-555555555555') } else { '11111111-2222-3333-4444-555555555555' }
            AuthType = if ($global:FixtureScenario -eq 'AppOnly') { 'AppOnly' } else { 'Delegated' }
            ContextScope = if ($global:FixtureScenario -eq 'SharedScope') { 'CurrentUser' } else { 'Process' }
            Scopes = if ($global:FixtureScenario -eq 'NoScope') { @('User.Read') } else { @('AuditLog.Read.All') }
            Environment = if ($global:FixtureScenario -eq 'WrongCloud') { 'USGov' } else { 'Global' }
        }
    }
    function Get-MgEnvironment {
        [CmdletBinding()] param($Name)
        if ($Name -ne 'Global') { throw 'Unexpected environment' }
        [pscustomobject]@{
            Name = 'Global'; Type = if ($global:FixtureScenario -eq 'CustomCloud') { 'User-defined' } else { 'Built-in' }
            GraphEndpoint = if ($global:FixtureScenario -eq 'HostMismatch') { 'https://example.invalid' } else { 'https://graph.microsoft.com' }
            AzureADEndpoint = if ($global:FixtureScenario -eq 'LoginMismatch') { 'https://example.invalid' } else { 'https://login.microsoftonline.com' }
        }
    }
} | Import-Module
New-Module -Name Microsoft.Graph.Reports {
    function Get-MgAuditLogSignIn {
        [CmdletBinding()] param($Filter,$Property,$Top,[switch]$All,$Headers)
        [IO.File]::WriteAllText($global:FixtureReadPath, 'mock')
        if ($All -or $Headers -or $PSBoundParameters['Debug'] -or $PSBoundParameters['Verbose'] -or
            $Filter -ne 'createdDateTime ge 2026-01-05T00:00:00.0000000Z and createdDateTime le 2026-01-06T00:00:00.0000000Z' -or
            $Top -ne 1000 -or ($Property -join ',') -ne 'id,appId,resourceId,createdDateTime,isInteractive') {
            throw 'Unexpected SDK arguments'
        }
        if ($global:FixtureScenario -eq 'Empty') { return }
        $row = [pscustomobject]@{
            Id = 'private-event'; AppId = 'cccccccc-cccc-cccc-cccc-cccccccccccc'
            ResourceId = 'dddddddd-dddd-dddd-dddd-dddddddddddd'; IsInteractive = $true
            CreatedDateTime = [DateTimeOffset]'2026-01-05T12:00:00Z'
            UserPrincipalName = 'private-user'; IpAddress = 'private-ip'
        }
        if ($global:FixtureScenario -eq 'BadTime') { $row.CreatedDateTime = [DateTimeOffset]'2026-01-04T12:00:00Z' }
        $row
        if ($global:FixtureScenario -eq 'SdkError') { throw 'private-error' }
        if ($global:FixtureScenario -eq 'Cap') { for ($i=0; $i -lt 1000; $i++) { $row } }
    }
} | Import-Module
""" + "if ($Scenario -eq 'OptionalConnect') {\n" + connect + "\nexit 0\n}\n" +
                            recipe + "\nexit $LASTEXITCODE\n")
        command = ['pwsh', '-NoProfile', '-File', str(operator), str(ROOT), str(self.repo), self.commit]
        called = self.repo / 'read-called'
        connect_called = self.repo / 'connect-called'
        optional = subprocess.run([*command, 'OptionalConnect'], text=True, capture_output=True)
        self.assertEqual(optional.returncode, 0, optional.stderr)
        self.assertTrue(connect_called.exists())
        self.assertFalse(called.exists())
        connect_called.unlink()
        for reason in ('NoContext', 'WrongTenant', 'ArrayTenant', 'NoScope', 'AppOnly', 'SharedScope',
                       'WrongCloud', 'CustomCloud', 'HostMismatch', 'LoginMismatch', 'Long', 'Reverse', 'Future'):
            with self.subTest(reason=reason):
                result = subprocess.run([*command, reason], text=True, capture_output=True)
                self.assertNotEqual(result.returncode, 0, result.stdout)
                self.assertFalse(called.exists())
        for reason in ('Sample', 'Empty', 'BadTime', 'Cap', 'SdkError'):
            with self.subTest(reason=reason):
                result = subprocess.run([*command, reason], text=True, capture_output=True)
                self.assertTrue(called.exists(), result.stderr)
                called.unlink()
                self.assertNotRegex(result.stdout + result.stderr, 'private-user|private-ip|private-error|private-event')
                if reason in ('Cap', 'SdkError'):
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn('Partial records were discarded', result.stderr)
                    self.assertFalse(result.stdout.strip())
                    continue
                report = json.loads(result.stdout)
                self.assertEqual(report['Source'], 'InMemorySnapshot')
                self.assertEqual(report['SourceWindowCoverage'], 'Unknown')
                self.assertEqual(report['ActualAudience'], 'UnknownFromSignInLogs')
                self.assertEqual(report['ReplayComplete'], reason != 'BadTime')
                self.assertEqual(result.returncode, 2 if reason == 'BadTime' else 0)
                self.assertEqual([r['Identifier'] for r in report['Candidates']], [NEW, TARGET] if reason == 'Sample' else [])
        self.assertFalse(connect_called.exists())
        self.unchanged()


if __name__ == '__main__':
    unittest.main()
