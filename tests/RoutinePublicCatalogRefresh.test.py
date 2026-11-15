#!/usr/bin/env python3
"""Focused offline orchestration regressions. No network, runtimes or authentication."""
import importlib.util
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
import subprocess
import tempfile
import time
import unittest
from unittest.mock import patch

REPO = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('routine_refresh', REPO / 'scripts/Refresh-TokenForgePublicCatalog.py')
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


class RoutineRefreshTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / 'job'
        self.root.mkdir()
        self.state = {'kind': 'FrozenAnonymousPublicInputs', 'schemaVersion': 1,
                      'sourceRevision': '1' * 40, 'authentication': False,
                      'startedAt': m.utc(), 'finishedAt': m.utc(),
                      'deadlineEpoch': time.time() + 180, 'requests': 0,
                      'sources': [], 'complete': False}
        self.state['finishedAt'] = self.state['startedAt']
        self.bind_job()
        self.calls = []

    def bind_job(self):
        m.write(self.root / 'job.json', {
            'acquisitionStartedAt': self.state['startedAt'],
            'acquisitionDeadlineEpoch': self.state['deadlineEpoch'],
            'sourceRevision': self.state['sourceRevision']})

    def capture(self, pwsh, script, args, log, timeout=300):
        self.calls.append(args[1])
        # Retain real public-health fixture bytes, never operational data.
        Path(args[2]).write_bytes((REPO / 'tests/fixtures/public-health' / (args[1] + '.json')).read_bytes())

    def test_completed_capture_recovery_never_refetches(self):
        def stop_after_first(*args, **kwargs):
            if self.calls:
                raise KeyboardInterrupt('Synthetic durable-boundary stop')
            return self.capture(*args, **kwargs)
        with patch.object(m, 'ps', side_effect=stop_after_first):
            with self.assertRaises(KeyboardInterrupt):
                m.acquire(self.root, self.state, Path('fake-pwsh'))
        saved = m.adapter.read(self.root / 'acquisition.json')
        self.assertEqual(saved['sources'][0]['status'], 'Captured')
        # The second dispatch was uncertain, and remains charged; it cannot be retried.
        self.assertEqual(saved['requests'], 2)
        with patch.object(m, 'ps') as network:
            with self.assertRaisesRegex(ValueError, 'Uncertain|failed'):
                m.acquire(self.root, saved, Path('fake-pwsh'))
            network.assert_not_called()
        self.assertEqual(saved['requests'], 2)

    def test_resume_after_completed_source_only_fetches_remaining(self):
        # A normal process boundary after durable completion has no uncertain attempt.
        first = next(iter(m.SOURCES))
        raw = self.root / 'raw-public-inputs'
        raw.mkdir()
        payload = (REPO / 'tests/fixtures/public-health' / (first + '.json')).read_bytes()
        (raw / (first + '.json')).write_bytes(payload)
        self.state['sources'] = [{'name': first, 'uri': m.SOURCES[first], 'attempts': 1,
                                  'status': 'Captured', 'sha256': m.adapter.digest(payload),
                                  'bytes': len(payload), 'retrievedAt': m.utc()}]
        self.state['requests'] = 1
        self.state['finishedAt'] = self.state['sources'][0]['retrievedAt']
        deadline = self.state['deadlineEpoch']
        with patch.object(m, 'ps', side_effect=self.capture):
            m.acquire(self.root, self.state, Path('fake-pwsh'))
        self.assertEqual(self.calls, list(m.SOURCES)[1:])
        self.assertEqual(self.state['requests'], 3)
        self.assertTrue(self.state['complete'])
        self.assertEqual(self.state['deadlineEpoch'], deadline)
        with patch.object(m, 'ps') as network:
            m.acquire(self.root, self.state, Path('fake-pwsh'), offline=True)
            network.assert_not_called()

    def test_capture_tampering_refused_before_dispatch(self):
        with patch.object(m, 'ps', side_effect=self.capture):
            m.acquire(self.root, self.state, Path('fake-pwsh'))
        target = self.root / 'raw-public-inputs/roadtools.json'
        target.write_bytes(target.read_bytes() + b' ')
        with patch.object(m, 'ps') as network:
            with self.assertRaisesRegex(ValueError, 'changed'):
                m.acquire(self.root, self.state, Path('fake-pwsh'), offline=True)
            network.assert_not_called()
        self.assertFalse((self.root / 'result.json').exists())
        self.assertFalse((self.root / 'release').exists())

    def test_deadline_cannot_reset_on_resume(self):
        self.state['deadlineEpoch'] = time.time() - 1
        self.bind_job()
        with patch.object(m, 'ps') as network:
            with self.assertRaisesRegex(ValueError, 'deadline|ceiling'):
                m.acquire(self.root, self.state, Path('fake-pwsh'))
            network.assert_not_called()
        self.assertEqual(self.state['requests'], 0)

    def test_edited_deadline_or_counter_refused_before_dispatch(self):
        for key, value in [('deadlineEpoch', time.time() + 1000), ('requests', 0)]:
            with self.subTest(key=key):
                state = json.loads(json.dumps(self.state))
                if key == 'requests':
                    state['sources'] = [{'name': 'roadtools', 'uri': m.SOURCES['roadtools'],
                                         'attempts': 1, 'status': 'Intent', 'sha256': None,
                                         'bytes': 0, 'retrievedAt': None}]
                state[key] = value
                with patch.object(m, 'ps') as network:
                    with self.assertRaisesRegex(ValueError, 'binding|requests|membership'):
                        m.acquire(self.root, state, Path('fake-pwsh'))
                    network.assert_not_called()
                self.assertFalse((self.root / 'release').exists())

    def test_offline_missing_input_cannot_dispatch(self):
        with patch.object(m, 'ps') as network:
            with self.assertRaisesRegex(ValueError, 'Offline'):
                m.acquire(self.root, self.state, Path('fake-pwsh'), offline=True)
            network.assert_not_called()
        self.assertFalse((self.root / 'release').exists())

    def test_inventory_detects_edit_addition_and_symlink(self):
        p = self.root / 'retained.json'
        p.write_text('{}')
        expected = m.inventory(self.root)
        p.write_text('{"changed":true}')
        with self.assertRaisesRegex(ValueError, 'changed'):
            m.check_inventory(self.root, expected)
        p.write_text('{}')
        (self.root / 'unexpected').write_text('extra')
        with self.assertRaisesRegex(ValueError, 'changed'):
            m.check_inventory(self.root, expected)
        (self.root / 'link').symlink_to(p)
        with self.assertRaisesRegex(ValueError, 'Linked'):
            m.inventory(self.root)

    def test_moved_or_dirty_baseline_refused(self):
        repo = Path(self.temp.name) / 'baseline'
        repo.mkdir()
        def git(*args):
            return subprocess.check_output(['git', '-C', str(repo), *args], text=True).strip()
        git('init', '-q')
        git('config', 'user.name', 'Synthetic fixture')
        git('config', 'user.email', 'fixture@invalid')
        (repo / 'applications.json').write_text('{}')
        git('add', '.')
        git('-c', 'core.hooksPath=/dev/null', '-c', 'commit.gpgsign=false', 'commit', '-qm', 'Synthetic baseline')
        expected = git('rev-parse', 'HEAD')
        m.checked_baseline(repo, expected)
        (repo / 'applications.json').write_text('{"changed":true}')
        with self.assertRaisesRegex(ValueError, 'moved|dirty'):
            m.checked_baseline(repo, expected)
        git('add', '.')
        git('-c', 'core.hooksPath=/dev/null', '-c', 'commit.gpgsign=false', 'commit', '-qm', 'Synthetic moved baseline')
        with self.assertRaisesRegex(ValueError, 'moved|dirty'):
            m.checked_baseline(repo, expected)

    def prepare_refresh(self, complete=True):
        self.state['complete'] = True
        m.write(self.root / 'acquisition.json', self.state)
        exchange = self.root / 'public-exchange'
        exchange.mkdir()
        m.write(exchange / 'health.json', {'complete': complete})
        m.write(self.root / 'exchange-inventory.json', m.inventory(exchange))
        return Path(self.temp.name) / 'baseline'

    def test_incomplete_projection_never_becomes_publishable(self):
        baseline = self.prepare_refresh(complete=False)
        with patch.object(m, 'assert_job', return_value={'sourceRevision': '1' * 40}), \
             patch.object(m, 'acquire'), patch.object(m.adapter, 'reconcile') as reconcile, \
             patch.object(m, 'release') as release:
            with self.assertRaisesRegex(ValueError, 'Incomplete|invalid'):
                m.refresh(baseline, '2' * 40, self.root, Path('fake-native'), Path('fake-pwsh'), offline=True)
            reconcile.assert_not_called()
            release.assert_not_called()
        self.assertFalse((self.root / 'result.json').exists())
        self.assertFalse((self.root / 'release').exists())

    def test_acquisition_seal_checked_before_any_fetch(self):
        baseline = self.prepare_refresh()
        m.write(self.root / 'acquisition-seal.json', {'sha256': m.adapter.digest((self.root / 'acquisition.json').read_bytes())})
        state = m.adapter.read(self.root / 'acquisition.json')
        state['sources'] = []
        state['requests'] = 0
        state['complete'] = False
        m.write(self.root / 'acquisition.json', state)
        with patch.object(m, 'assert_job', return_value={}), patch.object(m, 'acquire') as fetch, patch.object(m, 'ps') as dispatch:
            with self.assertRaisesRegex(ValueError, 'acquisition evidence changed'):
                m.refresh(baseline, '2' * 40, self.root, Path('fake-native'), Path('fake-pwsh'))
            fetch.assert_not_called()
            dispatch.assert_not_called()
        self.assertFalse((self.root / 'result.json').exists())

    def test_missing_exchange_cannot_replace_saved_inventory(self):
        baseline = self.prepare_refresh()
        original = (self.root / 'exchange-inventory.json').read_bytes()
        (self.root / 'public-exchange/health.json').unlink()
        (self.root / 'public-exchange').rmdir()
        with patch.object(m, 'assert_job', return_value={}), patch.object(m, 'acquire'), patch.object(m, 'ps') as collector:
            with self.assertRaisesRegex(ValueError, 'Frozen exchange is missing'):
                m.refresh(baseline, '2' * 40, self.root, Path('fake-native'), Path('fake-pwsh'), offline=True)
            collector.assert_not_called()
        self.assertEqual((self.root / 'exchange-inventory.json').read_bytes(), original)
        self.assertFalse((self.root / 'result.json').exists())

    def test_dotdot_work_alias_inside_baseline_refused_before_initialization(self):
        baseline = Path(self.temp.name) / 'baseline'
        baseline.mkdir()
        alias = baseline / '..' / 'baseline' / 'new-work'
        with patch.object(m, 'initialize') as initialize:
            with self.assertRaisesRegex(ValueError, 'overlapping'):
                m.refresh(baseline, '2' * 40, alias, Path('fake-native'), Path('fake-pwsh'))
            initialize.assert_not_called()
        self.assertEqual(list(baseline.iterdir()), [])

    def test_delayed_projection_keeps_capture_date_and_frozen_input(self):
        now = datetime.now(timezone.utc)
        start = (now - timedelta(hours=2)).isoformat()
        finish = (now - timedelta(hours=1)).isoformat()
        projection = (now - timedelta(minutes=1)).isoformat()
        acquisition = {'kind': 'FrozenSyntheticFixtureInputs', 'schemaVersion': 1,
                       'authentication': False, 'startedAt': start, 'finishedAt': finish,
                       'requests': 0, 'complete': True,
                       'sources': [{'name': name, 'status': 'Captured', 'retrievedAt': finish,
                                    'attempts': 1, 'bytes': 1} for name in m.SOURCES]}
        health = {'collectedAt': projection, 'complete': True, 'candidateCount': 1}
        incoming = {'CreatedAt': projection, 'Origins': {'Discovery///': {'LastRunId': 'fixture',
                     'LastObservedAt': projection}}, 'Runs': [{'Id': 'fixture', 'ObservedAt': projection,
                     'RecordedAt': projection}], 'Applications': {'fixture-app': {
                     'FirstSeenAt': projection, 'LastSeenAt': projection,
                     'Records': {'Discovery///': {'FirstSeenAt': projection, 'LastSeenAt': projection,
                                  'CurrentVersionFirstSeenAt': projection}}}}}
        frozen = json.dumps(incoming, sort_keys=True)
        normalized = m.adapter.capture_observation(incoming, health, acquisition)
        self.assertEqual(normalized['Origins']['Discovery///']['LastObservedAt'], finish)
        self.assertEqual(normalized['Runs'][0]['ObservedAt'], finish)
        self.assertEqual(normalized['Runs'][0]['RecordedAt'], projection)
        self.assertEqual(normalized['Applications']['fixture-app']['FirstSeenAt'], finish)
        self.assertEqual(normalized['Applications']['fixture-app']['LastSeenAt'], finish)
        self.assertEqual(normalized['Applications']['fixture-app']['Records']['Discovery///']['CurrentVersionFirstSeenAt'], finish)
        self.assertEqual(json.dumps(incoming, sort_keys=True), frozen)
        health['collectedAt'] = (now + timedelta(minutes=10)).isoformat()
        with self.assertRaisesRegex(ValueError, 'capture window'):
            m.adapter.capture_observation(incoming, health, acquisition)

    def test_edited_cached_result_cannot_claim_publishable(self):
        baseline = self.prepare_refresh()
        def reconcile(root, output, native, pwsh):
            output.mkdir()
            m.write(output / 'receipt.json', {'synthetic': True})
            return {'counts': {'additions': 0, 'contentChanges': 0, 'removals': 0}}
        with patch.object(m, 'assert_job', return_value={'sourceRevision': '1' * 40}), \
             patch.object(m, 'acquire'), patch.object(m.adapter, 'reconcile', side_effect=reconcile), \
             patch.object(m, 'release') as release:
            result = m.refresh(baseline, '2' * 40, self.root, Path('fake-native'), Path('fake-pwsh'), offline=True)
            result['status'] = 'CandidatePrepared'
            result['publishable'] = True
            m.write(self.root / 'result.json', result)
            with self.assertRaisesRegex(ValueError, 'receipt changed'):
                m.refresh(baseline, '2' * 40, self.root, Path('fake-native'), Path('fake-pwsh'), offline=True)
            release.assert_not_called()
        self.assertFalse((self.root / 'release').exists())

    def test_no_change_does_not_create_release(self):
        baseline = self.prepare_refresh()
        def reconcile(root, output, native, pwsh):
            output.mkdir()
            m.write(output / 'receipt.json', {'synthetic': True})
            return {'counts': {'additions': 0, 'contentChanges': 0, 'removals': 0}}
        with patch.object(m, 'assert_job', return_value={'sourceRevision': '1' * 40}), \
             patch.object(m, 'acquire'), patch.object(m.adapter, 'reconcile', side_effect=reconcile), \
             patch.object(m, 'release') as release:
            result = m.refresh(baseline, '2' * 40, self.root, Path('fake-native'), Path('fake-pwsh'), offline=True)
            self.assertEqual(result['status'], 'NoChange')
            self.assertFalse(result['publishable'])
            release.assert_not_called()
        self.assertFalse((self.root / 'release').exists())


if __name__ == '__main__':
    unittest.main(verbosity=2)
