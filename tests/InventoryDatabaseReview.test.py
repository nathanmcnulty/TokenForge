#!/usr/bin/env python3
"""Focused offline database-review fixtures. No native runtime, network or authentication."""
import copy
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

REPO = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('review', REPO / 'scripts/New-TokenForgeInventoryDatabaseReview.py')
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
APP = '11111111-1111-1111-1111-111111111111'
RESOURCE = '22222222-2222-2222-2222-222222222222'
PERMISSION = '33333333-3333-3333-3333-333333333333'
OTHER = '44444444-4444-4444-4444-444444444444'
STAMP = '2026-11-01T00:00:00Z'


def record(conflict=False):
    return {'Kind': 'Discovery', 'Attributes': {'Name': 'Public fixture', 'SourceClaims': [
        {'Evidence': 'PublishedEntraDocs', 'Location': 'https://example.test/public', 'Name': 'Public fixture'}],
        'MetadataConflicts': [{'Field': 'Name', 'Values': ['Public fixture', 'Other public label']}] if conflict else []},
        'ContentSha256': 'a' * 64, 'Sources': [], 'FirstSeenAt': STAMP, 'LastSeenAt': STAMP,
        'CurrentVersionFirstSeenAt': STAMP, 'PreviousVersions': []}


def private_row(identifier=APP, own=False, kinds=(), observed=False):
    return {'Identifier': identifier, 'Namespace': 'AppId', 'MicrosoftOwnership': 'DirectoryVerified' if own else 'Unresolved',
            'OwnershipEvidence': [{'Evidence': 'VerifiedMicrosoftDirectoryOwner'}] if own else [],
            'EntityEvidence': [{'Evidence': 'FixtureRole', 'Kind': k} for k in kinds],
            'ObservedSignIn': [{'Evidence': 'ObservedSignInNotOwnership', 'Count': 12345}] if observed else [],
            'ReviewReasons': [], 'SuccessfulTokenIssuance': [], 'VerifiedApiAccess': []}


class ReviewTests(unittest.TestCase):
    def setUp(self):
        self.baseline = {'Format': 'TokenForgeApplicationMetadata', 'SchemaVersion': 2, 'Runs': [],
                         'Applications': {APP: {'FirstSeenAt': STAMP, 'Records': {'Discovery///': record()}}}}
        self.graph = {'ResourceId': RESOURCE, 'Source': 'https://example.test/definitions', 'Permissions': {
            'delegatedScopesList': [{'id': PERMISSION, 'value': 'Read.Fixture'}], 'applicationScopesList': []}}
        self.definitions = {'Format': 'TokenForgeIdentifierDefinitions', 'SchemaVersion': 1, 'Definitions': []}
        self.raw = [{'AppId': APP, 'AppDisplayName': 'Public fixture', 'AppOwnerOrganizationId': None, 'Source': 'EntraDocs'}]

    def public(self, candidate=None, raw=None):
        return m.public_review(self.baseline, candidate or self.baseline, self.graph, self.definitions,
                               raw or self.raw, self.raw, {'Fixture': 'PublicInputsOnly'})

    def private(self, row, public=None, more=None):
        rows = {'AppId:' + row['Identifier']: row, **(more or {})}
        return m.private_review({'Identifiers': rows}, public or self.public(), {})['ApplicationDecisions'][0]

    def test_positive_nonapp_definition_is_conflict_not_removal(self):
        self.baseline['Applications'][PERMISSION] = copy.deepcopy(self.baseline['Applications'][APP])
        before = m.encode(self.baseline)
        public = self.public()
        row = public['Rows'][PERMISSION]
        self.assertEqual((row['Classification'], row['Priority']), ('AppNonAppConflict', 0))
        self.assertEqual(row['NonAppDefinitions'][0]['Kind'], 'Permission')
        self.assertEqual(m.encode(self.baseline), before)

    def test_current_public_definition_precedes_verified_private_role(self):
        self.baseline['Applications'][PERMISSION] = copy.deepcopy(self.baseline['Applications'][APP])
        public = self.public()
        row = private_row(identifier=PERMISSION, own=True, kinds=['ClientApplication'])
        actual = self.private(row, public)
        self.assertEqual(public['Rows'][PERMISSION]['Classification'], 'AppNonAppConflict')
        self.assertEqual((actual['Bucket'], actual['Priority']), ('AppNonAppConflict', 0))
        self.assertTrue(actual['DirectoryVerifiedMicrosoftOwnership'])
        self.assertEqual(actual['EstablishedRoles'], ['ClientApplication'])
        self.assertEqual(actual['NonAppDefinitions'], public['Rows'][PERMISSION]['NonAppDefinitions'])
        self.assertEqual(actual['RetainedEvidence'], row)
        self.assertNotIn('NonAppDefinitions', row)

    def test_positive_definition_without_app_claim_stays_typed_nonapp(self):
        self.assertEqual(self.public()['Rows'][PERMISSION]['Classification'], 'KnownNonAppIdentifier')

    def test_current_and_historical_conflicts_are_separate(self):
        r = self.baseline['Applications'][APP]['Records']['Discovery///']
        old = record(True)
        r['PreviousVersions'] = [{k: old[k] for k in ('Attributes', 'ContentSha256', 'Sources', 'FirstSeenAt', 'LastSeenAt')}]
        row = self.public()['Rows'][APP]
        self.assertFalse(row['CurrentClaimConflicts'])
        self.assertTrue(row['HistoricalClaimConflicts'])
        self.assertEqual(row['Classification'], 'HistoricalPublicClaimConflict')
        r['Attributes']['MetadataConflicts'] = old['Attributes']['MetadataConflicts']
        self.assertEqual(self.public()['Rows'][APP]['Classification'], 'CurrentPublicClaimConflict')

    def test_current_claims_and_conflicts_use_version_start_not_record_lifetime(self):
        r = self.baseline['Applications'][APP]['Records']['Discovery///']
        r['CurrentVersionFirstSeenAt'] = '2026-11-02T00:00:00Z'
        r['LastSeenAt'] = '2026-11-03T00:00:00Z'
        r['Attributes']['MetadataConflicts'] = record(True)['Attributes']['MetadataConflicts']
        row = self.public()['Rows'][APP]
        for payload in (row['CurrentClaims'][0], row['CurrentClaimConflicts'][0]):
            self.assertEqual(payload['FirstSeenAt'], r['CurrentVersionFirstSeenAt'])
            self.assertEqual(payload['RecordFirstSeenAt'], STAMP)

    def test_verified_ownership_does_not_clear_public_claim_conflict(self):
        self.baseline['Applications'][APP]['Records']['Discovery///']['Attributes']['MetadataConflicts'] = record(True)['Attributes']['MetadataConflicts']
        row = self.private(private_row(own=True, kinds=['ClientApplication']))
        self.assertEqual(row['Bucket'], 'PublicClaimConflict')
        self.assertTrue(row['DirectoryVerifiedMicrosoftOwnership'])

    def test_verified_ownership_without_role_is_distinct(self):
        self.assertEqual(self.private(private_row(own=True))['Bucket'], 'VerifiedMicrosoftOwnedRoleUnresolved')
        self.assertEqual(self.private(private_row(own=True, kinds=['ClientApplication']))['Bucket'], 'VerifiedMicrosoftOwnedRoleResolved')

    def test_observation_or_issuance_does_not_verify_ownership(self):
        row = private_row(observed=True, kinds=['ClientApplication'])
        row['SuccessfulTokenIssuance'] = [{'Evidence': 'RetainedMatchedIssuanceNotApiAccess'}]
        actual = self.private(row)
        self.assertEqual(actual['Bucket'], 'ObservedOnlyOwnershipUnverified')
        self.assertFalse(actual['DirectoryVerifiedMicrosoftOwnership'])

    def test_private_only_definition_cannot_enter_public_output(self):
        public = self.public()
        definition = {'Identifier': APP, 'Namespace': 'Identifier', 'NonAppDefinitions': [
            {'Kind': 'Permission', 'Evidence': 'PrivateDirectoryPermissionDefinition', 'Label': 'private label'}]}
        private = self.private(private_row(own=True, kinds=['ClientApplication']), public,
                               {'Identifier:' + APP: definition})
        self.assertEqual(private['Bucket'], 'AppNonAppConflict')
        self.assertEqual(public['Rows'][APP]['Classification'], 'UnresolvedPublicCandidate')
        self.assertNotIn(b'private label', m.encode(public))

    def test_private_poison_does_not_change_public_bytes(self):
        before = m.encode(self.public())
        row = private_row(own=True, observed=True)
        row['PrivateName'] = 'secret-user@example.invalid'
        row['TenantAdded'] = True
        self.private(row)
        self.assertEqual(before, m.encode(self.public()))
        for forbidden in (b'secret-user', b'TenantAdded', b'ObservedSignIn', b'DirectoryVerified'):
            self.assertNotIn(forbidden, before)

    def test_old_application_omission_refused(self):
        candidate = copy.deepcopy(self.baseline)
        candidate['Applications'] = {}
        with self.assertRaisesRegex(ValueError, 'removed'):
            self.public(candidate)

    def test_historical_runs_and_first_seen_preserved(self):
        self.baseline['Runs'] = [{'Id': 'old', 'ObservedAt': STAMP}]
        candidate = copy.deepcopy(self.baseline)
        candidate['Runs'][0]['ObservedAt'] = '2026-11-02T00:00:00Z'
        with self.assertRaisesRegex(ValueError, 'run'):
            self.public(candidate)
        candidate = copy.deepcopy(self.baseline)
        candidate['Applications'][APP]['FirstSeenAt'] = '2026-11-02T00:00:00Z'
        with self.assertRaisesRegex(ValueError, 'first-seen'):
            self.public(candidate)

    def test_changed_payload_requires_exact_prior_version(self):
        candidate = copy.deepcopy(self.baseline)
        current = candidate['Applications'][APP]['Records']['Discovery///']
        current['Attributes']['Name'] = 'New public name'
        with self.assertRaisesRegex(ValueError, 'Replaced payload'):
            self.public(candidate)
        old = self.baseline['Applications'][APP]['Records']['Discovery///']
        current['PreviousVersions'] = [{k: old[k] for k in ('Attributes', 'Sources', 'ContentSha256', 'FirstSeenAt', 'LastSeenAt')}]
        self.public(candidate)

    def test_no_guid_suffix_guessing_or_placeholder_promotion(self):
        bad = [{**self.raw[0], 'AppId': APP + '\u00c2\u00a0'}, {**self.raw[0], 'AppId': '00000000-0000-0000-0000-000000000000'}]
        self.assertEqual(m.merill_records(bad), [])
        self.assertEqual(len(self.public(raw=bad)['Rows']), len(self.public()['Rows']))

    def test_successive_merill_label_changes_are_not_corroboration(self):
        raw = [{**self.raw[0], 'AppDisplayName': 'Renamed fixture', 'Source': 'Graph'}]
        public = self.public(raw=raw)
        self.assertEqual(len(public['MerillSnapshotChanges']), 1)
        self.assertEqual(public['Rows'][APP]['Classification'], 'UnresolvedPublicCandidate')

    def test_non_appid_namespaces_are_not_application_decisions(self):
        object_row = {'Identifier': OTHER, 'Namespace': 'ServicePrincipalObjectId'}
        actual = m.private_review({'Identifiers': {'AppId:' + APP: private_row(), 'ServicePrincipalObjectId:' + OTHER: object_row}}, self.public(), {})
        self.assertEqual(len(actual['ApplicationDecisions']), 1)

    def test_contradictory_ownership_refused(self):
        row = private_row(own=True)
        row['OwnershipEvidence'] = []
        with self.assertRaisesRegex(ValueError, 'Contradictory'):
            self.private(row)

    def test_public_replay_is_byte_identical(self):
        self.assertEqual(m.encode(self.public()), m.encode(self.public()))

    def test_duplicate_json_keys_refused(self):
        with self.assertRaises(ValueError):
            m.read(b'{"a":1,"a":2}')

    def test_tampered_pinned_input_refuses_before_output(self):
        with tempfile.TemporaryDirectory() as root:
            root = Path(root)
            source = root / 'source.json'
            source.write_bytes(b'{}')
            manifest = root / 'inputs.json'
            manifest.write_text(json.dumps({'Inputs': {'Inventory': {'Path': str(source), 'Sha256': '0' * 64, 'Bytes': 2}}}))
            with self.assertRaisesRegex(ValueError, 'Pinned input mismatch'):
                m.prepare(manifest, root / 'output')
            self.assertFalse((root / 'output').exists())

    def test_nonapplication_release_file_changed_during_copy_is_refused(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            roots = {key: root / key for key in ('BaselineRoot', 'PreparedRoot')}
            for path in roots.values():
                path.mkdir()
                (path / 'applications.json').write_bytes(b'{}')
                (path / 'unrelated.txt').write_bytes(b'pinned public bytes')
            manifest = {key + 'Files': m.files(path) for key, path in roots.items()}
            candidate = root / 'output/candidate'
            candidate.mkdir(parents=True)
            for name in ('applications.json', 'unrelated.txt'):
                (candidate / name).write_bytes((roots['PreparedRoot'] / name).read_bytes())
            m.verify_trees(roots, manifest, root / 'output')
            (candidate / 'unrelated.txt').write_bytes(b'changed while copying')
            with self.assertRaisesRegex(ValueError, 'Copied prepared release'):
                m.verify_trees(roots, manifest, root / 'output')
            (candidate / 'unrelated.txt').write_bytes(b'pinned public bytes')
            (roots['PreparedRoot'] / 'unrelated.txt').write_bytes(b'changed source tree')
            with self.assertRaisesRegex(ValueError, 'Pinned data tree'):
                m.verify_trees(roots, manifest, root / 'output')

    def test_late_failure_marks_partial_and_does_not_fabricate_completion(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / 'review'
            def fail(manifest, target):
                target.mkdir()
                (target / 'candidate-manifest.json').write_bytes(b'{}')
                raise ValueError('Synthetic late immutable-input failure')
            with patch.object(m, '_prepare', fail):
                with self.assertRaisesRegex(ValueError, 'Synthetic late'):
                    m.prepare(None, output)
            self.assertTrue((output / 'FAILED').exists())
            self.assertFalse((output / 'receipt.json').exists())
            self.assertEqual((output / 'FAILED').stat().st_mode & 0o777, 0o600)

    def test_refusal_does_not_modify_existing_historical_output(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary)
            with patch.object(m, '_prepare', side_effect=ValueError('Existing output')):
                with self.assertRaises(ValueError):
                    m.prepare(None, output)
            self.assertFalse((output / 'FAILED').exists())


if __name__ == '__main__':
    unittest.main(verbosity=2)
