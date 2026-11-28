"""Exercise the pinned replay and source evidence semantics."""

import hashlib
import json
import os
from pathlib import Path
import runpy
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / 'scripts/Measure-TokenForgeDiscoveryCoverage.py'
sys.path.insert(0, str(SCRIPT.parent))
REPORTER = runpy.run_path(str(SCRIPT))
COMMAND = [sys.executable, '-B', str(SCRIPT), '--catalog-repo', str(ROOT)]
RAW_CAPTURES = os.environ.get('TOKENFORGE_B1_CAPTURES')


class DiscoveryCoverageTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.output = subprocess.check_output(COMMAND)
        cls.report = json.loads(cls.output)

    def test_pinned_replay_is_byte_stable_and_reconciles_catalog(self):
        self.assertEqual(self.output, subprocess.check_output(COMMAND))
        catalog = self.report['catalog']
        self.assertEqual(catalog['preReviewCounts'], dict(verified=2062, nonVerified=3434, distinctIds=5496))
        self.assertEqual(catalog['postReviewCounts'], dict(verified=2066, nonVerified=3434, distinctIds=5500))
        self.assertEqual(catalog['removedIds'], [])
        self.assertEqual(catalog['verifiedEvidenceResults'],
                         dict(AlreadyPresent=227, NewlyAdded=1837, OwnerObservedInSignIn=2))
        self.assertEqual(catalog['verifiedOwnerTenancyEvidence'], dict(ownerOutsideTargetTenant=2066,
                         outsideOwnerFromApplicationServicePrincipal=2064, outsideOwnerFromSignIn=2))
        self.assertEqual(catalog['nonVerifiedDispositions'], dict(CouldntAdd=3431, Pending=3))
        self.assertEqual(catalog['verifiedAttributeGaps'],
                         dict(withoutPublishedOwnerTenantId=1289, withoutRecordedSignInAudience=2066))
        self.assertEqual(catalog['nonVerifiedAttributeGaps'],
                         dict(withoutPublishedOwnerTenantId=3420, withoutRecordedSignInAudience=3434))
        self.assertIsNone(catalog['totalMicrosoftOwnedMultiTenantPopulation'])

    def test_pinned_batch_keeps_candidate_sources_and_evidence_distinct(self):
        batch = self.report['reviewBatch']
        outcomes = batch['individualDispositions']
        self.assertEqual(outcomes, dict(servicePrincipalOwnerVerified=2, signInOwnerVerified=2,
                                        managedIdentityOrOwnershipUnresolved=13))
        self.assertEqual(batch['aggregateDispositions'], dict(servicePrincipalOwnerVerified=2,
                         signInOwnerVerified=2, managedIdentity=1, ownershipUnresolved=12))
        rows = batch['candidates']
        self.assertEqual(len({row['appId'] for row in rows}), 17)
        self.assertEqual([row['appId'] for row in rows if row['postReviewPartition'] == 'verified'],
                         self.report['catalog']['newIds'])
        self.assertEqual(batch['candidateSourceMembership']['sources'], {
            'provisioning': dict(distinctIds=14, uniqueIds=12),
            'sign-in': dict(distinctIds=5, uniqueIds=3),
        })
        self.assertEqual(batch['candidateSourceMembership']['allSourceOverlapIds'], 2)
        self.assertEqual(batch['observedLabels']['audience'], {'audience unknown': 15, 'multi-tenant': 2})
        self.assertTrue(all(row['signInSubstreams'] is None for row in rows if 'sign-in' in row['sources']))
        self.assertIsNone(batch['managedIdentityAppId'])
        self.assertEqual(batch['collection']['windowReceiptStatus'], 'missing')
        self.assertIsNone(batch['collection']['perSourceWindowCounts'])

    def test_catalog_claims_and_missing_capture_have_separate_metrics(self):
        upstream = self.report['publicUpstream']
        claims = upstream['retainedCatalogClaims']
        self.assertEqual(claims['sources'], {
            'microsoftApps': dict(distinctIds=4464, uniqueIds=3615),
            'resources': dict(distinctIds=1753, uniqueIds=125),
            'roadtools': dict(distinctIds=1674, uniqueIds=58),
        })
        self.assertEqual([pair['distinctIds'] for pair in claims['pairwiseOverlap']], [804, 792, 1571])
        self.assertEqual(claims['allSourceOverlapIds'], 747)
        self.assertEqual(claims['observedUnionIds'], 5471)
        self.assertEqual(claims['catalogIdsOutsideUnion'], 29)
        self.assertEqual(claims['idsOutsideCatalog'], 0)
        self.assertIsNone(upstream['rawCaptureReplay']['observedUnionIds'])
        self.assertTrue(all(row['captureStatus'] == 'missing' for row in upstream['sourceEvidence'].values()))

    def test_partial_and_observed_empty_capture_sets(self):
        metrics = REPORTER['set_metrics']({'one': {'a'}, 'empty': set(), 'missing': None}, {'a', 'b'})
        self.assertEqual(metrics['sources']['empty'], dict(distinctIds=0, uniqueIds=None))
        self.assertEqual(metrics['sources']['missing'], dict(distinctIds=None, uniqueIds=None))
        self.assertEqual([pair['distinctIds'] for pair in metrics['pairwiseOverlap']], [0, None, None])
        self.assertEqual(metrics['observedUnionIds'], 1)
        self.assertIsNone(metrics['catalogIdsOutsideUnion'])
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / 'resources.json'
            path.write_bytes(b'[]')
            self.assertEqual(REPORTER['capture_ids']('resources', path, hashlib.sha256(b'[]').hexdigest()), set())
            proc = subprocess.run([*COMMAND, '--captures', temp], capture_output=True, check=False)
        self.assertNotEqual(proc.returncode, 0)
        self.assertEqual(proc.stdout, b'')
        self.assertIn(b'fails the pinned SHA-256', proc.stderr)

    @unittest.skipUnless(RAW_CAPTURES, 'Set TOKENFORGE_B1_CAPTURES to retained pinned public captures')
    def test_actual_raw_capture_memberships_match_catalog_claims(self):
        command = [*COMMAND, '--captures', RAW_CAPTURES]
        output = subprocess.check_output(command)
        self.assertEqual(output, subprocess.check_output(command))
        upstream = json.loads(output)['publicUpstream']
        self.assertEqual(upstream['rawCaptureReplay'], upstream['retainedCatalogClaims'])
        self.assertEqual(len(upstream['sourceEvidence']), 3)
        for evidence in upstream['sourceEvidence'].values():
            self.assertEqual(evidence['captureStatus'], 'hashVerified')
            self.assertTrue(evidence['captureCountMatchesPublished'])
            self.assertEqual(evidence['captureOnlyIds'], 0)
            self.assertEqual(evidence['catalogClaimOnlyIds'], 0)


if __name__ == '__main__':
    unittest.main()
