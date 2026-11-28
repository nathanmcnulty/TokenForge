#!/usr/bin/env python3
"""Measure discovery coverage from the pinned catalog and retained batch, offline."""

import argparse
from collections import Counter
import hashlib
from itertools import combinations
import json
from pathlib import Path
import subprocess
import sys

from tokenforge_offline_catalog import OfflineCatalog, app_id_is_canonical, decode


RECEIPT = Path(__file__).resolve().parents[1] / 'docs/discovery-coverage-issue-151.json'
SOURCES = ('microsoftApps', 'resources', 'roadtools')
ZERO_ID = '00000000-0000-0000-0000-000000000000'
SIGN_IN_STREAMS = ('interactiveUser', 'nonInteractiveUser', 'servicePrincipal', 'managedIdentity')


def set_metrics(sources, catalog_ids):
    """Summarize comparable evidence sets, preserving unknown input memberships."""
    available = {name: ids for name, ids in sources.items() if ids is not None}
    union = set().union(*available.values())
    complete = len(available) == len(sources)
    return {
        'allSourceSetsAvailable': complete,
        'observedUnionIds': len(union) if available else None,
        'allSourceOverlapIds': len(set.intersection(*available.values())) if complete else None,
        'idsOutsideCatalog': len(union - catalog_ids) if available else None,
        'catalogIdsOutsideUnion': len(catalog_ids - union) if complete else None,
        'sources': {
            name: {
                'distinctIds': len(ids) if ids is not None else None,
                'uniqueIds': len(ids - set().union(*(other for key, other in available.items() if key != name)))
                if complete else None,
            }
            for name, ids in sources.items()
        },
        'pairwiseOverlap': [
            {'sources': [left, right],
             'distinctIds': len(sources[left] & sources[right]) if left in available and right in available else None}
            for left, right in combinations(sources, 2)
        ],
    }


def capture_ids(name, path, sha256):
    # Only project identity membership from the exact published bytes.
    with path.open('rb') as stream:
        raw = stream.read(8388609)
    if len(raw) > 8388608 or hashlib.sha256(raw).hexdigest() != sha256:
        raise ValueError(f'{name} capture exceeds the size limit or fails the pinned SHA-256')
    data = decode(raw)
    if name == 'roadtools':
        values = list(data['apps']) + list(data['resourceidentifiers'].values())
        for app in data['apps'].values():
            values.extend(app['scopes'])
    elif name == 'resources':
        values = [row['resourceId'] for row in data]
    else:
        values = []
        for row in data:
            value = row['AppId']
            if row['Source'] == 'EntraDocs':
                value = value.strip()
                if not app_id_is_canonical(value.lower()) and value.lower() != ZERO_ID:
                    continue
            values.append(value)
    ids = {value.lower() for value in values} - {ZERO_ID}
    if not all(app_id_is_canonical(value) for value in ids):
        raise ValueError(f'{name} capture contains an invalid AppId')
    return ids


def partitions(catalog):
    verified = catalog.partition(True)['Applications']
    nonverified = catalog.partition(False)
    excluded = nonverified['Applications']
    return verified, excluded, catalog.app_ids(verified, excluded), nonverified


def discovery_attributes(record):
    return record['Records']['Discovery///']['Attributes']


def evidence_gaps(records):
    return {
        'withoutPublishedOwnerTenantId': sum(not row.get('OwnerTenantId') for row in records),
        'withoutRecordedSignInAudience': sum(not row.get('SignInAudience') for row in records),
    }


def owner_tenancy_evidence(evidence):
    outside = [row for row in evidence if row['OwnerOutsideTargetTenant'] is True]
    return {
        'ownerOutsideTargetTenant': len(outside),
        'outsideOwnerFromApplicationServicePrincipal': sum(
            row['ServicePrincipalType'] == 'Application' and row['Result'] in ('NewlyAdded', 'AlreadyPresent')
            for row in outside
        ),
        'outsideOwnerFromSignIn': sum(row['Result'] == 'OwnerObservedInSignIn' for row in outside),
    }


def upstream_report(stamps, records, catalog_ids, captures):
    by_name = {row['source']: row for row in stamps}
    if len(stamps) != len(SOURCES) or set(by_name) != set(SOURCES):
        raise ValueError('Pinned upstream stamps are incomplete or duplicated')
    claims_by_url = {row['url']: set() for row in stamps}
    for app_id, row in records.items():
        for claim in row.get('SourceClaims', []):
            if claim['Location'] in claims_by_url:
                claims_by_url[claim['Location']].add(app_id)

    claims, raw_sets, source_details = {}, {}, {}
    for name in SOURCES:
        stamp = by_name[name]
        claims[name] = claims_by_url[stamp['url']]
        try:
            ids = capture_ids(name, captures / (name + '.json'), stamp['sha256']) if captures else None
        except FileNotFoundError:
            ids = None
        raw_sets[name] = ids
        source_details[name] = {
            'url': stamp['url'],
            'revision': stamp['revision'],
            'expectedSha256': stamp['sha256'],
            'publishedDistinctIds': stamp['currentIdCount'],
            'catalogClaimCountMatchesPublished': len(claims[name]) == stamp['currentIdCount'],
            'captureStatus': 'missing' if ids is None else 'hashVerified',
            'captureCountMatchesPublished': len(ids) == stamp['currentIdCount'] if ids is not None else None,
            'captureOnlyIds': len(ids - claims[name]) if ids is not None else None,
            'catalogClaimOnlyIds': len(claims[name] - ids) if ids is not None else None,
        }
    return {
        'sourceEvidence': source_details,
        'retainedCatalogClaims': set_metrics(claims, catalog_ids),
        'rawCaptureReplay': set_metrics(raw_sets, catalog_ids),
    }


def review_batch(receipt, before, verified, excluded, verified_evidence):
    rows = receipt['candidates']
    ids = {row['appId'] for row in rows}
    if len(rows) != 17 or len(ids) != len(rows) or ids & before or not all(map(app_id_is_canonical, ids)):
        raise ValueError('Invalid candidate batch or a candidate was already in the pre-review catalog')
    attributed = {'sign-in': set(), 'provisioning': set()}
    outcomes = Counter()
    candidates = []
    for row in rows:
        app_id = row['appId']
        for source in row['sources']:
            attributed[source].add(app_id)
        review = row['ownershipReview']
        if review == 158 and verified_evidence.get(app_id, {}).get('Result') == 'AlreadyPresent':
            outcome = 'servicePrincipalOwnerVerified'
        elif review == 160 and verified_evidence.get(app_id, {}).get('Result') == 'OwnerObservedInSignIn':
            outcome = 'signInOwnerVerified'
        elif review is None and app_id not in verified and app_id not in excluded:
            outcome = 'managedIdentityOrOwnershipUnresolved'
        else:
            raise ValueError('Candidate ownership receipt disagrees with pinned catalog evidence')
        outcomes[outcome] += 1
        candidates.append({
            **row,
            'individualDisposition': outcome,
            'postReviewPartition': 'verified' if app_id in verified else 'absent',
            'signInSubstreams': None if 'sign-in' in row['sources'] else [],
        })

    aggregate = receipt['aggregateDispositions']
    expected = {
        'servicePrincipalOwnerVerified': aggregate['servicePrincipalOwnerVerified'],
        'signInOwnerVerified': aggregate['signInOwnerVerified'],
        'managedIdentityOrOwnershipUnresolved': aggregate['managedIdentity'] + aggregate['ownershipUnresolved'],
    }
    if outcomes != expected or set().union(*attributed.values()) != ids:
        raise ValueError('Candidate rows do not reconcile with the retained batch totals')

    return {
        'issue': receipt['issue'],
        'issueEdits': receipt['issueEdits'],
        'run': receipt['run'],
        'collection': {
            'documentedRequestedDays': 30,
            'documentedTerminalSources': [*SIGN_IN_STREAMS, 'provisioning'],
            'windowReceiptStatus': 'missing',
            'perSourceWindowCounts': None,
            'providerRetention': None,
            'distinctIdsBeforeCatalogFiltering': None,
        },
        'candidateSourceMembership': set_metrics(attributed, before),
        'aggregateDispositions': aggregate,
        'observedLabels': {
            'audience': dict(Counter(row['audienceLabel'] for row in candidates)),
            'publisher': dict(Counter(row['publisherLabel'] for row in candidates)),
        },
        'individualDispositions': dict(outcomes),
        'managedIdentityAppId': None,
        'candidates': sorted(candidates, key=lambda row: row['appId']),
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--catalog-repo', type=Path, default=Path('.'))
    parser.add_argument('--captures', type=Path, help='Directory containing retained public source JSON files')
    args = parser.parse_args()
    receipt = decode(RECEIPT.read_bytes())
    before_catalog = OfflineCatalog(args.catalog_repo, receipt['preReviewCommit'])
    after_catalog = OfflineCatalog(args.catalog_repo, receipt['postReviewCommit'])
    prior_verified, prior_excluded, prior_ids, _ = partitions(before_catalog)
    verified, excluded, catalog_ids, nonverified = partitions(after_catalog)
    evidence = after_catalog.verified_evidence()
    if evidence.keys() != verified.keys():
        raise ValueError('Verified evidence does not match verified partition membership')
    verified_attributes = {key: discovery_attributes(row) for key, row in verified.items()}
    excluded_attributes = {key: discovery_attributes(row['CatalogRecord']) for key, row in excluded.items()}
    report = {
        'format': 'TokenForgeDiscoveryCoverage',
        'schemaVersion': 1,
        'catalog': {
            'preReviewCommit': before_catalog.commit,
            'postReviewCommit': after_catalog.commit,
            'preReviewCounts': {'verified': len(prior_verified), 'nonVerified': len(prior_excluded), 'distinctIds': len(prior_ids)},
            'postReviewCounts': {'verified': len(verified), 'nonVerified': len(excluded), 'distinctIds': len(catalog_ids)},
            'newIds': sorted(catalog_ids - prior_ids),
            'removedIds': sorted(prior_ids - catalog_ids),
            'verifiedEvidenceResults': dict(Counter(row['Result'] for row in evidence.values())),
            'verifiedOwnerTenancyEvidence': owner_tenancy_evidence(evidence.values()),
            'nonVerifiedDispositions': dict(Counter(row['Disposition'] for row in excluded.values())),
            'verifiedAttributeGaps': evidence_gaps(verified_attributes.values()),
            'nonVerifiedAttributeGaps': evidence_gaps(excluded_attributes.values()),
            'totalMicrosoftOwnedMultiTenantPopulation': None,
        },
        'publicUpstream': upstream_report(nonverified['Upstream'], verified_attributes | excluded_attributes,
                                          catalog_ids, args.captures),
        'reviewBatch': review_batch(receipt, prior_ids, verified, excluded, evidence),
    }
    print(json.dumps(report, sort_keys=True, indent=2))


if __name__ == '__main__':
    try:
        main()
    except (OSError, subprocess.SubprocessError, ValueError, KeyError, TypeError) as exc:
        sys.exit(f'Discovery coverage refused: {exc}')
