#!/usr/bin/env python3
"""Compare retained public source observations to a published catalog, offline."""

import argparse
from datetime import datetime
import hashlib
import json
from pathlib import Path
import re
import signal
import subprocess
import sys

from tokenforge_offline_catalog import OfflineCatalog, app_id_is_canonical, decode


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode()


def digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def hex_id(value, length):
    return isinstance(value, str) and re.fullmatch(r'[0-9a-f]{%d}' % length, value)


def utc(value):
    if not isinstance(value, str):
        return False
    try:
        date = datetime.fromisoformat(value)
        return date.utcoffset() is not None and date.utcoffset().total_seconds() == 0
    except ValueError:
        return False


def claims_for(claims, url):
    return sorted({canonical(claim) for claim in claims if claim['Location'] == url})


COMPLETE_STATUSES = {'Unchanged', 'RevisionChangedSameContent', 'Compared'}
ISSUE_RECEIPT = Path(__file__).resolve().parents[1] / 'docs/discovery-coverage-issue-151.json'
REVIEW_FORMAT = 'TokenForgePublicCatalogReviewState'


def compare(baseline, observations, load_ledger, project, review_evidence=None):
    prior = {row['source']: row for row in baseline['Upstream']}
    if len(prior) != len(baseline['Upstream']) or set(prior) != {'roadtools', 'microsoftApps', 'resources'}:
        raise ValueError('Baseline source stamps are incomplete or duplicated')
    if not isinstance(observations, dict) or set(observations) - set(prior):
        raise ValueError('Unknown source observation')
    ledger = None
    sources = {}
    additions = {}
    for name, old in sorted(prior.items()):
        if not hex_id(old.get('revision'), 40) or not hex_id(old.get('sha256'), 64):
            raise ValueError('Invalid published source stamp')
        item = {'previousRevision': old['revision'], 'url': old['url']}
        sources[name] = item
        stamp = observations.get(name)
        if not isinstance(stamp, dict) or stamp.get('status') == 'Unavailable':
            item['status'] = 'Unavailable'
            continue
        if (set(stamp) - {'revision', 'committedAt', 'checkedAt', 'sha256'}
                or not hex_id(stamp.get('revision'), 40)
                or not utc(stamp.get('checkedAt'))
                or (stamp.get('committedAt') is not None and not utc(stamp['committedAt']))
                or ('sha256' in stamp and not hex_id(stamp['sha256'], 64))):
            item['status'] = 'InvalidStamp'
            continue
        item.update(revision=stamp['revision'], checkedAt=stamp['checkedAt'], committedAt=stamp.get('committedAt'))
        capture_hash = stamp.get('sha256')
        if stamp['revision'] == old['revision']:
            item['status'] = 'Unchanged' if capture_hash in (None, old['sha256']) else 'StampConflict'
            continue
        if not capture_hash:
            item['status'] = 'NeedsCapture'
            continue
        try:
            projected = project(name, capture_hash)
            if not isinstance(projected, dict):
                raise ValueError('Invalid projection')
            current = {}
            for app_id, claims in projected.items():
                if not app_id_is_canonical(app_id) or not isinstance(claims, list):
                    raise ValueError('Invalid projected AppId or claims')
                source_claims = claims_for(claims, old['url'])
                if not source_claims or any(claim['Location'] != old['url'] for claim in claims):
                    raise ValueError('Unexpected source claim')
                current[app_id] = source_claims
        except subprocess.TimeoutExpired:
            item['status'] = 'Interrupted'
            continue
        except FileNotFoundError:
            item['status'] = 'NeedsCapture'
            continue
        except (subprocess.SubprocessError, ValueError, KeyError, TypeError, OSError):
            item['status'] = 'InvalidCapture'
            continue
        if capture_hash == old['sha256']:
            item.update(status='RevisionChangedSameContent', verifiedCaptureSha256=capture_hash)
            continue
        if ledger is None:
            ledger = load_ledger()
        previous = {key: claims_for(claims, old['url']) for key, claims in ledger.items()}
        previous = {key: claims for key, claims in previous.items() if claims}
        changes = []
        for app_id in sorted(set(current) | set(previous)):
            before, after = previous.get(app_id), current.get(app_id)
            if app_id not in ledger:
                additions.setdefault(app_id, []).append(name)
            elif before != after:
                changes.append({'appId': app_id,
                                'previousClaimsSha256': digest([c.decode() for c in before]) if before else None,
                                'currentClaimsSha256': digest([c.decode() for c in after]) if after else None})
            if review_evidence is not None and before != after:
                evidence = {
                    'source': name, 'url': old['url'],
                    'previousRevision': old['revision'], 'previousCaptureSha256': old['sha256'],
                    'revision': stamp['revision'], 'captureSha256': capture_hash,
                    'checkedAt': stamp['checkedAt'],
                    'reason': ('NewAppId' if app_id not in ledger else
                               'SourceClaimAdded' if before is None else
                               'SourceClaimRemoved' if after is None else 'SourceClaimChanged'),
                    'previousClaims': [decode(claim) for claim in before or ()],
                    'currentClaims': [decode(claim) for claim in after or ()],
                }
                review_evidence.setdefault(app_id, []).append(evidence)
        item.update(status='Compared', verifiedCaptureSha256=capture_hash, provenanceChanges=changes)
    complete = all(row['status'] in COMPLETE_STATUSES
                   for row in sources.values())
    return {'complete': complete, 'sources': sources,
            'newApplications': [{'appId': key, 'sources': names, 'disposition': 'Pending'}
                                for key, names in sorted(additions.items())]}


def load_review_state(path, baseline_commit):
    if path is None:
        receipt = decode(ISSUE_RECEIPT.read_bytes())
        cases = {}
        if baseline_commit == receipt['postReviewCommit']:
            cases = {row['appId']: {'status': 'Unresolved', 'issue': receipt['issue'], 'evidenceIds': []}
                     for row in receipt['candidates'] if row['ownershipReview'] is None}
        return {'format': REVIEW_FORMAT, 'schemaVersion': 1, 'cases': cases}

    with path.open('rb') as stream:
        raw = stream.read(16 * 1024 * 1024 + 1)
    if len(raw) > 16 * 1024 * 1024:
        raise ValueError('Review state exceeds 16 MiB')
    state = decode(raw)
    if (not isinstance(state, dict) or set(state) != {'format', 'schemaVersion', 'cases'}
            or state['format'] != REVIEW_FORMAT or type(state['schemaVersion']) is not int
            or state['schemaVersion'] != 1 or not isinstance(state['cases'], dict)):
        raise ValueError('Invalid review state')
    for app_id, case in state['cases'].items():
        if (not app_id_is_canonical(app_id) or not isinstance(case, dict)
                or set(case) != {'status', 'issue', 'evidenceIds'}
                or case['status'] not in ('Pending', 'Unresolved')
                or (case['issue'] is not None and (type(case['issue']) is not int or case['issue'] < 1))
                or not isinstance(case['evidenceIds'], list)
                or not all(hex_id(value, 64) for value in case['evidenceIds'])
                or case['evidenceIds'] != sorted(set(case['evidenceIds']))):
            raise ValueError('Invalid review case')
    return state


def review_handoff(receipt, state, observed):
    gaps = {name: row['status'] for name, row in receipt['sources'].items()
            if row['status'] not in COMPLETE_STATUSES}
    if gaps:
        return {'coverageGaps': gaps, 'reviewItemCount': None, 'reviewItems': None, 'nextState': None}

    items = []
    cases = state['cases']
    for app_id, evidence in sorted(observed.items()):
        prior = cases.get(app_id)
        seen = set(prior['evidenceIds']) if prior else set()
        new = []
        for row in evidence:
            # Capture and check timestamps are provenance. Only different claim evidence opens work.
            evidence_id = digest([row[key] for key in ('url', 'previousClaims', 'currentClaims')])
            if evidence_id not in seen:
                new.append({**row, 'evidenceId': evidence_id})
                seen.add(evidence_id)
        if not new:
            continue
        action = 'Open' if prior is None else 'Reopen' if prior['status'] == 'Unresolved' else 'Update'
        issue = prior['issue'] if prior else None
        items.append({'appId': app_id, 'issue': issue, 'action': action,
                      'disposition': 'Pending', 'evidence': new})
        cases[app_id] = {'status': 'Pending', 'issue': issue, 'evidenceIds': sorted(seen)}
    return {'coverageGaps': {}, 'reviewItemCount': len(items), 'reviewItems': items, 'nextState': state}


def interrupt_replay(_signum, _frame):
    raise KeyboardInterrupt


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--baseline-repo', type=Path, required=True)
    parser.add_argument('--baseline-commit', required=True)
    parser.add_argument('--observations', type=Path, required=True)
    parser.add_argument('--captures', type=Path)
    parser.add_argument('--native', type=Path)
    parser.add_argument('--review', action='store_true', help='Emit an offline ownership-review handoff')
    parser.add_argument('--review-state', type=Path, help='Prior nextState JSON or operator-maintained review state')
    args = parser.parse_args()
    catalog = OfflineCatalog(args.baseline_repo, args.baseline_commit)
    nonverified = catalog.partition(False)

    def load_ledger():
        verified = catalog.partition(True)['Applications']
        excluded = nonverified['Applications']
        catalog.app_ids(verified, excluded)
        records = {key: row['CatalogRecord'] for key, row in excluded.items()}
        records.update(verified)
        return {key: row['Records']['Discovery///']['Attributes'].get('SourceClaims', []) for key, row in records.items()}

    def project(name, sha256):
        if args.captures is None or not (capture := args.captures / (name + '.json')).is_file():
            raise FileNotFoundError(name)
        if args.native is None:
            raise ValueError('Changed captures require an approved local runtime')
        script = Path(__file__).with_name('Read-TokenForgeCatalogSourceClaims.ps1')
        result = subprocess.run(['pwsh', '-NoProfile', '-NonInteractive', '-File', str(script),
                                 '-Name', name, '-CapturePath', str(capture), '-Sha256', sha256,
                                 '-NativeExecutablePath', str(args.native)], capture_output=True, check=True, timeout=180)
        return decode(result.stdout)

    with args.observations.open('rb') as stream:
        raw = stream.read(16385)
    if len(raw) > 16384:
        raise ValueError('Observation document exceeds 16 KiB')
    observations = decode(raw)
    review = args.review or args.review_state is not None
    if review:
        state = load_review_state(args.review_state, catalog.commit)
        evidence = {}
        previous_handler = signal.signal(signal.SIGTERM, interrupt_replay)
        try:
            receipt = compare(nonverified, observations, load_ledger, project, evidence)
        except KeyboardInterrupt:
            receipt = {'complete': False, 'newApplications': [],
                       'sources': {row['source']: {'status': 'Interrupted', 'url': row['url'],
                                                  'previousRevision': row['revision']}
                                   for row in nonverified['Upstream']}}
        finally:
            signal.signal(signal.SIGTERM, previous_handler)
        receipt['review'] = review_handoff(receipt, state, evidence)
    else:
        receipt = compare(nonverified, observations, load_ledger, project)
    print(json.dumps({'format': 'TokenForgePublicCatalogDelta', 'schemaVersion': 1,
                      'baselineCommit': args.baseline_commit, 'revisionLabelsVerified': False, 'observationsSha256': hashlib.sha256(raw).hexdigest(),
                      **receipt}, sort_keys=True, indent=2))
    return 0 if receipt['complete'] else 2


if __name__ == '__main__':
    try:
        sys.exit(main())
    except (OSError, subprocess.SubprocessError, ValueError, KeyError, TypeError) as exc:
        sys.exit(f'Catalog delta refused: {exc}')
