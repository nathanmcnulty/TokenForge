#!/usr/bin/env python3
"""Compare retained public source observations to a published catalog, offline."""

import argparse
from datetime import datetime
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys
import uuid


def unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('Duplicate JSON key')
        result[key] = value
    return result


def decode(raw):
    return json.loads(raw, object_pairs_hook=unique)


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


def compare(baseline, observations, load_ledger, project):
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
        if capture_hash == old['sha256']:
            item.update(status='RevisionChangedSameContent', sha256=capture_hash)
            continue
        try:
            projected = project(name, capture_hash)
            if not isinstance(projected, dict):
                raise ValueError('Invalid projection')
            current = {}
            for app_id, claims in projected.items():
                app = uuid.UUID(app_id)
                if str(app) != app_id or not app.int or not isinstance(claims, list):
                    raise ValueError('Invalid projected AppId or claims')
                source_claims = claims_for(claims, old['url'])
                if not source_claims or any(claim['Location'] != old['url'] for claim in claims):
                    raise ValueError('Unexpected source claim')
                current[app_id] = source_claims
        except FileNotFoundError:
            item['status'] = 'NeedsCapture'
            continue
        except (subprocess.SubprocessError, ValueError, KeyError, TypeError, OSError):
            item['status'] = 'InvalidCapture'
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
        item.update(status='Compared', sha256=capture_hash, provenanceChanges=changes)
    complete = all(row['status'] in ('Unchanged', 'RevisionChangedSameContent', 'Compared')
                   for row in sources.values())
    return {'complete': complete, 'sources': sources,
            'newApplications': [{'appId': key, 'sources': names, 'disposition': 'Pending'}
                                for key, names in sorted(additions.items())]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--baseline-repo', type=Path, required=True)
    parser.add_argument('--baseline-commit', required=True)
    parser.add_argument('--observations', type=Path, required=True)
    parser.add_argument('--captures', type=Path)
    parser.add_argument('--native', type=Path)
    args = parser.parse_args()
    if not hex_id(args.baseline_commit, 40):
        raise ValueError('Use the full published catalog commit ID')

    def git_blob(path):
        raw = subprocess.check_output(['git', '--no-replace-objects', '-C', str(args.baseline_repo),
                                       'show', args.baseline_commit + ':' + path], timeout=30)
        return decode(raw)

    nonverified = git_blob('applications.non-verified.json')
    if (nonverified.get('Format') != 'TokenForgeNonVerifiedApplications'
            or nonverified.get('SchemaVersion') != 1):
        raise ValueError('Unsupported non-verified catalog format')

    def load_ledger():
        verified = git_blob('applications.json')
        if verified.get('Format') != 'TokenForgeApplicationMetadata' or verified.get('SchemaVersion') != 2:
            raise ValueError('Unsupported verified catalog format')
        excluded = nonverified['Applications']
        if set(verified['Applications']) & set(excluded):
            raise ValueError('Published catalog partitions overlap')
        records = {key: row['CatalogRecord'] for key, row in excluded.items()}
        records.update(verified['Applications'])
        return {key: row['Records']['Discovery///']['Attributes']['SourceClaims'] for key, row in records.items()}

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
    receipt = compare(nonverified, observations, load_ledger, project)
    print(json.dumps({'format': 'TokenForgePublicCatalogDelta', 'schemaVersion': 1,
                      'baselineCommit': args.baseline_commit, 'observationsSha256': hashlib.sha256(raw).hexdigest(),
                      **receipt}, sort_keys=True, indent=2))
    return 0 if receipt['complete'] else 2


if __name__ == '__main__':
    try:
        sys.exit(main())
    except (OSError, subprocess.SubprocessError, ValueError, KeyError, TypeError) as exc:
        sys.exit(f'Catalog delta refused: {exc}')
