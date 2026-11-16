#!/usr/bin/env python3
"""Prepare a private database review and public-input-only candidate; never collect or publish."""
import argparse
import collections
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re

REPO = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('inventory', REPO / 'scripts/New-TokenForgeFirstPartyInventory.py')
inventory = importlib.util.module_from_spec(spec)
spec.loader.exec_module(inventory)
sha = lambda data: hashlib.sha256(data).hexdigest()
GUID = re.compile(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$')
PUBLIC_INPUTS = ('Baseline', 'Candidate', 'Merill', 'PreviousMerill', 'Graph', 'Definitions', 'Acquisition')


def encode(value):
    return (json.dumps(value, sort_keys=True, ensure_ascii=False, indent=2) + '\n').encode()


def read_bytes(path):
    path = Path(path)
    if any(p.is_symlink() for p in (path, *path.parents)) or not path.is_file() or not 0 < path.stat().st_size <= 134217728:
        raise ValueError('Expected bounded unlinked input file.')
    return path.read_bytes()


def read(data):
    return json.loads(data, object_pairs_hook=inventory.unique)


def files(root):
    result = {}
    for p in sorted(root.rglob('*')):
        if '.git' in p.relative_to(root).parts:
            continue
        if p.is_symlink():
            raise ValueError('Linked data tree.')
        if p.is_file():
            data = read_bytes(p)
            result[str(p.relative_to(root))] = {'Sha256': sha(data), 'Bytes': len(data)}
    return result


def preserve_history(before, after):
    if set(before['Applications']) - set(after['Applications']):
        raise ValueError('Historical identifiers were removed.')
    runs = {r['Id']: r for r in after['Runs']}
    if len(runs) != len(after['Runs']) or any(runs.get(r['Id']) != r for r in before['Runs']):
        raise ValueError('Historical run changed or duplicated.')
    for app_id, old in before['Applications'].items():
        new = after['Applications'][app_id]
        if old['FirstSeenAt'] != new['FirstSeenAt']:
            raise ValueError('Historical first-seen date changed.')
        for origin, previous in old['Records'].items():
            current = new['Records'].get(origin)
            if current is None or any(v not in current['PreviousVersions'] for v in previous['PreviousVersions']):
                raise ValueError('Historical record/version removed.')
            if any(previous.get(k) != current.get(k) for k in ('Attributes', 'Sources', 'ContentSha256')):
                prior_payload = {k: previous[k] for k in ('Attributes', 'Sources', 'ContentSha256', 'LastSeenAt')}
                prior_payload['FirstSeenAt'] = previous['CurrentVersionFirstSeenAt']
                if prior_payload not in current['PreviousVersions']:
                    raise ValueError('Replaced payload/history dates were not retained.')


def merill_records(raw):
    """Only identify rows already admitted by the existing pinned adapter; no suffix repair."""
    result = []
    for row in raw:
        value = row['AppId'].strip() if row['Source'] == 'EntraDocs' else row['AppId']
        value = value.lower()
        if GUID.fullmatch(value) and value != '00000000-0000-0000-0000-000000000000':
            result.append({**row, 'AppId': value})
    return result


def claim_versions(app):
    current, historical, conflicts, old_conflicts = [], [], [], []
    for origin, record in sorted(app.get('Records', {}).items()):
        for old, payload in [(False, record), *[(True, p) for p in record.get('PreviousVersions', [])]]:
            attributes = payload['Attributes']
            if not attributes.get('SourceClaims') and not attributes.get('MetadataConflicts'):
                continue
            if origin != 'Discovery///':
                raise ValueError('Public claims outside the public discovery origin.')
            first = payload['FirstSeenAt'] if old else record['CurrentVersionFirstSeenAt']
            item = {'ContentSha256': payload['ContentSha256'], 'FirstSeenAt': first,
                    'RecordFirstSeenAt': record['FirstSeenAt'],
                    'LastSeenAt': payload['LastSeenAt'], 'Claims': [
                        {k: c[k] for k in ('Evidence', 'Location', 'Name') if k in c}
                        for c in attributes.get('SourceClaims', [])]}
            (historical if old else current).append(item)
            if attributes.get('MetadataConflicts'):
                (old_conflicts if old else conflicts).append({
                    'ContentSha256': payload['ContentSha256'], 'FirstSeenAt': first,
                    'RecordFirstSeenAt': record['FirstSeenAt'],
                    'LastSeenAt': payload['LastSeenAt'], 'Conflicts': attributes['MetadataConflicts']})
    return current, historical, conflicts, old_conflicts


def public_review(baseline, candidate, graph, definitions, merill, previous_merill, bindings):
    """This function has NO private input. Never derive a public decision by redaction."""
    preserve_history(baseline, candidate)
    projected, _ = inventory.build(candidate, graph, definitions=(definitions,))
    positive = {r['Identifier']: r['NonAppDefinitions'] for r in projected['Identifiers'].values()
                if r['Namespace'] == 'Identifier' and r['NonAppDefinitions']}
    rows = {}
    for app_id in sorted(set(candidate['Applications']) | set(positive)):
        is_claim = app_id in candidate['Applications']
        current, history, conflicts, old_conflicts = claim_versions(candidate['Applications'][app_id]) if is_claim else ([], [], [], [])
        non_app = positive.get(app_id, [])
        if is_claim and non_app:
            classification, priority = 'AppNonAppConflict', 0
        elif conflicts:
            classification, priority = 'CurrentPublicClaimConflict', 1
        elif old_conflicts:
            classification, priority = 'HistoricalPublicClaimConflict', 2
        elif non_app:
            classification, priority = 'KnownNonAppIdentifier', 4
        else:
            classification, priority = 'UnresolvedPublicCandidate', 3
        rows[app_id] = {'Identifier': app_id, 'Classification': classification, 'Priority': priority,
                        'LegacyApplicationClaim': is_claim, 'NonAppDefinitions': non_app,
                        'CurrentClaims': current, 'HistoricalClaims': history,
                        'CurrentClaimConflicts': conflicts, 'HistoricalClaimConflicts': old_conflicts}
    def snapshot(raw):
        result = collections.defaultdict(list)
        for row in merill_records(raw):
            result[row['AppId']].append({'Name': row['AppDisplayName'], 'Source': row['Source']})
        return {key: sorted(value, key=lambda x: (x['Source'], x['Name'])) for key, value in result.items()}
    prior, latest = snapshot(previous_merill), snapshot(merill)
    changes = [{'Identifier': i, 'Before': prior.get(i, []), 'After': latest.get(i, [])}
               for i in sorted(set(prior) | set(latest)) if prior.get(i) != latest.get(i)]
    return {'Format': 'TokenForgePublicIdentifierReview', 'SchemaVersion': 1,
            'Policy': 'AdditiveClassificationOnly_NoRemovalOrOwnershipPromotion', 'Bindings': bindings,
            'Counts': {'Rows': len(rows), 'LegacyApplicationClaims': len(candidate['Applications']),
                       'Classifications': dict(sorted(collections.Counter(r['Classification'] for r in rows.values()).items())),
                       'CurrentPublicClaimConflicts': sum(bool(r['CurrentClaimConflicts']) for r in rows.values()),
                       'HistoricalPublicClaimConflicts': sum(bool(r['HistoricalClaimConflicts']) for r in rows.values())},
            'Rows': rows, 'MerillSnapshotChanges': changes,
            'Limitations': ['Successive Merill exports are one source over time, not independent corroboration.',
                            'Public claims do not verify Microsoft ownership, client/resource role, token issuance or API access.',
                            'Positive non-app evidence does not delete conflicting application claims or history.',
                            'The existing application database reader does not consume this proposed sidecar.']}


def private_review(retained, public, bindings):
    rows = []
    definitions = {r['Identifier']: r['NonAppDefinitions'] for r in retained['Identifiers'].values()
                   if r['Namespace'] == 'Identifier' and r['NonAppDefinitions']}
    for key, row in sorted(retained['Identifiers'].items()):
        if row['Namespace'] != 'AppId':
            continue
        own = row['MicrosoftOwnership'] == 'DirectoryVerified'
        proven = any(e['Evidence'] == 'VerifiedMicrosoftDirectoryOwner' for e in row['OwnershipEvidence'])
        if own != proven:
            raise ValueError('Contradictory retained ownership evidence.')
        kinds = sorted({e['Kind'] for e in row['EntityEvidence']} & {'ClientApplication', 'ApiResource'})
        current_public = public['Rows'].get(row['Identifier'], {})
        non_app = list(definitions.get(row['Identifier'], []))
        for definition in current_public.get('NonAppDefinitions', []):
            if definition not in non_app:
                non_app.append(definition)
        claim_conflict = ('ConflictingPublicClaims' in row['ReviewReasons'] or
                          current_public.get('CurrentClaimConflicts') or current_public.get('HistoricalClaimConflicts'))
        if non_app:
            bucket, priority = 'AppNonAppConflict', 0
        elif claim_conflict:
            bucket, priority = 'PublicClaimConflict', 1
        elif own and kinds:
            bucket, priority = 'VerifiedMicrosoftOwnedRoleResolved', 2
        elif own:
            bucket, priority = 'VerifiedMicrosoftOwnedRoleUnresolved', 3
        elif row['ObservedSignIn']:
            bucket, priority = 'ObservedOnlyOwnershipUnverified', 4
        else:
            bucket, priority = 'Unresolved', 5
        rows.append({'Key': key, 'Identifier': row['Identifier'], 'Bucket': bucket, 'Priority': priority,
                     'DirectoryVerifiedMicrosoftOwnership': own, 'EstablishedRoles': kinds,
                     'CurrentPublicClaimConflict': bool(current_public.get('CurrentClaimConflicts')),
                     'HistoricalPublicClaimConflict': bool(current_public.get('HistoricalClaimConflicts')),
                     'NonAppDefinitions': non_app, 'RetainedEvidence': row})
    rows.sort(key=lambda r: (r['Priority'], r['Identifier']))
    return {'Format': 'TokenForgePrivateDatabaseReview', 'SchemaVersion': 1, 'Privacy': 'Private',
            'Bindings': bindings, 'Counts': dict(sorted(collections.Counter(r['Bucket'] for r in rows).items())),
            'ApplicationDecisions': rows, 'OtherNamespacesPreservedByInventoryBinding': True,
            'Publication': 'NotAttempted'}


def verify_trees(roots, manifest, output=None):
    for key, root in roots.items():
        if files(root) != manifest[key + 'Files']:
            raise ValueError('Pinned data tree changed: ' + key)
    if output is not None:
        copied = files(output / 'candidate')
        copied.pop('identifier-classifications/inventory-v1.json', None)
        if copied != manifest['PreparedRootFiles']:
            raise ValueError('Copied prepared release differs from its pins.')


def render_review(private, public):
    def cell(value):
        return str(value).replace('|', '\\|').replace('\n', ' ')
    lines = ['# Private inventory database review', '',
             'Offline proposal only; no collection, authentication or publication.', '',
             '## Decision buckets (disjoint; ownership remains a separate evidence axis)', '',
             *[f'- {name}: {count}' for name, count in private['Counts'].items()], '',
             'App/non-app conflicts take priority, then public-claim conflicts, even when directory ownership is verified.',
             'Role-unresolved and observed-only IDs are not promoted to verified client/resource identities.',
             'All original evidence remains in the retained inventory and the per-row RetainedEvidence field.', '',
             '## Priority 0: app/non-app conflicts — hold promotion, retain both claims', '',
             '| Identifier | Positive non-app definitions | Ownership verified | Established app roles |',
             '| --- | --- | --- | --- |']
    for row in private['ApplicationDecisions']:
        if row['Bucket'] == 'AppNonAppConflict':
            labels = '; '.join(sorted({d['Kind'] + ': ' + d.get('Label', '') + ' [' + d['Evidence'] + ']' for d in row['NonAppDefinitions']}))
            lines.append('| ' + ' | '.join(map(cell, (row['Identifier'], labels, row['DirectoryVerifiedMicrosoftOwnership'], ', '.join(row['EstablishedRoles']) or 'Unresolved'))) + ' |')
    lines += ['', '## Priority 1: public-claim conflicts — retain history, do not guess a canonical label', '',
              '| Identifier | Current conflict | Historical conflict | Ownership verified | Retained names |',
              '| --- | --- | --- | --- | --- |']
    for row in private['ApplicationDecisions']:
        if row['Bucket'] == 'PublicClaimConflict':
            lines.append('| ' + ' | '.join(map(cell, (row['Identifier'], row['CurrentPublicClaimConflict'], row['HistoricalPublicClaimConflict'], row['DirectoryVerifiedMicrosoftOwnership'], '; '.join(row['RetainedEvidence'].get('Names', []))))) + ' |')
    lines += ['', '## Remaining decisions', '',
              '- VerifiedMicrosoftOwnedRoleResolved: ownership and at least one client/resource role are supported; retain exact evidence dates. No consent, token or API guarantee follows.',
              '- VerifiedMicrosoftOwnedRoleUnresolved: ownership is supported; withhold any client/resource-role assertion.',
              '- ObservedOnlyOwnershipUnverified: retain sign-in observations; withhold Microsoft ownership.',
              '- Unresolved: preserve claims and absence of proof; no automatic removal.', '',
              'Every AppId decision and full retained evidence is in private-review.json. Other namespaces remain preserved in the hash-bound original inventory.', '',
              '## Candidate and Merill bridge', '',
              'The qualified public-only release is reused unchanged, with one additive public classification sidecar.',
              'Public artifacts are generated solely from public inputs; no private ownership, usage, joins or candidate IDs are exported.',
              'Additional conflicts supported solely by private definitions remain in the private review.',
              'Current and historical public conflicts are separate; successive Merill exports are not independent sources.', '',
              json.dumps(public['Counts'], sort_keys=True), '',
              *['- ' + x['Identifier'] + ': ' + json.dumps({'Before': x['Before'], 'After': x['After']}, ensure_ascii=False) for x in public['MerillSnapshotChanges']], '',
              'Current claim FirstSeenAt is the current payload/version start; RecordFirstSeenAt is the separate original record lifetime.',
              'Inspect candidate-diff.json and candidate-manifest.json before any database update. A successful receipt.json is required; FAILED means unqualified partial output.',
              'The current application reader does not consume the additive classification sidecar. No automatic reclassification or deletion is applied.',
              'Missing evidence remains unresolved. Source snapshots and evidence dates are historical, not refreshed.', '']
    return '\n'.join(lines).encode()


def _prepare(manifest_path, output):
    source_paths = (Path(__file__), REPO / 'scripts/New-TokenForgeFirstPartyInventory.py')
    source_pins = {p: sha(p.read_bytes()) for p in source_paths}
    manifest_bytes = read_bytes(manifest_path)
    manifest = read(manifest_bytes)
    inputs, data = {}, {}
    for name, pin in manifest['Inputs'].items():
        raw = read_bytes(pin['Path'])
        if sha(raw) != pin['Sha256'] or len(raw) != pin['Bytes']:
            raise ValueError('Pinned input mismatch: ' + name)
        inputs[name] = raw
        if not name.startswith('DefinitionRaw'):
            data[name] = read(raw)
    retained, baseline, candidate = data['Inventory'], data['Baseline'], data['Candidate']
    receipt = data['InventoryReceipt']
    if receipt['Files']['report-complete/inventory.json']['Sha256'] != sha(inputs['Inventory']):
        raise ValueError('Retained inventory receipt mismatch.')
    if retained['Bindings']['0']['Sha256'] != sha(inputs['Baseline']):
        raise ValueError('Inventory refers to a different historical public baseline.')
    if retained['Bindings']['Execution']['EngineSha256'] != source_pins[source_paths[1]]:
        raise ValueError('Retained inventory engine changed; review equivalence before reuse.')
    if data['AcquisitionSeal'] != {'sha256': sha(inputs['Acquisition'])}:
        raise ValueError('Frozen acquisition seal mismatch.')
    if (data['Acquisition']['kind'] != 'FrozenAnonymousPublicInputs' or
            data['Acquisition']['authentication'] is not False or data['Acquisition']['complete'] is not True):
        raise ValueError('Expected complete anonymous public acquisition.')
    source = [s for s in data['Acquisition']['sources'] if s['name'] == 'microsoftApps']
    if (len(source) != 1 or source[0]['uri'] != 'https://raw.githubusercontent.com/merill/microsoft-info/main/_info/MicrosoftApps.json' or
            source[0]['status'] != 'Captured' or source[0]['sha256'] != sha(inputs['Merill']) or source[0]['bytes'] != len(inputs['Merill'])):
        raise ValueError('Exact Merill export acquisition mismatch.')
    adapted = data['AdaptedMerill']
    if adapted['Accounting']['inputSha256'] != sha(inputs['Merill']) or adapted['Records'] != merill_records(data['Merill']):
        raise ValueError('Existing Merill adapter output/input mismatch.')
    if adapted['Accounting'] != next(s['adaptation'] for s in data['Health']['sources'] if s['name'] == 'microsoftApps'):
        raise ValueError('Retained adapter accounting differs from qualified projection.')
    prior = data['PublicReceipt']
    if prior['candidateSha256'] != sha(inputs['Candidate']) or prior['diffSha256'] != sha(inputs['PublicDiff']):
        raise ValueError('Qualified public candidate receipt mismatch.')
    for definition in data['Definitions']['Definitions']:
        if sha(inputs['DefinitionRaw' + definition['Kind']]) != definition['SourceSha256']:
            raise ValueError('Positive definition source snapshot mismatch.')
    roots = {key: Path(manifest[key]) for key in ('BaselineRoot', 'PreparedRoot')}
    for key, root in roots.items():
        if output.resolve().is_relative_to(root.resolve()) or root.resolve().is_relative_to(output.resolve()):
            raise ValueError('Overlapping output/data trees.')
    verify_trees(roots, manifest)
    if read_bytes(roots['PreparedRoot'] / 'applications.json') != inputs['Candidate'] or read_bytes(roots['BaselineRoot'] / 'applications.json') != inputs['Baseline']:
        raise ValueError('Data tree/application binding mismatch.')
    bindings = {key: {'Sha256': sha(inputs[key]), 'Bytes': len(inputs[key])} for key in PUBLIC_INPUTS}
    bindings.update({'BaselineCommit': manifest['BaselineCommit'], 'PreparedReleaseCommit': manifest['PreparedReleaseCommit'],
                     'GeneratorSha256': sha(Path(__file__).read_bytes()), 'InventoryEngineSha256': sha((REPO / 'scripts/New-TokenForgeFirstPartyInventory.py').read_bytes())})
    public = public_review(baseline, candidate, data['Graph'], data['Definitions'], data['Merill'], data['PreviousMerill'], bindings)
    private = private_review(retained, public, {'InputManifestSha256': sha(manifest_bytes),
                              'InventorySha256': sha(inputs['Inventory']), 'InventoryExecution': retained['Bindings']['Execution'],
                              'PublicBindings': bindings})
    if output.exists() or any(p.is_symlink() for p in (output, *output.parents)):
        raise ValueError('Choose a new unlinked private output directory.')
    output.mkdir(mode=0o700)
    def write(path, raw):
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        for parent in (path.parent, *path.parent.parents):
            if parent == output.parent:
                break
            parent.chmod(0o700)
        with path.open('xb') as stream:
            os.chmod(path, 0o600)
            stream.write(raw)
    for name in manifest['PreparedRootFiles']:
        write(output / 'candidate' / name, read_bytes(roots['PreparedRoot'] / name))
    sidecar = 'identifier-classifications/inventory-v1.json'
    write(output / 'candidate' / sidecar, encode(public))
    before, after = manifest['BaselineRootFiles'], files(output / 'candidate')
    changes = [{'Path': name, 'Operation': 'Add' if name not in before else 'Modify',
                'Before': before.get(name), 'After': item} for name, item in after.items() if before.get(name) != item]
    if set(before) - set(after):
        raise ValueError('Published path removal is prohibited.')
    diff = {'Format': 'TokenForgeSanitizedDatabaseCandidateDiff', 'SchemaVersion': 1, 'Bindings': bindings,
            'Files': changes, 'UnchangedFiles': len(before) - sum(c['Operation'] == 'Modify' for c in changes),
            'ApplicationChange': {'Counts': data['PublicDiff']['counts'], 'Changes': data['PublicDiff']['changes'],
                                  'Removals': [], 'HistoryPreserved': True},
            'ClassificationReview': public['Counts'], 'MerillSnapshotChanges': public['MerillSnapshotChanges'],
            'Quarantine': adapted['Accounting'], 'Publication': 'NotAttempted',
            'Limitations': public['Limitations']}
    write(output / 'candidate-diff.json', encode(diff))
    write(output / 'private-review.json', encode(private))
    write(output / 'candidate-manifest.json', encode({'Format': 'TokenForgeDatabaseCandidateFiles', 'SchemaVersion': 1,
          'Bindings': bindings, 'Files': after, 'DiffSha256': sha(encode(diff)), 'Publication': 'NotAttempted'}))
    write(output / 'review.md', render_review(private, public))
    # Inputs remain immutable through projection and copy.
    for key, pin in manifest['Inputs'].items():
        if read_bytes(pin['Path']) != inputs[key]:
            raise ValueError('Input changed during projection: ' + key)
    verify_trees(roots, manifest, output)
    if any(sha(p.read_bytes()) != value for p, value in source_pins.items()):
        raise ValueError('Executing source changed during projection.')
    summary = {'Status': 'ReviewPrepared', 'Privacy': 'Private', 'PrivateBuckets': private['Counts'], 'PublicCounts': public['Counts'],
               'CandidateDiffSha256': sha(encode(diff)), 'CandidateFiles': len(after), 'NetworkRequests': 0,
               'InputManifestSha256': sha(manifest_bytes), 'OutputFiles': files(output), 'Publication': 'NotAttempted'}
    write(output / 'receipt.json', encode(summary))
    return summary


def prepare(manifest_path, output):
    existed = output.exists()
    try:
        return _prepare(manifest_path, output)
    except BaseException:
        if not existed and output.is_dir() and not any(p.is_symlink() for p in (output, *output.parents)):
            marker = output / 'FAILED'
            if not marker.exists():
                with marker.open('xb') as stream:
                    marker.chmod(0o600)
                    stream.write(b'Unqualified partial output. No completed review or publication. Preserve for inspection.\n')
        raise


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--inputs', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(prepare(args.inputs, args.output), indent=2))
