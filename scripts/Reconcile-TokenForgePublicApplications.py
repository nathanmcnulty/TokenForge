#!/usr/bin/env python3
"""Offline historical-union adapter. Never collect, authenticate, or publish."""
import argparse
import collections
import copy
from datetime import datetime, timezone, timedelta
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile


def digest(data):
    return hashlib.sha256(data).hexdigest()


def unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('Duplicate JSON key: ' + key)
        result[key] = value
    return result


def read(path):
    return json.loads(path.read_bytes(), object_pairs_hook=unique)


def encoded(value):
    return (json.dumps(value, sort_keys=True, ensure_ascii=False, indent=2) + '\n').encode()


def regular(path):
    if not path.is_file() or any(p.is_symlink() for p in (path, *path.parents)):
        raise ValueError('Expected an unlinked regular file: ' + str(path))
    return path


def classification(record):
    claims = record['Attributes'].get('SourceClaims', [])
    evidence = {c['Evidence'] for c in claims}
    identity = {c['Location'] for c in claims if c['Evidence'] in
                {'PublishedGraph', 'PublishedMetadata', 'PublishedGitHub'}}
    if len(identity) >= 2:
        return ('CorroboratedPublicIdentityWithDisagreements' if record['Attributes'].get('MetadataConflicts')
                else 'CorroboratedPublicIdentity')
    if identity:
        return 'SinglePublicIdentityClaim'
    if evidence == {'PublishedEntraDocs'}:
        return 'DocumentationOnlyCandidate'
    if evidence == {'PublishedResource'}:
        return 'ResourceOnlyCandidate'
    return 'UnresolvedMixedCandidate'


def select_permission_overlap(baseline, content_sha256):
    matches = []
    for path in sorted((baseline / 'identifier-overlaps').glob('*.json')):
        report = read(regular(path))
        catalog = report.get('Catalog') if isinstance(report, dict) else None
        if isinstance(catalog, dict) and catalog.get('ContentSha256') == content_sha256:
            matches.append((path, report))
    if not matches:
        raise ValueError('No identifier-overlaps report matches the pinned baseline manifest ContentSha256 ' +
                         str(content_sha256) + '.')
    if len(matches) != 1:
        names = ', '.join(path.name for path, _ in matches)
        raise ValueError(str(len(matches)) + ' identifier-overlaps reports match the pinned baseline manifest ' +
                         'ContentSha256 ' + str(content_sha256) + ': ' + names)
    return matches[0]


def timestamp(value):
    result = datetime.fromisoformat(value.replace('Z', '+00:00'))
    if result.utcoffset() != timedelta(0):
        raise ValueError('Observation timestamp must be UTC.')
    return result


def capture_observation(incoming, health, acquisition):
    if acquisition['kind'] not in {'FrozenAnonymousPublicInputs', 'FrozenSyntheticFixtureInputs'} or acquisition['schemaVersion'] != 1 or acquisition['authentication'] is not False:
        raise ValueError('Unexpected frozen acquisition envelope.')
    start, finish = timestamp(acquisition['startedAt']), timestamp(acquisition['finishedAt'])
    projection = timestamp(health['collectedAt'])
    if not start <= finish <= projection <= datetime.now(timezone.utc) + timedelta(minutes=5):
        raise ValueError('Projection date is not bound to the original capture window.')
    expected_requests = 0 if acquisition['kind'] == 'FrozenSyntheticFixtureInputs' else sum(s['attempts'] for s in acquisition['sources'])
    if acquisition['requests'] != expected_requests or not 0 <= acquisition['requests'] <= 6:
        raise ValueError('Acquisition accounting mismatch.')
    if len(acquisition['sources']) != 3 or len({s['name'] for s in acquisition['sources']}) != 3:
        raise ValueError('Acquisition membership mismatch.')
    for source in acquisition['sources']:
        if source['status'] == 'Captured' and not start <= timestamp(source['retrievedAt']) <= finish:
            raise ValueError('Retrieval date differs from capture window.')
        if not 1 <= source['attempts'] <= 2 or not 0 <= source['bytes'] <= 8388608:
            raise ValueError('Acquisition source bound.')
    if acquisition['complete'] != all(s['status'] == 'Captured' for s in acquisition['sources']):
        raise ValueError('Acquisition completeness mismatch.')
    result = copy.deepcopy(incoming)
    if health['complete'] and health['candidateCount']:
        origin = result['Origins']['Discovery///']
        latest = [r for r in result['Runs'] if r['Id'] == origin['LastRunId']]
        if len(latest) != 1 or timestamp(latest[0]['ObservedAt']) != projection:
            raise ValueError('Missing latest observation binding.')
        stamp = acquisition['finishedAt']
        origin['LastObservedAt'] = stamp
        latest[0]['ObservedAt'] = stamp
        # Only new projection observations move to their actual capture date.
        # Frozen raw exchange and all older history/RecordedAt values stay intact.
        for app in result['Applications'].values():
            for payload in (app, app['Records']['Discovery///']):
                for key in ('FirstSeenAt', 'LastSeenAt', 'CurrentVersionFirstSeenAt'):
                    if key in payload and timestamp(payload[key]) == projection:
                        payload[key] = stamp
        if timestamp(result['CreatedAt']) > finish:
            result['CreatedAt'] = stamp
    return result


# Use existing validators and catalog import/export. Import preserves absent IDs;
# Update-TokenForgeApplicationMetadata is deliberately not used for a full replacement.
VALIDATE_MERGE = r'''
param($Repo,$Native,$Baseline,$Exchange,$Observation,$Candidate,$Work)
$ErrorActionPreference='Stop'
. (Join-Path $Repo scripts/TokenForgePublicHealth.ps1)
Initialize-TokenForgeHealthRuntime $Native
$before=Get-TokenForgeApplicationMetadata -Path $Baseline -PublicOnly
[TokenForge.Core.ApplicationCatalogPolicy]::ValidateDocument([IO.File]::ReadAllText($Baseline))
$input=Read-TokenForgeHealthExchange $Exchange
if($input.Health.complete -and $input.Health.candidateCount -gt 0){
 $db=Join-Path $Work catalog.sqlite
 $null=Import-TokenForgeApplicationMetadata -Path $db -InputPath $Baseline -NativeExecutablePath $Native
 $null=Get-TokenForgeApplicationMetadata -Path $Observation -PublicOnly
 $null=Import-TokenForgeApplicationMetadata -Path $db -InputPath $Observation -NativeExecutablePath $Native
 & $Native catalog export --database $db > $Candidate
 if($LASTEXITCODE -ne 0){throw 'Existing native catalog export failed.'}
}
$after=Get-TokenForgeApplicationMetadata -Path $Candidate -PublicOnly
[TokenForge.Core.ApplicationCatalogPolicy]::ValidateDocument([IO.File]::ReadAllText($Candidate))
$download=& (Join-Path $Repo scripts/Export-TokenForgeCatalogDownload.ps1) -InputPath $Candidate -OutputPath (Join-Path (Split-Path $Work) candidate-download.json.gz) -NativeExecutablePath $Native
$download|ConvertTo-Json -Compress|Set-Content (Join-Path $Work download-summary.json) -Encoding utf8NoBOM
[ordered]@{Baseline=$before.Applications.Count;Candidate=$after.Applications.Count;Complete=$input.Health.complete}|ConvertTo-Json -Compress
'''


def reconcile(root, output, native, pwsh):
    repo = Path(__file__).resolve().parents[1]
    adapter_sha = digest(Path(__file__).read_bytes())
    if output.exists():
        raise ValueError('Choose a new immutable output; no overwrite or reset.')
    root = root.resolve()
    baseline = root / 'baseline'
    pin = read(regular(root / 'baseline-pin.json'))
    runtime = read(regular(root / 'runtime-equivalence.json'))
    for path in [*runtime['executedFiles'], *pin['files']]:
        if Path(path).is_absolute() or '..' in Path(path).parts:
            raise ValueError('Input inventories require safe relative paths.')
    if any(p.is_symlink() for p in baseline.rglob('*')) or output.resolve().is_relative_to(baseline) or baseline.is_relative_to(output.resolve()):
        raise ValueError('Linked baseline or overlapping output is refused.')
    for path, expected in runtime['executedFiles'].items():
        if digest(regular(repo / path).read_bytes()) != expected:
            raise ValueError('Executed validator/module source changed: ' + path)
    if digest(regular(native).read_bytes()) != runtime['nativeSha256'] or digest(regular(pwsh).read_bytes()) != runtime['powerShellSha256']:
        raise ValueError('Accepted runtime unavailable or changed; no compile/download fallback.')
    for path, item in pin['files'].items():
        data = regular(baseline / path).read_bytes()
        if len(data) != item['bytes'] or digest(data) != item['sha256']:
            raise ValueError('Frozen baseline changed: ' + path)
    if {str(p.relative_to(baseline)) for p in baseline.rglob('*') if p.is_file()} != set(pin['files']):
        raise ValueError('Baseline membership changed.')
    exchange = root / 'public-exchange'
    health = read(regular(exchange / 'health.json'))
    incoming = read(regular(exchange / 'metadata.json'))
    acquisition = read(regular(root / 'acquisition.json'))
    if acquisition['sourceRevision'] != pin['mainCommit']:
        raise ValueError('Capture source revision differs from pinned main.')
    observation = capture_observation(incoming, health, acquisition)
    raw = {}
    for source in acquisition['sources']:
        data = regular(root / 'raw-public-inputs' / (source['name'] + '.json')).read_bytes()
        if digest(data) != source['sha256'] or len(data) != source['bytes']:
            raise ValueError('Frozen public response changed.')
        raw[source['name']] = json.loads(data, object_pairs_hook=unique)
    for source in health['sources']:
        if source['status'] == 'Success':
            capture = [s for s in acquisition['sources'] if s['name'] == source['name']]
            if len(capture) != 1 or capture[0]['sha256'] != source['sha256'] or capture[0]['uri'] != source['uri']:
                raise ValueError('Health observation differs from retained raw input.')
    if health['complete'] and not acquisition['complete']:
        raise ValueError('Incomplete acquisition cannot claim completeness.')
    overlap_path, overlap = select_permission_overlap(baseline, pin['manifest']['ContentSha256'])
    before = read(baseline / 'applications.json')
    output.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    stage = Path(tempfile.mkdtemp(prefix='.reconcile-', dir=output.parent))
    try:
        shutil.copytree(baseline, stage / 'discovery-data')
        work = stage / 'work'
        work.mkdir(mode=0o700)
        observed_path = work / 'captured-observation.json'
        observed_path.write_bytes(encoded(observation))
        script = work / 'validate-merge.ps1'
        script.write_text(VALIDATE_MERGE)
        candidate = stage / 'discovery-data/applications.json'
        result = subprocess.run([str(pwsh), '-NoProfile', '-NonInteractive', '-File', str(script),
                                 str(repo), str(native), str(baseline / 'applications.json'), str(exchange),
                                 str(observed_path), str(candidate), str(work)], capture_output=True, timeout=300, check=False)
        (work / 'validation.stdout').write_bytes(result.stdout)
        (work / 'validation.stderr').write_bytes(result.stderr)
        if result.returncode:
            raise ValueError('Existing validation/import/export refused; inspect retained work log.')
        after = read(candidate)
        old, new = before['Applications'], after['Applications']
        observed = incoming['Applications'] if health['complete'] and health['candidateCount'] else {}
        if set(old) - set(new):
            raise ValueError('Historical application loss is prohibited.')
        overlaps = {m['Id']: m['Definitions'] for m in overlap['Matches']}
        added, changes, reobserved, disagreements, unresolved = [], [], [], [], []
        counts = collections.Counter()
        for app_id, app in sorted(new.items()):
            record = app['Records']['Discovery///']
            kind = classification(record)
            counts[kind] += 1
            row = {'id': app_id, 'name': record['Attributes']['Name'], 'classification': kind,
                   'permissionIdOverlap': overlaps.get(app_id, []), 'lastObservedAt': record['LastSeenAt']}
            if kind != 'CorroboratedPublicIdentity' or app_id in overlaps:
                unresolved.append(row)
            if record['Attributes'].get('MetadataConflicts'):
                disagreements.append({'id': app_id, 'conflicts': record['Attributes']['MetadataConflicts']})
            if app_id not in old:
                added.append(row)
                continue
            prior = old[app_id]['Records']['Discovery///']
            fields = sorted(k for k in set(prior['Attributes']) | set(record['Attributes'])
                            if prior['Attributes'].get(k) != record['Attributes'].get(k))
            if prior['Sources'] != record['Sources']:
                fields.append('Sources')
            if fields:
                changes.append({'id': app_id, 'fields': fields, 'before': prior['Attributes'],
                                'after': record['Attributes'], 'beforeSources': prior['Sources'],
                                'afterSources': record['Sources']})
            elif app_id in observed:
                reobserved.append(app_id)
            if app_id not in observed and app != old[app_id]:
                raise ValueError('Missing observation changed a retained historical record.')
            if app['FirstSeenAt'] != old[app_id]['FirstSeenAt']:
                raise ValueError('Historical first-seen date changed.')
            versions = record['PreviousVersions']
            for version in prior['PreviousVersions']:
                if version not in versions:
                    raise ValueError('Historical observation/version lost.')
            if fields and not any(v['Attributes'] == prior['Attributes'] and v['FirstSeenAt'] == prior['CurrentVersionFirstSeenAt']
                                  and v['LastSeenAt'] == prior['LastSeenAt'] for v in versions):
                raise ValueError('Replaced current payload was not retained with original dates.')
        if not health['complete'] or not health['candidateCount']:
            if candidate.read_bytes() != (baseline / 'applications.json').read_bytes():
                raise ValueError('Incomplete/empty input freshened baseline.')
        old_runs = {r['Id']: r for r in before['Runs']}
        new_runs = {r['Id']: r for r in after['Runs']}
        if len(new_runs) != len(after['Runs']) or any(new_runs.get(k) != v for k, v in old_runs.items()):
            raise ValueError('Duplicate runs or historical run changed.')
        for path, item in pin['files'].items():
            if path != 'applications.json' and digest((stage / 'discovery-data' / path).read_bytes()) != item['sha256']:
                raise ValueError('Unrelated published content changed: ' + path)
        quarantine = []
        for source in health['sources']:
            for q in (source.get('adaptation') or {}).get('quarantine', []):
                raw_row = raw[source['name']][q['index']]
                if digest(json.dumps(raw_row, ensure_ascii=False, separators=(',', ':')).encode()) != q['recordSha256']:
                    raise ValueError('Quarantine row differs from frozen public response.')
                quarantine.append({**q, 'source': source['name'], 'rawId': raw[source['name']][q['index']]['AppId'],
                                   'admittedId': None})
        duplicate_versions = sum(len(v) - len({encoded(x) for x in v}) for a in new.values()
                                 for r in a['Records'].values() for v in [r['PreviousVersions']])
        claim_overlaps = [{'id': i, 'claimCount': len(a['Records']['Discovery///']['Attributes'].get('SourceClaims', [])),
                           'distinctLocations': len({c['Location'] for c in a['Records']['Discovery///']['Attributes'].get('SourceClaims', [])})}
                          for i, a in sorted(new.items()) if len(a['Records']['Discovery///']['Attributes'].get('SourceClaims', [])) > 1]
        diff = {'schemaVersion': 1, 'kind': 'TokenForgeHistoricalApplicationReconciliation',
                'policy': 'HistoricalUnion_NoDeletionFromSourceAbsence',
                'bindings': {'main': pin['mainCommit'], 'dataCommit': pin['dataCommit'],
                             'baselineSha256': pin['files']['applications.json']['sha256'],
                             'baselineManifestSha256': pin['files'][pin['manifestPath']]['sha256'],
                             'exchangeManifestSha256': digest((exchange / 'manifest.json').read_bytes()),
                             'permissionOverlapSha256': digest(overlap_path.read_bytes()),
                             'acquisitionSha256': digest((root / 'acquisition.json').read_bytes()),
                             'adapterSha256': adapter_sha},
                'counts': {'baseline': len(old), 'observedAdmissibleCandidates': len(observed), 'candidate': len(new),
                           'additions': len(added), 'contentChanges': len(changes), 'reobservedUnchangedContent': len(reobserved),
                           'removals': 0, 'notObservedRetained': len(set(old) - set(observed)),
                           'duplicateApplicationIds': 0, 'duplicateRunIds': 0, 'duplicateExactHistoricalVersions': duplicate_versions,
                           'sourceDisagreements': len(disagreements), 'multipleSourceClaimIds': len(claim_overlaps), 'quarantinedRows': len(quarantine),
                           'unresolvedClassificationIds': len(unresolved)},
                'snapshot': {'inputComplete': health['complete'], 'inputKind': acquisition['kind'],
                             'observationAt': acquisition['finishedAt'], 'collectorProjectionStartedAt': health['collectedAt'],
                             'baselineUpdatedAt': before['UpdatedAt'], 'candidateUpdatedAt': after['UpdatedAt'],
                             'completeApplicationUniverse': False, 'sources': health['sources'],
                             'rawRetrievals': acquisition['sources']},
                'classifications': dict(counts), 'additions': added, 'changes': changes, 'removals': [],
                'notObservedRetainedIds': sorted(set(old) - set(observed)), 'sourceDisagreements': disagreements,
                'quarantined': quarantine, 'unresolvedIds': unresolved,
                'sourceClaimOverlaps': claim_overlaps,
                'permissionOverlap': {'use': 'ClassificationOnly_NeverDeletion', 'counts': overlap['Counts']},
                'limitations': ['Public corroboration is not tenant identity, ownership, consent or token proof.',
                                'Old PresentInLatestRun flags and dates are retained for unobserved historical records.',
                                'Permission and resource/documentation IDs are not promoted to application identities.']}
        (stage / 'diff.json').write_bytes(encoded(diff))
        lines = ['# Application ledger candidate', '', '**Reconciled into a copy of the published ledger; not replaced with collector output.**', '',
                 'Historical dates, versions and runs are retained. Scope exports and all other published paths are unchanged.', '',
                 '```json', json.dumps(diff['counts'], indent=2), '```', '', '## Additions', '', '| ID | Name | Classification |', '| --- | --- | --- |']
        lines += ['| ' + x['id'] + ' | ' + x['name'].replace('|', '\\|') + ' | ' + x['classification'] + ' |' for x in added]
        lines += ['', '## Content changes', '', '| ID | Fields |', '| --- | --- |']
        lines += ['| ' + x['id'] + ' | ' + ', '.join(x['fields']) + ' |' for x in changes]
        lines += ['', 'All before/after values, source disagreements, quarantines and unresolved classifications are in diff.json.',
                  'Public corroboration is descriptive evidence only. Permission-ID overlap is a classification signal, never a deletion list.',
                  'Absent observations never remove IDs. Incomplete/empty input preserves the baseline bytes and dates.', '']
        (stage / 'review.md').write_text('\n'.join(lines))
        receipt = {'candidateSha256': digest(candidate.read_bytes()), 'diffSha256': digest((stage / 'diff.json').read_bytes()),
                   'candidateBytes': candidate.stat().st_size,
                   'publicDownloadSha256': digest((stage / 'candidate-download.json.gz').read_bytes()), 'counts': diff['counts'], 'scopeExportsUnchanged': True,
                   'publication': 'NotAttempted', 'sourceMain': pin['mainCommit'], 'baselineCommit': pin['dataCommit']}
        (stage / 'receipt.json').write_bytes(encoded(receipt))
        if digest(Path(__file__).read_bytes()) != adapter_sha or any(digest((repo / p).read_bytes()) != h for p, h in runtime['executedFiles'].items()):
            raise ValueError('Executed source changed during reconciliation; partial evidence retained.')
        stage.rename(output)
        return receipt
    except BaseException:
        # Retain failed local evidence; never make a partial candidate look complete.
        (stage / 'FAILED').write_text('Not a completed candidate. Inspect work/ logs.\n')
        raise


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--input-root', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    p.add_argument('--native', type=Path, required=True)
    p.add_argument('--pwsh', type=Path, required=True)
    a = p.parse_args()
    print(json.dumps(reconcile(a.input_root, a.output, a.native, a.pwsh), indent=2))


if __name__ == '__main__':
    main()
