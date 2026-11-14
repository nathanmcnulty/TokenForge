#!/usr/bin/env python3
"""Offline verifier: focused fixtures plus one replay of the frozen real inputs."""
import argparse
import copy
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
from pathlib import Path
import shutil
import subprocess

REPO = Path(__file__).resolve().parents[1]
REUSED_FIXTURE_ADAPTER_SHA256 = '32abd6e926674bb41971b7504c9e29652b729dabd1cc77ff96fdeffb37471b81'
spec = importlib.util.spec_from_file_location('reconcile', REPO / 'scripts/Reconcile-TokenForgePublicApplications.py')
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


def write(path, obj):
    if path.exists():
        path.chmod(0o600)  # Only task-created fixture copies are rewritten.
    path.write_bytes(m.encoded(obj))


def manifest(exchange):
    value = m.read(exchange / 'manifest.json')
    for name in ('health.json', 'metadata.json'):
        data = (exchange / name).read_bytes()
        value['files'][name] = {'sha256': m.digest(data), 'bytes': len(data)}
    write(exchange / 'manifest.json', value)


def fixture(root, work, native, pwsh):
    target = work / 'fixture-input'
    base = target / 'baseline'
    (base / 'identifier-overlaps').mkdir(parents=True, mode=0o700)
    (base / 'downloads').mkdir()
    (base / 'scopes').mkdir()
    shutil.copyfile(root / 'fixture-exchange/metadata.json', base / 'applications.json')
    first_scope = next((root / 'baseline/scopes').glob('*.json'))
    shutil.copyfile(first_scope, base / 'scopes' / first_scope.name)
    content = m.digest((base / 'applications.json').read_bytes())
    value = {'kind': 'SyntheticFixtureManifest', 'ContentSha256': content}
    write(base / 'downloads/fixture.manifest.json', value)
    write(base / 'identifier-overlaps/fixture.json', {'Catalog': {'ContentSha256': content},
          'Matches': [], 'Counts': {'MatchedIdentifiers': 0}})
    original = m.read(root / 'baseline-pin.json')
    pin = {'mainCommit': original['mainCommit'], 'dataCommit': 'SyntheticFixture_NotPublished',
           'manifest': value, 'manifestPath': 'downloads/fixture.manifest.json', 'files': {}}
    for file in base.rglob('*'):
        if file.is_file():
            pin['files'][str(file.relative_to(base))] = {'bytes': file.stat().st_size, 'sha256': m.digest(file.read_bytes())}
    write(target / 'baseline-pin.json', pin)
    shutil.copyfile(root / 'runtime-equivalence.json', target / 'runtime-equivalence.json')
    raw = target / 'raw-public-inputs'
    raw.mkdir()
    now = datetime.now(timezone.utc).isoformat()
    acquisition = copy.deepcopy(m.read(root / 'acquisition.json'))
    acquisition.update(kind='FrozenSyntheticFixtureInputs', startedAt=now, finishedAt=now, requests=0, complete=True)
    for source in acquisition['sources']:
        value = m.read(REPO / 'tests/fixtures/public-health' / (source['name'] + '.json'))
        if source['name'] == 'roadtools':
            del value['apps']['22222222-2222-2222-2222-222222222222']
            value['apps']['11111111-1111-1111-1111-111111111111']['name'] = 'Changed fixture client'
        if source['name'] == 'microsoftApps':
            value.append({'AppId': '33333333-3333-3333-3333-333333333333', 'AppDisplayName': 'Added fixture client',
                          'AppOwnerOrganizationId': None, 'Source': 'Graph'})
        file = raw / (source['name'] + '.json')
        write(file, value)
        source.update(status='Captured', attempts=1, retrievedAt=now, sha256=m.digest(file.read_bytes()), bytes=file.stat().st_size)
    write(target / 'acquisition.json', acquisition)
    command = [str(pwsh), '-NoProfile', '-NonInteractive', '-File', str(REPO / 'scripts/Invoke-TokenForgePublicHealth.ps1'),
               '-OutputPath', str(target / 'public-exchange'), '-NativeExecutablePath', str(native),
               '-SourceRevision', pin['mainCommit'], '-FixturePath', str(raw), '-MaxSeconds', '180']
    result = subprocess.run(command, capture_output=True, timeout=60)
    (work / 'fixture-collector.stdout').write_bytes(result.stdout)
    (work / 'fixture-collector.stderr').write_bytes(result.stderr)
    if result.returncode or not json.loads(result.stdout)['CollectionComplete']:
        raise AssertionError('Existing supported fixture collector failed.')
    return target


def verify(root, expected, work, native, pwsh, reuse=None):
    work.mkdir(mode=0o700)
    results = []
    def passed(name):
        results.append({'check': name, 'passed': True})
    selector = work / 'overlap-selector'
    expected_content = 'b' * 64
    coexist = selector / 'coexist/identifier-overlaps'
    coexist.mkdir(parents=True)
    old_report = coexist / '00-historical.json'
    current_report = coexist / '99-current.json'
    write(old_report, {'Catalog': {'ContentSha256': 'a' * 64}, 'Matches': [], 'Counts': {}})
    write(current_report, {'Catalog': {'ContentSha256': expected_content}, 'Matches': [], 'Counts': {}})
    old_bytes = old_report.read_bytes()
    selected_path, selected = m.select_permission_overlap(coexist.parent, expected_content)
    assert selected_path == current_report and selected['Catalog']['ContentSha256'] == expected_content
    assert old_report.read_bytes() == old_bytes
    passed('Pinned ContentSha256 selects the current report alongside an intact historical report')
    no_match = selector / 'no-match/identifier-overlaps'
    no_match.mkdir(parents=True)
    write(no_match / 'historical.json', {'Catalog': {'ContentSha256': 'a' * 64}, 'Matches': [], 'Counts': {}})
    try:
        m.select_permission_overlap(no_match.parent, expected_content)
        raise AssertionError('Missing matching permission-overlap report accepted')
    except ValueError as exc:
        assert 'No identifier-overlaps report matches' in str(exc) and expected_content in str(exc)
    passed('Missing ContentSha256 match fails with an explicit error')
    duplicate = selector / 'duplicates/identifier-overlaps'
    duplicate.mkdir(parents=True)
    write(duplicate / 'one.json', {'Catalog': {'ContentSha256': expected_content}, 'Matches': [], 'Counts': {}})
    write(duplicate / 'two.json', {'Catalog': {'ContentSha256': expected_content}, 'Matches': [], 'Counts': {}})
    try:
        m.select_permission_overlap(duplicate.parent, expected_content)
        raise AssertionError('Ambiguous permission-overlap reports accepted')
    except ValueError as exc:
        assert '2 identifier-overlaps reports match' in str(exc) and 'one.json' in str(exc) and 'two.json' in str(exc)
    passed('Duplicate ContentSha256 matches fail with an explicit ambiguity error')
    if reuse:
        f = reuse / 'fixture-input'
        a, b = [m.read(reuse / name / 'receipt.json') for name in ('fixture-first', 'fixture-replay')]
        for name, receipt in zip(('fixture-first', 'fixture-replay'), (a, b)):
            prior = reuse / name
            assert m.digest((prior / 'discovery-data/applications.json').read_bytes()) == receipt['candidateSha256']
            assert m.digest((prior / 'diff.json').read_bytes()) == receipt['diffSha256']
            assert m.read(prior / 'diff.json')['bindings']['adapterSha256'] == REUSED_FIXTURE_ADAPTER_SHA256
    else:
        f = fixture(root, work, native, pwsh)
        a = m.reconcile(f, work / 'fixture-first', native, pwsh)
        b = m.reconcile(f, work / 'fixture-replay', native, pwsh)
    assert a['candidateSha256'] == b['candidateSha256'] and a['diffSha256'] == b['diffSha256']
    assert a['counts']['candidate'] == 4 and a['counts']['additions'] == 1 and a['counts']['removals'] == 0
    assert a['counts']['notObservedRetained'] == 1 and a['counts']['contentChanges'] == 1
    assert a['counts']['duplicateApplicationIds'] == a['counts']['duplicateRunIds'] == a['counts']['duplicateExactHistoricalVersions'] == 0
    passed('Fixture addition/change/omission retains history and scope bytes; deterministic replay without duplicates')
    saved = m.read(f / 'public-exchange/health.json')
    incomplete = work / 'incomplete-input'
    shutil.copytree(f, incomplete)
    h = copy.deepcopy(saved)
    h.update(complete=False, lastCompleteAt=None, candidateCount=0, conflictCount=0)
    h['sources'][0].update(status='Invalid', lastSuccessAt=None, sha256=None, candidateCount=0, changed=False)
    empty = {'Format': 'TokenForgeApplicationMetadata', 'SchemaVersion': 2, 'CreatedAt': h['collectedAt'],
             'UpdatedAt': h['collectedAt'], 'Applications': {}, 'Origins': {}, 'Runs': []}
    write(incomplete / 'public-exchange/health.json', h)
    write(incomplete / 'public-exchange/metadata.json', empty)
    manifest(incomplete / 'public-exchange')
    partial = m.reconcile(incomplete, work / 'incomplete-output', native, pwsh)
    assert partial['candidateSha256'] == m.digest((incomplete / 'baseline/applications.json').read_bytes())
    assert partial['counts']['removals'] == partial['counts']['additions'] == partial['counts']['contentChanges'] == 0
    passed('Incomplete valid exchange preserves exact baseline bytes/dates; no false fresh snapshot/removal')
    invalid = work / 'invalid-input'
    shutil.copytree(f, invalid)
    (invalid / 'public-exchange/metadata.json').chmod(0o600)
    with (invalid / 'public-exchange/metadata.json').open('ab') as stream:
        stream.write(b' ')
    try:
        m.reconcile(invalid, work / 'invalid-output', native, pwsh)
        raise AssertionError('Tampered exchange accepted')
    except ValueError:
        assert not (work / 'invalid-output').exists()
    passed('Invalid input/manifest mismatch cannot promote a candidate')
    acq = m.read(f / 'acquisition.json')
    future = copy.deepcopy(saved)
    future['collectedAt'] = '2099-01-01T00:00:00+00:00'
    try:
        m.capture_observation(m.read(f / 'public-exchange/metadata.json'), future, acq)
        raise AssertionError('Freshened projection time accepted')
    except ValueError:
        pass
    passed('Reprojection cannot freshen observation time; capture-date binding enforced')
    original = m.read(f / 'public-exchange/metadata.json')
    normalized = m.capture_observation(original, saved, acq)
    assert normalized['Origins']['Discovery///']['LastObservedAt'] == acq['finishedAt']
    assert original['Origins']['Discovery///']['LastObservedAt'] == saved['collectedAt']
    passed('Actual capture time used without rewriting frozen projection input')
    try:
        json.loads('{"a":1,"a":2}', object_pairs_hook=m.unique)
        raise AssertionError('Duplicate key accepted')
    except ValueError:
        pass
    passed('Duplicate identities/JSON keys refused before selection')
    doc = {'Attributes': {'SourceClaims': [{'Evidence': 'PublishedEntraDocs', 'Location': 'same'}]}}
    assert m.classification(doc) == 'DocumentationOnlyCandidate'
    doc['Attributes']['SourceClaims'] += [{'Evidence': 'PublishedGraph', 'Location': 'same'}, {'Evidence': 'PublishedGitHub', 'Location': 'same'}]
    assert m.classification(doc) == 'SinglePublicIdentityClaim'
    passed('Documentation and same-source claims never become independently corroborated identities')
    replay = m.reconcile(root, work / 'real-replay', native, pwsh)
    reference = m.read(expected / 'receipt.json')
    assert replay['candidateSha256'] == reference['candidateSha256']
    assert replay['publicDownloadSha256'] == reference['publicDownloadSha256']
    reference_diff = m.read(expected / 'diff.json')
    replay_diff = m.read(work / 'real-replay/diff.json')
    assert replay_diff['bindings']['adapterSha256'] == m.digest((REPO / 'scripts/Reconcile-TokenForgePublicApplications.py').read_bytes())
    diff_source_binding_changed = reference_diff['bindings']['adapterSha256'] != replay_diff['bindings']['adapterSha256']
    replay_diff['bindings']['adapterSha256'] = reference_diff['bindings']['adapterSha256']
    assert m.encoded(replay_diff) == (expected / 'diff.json').read_bytes()
    assert all(replay['counts'][k] == 0 for k in ('removals', 'duplicateApplicationIds', 'duplicateRunIds', 'duplicateExactHistoricalVersions'))
    passed('Frozen real-input replay matches candidate/gzip byte-for-byte and diff except the updated adapter source hash; zero duplicates/removals')
    for file, item in m.read(root / 'baseline-pin.json')['files'].items():
        assert m.digest((root / 'baseline' / file).read_bytes()) == item['sha256']
    passed('Original published baseline and scope exports remain unchanged')
    summary = {'passed': len(results), 'failed': 0, 'checks': results, 'replay': replay,
               'replayComparison': {'candidateByteIdentical': replay['candidateSha256'] == reference['candidateSha256'],
                                    'gzipByteIdentical': replay['publicDownloadSha256'] == reference['publicDownloadSha256'],
                                    'diffAllOtherFieldsIdentical': True,
                                    'diffSourceBindingChanged': diff_source_binding_changed,
                                    'retainedDiffSha256': reference['diffSha256'],
                                    'replayedDiffSha256': replay['diffSha256']},
               'authentication': False, 'networkRequests': 0, 'publication': 'NotAttempted'}
    write(work / 'verification.json', summary)
    print(json.dumps(summary, indent=2))


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    for name in ('input-root', 'expected-output', 'work-root', 'native', 'pwsh'):
        p.add_argument('--' + name, type=Path, required=True)
    p.add_argument('--reuse-fixture-from', type=Path)
    args = p.parse_args()
    verify(args.input_root, args.expected_output, args.work_root, args.native, args.pwsh, args.reuse_fixture_from)
