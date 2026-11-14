#!/usr/bin/env python3
"""Prepare a local public catalog candidate. Never authenticate or publish."""
import argparse
from datetime import datetime, timezone
import fcntl
import gzip
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import time

REPO = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('reconciliation', REPO / 'scripts/Reconcile-TokenForgePublicApplications.py')
adapter = importlib.util.module_from_spec(spec)
spec.loader.exec_module(adapter)
SOURCES = {
    'roadtools': 'https://raw.githubusercontent.com/dirkjanm/ROADtools/master/roadtx/roadtools/roadtx/firstpartyscopes.json',
    'microsoftApps': 'https://raw.githubusercontent.com/merill/microsoft-info/main/_info/MicrosoftApps.json',
    'resources': 'https://raw.githubusercontent.com/f-bader/entrascopes.com/main/resources.json',
}
PINNED = {'nativeSha256': '21e1f3c5b8005fae99dae2290d9bfdee8a080402c1346175f3ad80712efc79b1',
          'credentialSha256': '14a12d434306eace18ca14195ef682c92ea9c79e7ceb3b16f0c0707c4006c789',
          'powerShellSha256': '873de21f04b6a0269c220f9c8396ff5cd639e8deb058a32cc26df54b69bbff8d'}
GRAPH = 'api-definitions/graph/b9a67f126ee562c9ff20645f8a4fb6c0928d0a7a.json'
GRAPH_SHA256 = 'aa878a6f4d997314279df184f0b42d81f0de4fe033e05f464035fe8b407eaa78'
GET = r'''
param($Repo,$Name,$Destination,$Seconds)
$ErrorActionPreference='Stop'
. (Join-Path $Repo scripts/TokenForgePublicHealth.ps1)
$budget=New-TokenForgeHealthBudget -MaxSeconds ([double]$Seconds) -MaxRequests 1
$reply=Invoke-TokenForgeHealthGet -Uri $script:HealthSources[$Name] -MaxBytes 8388608 -Budget $budget -AllowedHosts @('raw.githubusercontent.com')
if($reply.StatusCode -ne 200){throw 'Public source refused.'}
[IO.File]::WriteAllBytes($Destination,$reply.Bytes)
'''
COMPARE = r'''
param($Repo,$Catalog,$Definitions,$Native,$Output)
$ErrorActionPreference='Stop'
. (Join-Path $Repo scripts/TokenForgePublicHealth.ps1)
Initialize-TokenForgeHealthRuntime $Native
$r=& (Join-Path $Repo scripts/Compare-TokenForgePermissionIdentifiers.ps1) -CatalogPath $Catalog -PermissionSnapshotPath $Definitions -NativeExecutablePath $Native -IncludeMatches
$r | ConvertTo-Json -Depth 100 | Set-Content -LiteralPath $Output -Encoding utf8NoBOM
'''


def utc():
    return datetime.now(timezone.utc).isoformat()


def write(path, value):
    """Atomically persist the journal before dispatch; never truncate its old copy."""
    data = adapter.encoded(value)
    fd, temporary = tempfile.mkstemp(prefix='.journal-', dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def git(root, *args, env=None):
    return subprocess.check_output(['git', '-C', str(root), *args], env=env, text=True).strip()


def inventory(root):
    if root.is_symlink() or any(p.is_symlink() for p in root.rglob('*') if '.git' not in p.relative_to(root).parts):
        raise ValueError('Linked input/output files are refused.')
    return {str(p.relative_to(root)): {'sha256': adapter.digest(p.read_bytes()), 'bytes': p.stat().st_size}
            for p in sorted(root.rglob('*')) if p.is_file() and '.git' not in p.relative_to(root).parts}


def check_inventory(root, expected):
    if inventory(root) != expected:
        raise ValueError('Retained input/output hashes or membership changed: ' + str(root))


def checked_baseline(baseline, expected):
    if git(baseline, 'rev-parse', 'HEAD') != expected or git(baseline, 'status', '--porcelain', '--untracked-files=all'):
        raise ValueError('Baseline moved or is dirty; choose a fresh reviewed baseline and work directory.')


def ps(pwsh, script, args, log, timeout=300):
    result = subprocess.run([str(pwsh), '-NoProfile', '-NonInteractive', '-File', str(script), *map(str, args)],
                            capture_output=True, timeout=timeout)
    log.with_suffix('.stdout').write_bytes(result.stdout)
    log.with_suffix('.stderr').write_bytes(result.stderr)
    if result.returncode:
        raise ValueError('Existing tool refused; inspect private logs: ' + str(log))
    return result



def validate_acquisition(root, state):
    job = adapter.read(adapter.regular(root / 'job.json'))
    if (state['startedAt'] != job['acquisitionStartedAt'] or
            state['deadlineEpoch'] != job['acquisitionDeadlineEpoch'] or
            state['sourceRevision'] != job['sourceRevision'] or
            state['kind'] != 'FrozenAnonymousPublicInputs' or state['schemaVersion'] != 1 or
            state['authentication'] is not False):
        raise ValueError('Acquisition envelope differs from immutable job binding.')
    names = [row['name'] for row in state['sources']]
    if names != list(SOURCES)[:len(names)] or len(names) > 3 or state['requests'] != len(names):
        raise ValueError('Acquisition requests or membership changed.')
    if state['complete'] != (len(names) == 3 and all(row['status'] == 'Captured' for row in state['sources'])):
        raise ValueError('Acquisition completeness changed.')
    times = [state['startedAt']]
    for row in state['sources']:
        if row['uri'] != SOURCES[row['name']] or row['attempts'] != 1 or row['status'] not in ('Intent', 'Captured'):
            raise ValueError('Acquisition source identity or charge changed.')
        if row['status'] == 'Captured':
            when = datetime.fromisoformat(row['retrievedAt']).timestamp()
            if not datetime.fromisoformat(state['startedAt']).timestamp() <= when <= state['deadlineEpoch']:
                raise ValueError('Source retrieval outside original acquisition deadline.')
            times.append(row['retrievedAt'])
        elif row['sha256'] is not None or row['retrievedAt'] is not None or row['bytes'] != 0:
            raise ValueError('Uncertain attempt cannot claim captured evidence.')
    if state['finishedAt'] != max(times):
        raise ValueError('Acquisition finish differs from retained retrieval time.')


def acquire(root, state, pwsh, offline=False):
    """Each intent consumes one slot permanently. Unknown consumption is never retried."""
    validate_acquisition(root, state)
    raw = root / 'raw-public-inputs'
    raw.mkdir(exist_ok=True, mode=0o700)
    script = root / 'capture.ps1'
    script.write_text(GET)
    for name, uri in SOURCES.items():
        prior = next((s for s in state['sources'] if s['name'] == name), None)
        if prior:
            if prior['status'] != 'Captured':
                raise ValueError('Uncertain/failed source attempt remains charged; no automatic retry: ' + name)
            data = adapter.regular(raw / (name + '.json')).read_bytes()
            if len(data) != prior['bytes'] or adapter.digest(data) != prior['sha256']:
                raise ValueError('Retained public input changed: ' + name)
            continue
        if offline:
            raise ValueError('Offline operation requires all retained captures; missing: ' + name)
        remaining = state['deadlineEpoch'] - time.time()
        if remaining <= 0 or state['requests'] >= 6:
            raise ValueError('Acquisition deadline/request ceiling exhausted; no reset.')
        row = {'name': name, 'uri': uri, 'attempts': 1, 'status': 'Intent', 'sha256': None,
               'bytes': 0, 'retrievedAt': None}
        state['sources'].append(row)
        state['requests'] += 1
        write(root / 'acquisition.json', state)
        # A crash anywhere after intent leaves the attempt charged and terminal.
        temporary = raw / (name + '.partial')
        ps(pwsh, script, [REPO, name, temporary, min(remaining, 180)], root / ('get-' + name), timeout=min(remaining, 180) + 2)
        data = adapter.regular(temporary).read_bytes()
        if len(data) > 8388608:
            raise ValueError('Source exceeds 8 MiB.')
        os.replace(temporary, raw / (name + '.json'))
        if time.time() > state['deadlineEpoch']:
            raise ValueError('Capture exceeded original deadline; uncertain intent remains charged.')
        row.update(status='Captured', sha256=adapter.digest(data), bytes=len(data), retrievedAt=utc())
        state['finishedAt'] = row['retrievedAt']
        state['complete'] = len(state['sources']) == 3
        write(root / 'acquisition.json', state)


def initialize(root, baseline, expected, native, pwsh):
    checked_baseline(baseline, expected)
    if adapter.digest(adapter.regular(baseline / GRAPH).read_bytes()) != GRAPH_SHA256:
        raise ValueError('Pinned Graph definitions changed.')
    for path, key in [(native, 'nativeSha256'), (native.parent / 'src/TokenForge/lib/net10.0/TokenForge.Credentials.dll', 'credentialSha256'),
                      (pwsh, 'powerShellSha256')]:
        if adapter.digest(adapter.regular(path).read_bytes()) != PINNED[key]:
            raise ValueError('Approved runtime unavailable or changed; no build/download fallback.')
    source = {str(p.relative_to(REPO)): adapter.digest(p.read_bytes()) for p in sorted((REPO / 'src/TokenForge').rglob('*')) if p.is_file()}
    for name in ['TokenForgePublicHealth.ps1', 'Invoke-TokenForgePublicHealth.ps1', 'Export-TokenForgeCatalogDownload.ps1',
                 'Compare-TokenForgePermissionIdentifiers.ps1', 'TokenForgePublicPermissions.ps1',
                 'Reconcile-TokenForgePublicApplications.py', 'Refresh-TokenForgePublicCatalog.py']:
        source['scripts/' + name] = adapter.digest((REPO / 'scripts' / name).read_bytes())
    files = inventory(baseline)
    ledger_sha = files['applications.json']['sha256']
    manifests = [(p, adapter.read(p)) for p in (baseline / 'downloads').glob('*.manifest.json')]
    blob = git(baseline, 'rev-parse', 'HEAD:applications.json')
    matches = [(p, m) for p, m in manifests if m.get('SourceSha256') == ledger_sha and m.get('SourceGitBlob') == blob]
    if len(matches) != 1:
        raise ValueError('Exactly one source-byte-bound baseline download manifest is required.')
    manifest_path, manifest = matches[0]
    adapter.select_permission_overlap(baseline, manifest['ContentSha256'])
    root.mkdir(mode=0o700)
    shutil.copytree(baseline, root / 'baseline', ignore=shutil.ignore_patterns('.git'))
    pin = {'mainCommit': git(REPO, 'rev-parse', 'HEAD'), 'dataCommit': expected,
           'manifestPath': str(manifest_path.relative_to(baseline)), 'manifest': manifest, 'files': files}
    write(root / 'baseline-pin.json', pin)
    write(root / 'runtime-equivalence.json', {**PINNED, 'executedFiles': source})
    now = utc()
    deadline = datetime.fromisoformat(now).timestamp() + 180
    write(root / 'job.json', {'acquisitionStartedAt': now, 'acquisitionDeadlineEpoch': deadline, 'baseline': str(baseline), 'expectedBaseline': expected,
                             'sourceRevision': pin['mainCommit'], 'sourceFiles': source,
                             'pinSha256': adapter.digest((root / 'baseline-pin.json').read_bytes()),
                             'runtimeSha256': adapter.digest((root / 'runtime-equivalence.json').read_bytes())})
    write(root / 'acquisition.json', {'kind': 'FrozenAnonymousPublicInputs', 'schemaVersion': 1,
          'sourceRevision': pin['mainCommit'], 'authentication': False, 'startedAt': now, 'finishedAt': now,
          'deadlineEpoch': deadline, 'requests': 0, 'sources': [], 'complete': False})


def assert_job(root, baseline, expected, native, pwsh):
    job = adapter.read(adapter.regular(root / 'job.json'))
    if job['baseline'] != str(baseline) or job['expectedBaseline'] != expected:
        raise ValueError('Existing job is bound to a different baseline.')
    checked_baseline(baseline, expected)
    for path, digest in job['sourceFiles'].items():
        if adapter.digest(adapter.regular(REPO / path).read_bytes()) != digest:
            raise ValueError('Executed source changed during job: ' + path)
    for path, key in [('baseline-pin.json', 'pinSha256'), ('runtime-equivalence.json', 'runtimeSha256')]:
        if adapter.digest(adapter.regular(root / path).read_bytes()) != job[key]:
            raise ValueError('Frozen job binding changed.')
    check_inventory(root / 'baseline', adapter.read(root / 'baseline-pin.json')['files'])
    check_inventory(baseline, adapter.read(root / 'baseline-pin.json')['files'])
    for path, key in [(native, 'nativeSha256'), (native.parent / 'src/TokenForge/lib/net10.0/TokenForge.Credentials.dll', 'credentialSha256'), (pwsh, 'powerShellSha256')]:
        if adapter.digest(adapter.regular(path).read_bytes()) != PINNED[key]:
            raise ValueError('Runtime changed during job.')
    return job


def release(root, baseline, native, pwsh, counts):
    reconciled = root / 'reconciled'
    target = root / 'release'
    if target.exists():
        raise ValueError('Partial release exists; retain it and inspect; no overwrite/reset.')
    subprocess.run(['git', 'clone', '--quiet', '--no-checkout', '--shared', str(baseline), str(target)], check=True)
    git(target, 'checkout', '--quiet', '--detach', adapter.read(root / 'job.json')['expectedBaseline'])
    shutil.copyfile(reconciled / 'discovery-data/applications.json', target / 'applications.json')
    stamp = adapter.read(root / 'acquisition.json')['finishedAt']
    env = {**os.environ, 'GIT_AUTHOR_NAME': 'TokenForge catalog preparation', 'GIT_AUTHOR_EMAIL': 'catalog@invalid',
           'GIT_COMMITTER_NAME': 'TokenForge catalog preparation', 'GIT_COMMITTER_EMAIL': 'catalog@invalid',
           'GIT_AUTHOR_DATE': stamp, 'GIT_COMMITTER_DATE': stamp}
    git(target, 'add', 'applications.json')
    git(target, '-c', 'core.hooksPath=/dev/null', '-c', 'commit.gpgsign=false', 'commit', '--quiet', '-m', 'Retain public catalog history with reviewed observations', env=env)
    source_commit = git(target, 'rev-parse', 'HEAD')
    blob = git(target, 'rev-parse', 'HEAD:applications.json')
    name = 'applications-' + blob
    z = (reconciled / 'candidate-download.json.gz').read_bytes()
    content = gzip.decompress(z)
    ledger = adapter.read(target / 'applications.json')
    if json.loads(content) != ledger:
        raise ValueError('Download differs from validated ledger.')
    manifest = {'SchemaVersion': 1, 'Format': 'TokenForgeCatalogSnapshot', 'File': name + '.json.gz',
                'CatalogSchemaVersion': 2, 'Applications': len(ledger['Applications']), 'CatalogUpdatedAt': ledger['UpdatedAt'],
                'SourceCommit': source_commit, 'SourcePath': 'applications.json', 'SourceGitBlob': blob,
                'SourceSha256': adapter.digest((target / 'applications.json').read_bytes()),
                'ContentSha256': adapter.digest(content), 'CompressedSha256': adapter.digest(z),
                'UncompressedBytes': len(content), 'CompressedBytes': len(z),
                'Evidence': 'PublicSourceMetadataNotCompletedTokenDiscovery'}
    (target / 'downloads' / (name + '.json.gz')).write_bytes(z)
    write(target / 'downloads' / (name + '.manifest.json'), manifest)
    diff = adapter.read(reconciled / 'diff.json')
    lines = ['# Public metadata classification changes', '', json.dumps(counts, sort_keys=True), '',
             'Public claims are not verified apps, consent, issuance or API-access proof.', '',
             '| ID | Name | Evidence strength |', '| --- | --- | --- |']
    lines += ['| ' + a['id'] + ' | ' + a['name'].replace('|', '\\|') + ' | ' + a['classification'] + ' |' for a in diff['additions']]
    lines += ['', 'Changed existing records:', ''] + ['- ' + a['id'] + ': ' + ', '.join(a['fields']) for a in diff['changes']]
    lines += ['', 'Uncertainty: ' + str(counts['sourceDisagreements']) + ' source disagreements; ' + str(counts['quarantinedRows']) +
              ' quarantined rows. Source claims and conflicting attributes remain in the ledger. Permission overlap never supplies a deletion rule.', '']
    (target / 'downloads' / (name + '.changes.md')).write_text('\n'.join(lines))
    index = target / 'downloads/README.md'
    index.write_text(index.read_text() + '\n## Reviewed candidate ' + blob + '\n\n[Download](' + name + '.json.gz) · [Manifest](' + name + '.manifest.json) · [Classification changes](' + name + '.changes.md). Public metadata identifiers retain their recorded evidence strength; they are not verified apps.\n')
    comparator = root / 'compare.ps1'
    comparator.write_text(COMPARE)
    report = target / 'identifier-overlaps' / ('graph-b9a67f126ee5-catalog-' + blob[:12] + '.json')
    if report.exists():
        raise ValueError('New report would overwrite historical content.')
    ps(pwsh, comparator, [REPO, target / 'applications.json', target / GRAPH, native, report], root / 'compare')
    if adapter.read(report)['Catalog']['ContentSha256'] != manifest['ContentSha256']:
        raise ValueError('Generated overlap report differs from candidate content.')
    git(target, 'add', 'downloads', 'identifier-overlaps')
    git(target, '-c', 'core.hooksPath=/dev/null', '-c', 'commit.gpgsign=false', 'commit', '--quiet', '-m', 'Prepare immutable public catalog download and classification summary', env=env)
    return git(target, 'rev-parse', 'HEAD')


def refresh(baseline, expected, root, native, pwsh, offline=False, replay_output=None):
    baseline, root, native, pwsh = [p.absolute() for p in (baseline, root, native, pwsh)]
    if any(q.is_symlink() for p in (baseline, root, native, pwsh) for q in (p, *p.parents)) or root.is_relative_to(baseline) or baseline.is_relative_to(root) or root.is_relative_to(REPO):
        raise ValueError('Linked paths or overlapping baseline/work directories refused.')
    if not root.exists():
        initialize(root, baseline, expected, native, pwsh)
    with (root / '.lock').open('a+b') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        job = assert_job(root, baseline, expected, native, pwsh)
        state = adapter.read(root / 'acquisition.json')
        acquire(root, state, pwsh, offline)
        if not state['complete']:
            raise ValueError('Incomplete input cannot produce a publishable candidate.')
        seal = root / 'acquisition-seal.json'
        capture_hash = adapter.digest((root / 'acquisition.json').read_bytes())
        if seal.exists():
            if adapter.read(adapter.regular(seal)) != {'sha256': capture_hash}:
                raise ValueError('Completed acquisition evidence changed.')
        else:
            write(seal, {'sha256': capture_hash})
        exchange = root / 'public-exchange'
        if not exchange.exists():
            ps(pwsh, REPO / 'scripts/Invoke-TokenForgePublicHealth.ps1',
               ['-OutputPath', exchange, '-NativeExecutablePath', native, '-SourceRevision', job['sourceRevision'],
                '-FixturePath', root / 'raw-public-inputs', '-MaxSeconds', '180'], root / 'collector')
            write(root / 'exchange-inventory.json', inventory(exchange))
        check_inventory(exchange, adapter.read(root / 'exchange-inventory.json'))
        if not adapter.read(exchange / 'health.json')['complete']:
            raise ValueError('Incomplete or invalid source projection cannot produce a publishable candidate.')
        if replay_output:
            receipt = adapter.reconcile(root, replay_output, native, pwsh)
            assert_job(root, baseline, expected, native, pwsh)
            return receipt
        if (root / 'result.json').exists():
            if adapter.read(adapter.regular(root / 'result-seal.json')) != {'sha256': adapter.digest((root / 'result.json').read_bytes())}:
                raise ValueError('Completed result receipt changed.')
            result = adapter.read(root / 'result.json')
            retained = adapter.read(adapter.regular(root / 'reconciled/receipt.json'))
            changed = bool(retained['counts']['additions'] or retained['counts']['contentChanges'])
            if (result['counts'] != retained['counts'] or result['publishable'] is not changed or
                    result['status'] != ('CandidatePrepared' if changed else 'NoChange') or
                    result['baselineCommit'] != expected or result['sourceRevision'] != job['sourceRevision'] or
                    result['requests'] != state['requests'] or result['publication'] != 'NotAttempted'):
                raise ValueError('Completed result disagrees with retained reconciliation/job.')
            check_inventory(root / 'reconciled', result['reconciledInventory'])
            if result['status'] == 'CandidatePrepared':
                check_inventory(root / 'release', result['releaseInventory'])
                if git(root / 'release', 'rev-parse', 'HEAD') != result['releaseCommit']:
                    raise ValueError('Prepared release HEAD changed.')
            return result
        output = root / 'reconciled'
        if output.exists():
            raise ValueError('Unreceipted reconciliation exists; preserve and inspect it; no reset.')
        receipt = adapter.reconcile(root, output, native, pwsh)
        counts = receipt['counts']
        changed = counts['additions'] or counts['contentChanges']
        result = {'status': 'CandidatePrepared' if changed else 'NoChange', 'publishable': bool(changed),
                  'counts': counts, 'baselineCommit': expected, 'sourceRevision': job['sourceRevision'],
                  'requests': state['requests'], 'publication': 'NotAttempted',
                  'reconciledInventory': inventory(output)}
        if changed:
            result['releaseCommit'] = release(root, baseline, native, pwsh, counts)
            result['releaseInventory'] = inventory(root / 'release')
        assert_job(root, baseline, expected, native, pwsh)
        write(root / 'result.json', result)
        write(root / 'result-seal.json', {'sha256': adapter.digest((root / 'result.json').read_bytes())})
        return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for arg in ['baseline', 'work-root', 'native', 'pwsh']:
        parser.add_argument('--' + arg, type=Path, required=True)
    parser.add_argument('--expected-baseline-commit', required=True)
    parser.add_argument('--offline', action='store_true')
    parser.add_argument('--replay-output', type=Path)
    args = parser.parse_args()
    result = refresh(args.baseline, args.expected_baseline_commit, args.work_root, args.native, args.pwsh,
                     args.offline, args.replay_output)
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()
