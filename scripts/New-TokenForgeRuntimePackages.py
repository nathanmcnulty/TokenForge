#!/usr/bin/env python3
"""Repack the reviewed local runtime archives without compilation or downloads.

Pins describe historical local artifacts, not signatures or release authorization.
Only Git blobs from the selected owning HEAD may replace source-backed files.
"""
import argparse
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import stat
import subprocess
import tarfile
import zipfile

PRIOR_SOURCE = '58203ecdcee47c4bdaaef0801d0b496d22daa35f'
NATIVE_SOURCE = 'c32cd7b27e98fdeac9f376807999205d99133a38'
MODULE_SOURCE = 'cbea33eca2dfde24f0c92b0385784876510e4ece'
LINUX_HASH = '975a8407cc0e7c90939fc630f48b7da2b92947ee2c8d11435944cc1c15e5ea7d'
ZIP_HASH = 'b953287a8364cdead26391dc12175b8a8e99a82df5cacd6e69140967b903cd0f'
DLL = 'src/TokenForge/lib/net10.0/TokenForge.Credentials.dll'
NATIVE_HASH = '42773ca3e048d5d29dd3edf488ca33ace5116d47afdd4513fa8df95b24a3047e'
LINUX_DLL_HASH = 'a96664feb04f767cd48360a706292e2577e36472a1b27ac282c6e67899fa1a52'
MODULE_DLL_HASH = '969c5ff5020b4be4e41b64a3a63c3602aa2d433b69cad853e42fe03ad801c2a4'
INPUT_PATHS = ('global.json', 'native', 'src/TokenForge/Core',
               'scripts/Build-TokenForgeNative.ps1', 'scripts/Build-TokenForgeCredentials.ps1',
               'scripts/Copy-TokenForgePackageSource.ps1')


def sha(data):
    return hashlib.sha256(data).hexdigest()


def require(condition, message):
    if not condition:
        raise ValueError(message)


def safe_name(name):
    require(name and not name.startswith('/') and '\\' not in name
            and not any(ord(c) < 32 or ord(c) == 127 for c in name)
            and all(p not in ('', '.', '..') for p in name.split('/')),
            'Unsafe package path')
    return name


def read_archive(path, expected, zipped=False):
    data = path.read_bytes()
    require(sha(data) == expected, 'Archive differs from the independently pinned historical artifact')
    files, seen = {}, set()

    def add(name, content):
        name = safe_name(name)
        require(name.casefold() not in seen, 'Duplicate or case-colliding package member')
        seen.add(name.casefold())
        files[name] = content

    if zipped:
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            for entry in archive.infolist():
                mode = entry.external_attr >> 16
                require(stat.S_IFMT(mode) in (0, stat.S_IFREG, stat.S_IFDIR), 'Nonregular package member')
                if not entry.is_dir():
                    add(entry.filename, archive.read(entry))
    else:
        with tarfile.open(fileobj=io.BytesIO(data), mode='r:gz') as archive:
            for entry in archive:
                require(entry.isfile() or entry.isdir(), 'Nonregular package member')
                if entry.isfile():
                    add(entry.name.removeprefix('./'), archive.extractfile(entry).read())
    for name in files:
        require(not any('/'.join(name.split('/')[:i]).casefold() in seen
                        for i in range(1, len(name.split('/')))), 'File/parent package conflict')
    return files


def git(repo, *args):
    return subprocess.check_output(['git', '-C', str(repo), *args])


def tree(repo, revision, *paths):
    entries = {}
    for entry in git(repo, 'ls-tree', '-rz', revision, '--', *paths).split(b'\0'):
        if entry:
            meta, name = entry.split(b'\t', 1)
            mode, kind, blob = meta.split()
            name = safe_name(name.decode('utf-8', errors='strict'))
            require(kind == b'blob' and mode in (b'100644', b'100755'), 'Source must be regular tracked files')
            entries[name] = blob.decode('ascii')
    require(len({n.casefold() for n in entries}) == len(entries), 'Case-colliding source paths')
    return entries


def blob(repo, revision, path):
    return git(repo, 'show', revision + ':' + path)


def linux_source(name):
    if name == 'README.md':
        return 'docs/native-cli.md'
    if name.startswith(('src/TokenForge/', 'scripts/')) or name == 'THIRD-PARTY-NOTICES.md':
        return name
    if name.startswith(('examples/', 'docs/')):
        return 'docs/' + name if name.startswith('examples/') else name
    require('/' not in name, 'Unexpected historical Linux layout')
    return 'docs/' + name


def prepare(repo, revision, old, zipped):
    compiled_source = MODULE_SOURCE if zipped else NATIVE_SOURCE
    inputs = tree(repo, compiled_source, *INPUT_PATHS)
    require(len(inputs) >= 100 and inputs == tree(repo, revision, *INPUT_PATHS),
            'Complete compilation inputs differ; rebuilding requires separate qualification')
    prior = tree(repo, PRIOR_SOURCE)
    binaries = {DLL: MODULE_DLL_HASH if zipped else LINUX_DLL_HASH}
    if not zipped:
        binaries['tokenforge'] = NATIVE_HASH
        manifest = json.loads(old.pop('public-health-package.json'))
        require(manifest['sourceRevision'] == PRIOR_SOURCE and set(manifest['files']) == set(old),
                'Historical Linux manifest inventory differs')
        for name, value in old.items():
            require(manifest['files'][name] == {'sha256': sha(value), 'bytes': len(value)},
                    'Historical Linux manifest bytes differ')
    source_map = {}
    for name, value in old.items():
        if name in binaries:
            require(sha(value) == binaries[name], 'Compiled binary differs from its independent pin')
        else:
            source = name if zipped else linux_source(name)
            require(source in prior and value == blob(repo, PRIOR_SOURCE, source),
                    'Historical source-backed member differs: ' + name)
            source_map[name] = source
    require(set(binaries).issubset(old), 'Missing compiled payload')
    current = tree(repo, revision)
    # Preserve historical layout while refreshing every source-backed member.
    source_map = {name: source for name, source in source_map.items() if source in current}
    for name in current:
        if name.startswith('src/TokenForge/') or name.startswith('examples/offline-admin/'):
            source_map[name] = name
        if name.startswith('docs/') and name.endswith('.md'):
            source_map[name] = name
    # Module ZIPs also need the collector wrappers and their local dependencies.
    for name in ('Get-TokenForgeCollectorStatus.ps1', 'Invoke-TokenForgeDiscoveryRun.ps1',
                 'TokenForgeDiscoveryCandidate.ps1', 'Test-TokenForgeOfflinePackage.ps1'):
        source_map['scripts/' + name] = 'scripts/' + name
    files = {name: old[name] for name in binaries}
    for name, source in source_map.items():
        require(name not in binaries, 'Source may not replace compiled payload')
        files[name] = blob(repo, revision, source)
    require(len({n.casefold() for n in files}) == len(files), 'Case-colliding output paths')
    provenance = dict(schemaVersion=1, kind='TokenForgeRuntimePackage', sourceRevision=revision,
                      compiledSource=compiled_source, compilationInputs=inputs,
                      priorArchiveSha256=ZIP_HASH if zipped else LINUX_HASH,
                      sourceFiles=source_map, operationalPublication=False,
                      files={n: dict(sha256=sha(v), bytes=len(v)) for n, v in sorted(files.items())})
    # Keep the public-health manifest name used by the offline administrator replay.
    manifest_name = 'runtime-package.json' if zipped else 'public-health-package.json'
    files[manifest_name] = (json.dumps(provenance, indent=2, sort_keys=True) + '\n').encode()
    return files


def write_archive(path, files, zipped):
    if zipped:
        with zipfile.ZipFile(path, 'x', compression=zipfile.ZIP_DEFLATED) as archive:
            for name, value in sorted(files.items()):
                entry = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
                entry.external_attr = (stat.S_IFREG | 0o600) << 16
                entry.compress_type = zipfile.ZIP_DEFLATED
                archive.writestr(entry, value)
    else:
        with path.open('xb') as raw, gzip.GzipFile(filename='', fileobj=raw, mode='wb', mtime=0) as compressed:
            with tarfile.open(fileobj=compressed, mode='w') as archive:
                for name, value in sorted(files.items()):
                    entry = tarfile.TarInfo(name)
                    entry.size = len(value)
                    entry.mode = 0o700 if name == 'tokenforge' else 0o600
                    archive.addfile(entry, io.BytesIO(value))
    return dict(path=path.name, sha256=sha(path.read_bytes()), bytes=path.stat().st_size,
                payloadFiles=len(files), payloadHashes={n: sha(v) for n, v in sorted(files.items())})


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--linux-archive', type=Path, required=True)
    parser.add_argument('--module-archive', type=Path, required=True)
    parser.add_argument('--source-revision', required=True)
    parser.add_argument('--output-directory', type=Path, required=True)
    args = parser.parse_args()
    require(os.name == 'posix' and __import__('sys').platform.startswith('linux'), 'Linux only')
    repo = Path(__file__).resolve().parent.parent
    revision = git(repo, 'rev-parse', 'HEAD').decode().strip()
    require(args.source_revision == revision, 'Source revision must be owning HEAD')
    require(Path(__file__).read_bytes() == blob(repo, revision, 'scripts/' + Path(__file__).name),
            'Packaging driver differs from owning HEAD')
    linux = prepare(repo, revision, read_archive(args.linux_archive, LINUX_HASH), False)
    module = prepare(repo, revision, read_archive(args.module_archive, ZIP_HASH, True), True)
    # Validate all inputs before create-new output; never overwrite historical receipts.
    os.umask(0o077)
    args.output_directory.mkdir(mode=0o700, parents=False, exist_ok=False)
    results = [write_archive(args.output_directory / 'TokenForge-linux-x64.tar.gz', linux, False),
               write_archive(args.output_directory / 'TokenForge-module.zip', module, True)]
    summary = dict(sourceRevision=revision, rebuilt=False, published=False, packages=results)
    (args.output_directory / 'qualification-packages.json').write_text(json.dumps(summary, indent=2) + '\n')
    print(json.dumps({k: v for k, v in summary.items() if k != 'packages'}))
    print(json.dumps([{k: v for k, v in r.items() if k != 'payloadHashes'} for r in results]))


if __name__ == '__main__':
    main()
