#!/usr/bin/env python3
"""Replay only native admin explain/check/packet over the bundled synthetic files."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess

# Outcome checks below must never be disabled by an optimized Python process.
if not __debug__:
    raise SystemExit('Run without Python optimization; expected-outcome checks are required.')

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--native-executable', type=Path, required=True)
parser.add_argument('--package-manifest-sha256', required=True)
parser.add_argument('--source-revision', required=True)
parser.add_argument('--output-directory', type=Path, required=True)
args = parser.parse_args()
if os.name != 'posix' or not __import__('sys').platform.startswith('linux'):
    parser.error('This walkthrough supports local Linux only.')
if not re.fullmatch('[0-9a-f]{64}', args.package_manifest_sha256):
    parser.error('Supply the independently reviewed package manifest SHA-256.')
if not re.fullmatch('[0-9a-f]{40}|[0-9a-f]{64}', args.source_revision):
    parser.error('Supply the independently reviewed source revision.')
exe = args.native_executable.resolve(strict=True)
manifest_path = exe.parent / 'public-health-package.json'
manifest_bytes = manifest_path.read_bytes()
if hashlib.sha256(manifest_bytes).hexdigest() != args.package_manifest_sha256:
    raise SystemExit('Package manifest digest does not match the reviewed pin.')
manifest = json.loads(manifest_bytes)
if manifest['sourceRevision'] != args.source_revision:
    raise SystemExit('Package source revision does not match the reviewed pin.')
# This checks consistency with a reviewed receipt, not publisher authenticity.
for name, entry in manifest['files'].items():
    path = exe.parent / name
    if Path(name).is_absolute() or '..' in Path(name).parts or not path.is_file():
        raise SystemExit('Invalid or missing package member.')
    data = path.read_bytes()
    if len(data) != entry['bytes'] or hashlib.sha256(data).hexdigest() != entry['sha256']:
        raise SystemExit('Package payload differs from its reviewed manifest.')
if 'tokenforge' not in manifest['files'] or exe.name != 'tokenforge':
    raise SystemExit('Expected the reviewed package tokenforge executable.')
base = Path(__file__).resolve().parent
expected = json.loads((base / 'expected.json').read_text())
# Exclusive creation: never inspect or reuse an operator account directory.
os.umask(0o077)
work = args.output_directory.absolute()
work.mkdir(mode=0o700, parents=False, exist_ok=False)
inputs = work / 'inputs'
inputs.mkdir(mode=0o700)
for path in (base / 'inputs').glob('*.json'):
    shutil.copyfile(path, inputs / path.name)
    (inputs / path.name).chmod(0o600)
environment = dict(os.environ, PATH=str(work / 'no-adapters'))
results = []
for case in expected['Cases']:
    for command in ('explain', 'check', 'packet'):
        options = [str(exe), 'admin', command, '--requirements-path', str(inputs / 'requirements.json')]
        if command == 'packet':
            options += ['--before-path', str(inputs / case['PacketBefore']),
                        '--after-path', str(inputs / case['Snapshot']),
                        '--source-revision', args.source_revision,
                        '--package-sha256', args.package_manifest_sha256]
        else:
            options += ['--profile-path', str(inputs / 'profile.json'),
                        '--inventory-path', str(inputs / 'inventory.json'),
                        '--snapshot-path', str(inputs / case['Snapshot']), '--tool', 'read-profile']
        options += ['--as-of', expected['AsOf'], '--json']
        process = subprocess.run(options, input='', capture_output=True, text=True,
                                 timeout=30, env=environment, cwd=work)
        # Preserve actual output and command/exit receipt before checking outcomes.
        stem = case['Name'] + '-' + command
        (work / (stem + '.stdout.json')).write_text(process.stdout)
        (work / (stem + '.stderr.txt')).write_text(process.stderr)
        (work / (stem + '.command.json')).write_text(json.dumps(dict(Arguments=options, ExitCode=process.returncode), indent=2) + '\n')
        result = json.loads(process.stdout)
        assert not process.stderr, stem + ': unexpected stderr'
        if command == 'packet':
            events = [entry['Change']['EventType'] for entry in result['Entries']]
            assert process.returncode == 0 and result['Status'] == 'PreparedForHumanReview', stem
            assert events == case['PacketEvents'], (stem, events)
            assert result['AutomaticCommunication'] is False and result['CommunicationAuthorized'] is False, stem
            assert result['RootCauseEstablished'] is False and result['RegressionConfirmation'] == 'NotPerformed', stem
            assert result['ProducerSourceRevision'] == args.source_revision, stem
            assert result['PackageManifestSha256'] == args.package_manifest_sha256, stem
            assert result['DisclosureRoute'] == 'PrivateMaintainerReview', stem
            assert result['OmittedEntryCount'] == 0 and not result['Truncated'], stem
        else:
            assert process.returncode == case['ExitCode'] and result['ExitCode'] == case['ExitCode'], stem
            assert result['Status'] == case['Status'], stem
            assert result['Clients'][0]['Reasons'] == case['Reasons'], stem
            assert result['AuthorizationEstablished'] is False and result['CurrentAcquisitionPerformed'] is False, stem
        results.append(dict(Case=case['Name'], Command=command, ExitCode=process.returncode,
                            Status=result['Status'], PacketEvents=events if command == 'packet' else None))
summary = dict(SourceRevision=args.source_revision, PackageManifestSha256=args.package_manifest_sha256,
               ExecutableSha256=hashlib.sha256(exe.read_bytes()).hexdigest(),
               AsOf=expected['AsOf'], CommandsPassed=len(results), Results=results)
(work / 'summary.json').write_text(json.dumps(summary, indent=2) + '\n')
print(json.dumps(dict(CommandsPassed=len(results), OutputDirectory=str(work))))
