"""Separated sign-in review jobs with an opt-in directory audit cohort."""

import base64
import json
import os
from pathlib import Path
import re
import sys

from candidate_metadata import classify_principal, principal_url
from collect import (CATALOG_COMMIT, GRAPH_EVENTS, MAX_IDS, REPOSITORY, IncompleteCategory,
                     collect_envelope, collection_end, decode, handoff_identity, intervals,
                     pinned_catalog_app_ids, run_scope, utc)
from directory_provisioning import COVERAGE_SOURCE, scan_directory
from handoff import MAX_CIPHERTEXT, open_envelope, seal
from report import report
from workload_http import HTTPFailure, graph_reader, request_json

MAX_ENCODED = 4 * ((MAX_CIPHERTEXT + 2) // 3)


def write_coverage(env, end, days, coverage):
    if 'GITHUB_STEP_SUMMARY' not in env:
        return
    lines = [
        '### Graph discovery coverage', '',
        f'Requested {days} days ending at {utc(end)} (UTC, exclusive).',
        f'Published catalog commit: `{CATALOG_COMMIT}`.',
        'Provider retention is unknown. A terminal page with no rows can reflect no activity or missing retained data.',
        'Incomplete or unattempted windows prevent a review issue update.', '',
        '| Source | Start (UTC) | End (UTC, exclusive) | Result |',
        '| --- | --- | --- | --- |',
    ]
    for source in (*GRAPH_EVENTS, COVERAGE_SOURCE):
        for start, stop in intervals(end, days):
            status = coverage.get((source, start, stop), 'Unattempted')
            lines.append(f'| {source} | {utc(start)} | {utc(stop)} | {status} |')
    with Path(env['GITHUB_STEP_SUMMARY']).open('a', encoding='ascii') as summary:
        summary.write('\n'.join(lines) + '\n')


def collect_job(env, *, directory=False):
    if 'TF_HANDOFF_IDENTITY' in env or 'GH_TOKEN' in env:
        raise ValueError('Unexpected issue authorization in audit job')
    handoff_identity(env)
    if directory:
        end, days = collection_end(), run_scope(env)
        coverage = {}
        sign_in_failure = None
        try:
            known = pinned_catalog_app_ids()
            get = graph_reader(env, include_directory_audit=True)
            try:
                envelope = decode(collect_envelope(env, get, known, end=end, coverage=coverage))
            except IncompleteCategory as error:
                sign_in_failure = error
            provisioned = scan_directory(get, end, days, known, coverage=coverage)
            if sign_in_failure is not None:
                raise sign_in_failure
        finally:
            write_coverage(env, end, days, coverage)
        provisioned_apps = set(provisioned['appIds'])
        envelope['directoryCoverage'] = {
            'status': 'requested-windows-terminal;retention-unknown',
            'windows': [
                {'since': window['since'], 'until': window['until'],
                 'unresolvedAppIdRows': window['counts'].get('successfulUnresolvedAppId', 0)}
                for window in provisioned['windows']
            ],
        }
    else:
        get = graph_reader(env)
        envelope = decode(collect_envelope(env, get))
        provisioned_apps = set()
    sign_in_apps = set(envelope['appIds'])
    apps = sign_in_apps | provisioned_apps
    if len(apps) > MAX_IDS:
        raise ValueError('Combined candidate handoff exceeds its bound')
    labels = {}
    for app in sorted(apps):
        try:
            principal = get(principal_url(app))
        except HTTPFailure as error:
            if error.status != 404:
                raise
            principal = None
        source = 'sign-in' if app in sign_in_apps else 'provisioning'
        if app in sign_in_apps and app in provisioned_apps:
            source = 'sign-in and provisioning'
        label = classify_principal(app, env['TF_AUDIT_TENANT_ID'], principal, source)
        if label is not None:
            labels[app] = label
    envelope.update(appIds=sorted(labels), labels=labels)
    raw = json.dumps(envelope, separators=(',', ':')).encode()
    ciphertext = seal(raw, env, env['TF_HANDOFF_RECIPIENT'], categories=GRAPH_EVENTS, labeled=True, directory=directory)
    with Path(env['GITHUB_OUTPUT']).open('a', encoding='ascii') as output:
        output.write('ciphertext=' + base64.b64encode(ciphertext).decode('ascii') + '\n')


def issue_call(*args, body=None):
    if len(args) == 1 and body is None:
        method, target = 'GET', args[0]
    elif len(args) == 5 and args[:2] == ('--method', 'PATCH') and args[3:] == ('--input', '-') and isinstance(body, bytes):
        method, target = 'PATCH', args[2]
    else:
        raise ValueError('Unexpected issue operation')
    if not re.fullmatch(rf'repos/{re.escape(REPOSITORY)}/issues/[1-9][0-9]{{0,9}}', target):
        raise ValueError('Unexpected issue destination')
    token = os.environ.get('GH_TOKEN', '')
    if not re.fullmatch(r'[!-~]{1,16384}', token):
        raise ValueError('Missing issue-only workflow token')
    return request_json(
        'https://api.github.com/' + target, method=method, data=body, max_bytes=256 * 1024,
        headers={'Authorization': 'Bearer ' + token, 'Accept': 'application/vnd.github+json',
                 'X-GitHub-Api-Version': '2022-11-28', 'Content-Type': 'application/json'},
    )


def report_job(env, identity, api=issue_call, *, directory=False):
    for key in ('ACTIONS_ID_TOKEN_REQUEST_TOKEN', 'ACTIONS_ID_TOKEN_REQUEST_URL',
                'TF_AUDIT_TENANT_ID', 'TF_AUDIT_CLIENT_ID', 'TF_HANDOFF_RECIPIENT'):
        if key in env:
            raise ValueError('Unexpected audit authorization in issue job')
    handoff_identity(env)
    encoded = env['TF_HANDOFF_CIPHERTEXT']
    if not 0 < len(encoded) <= MAX_ENCODED:
        raise ValueError('Unexpected candidate ciphertext size')
    ciphertext = base64.b64decode(encoded, validate=True)
    if base64.b64encode(ciphertext).decode('ascii') != encoded:
        raise ValueError('Noncanonical candidate ciphertext encoding')
    raw = open_envelope(ciphertext, env, identity, categories=GRAPH_EVENTS, labeled=True, directory=directory)
    report(env, raw, api, categories=GRAPH_EVENTS, labeled=True, directory=directory)


if __name__ == '__main__':
    try:
        if os.environ.get('GITHUB_EVENT_NAME') != 'workflow_dispatch':
            raise ValueError('The initial activation permits manual runs only')
        command = sys.argv[1:]
        if command in (['collect-directory'], ['issue-directory']) and os.environ.get('TF_CATALOG_TIP') != CATALOG_COMMIT:
            raise SystemExit('Published catalog does not match the reviewed discovery pin.')
        if command == ['collect-directory']:
            try:
                collect_job(os.environ, directory=True)
            except Exception:
                # Transport and parser errors can contain private provider data.
                raise SystemExit('Sign-in candidate review stopped.') from None
        elif command == ['collect']:
            collect_job(os.environ)
        elif command in (['issue'], ['issue-directory']):
            report_job(os.environ, os.environ.pop('TF_HANDOFF_IDENTITY'), directory=command == ['issue-directory'])
        else:
            raise ValueError('Unexpected candidate review command')
    except (KeyError, ValueError, TypeError, AttributeError, OSError):
        sys.exit('Sign-in candidate review stopped.')
