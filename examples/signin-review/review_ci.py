"""Separated sign-in review jobs with an opt-in directory audit cohort."""

import base64
from datetime import datetime
import json
import os
from pathlib import Path
import re
import sys

from candidate_metadata import classify_principal, principal_url
from collect import (GRAPH_EVENTS, MAX_IDS, REPOSITORY, collect_envelope, decode, handoff_identity,
                     pinned_catalog_app_ids, run_scope)
from directory_provisioning import scan_directory
from handoff import MAX_CIPHERTEXT, open_envelope, seal
from report import report
from workload_http import HTTPFailure, graph_reader, request_json

MAX_ENCODED = 4 * ((MAX_CIPHERTEXT + 2) // 3)


def collect_job(env, *, directory=False):
    if 'TF_HANDOFF_IDENTITY' in env or 'GH_TOKEN' in env:
        raise ValueError('Unexpected issue authorization in audit job')
    handoff_identity(env)
    if directory:
        get = graph_reader(env, include_directory_audit=True)
        known = pinned_catalog_app_ids()
        envelope = decode(collect_envelope(env, get, known))
        provisioned = scan_directory(get, datetime.fromisoformat(envelope['until']), run_scope(env), known)
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
        if sys.argv[1:] == ['collect-directory']:
            try:
                collect_job(os.environ, directory=True)
            except Exception:
                # Transport and parser errors can contain private provider data.
                raise SystemExit('Sign-in candidate review stopped.') from None
        elif sys.argv[1:] == ['collect']:
            collect_job(os.environ)
        elif sys.argv[1:] in (['issue'], ['issue-directory']):
            report_job(os.environ, os.environ.pop('TF_HANDOFF_IDENTITY'), directory=sys.argv[1] == 'issue-directory')
        else:
            raise ValueError('Unexpected candidate review command')
    except (KeyError, ValueError, TypeError, AttributeError, OSError):
        sys.exit('Sign-in candidate review stopped.')
