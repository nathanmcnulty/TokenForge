"""Inert production candidate for separated audit-reader and issue-writer jobs."""

import base64
import json
import os
from pathlib import Path
import re
import sys

from candidate_metadata import classify_principal, principal_url
from collect import GRAPH_EVENTS, REPOSITORY, collect_envelope, decode, handoff_identity
from handoff import MAX_CIPHERTEXT, open_envelope, seal
from report import report
from workload_http import HTTPFailure, graph_reader, request_json

MAX_ENCODED = 4 * ((MAX_CIPHERTEXT + 2) // 3)


def collect_job(env):
    if 'TF_HANDOFF_IDENTITY' in env or 'GH_TOKEN' in env:
        raise ValueError('Unexpected issue authorization in audit job')
    handoff_identity(env)
    get = graph_reader(env)
    envelope = decode(collect_envelope(env, get))
    labels = {}
    for app in envelope['appIds']:
        try:
            principal = get(principal_url(app))
        except HTTPFailure as error:
            if error.status != 404:
                raise
            principal = None
        label = classify_principal(app, env['TF_AUDIT_TENANT_ID'], principal, 'sign-in')
        if label is not None:
            labels[app] = label
    envelope.update(appIds=sorted(labels), labels=labels)
    raw = json.dumps(envelope, separators=(',', ':')).encode()
    ciphertext = seal(raw, env, env['TF_HANDOFF_RECIPIENT'], categories=GRAPH_EVENTS, labeled=True)
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


def report_job(env, identity, api=issue_call):
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
    raw = open_envelope(ciphertext, env, identity, categories=GRAPH_EVENTS, labeled=True)
    report(env, raw, api, categories=GRAPH_EVENTS, labeled=True)


if __name__ == '__main__':
    try:
        if os.environ.get('GITHUB_EVENT_NAME') != 'workflow_dispatch':
            raise ValueError('The initial activation permits manual runs only')
        if sys.argv[1:] == ['collect']:
            collect_job(os.environ)
        elif sys.argv[1:] == ['issue']:
            report_job(os.environ, os.environ.pop('TF_HANDOFF_IDENTITY'))
        else:
            raise ValueError('Unexpected candidate review command')
    except (KeyError, ValueError, TypeError, AttributeError, OSError):
        sys.exit('Sign-in candidate review stopped.')
