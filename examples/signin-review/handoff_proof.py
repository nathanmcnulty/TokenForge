"""Inert synthetic workflow entry point. It has no live API transport."""

import base64
import binascii
import json
import os
from pathlib import Path
import sys

from collect import EVENTS, REPOSITORY, handoff_identity
from handoff import MAX_CIPHERTEXT, open_envelope, seal
from report import OWNER_ID, body_for, report

PROOF_REF = f'{REPOSITORY}/.github/workflows/signin-review-handoff-proof.yml@refs/heads/main'
KNOWN = '22222222-2222-4222-8222-222222222222'
CANDIDATE = '33333333-3333-4333-8333-333333333333'
MAX_ENCODED = 4 * ((MAX_CIPHERTEXT + 2) // 3)


def check_scope(env):
    if env.get('GITHUB_EVENT_NAME') != 'workflow_dispatch':
        raise ValueError('Unexpected proof event')
    return handoff_identity(env, workflow_ref=PROOF_REF)


def collect_fixture(env):
    context = check_scope(env)
    if 'TF_PROOF_AGE_IDENTITY' in env or 'TF_PROOF_CIPHERTEXT' in env:
        raise ValueError('Unexpected input in synthetic reader')
    raw = json.dumps(context | {
        'since': '2026-01-01T00:00:00Z', 'until': '2026-01-31T00:00:00Z',
        'categories': list(EVENTS), 'coverage': 'requested-windows-terminal;retention-unknown',
        'appIds': [KNOWN, CANDIDATE],
    }, separators=(',', ':')).encode()
    encrypted = seal(raw, env, env['TF_PROOF_AGE_RECIPIENT'], workflow_ref=PROOF_REF)
    with Path(env['GITHUB_OUTPUT']).open('a', encoding='ascii') as output:
        output.write('ciphertext=' + base64.b64encode(encrypted).decode('ascii') + '\n')


def prove_writer(env, identity):
    check_scope(env)
    encoded = env['TF_PROOF_CIPHERTEXT']
    if not 0 < len(encoded) <= MAX_ENCODED:
        raise ValueError('Unexpected proof ciphertext size')
    raw = open_envelope(base64.b64decode(encoded, validate=True), env, identity, workflow_ref=PROOF_REF)
    context = dict(env, TF_REVIEW_ISSUE='57', TF_REVIEW_ISSUE_NODE='I_synthetic')
    target = f'repos/{REPOSITORY}/issues/57'
    issue = {'number': 57, 'node_id': 'I_synthetic', 'state': 'open',
             'user': {'id': OWNER_ID}, 'body': body_for([KNOWN])}
    patched = False

    def fixture_api(*args, body=None):
        nonlocal patched
        if args == (target,) and body is None:
            return issue
        if args != ('--method', 'PATCH', target, '--input', '-') or patched:
            raise ValueError('Unexpected synthetic issue operation')
        expected = {'body': body_for([KNOWN, CANDIDATE])}
        if json.loads(body) != expected:
            raise ValueError('Unexpected synthetic issue body')
        issue.update(expected)
        patched = True
        return issue

    report(context, raw, fixture_api, workflow_ref=PROOF_REF)
    if not patched:
        raise ValueError('Synthetic issue proof did not exercise deduplication')
    report(context, raw, fixture_api, workflow_ref=PROOF_REF)


if __name__ == '__main__':
    try:
        if sys.argv[1:] == ['collect']:
            collect_fixture(os.environ)
        elif sys.argv[1:] == ['issue-proof']:
            prove_writer(os.environ, os.environ.pop('TF_PROOF_AGE_IDENTITY'))
            print('Synthetic handoff proof passed.')
        else:
            raise ValueError('Unexpected synthetic command')
    except (KeyError, ValueError, TypeError, OSError, binascii.Error):
        sys.exit('Synthetic handoff proof stopped.')
