"""Local review prototype for validated candidate input and an exact issue queue."""

from datetime import datetime, timedelta
import json
import re

from candidate_metadata import valid_labels
from collect import EVENTS, MAX_IDS, REPOSITORY, WORKFLOW_REF, app_id_is_canonical, decode, handoff_identity, run_scope

OWNER_ID = 6653432
ISSUE_MARKER = '<!-- tokenforge-signin-review:v2 -->'
LABELED_MARKER = '<!-- tokenforge-signin-review:v3 -->'


def valid_ids(ids):
    if (not isinstance(ids, list) or len(ids) > MAX_IDS or
            any(not app_id_is_canonical(app) for app in ids) or ids != sorted(set(ids))):
        raise ValueError('Invalid candidate list')
    return set(ids)


def utc(value):
    if not isinstance(value, str) or not re.fullmatch(r'[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z', value):
        raise ValueError('Unexpected window timestamp')
    return datetime.fromisoformat(value)


def validate_handoff(raw, env, *, workflow_ref=WORKFLOW_REF, categories=EVENTS, labeled=False):
    days = run_scope(env)
    if len(raw) > 65536:
        raise ValueError('Invalid handoff size')
    expected = handoff_identity(env, workflow_ref=workflow_ref)
    value = decode(raw)
    keys = expected.keys() | {'since', 'until', 'categories', 'coverage', 'appIds'}
    if labeled:
        keys.add('labels')
    if not isinstance(value, dict) or value.keys() != keys:
        raise ValueError('Unexpected handoff shape')
    if (type(value['version']) is not int or any(value[k] != v for k, v in expected.items()) or
            value['categories'] != list(categories) or
            value['coverage'] != 'requested-windows-terminal;retention-unknown' or
            utc(value['until']) - utc(value['since']) != timedelta(days=days)):
        raise ValueError('Unexpected handoff evidence')
    ids = valid_ids(value['appIds'])
    if not labeled:
        return ids
    labels = value['labels']
    if not isinstance(labels, dict) or labels.keys() != ids or not all(valid_labels(v) for v in labels.values()):
        raise ValueError('Unexpected candidate labels')
    return labels


def body_for(ids, *, labeled=False):
    if labeled:
        return '\n'.join([LABELED_MARKER, *(f'- `{app}` | ' + ' | '.join(ids[app]) for app in sorted(ids))])
    return '\n'.join([ISSUE_MARKER, *(f'- `{app}`' for app in sorted(ids))])


def validate_issue(issue, number, node, *, labeled=False):
    if (not isinstance(issue, dict) or 'pull_request' in issue or issue.get('number') != number or
            issue.get('node_id') != node or issue.get('state') != 'open' or
            (issue.get('user') or {}).get('id') != OWNER_ID or not isinstance(issue.get('body'), str)):
        raise ValueError('The configured issue is outside the reviewed queue')
    body = issue['body']
    lines = body.splitlines()
    marker = LABELED_MARKER if labeled else ISSUE_MARKER
    if not lines or lines[0] != marker:
        raise ValueError('Unexpected review issue body')
    if labeled:
        ids = {}
        for line in lines[1:]:
            pieces = line.split(' | ')
            if len(pieces) != 4 or not re.fullmatch(r'- `[a-f0-9-]{36}`', pieces[0]) or not valid_labels(pieces[1:]):
                raise ValueError('Unexpected review issue labels')
            ids[pieces[0][3:-1]] = pieces[1:]
        valid_ids(list(ids))
    else:
        if any(not re.fullmatch(r'- `[a-f0-9-]{36}`', line) for line in lines[1:]):
            raise ValueError('Unexpected review issue body')
        ids = valid_ids([line[3:-1] for line in lines[1:]])
    if body_for(ids, labeled=labeled) != body:
        raise ValueError('Unexpected review issue format')
    return ids


def report(env, raw, api, *, workflow_ref=WORKFLOW_REF, categories=EVENTS, labeled=False):
    """Future issue-only job entry point; the transport is supplied by its caller."""
    number = env['TF_REVIEW_ISSUE']
    node = env['TF_REVIEW_ISSUE_NODE']
    if not re.fullmatch(r'[1-9][0-9]{0,9}', number) or not re.fullmatch(r'[A-Za-z0-9_=-]{3,128}', node):
        raise ValueError('Expected one configured issue identity')
    candidates = validate_handoff(raw, env, workflow_ref=workflow_ref, categories=categories, labeled=labeled)
    if not candidates:
        return
    target = f'repos/{REPOSITORY}/issues/{number}'
    existing = validate_issue(api(target), int(number), node, labeled=labeled)
    updated = candidates | existing
    if updated == existing:
        return
    if len(updated) > MAX_IDS:
        raise ValueError('Issue queue size limit reached')
    queue_body = body_for(updated, labeled=labeled)
    if len(queue_body.encode('utf-8')) > 65536:
        raise ValueError('Issue queue body exceeds its bound')
    body = json.dumps({'body': queue_body}).encode()
    receipt = api('--method', 'PATCH', target, '--input', '-', body=body)
    if validate_issue(receipt, int(number), node, labeled=labeled) != updated:
        raise ValueError('Issue update outcome uncertain')
