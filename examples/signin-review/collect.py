"""Inert workflow prototype: app-only Graph audit read and minimal candidate handoff."""

from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time
from urllib.parse import urlencode, urlsplit

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'scripts'))
from tokenforge_offline_catalog import OfflineCatalog, app_id_is_canonical, decode

HOST = 'graph.microsoft.com'
PATH = '/beta/auditLogs/signIns'
EVENTS = ('interactiveUser', 'nonInteractiveUser')
MODES = {'workflow_dispatch': 30, 'schedule': 2}
REPOSITORY = 'nathanmcnulty/TokenForge'
REPOSITORY_ID = '1402673320'
CATALOG_COMMIT = 'd9955781a7130793a5bba178a1b1aa1cf4003439'
WORKFLOW_REF = f'{REPOSITORY}/.github/workflows/signin-review-candidates.yml@refs/heads/main'
MAX_IDS = 1000


def utc(value):
    return value.astimezone(timezone.utc).isoformat(timespec='seconds').replace('+00:00', 'Z')


def run_scope(environment):
    if (environment.get('GITHUB_REPOSITORY'), environment.get('GITHUB_REPOSITORY_ID'), environment.get('GITHUB_REF')) != (
        REPOSITORY, REPOSITORY_ID, 'refs/heads/main'
    ):
        raise ValueError('Unexpected repository or ref')
    if environment.get('GITHUB_EVENT_NAME') not in MODES:
        raise ValueError('Unexpected workflow event')
    if not re.fullmatch(r'[1-9][0-9]{0,19}', environment.get('GITHUB_RUN_ID', '')):
        raise ValueError('Unexpected run identity')
    if not re.fullmatch(r'[1-9][0-9]{0,9}', environment.get('GITHUB_RUN_ATTEMPT', '')):
        raise ValueError('Unexpected run attempt')
    return MODES[environment['GITHUB_EVENT_NAME']]


def handoff_identity(environment, *, workflow_ref=WORKFLOW_REF):
    run_scope(environment)
    source = environment.get('GITHUB_SHA', '')
    if not re.fullmatch(r'[0-9a-f]{40}', source):
        raise ValueError('Unexpected source commit')
    if environment.get('GITHUB_WORKFLOW_REF') != workflow_ref:
        raise ValueError('Unexpected workflow source')
    return {
        'version': 2, 'repository': REPOSITORY, 'repositoryId': REPOSITORY_ID,
        'ref': environment['GITHUB_REF'], 'event': environment['GITHUB_EVENT_NAME'],
        'sourceCommit': source, 'workflowRef': workflow_ref, 'catalogCommit': CATALOG_COMMIT,
        'run': environment['GITHUB_RUN_ID'], 'attempt': environment['GITHUB_RUN_ATTEMPT'],
    }


def intervals(end, days):
    start = end - timedelta(days=days)
    while start < end:
        stop = min(end, start.replace(hour=0, minute=0, second=0, microsecond=0) + timedelta(days=1))
        yield start, stop
        start = stop


def valid_link(link):
    if not isinstance(link, str) or len(link) > 16384 or any(c.isspace() or ord(c) < 32 for c in link):
        return False
    try:
        url = urlsplit(link)
        return (url.scheme == 'https' and url.netloc.lower() in (HOST, f'{HOST}:443')
                and url.path.lower() == PATH.lower() and bool(url.query) and not url.fragment)
    except ValueError:
        return False


def az_json(arguments):
    for attempt in range(4):
        try:
            response = subprocess.run(['az', *arguments, '--only-show-errors', '-o', 'json'],
                                      capture_output=True, timeout=60, check=False)
        except subprocess.TimeoutExpired as exc:
            raise ValueError('Azure CLI read timed out') from exc
        if response.returncode == 0:
            if len(response.stdout) > 32 * 1024 * 1024:
                raise ValueError('Graph page exceeded the local parsing bound')
            return decode(response.stdout)
        if not re.search(rb'(?im)^ERROR:\s*(?:Too Many Requests|Service Unavailable)\b', response.stderr) or attempt == 3:
            raise ValueError('Azure CLI read failed or retry limit reached')
        # az rest does not expose Retry-After through its normal JSON output.
        time.sleep(30 * 2**attempt)


def assert_context(tenant, client, run=az_json):
    if not all(app_id_is_canonical(value) for value in (tenant, client)):
        raise ValueError('Expected application and tenant GUIDs')
    account = run(['account', 'show', '--query', '{tenant:tenantId,client:user.name,type:user.type,cloud:environmentName}'])
    expected = {'tenant': tenant, 'client': client, 'type': 'servicePrincipal', 'cloud': 'AzureCloud'}
    if account != expected:
        raise ValueError('Unexpected app-only Azure CLI context')
    endpoint = run(['cloud', 'show', '--name', 'AzureCloud', '--query', 'endpoints.microsoftGraphResourceId'])
    if endpoint not in (f'https://{HOST}', f'https://{HOST}/'):
        raise ValueError('Unexpected Graph origin')


def collect_window(get, start, end, category, catalog_ids):
    predicate = (f"createdDateTime ge {utc(start)} and createdDateTime le {utc(end)} "
                 f"and signInEventTypes/any(t: t eq '{category}')")
    url = f'https://{HOST}{PATH}?' + urlencode({'$top': 1000, '$filter': predicate})
    seen_links = set()
    found = set()
    for _ in range(100):
        if not valid_link(url) or url in seen_links:
            raise ValueError('Invalid or cyclic Graph continuation')
        seen_links.add(url)
        document = get(url)
        if not isinstance(document, dict) or not isinstance(document.get('value'), list) or len(document['value']) > 1000:
            raise ValueError('Unexpected Graph page')
        for item in document['value']:
            if not isinstance(item, dict) or item.get('signInEventTypes') != [category]:
                raise ValueError('Unexpected Graph event category')
            stamp = item.get('createdDateTime')
            if not isinstance(stamp, str) or not re.fullmatch(
                r'[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,7})?(?:Z|\+00:00)', stamp
            ):
                raise ValueError('Invalid Graph timestamp')
            observed = datetime.fromisoformat(stamp.replace('Z', '+00:00'))
            # Graph may emit 100 ns precision. Python truncates the seventh digit.
            sub_microsecond = re.search(r'\.[0-9]{6}[1-9](?:Z|\+00:00)$', stamp)
            if not start <= observed <= end or (observed == end and sub_microsecond):
                raise ValueError('Graph event fell outside its requested window')
            if observed == end:
                continue
            app = item.get('appId')
            if not isinstance(app, str) or not app_id_is_canonical(app.lower()):
                raise ValueError('Unreadable client application ID')
            if app.lower() not in catalog_ids:
                found.add(app.lower())
        if '@odata.nextLink' not in document:
            return found
        url = document['@odata.nextLink']
    raise ValueError('Graph window page limit reached')


def gather(get, end, days, catalog_ids):
    ids = set()
    for start, stop in intervals(end, days):
        for category in EVENTS:
            ids.update(collect_window(get, start, stop, category, catalog_ids))
            if len(ids) > MAX_IDS:
                raise ValueError('Candidate handoff would exceed its safe bound')
    return sorted(ids)


def main():
    days = run_scope(os.environ)
    assert_context(os.environ['TF_AUDIT_TENANT_ID'], os.environ['TF_AUDIT_CLIENT_ID'])
    identity = handoff_identity(os.environ)
    catalog = OfflineCatalog(ROOT, CATALOG_COMMIT)
    known = catalog.app_ids(catalog.partition(True)['Applications'], catalog.partition(False)['Applications'])
    end = datetime.now(timezone.utc).replace(microsecond=0)
    ids = gather(lambda url: az_json(['rest', '--method', 'get', '--url', url]), end, days, known)
    handoff = identity | {'since': utc(end - timedelta(days=days)), 'until': utc(end),
               'categories': list(EVENTS), 'coverage': 'requested-windows-terminal;retention-unknown', 'appIds': ids}
    with Path(os.environ['TF_CANDIDATE_FILE']).open('x') as output:
        json.dump(handoff, output, separators=(',', ':'))


if __name__ == '__main__':
    try:
        main()
    except (KeyError, ValueError, OSError, TypeError, AttributeError, subprocess.SubprocessError):
        sys.exit('Audit collection did not produce a candidate handoff.')
