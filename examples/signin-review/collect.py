"""Inert workflow prototype: app-only Graph audit read and minimal candidate handoff."""

from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import re
import sys
from urllib.parse import urlencode, urlsplit

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'scripts'))
from tokenforge_offline_catalog import OfflineCatalog, app_id_is_canonical, decode

HOST = 'graph.microsoft.com'
PATH = '/beta/auditLogs/signIns'
EVENTS = ('interactiveUser', 'nonInteractiveUser')
GRAPH_EVENTS = EVENTS + ('servicePrincipal', 'managedIdentity')
MODES = {'workflow_dispatch': 30, 'schedule': 2}
REPOSITORY = 'nathanmcnulty/TokenForge'
REPOSITORY_ID = '1402673320'
CATALOG_COMMIT = 'ec3d72d75241c69bb9ca46528b32a1e7fd2a0b62'
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


def collect_window(get, start, end, category, catalog_ids, *, allow_unresolved=False):
    predicate = (f"createdDateTime ge {utc(start)} and createdDateTime le {utc(end)} "
                 f"and signInEventTypes/any(t: t eq '{category}')")
    url = f'https://{HOST}{PATH}?' + urlencode({'$top': 1000, '$filter': predicate})
    seen_links = set()
    found = set()
    coverage = 'Terminal page, no rows'
    unresolved = False
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
            coverage = 'Terminal page'
            app = item.get('appId')
            if not isinstance(app, str) or not app_id_is_canonical(app.lower()):
                if not allow_unresolved:
                    raise ValueError('Unreadable client application ID')
                unresolved = True
                continue
            if app.lower() not in catalog_ids:
                found.add(app.lower())
        if '@odata.nextLink' not in document:
            return found, 'Terminal page, unresolved AppIds' if unresolved else coverage
        url = document['@odata.nextLink']
    raise ValueError('Graph window page limit reached')


def http_status(error):
    status = getattr(error, 'status', None)
    return status if type(status) is int and 300 <= status < 600 else None


class IncompleteCategory(ValueError):
    pass


def gather(get, end, days, catalog_ids, *, coverage=None):
    ids = set()
    denied_categories = set()
    first_failure = None
    for start, stop in intervals(end, days):
        for category in GRAPH_EVENTS:
            if category in denied_categories:
                continue
            key = (category, start, stop)
            if coverage is not None:
                coverage[key] = 'Incomplete traversal'
            try:
                found, status = collect_window(
                    get, start, stop, category, catalog_ids, allow_unresolved=coverage is not None)
            except ValueError as exc:
                status = http_status(exc)
                suffix = f' (HTTP {status})' if status is not None else ''
                failure = IncompleteCategory(f'Graph coverage incomplete for {category}{suffix}.')
                if coverage is None:
                    raise failure from None
                coverage[key] += suffix
                if first_failure is None:
                    first_failure = failure
                if status in (401, 403):
                    denied_categories.add(category)
                continue
            if coverage is not None:
                coverage[key] = status
            ids.update(found)
            if len(ids) > MAX_IDS:
                raise ValueError('Candidate handoff would exceed its safe bound')
    if first_failure is not None:
        raise first_failure
    return sorted(ids)


def pinned_catalog_app_ids():
    catalog = OfflineCatalog(ROOT, CATALOG_COMMIT)
    return catalog.app_ids(catalog.partition(True)['Applications'], catalog.partition(False)['Applications'])


def collection_end():
    return datetime.now(timezone.utc).replace(microsecond=0)


def collect_envelope(environment, get, known=None, *, end=None, coverage=None):
    days = run_scope(environment)
    identity = handoff_identity(environment)
    if known is None:
        known = pinned_catalog_app_ids()
    end = end if end is not None else collection_end()
    ids = gather(get, end, days, known, coverage=coverage)
    envelope = identity | {'since': utc(end - timedelta(days=days)), 'until': utc(end),
                           'categories': list(GRAPH_EVENTS), 'coverage': 'requested-windows-terminal;retention-unknown', 'appIds': ids}
    return json.dumps(envelope, separators=(',', ':')).encode()
