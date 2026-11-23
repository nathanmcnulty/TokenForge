"""Bounded directory-audit shape checks and attended normalized replay."""

from collections import Counter
from datetime import datetime
from pathlib import Path
import os
import re
import stat
import sys
from urllib.parse import urlencode, urlsplit

from candidate_metadata import audience_label
from collect import HOST, MAX_IDS, OfflineCatalog, app_id_is_canonical, decode, intervals, utc

DIRECTORY_PATH = '/v1.0/auditLogs/directoryAudits'
ACTIVITY = 'Add service principal'
MAX_REPLAY_BYTES = 1024 * 1024


def valid_directory_link(link):
    if not isinstance(link, str) or len(link) > 16384 or any(c.isspace() or ord(c) < 32 for c in link):
        return False
    try:
        uri = urlsplit(link)
        return (uri.scheme == 'https' and uri.netloc.lower() in (HOST, f'{HOST}:443')
                and uri.path.lower() == DIRECTORY_PATH.lower() and bool(uri.query) and not uri.fragment)
    except ValueError:
        return False


def within(event, start, stop):
    if not isinstance(event, dict) or event.get('activityDisplayName') != ACTIVITY:
        raise ValueError('Unexpected directory audit event')
    stamp = event.get('activityDateTime')
    if not isinstance(stamp, str) or not re.fullmatch(
        r'[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,7})?(?:Z|\+00:00)', stamp
    ):
        raise ValueError('Unreadable directory audit UTC timestamp')
    observed = datetime.fromisoformat(stamp)
    beyond_inclusive_end = observed == stop and re.search(r'\.[0-9]{6}[1-9](?:Z|\+00:00)$', stamp)
    if not start <= observed <= stop or beyond_inclusive_end:
        raise ValueError('Directory audit event outside requested window')
    return observed < stop


def scan_window(get, start, stop):
    """Read successful service-principal provisioning and validated scalar AppIds."""
    predicate = f"activityDisplayName eq '{ACTIVITY}' and activityDateTime ge {utc(start)} and activityDateTime le {utc(stop)}"
    url = f'https://{HOST}{DIRECTORY_PATH}?' + urlencode({'$top': 1000, '$filter': predicate})
    seen = set()
    counts = Counter()
    app_ids = set()
    for _ in range(100):
        if not valid_directory_link(url) or url in seen:
            raise ValueError('Invalid directory audit continuation')
        seen.add(url)
        page = get(url)
        if not isinstance(page, dict) or not isinstance(page.get('value'), list) or len(page['value']) > 1000:
            raise ValueError('Unreadable directory audit page')
        for event in page['value']:
            if not within(event, start, stop):
                continue
            result = event.get('result')
            if result != 'success':
                counts['notSuccessful' if result in ('failure', 'timeout') else 'unknownResult'] += 1
                continue
            resources = event.get('targetResources')
            one_principal = isinstance(resources, list) and sum(
                isinstance(row, dict) and row.get('type') == 'ServicePrincipal' for row in resources
            ) == 1
            if not one_principal:
                counts['ambiguousPrincipalTarget'] += 1
            details = event.get('additionalDetails')
            matches = []
            if isinstance(details, list):
                for key, counter in (('ServicePrincipalProvisioningType', 'provisioningTypePresent'),
                                     ('AppOwnerOrganizationId', 'ownerCluePresent')):
                    if any(isinstance(item, dict) and item.get('key') == key for item in details):
                        counts[counter] += 1
                matches = [
                    item.get('value') for item in details if isinstance(item, dict)
                    and isinstance(item.get('key'), str) and item['key'].casefold() == 'appid'
                ]
            if (one_principal and len(matches) == 1 and isinstance(matches[0], str)
                    and app_id_is_canonical(matches[0].lower())):
                app_ids.add(matches[0].lower())
                counts['successfulTargetAppId'] += 1
                if len(app_ids) > MAX_IDS:
                    raise ValueError('Provisioning candidate bound exceeded')
            else:
                counts['successfulUnresolvedAppId'] += 1
        if '@odata.nextLink' not in page:
            return dict(sorted(counts.items())), app_ids
        url = page['@odata.nextLink']
    raise ValueError('Directory audit page limit reached')


def scan_directory(get, until, days):
    if type(days) is not int or not 1 <= days <= 31:
        raise ValueError('Unexpected directory audit window length')
    rows = []
    app_ids = set()
    for start, stop in intervals(until, days):
        counts, window_ids = scan_window(get, start, stop)
        rows.append({'since': utc(start), 'until': utc(stop), 'counts': counts})
        app_ids.update(window_ids)
        if len(app_ids) > MAX_IDS:
            raise ValueError('Provisioning candidate bound exceeded')
    return {'windows': rows, 'appIds': sorted(app_ids), 'appIdMapping': 'additionalDetails.AppId',
            'providerRetention': 'unknown'}


def normalize_replay(value, known, sign_ins=()):
    """Only accept already-minimized, caller-attested target AppId evidence."""
    if not isinstance(value, dict) or value.keys() != {'format', 'rows'} or value['format'] != 'TokenForgeAttendedTargetAppIdEvidenceV1':
        raise ValueError('Expected normalized attended target evidence')
    rows = value['rows']
    sign_ins = tuple(sign_ins)
    if not isinstance(rows, list) or len(rows) > 10000 or any(not app_id_is_canonical(app) for app in sign_ins):
        raise ValueError('Unexpected provisioning evidence scope')
    observations = {}
    for row in rows:
        if (not isinstance(row, dict) or row.keys() != {'targetAppId', 'audiences', 'localManagedIdentity'}
                or not app_id_is_canonical(row['targetAppId']) or not isinstance(row['audiences'], list)
                or any(not isinstance(audience, str) for audience in row['audiences'])
                or type(row['localManagedIdentity']) is not bool):
            raise ValueError('Unexpected normalized provisioning row')
        app = row['targetAppId']
        audiences, local_flags = observations.setdefault(app, ([], []))
        audiences.extend(row['audiences'] or [None])
        local_flags.append(row['localManagedIdentity'])
    existing_sign_ins = set(sign_ins)
    candidates = {}
    for app, (audiences, local_flags) in sorted(observations.items()):
        if app in known:
            continue
        label = audience_label(audiences)
        if label is None or (all(local_flags) and label == 'audience unknown'):
            continue
        source = 'sign-in and provisioning' if app in existing_sign_ins else 'provisioning'
        candidates[app] = [source, label, 'publisher unknown']
        if len(candidates) > MAX_IDS:
            raise ValueError('Provisioning candidate bound exceeded')
    return {'coverage': 'caller-provided evidence; provider retention unknown', 'candidates': candidates}


def main(args):
    if len(args) != 3:
        raise ValueError('Expected a normalized evidence file, a catalog repository and an exact commit')
    source = Path(args[0])
    fd = os.open(source, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as file:
        if not stat.S_ISREG(os.fstat(file.fileno()).st_mode):
            raise ValueError('Expected a regular evidence file')
        raw = file.read(MAX_REPLAY_BYTES + 1)
    if len(raw) > MAX_REPLAY_BYTES:
        raise ValueError('Provisioning evidence exceeds its bound')
    catalog = OfflineCatalog(Path(args[1]), args[2])
    known = catalog.app_ids(catalog.partition(True)['Applications'], catalog.partition(False)['Applications'])
    return normalize_replay(decode(raw), known)


if __name__ == '__main__':
    import json
    try:
        print(json.dumps(main(sys.argv[1:]), sort_keys=True))
    except (KeyError, TypeError, ValueError, OSError):
        sys.exit('Directory provisioning replay stopped.')
