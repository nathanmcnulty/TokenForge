#!/usr/bin/env python3
"""Assemble local sign-in gap reports. Coverage describes inputs, never tenant history."""

import argparse
from collections import Counter
from datetime import datetime
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys

from tokenforge_offline_catalog import OfflineCatalog, app_id_is_canonical, decode


TYPES = {
    'v1.0': ('GraphV1IsInteractive', {'interactiveUser', 'nonInteractiveUser'}),
    'beta': ('GraphBetaEventTypes', {'interactiveUser', 'nonInteractiveUser', 'servicePrincipal', 'managedIdentity'}),
}
KINDS = {'AppId': 'UnusableAppIds', 'GraphResourceId': 'UnusableGraphResourceIds'}
STATUSES = {'Complete', 'PageLimit', 'InvalidNextLink', 'PaginationLoop', 'FixtureUnavailable',
            'InvalidPage', 'MalformedEvents'}
SOURCES = {'LocalPageReplay', 'LocalSnapshot', 'InMemorySnapshot'}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def instant(value):
    # PowerShell emits seven fractional digits. Preserve the last digit for exact boundary ordering.
    match = re.fullmatch(r'(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d)(?:\.(\d{1,7}))?(?:Z|\+00:00)', value)
    require(match is not None, 'Expected a UTC timestamp')
    try:
        datetime.fromisoformat(match[1])
    except ValueError:
        raise ValueError('Invalid UTC calendar timestamp') from None
    return f'{match[1]}.{(match[2] or "").ljust(7, "0")}Z'


def count(value):
    require(type(value) is int and 0 <= value <= 500000, 'Invalid aggregate count')
    return value


def validated_report(report, commit, version, known, since, until):
    shape, event_types = TYPES[version]
    require(report.get('Format') == 'TokenForgeSignInCatalogGaps' and
            type(report.get('SchemaVersion')) is int and report['SchemaVersion'] == 1 and
            report.get('CatalogCommit') == commit and report.get('GraphVersion') == version and
            report.get('InputEventShape') == shape and report.get('Source') in SOURCES and
            report.get('ActualAudience') == 'UnknownFromSignInLogs' and
            report.get('SourceWindowCoverage') == 'Unknown' and
            report.get('TenantHistoryComplete') is False and type(report.get('ReplayComplete')) is bool,
            'Report format, catalog pin, event shape, or coverage is incompatible')
    start, end = instant(report['Since']), instant(report['UntilExclusive'])
    require(since <= start < end <= until, 'Report interval is outside the requested bounds')

    windows = report['Windows']
    require(isinstance(windows, list) and 1 <= len(windows) <= 31, 'Invalid replay windows')
    require(report['Source'] == 'LocalPageReplay' or len(windows) == 1, 'Snapshot must have one replay window')
    rows = []
    capacity = Counter()
    previous_end = start
    pages = 0
    observed_events = 0
    duplicates = 0
    for window in windows:
        window_start, window_end = instant(window['Since']), instant(window['UntilExclusive'])
        status = window['Status']
        require(previous_end == window_start < window_end <= end and status in STATUSES,
                'Report windows must form one contiguous interval')
        window_pages = count(window['Pages'])
        unique_events = count(window['UniqueEvents'])
        malformed = count(window['MalformedEvents'])
        duplicate_events = count(window['DuplicateEvents'])
        pages += window_pages
        observed_events += unique_events
        duplicates += duplicate_events
        require(unique_events + malformed + duplicate_events + count(window['BoundaryEventsSkipped'])
                <= 1000 * window_pages, 'Replay window counts exceed page capacity')
        require(status != 'Complete' or (window_pages > 0 and malformed == 0), 'Invalid complete replay window')
        for kind, field in KINDS.items():
            unusable = count(window[field])
            require(unusable <= unique_events, 'Unusable identifiers exceed observed events')
            capacity[kind] += unique_events - unusable
        rows.append((window_start, window_end, status))
        previous_end = window_end
    require(previous_end == end and pages <= 500, 'Replay windows do not match the report interval')
    require(report['ReplayComplete'] == all(row[2] == 'Complete' for row in rows), 'Inconsistent replay completeness')

    candidates = {}
    totals = Counter()
    require(isinstance(report['Candidates'], list), 'Invalid candidate rows')
    for row in report['Candidates']:
        kind, identifier = row['IdentifierKind'], row['Identifier']
        require(kind in KINDS and app_id_is_canonical(identifier) and identifier not in known and
                row['Disposition'] == 'Pending' and (kind, identifier) not in candidates,
                'Invalid, known, or duplicate candidate')
        first, last = instant(row['FirstObservedAt']), instant(row['LastObservedAt'])
        n = count(row['Count'])
        require(start <= first <= last < end and n > 0 and (n != 1 or first == last),
                'Candidate time or count is incompatible with its report')
        events = row['EventTypeCounts']
        require(isinstance(events, dict) and events and events.keys() <= event_types and
                all(0 < count(x) <= n for x in events.values()) and sum(events.values()) >= n and
                (version == 'beta' or sum(events.values()) == n), 'Invalid candidate event counts')
        candidates[kind, identifier] = (first, last, n, Counter(events))
        totals[kind] += n
    require(all(totals[kind] <= capacity[kind] for kind in KINDS), 'Candidate counts exceed observed events')
    return {'start': start, 'end': end, 'windows': rows, 'candidates': candidates,
            'source': report['Source'], 'complete': report['ReplayComplete'],
            'pages': pages, 'observed_events': observed_events, 'duplicates': duplicates}


def assemble(documents, commit, version, known, since, until):
    reports = {}
    duplicates = Counter()
    for document in documents:
        fingerprint = hashlib.sha256(json.dumps(document, sort_keys=True, ensure_ascii=True,
                                                 separators=(',', ':')).encode()).hexdigest()
        if fingerprint not in reports:
            reports[fingerprint] = validated_report(document, commit, version, known, since, until)
        else:
            duplicates[fingerprint] += 1

    # Exclude every report in an overlap, including its nonoverlapping tails. Its aggregate is indivisible.
    ordered = sorted(reports, key=lambda key: (reports[key]['start'], reports[key]['end'], key))
    conflicts = set()
    previous = None
    for key in ordered:
        report = reports[key]
        if previous and report['start'] < reports[previous]['end']:
            conflicts.update((previous, key))
        if previous is None or report['end'] > reports[previous]['end']:
            previous = key

    inputs = []
    totals = {}
    boundaries = {since, until}
    for key in ordered:
        report = reports[key]
        boundaries.update(point for start, end, _ in report['windows'] for point in (start, end))
        inputs.append({'ReportSha256': key, 'Since': report['start'], 'UntilExclusive': report['end'],
                       'Source': report['source'], 'ReplayComplete': report['complete'],
                       'Pages': report['pages'], 'UniqueEvents': report['observed_events'],
                       'DuplicateEvents': report['duplicates'], 'DuplicateCopiesIgnored': duplicates[key],
                       'Included': key not in conflicts})
        if key in conflicts:
            continue
        for identity, (first, last, n, events) in report['candidates'].items():
            if identity in totals:
                old_first, old_last, old_n, old_events = totals[identity]
                first, last, n, events = min(first, old_first), max(last, old_last), n + old_n, events + old_events
            totals[identity] = first, last, n, events

    points = sorted(boundaries)
    coverage = []
    for start, end in zip(points, points[1:]):
        active = [(key, status) for key in ordered for low, high, status in reports[key]['windows']
                  if low <= start < high]
        if not active:
            status = 'Missing'
        elif len(active) > 1:
            status = 'OverlappingReports'
        elif active[0][0] in conflicts:
            status = 'ExcludedOverlap'
        else:
            status = 'ReplayComplete' if active[0][1] == 'Complete' else 'ReplayIncomplete'
        coverage.append({'Since': start, 'UntilExclusive': end, 'Status': status,
                         'Inputs': [{'ReportSha256': key, 'WindowStatus': window_status}
                                    for key, window_status in active]})

    candidates = [{'IdentifierKind': kind, 'Identifier': identifier, 'Disposition': 'Pending',
                   'Count': n, 'FirstObservedAt': first, 'LastObservedAt': last, 'EventTypeCounts': dict(events)}
                  for (kind, identifier), (first, last, n, events) in sorted(totals.items())]
    return {'Format': 'TokenForgeSignInCatalogGapAssembly', 'SchemaVersion': 1,
            'CatalogCommit': commit, 'GraphVersion': version, 'Since': since, 'UntilExclusive': until,
            'InputCoverageComplete': all(row['Status'] == 'ReplayComplete' for row in coverage),
            'SourceWindowCoverage': 'Unknown', 'TenantHistoryComplete': False,
            'ActualAudience': 'UnknownFromSignInLogs', 'Inputs': inputs, 'Windows': coverage, 'Candidates': candidates}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--catalog-repo', type=Path, required=True)
    parser.add_argument('--catalog-commit', required=True)
    parser.add_argument('--since', required=True)
    parser.add_argument('--until', required=True)
    parser.add_argument('--graph-version', choices=TYPES, default='v1.0')
    parser.add_argument('reports', type=Path, nargs='*')
    args = parser.parse_args()
    since, until = instant(args.since), instant(args.until)
    require(since < until and len(args.reports) <= 128, 'Choose an ordered interval and at most 128 reports')
    catalog = OfflineCatalog(args.catalog_repo, args.catalog_commit)
    known = catalog.app_ids(catalog.partition(True)['Applications'], catalog.partition(False)['Applications'])

    def read_reports():
        remaining = 64 * 1024 * 1024
        for path in args.reports:
            limit = min(8 * 1024 * 1024, remaining)
            with path.open('rb') as stream:
                raw = stream.read(limit + 1)
            require(len(raw) <= limit, 'Aggregate report size limit exceeded')
            remaining -= len(raw)
            yield decode(raw)

    result = assemble(read_reports(), args.catalog_commit, args.graph_version, known, since, until)
    print(json.dumps(result, sort_keys=True, indent=2))
    return 0 if result['InputCoverageComplete'] else 2


if __name__ == '__main__':
    try:
        sys.exit(main())
    except (OSError, ValueError, KeyError, TypeError, AttributeError, subprocess.SubprocessError):
        sys.exit('Assembly refused: a catalog pin, report, or requested interval is invalid or unavailable.')
