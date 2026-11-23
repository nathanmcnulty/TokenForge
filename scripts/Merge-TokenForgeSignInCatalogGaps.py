#!/usr/bin/env python3
"""Assemble local sign-in gap reports. Coverage describes inputs, never tenant history."""

import argparse
from bisect import bisect_right
from collections import Counter
from datetime import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys

from tokenforge_offline_catalog import OfflineCatalog, app_id_is_canonical, unique


TYPES = {
    'v1.0': ('GraphV1IsInteractive', {'interactiveUser', 'nonInteractiveUser'}),
    'beta': ('GraphBetaEventTypes', {'interactiveUser', 'nonInteractiveUser', 'servicePrincipal', 'managedIdentity'}),
}
KINDS = {'AppId': 'UnusableAppIds', 'GraphResourceId': 'UnusableGraphResourceIds'}
STATUSES = {'Complete', 'PageLimit', 'InvalidNextLink', 'PaginationLoop', 'FixtureUnavailable',
            'InvalidPage', 'MalformedEvents'}
SOURCES = {'LocalPageReplay', 'LocalSnapshot', 'InMemorySnapshot'}
REPORT_FIELDS = {'Format', 'SchemaVersion', 'CatalogCommit', 'Source', 'GraphVersion', 'InputEventShape',
                 'ReplayComplete', 'SourceWindowCoverage', 'TenantHistoryComplete', 'ActualAudience',
                 'Since', 'UntilExclusive', 'Windows', 'Candidates'}
WINDOW_FIELDS = {'Since', 'UntilExclusive', 'Pages', 'UniqueEvents', 'DuplicateEvents', 'MalformedEvents',
                 'BoundaryEventsSkipped', 'UnusableAppIds', 'UnusableGraphResourceIds', 'Status'}
CANDIDATE_FIELDS = {'IdentifierKind', 'Identifier', 'Disposition', 'Count',
                    'FirstObservedAt', 'LastObservedAt', 'EventTypeCounts'}
TICKS_PER_DAY = 86400 * 10_000_000


def require(condition, message):
    if not condition:
        raise ValueError(message)


def require_fields(value, fields):
    require(isinstance(value, dict) and value.keys() == fields, 'Invalid aggregate object fields')


def reject_nonstandard_number(_):
    raise ValueError('Nonstandard JSON number')


def instant(value):
    # PowerShell emits seven fractional digits. Preserve the last digit for exact boundary ordering.
    match = re.fullmatch(r'(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d)(?:\.(\d{1,7}))?(?:Z|\+00:00)',
                         value, flags=re.ASCII)
    require(match is not None, 'Expected a UTC timestamp')
    try:
        datetime.fromisoformat(match[1])
    except ValueError:
        raise ValueError('Invalid UTC calendar timestamp') from None
    return f'{match[1]}.{(match[2] or "").ljust(7, "0")}Z'


def ticks(timestamp):
    whole = datetime.fromisoformat(timestamp[:19])
    seconds = whole.toordinal() * 86400 + whole.hour * 3600 + whole.minute * 60 + whole.second
    return seconds * 10_000_000 + int(timestamp[20:27])


def count(value):
    require(type(value) is int and 0 <= value <= 500000, 'Invalid aggregate count')
    return value


def validated_report(report, commit, version, known, since, until):
    require_fields(report, REPORT_FIELDS)
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
    end_ticks = ticks(end)
    require(end_ticks - ticks(start) <= 31 * TICKS_PER_DAY, 'A replay report is limited to 31 days')

    windows = report['Windows']
    require(isinstance(windows, list) and 1 <= len(windows) <= 31, 'Invalid replay windows')
    require(report['Source'] == 'LocalPageReplay' or len(windows) == 1, 'Snapshot must have one replay window')
    rows = []
    canonical_windows = []
    available = {kind: [] for kind in KINDS}
    previous_end = start
    pages = 0
    observed_events = 0
    duplicates = 0
    for window in windows:
        require_fields(window, WINDOW_FIELDS)
        window_start, window_end = instant(window['Since']), instant(window['UntilExclusive'])
        status = window['Status']
        require(previous_end == window_start < window_end <= end and status in STATUSES,
                'Report windows must form one contiguous interval')
        if report['Source'] == 'LocalPageReplay':
            start_ticks = ticks(window_start)
            require(ticks(window_end) - start_ticks == min(TICKS_PER_DAY, end_ticks - start_ticks),
                    'Page replay must use one-day slices with a shorter final window allowed')
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
            available[kind].append(unique_events - unusable)
        rows.append((window_start, window_end, status))
        canonical_windows.append({**window, 'Since': window_start, 'UntilExclusive': window_end})
        previous_end = window_end
    page_limit = 500 if report['Source'] == 'LocalPageReplay' else 1
    require(previous_end == end and pages <= page_limit, 'Replay windows or page count do not match the report source')
    require(report['ReplayComplete'] == all(row[2] == 'Complete' for row in rows), 'Inconsistent replay completeness')

    candidates = {}
    canonical_candidates = {}
    obligations = {kind: [] for kind in KINDS}
    starts = [row[0] for row in rows]
    require(isinstance(report['Candidates'], list), 'Invalid candidate rows')
    for row in report['Candidates']:
        require_fields(row, CANDIDATE_FIELDS)
        kind, identifier = row['IdentifierKind'], row['Identifier']
        require(kind in KINDS and app_id_is_canonical(identifier) and identifier not in known and
                row['Disposition'] == 'Pending' and (kind, identifier) not in candidates,
                'Invalid, known, or duplicate candidate')
        first, last = instant(row['FirstObservedAt']), instant(row['LastObservedAt'])
        n = count(row['Count'])
        require(start <= first <= last < end and n > 0 and (n != 1 or first == last),
                'Candidate time or count is incompatible with its report')
        first_window = bisect_right(starts, first) - 1
        last_window = bisect_right(starts, last) - 1
        if first_window == last_window:
            available[kind][first_window] -= n
        else:
            available[kind][first_window] -= 1
            available[kind][last_window] -= 1
            obligations[kind].append((last_window, first_window, n - 2))
        events = row['EventTypeCounts']
        require(isinstance(events, dict) and events and events.keys() <= event_types and
                all(0 < count(x) <= n for x in events.values()) and sum(events.values()) >= n and
                (version == 'beta' or sum(events.values()) == n), 'Invalid candidate event counts')
        candidates[kind, identifier] = (first, last, n, Counter(events))
        canonical_candidates[kind, identifier] = {**row, 'FirstObservedAt': first, 'LastObservedAt': last}
    for kind in KINDS:
        capacity = available[kind]
        require(all(n >= 0 for n in capacity), 'Candidate endpoints exceed observations in a window')
        # Earliest-deadline allocation checks feasibility without guessing where events actually occurred.
        for deadline, release, remaining in sorted(obligations[kind]):
            for index in range(release, deadline + 1):
                taken = min(remaining, capacity[index])
                capacity[index] -= taken
                remaining -= taken
                if not remaining:
                    break
            require(remaining == 0, 'Candidate counts exceed observations between their endpoints')
    canonical = {**report, 'Since': start, 'UntilExclusive': end, 'Windows': canonical_windows,
                 'Candidates': [canonical_candidates[key] for key in sorted(canonical_candidates)]}
    fingerprint = hashlib.sha256(json.dumps(canonical, sort_keys=True, ensure_ascii=True, allow_nan=False,
                                            separators=(',', ':')).encode()).hexdigest()
    return fingerprint, {'start': start, 'end': end, 'windows': rows, 'candidates': candidates,
                         'source': report['Source'], 'complete': report['ReplayComplete'],
                         'pages': pages, 'observed_events': observed_events, 'duplicates': duplicates}


def assemble(documents, commit, version, known, since, until):
    reports = {}
    duplicates = Counter()
    for document in documents:
        fingerprint, report = validated_report(document, commit, version, known, since, until)
        if fingerprint not in reports:
            reports[fingerprint] = report
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
            require(stat.S_ISREG(path.lstat().st_mode), 'Aggregate input must be a regular file')
            flags = os.O_RDONLY | getattr(os, 'O_NONBLOCK', 0) | getattr(os, 'O_NOFOLLOW', 0)
            with os.fdopen(os.open(path, flags), 'rb') as stream:
                require(stat.S_ISREG(os.fstat(stream.fileno()).st_mode), 'Aggregate input must be a regular file')
                raw = stream.read(limit + 1)
            require(len(raw) <= limit, 'Aggregate report size limit exceeded')
            remaining -= len(raw)
            yield json.loads(raw, object_pairs_hook=unique, parse_constant=reject_nonstandard_number)

    result = assemble(read_reports(), args.catalog_commit, args.graph_version, known, since, until)
    print(json.dumps(result, sort_keys=True, indent=2))
    return 0 if result['InputCoverageComplete'] else 2


if __name__ == '__main__':
    try:
        sys.exit(main())
    except (OSError, ValueError, KeyError, TypeError, AttributeError, RecursionError, subprocess.SubprocessError):
        sys.exit('Assembly refused: a catalog pin, report, or requested interval is invalid or unavailable.')
