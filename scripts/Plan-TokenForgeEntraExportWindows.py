#!/usr/bin/env python3
"""Plan disjoint Entra portal export windows and reconcile local status receipts."""

import argparse
from collections import Counter
from datetime import datetime, timedelta
import json
import os
from pathlib import Path
import re
import stat
import sys

from tokenforge_offline_catalog import unique


CATEGORIES = ('InteractiveUser', 'NonInteractiveUser', 'ServicePrincipal', 'ManagedIdentity')
STATES = ('PortalReportedSuccess', 'Incomplete', 'Unavailable')
UTC = re.compile(r'[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z')
MAX_RECEIPT_BYTES = 2 * 1024 * 1024


def instant(value):
    if not isinstance(value, str) or not UTC.fullmatch(value):
        raise ValueError('Expected a whole-second UTC timestamp')
    return datetime.fromisoformat(value)


def stamp(value):
    return value.isoformat(timespec='seconds').replace('+00:00', 'Z')


def receipt_entries(path):
    if not stat.S_ISREG(path.lstat().st_mode):
        raise ValueError('Expected a regular local receipt file')
    flags = os.O_RDONLY | getattr(os, 'O_NONBLOCK', 0) | getattr(os, 'O_NOFOLLOW', 0)
    with os.fdopen(os.open(path, flags), 'rb') as stream:
        if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
            raise ValueError('Expected a regular local receipt file')
        raw = stream.read(MAX_RECEIPT_BYTES + 1)
    if len(raw) > MAX_RECEIPT_BYTES:
        raise ValueError('Receipt file is too large')
    entries = json.loads(raw, object_pairs_hook=unique)
    if not isinstance(entries, list):
        raise ValueError('Expected an array of status receipts')
    return entries


def plan(since, until, hours, receipts):
    if not 1 <= hours <= 24 or not timedelta(0) < until - since <= timedelta(days=31):
        raise ValueError('Use an interval of up to 31 days and a window size of 1 to 24 hours')
    windows = {}
    step = timedelta(hours=hours)
    start = since
    while start < until:
        end = start + min(step, until - start)
        for category in CATEGORIES:
            windows[(category, stamp(start), stamp(end))] = Counter()
        start = end

    for entry in receipts:
        if not isinstance(entry, dict) or entry.keys() != {'ExportKind', 'Since', 'UntilExclusive', 'State'}:
            raise ValueError('Invalid status receipt fields')
        category = entry['ExportKind']
        start, end, state = instant(entry['Since']), instant(entry['UntilExclusive']), entry['State']
        if category not in CATEGORIES or state not in STATES or not since <= start < end <= until:
            raise ValueError('Receipt does not match the requested export plan')
        key = (category, stamp(start), stamp(end))
        if key not in windows:
            raise ValueError('Receipt is not an exact planned window')
        windows[key][state] += 1

    rows = []
    for (category, start, end), evidence in windows.items():
        if not evidence:
            status = 'Missing'
        elif len(evidence) > 1:
            status = 'ConflictingReceipts'
        else:
            status = next(iter(evidence))
        rows.append({'ExportKind': category, 'Since': start, 'UntilExclusive': end, 'Status': status,
                     'DuplicateReceiptsIgnored': sum(evidence.values()) - len(evidence)})
    return {
        'Format': 'TokenForgeEntraExportWindowLedger', 'SchemaVersion': 1,
        'Since': stamp(since), 'UntilExclusive': stamp(until), 'WindowHours': hours, 'Windows': rows,
        'SourceWindowCoverage': 'Unknown', 'TenantHistoryComplete': False,
        'StatusBasis': 'OperatorReported',
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--since', type=instant, required=True)
    parser.add_argument('--until', type=instant, required=True)
    parser.add_argument('--window-hours', type=int, default=24)
    parser.add_argument('--receipts', type=Path)
    args = parser.parse_args()
    output = plan(args.since, args.until, args.window_hours, receipt_entries(args.receipts) if args.receipts else [])
    print(json.dumps(output, indent=2, sort_keys=True))


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, TypeError, RecursionError):
        sys.exit('Entra export plan refused: invalid interval or local status receipts.')
