#!/usr/bin/env python3
"""Compare a local standard Entra sign-in CSV with both pinned catalog partitions."""

import argparse
from collections import Counter
import csv
import json
import os
from pathlib import Path
import stat
import subprocess
import sys

from tokenforge_entra_csv import (COLUMNS, EXPORT_KINDS, EXPORT_STATES, PORTAL_ROW_CAP, incomplete_reasons,
                                 instant, resource_match)
from tokenforge_offline_catalog import OfflineCatalog, app_id_is_canonical


LOCAL_BYTE_LIMIT = 256 * 1024 * 1024


def read_counts(path, since, until):
    if not stat.S_ISREG(path.lstat().st_mode):
        raise ValueError('Expected a regular local CSV file')
    flags = os.O_RDONLY | getattr(os, 'O_NONBLOCK', 0) | getattr(os, 'O_NOFOLLOW', 0)
    app_counts, resource_counts = Counter(), Counter()
    totals = dict(CsvRows=0, RowsInWindow=0, UpperBoundaryRowsSkipped=0, RowsOutsideWindow=0,
                  MalformedDates=0, UnusableApplicationIds=0, UnusableResourceIds=0)
    with os.fdopen(os.open(path, flags), 'r', encoding='utf-8-sig', newline='') as stream:
        before = os.fstat(stream.fileno())
        if not stat.S_ISREG(before.st_mode) or before.st_size > LOCAL_BYTE_LIMIT:
            raise ValueError('Expected a bounded regular local CSV file')
        rows = csv.reader(stream, strict=True)
        header = [field.strip().casefold() for field in next(rows, [])]
        columns = [field.casefold() for field in COLUMNS]
        if any(header.count(field) != 1 for field in columns):
            raise ValueError('Missing or ambiguous identifier/date columns')
        date_col, app_col, resource_col = [header.index(field) for field in columns]

        for row in rows:
            totals['CsvRows'] += 1
            if totals['CsvRows'] > PORTAL_ROW_CAP or len(row) != len(header):
                raise ValueError('CSV has an unexpected row count or width')
            try:
                stamp = instant(row[date_col])
            except ValueError:
                totals['MalformedDates'] += 1
                continue
            if stamp == until:
                totals['UpperBoundaryRowsSkipped'] += 1
                continue
            if not since <= stamp < until:
                totals['RowsOutsideWindow'] += 1
                continue
            totals['RowsInWindow'] += 1
            app = row[app_col].strip().lower()
            resource = row[resource_col].strip().lower()
            if app_id_is_canonical(app):
                app_counts[app] += 1
            else:
                totals['UnusableApplicationIds'] += 1
            if app_id_is_canonical(resource):
                resource_counts[resource] += 1
            else:
                totals['UnusableResourceIds'] += 1

        after = os.fstat(stream.fileno())
        if (after.st_size, after.st_mtime_ns, after.st_ctime_ns) != (before.st_size, before.st_mtime_ns, before.st_ctime_ns):
            raise ValueError('CSV changed during the read')
    return totals, app_counts, resource_counts


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--catalog-repo', type=Path, required=True)
    parser.add_argument('--catalog-commit', required=True)
    parser.add_argument('--since', required=True)
    parser.add_argument('--until', required=True)
    parser.add_argument('--export-kind', choices=EXPORT_KINDS, required=True)
    parser.add_argument('--export-status', choices=EXPORT_STATES, default='NotRecorded',
                        help='Operator-recorded portal status, without claiming coverage')
    parser.add_argument('csv', type=Path)
    args = parser.parse_args()
    since, until = instant(args.since, require_zone=True), instant(args.until, require_zone=True)
    if since >= until:
        raise ValueError('Expected an ordered UTC interval')
    catalog = OfflineCatalog(args.catalog_repo, args.catalog_commit)
    verified, nonverified = [catalog.partition(part)['Applications'] for part in (True, False)]
    known = catalog.app_ids(verified, nonverified)
    totals, apps, resources = read_counts(args.csv, since, until)

    incomplete = incomplete_reasons(totals, args.export_status)

    result = {
        'Format': 'TokenForgeEntraSignInCsvGapReport', 'SchemaVersion': 1, 'CatalogCommit': args.catalog_commit,
        'Since': since, 'UntilExclusive': until, 'ExportKind': args.export_kind,
        'OperatorReportedExportStatus': args.export_status, 'DocumentedRowCap': PORTAL_ROW_CAP,
        'Counts': totals, 'IncompleteReasons': incomplete,
        'SourceWindowCoverage': 'Unknown', 'TenantHistoryComplete': False,
        'ActualAudience': 'UnknownFromEntraSignInExport', 'SignInOutcome': 'NotEvaluated',
        'Candidates': [{'AppId': key, 'Disposition': 'Pending', 'CsvRows': apps[key]}
                       for key in sorted(apps.keys() - known)],
        'ObservedResources': [{'SourceColumn': 'Resource ID', 'Identifier': key, 'CsvRows': resources[key],
                               'ExactCatalogAppIdMatch': resource_match(key, verified, nonverified)} for key in sorted(resources)],
    }
    print(json.dumps(result, sort_keys=True, indent=2))
    return 2 if incomplete else 0


if __name__ == '__main__':
    try:
        sys.exit(main())
    except (OSError, ValueError, csv.Error, KeyError, TypeError, AttributeError, subprocess.SubprocessError):
        sys.exit('Entra sign-in CSV refused: invalid or unavailable input or pinned catalog.')
