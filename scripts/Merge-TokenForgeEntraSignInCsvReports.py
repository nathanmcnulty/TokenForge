#!/usr/bin/env python3
"""Reconcile local Entra CSV aggregate receipts without inferring provider coverage."""

import argparse
from collections import Counter, defaultdict
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import sys

from tokenforge_entra_csv import (EXPORT_KINDS, EXPORT_STATES, PORTAL_ROW_CAP, incomplete_reasons,
                                 instant, resource_match)
from tokenforge_offline_catalog import OfflineCatalog, app_id_is_canonical, unique


REPORT_FORMAT = 'TokenForgeEntraSignInCsvGapReport'
REPORT_FIELDS = {'Format', 'SchemaVersion', 'CatalogCommit', 'Since', 'UntilExclusive', 'ExportKind',
                 'OperatorReportedExportStatus', 'DocumentedRowCap', 'Counts', 'IncompleteReasons',
                 'SourceWindowCoverage', 'TenantHistoryComplete', 'ActualAudience', 'SignInOutcome',
                 'Candidates', 'ObservedResources'}
COUNT_FIELDS = {'CsvRows', 'RowsInWindow', 'UpperBoundaryRowsSkipped', 'RowsOutsideWindow',
                'MalformedDates', 'UnusableApplicationIds', 'UnusableResourceIds'}
NO_FILE_STATES = ('Incomplete', 'Unavailable')
MAX_FILE_BYTES = 8 * 1024 * 1024
MAX_BATCH_BYTES = 64 * 1024 * 1024
MAX_REPORTS = 128


@dataclass(frozen=True)
class Receipt:
    category: str
    since: str
    until: str
    status: str
    totals: dict[str, int]
    incomplete_reasons: list[str]
    apps: dict[str, int]
    resources: dict[str, int]


def require(condition, message):
    if not condition:
        raise ValueError(message)


def fields(value, names):
    require(isinstance(value, dict) and value.keys() == names, 'Unexpected aggregate fields')


def invalid_number(_):
    raise ValueError('Invalid JSON number')


def read_local(path, byte_limit):
    require(stat.S_ISREG(path.lstat().st_mode), 'Expected a regular file')
    flags = os.O_RDONLY | getattr(os, 'O_NONBLOCK', 0) | getattr(os, 'O_NOFOLLOW', 0)
    with os.fdopen(os.open(path, flags), 'rb') as stream:
        require(stat.S_ISREG(os.fstat(stream.fileno()).st_mode), 'Expected a regular file')
        raw = stream.read(byte_limit + 1)
    require(len(raw) <= byte_limit, 'Input exceeds byte limit')
    return raw, json.loads(raw, object_pairs_hook=unique, parse_constant=invalid_number)


def window(value, since, until):
    kind = value['ExportKind']
    low, high = [instant(value[key], require_zone=True) for key in ('Since', 'UntilExclusive')]
    require(kind in EXPORT_KINDS and since <= low < high <= until, 'Category or validation envelope mismatch')
    return kind, low, high


def identifier_counts(rows, verified, nonverified, resource):
    require(isinstance(rows, list), 'Expected a list of identifier counts')
    result = {}
    for row in rows:
        if resource:
            fields(row, {'SourceColumn', 'Identifier', 'CsvRows', 'ExactCatalogAppIdMatch'})
            key = row['Identifier']
            require(app_id_is_canonical(key) and row['SourceColumn'] == 'Resource ID' and
                    row['ExactCatalogAppIdMatch'] == resource_match(key, verified, nonverified), 'Invalid resource entry')
        else:
            fields(row, {'AppId', 'Disposition', 'CsvRows'})
            key = row['AppId']
            require(app_id_is_canonical(key) and key not in verified and key not in nonverified and
                    row['Disposition'] == 'Pending', 'Invalid application candidate')
        count = row['CsvRows']
        require(key not in result and type(count) is int and 0 < count <= PORTAL_ROW_CAP, 'Invalid identifier count')
        result[key] = count
    return result


def validate(report, commit, verified, nonverified, since, until):
    fields(report, REPORT_FIELDS)
    status = report['OperatorReportedExportStatus']
    require(report['Format'] == REPORT_FORMAT and type(report['SchemaVersion']) is int and report['SchemaVersion'] == 1 and
            report['CatalogCommit'] == commit and type(report['DocumentedRowCap']) is int and
            report['DocumentedRowCap'] == PORTAL_ROW_CAP and
            status in EXPORT_STATES and report['SourceWindowCoverage'] == 'Unknown' and
            report['TenantHistoryComplete'] is False and report['ActualAudience'] == 'UnknownFromEntraSignInExport' and
            report['SignInOutcome'] == 'NotEvaluated', 'Unrecognized CSV receipt provenance or coverage')
    kind, low, high = window(report, since, until)
    totals = report['Counts']
    fields(totals, COUNT_FIELDS)
    require(all(type(n) is int and 0 <= n <= PORTAL_ROW_CAP for n in totals.values()), 'Invalid row counts')
    in_window = totals['RowsInWindow']
    require(totals['CsvRows'] == in_window + totals['UpperBoundaryRowsSkipped'] + totals['RowsOutsideWindow'] +
            totals['MalformedDates'] and totals['UnusableApplicationIds'] <= in_window and
            totals['UnusableResourceIds'] <= in_window and report['IncompleteReasons'] == incomplete_reasons(totals, status),
            'Inconsistent counts or completeness flags')
    apps = identifier_counts(report['Candidates'], verified, nonverified, resource=False)
    resources = identifier_counts(report['ObservedResources'], verified, nonverified, resource=True)
    require(sum(apps.values()) <= in_window - totals['UnusableApplicationIds'] and
            sum(resources.values()) == in_window - totals['UnusableResourceIds'], 'Inconsistent identifier totals')
    # Only fully validated, aggregate fields participate in identity. JSON layout does not change duplicate detection.
    normalized = {**report, 'Since': low, 'UntilExclusive': high,
                  'Candidates': sorted(report['Candidates'], key=lambda row: row['AppId']),
                  'ObservedResources': sorted(report['ObservedResources'], key=lambda row: row['Identifier'])}
    identity = hashlib.sha256(json.dumps(normalized, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
    return identity, Receipt(kind, low, high, status, totals, report['IncompleteReasons'], apps, resources)


def no_file_receipts(path, since, until):
    if path is None:
        return Counter()
    _, entries = read_local(path, 2 * 1024 * 1024)
    require(isinstance(entries, list) and len(entries) <= 4096, 'Invalid no-file receipt list')
    result = Counter()
    for entry in entries:
        fields(entry, {'ExportKind', 'Since', 'UntilExclusive', 'State'})
        require(entry['State'] in NO_FILE_STATES, 'Only incomplete or unavailable no-file states are accepted')
        result[(*window(entry, since, until), entry['State'])] += 1
    return result


def record_ids(totals, counts, category):
    for identifier, count in counts.items():
        totals[identifier][category] += count


def merge(reports, duplicates, exact_hashes, no_file, catalog_commit, verified, nonverified, since, until):
    by_category = defaultdict(list)
    for key, receipt in reports.items():
        by_category[receipt.category].append((receipt.since, receipt.until, key))

    app_totals, resource_totals = defaultdict(Counter), defaultdict(Counter)
    inputs, ledger = [], []
    for category in EXPORT_KINDS:
        supplied = sorted(by_category[category])
        overlap = set()
        previous = None
        for low, high, key in supplied:
            if previous and low < previous[1]:
                overlap.update((previous[2], key))
            if previous is None or high > previous[1]:
                previous = (low, high, key)
        for low, high, key in supplied:
            receipt = reports[key]
            if key not in overlap:
                record_ids(app_totals, receipt.apps, category)
                record_ids(resource_totals, receipt.resources, category)
            inputs.append({'AggregateSha256': key, 'ExactInputSha256': sorted(exact_hashes[key]),
                           'ExportKind': category, 'Since': low, 'UntilExclusive': high,
                           'OperatorReportedExportStatus': receipt.status, 'Counts': receipt.totals,
                           'IncompleteReasons': receipt.incomplete_reasons, 'Included': key not in overlap,
                           'DuplicateCopiesIgnored': duplicates[key]})
        declared = sorted((low, high, status) for kind, low, high, status in no_file if kind == category)
        bounds = sorted({since, until} | {point for low, high, _ in supplied + declared for point in (low, high)})
        for low, high in zip(bounds, bounds[1:]):
            active = [key for start, end, key in supplied if start <= low < end]
            states = sorted({state for start, end, state in declared if start <= low < end})
            if len(active) > 1:
                status = 'OverlappingAggregates'
            elif active and active[0] in overlap:
                status = 'ExcludedOverlap'
            elif active:
                status = 'ParsedWithIssues' if reports[active[0]].incomplete_reasons else 'ParsedInput'
            else:
                status = 'NoAggregate' if states else 'Missing'
            ledger.append({'ExportKind': category, 'Since': low, 'UntilExclusive': high,
                           'Status': status, 'AggregateSha256': active, 'NoFileStates': states})

    def observations(counts):
        return [{'ExportKind': kind, 'CsvRows': counts[kind]} for kind in EXPORT_KINDS if kind in counts]

    return {
        'Format': 'TokenForgeEntraCsvAssembly', 'SchemaVersion': 1, 'CatalogCommit': catalog_commit,
        'Since': since, 'UntilExclusive': until, 'Source': 'LocalEntraPortalCsvAggregates',
        'SourceWindowCoverage': 'Unknown', 'TenantHistoryComplete': False,
        'ActualAudience': 'UnknownFromEntraSignInExport', 'CountUnit': 'CsvRows',
        'Inputs': inputs, 'Windows': ledger,
        'NoFileReceipts': [{'ExportKind': kind, 'Since': low, 'UntilExclusive': high, 'State': status,
                            'DuplicateCopiesIgnored': n - 1} for (kind, low, high, status), n in sorted(no_file.items())],
        'Candidates': [{'AppId': key, 'Disposition': 'Pending', 'Observations': observations(counts)}
                       for key, counts in sorted(app_totals.items())],
        'ObservedResources': [{'SourceColumn': 'Resource ID', 'Identifier': key,
                               'ExactCatalogAppIdMatch': resource_match(key, verified, nonverified),
                               'Observations': observations(counts)} for key, counts in sorted(resource_totals.items())],
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--catalog-repo', type=Path, required=True)
    parser.add_argument('--catalog-commit', required=True)
    parser.add_argument('--since', required=True)
    parser.add_argument('--until', required=True)
    parser.add_argument('--no-file-receipts', type=Path)
    parser.add_argument('reports', type=Path, nargs='*')
    args = parser.parse_args()
    since, until = [instant(value, require_zone=True) for value in (args.since, args.until)]
    require(since < until and len(args.reports) <= MAX_REPORTS, 'Invalid bounds or too many files')
    catalog = OfflineCatalog(args.catalog_repo, args.catalog_commit)
    verified, nonverified = [catalog.partition(part)['Applications'] for part in (True, False)]
    catalog.app_ids(verified, nonverified)

    reports, duplicates, exact_hashes = {}, Counter(), defaultdict(set)
    hashed_bytes = 0
    for path in args.reports:
        raw, report = read_local(path, min(MAX_FILE_BYTES, MAX_BATCH_BYTES - hashed_bytes))
        hashed_bytes += len(raw)
        identity, validated = validate(report, args.catalog_commit, verified, nonverified, since, until)
        exact_hashes[identity].add(hashlib.sha256(raw).hexdigest())
        if identity in reports:
            duplicates[identity] += 1
        else:
            reports[identity] = validated

    failed = no_file_receipts(args.no_file_receipts, since, until)
    result = merge(reports, duplicates, exact_hashes, failed, args.catalog_commit, verified, nonverified, since, until)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 2 if any(row['Status'] != 'ParsedInput' or row['NoFileStates'] for row in result['Windows']) else 0


if __name__ == '__main__':
    try:
        sys.exit(main())
    except (OSError, ValueError, KeyError, TypeError, AttributeError, RecursionError, subprocess.SubprocessError):
        sys.exit('Entra CSV assembly refused: invalid or unavailable aggregate input or pinned catalog.')
