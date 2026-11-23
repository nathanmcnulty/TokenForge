#!/usr/bin/env python3
"""Read a local Sentinel sign-in aggregate and compare identifiers with the pinned catalog."""

import argparse
from datetime import datetime
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys

from tokenforge_offline_catalog import OfflineCatalog, app_id_is_canonical, unique


COMMON = {'AppId', 'ResourceIdentity', 'ResourceServicePrincipalId'}
TABLE_FIELDS = {
    'SigninLogs': COMMON | {'ResourceId'},
    'AADNonInteractiveUserSignInLogs': COMMON,
    'AADServicePrincipalSignInLogs': COMMON,
    'AADManagedIdentitySignInLogs': COMMON,
}
FORMAT = 'TokenForgeSentinelSignInAggregate'
MAX_BYTES = 8 * 1024 * 1024


def require(condition, message):
    if not condition:
        raise ValueError(message)


def require_fields(value, fields):
    require(isinstance(value, dict) and value.keys() == fields, 'Invalid aggregate fields')


def utc_instant(value):
    require(isinstance(value, str) and re.fullmatch(r'[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z', value),
            'Use whole-second UTC bounds')
    datetime.fromisoformat(value[:-1] + '+00:00')
    return value


def reject_nonstandard_number(_):
    raise ValueError('Invalid JSON number')


def read_input(path):
    require(stat.S_ISREG(path.lstat().st_mode), 'Aggregate must be a regular file')
    flags = os.O_RDONLY | getattr(os, 'O_NONBLOCK', 0) | getattr(os, 'O_NOFOLLOW', 0)
    with os.fdopen(os.open(path, flags), 'rb') as stream:
        require(stat.S_ISREG(os.fstat(stream.fileno()).st_mode), 'Aggregate must be a regular file')
        raw = stream.read(MAX_BYTES + 1)
    require(len(raw) <= MAX_BYTES, 'Aggregate exceeds 8 MiB')
    return json.loads(raw, object_pairs_hook=unique, parse_constant=reject_nonstandard_number)


def analyze(document, catalog_commit, verified, nonverified):
    require_fields(document, {'Format', 'SchemaVersion', 'Since', 'UntilExclusive', 'Tables'})
    require(document['Format'] == FORMAT and type(document['SchemaVersion']) is int and document['SchemaVersion'] == 1,
            'Unsupported aggregate format')
    start, end = utc_instant(document['Since']), utc_instant(document['UntilExclusive'])
    require(start < end, 'Invalid aggregate interval')
    require(isinstance(document['Tables'], list) and len(document['Tables']) <= len(TABLE_FIELDS),
            'Invalid table list')
    tables = {}
    apps = {}
    resources = []
    for table in document['Tables']:
        require_fields(table, {'Table', 'State', 'Rows'})
        name = table['Table']
        state = table['State']
        rows = table['Rows']
        require(name in TABLE_FIELDS and name not in tables and state in ('Supplied', 'Unavailable') and
                isinstance(rows, list) and (state == 'Supplied' or not rows), 'Invalid table aggregate')
        tables[name] = {'InputState': state, 'AggregateRows': len(rows)}
        seen = set()
        for row in rows:
            require_fields(row, {'Field', 'Identifier', 'Count'})
            field, identifier, count = row['Field'], row['Identifier'], row['Count']
            require(field in TABLE_FIELDS[name] and app_id_is_canonical(identifier) and
                    type(count) is int and 0 < count < 2**63 and (field, identifier) not in seen,
                    'Invalid or duplicate aggregate identifier')
            seen.add((field, identifier))
            match = 'Verified' if identifier in verified else 'NonVerified' if identifier in nonverified else 'NoExactMatch'
            if field == 'AppId':
                if match == 'NoExactMatch':
                    apps.setdefault(identifier, []).append({'Table': name, 'Count': count})
            else:
                resources.append({'Table': name, 'SourceField': field, 'Identifier': identifier, 'Count': count,
                                  'ExactCatalogAppIdMatch': 'NotComparable' if field == 'ResourceServicePrincipalId' else match})

    return {
        'Format': 'TokenForgeSentinelSignInGapReport', 'SchemaVersion': 1, 'CatalogCommit': catalog_commit,
        'Since': start, 'UntilExclusive': end, 'TimeColumn': 'TimeGenerated',
        'WorkspaceAvailability': 'Unknown', 'RetentionCoverage': 'Unknown', 'TenantHistoryComplete': False,
        'ActualAudience': 'UnknownFromSentinelSignInLogs',
        'Tables': [{'Table': name, 'Availability': 'Unknown',
                    **tables.get(name, {'InputState': 'NotProvided', 'AggregateRows': 0})}
                   for name in sorted(TABLE_FIELDS)],
        'Candidates': [{'AppId': key, 'Disposition': 'Pending',
                        'Observations': sorted(value, key=lambda row: row['Table'])}
                       for key, value in sorted(apps.items())],
        'ObservedResources': sorted(resources, key=lambda row: (row['Table'], row['SourceField'], row['Identifier'])),
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--catalog-repo', type=Path, required=True)
    parser.add_argument('--catalog-commit', required=True)
    parser.add_argument('aggregate', type=Path)
    args = parser.parse_args()
    catalog = OfflineCatalog(args.catalog_repo, args.catalog_commit)
    verified = catalog.partition(True)['Applications']
    nonverified = catalog.partition(False)['Applications']
    catalog.app_ids(verified, nonverified)
    result = analyze(read_input(args.aggregate), args.catalog_commit, verified, nonverified)
    print(json.dumps(result, sort_keys=True, indent=2))


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, KeyError, TypeError, AttributeError, RecursionError, subprocess.SubprocessError):
        sys.exit('Sentinel aggregate refused: invalid or unavailable input or pinned catalog.')
