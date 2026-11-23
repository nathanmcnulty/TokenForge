"""Shared schema rules for Entra portal CSV aggregates."""

from datetime import datetime
import re


EXPORT_KINDS = ('InteractiveUser', 'NonInteractiveUser', 'ServicePrincipal', 'ManagedIdentity')
EXPORT_STATES = ('NotRecorded', 'PortalReportedSuccess', 'PortalReportedIncomplete')
COLUMNS = ('Date (UTC)', 'Application ID', 'Resource ID')
PORTAL_ROW_CAP = 100_000
ISO_UTC = re.compile(r'([0-9]{4}-[0-9]{2}-[0-9]{2})[T ]([0-9]{2}:[0-9]{2}:[0-9]{2})(?:\.([0-9]{1,7}))?(Z|\+00:00)?')


def instant(value, *, require_zone=False):
    stamp = ISO_UTC.fullmatch(value.strip())
    if stamp is None or (require_zone and stamp[4] is None):
        raise ValueError('Expected an ISO-format UTC timestamp')
    whole = f'{stamp[1]}T{stamp[2]}'
    datetime.fromisoformat(whole)
    return f'{whole}.{(stamp[3] or "").ljust(7, "0")}Z'


def incomplete_reasons(totals, status):
    reasons = []
    if totals['CsvRows'] == PORTAL_ROW_CAP:
        reasons.append('DocumentedRowCapReached')
    if status == 'PortalReportedIncomplete':
        reasons.append('OperatorReportedIncompleteExport')
    if totals['MalformedDates'] or totals['RowsOutsideWindow']:
        reasons.append('UnusableOrOutOfWindowDates')
    if totals['UnusableApplicationIds'] or totals['UnusableResourceIds']:
        reasons.append('UnusableIdentifiers')
    return reasons


def resource_match(identifier, verified, nonverified):
    if identifier in verified:
        return 'Verified'
    return 'NonVerified' if identifier in nonverified else 'NoExactMatch'
