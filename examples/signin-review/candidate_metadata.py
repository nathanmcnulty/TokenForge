"""Minimize exact service-principal evidence to fixed public labels."""

import re
from urllib.parse import urlencode

from collect import app_id_is_canonical

BASE = 'https://graph.microsoft.com/v1.0/servicePrincipals(appId='
QUERY = urlencode({'$select': 'appId,signInAudience,appOwnerOrganizationId,servicePrincipalType,verifiedPublisher'})
SOURCES = frozenset(('sign-in', 'provisioning', 'sign-in and provisioning'))
AUDIENCES = frozenset(('multi-tenant', 'multi-tenant and personal', 'personal only', 'audience unknown'))
PUBLISHERS = frozenset(('verified publisher', 'publisher unknown'))
AUDIENCE_LABELS = {
    'AzureADMultipleOrgs': 'multi-tenant',
    'AzureADandPersonalMicrosoftAccount': 'multi-tenant and personal',
    'PersonalMicrosoftAccount': 'personal only',
}


def principal_url(app):
    if not app_id_is_canonical(app):
        raise ValueError('Unexpected candidate AppId')
    return f"{BASE}'{app}')?{QUERY}"


def is_principal_url(url):
    if not isinstance(url, str) or not url.startswith(BASE):
        return False
    match = re.match(r"'([a-f0-9-]{36})'\)", url[len(BASE):])
    return bool(match and app_id_is_canonical(match[1]) and url == principal_url(match[1]))


def audience_label(values):
    """Use one unequivocal recognized audience. Missing or conflicting values stay visible."""
    if not values or any(not isinstance(value, str) for value in values) or len(set(values)) != 1:
        return 'audience unknown'
    value = values[0]
    if value == 'AzureADMyOrg':
        return None
    return AUDIENCE_LABELS.get(value, 'audience unknown')


def classify_principal(app, tenant, value, source):
    if source not in SOURCES or not app_id_is_canonical(app) or not app_id_is_canonical(tenant):
        raise ValueError('Unexpected candidate context')
    if value is None:
        return [source, 'audience unknown', 'publisher unknown']
    if not isinstance(value, dict) or value.get('appId') != app:
        raise ValueError('Unverified service principal response')
    raw_audience = value.get('signInAudience')
    audience = audience_label([raw_audience])
    principal_type = value.get('servicePrincipalType')
    if principal_type in ('ManagedIdentity', 'Legacy'):
        if value.get('appOwnerOrganizationId') == tenant and raw_audience in (None, 'AzureADMyOrg'):
            return None
        audience = 'audience unknown'
    if audience is None:
        return None
    publisher = value.get('verifiedPublisher')
    key = publisher.get('verifiedPublisherId') if isinstance(publisher, dict) else None
    verified = isinstance(key, str) and re.fullmatch(r'[0-9]{1,32}', key) and int(key) > 0
    return [source, audience, 'verified publisher' if verified else 'publisher unknown']


def valid_labels(labels):
    return (isinstance(labels, list) and len(labels) == 3 and all(isinstance(x, str) for x in labels)
            and labels[0] in SOURCES and labels[1] in AUDIENCES and labels[2] in PUBLISHERS)
