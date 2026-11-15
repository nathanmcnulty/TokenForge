#!/usr/bin/env python3
"""Build a private evidence inventory offline. Never resolve by registration or collect tokens."""
import argparse
import collections
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import uuid
from urllib.parse import urlsplit, parse_qs

REPO = Path(__file__).resolve().parents[1]
OWNER_TENANTS = {'f8cdef31-a31e-4b4a-93e4-5f571e91255a', '72f988bf-86f1-41af-91ab-2d7cd011db47', 'cdc5aeea-15c5-4db6-b079-fcadd2505dc2'}
EVENT_TYPES = {'interactiveUser', 'nonInteractiveUser', 'servicePrincipal', 'managedIdentity'}
KINDS = {'Permission', 'AppRole', 'DirectoryRole', 'AAGUID', 'SKU'}
HASH = re.compile(r'^[a-f0-9]{64}$')
VALIDATE = r'''
param($Repo,$Native,$Ledger,$Definitions,$Overlap,$Flows)
$ErrorActionPreference='Stop'
. (Join-Path $Repo scripts/TokenForgePublicHealth.ps1)
Initialize-TokenForgeHealthRuntime $Native
$null=Get-TokenForgeApplicationMetadata -Path $Ledger -PublicOnly -NativeExecutablePath $Native
$comparison=& (Join-Path $Repo scripts/Compare-TokenForgePermissionIdentifiers.ps1) -CatalogPath $Ledger -PermissionSnapshotPath $Definitions -NativeExecutablePath $Native -IncludeMatches
$comparison | ConvertTo-Json -Depth 100 | Set-Content -LiteralPath $Overlap -Encoding utf8NoBOM
foreach($path in @($Flows | ConvertFrom-Json)){
 if($path.EndsWith('.sqlite')){throw 'Export the selected private flow document with Get-TokenForgeFlowEvidence first.'}
 [TokenForge.Core.FlowEvidencePolicy]::ValidateDocument([IO.File]::ReadAllText($path))
}
'''


def unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('Duplicate JSON key.')
        result[key] = value
    return result


def encoded(value):
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + '\n').encode()


def sha(data):
    return hashlib.sha256(data).hexdigest()


def read(path, maximum=134217728):
    path = Path(path)
    if any(p.is_symlink() for p in (path, *path.parents)) or not path.is_file():
        raise ValueError('Expected unlinked regular evidence file.')
    if not 0 < path.stat().st_size <= maximum:
        raise ValueError('Evidence file size outside limit.')
    return json.loads(path.read_bytes(), object_pairs_hook=unique)


def guid(value):
    if not isinstance(value, str):
        raise ValueError('Identity must be a string.')
    try:
        parsed = uuid.UUID(value)
    except (ValueError, AttributeError):
        raise ValueError('Malformed GUID identity.') from None
    if not parsed.int or str(parsed) != value:
        raise ValueError('Identity must be a nonzero canonical GUID.')
    return value


def text(value, limit=1024):
    if not isinstance(value, str) or not value or len(value) > limit or any(ord(c) < 32 for c in value):
        raise ValueError('Invalid bounded evidence text.')
    return value


def namespace_id(value, namespace='AppId'):
    return namespace + ':' + (guid(value) if namespace not in ('ResourceIdentifier', 'ObservedAudience', 'SignInResourceId', 'SignInServicePrincipalId') else text(value))


def build(ledger, graph, inventory=None, signins=(), flows=(), definitions=(), api_evidence=(), bindings=None):
    """Pure deterministic projection. Public ledger/Graph/flows are prevalidated by the existing policies."""
    rows = {}
    tenant = inventory.get('TenantFingerprint') if inventory else None
    if inventory and (inventory.get('SchemaVersion') != 1 or not HASH.fullmatch(tenant or '') or not isinstance(inventory.get('Applications'), list)):
        raise ValueError('Invalid private tenant inventory context.')
    principal = inventory.get('PrincipalFingerprint') if inventory else None
    if principal is not None and not HASH.fullmatch(principal):
        raise ValueError('Invalid private principal context.')
    notices = []
    def row(identifier, namespace='AppId'):
        key = namespace_id(identifier, namespace)
        if key not in rows:
            rows[key] = {'Identifier': identifier, 'Namespace': namespace, 'Names': [], 'EntityEvidence': [],
                         'OwnershipEvidence': [], 'PublicClaims': [], 'HistoricalClaims': [], 'RecordProvenance': [], 'NonAppDefinitions': [],
                         'Relationships': [], 'ObservedSignIn': [], 'SuccessfulTokenIssuance': [], 'VerifiedApiAccess': [], 'ReviewReasons': []}
        return rows[key]
    def add(target, field, value):
        if value not in target[field]:
            target[field].append(value)
    def name(target, value):
        if value:
            add(target, 'Names', text(value))
    def fact(target, field, evidence, **details):
        add(target, field, {'Evidence': evidence, **details})
    def claim(target, attrs, historical=False):
        name(target, attrs.get('Name'))
        for c in attrs.get('SourceClaims', []):
            # Only public provenance fields survive, never arbitrary source payload.
            safe = {k: text(c[k]) for k in ('Evidence', 'Location', 'Name') if c.get(k)}
            if safe:
                add(target, 'HistoricalClaims' if historical else 'PublicClaims', safe)
        if attrs.get('Ownership') in ('PublishedMicrosoftOwner', 'VerifiedMicrosoftOwner'):
            # Public ledger ownership strings are still public claims, not directory proof.
            fact(target, 'OwnershipEvidence', 'PublicMicrosoftOwnershipHint', Value=attrs['Ownership'])
        if attrs.get('MetadataConflicts'):
            add(target, 'ReviewReasons', 'ConflictingPublicClaims')
    if ledger.get('Format') != 'TokenForgeApplicationMetadata' or ledger.get('SchemaVersion') != 2:
        raise ValueError('Unexpected public ledger format.')
    for app_id, app in ledger['Applications'].items():
        target = row(app_id)
        for origin, record in app.get('Records', {}).items():
            claim(target, record.get('Attributes', {}))
            provenance = {'Origin': text(origin), 'Historical': False}
            for key in ('ContentSha256', 'FirstSeenAt', 'LastSeenAt', 'CurrentVersionFirstSeenAt'):
                if record.get(key):
                    provenance[key] = text(record[key])
            add(target, 'RecordProvenance', provenance)
            for previous in record.get('PreviousVersions', []):
                claim(target, previous.get('Attributes', {}), historical=True)
                provenance = {'Origin': text(origin), 'Historical': True}
                for key in ('ContentSha256', 'FirstSeenAt', 'LastSeenAt'):
                    if previous.get(key):
                        provenance[key] = text(previous[key])
                add(target, 'RecordProvenance', provenance)
    # A source-bound permission definition is positive identifier evidence, not a deletion instruction.
    resource = guid(graph['ResourceId'])
    resource_row = row(resource)
    fact(resource_row, 'EntityEvidence', 'PublishedApiPermissionDefinition', Kind='ApiResource')
    permission_source = (text(graph['Source']['Repository']) + '/blob/' + text(graph['Source']['Commit']) + '/' + text(graph['Source']['Path']) if isinstance(graph['Source'], dict) else text(graph['Source']))
    for key, kind in [('delegatedScopesList', 'Permission'), ('applicationScopesList', 'AppRole')]:
        for definition in graph['Permissions'][key]:
            target = row(guid(definition['id']), 'Identifier')
            fact(target, 'NonAppDefinitions', 'PinnedGraphPermissionDefinition', Kind=kind,
                 Label=text(definition['value']), ResourceAppId=resource, Source=permission_source)
    for document in definitions:
        if document.get('Format') != 'TokenForgeIdentifierDefinitions' or document.get('SchemaVersion') != 1:
            raise ValueError('Unexpected identifier definition document.')
        for definition in document['Definitions']:
            if set(definition) != {'Kind', 'Id', 'Label', 'Source', 'SourceSha256', 'Evidence'} or definition['Kind'] not in KINDS or not HASH.fullmatch(definition['SourceSha256']):
                raise ValueError('Invalid positive definition provenance.')
            target = row(guid(definition['Id']), 'Identifier')
            fact(target, 'NonAppDefinitions', text(definition['Evidence']), Kind=definition['Kind'],
                 Label=text(definition['Label']), Source=text(definition['Source']), SourceSha256=definition['SourceSha256'])
    directory_by_object = collections.defaultdict(set)
    directory_by_identifier = collections.defaultdict(set)
    if inventory:
        for obj in inventory.get('DirectoryObjects', []):
            app_id, object_id = guid(obj['AppId']), guid(obj['ServicePrincipalObjectId'])
            directory_by_object[object_id].add(app_id)
            directory_by_identifier[app_id].add(app_id)
            for identifier in obj.get('IdentifierUris', []):
                directory_by_identifier[text(identifier)].add(app_id)
            target = row(object_id, 'ServicePrincipalObjectId')
            fact(target, 'EntityEvidence', 'PrivateDirectoryObjectMapping', Kind='ServicePrincipalObject')
            add(target, 'Relationships', {'Kind': 'RepresentsAppId', 'AppId': app_id})
            app = row(app_id)
            add(app, 'Relationships', {'Kind': 'DirectoryServicePrincipal', 'ServicePrincipalObjectId': object_id})
        for app in inventory['Applications']:
            target = row(guid(app['AppId']))
            name(target, app.get('Name'))
            if app.get('Registration') == 'Present':
                directory_by_identifier[app['AppId']].add(app['AppId'])
                for identifier in app.get('IdentifierUris', []):
                    directory_by_identifier[text(identifier)].add(app['AppId'])
                fact(target, 'EntityEvidence', 'PrivateDirectoryApplication', Kind='Application')
                if app.get('Ownership') == 'VerifiedMicrosoftOwner' and app.get('OwnerTenantId') in OWNER_TENANTS:
                    fact(target, 'OwnershipEvidence', 'VerifiedMicrosoftDirectoryOwner', CapturedAt=inventory.get('CapturedAt'))
                elif app.get('Ownership') == 'VerifiedMicrosoftOwner':
                    add(target, 'ReviewReasons', 'DirectoryOwnerClaimWithoutMatchingOwnerTenant')
            if app.get('Registration') == 'Present' and (app.get('DelegatedScopeDefinitions') or app.get('AppRoleDefinitions')):
                fact(target, 'EntityEvidence', 'PrivateDirectoryResourceDefinition', Kind='ApiResource')
            elif app.get('IsResourceCandidate'):
                fact(target, 'EntityEvidence', 'PublishedResourceHint', Kind='ResourceCandidate')
            for uri in app.get('IdentifierUris', []):
                identifier = row(text(uri), 'ResourceIdentifier')
                add(identifier, 'Relationships', {'Kind': 'DirectoryResourceIdentifierFor' if app.get('Registration') == 'Present' else 'PublishedResourceIdentifierHint', 'AppId': app['AppId']})
                add(target, 'Relationships', {'Kind': 'ResourceIdentifier', 'Value': uri})
            for key, kind in [('DelegatedScopeDefinitions', 'Permission'), ('AppRoleDefinitions', 'AppRole')]:
                if app.get('Registration') != 'Present':
                    continue
                for definition in app.get(key, []):
                    if not definition.get('Id'):
                        continue
                    target_definition = row(guid(definition['Id']), 'Identifier')
                    fact(target_definition, 'NonAppDefinitions', 'PrivateDirectoryPermissionDefinition', Kind=kind,
                         Label=text(definition.get('Value') or definition['Id']), ResourceAppId=app['AppId'])
    coverage = []
    for summary in signins:
        if not tenant or summary.get('TenantFingerprint') != tenant:
            raise ValueError('Sign-in tenant context does not match selected inventory.')
        requested = summary.get('EventTypes', [])
        if not isinstance(requested, list) or not set(requested) <= EVENT_TYPES:
            raise ValueError('Invalid sign-in event type coverage.')
        coverage_detail = {key: summary.get('Coverage', {}).get(key) for key in ('WindowEnumeration', 'RetentionAvailability', 'RawEventsRetained') if key in summary.get('Coverage', {})}
        by_type = summary.get('Coverage', {}).get('ByEventType', {})
        if not by_type:
            counts = collections.Counter()
            for app in summary.get('Applications', []):
                for entry in app.get('EventTypeCounts', []):
                    if entry.get('Value') in EVENT_TYPES and type(entry.get('Count')) is int and entry['Count'] >= 0:
                        counts[entry['Value']] += entry['Count']
            by_type = {key: {'RecordCount': count} for key, count in counts.items()}
            if counts:
                coverage_detail['CountSource'] = 'LegacyAggregatedApplicationSummaries'
        coverage_detail['ByEventType'] = {}
        for event_type in sorted(EVENT_TYPES & set(by_type)):
            entry = by_type[event_type]
            safe = {}
            if type(entry.get('RecordCount')) is int and entry['RecordCount'] >= 0:
                safe['RecordCount'] = entry['RecordCount']
            for field in ('FirstObservedAt', 'LastObservedAt'):
                if entry.get(field) is not None:
                    safe[field] = text(entry[field], 64)
            coverage_detail['ByEventType'][event_type] = safe
        coverage.append({'Since': summary.get('Since'), 'Until': summary.get('Until'), 'EventTypes': sorted(requested),
                         'Enumeration': summary.get('Enumeration', 'Unknown'),
                         'AllFourEventTypesRequested': set(requested) == EVENT_TYPES,
                         'Coverage': coverage_detail})
        if summary.get('Enumeration') != 'Complete' or set(requested) != EVENT_TYPES:
            notices.append('PartialSignInCoverage')
        for app in summary.get('Applications', []):
            target = row(guid(app['AppId']))
            fact(target, 'ObservedSignIn', 'ObservedSignInNotOwnershipOrIssuance', Count=app.get('SignInCount', 0),
                 RequestedEventTypes=sorted(requested),
                 ObservedEventTypeCounts=[{'EventType': entry['Value'], 'Count': entry['Count']} for entry in app.get('EventTypeCounts', []) if entry.get('Value') in EVENT_TYPES and type(entry.get('Count')) is int and entry['Count'] >= 0],
                 Since=summary.get('Since'), Until=summary.get('Until'))
            fact(target, 'EntityEvidence', 'ObservedClientAppId', Kind='ClientApplication')
            for count in app.get('ResourceCounts', []):
                raw = row(text(count['Value']), 'SignInResourceId')
                add(raw, 'ReviewReasons', 'LegacyResourceIdNamespaceUnmapped')
                if type(count.get('Count')) is int and count['Count'] >= 0:
                    fact(raw, 'ObservedSignIn', 'LegacyRawResourceIdNotAppIdOrAudience', Count=count['Count'], ClientAppId=app['AppId'])
        for observation in summary.get('IdentifierObservations', []):
            # Sign-in extension supplies typed observations; ambiguous raw resource IDs stay ambiguous.
            identifier = observation.get('Identifier') or observation.get('Value')
            namespace = observation.get('Namespace') or observation.get('Kind') or {'appId': 'ClientAppId', 'resourceId': 'SignInResourceId', 'servicePrincipalId': 'SignInServicePrincipalId', 'resourceServicePrincipalId': 'ResourceServicePrincipalObjectId'}.get(observation.get('Field'))
            if namespace in ('ClientAppId', 'AppId', 'ResourceAppId'):
                target = row(guid(identifier))
                fact(target, 'ObservedSignIn', 'TypedSignInIdentifier', Role=namespace)
            elif namespace in ('ResourceServicePrincipalObjectId', 'ClientServicePrincipalObjectId', 'ServicePrincipalObjectId'):
                target = row(guid(identifier), 'ServicePrincipalObjectId')
                mapped = sorted(directory_by_object.get(identifier, set()))
                if len(mapped) == 1:
                    add(target, 'Relationships', {'Kind': 'ResolvedFromDirectory', 'AppId': mapped[0]})
                else:
                    add(target, 'ReviewReasons', 'MissingOrAmbiguousDirectoryObjectMapping')
            else:
                target = row(text(identifier), 'SignInResourceId' if namespace in ('SignInResourceId', 'ResourceId') else 'SignInServicePrincipalId')
                add(target, 'ReviewReasons', 'AmbiguousSignInIdentifierNamespace')
        for observed in summary.get('Resources', []):
            raw_id = observed.get('SignInResourceId')
            object_id = observed.get('ResourceServicePrincipalObjectId')
            candidates = set()
            targets = []
            if raw_id:
                raw = row(text(raw_id), 'SignInResourceId')
                raw_candidates = directory_by_identifier.get(raw_id, set()) | directory_by_object.get(raw_id, set())
                targets.append((raw, raw_candidates))
                fact(raw, 'ObservedSignIn', 'ObservedTargetNotTokenAudienceOrApiAccess')
                add(raw, 'ReviewReasons', 'RawResourceIdentifierIsNotAnAppIdOrTokenAudience')
                candidates |= raw_candidates
            if object_id:
                object_candidates = directory_by_object.get(guid(object_id), set())
                candidates |= object_candidates
                targets.append((row(object_id, 'ServicePrincipalObjectId'), object_candidates))
            if len(candidates) == 1:
                resolved = next(iter(candidates))
                for target, own_candidates in targets:
                    if resolved in own_candidates:
                        add(target, 'Relationships', {'Kind': 'ResolvedTargetThroughDirectory', 'AppId': resolved})
                    else:
                        add(target, 'ReviewReasons', 'FieldNotResolvedByDirectory')
                app = row(resolved)
                fact(app, 'EntityEvidence', 'SignInTargetResolvedThroughDirectory', Kind='ObservedTargetApplication')
                fact(app, 'ObservedSignIn', 'DirectoryMappedTargetNotApiAccess')
            else:
                for target, _ in targets:
                    add(target, 'ReviewReasons', 'MissingOrAmbiguousDirectoryObjectMapping')
    if not signins:
        notices.append('NoRetainedSignInCoverage')
    for document in flows:
        if document.get('Format') != 'TokenForgeFlowEvidence' or document.get('SchemaVersion') != 1:
            raise ValueError('Unexpected private flow evidence format.')
        for attempt in document['Attempts']:
            if not tenant or not principal or attempt.get('TenantFingerprint') != tenant or attempt.get('PrincipalFingerprint') != principal:
                notices.append('FlowContextMismatchExcluded')
                continue
            client, resource_id = guid(attempt['ClientId']), guid(attempt['ResourceId'])
            target = row(client)
            if attempt.get('Outcome') == 'Succeeded' and attempt.get('NamespaceVerification') == 'Matched' and attempt.get('RequestVerification') == 'Matched' and attempt.get('ClaimsReadable') is True:
                fact(target, 'EntityEvidence', 'MatchedClientIssuance', Kind='ClientApplication')
                fact(target, 'SuccessfulTokenIssuance', 'RetainedMatchedIssuanceNotApiAccess', ResourceAppId=resource_id,
                     Protocol=text(attempt['Protocol']), ObservedAt=text(attempt['ObservedAt']))
                row(resource_id)
    for doc in api_evidence:
        if doc.get('Format') != 'TokenForgePrivateApiAccessProofs' or doc.get('SchemaVersion') != 1:
            raise ValueError('Unexpected API proof format.')
        for proof in doc['Proofs']:
            allowed = {'TenantFingerprint', 'PrincipalFingerprint', 'ClientAppId', 'ResourceAppId', 'Audience', 'Method', 'Endpoint', 'StatusCode', 'ObservedAt', 'SourceSha256', 'ContextVerified'}
            if not allowed <= set(proof) or set(proof) - allowed - {'SourceBindings', 'FlowObservedAt'} or proof['Method'] != 'GET' or not HASH.fullmatch(proof['SourceSha256']):
                raise ValueError('Invalid retained API proof.')
            if not tenant or not principal or proof['TenantFingerprint'] != tenant or proof['PrincipalFingerprint'] != principal or proof['ContextVerified'] is not True or not isinstance(proof['StatusCode'], int) or not 200 <= proof['StatusCode'] < 300:
                notices.append('UnverifiedApiProofExcluded')
                continue
            endpoint = urlsplit(text(proof['Endpoint']))
            if endpoint.scheme != 'https' or endpoint.hostname not in ('graph.microsoft.com', 'management.azure.com') or endpoint.username or endpoint.password or endpoint.fragment or endpoint.port not in (None, 443):
                raise ValueError('API proof endpoint is outside fixed Graph/ARM GET boundary.')
            if (endpoint.hostname == 'graph.microsoft.com' and (endpoint.path != '/v1.0/me' or parse_qs(endpoint.query) not in ({}, {'$select': ['id']}))) or (endpoint.hostname == 'management.azure.com' and (endpoint.path != '/subscriptions' or set(parse_qs(endpoint.query)) != {'api-version'})):
                raise ValueError('API proof is not a supported fixed GET.')
            source_bindings = proof.get('SourceBindings', {})
            if not isinstance(source_bindings, dict) or any(not re.fullmatch('[A-Za-z][A-Za-z0-9]{0,63}', k) or not HASH.fullmatch(v) for k, v in source_bindings.items()):
                raise ValueError('Invalid API proof source bindings.')
            if source_bindings and sha(json.dumps(source_bindings, sort_keys=True, separators=(',', ':')).encode()) != proof['SourceSha256']:
                raise ValueError('API proof compound source digest does not match its bindings.')
            client, resource_id = guid(proof['ClientAppId']), guid(proof['ResourceAppId'])
            target = row(client)
            fact(target, 'EntityEvidence', 'RetainedFixedGetClient', Kind='ClientApplication')
            fact(row(resource_id), 'EntityEvidence', 'RetainedFixedGetResource', Kind='ApiResource')
            fact(target, 'VerifiedApiAccess', 'RetainedFixedGetApiProof', ResourceAppId=resource_id,
                 Audience=text(proof['Audience']) if proof['Audience'] is not None else None, Method='GET', Endpoint=text(proof['Endpoint']),
                 StatusCode=proof['StatusCode'], ObservedAt=text(proof['ObservedAt']) if proof['ObservedAt'] is not None else None,
                 FlowObservedAt=text(proof['FlowObservedAt']) if proof.get('FlowObservedAt') else None, SourceSha256=proof['SourceSha256'], SourceBindings=source_bindings)
            if proof['Audience'] is not None:
                audience = row(text(proof['Audience']), 'ObservedAudience')
                add(audience, 'Relationships', {'Kind': 'ObservedForResource', 'ResourceAppId': resource_id})
    # Lookups join equal identifier strings across namespaces without merging their meanings.
    by_value = collections.defaultdict(list)
    for target in rows.values():
        by_value[target['Identifier']].append(target)
    queue = []
    for key, target in sorted(rows.items()):
        sibling_definitions = [x for sibling in by_value[target['Identifier']] for x in sibling['NonAppDefinitions']]
        client = any(x.get('Kind') == 'ClientApplication' for x in target['EntityEvidence'])
        resource_kind = any(x.get('Kind') == 'ApiResource' for x in target['EntityEvidence'])
        verified_owner = any(x['Evidence'] == 'VerifiedMicrosoftDirectoryOwner' for x in target['OwnershipEvidence'])
        target['TenantAdded'] = target['Namespace'] == 'AppId' and target['Identifier'] not in ledger['Applications'] and any(x['Evidence'] == 'PrivateDirectoryApplication' for x in target['EntityEvidence'])
        target['MicrosoftOwnership'] = 'DirectoryVerified' if verified_owner else ('PublishedHint' if target['OwnershipEvidence'] else 'Unresolved')
        target['Kinds'] = sorted({x['Kind'] for x in target['EntityEvidence']} | {x['Kind'] for x in target['NonAppDefinitions']})
        if sibling_definitions and (target['PublicClaims'] or client or resource_kind or any(x.get('Kind') == 'Application' for x in target['EntityEvidence'])):
            target['Classification'] = 'ConflictingAppAndNonAppEvidence'
            add(target, 'ReviewReasons', 'IdentifierAlsoHasNonAppDefinition')
        elif target['NonAppDefinitions']:
            target['Classification'] = 'KnownNonAppIdentifier'
        elif verified_owner and (client or resource_kind):
            target['Classification'] = 'MicrosoftOwnedClientAndResource' if client and resource_kind else ('MicrosoftApiResource' if resource_kind else 'MicrosoftOwnedClient')
        elif verified_owner:
            target['Classification'] = 'MicrosoftOwnedApplicationRoleUnresolved'
            add(target, 'ReviewReasons', 'ClientOrResourceRoleNotEstablished')
        elif target['Namespace'] == 'ServicePrincipalObjectId':
            target['Classification'] = 'DirectoryServicePrincipalObject'
        else:
            target['Classification'] = 'Unresolved'
            add(target, 'ReviewReasons', 'InsufficientTypedIdentityOrOwnershipEvidence')
        if not verified_owner and target['PublicClaims']:
            add(target, 'ReviewReasons', 'PublicClaimsDoNotVerifyMicrosoftOwnership')
        if target['HistoricalClaims']:
            target['HistoricalClaimsRetained'] = True
        for field, values in target.items():
            if isinstance(values, list):
                target[field] = sorted(values, key=lambda x: json.dumps(x, sort_keys=True))
        if target['ReviewReasons']:
            queue.append({'Key': key, 'Classification': target['Classification'], 'Reasons': target['ReviewReasons']})
    result = {'Format': 'TokenForgeFirstPartyInventory', 'SchemaVersion': 1, 'Privacy': 'Private',
              'Bindings': bindings or {}, 'Identifiers': dict(sorted(rows.items())), 'SignInCoverage': coverage,
              'Notices': sorted(set(notices)), 'Counts': {'Identifiers': len(rows), 'ReviewQueue': len(queue),
              'Classifications': dict(sorted(collections.Counter(x['Classification'] for x in rows.values()).items())),
              'TenantAddedIdentifiers': sum(x['TenantAdded'] for x in rows.values()),
              'DirectoryVerifiedMicrosoft': sum(x['MicrosoftOwnership'] == 'DirectoryVerified' for x in rows.values()),
              'WithObservedSignIn': sum(bool(x['ObservedSignIn']) for x in rows.values()),
              'WithMatchedTokenIssuance': sum(bool(x['SuccessfulTokenIssuance']) for x in rows.values()),
              'WithVerifiedApiAccess': sum(bool(x['VerifiedApiAccess']) for x in rows.values())},
              'Limitations': ['No match is not proof of non-application identity.', 'Public claims and GUID syntax do not verify applications.',
                             'Ownership, sign-in, token issuance and API access are independent evidence axes.',
                             'Retained evidence is not fresh collection; no service principal was created.']}
    return result, {'Format': 'TokenForgeFirstPartyReviewQueue', 'SchemaVersion': 1, 'Privacy': 'Private', 'Items': queue}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for key in ('public-ledger', 'graph-definitions', 'native', 'pwsh', 'output'):
        parser.add_argument('--' + key, type=Path, required=True)
    parser.add_argument('--tenant-inventory', type=Path)
    for key in ('signins', 'flows', 'definitions', 'api-evidence'):
        parser.add_argument('--' + key, type=Path, action='append', default=[])
    parser.add_argument('--lookup')
    args = parser.parse_args()
    output = Path(os.path.abspath(args.output))
    if output.exists() or any(p.is_symlink() for p in (output, *output.parents)):
        raise ValueError('Choose a new unlinked private output directory.')
    files = [args.public_ledger, args.graph_definitions, *args.signins, *args.flows, *args.definitions, *args.api_evidence]
    if args.tenant_inventory:
        files.append(args.tenant_inventory)
    source_bytes = {}
    documents = {}
    for p in files:
        read(p)  # Path/size contract before the immutable read.
        data = p.read_bytes()
        if not 0 < len(data) <= 134217728:
            raise ValueError('Evidence file size outside limit.')
        source_bytes[str(p)] = data
        documents[str(p)] = json.loads(data, object_pairs_hook=unique)
    bindings = {str(index): {'Sha256': sha(source_bytes[str(p)]), 'Bytes': len(source_bytes[str(p)]),
                             'Role': 'PublicLedger' if p == args.public_ledger else 'PinnedGraphDefinitions' if p == args.graph_definitions else 'PrivateEvidence'}
                for index, p in enumerate(files)}
    source_files = [Path(__file__).resolve(), REPO / 'scripts/TokenForgePublicHealth.ps1', REPO / 'scripts/Compare-TokenForgePermissionIdentifiers.ps1', REPO / 'scripts/TokenForgePublicPermissions.ps1', *sorted((REPO / 'src/TokenForge').rglob('*'))]
    source_hashes = {str(p.relative_to(REPO)): sha(p.read_bytes()) for p in source_files if p.is_file()}
    bindings['Execution'] = {'EngineSha256': source_hashes['scripts/New-TokenForgeFirstPartyInventory.py'], 'SourceOverlaySha256': source_hashes,
                             'NativeSha256': sha(args.native.read_bytes()), 'CredentialLibrarySha256': sha((args.native.parent / 'src/TokenForge/lib/net10.0/TokenForge.Credentials.dll').read_bytes()),
                             'PowerShellSha256': sha(args.pwsh.read_bytes()), 'CompilationProvenance': 'Existing approved runtime pair; these hashes do not assert a new build.'}
    output.mkdir(mode=0o700)
    try:
        with tempfile.TemporaryDirectory(prefix='.validation-', dir=output) as temporary:
            tmp = Path(temporary)
            frozen = {}
            for index, p in enumerate(files):
                copy_path = tmp / ('input-' + str(index) + '.json')
                copy_path.write_bytes(source_bytes[str(p)]);copy_path.chmod(0o400)
                frozen[str(p)] = copy_path
            script = tmp / 'validate.ps1'
            script.write_text(VALIDATE)
            command = [str(args.pwsh), '-NoProfile', '-NonInteractive', '-File', str(script), str(REPO), str(args.native),
                       str(frozen[str(args.public_ledger)]), str(frozen[str(args.graph_definitions)]), str(tmp / 'overlap.json'), json.dumps([str(frozen[str(p)]) for p in args.flows])]
            checked = subprocess.run(command, capture_output=True, timeout=300)
            if checked.returncode:
                raise ValueError('Existing public/flow validators refused the inputs; private details suppressed.')
            # Comparator validation has accepted the complete Graph snapshot and public ledger.
            overlap = read(tmp / 'overlap.json')
            bindings['ValidatedGraphOverlap'] = {'MatchedIdentifiers': overlap['Counts']['MatchedIdentifiers'], 'Sha256': sha((tmp / 'overlap.json').read_bytes())}
        inventory, queue = build(documents[str(args.public_ledger)], documents[str(args.graph_definitions)],
                                 documents[str(args.tenant_inventory)] if args.tenant_inventory else None,
                                 [documents[str(p)] for p in args.signins], [documents[str(p)] for p in args.flows],
                                 [documents[str(p)] for p in args.definitions], [documents[str(p)] for p in args.api_evidence], bindings)
        if any(sha((REPO / p).read_bytes()) != digest for p, digest in source_hashes.items()):
            raise ValueError('Executing source changed during projection.')
        if any(p.read_bytes() != source_bytes[str(p)] for p in files):
            raise ValueError('Input evidence changed during projection.')
        for filename, doc in [('inventory.json', inventory), ('review-queue.json', queue)]:
            path = output / filename
            with path.open('xb') as stream:
                os.chmod(path, 0o600)
                stream.write(encoded(doc))
        lines = ['# First-Party Inventory v1 — private', '', json.dumps(inventory['Counts'], sort_keys=True), '',
                 'Evidence remains typed. Directory ownership does not imply token issuance; issuance does not imply API access.', '',
                 '## Coverage', '', json.dumps(inventory['SignInCoverage'], sort_keys=True), '',
                 '## Remaining review', '', *['- ' + x for x in inventory['Notices']], '',
                 'The full identifier evidence and review queue are in the adjacent private JSON files. No raw events or token material are copied.', '']
        report = output / 'report.md'
        report.write_text('\n'.join(lines));report.chmod(0o600)
        if args.lookup:
            try:
                lookup = str(uuid.UUID(args.lookup))
            except ValueError:
                lookup = args.lookup
            selected = {key: value for key, value in inventory['Identifiers'].items() if value['Identifier'] == lookup}
            print(json.dumps({'Matches': selected, 'NoMatchMeans': 'Unresolved, not proof of non-app identity.'}, sort_keys=True, indent=2))
        else:
            print(json.dumps({'Privacy': 'Private', 'Counts': inventory['Counts'], 'Notices': inventory['Notices']}, sort_keys=True))
    except BaseException:
        failure = output / 'FAILED'
        failure.write_text('Not a completed inventory. Retain and investigate; no publication.\n');failure.chmod(0o600)
        raise


if __name__ == '__main__':
    main()
