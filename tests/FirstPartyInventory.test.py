#!/usr/bin/env python3
"""Offline typed evidence projection regressions; no authentication/network/native execution."""
import copy
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

REPO = Path(__file__).resolve().parents[1]
s = importlib.util.spec_from_file_location('inventory', REPO / 'scripts/New-TokenForgeFirstPartyInventory.py')
m = importlib.util.module_from_spec(s);s.loader.exec_module(m)
CLIENT='11111111-1111-1111-1111-111111111111'
RESOURCE='22222222-2222-2222-2222-222222222222'
OBJECT='33333333-3333-3333-3333-333333333333'
PERMISSION='44444444-4444-4444-4444-444444444444'
TENANT='a'*64
PRINCIPAL='b'*64


class InventoryTests(unittest.TestCase):
    def setUp(self):
        self.ledger={'Format':'TokenForgeApplicationMetadata','SchemaVersion':2,'Applications':{
            CLIENT:{'Records':{'Discovery///':{'Attributes':{'Name':'Public client','SourceClaims':[{'Evidence':'PublishedGraph','Location':'https://example.test/apps'}]},'PreviousVersions':[{'Attributes':{'Name':'Old public client','SourceClaims':[{'Evidence':'PublishedEntraDocs','Location':'https://example.test/old'}]}}]}}}}}
        self.graph={'ResourceId':RESOURCE,'Source':'https://example.test/permissions','Permissions':{'delegatedScopesList':[{'id':PERMISSION,'value':'Read.Fixture'}],'applicationScopesList':[]}}
        self.inventory={'SchemaVersion':1,'TenantFingerprint':TENANT,'PrincipalFingerprint':PRINCIPAL,'CapturedAt':'2026-11-01T00:00:00Z','Applications':[{'AppId':CLIENT,'Name':'Private directory client','Ownership':'VerifiedMicrosoftOwner','OwnerTenantId':next(iter(m.OWNER_TENANTS)),'Registration':'Present'},{'AppId':RESOURCE,'Name':'Fixture resource','Registration':'Present','Ownership':'VerifiedMicrosoftOwner','OwnerTenantId':next(iter(m.OWNER_TENANTS)),'IsResourceCandidate':True}], 'DirectoryObjects':[{'AppId':RESOURCE,'ServicePrincipalObjectId':OBJECT}]}
        self.signins={'TenantFingerprint':TENANT,'EventTypes':sorted(m.EVENT_TYPES),'Enumeration':'Complete','Since':'2026-10-01T00:00:00Z','Until':'2026-10-02T00:00:00Z','Applications':[{'AppId':CLIENT,'SignInCount':2}], 'IdentifierObservations':[{'Field':'resourceId','Value':OBJECT,'Count':2}], 'Resources':[{'SignInResourceId':OBJECT,'ResourceServicePrincipalObjectId':OBJECT,'SignInCount':2}]}

    def build(self, **kwargs):
        return m.build(self.ledger,self.graph,self.inventory,**kwargs)

    def test_positive_definitions_never_erase_ambiguous_app_claim(self):
        self.ledger['Applications'][PERMISSION]=copy.deepcopy(self.ledger['Applications'][CLIENT])
        result,queue=self.build()
        self.assertEqual(result['Identifiers']['Identifier:'+PERMISSION]['Classification'],'KnownNonAppIdentifier')
        self.assertEqual(result['Identifiers']['AppId:'+PERMISSION]['Classification'],'ConflictingAppAndNonAppEvidence')
        self.assertTrue(result['Identifiers']['AppId:'+PERMISSION]['HistoricalClaims'])
        self.assertTrue(queue['Items'])

    def test_resource_mapping_keeps_object_app_and_raw_resource_distinct(self):
        result,_=self.build(signins=[self.signins])
        self.assertIn('ServicePrincipalObjectId:'+OBJECT,result['Identifiers'])
        self.assertIn('SignInResourceId:'+OBJECT,result['Identifiers'])
        self.assertNotIn('AppId:'+OBJECT,result['Identifiers'])
        target=result['Identifiers']['AppId:'+RESOURCE]
        self.assertTrue(any(x['Evidence']=='DirectoryMappedTargetNotApiAccess' for x in target['ObservedSignIn']))
        self.assertFalse(target['VerifiedApiAccess'])
        self.assertFalse(target['SuccessfulTokenIssuance'])

    def test_unmapped_object_does_not_borrow_other_field_directory_resolution(self):
        self.signins['Resources'][0].update(SignInResourceId=RESOURCE,ResourceServicePrincipalObjectId='99999999-9999-9999-9999-999999999999')
        result,_=self.build(signins=[self.signins])
        unknown=result['Identifiers']['ServicePrincipalObjectId:99999999-9999-9999-9999-999999999999']
        self.assertIn('FieldNotResolvedByDirectory',unknown['ReviewReasons'])
        self.assertFalse(unknown['Relationships'])
        self.assertTrue(any(x['Evidence']=='DirectoryMappedTargetNotApiAccess' for x in result['Identifiers']['AppId:'+RESOURCE]['ObservedSignIn']))

    def test_contradictory_resource_fields_never_select_two_targets(self):
        self.signins['Resources'][0]['SignInResourceId']=CLIENT
        result,_=self.build(signins=[self.signins])
        self.assertIn('MissingOrAmbiguousDirectoryObjectMapping',result['Identifiers']['SignInResourceId:'+CLIENT]['ReviewReasons'])
        for appid in (CLIENT,RESOURCE):
            self.assertFalse(any(x['Evidence']=='DirectoryMappedTargetNotApiAccess' for x in result['Identifiers']['AppId:'+appid]['ObservedSignIn']))

    def test_requested_eventtypes_are_not_claimed_as_observed_for_each_client(self):
        self.signins['Applications'][0]['EventTypeCounts']=[{'Value':'interactiveUser','Count':2}]
        result,_=self.build(signins=[self.signins])
        observed=result['Identifiers']['AppId:'+CLIENT]['ObservedSignIn'][0]
        self.assertEqual(observed['RequestedEventTypes'],sorted(m.EVENT_TYPES))
        self.assertEqual(observed['ObservedEventTypeCounts'],[{'EventType':'interactiveUser','Count':2}])
        self.assertEqual(result['SignInCoverage'][0]['Coverage']['ByEventType'],{'interactiveUser':{'RecordCount':2}})

    def test_ambiguous_directory_object_never_chooses_app(self):
        self.inventory['DirectoryObjects'].append({'AppId':CLIENT,'ServicePrincipalObjectId':OBJECT})
        result,_=self.build(signins=[self.signins])
        self.assertIn('MissingOrAmbiguousDirectoryObjectMapping',result['Identifiers']['ServicePrincipalObjectId:'+OBJECT]['ReviewReasons'])
        self.assertFalse(any(x['Evidence']=='DirectoryMappedTargetNotApiAccess' for x in result['Identifiers']['AppId:'+RESOURCE]['ObservedSignIn']))

    def test_context_mismatch_cannot_join_signins_or_flow_success(self):
        wrong=copy.deepcopy(self.signins);wrong['TenantFingerprint']='c'*64
        with self.assertRaisesRegex(ValueError,'context'):
            self.build(signins=[wrong])
        flow={'Format':'TokenForgeFlowEvidence','SchemaVersion':1,'Attempts':[{'ClientId':CLIENT,'ResourceId':RESOURCE,'TenantFingerprint':'c'*64,'PrincipalFingerprint':PRINCIPAL,'Outcome':'Succeeded'}]}
        result,_=self.build(flows=[flow]);self.assertIn('FlowContextMismatchExcluded',result['Notices'])
        self.assertFalse(result['Identifiers']['AppId:'+CLIENT]['SuccessfulTokenIssuance'])

    def test_partial_coverage_not_relabeled_complete(self):
        self.signins.update(Enumeration='Partial',EventTypes=['interactiveUser'])
        result,_=self.build(signins=[self.signins]);self.assertIn('PartialSignInCoverage',result['Notices'])
        self.assertFalse(result['SignInCoverage'][0]['AllFourEventTypesRequested'])

    def test_privacy_allowlist_drops_raw_events_tokens_and_unknown_coverage(self):
        self.inventory['AccessToken']='private-secret-token'
        self.inventory['Applications'][0]['Credential']='private-secret-token'
        self.signins.update(RawEvents=[{'userPrincipalName':'private-user','accessToken':'private-secret-token'}],Coverage={'Password':'private-secret-token','RetentionAvailability':'Unknown_NotEstablishedByQueryCompletion'})
        result,queue=self.build(signins=[self.signins]);raw=m.encoded([result,queue]).decode()
        self.assertNotIn('private-secret-token',raw);self.assertNotIn('private-user',raw);self.assertNotIn('RawEvents',raw)

    def test_directory_owner_signin_issuance_and_api_are_separate(self):
        attempt={'ClientId':CLIENT,'ResourceId':RESOURCE,'TenantFingerprint':TENANT,'PrincipalFingerprint':PRINCIPAL,'Outcome':'Succeeded','NamespaceVerification':'Matched','RequestVerification':'Matched','ClaimsReadable':True,'Protocol':'OAuth2V2Pkce','ObservedAt':'2026-11-01T00:00:00Z'}
        flow={'Format':'TokenForgeFlowEvidence','SchemaVersion':1,'Attempts':[attempt]}
        result,_=self.build(signins=[self.signins],flows=[flow]);client=result['Identifiers']['AppId:'+CLIENT]
        self.assertEqual(client['MicrosoftOwnership'],'DirectoryVerified');self.assertTrue(client['ObservedSignIn']);self.assertTrue(client['SuccessfulTokenIssuance']);self.assertFalse(client['VerifiedApiAccess'])

    def test_api_unknown_audience_is_not_filled_from_resource(self):
        proof={'TenantFingerprint':TENANT,'PrincipalFingerprint':PRINCIPAL,'ClientAppId':CLIENT,'ResourceAppId':RESOURCE,'Audience':None,'Method':'GET','Endpoint':'https://graph.microsoft.com/v1.0/me','StatusCode':200,'ObservedAt':None,'SourceSha256':'c'*64,'ContextVerified':True,'SourceBindings':{'Plan':'d'*64}}
        proof['SourceSha256']=m.sha(json.dumps(proof['SourceBindings'],sort_keys=True,separators=(',', ':')).encode())
        result,_=self.build(api_evidence=[{'Format':'TokenForgePrivateApiAccessProofs','SchemaVersion':1,'Proofs':[proof]}]);client=result['Identifiers']['AppId:'+CLIENT]
        self.assertTrue(client['VerifiedApiAccess']);self.assertIsNone(client['VerifiedApiAccess'][0]['Audience']);self.assertFalse(any(x.startswith('ObservedAudience:') for x in result['Identifiers']))

    def test_positive_role_aaguid_sku_and_permission_facts(self):
        definitions={'Format':'TokenForgeIdentifierDefinitions','SchemaVersion':1,'Definitions':[{'Kind':kind,'Id':identifier,'Label':kind+' fixture','Source':'https://example.test/definitions','SourceSha256':'a'*64,'Evidence':'PinnedFixtureDefinition'} for kind,identifier in [('DirectoryRole','55555555-5555-5555-5555-555555555555'),('AAGUID','66666666-6666-6666-6666-666666666666'),('SKU','77777777-7777-7777-7777-777777777777')]]}
        result,_=self.build(definitions=[definitions]);self.assertEqual(sum(x['Classification']=='KnownNonAppIdentifier' for x in result['Identifiers'].values()),4)
        self.assertFalse(result['Identifiers']['AppId:'+CLIENT]['VerifiedApiAccess'])

    def test_unknown_identifier_does_not_become_app_and_projection_reproducible(self):
        self.ledger['Applications']['88888888-8888-8888-8888-888888888888']={'Records':{}}
        a=self.build();b=self.build();self.assertEqual(m.encoded(a),m.encoded(b))
        self.assertEqual(a[0]['Identifiers']['AppId:88888888-8888-8888-8888-888888888888']['Classification'],'Unresolved')


    def test_directory_presence_does_not_invent_client_role(self):
        result,_=self.build()
        client=result['Identifiers']['AppId:'+CLIENT]
        self.assertEqual(client['Classification'],'MicrosoftOwnedApplicationRoleUnresolved')
        self.assertNotIn('ClientApplication',client['Kinds'])

    def test_missing_directory_entry_cannot_upgrade_resource_or_alias_hint(self):
        self.inventory['Applications'][0].update(Registration='Missing',IsResourceCandidate=True,IdentifierUris=['https://published.example.test/resource'])
        result,_=self.build()
        client=result['Identifiers']['AppId:'+CLIENT]
        self.assertNotIn('ApiResource',client['Kinds'])
        alias=result['Identifiers']['ResourceIdentifier:https://published.example.test/resource']
        self.assertEqual(alias['Relationships'][0]['Kind'],'PublishedResourceIdentifierHint')

    def test_private_app_and_positive_nonapp_fact_remain_conflicting(self):
        self.graph['Permissions']['delegatedScopesList'][0]['id']=RESOURCE
        result,_=self.build()
        self.assertEqual(result['Identifiers']['AppId:'+RESOURCE]['Classification'],'ConflictingAppAndNonAppEvidence')

    def test_missing_principal_context_excludes_flow_and_api_success(self):
        self.inventory['PrincipalFingerprint']=None
        flow={'Format':'TokenForgeFlowEvidence','SchemaVersion':1,'Attempts':[{'ClientId':CLIENT,'ResourceId':RESOURCE,'TenantFingerprint':TENANT,'PrincipalFingerprint':PRINCIPAL,'Outcome':'Succeeded'}]}
        result,_=self.build(flows=[flow]);self.assertIn('FlowContextMismatchExcluded',result['Notices'])
        self.assertFalse(result['Identifiers']['AppId:'+CLIENT]['SuccessfulTokenIssuance'])

    def test_legacy_resource_and_bounded_coverage_survive_without_type_promotion(self):
        self.signins['Applications'][0]['ResourceCounts']=[{'Value':OBJECT,'Count':2}]
        self.signins['Coverage']={'ByEventType':{'interactiveUser':{'RecordCount':2,'FirstObservedAt':'2026-10-01T00:00:00Z','LastObservedAt':'2026-10-01T12:00:00Z','RawToken':'secret'}}}
        result,_=self.build(signins=[self.signins])
        self.assertIn('LegacyResourceIdNamespaceUnmapped',result['Identifiers']['SignInResourceId:'+OBJECT]['ReviewReasons'])
        self.assertEqual(result['SignInCoverage'][0]['Coverage']['ByEventType']['interactiveUser']['RecordCount'],2)
        self.assertNotIn('secret',m.encoded(result).decode())

    def test_compound_api_proof_digest_mismatch_refused(self):
        proof={'TenantFingerprint':TENANT,'PrincipalFingerprint':PRINCIPAL,'ClientAppId':CLIENT,'ResourceAppId':RESOURCE,'Audience':None,'Method':'GET','Endpoint':'https://graph.microsoft.com/v1.0/me','StatusCode':200,'ObservedAt':None,'SourceSha256':'c'*64,'ContextVerified':True,'SourceBindings':{'Plan':'d'*64}}
        with self.assertRaisesRegex(ValueError,'compound'):
            self.build(api_evidence=[{'Format':'TokenForgePrivateApiAccessProofs','SchemaVersion':1,'Proofs':[proof]}])

    def test_duplicate_json_and_linked_inputs_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            p=Path(directory)/'duplicate.json';p.write_text('{"id":1,"id":2}')
            with self.assertRaisesRegex(ValueError,'Duplicate'):
                m.read(p)
            link=Path(directory)/'link.json';link.symlink_to(p)
            with self.assertRaisesRegex(ValueError,'unlinked'):
                m.read(link)


if __name__=='__main__':unittest.main(verbosity=2)
