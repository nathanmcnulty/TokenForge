BeforeAll {
 Import-Module "$PSScriptRoot/../src/TokenForge/TokenForge.psd1" -Force
 function New-ChangeFixture([string]$Type='IssuedScopes',[string]$Date='2026-01-02T00:00:00.0000000+00:00') {
  $context=@{ContextVersion=1;QueryFingerprint=('a'*64)}
  $identity=@{};$value=@{};$privacy='Public'
  switch($Type){
   PermissionDefinition {$context.ResourceId='00000003-0000-0000-c000-000000000000';$identity=@{Id='11111111-1111-1111-1111-111111111111';PermissionType='Delegated';Origin='PublicPublished'};$value=@{Name='User.Read';Enabled=$true}}
   PublicHint {$identity=@{ClientId='11111111-1111-1111-1111-111111111111'};$value=@{Grants=@(@{ResourceId='00000003-0000-0000-c000-000000000000';Scopes=@('User.Read')});CallbackFingerprints=@('c'*64);MetadataSha256=('d'*64);Conflicts=@()}}
   ConfiguredGrant {$privacy='Private';$context.TenantFingerprint='a'*64;$context.ObserverFingerprint='b'*64;$identity=@{ClientId='11111111-1111-1111-1111-111111111111';ResourceId='00000003-0000-0000-c000-000000000000';GrantType='AllPrincipals';SubjectFingerprint=$null};$value=@{Scopes=@('User.Read','Mail.Read')}}
   default {$privacy='Private';$context.TenantFingerprint='a'*64;$context.PrincipalFingerprint='b'*64;$context.ClientId='11111111-1111-1111-1111-111111111111';$context.ResourceId='00000003-0000-0000-c000-000000000000';$context.AuthorityFingerprint='c'*64;$context.RequestedScopes=@('.default');$context.Protocol='OAuth2V2Pkce';$context.CallbackFingerprint='d'*64;$context.CallbackClass='Native';$context.Spa=$false;$context.RecipeFingerprint='e'*64;$context.ExecutionPolicyFingerprint='f'*64;$identity=@{ClientId=$context.ClientId;ResourceId=$context.ResourceId}
    if($Type -eq 'ApiAcceptance'){$context.OperationFingerprint='1'*64;$context.Method='GET';$context.ApiVersion='v1.0';$context.ApprovalFingerprint='2'*64;$value=@{Status=200;Accepted=$true}}
    else{$value=@{Scopes=@('User.Read','Mail.Read');NamespaceVerification='Matched';RequestVerification='Matched';ClaimsReadable=$true;HasScpClaim=$true;SignatureValidated=$false}}
   }
  }
  $outcome=if($Type -eq 'IssuedScopes'){'Succeeded'}elseif($Type -eq 'ApiAcceptance'){'Responded'}else{'Observed'}
  @{Format='TokenForgeChangeSnapshot';SchemaVersion=1;Collections=@(@{EvidenceType=$Type;Privacy=$privacy;Status='Complete';Context=$context;Source=@{Id='synthetic-source';Location=('urn:sha256:'+('0'*64));ContentSha256=('0'*64);HashKind='NormalizedDocument';SourceObservedAt=$null;CollectedAt=([DateTimeOffset]$Date).AddHours(1).ToString('o')};Records=@(@{RecordId=('1'*64);ObservedAt=$Date;Outcome=$outcome;Identity=$identity;Value=$value})})}
 }
 function Copy-ChangeFixture($Object){[TokenForge.Core.DiscoverySourceClaims]::ReadMetadataJson(($Object|ConvertTo-Json -Depth 40 -Compress))}
 function Compare-ChangeFixture($Before,$After){[TokenForge.Core.DiscoverySourceClaims]::ReadMetadataJson([TokenForge.Core.ChangeReports]::Compare(($Before|ConvertTo-Json -Depth 40 -Compress),($After|ConvertTo-Json -Depth 40 -Compress),24,[DateTimeOffset]'2026-01-02T01:00:00Z',$false))}
}
Describe 'Goal 2 typed comparable evidence changes' {
 It 'treats first issued evidence as a baseline, never as newly available scopes' {
  $after=New-ChangeFixture;$before=Copy-ChangeFixture $after;$before.Collections=@()
  $r=Compare-ChangeFixture $before $after
  $r.Entries[0].EventType|Should -Be Baseline
  $r.Entries[0].AddedScopes.Count|Should -Be 0
  $r.Entries[0].RemovedScopes.Count|Should -Be 0
 }
 It 'distinguishes stable-ID rename from definition addition/removal' {
  $before=New-ChangeFixture PermissionDefinition;$after=Copy-ChangeFixture $before;$after.Collections[0].Records[0].Value.Name='User.Read.Basic'
  $r=Compare-ChangeFixture $before $after
  $r.Entries[0].EventType|Should -Be DefinitionRenamed
  $r.Entries[0].Identity.Id|Should -Be '11111111-1111-1111-1111-111111111111'
 }
 It 'detects a definition absent from an equivalent complete visible vocabulary' {
  $before=New-ChangeFixture PermissionDefinition;$after=Copy-ChangeFixture $before;$after.Collections[0].Records=@()
  (Compare-ChangeFixture $before $after).Entries[0].EventType|Should -Be DefinitionRemoved
 }
 It 'keeps source conflicts and public hints separate from configured authorization' {
  $before=New-ChangeFixture PublicHint;$after=Copy-ChangeFixture $before;$after.Collections[0].Records[0].Value.Conflicts=@(@{Field='Name';ValueHashes=@(('3'*64),('4'*64))})
  $e=(Compare-ChangeFixture $before $after).Entries[0]
  $e.EventType|Should -Be PublicHintChanged
  $e.EvidenceType|Should -Be PublicHint
  $e.After.LatestValue.Conflicts.Count|Should -Be 1
 }
 It 'reports changed visible grant scopes in the same observer and beneficiary context' {
  $before=New-ChangeFixture ConfiguredGrant;$after=Copy-ChangeFixture $before;$after.Collections[0].Records[0].Value.Scopes=@('User.Read')
  $e=(Compare-ChangeFixture $before $after).Entries[0]
  $e.EventType|Should -Be ConfiguredGrantChanged
  $e.RemovedScopes|Should -Contain 'Mail.Read'
 }
 It 'does not compare grants observed by different accounts' {
  $before=New-ChangeFixture ConfiguredGrant;$after=Copy-ChangeFixture $before;$after.Collections[0].Context.ObserverFingerprint='5'*64;$after.Collections[0].Records=@()
  $e=(Compare-ChangeFixture $before $after).Entries[0]
  $e.EventType|Should -Be Incomparable
  $e.RemovedScopes.Count|Should -Be 0
 }
 It 'reports an inspected-scope change only for a fully matching successful request' {
  $before=New-ChangeFixture;$after=Copy-ChangeFixture $before;$after.Collections[0].Records[0].Value.Scopes=@('User.Read')
  $e=(Compare-ChangeFixture $before $after).Entries[0]
  $e.EventType|Should -Be MatchedRequestScopesChanged
  $e.RemovedScopes|Should -Contain Mail.Read
  $e.RootCauseEstablished|Should -BeFalse
  $e.RegressionConfirmation|Should -Be NotPerformed
 }
 It 'refuses false removal for changed request field <Field>' -TestCases @(@{Field='RecipeFingerprint'},@{Field='ExecutionPolicyFingerprint'},@{Field='AuthorityFingerprint'},@{Field='CallbackFingerprint'},@{Field='PrincipalFingerprint'},@{Field='RequestedScopes'},@{Field='Protocol'},@{Field='Spa'}) {
  param($Field)
  $before=New-ChangeFixture;$after=Copy-ChangeFixture $before
  $after.Collections[0].Context[$Field]=switch($Field){RequestedScopes {,@('User.Read')} Protocol {'OAuth2V2Implicit'} Spa {$true} default {'7'*64}}
  $after.Collections[0].Records[0].Value.Scopes=@('User.Read')
  $e=(Compare-ChangeFixture $before $after).Entries[0]
  $e.EventType|Should -Be Incomparable
  $e.RemovedScopes.Count|Should -Be 0
 }
 It 'does not infer removal from <Status> collection visibility' -TestCases @(@{Status='Incomplete'},@{Status='Denied'},@{Status='Failed'},@{Status='NotCollected'},@{Status='Unknown'}) {
  param($Status)
  $before=New-ChangeFixture ConfiguredGrant;$after=Copy-ChangeFixture $before;$after.Collections[0].Status=$Status;$after.Collections[0].Records=@()
  $e=(Compare-ChangeFixture $before $after).Entries[0]
  $e.EventType|Should -BeIn @('LostVisibility','Unknown','Incomparable')
  $e.RemovedScopes.Count|Should -Be 0
 }
 It 'reports missing collections as lost visibility, preserving last success and dates' {
  $before=New-ChangeFixture;$after=Copy-ChangeFixture $before;$after.Collections=@()
  $e=(Compare-ChangeFixture $before $after).Entries[0]
  $e.EventType|Should -Be LostVisibility
  $e.LastKnownSuccess.ObservedAt|Should -Be '2026-01-02T00:00:00.0000000+00:00'
  $e.RemovedScopes.Count|Should -Be 0
 }
 It 'retains last successful scopes alongside a newer failed attempt and recovery' {
  $before=New-ChangeFixture;$after=Copy-ChangeFixture $before
  $failure=Copy-ChangeFixture $after.Collections[0].Records[0];$failure.RecordId='2'*64;$failure.ObservedAt='2026-01-02T00:30:00.0000000+00:00';$failure.Outcome='Failed';$failure.Value.Scopes=@()
  $after.Collections[0].Records+=@($failure)
  $e=(Compare-ChangeFixture $before $after).Entries[0]
  $e.AfterOutcome|Should -Be Failed
  $e.LastKnownSuccess.Value.Scopes|Should -Contain Mail.Read
  $e.LastKnownSuccess.ObservedAt|Should -Be '2026-01-02T00:00:00.0000000+00:00'
  $e.RemovedScopes.Count|Should -Be 0
  $recovered=Copy-ChangeFixture $after;$success=Copy-ChangeFixture $before.Collections[0].Records[0];$success.RecordId='3'*64;$success.ObservedAt='2026-01-02T00:45:00.0000000+00:00';$recovered.Collections[0].Records+=@($success)
  $r=(Compare-ChangeFixture $after $recovered).Entries[0]
  $r.BeforeOutcome|Should -Be Failed
  $r.AfterOutcome|Should -Be Succeeded
  $r.AddedScopes.Count|Should -Be 0
 }
 It 'keeps stale after-evidence from manufacturing removals' {
  $before=New-ChangeFixture -Date '2025-12-01T00:00:00.0000000+00:00';$after=Copy-ChangeFixture $before;$after.Collections[0].Records[0].Value.Scopes=@('User.Read')
  $e=(Compare-ChangeFixture $before $after).Entries[0]
  $e.EventType|Should -Be Stale
  $e.RemovedScopes.Count|Should -Be 0
 }
 It 'separates optional API response changes from issuance and consent' {
  $before=New-ChangeFixture ApiAcceptance;$after=Copy-ChangeFixture $before;$after.Collections[0].Records[0].Value=@{Status=403;Accepted=$false}
  $e=(Compare-ChangeFixture $before $after).Entries[0]
  $e.EventType|Should -Be ApiAcceptanceChanged
  $e.RemovedScopes.Count|Should -Be 0
 }
 It 'rejects credential and unknown fields rather than copying them into reports' {
  $before=New-ChangeFixture;$after=Copy-ChangeFixture $before;$after.Collections[0].Records[0].Value.AccessToken='synthetic-private-cookie'
  {Compare-ChangeFixture $before $after}|Should -Throw '*Change evidence*'
 }
 It 'rejects duplicate record identities and duplicate JSON keys' {
  $before=New-ChangeFixture;$after=Copy-ChangeFixture $before;$after.Collections[0].Records+=@(Copy-ChangeFixture $after.Collections[0].Records[0])
  {Compare-ChangeFixture $before $after}|Should -Throw '*Change evidence*'
  {[TokenForge.Core.ChangeReports]::Compare('{"Format":"TokenForgeChangeSnapshot","SchemaVersion":1,"SchemaVersion":1,"Collections":[]}','{}',24,[DateTimeOffset]'2026-01-02T01:00:00Z',$false)}|Should -Throw '*Change evidence*'
 }
}

Describe 'Goal 2 adverse chronology and coverage' {
 It 'never removes an unknown prior definition' {
  $b=New-ChangeFixture PermissionDefinition;$b.Collections[0].Records[0].Outcome='Unknown';$a=Copy-ChangeFixture $b;$a.Collections[0].Records=@()
  (Compare-ChangeFixture $b $a).Entries[0].EventType|Should -Not -Be DefinitionRemoved
 }
 It 'rejects a purported verified scope success with zero scopes' {
  $b=New-ChangeFixture;$a=Copy-ChangeFixture $b;$a.Collections[0].Records[0].Value.Scopes=@()
  {Compare-ChangeFixture $b $a}|Should -Throw '*Change evidence*'
 }
 It 'does not order conflicting simultaneous history by array order' {
  $b=New-ChangeFixture;$a=Copy-ChangeFixture $b;$other=Copy-ChangeFixture $a.Collections[0].Records[0];$other.RecordId='8'*64;$other.Value.Scopes=@('User.Read');$a.Collections[0].Records+=@($other)
  $first=Compare-ChangeFixture $b $a;$a.Collections[0].Records=@($a.Collections[0].Records[1],$a.Collections[0].Records[0]);$second=Compare-ChangeFixture $b $a
  $first.Entries[0].EventType|Should -Be Unknown
  ($first|ConvertTo-Json -Depth 50 -Compress)|Should -Be ($second|ConvertTo-Json -Depth 50 -Compress)
  $first.Entries[0].RemovedScopes.Count|Should -Be 0
 }
 It 'refuses reversed observation chronology' {
  $b=New-ChangeFixture;$a=New-ChangeFixture -Date '2026-01-01T00:00:00Z';$a.Collections[0].Records[0].Value.Scopes=@('User.Read')
  (Compare-ChangeFixture $b $a).Entries[0].EventType|Should -Be Incomparable
 }
 It 'rejects observation dates after local collection' {
  $b=New-ChangeFixture;$a=Copy-ChangeFixture $b;$a.Collections[0].Records[0].ObservedAt='2026-01-03T00:00:00Z'
  {Compare-ChangeFixture $b $a}|Should -Throw '*Change evidence*'
 }
 It 'refuses observations later than the requested report instant' {
  $b=New-ChangeFixture;$a=Copy-ChangeFixture $b
  $r=[TokenForge.Core.DiscoverySourceClaims]::ReadMetadataJson([TokenForge.Core.ChangeReports]::Compare(($b|ConvertTo-Json -Depth 40 -Compress),($a|ConvertTo-Json -Depth 40 -Compress),24,[DateTimeOffset]'2026-01-01T23:00:00Z',$false))
  $r.Entries[0].EventType|Should -Be Unknown
 }
 It 'retains empty collection failure as explicit coverage evidence' {
  $b=New-ChangeFixture ConfiguredGrant;$b.Collections=@();$a=New-ChangeFixture ConfiguredGrant;$a.Collections[0].Status='Denied';$a.Collections[0].Records=@()
  $e=(Compare-ChangeFixture $b $a).Entries[0];$e.EventType|Should -Be Unknown;$e.Reasons.Count|Should -BeGreaterThan 0
 }
 It 'requires observer and tenant for private definition removals' {
  $b=New-ChangeFixture PermissionDefinition;$b.Collections[0].Privacy='Private';$b.Collections[0].Records[0].Identity.Origin='ServicePrincipal';$a=Copy-ChangeFixture $b;$a.Collections[0].Records=@()
  (Compare-ChangeFixture $b $a).Entries[0].EventType|Should -Be Incomparable
 }
 It 'rejects private definition origin in a public collection' {
  $b=New-ChangeFixture PermissionDefinition;$a=Copy-ChangeFixture $b;$a.Collections[0].Records[0].Identity.Origin='ServicePrincipal'
  {Compare-ChangeFixture $b $a}|Should -Throw '*Change evidence*'
 }
 It 'rejects public-only reporting of private or mixed input' {
  $a=New-ChangeFixture
  {[TokenForge.Core.ChangeReports]::Compare(($a|ConvertTo-Json -Depth 40 -Compress),($a|ConvertTo-Json -Depth 40 -Compress),24,[DateTimeOffset]'2026-01-02T01:00:00Z',$true)}|Should -Throw '*Change evidence*'
 }
}

Describe 'Goal 2 saved evidence adapters' {
 BeforeAll {
  $g='00000003-0000-0000-c000-000000000000';$c='11111111-1111-1111-1111-111111111111';$d='2026-01-02T00:00:00.0000000+00:00'
  function New-SavedScope {
   $f=New-ChangeFixture;$ctx=$f.Collections[0].Context;$r=$f.Collections[0].Records[0]
   @{SchemaVersion=1;UpdatedAt='2026-01-02T01:00:00Z';RegistrationAttempts=@();Observations=@(@{ClientId=$ctx.ClientId;ResourceId=$ctx.ResourceId;TenantFingerprint=$ctx.TenantFingerprint;PrincipalFingerprint=$ctx.PrincipalFingerprint;ObservedAt=$r.ObservedAt;Outcome=$r.Outcome;Protocol=$ctx.Protocol;Spa=$ctx.Spa;RedirectFingerprint=$ctx.CallbackFingerprint;RequestedScopes=$ctx.RequestedScopes;ScpScopes=$r.Value.Scopes;ResponseScopes=$r.Value.Scopes;ClaimsReadable=$true;HasScpClaim=$true;NamespaceVerification='Matched';RequestVerification='Matched';SignatureValidated=$false;ComparisonContext=$ctx})}
  }
  function New-SavedInventory {
   @{SchemaVersion=1;CapturedAt=$d;TenantFingerprint=('a'*64);PrincipalFingerprint=('b'*64);GrantEnumeration='Complete';EvidenceCoverage=@{SchemaVersion=1;InventoryQueryFingerprint=('c'*64);GrantQueryFingerprint=('d'*64)};Applications=@(@{AppId=$g;Registration='Present';Ownership='VerifiedMicrosoftOwner';DelegatedScopeDefinitions=@(@{Id=$c;Value='User.Read';Enabled=$true});AppRoleDefinitions=@()});TenantGrants=@(@{ClientId=$c;ResourceId=$g;Scopes=@('User.Read','Mail.Read');PrincipalFingerprint=$null;ConsentType='AllPrincipals';AppliesToCurrentPrincipal=$true;Evidence='TenantConfiguredGrant'})}
  }
  function New-PermissionSnapshot {
   $delegate=@{id=$c;value='User.Read';isAdmin=$false;isEnabled=$true;consentDescription=$null;consentDisplayName=$null;adminConsentDescription=$null;adminConsentDisplayName=$null}
   $role=@{id=$c;value='User.Read';isAdmin=$true;isEnabled=$true;consentDescription=$null;consentDisplayName=$null;allowedMemberTypes=@('Application')}
   @{Format='TokenForgePublicPermissions';SchemaVersion=1;Evidence='PublicSourceDefinitions';ResourceId=$g;RetrievedAt=$d;Source=@{Repository='https://github.com/microsoftgraph/microsoft-graph-devx-content';Path='permissions/permissions-descriptions.json';Commit=('1'*40);RawSha256=('2'*64)};Permissions=@{delegatedScopesList=@($delegate);applicationScopesList=@($role)}}
  }
 }
 It 'accepts the legacy local tenant verification source without inventing its URL or refreshing dates' {
  $i=New-SavedInventory;$i.Applications[0].Sources=@(@{Name='TenantDiscovery';Evidence='VerifiedMicrosoftOwner'})
  $snapshot=ConvertTo-TokenForgeChangeSnapshot $i -Kind Inventory
  $snapshot.Collections[0].Source.CollectedAt|Should -Be $i.CapturedAt
  $i.Applications[0].Sources[0].Contains('Location')|Should -BeFalse
 }
 It 'does not repair unknown or credential-bearing legacy source rows' -TestCases @(@{Case='UnknownSource'},@{Case='CredentialField'}) {
  param($Case)
  $i=New-SavedInventory;$i.Applications[0].Sources=@(@{Name='TenantDiscovery';Evidence='VerifiedMicrosoftOwner'})
  if($Case -eq 'UnknownSource'){$i.Applications[0].Sources[0].Name='OtherSource'}else{$i.Applications[0].Sources[0].AccessToken='synthetic-private'}
  {ConvertTo-TokenForgeChangeSnapshot $i -Kind Inventory}|Should -Throw '*Change evidence*'
 }
 It 'routes ordinary database comparison through exact request context' {
  $b=New-SavedScope;$a=Copy-ChangeFixture $b;$a.Observations[0].ScpScopes=@('User.Read')
  $e=@(Compare-TokenForgeScopeDatabase $b $a -AsOf ([DateTimeOffset]'2026-01-02T01:00:00Z'))[0]
  $e.EventType|Should -Be MatchedRequestScopesChanged;$e.RemovedScopes|Should -Contain Mail.Read
  $a.Observations[0].ComparisonContext.RecipeFingerprint='0'*64
  @(Compare-TokenForgeScopeDatabase $b $a -AsOf ([DateTimeOffset]'2026-01-02T01:00:00Z'))[0].EventType|Should -Be Incomparable
 }
 It 'keeps old database rows lacking execution provenance incomparable' {
  $b=New-SavedScope;$null=$b.Observations[0].Remove('ComparisonContext');$a=Copy-ChangeFixture $b;$a.Observations[0].ScpScopes=@('User.Read')
  @(Compare-TokenForgeScopeDatabase $b $a -AsOf ([DateTimeOffset]'2026-01-02T01:00:00Z'))[0].RemovedScopes.Count|Should -Be 0
 }
 It 'validates old unselected history before ordinary comparison' {
  $b=New-SavedScope;$a=Copy-ChangeFixture $b;$old=Copy-ChangeFixture $b.Observations[0];$old.ObservedAt='2025-01-01T00:00:00Z';$old.Cookie='synthetic-private';$a.Observations+=@($old)
  {Compare-TokenForgeScopeDatabase $b $a}|Should -Throw '*Change evidence*'
 }
 It 'binds persisted descriptors to namespace and actual requested scopes' {
  $b=New-SavedScope;$b.Observations[0].ComparisonContext.RequestedScopes=@('different')
  {ConvertTo-TokenForgeChangeSnapshot $b -Kind ScopeDatabase}|Should -Throw '*Change evidence*'
 }
 It 'compares resource definitions by stable ID and permission kind across revisions' {
  $b=New-PermissionSnapshot;$a=Copy-ChangeFixture $b;$a.Source.Commit='3'*40;$a.Source.RawSha256='4'*64;$a.Permissions.delegatedScopesList[0].value='User.Read.Basic'
  $r=Compare-TokenForgeEvidence $b $a -Kind PublicPermissions -AsOf ([DateTimeOffset]'2026-01-02T01:00:00Z')
  @($r.Entries|Where-Object EventType -eq DefinitionRenamed).Count|Should -Be 1
  @($r.Entries|Where-Object EventType -eq Unchanged).Count|Should -Be 1
  $r.Entries[0].Before.Source.SourceObservedAt|Should -BeNullOrEmpty
  $r.Entries[0].Before.Source.ContentSha256|Should -Be ('2'*64)
 }
 It 'rejects malformed public-source vocabulary before declaring complete' {
  $s=New-PermissionSnapshot;$s.Permissions.applicationScopesList[0].allowedMemberTypes=@('Application','Application')
  {ConvertTo-TokenForgeChangeSnapshot $s -Kind PublicPermissions}|Should -Throw '*Change evidence*'
 }
 It 'reports equivalent visible aggregate grant changes with beneficiary context' {
  $b=New-SavedInventory;$a=Copy-ChangeFixture $b;$a.TenantGrants[0].Scopes=@('User.Read')
  $r=Compare-TokenForgeEvidence $b $a -Kind Inventory -AsOf ([DateTimeOffset]'2026-01-02T01:00:00Z')
  $e=@($r.Entries|Where-Object EvidenceType -eq ConfiguredGrant)[0];$e.EventType|Should -Be ConfiguredGrantChanged;$e.RemovedScopes|Should -Contain Mail.Read
 }
 It 'does not infer definition removal from an inaccessible or unverified resource' -TestCases @(@{Registration='Missing'},@{Registration='OwnerMismatch'}) {
  param($Registration)
  $b=New-SavedInventory;$a=Copy-ChangeFixture $b;$a.Applications[0].Registration=$Registration;$a.Applications[0].DelegatedScopeDefinitions=@()
  $r=Compare-TokenForgeEvidence $b $a -Kind Inventory -AsOf ([DateTimeOffset]'2026-01-02T01:00:00Z')
  @($r.Entries|Where-Object EventType -eq DefinitionRemoved).Count|Should -Be 0
 }
 It 'does not treat missing inventory definition fields as empty vocabulary' {
  $b=New-SavedInventory;$a=Copy-ChangeFixture $b;$null=$a.Applications[0].Remove('DelegatedScopeDefinitions')
  $r=Compare-TokenForgeEvidence $b $a -Kind Inventory -AsOf ([DateTimeOffset]'2026-01-02T01:00:00Z')
  @($r.Entries|Where-Object EventType -eq DefinitionRemoved).Count|Should -Be 0
 }
 It 'keeps legacy inventory lacking exact observer query provenance incomparable' {
  $b=New-SavedInventory;$null=$b.Remove('EvidenceCoverage');$a=Copy-ChangeFixture $b;$a.TenantGrants=@()
  $r=Compare-TokenForgeEvidence $b $a -Kind Inventory -AsOf ([DateTimeOffset]'2026-01-02T01:00:00Z')
  @($r.Entries|Where-Object EventType -eq ConfiguredGrantRemoved).Count|Should -Be 0
 }
 It 'does not equate unknown Principal beneficiary with AllPrincipals' {
  $b=New-SavedInventory;$b.TenantGrants[0].ConsentType='Principal';$a=Copy-ChangeFixture $b;$a.TenantGrants=@()
  $r=Compare-TokenForgeEvidence $b $a -Kind Inventory -AsOf ([DateTimeOffset]'2026-01-02T01:00:00Z')
  @($r.Entries|Where-Object EventType -eq ConfiguredGrantRemoved).Count|Should -Be 0
 }
 It 'keeps anonymous observations incapable of private removals' {
  $b=@{SchemaVersion=1;Observations=@(@{ClientId=$c;ResourceId=$g;ObservedAt=$d;Scopes=@('User.Read','Mail.Read');Evidence='AnonymousTenantTokenObservation';SignatureValidated=$false})};$a=Copy-ChangeFixture $b;$a.Observations[0].Scopes=@('User.Read')
  $r=Compare-TokenForgeEvidence $b $a -Kind Anonymous -AsOf ([DateTimeOffset]'2026-01-02T01:00:00Z') -PublicOnly
  $r.Entries[0].EventType|Should -Be Incomparable;$r.Entries[0].RemovedScopes.Count|Should -Be 0
 }
 It 'preserves missing API operation context as incomparable' {
  $b=@{Format='TokenForgeApiChecks';SchemaVersion=1;CollectedAt=$d;Checks=@(@{ResourceId=$g;Status=200;Accepted=$true;Evidence='ReadOnlyApiResponse';CheckedAt=$d})};$a=Copy-ChangeFixture $b;$a.Checks[0].Status=403;$a.Checks[0].Accepted=$false
  (Compare-TokenForgeEvidence $b $a -Kind ApiChecks -AsOf ([DateTimeOffset]'2026-01-02T01:00:00Z')).Entries[0].EventType|Should -Be Incomparable
 }
 It 'compares saved approved API operation while keeping issuance separate' {
  $f=New-ChangeFixture ApiAcceptance;$b=@{Format='TokenForgeApiChecks';SchemaVersion=1;CollectedAt=$d;Checks=@(@{ResourceId=$g;Status=200;Accepted=$true;Evidence='ReadOnlyApiResponse';CheckedAt=$d;ComparisonContext=$f.Collections[0].Context})};$a=Copy-ChangeFixture $b;$a.Checks[0].Status=403;$a.Checks[0].Accepted=$false
  (Compare-TokenForgeEvidence $b $a -Kind ApiChecks -AsOf ([DateTimeOffset]'2026-01-02T01:00:00Z')).Entries[0].EventType|Should -Be ApiAcceptanceChanged
 }
}

Describe 'Goal 2 real discovery and maintenance histories' {
 BeforeAll {
  function New-SourceClaim([string]$Scope='User.Read',[string]$Name='Example') {
   @{SourceName='MicrosoftApps';Location='LocalMicrosoftApps';Evidence='PublishedMetadata';Name=$Name;Grants=@(@{ResourceId='00000003-0000-0000-c000-000000000000';Scopes=@($Scope)});RedirectUris=@('https://example.test/callback')}
  }
  function New-DiscoveryEvidence($Claims) {
   $id='11111111-1111-1111-1111-111111111111';$normalized=[TokenForge.Core.DiscoverySourceClaims]::NormalizeMetadata(($Claims|ConvertTo-Json -Depth 20 -Compress -AsArray),$id)
   @{SchemaVersion=2;FetchedAt='2026-01-02T00:00:00Z';InvalidSourceRecordCount=0;Applications=@(@{AppId=$id;Sources=@();SourceClaims=$normalized.SourceClaims;MetadataConflicts=$normalized.MetadataConflicts})}
  }
 }
 It 'aggregates conflicting claims from a source without order-dependent latest selection' {
  $claims=@((New-SourceClaim User.Read First),(New-SourceClaim Mail.Read Second));$b=New-DiscoveryEvidence $claims;$a=Copy-ChangeFixture $b;$a.Applications[0].SourceClaims=@($a.Applications[0].SourceClaims[1],$a.Applications[0].SourceClaims[0])
  # Normalize order is part of source-claim validation, so independently normalize the reordered source.
  $normal=[TokenForge.Core.DiscoverySourceClaims]::NormalizeMetadata(($a.Applications[0].SourceClaims|ConvertTo-Json -Depth 20 -Compress -AsArray),$a.Applications[0].AppId);$a.Applications[0].SourceClaims=$normal.SourceClaims;$a.Applications[0].MetadataConflicts=$normal.MetadataConflicts
  $r=Compare-TokenForgeEvidence $b $a -Kind Discovery -AsOf ([DateTimeOffset]'2026-01-02T01:00:00Z')
  $r.Entries.Count|Should -Be 1;$r.Entries[0].EventType|Should -Be Unchanged
  $r.Entries[0].After.LatestValue.Grants[0].Scopes.Count|Should -Be 2
  $r.Entries[0].After.LatestValue.Conflicts.Count|Should -Be 1
 }
 It 'detects changed source-specific claims without labelling them consent' {
  $b=New-DiscoveryEvidence @((New-SourceClaim));$a=New-DiscoveryEvidence @((New-SourceClaim Mail.Read))
  $e=(Compare-TokenForgeEvidence $b $a -Kind Discovery -AsOf ([DateTimeOffset]'2026-01-02T01:00:00Z')).Entries[0]
  $e.EventType|Should -Be PublicHintChanged;$e.RemovedScopes.Count|Should -Be 0
 }
 It 'does not remove a source claim when a mixed legacy projection is missing' {
  $b=New-DiscoveryEvidence @((New-SourceClaim));$second=Copy-ChangeFixture $b.Applications[0];$second.AppId='22222222-2222-2222-2222-222222222222';$b.Applications+=@($second)
  $a=Copy-ChangeFixture $b;$null=$a.Applications[0].Remove('SourceClaims');$null=$a.Applications[0].Remove('MetadataConflicts')
  @((Compare-TokenForgeEvidence $b $a -Kind Discovery -AsOf ([DateTimeOffset]'2026-01-02T01:00:00Z')).Entries|Where-Object EventType -eq PublicHintRemoved).Count|Should -Be 0
 }
 It 'does not manufacture hint removal from invalid source records' {
  $b=New-DiscoveryEvidence @((New-SourceClaim));$a=Copy-ChangeFixture $b;$a.InvalidSourceRecordCount=1;$a.Applications=@()
  @((Compare-TokenForgeEvidence $b $a -Kind Discovery -AsOf ([DateTimeOffset]'2026-01-02T01:00:00Z')).Entries|Where-Object EventType -eq PublicHintRemoved).Count|Should -Be 0
 }
 It 'retains maintenance intervals and latest failed collection separately' {
  $catalog=@{Format='TokenForgeApplicationMetadata';SchemaVersion=2;CreatedAt='2026-01-01T00:00:00Z';UpdatedAt='2026-01-02T00:00:00Z';Applications=@{};Origins=@{};Runs=@()}
  $grant=@{ClientId='11111111-1111-1111-1111-111111111111';ResourceId='00000003-0000-0000-c000-000000000000';Scopes=@('User.Read');PrincipalFingerprint=$null;ConsentType='AllPrincipals';AppliesToCurrentPrincipal=$true;Evidence='TenantConfiguredGrant'}
  $payload=@{SchemaVersion=1;Context=('private-maintenance/v1/'+('a'*64)+'/'+('b'*64));Metadata=$catalog;GrantHistory=@(@{FirstSeenAt='2026-01-01T00:00:00Z';LastSeenAt='2026-01-02T00:00:00Z';Grants=@($grant)},@{FirstSeenAt='2026-01-03T00:00:00Z';LastSeenAt='2026-01-04T00:00:00Z';Grants=@($grant)});LastRun=@{StartedAt='2026-01-05T00:00:00Z';FinishedAt='2026-01-05T01:00:00Z';Discovery='Complete';Inventory='Complete';Grants='Forbidden';SignIns='Skipped';SignInSince='2026-01-01T00:00:00Z';SignInUntil='2026-01-05T00:00:00Z';SignInMaxPages=20;Registration='NotRun';Status='Partial'}}
  $s=ConvertTo-TokenForgeChangeSnapshot $payload -Kind Maintenance
  $s.Collections[0].Records.Count|Should -Be 2;$s.Collections[0].Status|Should -Be Denied
  $r=Compare-TokenForgeEvidence $s $s -AsOf ([DateTimeOffset]'2026-01-05T01:00:00Z')
  $r.Entries[0].LastKnownSuccess.ObservedAt|Should -Be '2026-01-04T00:00:00Z'
  $r.Entries[0].FirstCollectedObservationAt|Should -Be '2026-01-01T00:00:00Z'
  $r.Entries[0].After.Source.CollectedAt|Should -Be '2026-01-05T01:00:00Z'
  $r.Entries[0].RemovedScopes.Count|Should -Be 0
 }
}

Describe 'Goal 2 new bounded producer comparison receipt' {
 BeforeEach {
  $state=Join-Path $TestDrive ([guid]::NewGuid().ToString());$null=New-Item -ItemType Directory $state
  if(-not $IsWindows){[IO.File]::SetUnixFileMode($state,[IO.UnixFileMode]448)}
  $path=Join-Path $state scopes.json;$flow="$path.flows.json"
  $graph='00000003-0000-0000-c000-000000000000';$client='11111111-1111-1111-1111-111111111111'
  $inventory=[pscustomobject]@{TenantFingerprint=('a'*64);PrincipalFingerprint=('b'*64);DiscoveryCatalogHash=('c'*64);Applications=@([pscustomobject]@{AppId=$client;Registration='Present';Ownership='VerifiedMicrosoftOwner';AccountEnabled=$true;RedirectUris=@('https://login.microsoftonline.com/common/oauth2/nativeclient');PreferredRedirectUri='https://login.microsoftonline.com/common/oauth2/nativeclient';IdentifierUris=@()})}
  $budget=& (Get-Module TokenForge) {New-TokenForgeOperationBudget}
  $secret=ConvertTo-SecureString synthetic -AsPlainText -Force
  Mock Get-TokenForgeToken -ModuleName TokenForge {param($Request) [pscustomobject]@{AccessToken=ConvertTo-SecureString synthetic -AsPlainText -Force;RefreshToken=$null;GrantedScopes=@('User.Read');TokenClaims=[pscustomobject]@{Readable=$true;HasDelegatedScopeClaim=$true;Scopes=@('User.Read');TenantFingerprint=('a'*64);PrincipalFingerprint=('b'*64);ClientId=$Request.ClientId;Audience=$Request.ResourceId}}}
 }
 AfterEach {$secret.Dispose()}
 It 'persists actual OAuth request scopes and policy without changing resume identity' {
  $options=@{Inventory=$inventory;EstsAuth=$secret;ResourceId=$graph;DatabasePath=$path;Protocols=@('OAuth2V2Pkce');DelayMilliseconds=0;OperationBudget=$budget}
  $null=Invoke-TokenForgeScopeProbe @options
  $flows=Get-TokenForgeFlowEvidence $flow;$attempt=$flows.Attempts[0]
  $attempt.ComparisonContext.RequestedScopes|Should -Contain "$graph/.default"
  $attempt.ComparisonContext.RequestedScopes|Should -Contain offline_access
  $attempt.ComparisonContext.ExecutionPolicyFingerprint|Should -Match '^[a-f0-9]{64}$'
  $scope=Get-TokenForgeScopeDatabase $path
  $scope.Observations[0].RequestedScopes.Count|Should -Be 2
  $snapshot=ConvertTo-TokenForgeChangeSnapshot $flows -Kind FlowEvidence
  $comparison=Compare-TokenForgeEvidence $snapshot $snapshot
  $comparison.Entries[0].EventType|Should -Be Unchanged
  $before=(Get-FileHash $flow).Hash;$null=Invoke-TokenForgeScopeProbe @options
  (Get-FileHash $flow).Hash|Should -Be $before
  Should -Invoke Get-TokenForgeToken -ModuleName TokenForge -Times 1 -Exactly
  $meta=Join-Path $state applications.json
  $null=Update-TokenForgeApplicationMetadata $meta $flows FlowAttempts
  $null=Update-TokenForgeApplicationMetadata $meta $scope ScopeObservations
  [TokenForge.Core.ApplicationCatalogPolicy]::ValidateDocument([IO.File]::ReadAllText($meta))
 }
 It 'keeps comparison context immutable from Started intent through terminal evidence' -TestCases @(@{Case='Changed'},@{Case='Removed'},@{Case='AddedToLegacy'}) {
  param($Case)
  $null=Invoke-TokenForgeScopeProbe $inventory $secret -ResourceId $graph -DatabasePath $path -Protocols OAuth2V2Pkce -DelayMilliseconds 0 -OperationBudget $budget
  $flows=Get-TokenForgeFlowEvidence $flow;$terminal=$flows.Attempts[0].Clone();$started=$terminal.Clone();$started.Outcome='Started';$started.ObservedAt=$started.StartedAt
  if($Case -eq 'AddedToLegacy'){$null=$started.Remove('ComparisonContext')}
  $flows.Attempts=@($started);[IO.File]::WriteAllText($flow,(ConvertTo-Json -InputObject $flows -Depth 30))
  if($Case -eq 'Changed'){$terminal.ComparisonContext=$terminal.ComparisonContext.Clone();$terminal.ComparisonContext.RecipeFingerprint='9'*64}
  if($Case -eq 'Removed'){$null=$terminal.Remove('ComparisonContext')}
  $prior=(Get-FileHash $flow).Hash
  {& (Get-Module TokenForge) {param($p,$a)Save-TokenForgeFlowEvidence $p -Attempt $a} $flow $terminal}|Should -Throw '*Immutable flow comparison context*'
  (Get-FileHash $flow).Hash|Should -Be $prior
 }
 It 'keeps old flow history without the request descriptor incomparable' {
  $null=Invoke-TokenForgeScopeProbe $inventory $secret -ResourceId $graph -DatabasePath $path -Protocols OAuth2V2Pkce -DelayMilliseconds 0
  $flows=Get-TokenForgeFlowEvidence $flow
  $snapshot=ConvertTo-TokenForgeChangeSnapshot $flows -Kind FlowEvidence
  (Compare-TokenForgeEvidence $snapshot $snapshot).Entries[0].EventType|Should -Be Incomparable
 }
}

Describe 'Goal 2 chronology preserves the latest failed outcome across all request history' {
 It 'does not remove a definition after unknown latest prior evidence' {
  $b=New-ChangeFixture PermissionDefinition;$unknown=Copy-ChangeFixture $b.Collections[0].Records[0];$unknown.RecordId='9'*64;$unknown.ObservedAt='2026-01-02T00:30:00Z';$unknown.Outcome='Unknown';$b.Collections[0].Records+=@($unknown)
  $a=Copy-ChangeFixture $b;$a.Collections[0].Records=@()
  (Compare-ChangeFixture $b $a).Entries[0].EventType|Should -Not -Be DefinitionRemoved
 }
 It 'does not claim baseline when several old request contexts become incomparable' {
  $b=New-ChangeFixture;$second=Copy-ChangeFixture $b.Collections[0];$second.Context.Protocol='OAuth2V2Implicit';$b.Collections+=@($second)
  $a=Copy-ChangeFixture $b;foreach($collection in $a.Collections){$collection.Context.RecipeFingerprint='9'*64}
  $r=Compare-ChangeFixture $b $a
  @($r.Entries|Where-Object EventType -eq Baseline).Count|Should -Be 0
  @($r.Entries|Where-Object EventType -eq Incomparable).Count|Should -Be 2
  @($r.Entries|Where-Object {$_.RemovedScopes.Count}).Count|Should -Be 0
 }
}

Describe 'Goal 2 collection chronology cannot bypass evidence absence guards' {
 It 'does not remove a definition based on a future empty collection' {
  $b=New-ChangeFixture PermissionDefinition;$a=Copy-ChangeFixture $b;$a.Collections[0].Records=@();$a.Collections[0].Source.CollectedAt='2026-01-03T00:00:00Z'
  $e=(Compare-ChangeFixture $b $a).Entries[0];$e.EventType|Should -Be Unknown;$e.RemovedScopes.Count|Should -Be 0
 }
 It 'checks reversed empty collection chronology' {
  $b=New-ChangeFixture ConfiguredGrant;$b.Collections[0].Records=@();$a=Copy-ChangeFixture $b;$a.Collections[0].Source.CollectedAt='2026-01-01T00:00:00Z'
  (Compare-ChangeFixture $b $a).Entries[0].EventType|Should -Be Incomparable
 }
}
