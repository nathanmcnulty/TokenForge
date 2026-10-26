BeforeAll {
 Import-Module "$PSScriptRoot/../src/TokenForge/TokenForge.psd1" -Force
 function Copy-AdminFixture($Object){[TokenForge.Core.DiscoverySourceClaims]::ReadMetadataJson((ConvertTo-Json -InputObject $Object -Depth 40 -Compress))}
 $graph='00000003-0000-0000-c000-000000000000';$client='11111111-1111-1111-1111-111111111111';$bootstrap='22222222-2222-2222-2222-222222222222';$tenant='aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'
 $profile=[TokenForge.Core.DiscoverySourceClaims]::ReadMetadataJson([TokenForge.Core.AdminWorkflows]::CreateStrictProfile($tenant,('b'*64),$bootstrap,[string[]]@($client,$bootstrap)))
 $requirements=@{Format='TokenForgeToolRequirements';SchemaVersion=1;Tools=@(@{Id='read-profile';ClientIds=@($client);ResourceId=$graph;Scopes=@('User.Read');Protocol='OAuth2V2Pkce';CallbackClass='Native';Operations=@('GraphMeV1');Prerequisites=@();SecuritySensitive=$false})}
}
Describe 'Goal 3 versioned administrator contracts' {
 It 'creates an explicitly silent profile with independent zero scope ceilings' {
  $profile.Format|Should -Be TokenForgeStrictProfile;$profile.SilentOnly|Should -BeTrue
  $profile.MaxAdditionalScopes|Should -Be 0;$profile.MaxBootstrapAdditionalScopes|Should -Be 0
  $profile.ExpectedTenantFingerprint|Should -Be ([TokenForge.Core.ApplicationCatalogPolicy]::Hash($tenant))
 }
 It 'does not reinterpret a compatibility profile as strict policy' {
  {[TokenForge.Core.AdminWorkflows]::ValidateStrictProfile('{"Format":"TokenForgeProfile","SchemaVersion":1}')}|Should -Throw '*Administrator workflow input*'
  {[TokenForge.Core.V0200.ProfilePolicy]::Validate(($profile|ConvertTo-Json -Depth 10 -Compress),'lab')}|Should -Throw '*Profile configuration*'
 }
 It 'requires explicit bootstrap approval as well as approved final clients' {
  $p=Copy-AdminFixture $profile;$p.ApprovedClientIds=@($client)
  {[TokenForge.Core.AdminWorkflows]::ValidateStrictProfile(($p|ConvertTo-Json -Depth 10 -Compress))}|Should -Throw '*Administrator workflow input*'
 }
 It 'rejects profile weakening or credential fields' -TestCases @(@{Field='SilentOnly';Value=$false},@{Field='AccessToken';Value='synthetic-private'},@{Field='MaxAdditionalScopes';Value=-1},@{Field='MaxSeconds';Value=901}) {
  param($Field,$Value)
  $p=Copy-AdminFixture $profile;$p[$Field]=$Value
  {[TokenForge.Core.AdminWorkflows]::ValidateStrictProfile(($p|ConvertTo-Json -Depth 10 -Compress))}|Should -Throw '*Administrator workflow input*'
 }
 It 'validates explicit tool requirements without inferring script text' {
  $r=[TokenForge.Core.AdminWorkflows]::ValidateRequirements(($requirements|ConvertTo-Json -Depth 20 -Compress))
  $r|Should -Match 'TokenForgeToolRequirements'
  {[TokenForge.Core.AdminWorkflows]::ValidateRequirements('Get-Content script.ps1')}|Should -Throw '*Administrator workflow input*'
 }
 It 'rejects unknown requirements, stronger-scope substitutions and arbitrary operation URIs' -TestCases @(@{Field='Script';Value='Get-Content secret'},@{Field='Operations';Value=@('https://example.test/delete')},@{Field='Scopes';Value=@('.default')},@{Field='Scopes';Value=@('offline_access')},@{Field='Scopes';Value=@('User.Read','User.Read')}) {
  param($Field,$Value)
  $r=Copy-AdminFixture $requirements;$r.Tools[0][$Field]=$Value
  {[TokenForge.Core.AdminWorkflows]::ValidateRequirements(($r|ConvertTo-Json -Depth 20 -Compress))}|Should -Throw '*Administrator workflow input*'
 }
 It 'rejects duplicate JSON keys even before selecting a tool' {
  {[TokenForge.Core.AdminWorkflows]::ValidateRequirements('{"Format":"TokenForgeToolRequirements","SchemaVersion":1,"SchemaVersion":1,"Tools":[]}')}|Should -Throw '*Administrator workflow input*'
 }
}

Describe 'Goal 3 exact request explanation and tool health' {
 BeforeAll {
  $stamp=[DateTimeOffset]::UtcNow.AddMinutes(-1).ToString('o')
  function New-AdminInventory {
   $apps=@(foreach($id in @($client,$bootstrap,$graph)){@{AppId=$id;Registration='Present';Ownership='VerifiedMicrosoftOwner';AccountEnabled=$true;RedirectUris=@('https://login.microsoftonline.com/common/oauth2/nativeclient');PublishedGrants=@();DelegatedScopeDefinitions=@(@{Id='33333333-3333-3333-3333-333333333333';Value='User.Read';Enabled=$true});AppRoleDefinitions=@()}})
   @{SchemaVersion=1;CapturedAt=$stamp;TenantFingerprint=$profile.ExpectedTenantFingerprint;PrincipalFingerprint=$profile.ExpectedPrincipalFingerprint;GrantEnumeration='Complete';Applications=$apps;TenantGrants=@()}
  }
  function Get-AdminPlan($Inventory,$Requirements=$requirements) {[TokenForge.Core.DiscoverySourceClaims]::ReadMetadataJson([TokenForge.Core.AdminWorkflows]::Plan(($profile|ConvertTo-Json -Depth 20 -Compress),($Requirements|ConvertTo-Json -Depth 20 -Compress),($Inventory|ConvertTo-Json -Depth 20 -Compress),'read-profile'))}
  function New-AdminSnapshot($Inventory,$Requirements=$requirements) {
   $plan=Get-AdminPlan $Inventory $Requirements;$ctx=$plan.Context
   $row=@{ClientId=$client;ResourceId=$graph;TenantFingerprint=$ctx.TenantFingerprint;PrincipalFingerprint=$ctx.PrincipalFingerprint;ObservedAt=$stamp;Outcome='Succeeded';Protocol='OAuth2V2Pkce';Spa=$false;RedirectFingerprint=$ctx.CallbackFingerprint;RequestedScopes=$ctx.RequestedScopes;ScpScopes=@('User.Read');ClaimsReadable=$true;HasScpClaim=$true;NamespaceVerification='Matched';RequestVerification='Matched';SignatureValidated=$false;ComparisonContext=$ctx}
   $db=@{SchemaVersion=1;UpdatedAt=$stamp;Observations=@($row);RegistrationAttempts=@()}
   [TokenForge.Core.DiscoverySourceClaims]::ReadMetadataJson([TokenForge.Core.ChangeReports]::Normalize('ScopeDatabase',($db|ConvertTo-Json -Depth 30 -Compress)))
  }
  function Explain-Admin($Inventory,$Snapshot,$Requirements=$requirements,$Prerequisites=$null) {
   $pre=if($Prerequisites){$Prerequisites|ConvertTo-Json -Depth 30 -Compress}else{[NullString]::Value}
   [TokenForge.Core.DiscoverySourceClaims]::ReadMetadataJson([TokenForge.Core.AdminWorkflows]::Explain(($profile|ConvertTo-Json -Depth 30 -Compress),($Requirements|ConvertTo-Json -Depth 30 -Compress),($Inventory|ConvertTo-Json -Depth 30 -Compress),($Snapshot|ConvertTo-Json -Depth 50 -Compress),'read-profile',$pre,$null))
  }
 }
 It 'selects one approved concrete request without dispatching or broadening scopes' {
  $plan=Get-AdminPlan (New-AdminInventory)
  $plan.Status|Should -Be ReadyForExplicitSilentAttempt;$plan.Dispatched|Should -BeFalse
  $plan.ClientId|Should -Be $client;$plan.Scopes.Count|Should -Be 1
  $plan.Context.RequestedScopes|Should -Contain "$graph/User.Read"
 }
 It 'keeps missing exact evidence unknown rather than using public hints as proof' {
  $i=New-AdminInventory;$s=@{Format='TokenForgeChangeSnapshot';SchemaVersion=1;Collections=@()}
  $e=Explain-Admin $i $s
  $e.Status|Should -Be NeedsObservation;$e.ExitCode|Should -Be 3
  $e.AuthorizationEstablished|Should -BeFalse;$e.CurrentAcquisitionPerformed|Should -BeFalse
 }
 It 'reports matched saved issuance as verified working only when all declared evidence exists' {
  $i=New-AdminInventory;$req=Copy-AdminFixture $requirements;$req.Tools[0].Operations=@();$s=New-AdminSnapshot $i $req
  $e=Explain-Admin $i $s $req
  $e.Status|Should -Be VerifiedWorking;$e.ExitCode|Should -Be 0
  $e.Clients[0].ObservedAdditionalScopes.Count|Should -Be 0
 }
 It 'requires optional declared operation proof even after successful issuance' {
  $i=New-AdminInventory;$s=New-AdminSnapshot $i
  (Explain-Admin $i $s).Status|Should -Be NeedsObservation
 }
 It 'does not mistake default discovery breadth for an exact explicit request' {
  $i=New-AdminInventory;$s=New-AdminSnapshot $i;$s.Collections[0].Context.RequestedScopes=@('.default')
  $e=Explain-Admin $i $s
  $e.Status|Should -Be NeedsObservation;$e.Clients[0].OtherObservedBreadth.Count|Should -Be 1
 }
 It 'rejects a known excess scope result under a zero ceiling and shows actual names' {
  $i=New-AdminInventory;$s=New-AdminSnapshot $i;$s.Collections[0].Records[0].Value.Scopes=@('User.Read','Mail.Read')
  $e=Explain-Admin $i $s
  $e.Status|Should -Be Blocked;$e.Clients[0].ObservedAdditionalScopes|Should -Contain Mail.Read
 }
 It 'does not treat a missing required scope as working' {
  $i=New-AdminInventory;$s=New-AdminSnapshot $i;$s.Collections[0].Records[0].Value.Scopes=@('Mail.Read')
  (Explain-Admin $i $s).Status|Should -Not -Be VerifiedWorking
 }
 It 'returns an explicit blocked route for a disabled client' {
  $i=New-AdminInventory;$i.Applications[0].AccountEnabled=$false
  (Get-AdminPlan $i).Status|Should -Be Blocked
  $s=@{Format='TokenForgeChangeSnapshot';SchemaVersion=1;Collections=@()}
  (Explain-Admin $i $s).Status|Should -Be Blocked
 }
 It 'refuses an unapproved selected client before any request' {
  $i=New-AdminInventory
  $r=[TokenForge.Core.DiscoverySourceClaims]::ReadMetadataJson([TokenForge.Core.AdminWorkflows]::Plan(($profile|ConvertTo-Json -Depth 20 -Compress),($requirements|ConvertTo-Json -Depth 20 -Compress),($i|ConvertTo-Json -Depth 20 -Compress),'read-profile','99999999-9999-9999-9999-999999999999',[NullString]::Value))
  $r.Status|Should -Be Blocked;$r.Dispatched|Should -BeFalse
 }
 It 'validates supplied prerequisites even when no supported route exists' {
  $i=New-AdminInventory;$r=Copy-AdminFixture $requirements;$r.Tools[0].Protocol='OAuth2V1Implicit'
  $bad='{"Format":"TokenForgePrerequisiteEvidence","SchemaVersion":1,"Observations":[],"AccessToken":"synthetic-private"}'
  {[TokenForge.Core.AdminWorkflows]::Acquire(($profile|ConvertTo-Json -Depth 20 -Compress),($r|ConvertTo-Json -Depth 20 -Compress),($i|ConvertTo-Json -Depth 20 -Compress),'read-profile',$null,'ESTSAUTH',[NullString]::Value,[NullString]::Value,$false,$bad)}|Should -Throw '*Administrator workflow input*'
 }
 It 'does not try an unsupported protocol through a shortcut' {
  $i=New-AdminInventory;$r=Copy-AdminFixture $requirements;$r.Tools[0].Protocol='OAuth2V1Implicit'
  (Get-AdminPlan $i $r).Reason|Should -Be UnsupportedStrictProtocol
 }
 It 'requires missing role and license prerequisites to remain unknown' {
  $i=New-AdminInventory;$r=Copy-AdminFixture $requirements;$r.Tools[0].Operations=@();$r.Tools[0].Prerequisites=@(@{Kind='Role';Name='Directory Readers'},@{Kind='License';Name='Example License'});$s=New-AdminSnapshot $i $r
  $e=Explain-Admin $i $s $r
  $e.Status|Should -Be NeedsObservation;$e.Prerequisites.Count|Should -Be 2
  @($e.Prerequisites|Where-Object Status -eq Unknown).Count|Should -Be 2
 }
 It 'requires the complete approved API operation context' -TestCases @(@{Field='Method';Value='HEAD'},@{Field='ApiVersion';Value='beta'},@{Field='ApprovalFingerprint';Value=('9'*64)},@{Field='CallbackFingerprint';Value=('8'*64)}) {
  param($Field,$Value)
  $i=New-AdminInventory;$s=New-AdminSnapshot $i;$proof=Copy-AdminFixture $s.Collections[0];$proof.EvidenceType='ApiAcceptance';$proof.Source.Id='api-proof';$proof.Context.OperationFingerprint=[TokenForge.Core.ApplicationCatalogPolicy]::Hash('GraphMeV1');$proof.Context.Method='GET';$proof.Context.ApiVersion='v1.0'
  $approval=@{Version=1;ProfileSha256=[TokenForge.Core.ChangeReports]::FingerprintJson(($profile|ConvertTo-Json -Depth 30 -Compress));ToolSha256=[TokenForge.Core.ChangeReports]::FingerprintJson(($requirements.Tools[0]|ConvertTo-Json -Depth 30 -Compress));Operation='GraphMeV1';Authorization='ExplicitSelectedReadOnlyProof/v1'}
  $proof.Context.ApprovalFingerprint=[TokenForge.Core.ChangeReports]::FingerprintJson(($approval|ConvertTo-Json -Depth 30 -Compress));$proof.Records[0].Outcome='Responded';$proof.Records[0].Value=@{Status=200;Accepted=$true};$s.Collections+=@($proof)
  (Explain-Admin $i $s).Status|Should -Be VerifiedWorking
  $proof.Context[$Field]=$Value
  (Explain-Admin $i $s).Status|Should -Not -Be VerifiedWorking
 }
 It 'does not choose positive evidence from conflicting cross-source timestamps' {
  $i=New-AdminInventory;$req=Copy-AdminFixture $requirements;$req.Tools[0].Operations=@();$s=New-AdminSnapshot $i $req;$conflict=Copy-AdminFixture $s.Collections[0];$conflict.Source.Id='another-private-source';$conflict.Records[0].Outcome='RequestBlocked';$s.Collections+=@($conflict)
  $e=Explain-Admin $i $s $req
  $e.Status|Should -Be NeedsObservation;$e.Clients[0].Reasons|Should -Contain ConflictingMatchingScopeEvidence
 }
 It 'includes bootstrap prerequisites before route readiness or tool health claims' -TestCases @(@{Case='Disabled'},@{Case='MissingDefinition'},@{Case='MissingCallback'}) {
  param($Case)
  $i=New-AdminInventory;$req=Copy-AdminFixture $requirements;$req.Tools[0].Operations=@();$s=New-AdminSnapshot $i $req
  switch($Case){Disabled {$i.Applications[1].AccountEnabled=$false} MissingDefinition {$i.Applications[2].DelegatedScopeDefinitions=@()} MissingCallback {$i.Applications[1].RedirectUris=@()}}
  (Get-AdminPlan $i $req).Reason|Should -Be NoSilentBootstrapRoute
  (Explain-Admin $i $s $req).Status|Should -Be Blocked
 }
 It 'reproduces historical health using the requested AsOf for bootstrap and inventory freshness' {
  $i=New-AdminInventory;$req=Copy-AdminFixture $requirements;$req.Tools[0].Operations=@();$s=New-AdminSnapshot $i $req
  $historical=[DateTimeOffset]::UtcNow.AddDays(-7);$i.CapturedAt=$historical.AddMinutes(-1).ToString('o');$s.Collections[0].Source.CollectedAt=$i.CapturedAt;$s.Collections[0].Records[0].ObservedAt=$i.CapturedAt
  $e=Get-TokenForgeToolExplanation -Profile $profile -Requirements $req -Inventory $i -Snapshot $s -ToolId read-profile -AsOf $historical
  $e.Status|Should -Be VerifiedWorking
 }
 It 'keeps source hints, anonymous breadth and fresh private authorization separate' {
  $i=New-AdminInventory;$s=New-AdminSnapshot $i;$anonymous=Copy-AdminFixture $s.Collections[0];$anonymous.Privacy='Anonymous';$anonymous.Source.Id='anonymous';$anonymous.Context.TenantFingerprint=$null;$anonymous.Context.PrincipalFingerprint=$null
  $hint=Copy-AdminFixture $s.Collections[0];$hint.EvidenceType='PublicHint';$hint.Privacy='Public';$hint.Source.Id='public';$hint.Context=@{ContextVersion=1;QueryFingerprint=('1'*64)};$hint.Records[0].Identity=@{ClientId=$client};$hint.Records[0].Outcome='Observed';$hint.Records[0].Value=@{Grants=@(@{ResourceId=$graph;Scopes=@('Mail.Read')});CallbackFingerprints=@();MetadataSha256=('2'*64);Conflicts=@(@{Field='Name';ValueHashes=@(('3'*64),('4'*64))})}
  $s.Collections=@($anonymous,$hint);$e=Explain-Admin $i $s
  $e.Status|Should -Be NeedsObservation;$e.Clients[0].AnonymousObservations.Count|Should -Be 1
  $e.Clients[0].PublishedHints[0].MatchesResourceAndAllScopesInOneRecord|Should -BeFalse
  $e.Clients[0].PublishedHints[0].SourceFreshness|Should -Be Fresh
  $e.Clients[0].PublishedHints[0].Record.Value.Conflicts.Count|Should -Be 1
 }
 It 'does not select success over a contradictory observation at the same UTC instant' {
  $i=New-AdminInventory;$req=Copy-AdminFixture $requirements;$req.Tools[0].Operations=@();$s=New-AdminSnapshot $i $req;$other=Copy-AdminFixture $s.Collections[0];$other.Source.Id='offset-source';$other.Records[0].ObservedAt=([DateTimeOffset]$other.Records[0].ObservedAt).ToOffset([TimeSpan]::FromHours(2)).ToString('o');$other.Records[0].Outcome='RequestBlocked';$s.Collections+=@($other)
  (Explain-Admin $i $s $req).Status|Should -Be NeedsObservation
 }
 It 'validates full evidence including unselected credential fields' {
  $i=New-AdminInventory;$s=New-AdminSnapshot $i;$s.Collections[0].Records[0].Value.AccessToken='synthetic-private'
  {Explain-Admin $i $s}|Should -Throw '*Administrator workflow input*'
 }
}

Describe 'Goal 3 strict single-route acquisition with synthetic transports' {
 BeforeEach {
  $script:adminPrincipal='bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb'
  $script:adminTenant=$tenant;$script:adminBootstrap=$bootstrap;$script:adminClient=$client
  $p=[TokenForge.Core.DiscoverySourceClaims]::ReadMetadataJson([TokenForge.Core.AdminWorkflows]::CreateStrictProfile($tenant,[TokenForge.Core.ApplicationCatalogPolicy]::Hash("$tenant/$script:adminPrincipal"),$bootstrap,[string[]]@($client,$bootstrap)))
  $r=Copy-AdminFixture $requirements
  $now=[DateTimeOffset]::UtcNow.AddSeconds(-1).ToString('o')
  $apps=@(foreach($id in @($client,$bootstrap,$graph)){@{AppId=$id;Registration='Present';Ownership='VerifiedMicrosoftOwner';AccountEnabled=$true;RedirectUris=@('https://login.microsoftonline.com/common/oauth2/nativeclient');PublishedGrants=@();DelegatedScopeDefinitions=@(@{Id='33333333-3333-3333-3333-333333333333';Value='User.Read';Enabled=$true});AppRoleDefinitions=@()}})
  $i=@{SchemaVersion=1;CapturedAt=$now;TenantFingerprint=$p.ExpectedTenantFingerprint;PrincipalFingerprint=$p.ExpectedPrincipalFingerprint;GrantEnumeration='Complete';Applications=$apps;TenantGrants=@()}
  $cookie=ConvertTo-SecureString synthetic-cookie -AsPlainText -Force
  $script:adminCalls=[Collections.Generic.List[string]]::new();$script:adminTokens=[Collections.Generic.List[object]]::new();$script:adminFailure='';$script:adminApiStatus=200
  $execute=[Func[TokenForge.Core.ScopePlanning+RequestRow,TokenForge.Core.ProfileCredentialToken]]{
   param($request)
   $script:adminCalls.Add($request.ClientId)
   if($script:adminFailure -eq 'Deadline'){Start-Sleep -Milliseconds 1100}
   if($script:adminFailure -eq 'Expires' -and $request.ClientId -eq $script:adminClient){Start-Sleep -Milliseconds 2200}
   if($script:adminFailure -eq 'Denied' -and $request.ClientId -eq $script:adminClient){throw 'AADSTS65001 synthetic-private-body'}
   $scopes=if($script:adminFailure -eq 'AccountMismatch'){'User.Read synthetic-private-scope'}elseif($script:adminFailure -eq 'BootstrapExtras' -and $request.ClientId -eq $script:adminBootstrap){'User.Read Directory.Read.All'}elseif($script:adminFailure -eq 'FinalExtras' -and $request.ClientId -eq $script:adminClient){'User.Read Mail.Read'}else{$request.Scopes -join ' '}
   $oid=if($script:adminFailure -eq 'AccountMismatch'){'cccccccc-cccc-cccc-cccc-cccccccccccc'}else{$script:adminPrincipal}
   $body=@{tid=$script:adminTenant;oid=$oid;appid=$request.ClientId;aud=$request.ResourceId;scp=$scopes;exp=[DateTimeOffset]::UtcNow.AddMinutes(30).ToUnixTimeSeconds()}|ConvertTo-Json -Compress
   $jwt='e30.'+[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($body)).TrimEnd('=').Replace('+','-').Replace('/','_')+'.synthetic'
   $access=ConvertTo-SecureString $jwt -AsPlainText -Force
   try{$responseExtras=if($script:adminFailure -eq 'ResponseExtras' -and $request.ClientId -eq $script:adminClient){1}else{0};$token=[TokenForge.Core.ProfileCredentialToken]::new($request.ToTransport(),$access,$null,[DateTimeOffset]::UtcNow.AddMinutes(30),$responseExtras);$script:adminTokens.Add($token);return $token}finally{$access.Dispose()}
  }
  $identity=[Func[Security.SecureString,string]]{param($token) $script:adminPrincipal}
  $api=[Func[Security.SecureString,TokenForge.Core.ProfileApiCheck]]{param($token) if($script:adminFailure -eq 'ApiTransport'){throw 'synthetic-private-body'};[TokenForge.Core.ProfileApiCheck]::new($script:adminApiStatus,($script:adminApiStatus -ge 200 -and $script:adminApiStatus -le 299))}
  function Invoke-SyntheticStrict([bool]$Proof=$true,$Prerequisites=$null) {
   [TokenForge.Core.AdminWorkflows]::Acquire(($p|ConvertTo-Json -Depth 30 -Compress),($r|ConvertTo-Json -Depth 30 -Compress),($i|ConvertTo-Json -Depth 30 -Compress),'read-profile',$cookie,'ESTSAUTH',[NullString]::Value,[NullString]::Value,$Proof,$(if($Prerequisites){$Prerequisites|ConvertTo-Json -Depth 30 -Compress}else{[NullString]::Value}),$execute,$identity,$api,[Threading.CancellationToken]::None)
  }
 }
 AfterEach {$cookie.Dispose();foreach($token in $script:adminTokens){$token.Dispose()}}
 It 'executes bootstrap/current identity/final/selected proof and returns metadata without credentials' {
  $result=Invoke-SyntheticStrict
  try{$json=$result.ToJson();$meta=[TokenForge.Core.DiscoverySourceClaims]::ReadMetadataJson($json)
   $meta.Status|Should -Be IssuedWithinStrictPolicy;$meta.IssuanceSucceeded|Should -BeTrue;$meta.CurrentContextConfirmed|Should -BeTrue
   $meta.BootstrapAttempts|Should -Be 1;$meta.FinalAttempts|Should -Be 1;$meta.ApiCheck.Accepted|Should -BeTrue
   $meta.FinalAdditionalScopes.Count|Should -Be 0;$result.Credential.AccessToken.Length|Should -BeGreaterThan 0
   $json|Should -Not -Match 'synthetic|AccessToken|RefreshToken|Cookie|eyJ'
   $script:adminCalls.Count|Should -Be 2
  }finally{$result.Dispose()}
  { $script:adminTokens[0].AccessToken.AppendChar([char]'x') }|Should -Throw
 }
 It 'feeds sanitized acquisition evidence into the named tool health workflow' {
  $result=Invoke-SyntheticStrict
  try{$metadata=[TokenForge.Core.DiscoverySourceClaims]::ReadMetadataJson($result.ToJson());$snapshot=ConvertTo-TokenForgeToolEvidence $metadata
   $health=Test-TokenForgeTool -Profile $p -Requirements $r -Inventory $i -Snapshot $snapshot -ToolId read-profile
   $health.Status|Should -Be VerifiedWorking;$snapshot.Collections.Count|Should -Be 2
   $metadata.AccessToken='synthetic-private'
   {ConvertTo-TokenForgeToolEvidence $metadata}|Should -Throw '*Administrator workflow input*'
  }finally{$result.Dispose()}
 }
 It 'preserves API denial as blocked tool evidence after successful issuance' {
  $script:adminApiStatus=403;$result=Invoke-SyntheticStrict
  try{$snapshot=ConvertTo-TokenForgeToolEvidence ([TokenForge.Core.DiscoverySourceClaims]::ReadMetadataJson($result.ToJson()));$health=Test-TokenForgeTool -Profile $p -Requirements $r -Inventory $i -Snapshot $snapshot -ToolId read-profile
   $health.Status|Should -Be Blocked;$health.Clients[0].ScopeEvidence.After.LatestOutcome|Should -Be Succeeded
  }finally{$result.Dispose()}
 }
 It 'validates all receipt fields and rejects impossible or mismatched success metadata' -TestCases @(@{Case='NestedSecret'},@{Case='NoBootstrap'},@{Case='ExtraMismatch'},@{Case='PolicyMismatch'},@{Case='ApiMismatch'},@{Case='UnusedApi'}) {
  param($Case)
  $result=Invoke-SyntheticStrict
  try{$m=[TokenForge.Core.DiscoverySourceClaims]::ReadMetadataJson($result.ToJson())
   switch($Case){NestedSecret {$m.BootstrapScopes=@(@{AccessToken='synthetic-private'})} NoBootstrap {$m.BootstrapAttempts=0} ExtraMismatch {$m.FinalAdditionalScopes=@('Mail.Read')} PolicyMismatch {$m.Context.ExecutionPolicyFingerprint='9'*64} ApiMismatch {$m.ApiComparisonContext.Method='HEAD'} UnusedApi {$m.ApiProofPerformed=$false}}
   {ConvertTo-TokenForgeToolEvidence $m}|Should -Throw '*Administrator workflow input*'
  }finally{$result.Dispose()}
 }
 It 'stops a declined final request without a second client or callback' {
  $script:adminFailure='Denied';$result=Invoke-SyntheticStrict
  try{$m=[TokenForge.Core.DiscoverySourceClaims]::ReadMetadataJson($result.ToJson());$m.Status|Should -Be Blocked;$m.Reason|Should -Be FinalSilentAttemptOrPolicyFailed;$script:adminCalls.Count|Should -Be 2;$result.Credential|Should -BeNullOrEmpty;$result.ToJson()|Should -Not -Match 'AADSTS|synthetic-private'}finally{$result.Dispose()}
 }
 It 'enforces independent bootstrap and final scope ceilings' -TestCases @(@{Failure='BootstrapExtras';Calls=1},@{Failure='FinalExtras';Calls=2},@{Failure='ResponseExtras';Calls=2}) {
  param($Failure,$Calls)
  $script:adminFailure=$Failure;$result=Invoke-SyntheticStrict
  try{$m=[TokenForge.Core.DiscoverySourceClaims]::ReadMetadataJson($result.ToJson());$m.Status|Should -Be Blocked;$script:adminCalls.Count|Should -Be $Calls;$result.Credential|Should -BeNullOrEmpty
   if($Failure -eq 'FinalExtras'){$m.FinalAdditionalScopes|Should -Contain Mail.Read}
   if($Failure -eq 'BootstrapExtras'){$m.BootstrapAdditionalScopes|Should -Contain Directory.Read.All}
  }finally{$result.Dispose()}
 }
 It 'keeps successful issuance distinct from optional API denial and discards credentials' {
  $script:adminApiStatus=403;$result=Invoke-SyntheticStrict
  try{$m=[TokenForge.Core.DiscoverySourceClaims]::ReadMetadataJson($result.ToJson());$m.IssuanceSucceeded|Should -BeTrue;$m.Status|Should -Be Blocked;$m.Reason|Should -Be SelectedApiDeniedOrUnavailable;$m.ApiCheck.Status|Should -Be 403;$result.Credential|Should -BeNullOrEmpty;$script:adminCalls.Count|Should -Be 2}finally{$result.Dispose()}
 }
 It 'stops on account mismatch before any final issuance' {
  $script:adminFailure='AccountMismatch';$result=Invoke-SyntheticStrict
  try{$m=[TokenForge.Core.DiscoverySourceClaims]::ReadMetadataJson($result.ToJson());$m.Status|Should -Be Blocked;$m.CurrentContextConfirmed|Should -BeFalse;$script:adminCalls.Count|Should -Be 1;$result.ToJson()|Should -Not -Match 'synthetic-private-scope'}finally{$result.Dispose()}
 }
 It 'requires an existing silent session and never starts authentication' {
  $cookie.Dispose();$cookie=$null;$result=Invoke-SyntheticStrict
  try{$m=[TokenForge.Core.DiscoverySourceClaims]::ReadMetadataJson($result.ToJson());$m.Reason|Should -Be ExistingSilentSessionRequired;$script:adminCalls.Count|Should -Be 0}finally{$result.Dispose();$cookie=ConvertTo-SecureString synthetic -AsPlainText -Force}
 }
 It 'preserves an unobserved API response as unknown after successful issuance' {
  $script:adminFailure='ApiTransport';$result=Invoke-SyntheticStrict
  try{$m=[TokenForge.Core.DiscoverySourceClaims]::ReadMetadataJson($result.ToJson());$s=ConvertTo-TokenForgeToolEvidence $m
   $m.IssuanceSucceeded|Should -BeTrue;$result.Credential|Should -BeNullOrEmpty
   $s.Collections[1].Records[0].Outcome|Should -Be Unknown
   (Test-TokenForgeTool -Profile $p -Requirements $r -Inventory $i -Snapshot $s -ToolId read-profile).Status|Should -Be NeedsObservation
  }finally{$result.Dispose()}
 }
 It 'stops a total deadline before any final request and disposes bootstrap credentials' {
  $p.MaxSeconds=1;$script:adminFailure='Deadline';$result=Invoke-SyntheticStrict
  try{$m=[TokenForge.Core.DiscoverySourceClaims]::ReadMetadataJson($result.ToJson());$m.Reason|Should -Be DeadlineOrCancelled;$script:adminCalls.Count|Should -Be 1;$result.Credential|Should -BeNullOrEmpty}finally{$result.Dispose()}
 }
 It 'discards credentials if inventory or prerequisites expire during the attempt' -TestCases @(@{Case='Inventory'},@{Case='Prerequisites'}) {
  param($Case)
  $p.MaxAgeHours=1;$script:adminFailure='Expires';$pre=$null
  if($Case -eq 'Inventory'){$i.CapturedAt=[DateTimeOffset]::UtcNow.AddHours(-1).AddSeconds(2).ToString('o')}
  else{$r.Tools[0].Prerequisites=@(@{Kind='Role';Name='Directory Readers'});$pre=@{Format='TokenForgePrerequisiteEvidence';SchemaVersion=1;Observations=@(@{Kind='Role';Name='Directory Readers';Status='Satisfied';TenantFingerprint=$p.ExpectedTenantFingerprint;PrincipalFingerprint=$p.ExpectedPrincipalFingerprint;ObservedAt=[DateTimeOffset]::UtcNow.AddHours(-1).AddSeconds(2).ToString('o');SourceSha256=('1'*64)})}}
  $result=Invoke-SyntheticStrict -Prerequisites $pre
  try{$m=[TokenForge.Core.DiscoverySourceClaims]::ReadMetadataJson($result.ToJson());$m.Reason|Should -Be EvidenceExpiredDuringAttempt;$m.ExitCode|Should -Be 3;$result.Credential|Should -BeNullOrEmpty}finally{$result.Dispose()}
 }
 It 'blocks an unsatisfied prerequisite before credential use' {
  $r.Tools[0].Prerequisites=@(@{Kind='License';Name='Example License'});$pre=@{Format='TokenForgePrerequisiteEvidence';SchemaVersion=1;Observations=@(@{Kind='License';Name='Example License';Status='Unsatisfied';TenantFingerprint=$p.ExpectedTenantFingerprint;PrincipalFingerprint=$p.ExpectedPrincipalFingerprint;ObservedAt=[DateTimeOffset]::UtcNow.AddSeconds(-1).ToString('o');SourceSha256=('1'*64)})}
  $result=Invoke-SyntheticStrict -Prerequisites $pre
  try{$m=[TokenForge.Core.DiscoverySourceClaims]::ReadMetadataJson($result.ToJson());$m.Reason|Should -Be PrerequisiteNotSatisfied;$m.ExitCode|Should -Be 4;$script:adminCalls.Count|Should -Be 0}finally{$result.Dispose()}
 }
 It 'does not describe unperformed API proof as verified API access' {
  $result=Invoke-SyntheticStrict -Proof $false
  try{$m=[TokenForge.Core.DiscoverySourceClaims]::ReadMetadataJson($result.ToJson());$m.Status|Should -Be IssuedNeedsApiObservation;$m.ExitCode|Should -Be 3;$m.ApiProofPerformed|Should -BeFalse}finally{$result.Dispose()}
 }
}

Describe 'Goal 3 bounded packet preparation' {
 BeforeAll {
  $when=[DateTimeOffset]::UtcNow.AddMinutes(-1).ToString('o')
  function New-PacketSnapshot([string[]]$Scopes=@('User.Read','Mail.Read')) {
   @{Format='TokenForgeChangeSnapshot';SchemaVersion=1;Collections=@(@{EvidenceType='ConfiguredGrant';Privacy='Private';Status='Complete';Context=@{ContextVersion=1;QueryFingerprint=('c'*64);TenantFingerprint=('a'*64);ObserverFingerprint=('b'*64)};Source=@{Id='synthetic-grants';Location=('urn:sha256:'+('d'*64));ContentSha256=('d'*64);HashKind='NormalizedDocument';SourceObservedAt=$null;CollectedAt=$when};Records=@(@{RecordId=('e'*64);ObservedAt=$when;Outcome='Observed';Identity=@{ClientId=$client;ResourceId=$graph;GrantType='AllPrincipals';SubjectFingerprint=$null};Value=@{Scopes=$Scopes}})})}
  }
 }
 It 'recomputes a typed change and maps it to the named tool without sending' {
  $b=New-PacketSnapshot;$a=New-PacketSnapshot @('User.Read')
  $packet=New-TokenForgeToolChangePacket -Requirements $requirements -Before $b -After $a -SourceRevision ('1'*40) -PackageManifestSha256 ('2'*64)
  $packet.Format|Should -Be TokenForgeToolChangePacket;$packet.Entries.Count|Should -Be 1
  $packet.Entries[0].AffectedTools|Should -Contain read-profile
  $packet.Entries[0].Change.EventType|Should -Be ConfiguredGrantChanged
  $packet.RootCauseEstablished|Should -BeFalse;$packet.CommunicationAuthorized|Should -BeFalse
  $packet.DisclosureRoute|Should -Be PrivateMaintainerReview
 }
 It 'routes security-sensitive findings to private disclosure' {
  $b=New-PacketSnapshot;$a=New-PacketSnapshot @('User.Read')
  $packet=New-TokenForgeToolChangePacket -Requirements $requirements -Before $b -After $a -SourceRevision ('1'*40) -PackageManifestSha256 ('2'*64) -SecuritySensitive
  $packet.DisclosureRoute|Should -Be PrivateSecurityDisclosure
  $packet.AutomaticCommunication|Should -BeFalse
 }
 It 'preserves collection coverage loss as potential named tool impact' {
  $b=New-PacketSnapshot;$b.Collections[0].Records=@();$a=Copy-AdminFixture $b;$a.Collections[0].Status='Denied'
  $packet=New-TokenForgeToolChangePacket -Requirements $requirements -Before $b -After $a -SourceRevision ('1'*40) -PackageManifestSha256 ('2'*64)
  $packet.AffectedChangeCount|Should -BeGreaterThan 0;$packet.Entries[0].AffectedTools|Should -Contain read-profile
  $packet.Entries[0].ImpactConclusion|Should -Be PotentiallyRelevantTypedEvidenceNotProvenToolFailure
 }
 It 'bounds retained entries and explicitly accounts for omitted changes' {
  $b=New-PacketSnapshot;$second=Copy-AdminFixture $b.Collections[0];$second.Source.Id='second-source';$b.Collections+=@($second);$a=Copy-AdminFixture $b;foreach($c in $a.Collections){$c.Records[0].Value.Scopes=@('User.Read')}
  $packet=New-TokenForgeToolChangePacket -Requirements $requirements -Before $b -After $a -SourceRevision ('1'*40) -PackageManifestSha256 ('2'*64) -MaxEntries 1
  $packet.RetainedEntryCount|Should -Be 1;$packet.OmittedEntryCount|Should -Be 1;$packet.Truncated|Should -BeTrue
  [Text.Encoding]::UTF8.GetByteCount(($packet|ConvertTo-Json -Depth 64 -Compress))|Should -BeLessOrEqual 1048576
 }
 It 'requires validated snapshots rather than trusting supplied event labels' {
  $fake=@{Format='TokenForgeChangeReport';SchemaVersion=1;Entries=@(@{EventType='MatchedRequestScopesChanged'})}
  {New-TokenForgeToolChangePacket -Requirements $requirements -Before $fake -After $fake -SourceRevision ('1'*40) -PackageManifestSha256 ('2'*64)}|Should -Throw '*Administrator workflow input*'
 }
}
