 Import-Module "$PSScriptRoot/../../../src/TokenForge/TokenForge.psd1" -Force
 function Read-RefreshJson($Json){[TokenForge.Core.DiscoverySourceClaims]::ReadMetadataJson($Json)}
 function Copy-Refresh($Object){Read-RefreshJson (ConvertTo-Json -InputObject $Object -Depth 64 -Compress)}
 $script:rfNow=[DateTimeOffset]'2026-01-10T00:00:00Z';$script:rfClient='11111111-1111-1111-1111-111111111111';$script:rfBoot='22222222-2222-2222-2222-222222222222';$script:rfGraph='00000003-0000-0000-c000-000000000000';$script:rfCallback='https://login.microsoftonline.com/common/oauth2/nativeclient'
 function New-RefreshInput {
  $profile=Read-RefreshJson ([TokenForge.Core.AdminWorkflows]::CreateStrictProfile('aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa',('b'*64),$script:rfBoot,[string[]]@($script:rfBoot,$script:rfClient)))
  $requirements=@{Format='TokenForgeToolRequirements';SchemaVersion=1;Tools=@(@{Id='read-profile';ClientIds=@($script:rfClient);ResourceId=$script:rfGraph;Scopes=@('User.Read');Protocol='OAuth2V2Pkce';CallbackClass='Native';Operations=@();Prerequisites=@();SecuritySensitive=$false})}
  $apps=@(foreach($id in @($script:rfClient,$script:rfBoot,$script:rfGraph)){@{AppId=$id;Name='Synthetic';Registration='Present';Ownership='VerifiedMicrosoftOwner';AccountEnabled=$true;RedirectUris=@($script:rfCallback);PublishedGrants=@();DelegatedScopeDefinitions=@(@{Id='33333333-3333-3333-3333-333333333333';Value='User.Read';Enabled=$true});AppRoleDefinitions=@()}})
  $inventory=@{SchemaVersion=1;CapturedAt=$script:rfNow.AddHours(-1).ToString('o');TenantFingerprint=$profile.ExpectedTenantFingerprint;PrincipalFingerprint=$profile.ExpectedPrincipalFingerprint;GrantEnumeration='Complete';Applications=$apps;TenantGrants=@()}
  @{Format='TokenForgeRefreshInput';SchemaVersion=1;Profile=$profile;Requirements=$requirements;Inventory=$inventory;Snapshot=@{Format='TokenForgeChangeSnapshot';SchemaVersion=1;Collections=@()};Pins=@{SourceRevision=('1'*40);PackageManifestSha256=('2'*64);SchemaSha256=('3'*64);CollectorSemanticsSha256=('4'*64);CatalogHash=('5'*64);CohortHash=('6'*64);LegacyInventoryHash=('7'*64)};Policy=(Read-RefreshJson ([TokenForge.Core.AdminWorkflows]::CreateRefreshPolicy(($requirements|ConvertTo-Json -Depth 20 -Compress))));History=(Read-RefreshJson ([TokenForge.Core.AdminWorkflows]::CreateRefreshHistory()))}
 }
 function Plan-Refresh($InputObject,[DateTimeOffset]$At=$script:rfNow){Read-RefreshJson ([TokenForge.Core.AdminWorkflows]::PlanRefresh((ConvertTo-Json -InputObject $InputObject -Depth 64 -Compress),$At))}
 function New-RefreshObservation($Plan,[string]$Outcome='Succeeded',[DateTimeOffset]$At=$script:rfNow.AddMinutes(-9)) {
  $row=$Plan.Candidates[0];$ctx=$row.Context
  @{Format='TokenForgeChangeSnapshot';SchemaVersion=1;Collections=@(@{EvidenceType='IssuedScopes';Privacy='Private';Status='Complete';Context=$ctx;Source=@{Id='synthetic-refresh';Location=('urn:sha256:'+('d'*64));ContentSha256=('d'*64);HashKind='NormalizedDocument';SourceObservedAt=$null;CollectedAt=$At.ToString('o')};Records=@(@{RecordId=('e'*64);ObservedAt=$At.ToString('o');Outcome=$Outcome;Identity=@{ClientId=$script:rfClient;ResourceId=$script:rfGraph};Value=@{Scopes=@('User.Read');NamespaceVerification='Matched';RequestVerification='Matched';ClaimsReadable=$true;HasScpClaim=$true;SignatureValidated=$false}})})}
 }
 function Capture-Refresh($Plan,$Snapshot,$History){Read-RefreshJson ([TokenForge.Core.AdminWorkflows]::CaptureRefreshEvidence(($Plan|ConvertTo-Json -Depth 64 -Compress),($Snapshot|ConvertTo-Json -Depth 64 -Compress),($History|ConvertTo-Json -Depth 64 -Compress)))}
 function New-WarmRefreshInput {
  $i=New-RefreshInput;$plan=Plan-Refresh $i $script:rfNow.AddMinutes(-10);$s=New-RefreshObservation $plan;$i.History=Capture-Refresh $plan $s $i.History;$i.Snapshot=$s;$i
 }
 function Get-RefreshCanonicalHash($Object){$doc=[Text.Json.JsonDocument]::Parse((ConvertTo-Json -InputObject $Object -Depth 100 -Compress));try{[TokenForge.Core.ApplicationCatalogPolicy]::Hash([TokenForge.Core.ApplicationCatalogPolicy]::Canonical($doc.RootElement))}finally{$doc.Dispose()}}
 function New-RefreshApiSnapshot($Plan,[DateTimeOffset]$IssuedAt,[DateTimeOffset]$ApiAt,[int]$Status){
  $s=New-RefreshObservation $Plan -At $IssuedAt;$row=$Plan.Candidates[0];$ctx=Copy-Refresh $row.Context
  $ctx.OperationFingerprint=[TokenForge.Core.ApplicationCatalogPolicy]::Hash('GraphMeV1');$ctx.Method='GET';$ctx.ApiVersion='v1.0';$ctx.ApprovalFingerprint=Get-RefreshCanonicalHash @{Version=1;ProfileSha256=(Get-RefreshCanonicalHash $row.CompatibilityDescriptor.Profile);ToolSha256=(Get-RefreshCanonicalHash $row.CompatibilityDescriptor.Tool);Operation='GraphMeV1';Authorization='ExplicitSelectedReadOnlyProof/v1'}
  $source=Copy-Refresh $s.Collections[0].Source;$source.CollectedAt=$ApiAt.ToString('o')
  $s.Collections+=@(@{EvidenceType='ApiAcceptance';Privacy='Private';Status='Complete';Context=$ctx;Source=$source;Records=@(@{RecordId=('f'*64);ObservedAt=$ApiAt.ToString('o');Outcome='Responded';Identity=@{ClientId=$script:rfClient;ResourceId=$script:rfGraph};Value=@{Status=$Status;Accepted=($Status -ge 200 -and $Status -le 299)}})})
  $s
 }
