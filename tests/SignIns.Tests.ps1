BeforeAll {
 Import-Module "$PSScriptRoot/../src/TokenForge/TokenForge.psd1" -Force
 $tid='aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa';$id='11111111-1111-1111-1111-111111111111'
 $encoded=[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes((@{tid=$tid;oid='bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb'}|ConvertTo-Json -Compress))).TrimEnd('=').Replace('+','-').Replace('/','_')
 $token=ConvertTo-SecureString "e30.$encoded.synthetic" -AsPlainText -Force
 $fp=(Get-TokenForgeTokenClaims $token).TenantFingerprint
}
AfterAll {$token.Dispose()}
Describe 'Sign-in application extraction' {
 BeforeEach {
  $inventory=[pscustomobject]@{TenantFingerprint=$fp;Applications=@([pscustomobject]@{AppId=$id;Registration='Present';Ownership='VerifiedMicrosoftOwner'})}
  Mock Invoke-TokenForgeGraph -ModuleName TokenForge {param($Uri)
   if($Uri.Query -eq '?page=2'){return @{value=@(@{appId='22222222-2222-2222-2222-222222222222';userPrincipalName='private-user';ipAddress='private-ip'})}}
   @{value=@(@{appId=$id},@{appId=$id.ToUpper()},@{appId='bad'},@{appId=[guid]::Empty.ToString()});'@odata.nextLink'='https://graph.microsoft.com/beta/auditLogs/signIns?page=2'}
  }
 }
 It 'deduplicates only client UUIDs across pages and excludes raw events' {
  $r=Get-TokenForgeSignInApplications -GraphToken $token -Inventory $inventory
  $r.Applications.Count|Should -Be 2;$r.RecordCount|Should -Be 5;$r.InvalidAppIdCount|Should -Be 2
  $r.Applications[0].SignInCount|Should -Be 2;$r.Applications[0].RegisteredMicrosoft|Should -BeTrue
  $r.Applications[1].KnownInInventory|Should -BeFalse
  ($r|ConvertTo-Json -Depth 8)|Should -Not -Match 'private-user|private-ip|userPrincipalName|ipAddress'
  Should -Invoke Invoke-TokenForgeGraph -ModuleName TokenForge -Times 1 -ParameterFilter {$Uri.Query -match '\$select=appId,resourceId,authenticationProtocol' -and [uri]::UnescapeDataString($Uri.Query) -match 'nonInteractiveUser'}
 }
 It 'fails rather than returning partial discovery at the paging limit' {
  {Get-TokenForgeSignInApplications $token $inventory -MaxPages 1}|Should -Throw '*page limit*'
 }
 It 'rejects off-endpoint paging links before sending another request' -TestCases @(@{Link='https://evil.test/beta/auditLogs/signIns'},@{Link='https://graph.microsoft.com/v1.0/me'},@{Link='http://graph.microsoft.com/beta/auditLogs/signIns'}) {
  param($Link)
  Mock Invoke-TokenForgeGraph -ModuleName TokenForge { @{value=@();'@odata.nextLink'=$Link} }
  {Get-TokenForgeSignInApplications $token $inventory}|Should -Throw '*boundary*'
  Should -Invoke Invoke-TokenForgeGraph -ModuleName TokenForge -Times 1
 }
 It 'rejects a different tenant and invalid window before querying' {
  $inventory.TenantFingerprint='f'*64
  {Get-TokenForgeSignInApplications $token $inventory}|Should -Throw '*tenant*'
  {Get-TokenForgeSignInApplications $token $inventory -Since ([DateTimeOffset]::UtcNow.AddDays(-32))}|Should -Throw '*window*'
  Should -Invoke Invoke-TokenForgeGraph -ModuleName TokenForge -Times 0
 }
 It 'does not convert authorization failure to empty discovery' {
  Mock Invoke-TokenForgeGraph -ModuleName TokenForge {throw 'Graph request failed (HTTP 403); response details suppressed.'}
  {Get-TokenForgeSignInApplications $token $inventory}|Should -Throw '*403*'
 }
}
Describe 'Explicit sign-in candidate registration' {
 BeforeEach {
  $registrationRoot=Join-Path ($TestDrive -replace '^/var/','/private/var/') ([guid]::NewGuid().ToString())
  $null=Get-TokenForgeFlowEvidence (Join-Path $registrationRoot missing.json)
  $app=[pscustomobject]@{AppId=$id;OwnerTenantId=$null;Ownership='Unverified';Registration='Missing';Sources=@([pscustomobject]@{Evidence='ObservedSignInNotOwnership'})}
  Mock Invoke-TokenForgeGraph -ModuleName TokenForge {param($Method)
   if($Method -eq 'POST'){@{appId=$id;id='33333333-3333-3333-3333-333333333333';appOwnerOrganizationId='f8cdef31-a31e-4b4a-93e4-5f571e91255a'}}else{$null}
  }
 }
 It 'requires the sign-in-specific opt-in, not merely published candidate resolution' {
  {Register-TokenForgeApplication $token $app -ResolvePublishedCandidate -Confirm:$false}|Should -Throw '*requires*'
  Should -Invoke Invoke-TokenForgeGraph -ModuleName TokenForge -Times 0 -ParameterFilter {$Method -eq 'POST'}
  (Register-TokenForgeApplication $token $app -ResolveSignInCandidate -Confirm:$false).Outcome|Should -Be Created
 }
 It 'registers only selected missing sign-in candidates and checkpoints ownership' {
  $i=[pscustomobject]@{TenantFingerprint=$fp;Applications=@($app)}
  $result=@(Sync-TokenForgeApplicationRegistration $i $token "$registrationRoot/signin-register.json" -ResolveSignInCandidates -DelayMilliseconds 0 -Confirm:$false)
  $result.Count|Should -Be 1;$result[0].Outcome|Should -Be Created
 }
 It 'rejects another tenant before registration calls or checkpoint writes' {
  $i=[pscustomobject]@{TenantFingerprint=('f'*64);Applications=@($app)}
  {Sync-TokenForgeApplicationRegistration $i $token "$registrationRoot/wrong-tenant.json" -ResolveSignInCandidates -Confirm:$false}|Should -Throw '*tenant*'
  Should -Invoke Invoke-TokenForgeGraph -ModuleName TokenForge -Times 0
  Test-Path "$registrationRoot/wrong-tenant.json"|Should -BeFalse
 }
 It 'rolls back only a newly created exact candidate with a non-Microsoft owner' {
  Mock Invoke-TokenForgeGraph -ModuleName TokenForge {@{appId=$id;id='33333333-3333-3333-3333-333333333333';appOwnerOrganizationId='44444444-4444-4444-4444-444444444444'}} -ParameterFilter {$Method -eq 'POST'}
  {Register-TokenForgeApplication $token $app -ResolveSignInCandidate -Confirm:$false}|Should -Throw '*was removed*'
  Should -Invoke Invoke-TokenForgeGraph -ModuleName TokenForge -Times 1 -ParameterFilter {$Method -eq 'DELETE' -and $Uri.AbsolutePath -eq '/v1.0/servicePrincipals/33333333-3333-3333-3333-333333333333'}
 }
 It 'stops and checkpoints ambiguous creation responses without deleting another principal' -TestCases @(@{Response=@{appId='44444444-4444-4444-4444-444444444444'}},@{Response=$null},@{Response=@{id='33333333-3333-3333-3333-333333333333'}}) {
  param($Response)
  Mock Invoke-TokenForgeGraph -ModuleName TokenForge {$Response} -ParameterFilter {$Method -eq 'POST'}
  $i=[pscustomobject]@{TenantFingerprint=$fp;Applications=@($app)};$path="$registrationRoot/ambiguous.json"
  {Sync-TokenForgeApplicationRegistration $i $token $path -ResolveSignInCandidates -DelayMilliseconds 0 -Confirm:$false}|Should -Throw '*cleanup*'
  (Get-TokenForgeScopeDatabase $path).RegistrationAttempts[0].Outcome|Should -Be CleanupRequired
  Should -Invoke Invoke-TokenForgeGraph -ModuleName TokenForge -Times 0 -ParameterFilter {$Method -eq 'DELETE'}
 }
}
Describe 'Sign-in CLI discovery persistence' {
 It 'saves whitelisted discovery and merges repeated client evidence idempotently' {
  $state=Join-Path $TestDrive state;$null=New-Item -ItemType Directory $state
  $inventory=[pscustomobject]@{TenantFingerprint=$fp;Applications=@()}
  $inventory|ConvertTo-Json -Depth 8|Set-Content (Join-Path $state inventory.json)
  $catalog=Get-TokenForgeCatalog "$PSScriptRoot/fixtures/catalog.json"
  Get-TokenForgeDiscovery $catalog|ConvertTo-Json -Depth 20|Set-Content (Join-Path $state discovery.json)
  Mock Import-Module {}
  Mock Invoke-TokenForgeGraph -ModuleName TokenForge {@{value=@(@{appId='22222222-2222-2222-2222-222222222222';userPrincipalName='private-user';ipAddress='private-ip'})}}
  $runner="$PSScriptRoot/../scripts/Invoke-TokenForgeInventory.ps1"
  $r=& $runner -Action SignIns -StatePath $state -GraphToken $token
  $r.Enumeration|Should -Be Complete
  $null=& $runner -Action SignIns -StatePath $state -GraphToken $token
  $saved=Get-Content (Join-Path $state discovery.json) -Raw|ConvertFrom-Json
  $candidate=$saved.Applications|Where-Object AppId -eq '22222222-2222-2222-2222-222222222222'
  $candidate.Ownership|Should -Be Unverified
  @($candidate.Sources|Where-Object Evidence -eq 'ObservedSignInNotOwnership').Count|Should -Be 1
  (Get-Content (Join-Path $state signin-applications.json) -Raw)|Should -Not -Match 'private-user|private-ip'
 }
}
Describe 'Bounded sign-in protocol summaries' {
 It 'retains expanded enums but suppresses unknown text and raw failure details' {
  Mock Invoke-TokenForgeGraph -ModuleName TokenForge {
   @{value=@(@{appId=$id;resourceId='00000003-0000-0000-c000-000000000000';authenticationProtocol='authorizationCodeWithPkce';clientAppUsed='Browser';authenticationMethodsUsed=@('FIDO');clientCredentialType='certificate';incomingTokenType='primaryRefreshToken';signInEventTypes=@('interactiveUser');status=@{errorCode=0}},@{appId=$id;authenticationProtocol='private-protocol';clientAppUsed='private-client';authenticationMethodsUsed=@('private-method');clientCredentialType='private-credential';incomingTokenType='private-token-type';signInEventTypes=@('private-event');status=@{errorCode=65001;failureReason='private-failure'}})}
  }
  $inventory=[pscustomobject]@{TenantFingerprint=$fp;Applications=@()}
  $r=Get-TokenForgeSignInApplications $token $inventory
  @($r.Applications[0].ProtocolCounts|Where-Object Value -eq authorizationCodeWithPkce).Count|Should -Be 1
  @($r.Applications[0].OutcomeCounts|Where-Object Value -eq Failed)[0].Count|Should -Be 1
  $r.Applications[0].AuthenticationMethodCounts.Value|Should -Contain FIDO
  $r.Applications[0].IncomingTokenTypeCounts.Value|Should -Contain primaryRefreshToken
  $r.Applications[0].CredentialTypeCounts.Value|Should -Contain certificate
  ($r|ConvertTo-Json -Depth 8)|Should -Not -Match 'private-protocol|private-client|private-event|private-failure|private-method|private-credential|private-token-type'
  Should -Invoke Invoke-TokenForgeGraph -ModuleName TokenForge -Times 1 -ParameterFilter {$IncludeUnknownEnumMembers}
  $null=Update-TokenForgeApplicationMetadata "$TestDrive/protocols.json" $r SignIns
  $r.Applications[0].ProtocolCounts[0].Value='private-injected'
  {Update-TokenForgeApplicationMetadata "$TestDrive/protocols.json" $r SignIns}|Should -Throw '*summary value*'
 }
}
