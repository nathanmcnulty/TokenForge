BeforeAll {Import-Module "$PSScriptRoot/../src/TokenForge/TokenForge.psd1" -Force}
Describe 'Scope candidate evidence' {
 BeforeEach {
  $graph='00000003-0000-0000-c000-000000000000';$client='11111111-1111-1111-1111-111111111111';$other='22222222-2222-2222-2222-222222222222'
  $app=[pscustomobject]@{AppId=$client;Name='Fixture';Registration='Present';Ownership='VerifiedMicrosoftOwner';AccountEnabled=$true;RedirectUris=@('http://localhost');PublishedGrants=@([pscustomobject]@{ResourceId=$graph;Scopes=@('User.Read')})}
  $resource=$app.PSObject.Copy();$resource.AppId=$graph;$resource.PublishedGrants=@()
  $inventory=[pscustomobject]@{CapturedAt=[DateTimeOffset]::UtcNow.ToString('o');TenantFingerprint=('a'*64);PrincipalFingerprint=('b'*64);GrantEnumeration='Complete';Applications=@($app,$resource);TenantGrants=@()}
  $observation=[pscustomobject]@{ClientId=$client;ResourceId=$graph;TenantFingerprint=('a'*64);PrincipalFingerprint=('c'*64);ObservedAt=[DateTimeOffset]::UtcNow.ToString('o');Outcome='Succeeded';NamespaceVerification='Matched';RequestVerification='Matched';ScpScopes=@('User.Read','Mail.Read');RequestedScopes=@('.default');Protocol='OAuth2V2Pkce'}
  $db=New-TokenForgeScopeDatabase;$db.Observations=@($observation)
  $options=@{Inventory=$inventory;Database=$db;ResourceId=$graph;Scope=@('User.Read');PrincipalFingerprint=('c'*64)}
 }
 It 'keeps published hints distinct from configured and observed coverage' {
  $row=Get-TokenForgeScopeCandidates @options
  $row.PublishedScopes|Should -Be @('User.Read')
  $row.ApplicableConfiguredGrantScopes.Count|Should -Be 0
  $row.FreshObservedScopes|Should -Contain Mail.Read
  $row.ObservedAdditionalScopeCount|Should -Be 1
  $row.ObservationStatus|Should -Be FreshCoverage
  $row.RequestedScopes|Should -Be @('.default')
  $row.Evidence|Should -Be PlanningHintsNotGuaranteedSilentExplicitAuthorization
 }
 It 'applies only all-principal grants and grants for the requested observer' {
  $inventory.TenantGrants=@(
   [pscustomobject]@{ClientId=$client;ResourceId=$graph;ConsentType='AllPrincipals';PrincipalFingerprint=$null;Scopes=@('User.Read')},
   [pscustomobject]@{ClientId=$client;ResourceId=$graph;ConsentType='Principal';PrincipalFingerprint=('b'*64);AppliesToCurrentPrincipal=$true;Scopes=@('Mail.Read')},
   [pscustomobject]@{ClientId=$client;ResourceId=$graph;ConsentType='Principal';PrincipalFingerprint=('c'*64);AppliesToCurrentPrincipal=$false;Scopes=@('Files.Read')}
  )
  $row=Get-TokenForgeScopeCandidates @options
  $row.ApplicableConfiguredGrantScopes|Should -Be @('Files.Read','User.Read')
 }
 It 'preserves unknown grant enumeration rather than claiming no consent exists' -TestCases @(@{Status='Forbidden'},@{Status='Skipped'},@{Status='Failed'},@{Status='Unknown'}) {
  param($Status)
  $inventory.GrantEnumeration=$Status;$db.Observations=@()
  $row=Get-TokenForgeScopeCandidates @options
  $row.GrantEnumeration|Should -Be $Status
  $row.ConfiguredGrantStatus|Should -Be Unknown
  $row.ConfiguredGrantMissingScopes|Should -BeNullOrEmpty
  $row.ObservationStatus|Should -Be NotObserved
  $row.CandidateRank|Should -Be 2
 }
 It 'does not restore older coverage after a newer failure' {
  $failure=$observation.PSObject.Copy();$failure.ObservedAt=[DateTimeOffset]::UtcNow.AddSeconds(1).ToString('o');$failure.Outcome='Failed';$db.Observations+=$failure
  $row=Get-TokenForgeScopeCandidates @options
  $row.ObservationStatus|Should -Be LatestAttemptUnsuccessful
  $row.FreshObservedScopes.Count|Should -Be 0
 }
 It 'isolates tenant and observer namespaces' {
  $observation.PrincipalFingerprint='b'*64
  (Get-TokenForgeScopeCandidates @options).ObservationStatus|Should -Be NotObserved
  $observation.PrincipalFingerprint='c'*64;$observation.TenantFingerprint='d'*64
  (Get-TokenForgeScopeCandidates @options).ObservationStatus|Should -Be NotObserved
 }
 It 'shows stale inventory and observations without ranking them as verified acquisition' {
  $inventory.CapturedAt=[DateTimeOffset]::UtcNow.AddDays(-2).ToString('o');$observation.ObservedAt=$inventory.CapturedAt
  $row=Get-TokenForgeScopeCandidates @options
  $row.InventoryFresh|Should -BeFalse
  $row.ObservationStatus|Should -Be Stale
  $row.CandidateRank|Should -Be 3
 }
 It 'ranks fresh observed coverage before grant coverage and published hints' {
  $second=$app.PSObject.Copy();$second.AppId=$other;$inventory.Applications=@($second,$app,$resource)
  $inventory.TenantGrants=@([pscustomobject]@{ClientId=$other;ResourceId=$graph;ConsentType='AllPrincipals';Scopes=@('User.Read')})
  $rows=@(Get-TokenForgeScopeCandidates @options)
  $rows[0].ClientId|Should -Be $client
  $rows[1].CandidateRank|Should -Be 1
 }
 It 'does not rank coverage as eligible when the resource is disabled or absent' {
  $resource.AccountEnabled=$false
  (Get-TokenForgeScopeCandidates @options).CandidateRank|Should -Be 3
  $inventory.Applications=@($app)
  (Get-TokenForgeScopeCandidates @options).ResourceEligible|Should -BeFalse
 }
 It 'does not copy credentials or namespace fingerprints into report rows' {
  $observation|Add-Member AccessToken synthetic-secret
  $app|Add-Member Cookie synthetic-secret
  $json=Get-TokenForgeScopeCandidates @options|ConvertTo-Json -Depth 8
  $json|Should -Not -Match 'synthetic-secret|TenantFingerprint|PrincipalFingerprint|AccessToken|Cookie'
 }
}
