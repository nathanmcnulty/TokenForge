BeforeAll {
 Import-Module "$PSScriptRoot/../src/TokenForge/TokenForge.psd1" -Force
}
Describe 'Assessment freshness and private export boundaries' {
 BeforeEach {
  $client='11111111-1111-1111-1111-111111111111'
  $graph='00000003-0000-0000-c000-000000000000'
  $observation=[pscustomobject]@{ClientId=$client;ResourceId=$graph;Outcome='Succeeded';ObservedAt=[DateTimeOffset]::UtcNow.ToString('o');TenantFingerprint=('a'*64);PrincipalFingerprint=('b'*64);ScpScopes=@('User.Read','Mail.Read');NamespaceVerification='Matched';RequestVerification='Matched'}
  $database=New-TokenForgeScopeDatabase
  $database.Observations=@($observation)
  $manifest=Join-Path $PSScriptRoot '../manifests/self-profile.json'
  $planOptions=@{ManifestPath=$manifest;Database=$database;TenantFingerprint=('a'*64);PrincipalFingerprint=('b'*64)}
  $inventory=[pscustomobject]@{CapturedAt=[DateTimeOffset]::UtcNow.ToString('o');TenantFingerprint=('a'*64);PrincipalFingerprint=('b'*64);TenantGrants=@();Applications=@([pscustomobject]@{AppId=$client;Registration='Present';Ownership='VerifiedMicrosoftOwner';AccountEnabled=$true;PublishedGrants=@();DelegatedScopeDefinitions=@()})}
 }
 It 'ranks scope candidates without claiming role, licensing, or API access' {
  $plan=Get-TokenForgeAssessmentPlan @planOptions
  $plan.Checks[0].BestClientId|Should -Be $client
  $plan.Checks[0].Candidates[0].AdditionalScopes|Should -Contain Mail.Read
  $plan.Checks[0].ApiStatus|Should -Be NotValidated
  $plan.Checks[0].RoleStatus|Should -Be NotValidated
  $plan.Checks[0].LicensingStatus|Should -Be NotValidated
 }
 It 'does not substitute a different observer or stale evidence' {
  $planOptions.PrincipalFingerprint='c'*64
  (Get-TokenForgeAssessmentPlan @planOptions).Checks[0].ScopeStatus|Should -Be NeedsObservation
  $planOptions.PrincipalFingerprint='b'*64
  $observation.ObservedAt=[DateTimeOffset]::UtcNow.AddHours(-25).ToString('o')
  (Get-TokenForgeAssessmentPlan @planOptions).Checks[0].ScopeStatus|Should -Be NeedsObservation
 }
 It 'rejects future-dated evidence as fresh coverage' {
  $observation.ObservedAt=[DateTimeOffset]::UtcNow.AddHours(3).ToString('o')
  (Get-TokenForgeAssessmentPlan @planOptions).Checks[0].ScopeStatus|Should -Be NeedsObservation
  (Get-TokenForgeMaintenanceReport -Inventory $inventory -Database $database -PrincipalFingerprint ('b'*64)).ProbeQueue[0].Reason|Should -Be InvalidFutureTimestamp
 }
 It 'queues stale evidence and a different observer independently' {
  $observation.ObservedAt=[DateTimeOffset]::UtcNow.AddHours(-25).ToString('o')
  (Get-TokenForgeMaintenanceReport -Inventory $inventory -Database $database -PrincipalFingerprint ('b'*64)).ProbeQueue[0].Reason|Should -Be Stale
  (Get-TokenForgeMaintenanceReport -Inventory $inventory -Database $database -PrincipalFingerprint ('c'*64)).ProbeQueue[0].Reason|Should -Be NotObserved
 }
 It 'does not fall back to older success after a failed probe' {
  $failed=$observation.PSObject.Copy();$failed.Outcome='Failed';$failed.ObservedAt=[DateTimeOffset]::UtcNow.AddSeconds(1).ToString('o')
  $database.Observations+=$failed
  (Get-TokenForgeAssessmentPlan @planOptions).Checks[0].ScopeStatus|Should -Be NeedsObservation
  (Get-TokenForgeMaintenanceReport -Inventory $inventory -Database $database -PrincipalFingerprint ('b'*64)).ProbeQueue[0].Reason|Should -Be Unavailable
 }
 It 'rejects mismatched API hosts instead of treating the manifest as executable instructions' {
  $document=Get-Content $manifest -Raw|ConvertFrom-Json
  $document.Checks[0].ApiUri='https://other.example.test/v1.0/me'
  $document|ConvertTo-Json -Depth 10|Set-Content "$TestDrive/manifest.json"
  $planOptions.ManifestPath="$TestDrive/manifest.json"
  {Get-TokenForgeAssessmentPlan @planOptions}|Should -Throw '*boundary*'
 }
 It 'rejects nested private data in an export before replacing the destination' {
  'previous export'|Set-Content "$TestDrive/export.json"
  $observation.ScpScopes=@([pscustomobject]@{AccessToken='synthetic-secret'})
  {Export-TokenForgeScopeDatabase -Database $database -Path "$TestDrive/export.json"}|Should -Throw '*invalid public*'
  (Get-Content "$TestDrive/export.json" -Raw).Trim()|Should -Be 'previous export'
 }
 It 'omits unverified observer evidence from the anonymous export' {
  $observation.NamespaceVerification='Unverifiable'
  Export-TokenForgeScopeDatabase -Database $database -Path "$TestDrive/export.json"
  @( (Get-Content "$TestDrive/export.json" -Raw|ConvertFrom-Json).Observations).Count|Should -Be 0
 }
}
Describe 'Observation ordering uses instants rather than timestamp text' {
 It 'prefers a later failed observation with a different UTC offset' {
  $now=[DateTimeOffset]::UtcNow
  $client='11111111-1111-1111-1111-111111111111'
  $graph='00000003-0000-0000-c000-000000000000'
  $success=[pscustomobject]@{ClientId=$client;ResourceId=$graph;Outcome='Succeeded';ObservedAt=$now.AddHours(-2).ToOffset([TimeSpan]::FromHours(5)).ToString('o');TenantFingerprint=('a'*64);PrincipalFingerprint=('b'*64);ScpScopes=@('User.Read');NamespaceVerification='Matched';RequestVerification='Matched'}
  $failure=$success.PSObject.Copy();$failure.Outcome='Failed';$failure.ObservedAt=$now.AddHours(-1).ToString('o')
  $db=New-TokenForgeScopeDatabase;$db.Observations=@($success,$failure)
  @(Get-TokenForgeAssessmentCoverage -Database $db -ResourceId $graph -Scope User.Read -TenantFingerprint ('a'*64) -PrincipalFingerprint ('b'*64)).Count|Should -Be 0
  $old=New-TokenForgeScopeDatabase;$old.Observations=@($success)
  (Compare-TokenForgeScopeDatabase -Before $old -After $db).AfterOutcome|Should -Be Failed
 }
 It 'requests inventory refresh for a future timestamp' {
  $inventory=[pscustomobject]@{CapturedAt=[DateTimeOffset]::UtcNow.AddDays(1).ToString('o');TenantFingerprint=('a'*64);PrincipalFingerprint=('b'*64);Applications=@();TenantGrants=@()}
  (Get-TokenForgeMaintenanceReport -Inventory $inventory -Database (New-TokenForgeScopeDatabase) -PrincipalFingerprint ('b'*64)).InventoryRefreshRequired|Should -BeTrue
 }
}
