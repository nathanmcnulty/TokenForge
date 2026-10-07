BeforeAll {
 Import-Module "$PSScriptRoot/../src/TokenForge/TokenForge.psd1" -Force
 $graph='00000003-0000-0000-c000-000000000000';$client='11111111-1111-1111-1111-111111111111'
 $runner="$PSScriptRoot/../scripts/Invoke-TokenForgeInventory.ps1"
}
Describe 'Exact flow evidence and coverage' {
 BeforeEach {
  $state=Join-Path ($TestDrive -replace '^/var/','/private/var/') ([guid]::NewGuid().ToString())
  $null=New-Item -ItemType Directory $state
  if(-not $IsWindows){[IO.File]::SetUnixFileMode($state,[IO.UnixFileMode]448)}
  $path=Join-Path $state scopes.json;$flowPath="$path.flows.json";$metadata=Join-Path $state applications.json
  $secret=ConvertTo-SecureString synthetic -AsPlainText -Force
  $app=[pscustomobject]@{AppId=$client;Name='Synthetic';Registration='Present';Ownership='VerifiedMicrosoftOwner';AccountEnabled=$true;RedirectUris=@('https://example.test/callback');PreferredRedirectUri='https://example.test/callback';IdentifierUris=@();PublicClient=$true;PublishedGrants=@();DelegatedScopeDefinitions=@();IsResourceCandidate=$false;Sources=@();OwnerTenantId='f8cdef31-a31e-4b4a-93e4-5f571e91255a'}
  $inventory=[pscustomobject]@{SchemaVersion=1;CapturedAt=[DateTimeOffset]::UtcNow.ToString('o');TenantFingerprint=('a'*64);PrincipalFingerprint=('b'*64);DiscoveryCatalogHash=('c'*64);Applications=@($app);TenantGrants=@()}
  Mock Get-TokenForgeToken -ModuleName TokenForge {
   param($Request)
   [pscustomobject]@{AccessToken=ConvertTo-SecureString private-access -AsPlainText -Force;RefreshToken=$null;GrantedScopes=@('User.Read');TokenClaims=[pscustomobject]@{Readable=$true;HasDelegatedScopeClaim=$true;Scopes=@('User.Read');TenantFingerprint=('a'*64);PrincipalFingerprint=('b'*64);ClientId=$Request.ClientId;Audience=$Request.ResourceId}}
  }
 }
 AfterEach {$secret.Dispose()}
 It 'retains all four cells, resumes without issuance, and reports selected-account coverage' {
  $null=Invoke-TokenForgeScopeProbe $inventory $secret -ResourceId $graph -DatabasePath $path -ExploreAllFlows -DelayMilliseconds 0
  $flows=Get-TokenForgeFlowEvidence $flowPath
  $flows.Attempts.Count|Should -Be 4
  @($flows.Attempts|Where-Object Outcome -eq Succeeded).Count|Should -Be 4
  $null=Invoke-TokenForgeScopeProbe $inventory $secret -ResourceId $graph -DatabasePath $path -ExploreAllFlows -DelayMilliseconds 0
  Should -Invoke Get-TokenForgeToken -ModuleName TokenForge -Times 4
  $null=Update-TokenForgeApplicationMetadata $metadata $inventory Inventory
  $null=Update-TokenForgeApplicationMetadata $metadata $flows FlowAttempts
  $report=Get-TokenForgeResearchCoverage $metadata -FlowPath $flowPath -TenantFingerprint ('a'*64) -PrincipalFingerprint ('b'*64)
  $report.PlannedSlots|Should -Be 4;$report.TerminalSlots|Should -Be 4;$report.UntestedSlots|Should -Be 0
  $report.ApplicationsWithObservedSuccess|Should -Be 1
  (Get-TokenForgeResearchCoverage $metadata -FlowPath $flowPath).PlannedSlots|Should -Be 0
  {Get-TokenForgeApplicationMetadata $metadata -PublicOnly}|Should -Throw
 }
 It 'leaves alternatives untested after first success and preserves failures in exhaustive mode' {
  $null=Invoke-TokenForgeScopeProbe $inventory $secret -ResourceId $graph -DatabasePath $path -DelayMilliseconds 0
  (Get-TokenForgeFlowEvidence $flowPath).Attempts.Count|Should -Be 1
  Mock Get-TokenForgeToken -ModuleName TokenForge {throw 'AADSTS65001 private-user private-cookie'} -ParameterFilter {$Request.Protocol -ne 'OAuth2V2Pkce'}
  $null=Invoke-TokenForgeScopeProbe $inventory $secret -ResourceId $graph -DatabasePath $path -ExploreAllFlows -DelayMilliseconds 0
  $flows=Get-TokenForgeFlowEvidence $flowPath
  @($flows.Attempts|Where-Object Outcome -eq Failed).Count|Should -Be 2
  (Get-Content $flowPath -Raw)|Should -Not -Match 'private-user|private-cookie|private-access'
  $null=Update-TokenForgeApplicationMetadata $metadata $inventory Inventory
  $null=Update-TokenForgeApplicationMetadata $metadata $flows FlowAttempts
  $report=Get-TokenForgeResearchCoverage $metadata -FlowPath $flowPath -TenantFingerprint ('a'*64) -PrincipalFingerprint ('b'*64)
  $report.Applications[0].FlowCoverage[0].FailedSlots|Should -Be 2
 }
 It 'resumes a fully failed plan without duplicate attempts or aggregate rows' {
  Mock Get-TokenForgeToken -ModuleName TokenForge {throw 'AADSTS65001'}
  $null=Invoke-TokenForgeScopeProbe $inventory $secret -ResourceId $graph -DatabasePath $path -ExploreAllFlows -DelayMilliseconds 0
  $before=(Get-FileHash $flowPath).Hash
  @(Invoke-TokenForgeScopeProbe $inventory $secret -ResourceId $graph -DatabasePath $path -ExploreAllFlows -DelayMilliseconds 0).Count|Should -Be 0
  (Get-FileHash $flowPath).Hash|Should -Be $before
  (Get-TokenForgeScopeDatabase $path).Observations.Count|Should -Be 1
  Should -Invoke Get-TokenForgeToken -ModuleName TokenForge -Times 4
 }
 It 'retries a newer Started slot even when older terminal evidence exists' {
  $null=Invoke-TokenForgeScopeProbe $inventory $secret -ResourceId $graph -DatabasePath $path -ExploreAllFlows -DelayMilliseconds 0
  $flows=Get-TokenForgeFlowEvidence $flowPath;$row=$flows.Attempts[0].Clone()
  $row.AttemptId=[guid]::NewGuid().ToString();$row.StartedAt=[DateTimeOffset]::UtcNow.ToString('o');$row.ObservedAt=$row.StartedAt;$row.Outcome='Started'
  & (Get-Module TokenForge) {param($path,$row) $null=Save-TokenForgeFlowEvidence $path -Attempt $row} $flowPath $row
  $null=Invoke-TokenForgeScopeProbe $inventory $secret -ResourceId $graph -DatabasePath $path -ExploreAllFlows -DelayMilliseconds 0
  Should -Invoke Get-TokenForgeToken -ModuleName TokenForge -Times 5
 }
 It 'reconstructs the aggregate after a new plan checkpoint without repeating issuance' {
  $null=Invoke-TokenForgeScopeProbe $inventory $secret -ResourceId $graph -DatabasePath $path -Protocols OAuth2V2Implicit -DelayMilliseconds 0
  $old=Get-Content $path -Raw
  $null=Invoke-TokenForgeScopeProbe $inventory $secret -ResourceId $graph -DatabasePath $path -Protocols OAuth2V2Pkce -DelayMilliseconds 0
  Set-Content $path $old
  $null=Invoke-TokenForgeScopeProbe $inventory $secret -ResourceId $graph -DatabasePath $path -Protocols OAuth2V2Pkce -DelayMilliseconds 0
  Should -Invoke Get-TokenForgeToken -ModuleName TokenForge -Times 2
  (Get-TokenForgeScopeDatabase $path).Observations[-1].Protocol|Should -Be OAuth2V2Pkce
 }
 It 'treats changed callback hints as a new plan and keeps old evidence' {
  $null=Invoke-TokenForgeScopeProbe $inventory $secret -ResourceId $graph -DatabasePath $path -DelayMilliseconds 0
  $app.RedirectUris=@('https://example.test/changed');$app.PreferredRedirectUri=$app.RedirectUris[0]
  $null=Invoke-TokenForgeScopeProbe $inventory $secret -ResourceId $graph -DatabasePath $path -DelayMilliseconds 0
  (Get-TokenForgeFlowEvidence $flowPath).Plans.Count|Should -Be 2
  Should -Invoke Get-TokenForgeToken -ModuleName TokenForge -Times 2
 }
 It 'rejects injected flow fields at both read and metadata boundaries' {
  $null=Invoke-TokenForgeScopeProbe $inventory $secret -ResourceId $graph -DatabasePath $path -DelayMilliseconds 0
  $flows=Get-TokenForgeFlowEvidence $flowPath;$flows.Attempts[0].Cookie='private-cookie'
  {Update-TokenForgeApplicationMetadata $metadata $flows FlowAttempts}|Should -Throw
  $flows|ConvertTo-Json -Depth 12|Set-Content $flowPath
  {Get-TokenForgeFlowEvidence $flowPath}|Should -Throw '*Details suppressed*'
 }
 It 'exports only anonymous matched successes and never linkage fields' {
  $null=Invoke-TokenForgeScopeProbe $inventory $secret -ResourceId $graph -DatabasePath $path -ExploreAllFlows -DelayMilliseconds 0
  $export=Join-Path $state public.json;Export-TokenForgeFlowEvidence $flowPath -OutputPath $export
  $json=Get-Content $export -Raw
  $json|Should -Not -Match 'Fingerprint|AttemptId|ObservedAt|PlannedAt|example.test|private-access|private-refresh'
  ($json|ConvertFrom-Json).Observations.Count|Should -Be 4
 }
 It 'supports offline report and anonymous export through the simple CLI' {
  $null=Invoke-TokenForgeScopeProbe $inventory $secret -ResourceId $graph -DatabasePath $path -DelayMilliseconds 0
  Copy-Item $flowPath (Join-Path $state flows.json)
  $null=Update-TokenForgeApplicationMetadata $metadata $inventory Inventory
  $cli="$PSScriptRoot/../scripts/tokenforge.ps1"
  $r=(& $cli research report -StatePath $state -SummaryOnly -Json)|ConvertFrom-Json
  $r.ApplicationCount|Should -Be 1;$r.PlannedSlots|Should -Be 0
  $r=(& $cli research report -StatePath $state -TenantFingerprint ('a'*64) -PrincipalFingerprint ('b'*64) -SummaryOnly -Json)|ConvertFrom-Json
  $r.PlannedSlots|Should -Be 4;$r.TerminalSlots|Should -Be 1;$r.UntestedSlots|Should -Be 3
  $export=Join-Path $state anonymous.json
  $r=(& $cli research export-flows -StatePath $state -ExportPath $export -Json)|ConvertFrom-Json
  $r.Exported|Should -BeTrue;$r.CredentialOutput|Should -BeFalse
 }
 It 'halts the whole matrix after issued account mismatch' {
  Mock Get-TokenForgeToken -ModuleName TokenForge {param($Request) [pscustomobject]@{AccessToken=ConvertTo-SecureString synthetic -AsPlainText -Force;RefreshToken=$null;GrantedScopes=@();TokenClaims=[pscustomobject]@{TenantFingerprint=('a'*64);PrincipalFingerprint=('f'*64)}}}
  $result=Invoke-TokenForgeScopeProbe $inventory $secret -ResourceId $graph,'797f4846-ba00-4fd7-ba43-dac1f8f63013' -DatabasePath $path -ExploreAllFlows -DelayMilliseconds 0
  $result.Outcome|Should -Be ContextMismatch
  Should -Invoke Get-TokenForgeToken -ModuleName TokenForge -Times 1
 }
}
