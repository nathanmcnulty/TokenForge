BeforeAll {
 Import-Module "$PSScriptRoot/../src/TokenForge/TokenForge.psd1" -Force
}
Describe 'Inventory wrapper budget for <Action>' -Tag InventoryBudget -ForEach @(@{Action='Probe'},@{Action='ProbeChunk'}) {
 BeforeEach {
  $stage="$PSScriptRoot/../scripts/Invoke-TokenForgeInventory.ps1"
  $state=Join-Path $TestDrive ([guid]::NewGuid().ToString())
  $null=[TokenForge.Core.V0220.PrivateFiles]::Resolve((Join-Path $state 'fixture'),$true)
  $secret=ConvertTo-SecureString synthetic -AsPlainText -Force
  $graph='00000003-0000-0000-c000-000000000000';$cohortId='d'*64
  $apps=@(1..3|ForEach-Object {
   [pscustomobject]@{AppId=('{0:x8}-0000-0000-0000-{0:x12}' -f $_);Registration='Present';Ownership='VerifiedMicrosoftOwner';AccountEnabled=$true;RedirectUris=@('https://login.microsoftonline.com/common/oauth2/nativeclient');PreferredRedirectUri='https://login.microsoftonline.com/common/oauth2/nativeclient';IdentifierUris=@()}
  })
  $inventory=[pscustomobject]@{CapturedAt=[DateTimeOffset]::UtcNow.ToString('o');TenantFingerprint=('a'*64);PrincipalFingerprint=('b'*64);DiscoveryCatalogHash=('c'*64);Applications=$apps}
  $inventory|ConvertTo-Json -Depth 32|Set-Content (Join-Path $state inventory.json)
  $pairs=@($apps|ForEach-Object {@{ClientId=$_.AppId;ResourceId=$graph}})
  $inventoryHash=& (Get-Module TokenForge) {param($apps) Get-TokenForgeFingerprint (ConvertTo-Json -InputObject @($apps|Sort-Object {[string]$_.AppId}) -Depth 32 -Compress)} $apps
  $cohort=[pscustomobject]@{PlanId=$cohortId;BatchSize=3;ChunkCount=1;ClientCount=3;Pending=@($apps|ForEach-Object {@{ClientId=$_.AppId;Chunk=0}});Cohort=@{Authority='organizations';Protocols=@('OAuth2V2Pkce');MaxRedirects=1;ExploreAllFlows=$false;TenantFingerprint=('a'*64);PrincipalFingerprint=('b'*64);CatalogHash=('c'*64);InventoryHash=$inventoryHash;Pairs=$pairs}}
  $opts=@{Action=$Action;StatePath=$state;EstsAuth=$secret;DatabasePath=(Join-Path $state $(if($Action -eq 'ProbeChunk'){'scopes.sqlite'}else{'scopes.json'}));FlowPath=(Join-Path $state flows.json);CohortId=$cohortId}
  $budget=& (Get-Module TokenForge) {$script:OperationBudget=$null;New-TokenForgeOperationBudget -MaxIssuanceAttempts 10}
  $dispatch=@{Count=0}
  # Keep the real wrapper, chunk, probe, JSON checkpoints and budget helpers.
  # Replace acquisition and native persistence; no token or HTTP request leaves this test.
  Mock Import-Module {}
  Mock Get-TokenForgeProbePlan {$pairs}
  Mock Get-TokenForgeResearchCohort -ModuleName TokenForge {$cohort}
  Mock Invoke-TokenForgeNativeEvidence -ModuleName TokenForge {}
  Mock Update-TokenForgeApplicationMetadata {}
  Mock Update-TokenForgeApplicationMetadata -ModuleName TokenForge {}
  Mock Start-Sleep -ModuleName TokenForge {}
  Mock Get-TokenForgeToken -ModuleName TokenForge {
   param($Request,$OperationBudget)
   # Mirror Get-TokenForgeToken's existing module-budget default at this boundary.
   if(-not $OperationBudget){$OperationBudget=& (Get-Module TokenForge) {$script:OperationBudget}}
   & (Get-Module TokenForge) {param($b) Start-TokenForgeBudgetRequest -Budget $b -Category Identity} $OperationBudget
   $dispatch.Count++
   & (Get-Module TokenForge) {param($b) Complete-TokenForgeBudgetRequest -Budget $b} $OperationBudget
   [pscustomobject]@{AccessToken=ConvertTo-SecureString synthetic -AsPlainText -Force;RefreshToken=$null;GrantedScopes=@('User.Read');TokenClaims=[pscustomobject]@{Readable=$true;HasDelegatedScopeClaim=$true;Scopes=@('User.Read');TenantFingerprint=('a'*64);PrincipalFingerprint=('b'*64);ClientId=$Request.ClientId;Audience=$Request.ResourceId}}
  }
 }
 AfterEach {$secret.Dispose();& (Get-Module TokenForge) {$script:OperationBudget=$null}}
 It 'refuses zero issuance before acquisition even with HTTP allowance remaining' {
  $budget.Limits.IssuanceAttempts=0
  {& $stage @opts -OperationBudget $budget}|Should -Throw '*IssuanceAttempts*'
  $budget.Counts.IssuanceAttempts|Should -Be 0;$budget.Counts.TotalRequests|Should -Be 0
  $dispatch.Count|Should -Be 0
  Should -Invoke Get-TokenForgeToken -ModuleName TokenForge -Times 0 -Exactly
 }
 It 'exhausts a finite issuance allowance before the next acquisition' {
  $budget.Limits.IssuanceAttempts=2
  {& $stage @opts -OperationBudget $budget}|Should -Throw '*IssuanceAttempts*'
  $budget.Counts.IssuanceAttempts|Should -Be 2;$budget.Counts.TotalRequests|Should -Be 2
  $dispatch.Count|Should -Be 2
  Should -Invoke Get-TokenForgeToken -ModuleName TokenForge -Times 2 -Exactly
  @((Get-TokenForgeFlowEvidence $opts.FlowPath).Attempts|Where-Object Outcome -eq Succeeded).Count|Should -Be 2
 }
 It 'retains the HTTP request ceiling independently of the issuance ceiling' {
  $budget.Limits.TotalRequests=1
  {& $stage @opts -OperationBudget $budget}|Should -Throw '*TotalRequests*'
  $budget.Counts.TotalRequests|Should -Be 1;$budget.Counts.IdentityRequests|Should -Be 1
  $dispatch.Count|Should -Be 1;$budget.PendingRequest|Should -BeFalse
 }
 It 'refuses an elapsed deadline before acquisition' {
  $budget.Timer=[pscustomobject]@{Elapsed=[TimeSpan]::FromSeconds($budget.MaxSeconds+1)}
  {& $stage @opts -OperationBudget $budget}|Should -Throw '*DeadlineReached*'
  $budget.Counts.TotalRequests|Should -Be 0;$dispatch.Count|Should -Be 0
  Should -Invoke Get-TokenForgeToken -ModuleName TokenForge -Times 0 -Exactly
 }
 It 'retains bounded evidence and does not reissue completed work on resume' {
  $null=& $stage @opts -OperationBudget $budget
  $rows=(Get-TokenForgeFlowEvidence $opts.FlowPath).Attempts
  $before=ConvertTo-Json -InputObject $rows -Depth 32 -Compress
  $rows.Count|Should -Be 3
  @($rows|Where-Object {$_.Contains('ComparisonContext')}).Count|Should -Be 3
  $null=& $stage @opts -OperationBudget $budget
  (ConvertTo-Json -InputObject (Get-TokenForgeFlowEvidence $opts.FlowPath).Attempts -Depth 32 -Compress)|Should -BeExactly $before
  $budget.Counts.IssuanceAttempts|Should -Be 3;$budget.Counts.TotalRequests|Should -Be 3
  Should -Invoke Get-TokenForgeToken -ModuleName TokenForge -Times 3 -Exactly
 }
 It 'preserves bounded refresh refusal for Probe and frozen resume for ProbeChunk' {
  $null=& $stage @opts -OperationBudget $budget
  $before=ConvertTo-Json -InputObject (Get-TokenForgeFlowEvidence $opts.FlowPath).Attempts -Depth 32 -Compress
  if($Action -eq 'Probe'){
   {& $stage @opts -OperationBudget $budget -Refresh}|Should -Throw '*refresh is refused*'
  }else{
   # ProbeChunk has no refresh option: the frozen recipe still resumes its completed cells.
   $null=& $stage @opts -OperationBudget $budget -Refresh
  }
  (ConvertTo-Json -InputObject (Get-TokenForgeFlowEvidence $opts.FlowPath).Attempts -Depth 32 -Compress)|Should -BeExactly $before
  $budget.Counts.IssuanceAttempts|Should -Be 3;$dispatch.Count|Should -Be 3
  Should -Invoke Get-TokenForgeToken -ModuleName TokenForge -Times 3 -Exactly
 }
 It 'preserves no-budget acquisition and the existing action-specific refresh behavior' {
  $null=& $stage @opts
  $dispatch.Count|Should -Be 3
  $null=& $stage @opts -Refresh
  $expected=if($Action -eq 'Probe'){6}else{3}
  $dispatch.Count|Should -Be $expected
  Should -Invoke Get-TokenForgeToken -ModuleName TokenForge -Times $expected -Exactly
 }
}
Describe 'Bounded collector safe session and durable resume' {
 BeforeEach {
  $root=Join-Path $TestDrive ([guid]::NewGuid().ToString())
  $null=New-Item -ItemType Directory $root
  if(-not $IsWindows){[IO.File]::SetUnixFileMode($root,[IO.UnixFileMode]448)}
  $path=Join-Path $root scopes.json;$flow="$path.flows.json"
  $secret=ConvertTo-SecureString synthetic -AsPlainText -Force
  $client='11111111-1111-1111-1111-111111111111';$graph='00000003-0000-0000-c000-000000000000'
  $inventory=[pscustomobject]@{TenantFingerprint=('a'*64);PrincipalFingerprint=('b'*64);DiscoveryCatalogHash=('c'*64);Applications=@([pscustomobject]@{AppId=$client;Registration='Present';Ownership='VerifiedMicrosoftOwner';AccountEnabled=$true;RedirectUris=@('https://login.microsoftonline.com/common/oauth2/nativeclient');PreferredRedirectUri='https://login.microsoftonline.com/common/oauth2/nativeclient';IdentifierUris=@()})}
  $budget=& (Get-Module TokenForge) {New-TokenForgeOperationBudget}
  $opts=@{Inventory=$inventory;EstsAuth=$secret;ResourceId=$graph;DatabasePath=$path;Protocols=@('OAuth2V2Pkce');DelayMilliseconds=0;StopOnTransientFailure=$true;OperationBudget=$budget}
  Mock Get-TokenForgeToken -ModuleName TokenForge {param($Request) [pscustomobject]@{AccessToken=ConvertTo-SecureString synthetic -AsPlainText -Force;RefreshToken=$null;GrantedScopes=@('User.Read');TokenClaims=[pscustomobject]@{Readable=$true;HasDelegatedScopeClaim=$true;Scopes=@('User.Read');TenantFingerprint=('a'*64);PrincipalFingerprint=('b'*64);ClientId=$Request.ClientId;Audience=$Request.ResourceId}}}
 }
 AfterEach {$secret.Dispose()}
 It 'pauses ambiguous interaction and requires explicit session continuation' {
  Mock Get-TokenForgeToken -ModuleName TokenForge {throw 'interaction_required private-cookie private-identity'}
  {Invoke-TokenForgeScopeProbe @opts}|Should -Throw '*paused*'
  (Get-TokenForgeFlowEvidence $flow).Attempts[-1].Outcome|Should -Be SessionPaused
  {Invoke-TokenForgeScopeProbe @opts}|Should -Throw '*continuation*'
  Should -Invoke Get-TokenForgeToken -ModuleName TokenForge -Times 1 -Exactly
  (Get-Content $flow -Raw)|Should -Not -Match 'private-cookie|private-identity|interaction_required'
  Test-Path $path|Should -BeFalse
 }
 It 'records evidenced consent decline for the request without pausing every cell' {
  Mock Get-TokenForgeToken -ModuleName TokenForge {throw 'AADSTS65001 private-cookie'}
  $null=Invoke-TokenForgeScopeProbe @opts
  (Get-TokenForgeFlowEvidence $flow).Attempts[-1].Outcome|Should -Be RequestBlocked
  $before=(Get-FileHash $flow).Hash
  $null=Invoke-TokenForgeScopeProbe @opts
  (Get-FileHash $flow).Hash|Should -Be $before
  Should -Invoke Get-TokenForgeToken -ModuleName TokenForge -Times 1 -Exactly
 }
 It 'records platform redemption code <Code> as request-blocked without replay or raw diagnostics' -TestCases @(@{Code='9002325'},@{Code='9002326'},@{Code='9002327'}) {
  param($Code)
  $script:platformCode=$Code
  Mock Get-TokenForgeToken -ModuleName TokenForge {throw ('Token request failed (HTTP 400). AADSTS'+$script:platformCode+' private-response private-cookie')}
  $null=Invoke-TokenForgeScopeProbe @opts
  $before=Get-TokenForgeFlowEvidence $flow
  $before.Attempts[-1].Outcome|Should -Be RequestBlocked
  $before.Attempts[-1].ErrorCodes|Should -Contain $Code
  $null=Invoke-TokenForgeScopeProbe @opts
  $after=Get-TokenForgeFlowEvidence $flow
  $after.Attempts.Count|Should -Be 1
  $after.Attempts[0].ObservedAt|Should -Be $before.Attempts[0].ObservedAt
  Should -Invoke Get-TokenForgeToken -ModuleName TokenForge -Times 1 -Exactly
  (Get-Content $flow -Raw)|Should -Not -Match 'private-response|private-cookie'
 }
 It 'continues an explicitly renewed paused platform request without rewriting historical evidence' {
  Mock Get-TokenForgeToken -ModuleName TokenForge {throw 'ambiguous synthetic pause'}
  {Invoke-TokenForgeScopeProbe @opts}|Should -Throw '*paused*'
  $old=(Get-TokenForgeFlowEvidence $flow).Attempts[0]
  Mock Get-TokenForgeToken -ModuleName TokenForge {throw 'AADSTS9002327 private-response'}
  $null=Invoke-TokenForgeScopeProbe @opts -ResumePaused
  $rows=(Get-TokenForgeFlowEvidence $flow).Attempts
  $rows.Count|Should -Be 2
  $rows[0].AttemptId|Should -Be $old.AttemptId
  $rows[0].ObservedAt|Should -Be $old.ObservedAt
  $rows[0].Outcome|Should -Be SessionPaused
  $rows[1].Outcome|Should -Be RequestBlocked
  $null=Invoke-TokenForgeScopeProbe @opts
  Should -Invoke Get-TokenForgeToken -ModuleName TokenForge -Times 2 -Exactly
 }
 It 'prioritizes an evidenced session failure over a platform code and keeps unknown failures paused' {
  $er=[Management.Automation.ErrorRecord]::new([InvalidOperationException]::new('AADSTS50173 AADSTS9002327'),'Synthetic',[Management.Automation.ErrorCategory]::AuthenticationError,$null)
  $mixed=& (Get-Module TokenForge) {param($e) Get-TokenForgeProbeFailure $e} $er
  $mixed.Status|Should -Be SessionPaused
  $er=[Management.Automation.ErrorRecord]::new([InvalidOperationException]::new('AADSTS123456789 private-response'),'Synthetic',[Management.Automation.ErrorCategory]::AuthenticationError,$null)
  $unknown=& (Get-Module TokenForge) {param($e) Get-TokenForgeProbeFailure $e} $er
  $unknown.Status|Should -Be SessionPaused
  $unknown.ErrorCodes.Count|Should -Be 0
 }
 It 'pauses expired context and retains numeric allowlist only' {
  Mock Get-TokenForgeToken -ModuleName TokenForge {throw 'AADSTS50173 AADSTS123456789 private-user'}
  {Invoke-TokenForgeScopeProbe @opts}|Should -Throw '*paused*'
  $row=(Get-TokenForgeFlowEvidence $flow).Attempts[-1]
  $row.Outcome|Should -Be SessionPaused
  @($row.ErrorCodes).Count|Should -Be 1;$row.ErrorCodes[0]|Should -Be '50173'
 }
 It 'leaves request intent unknown after an interrupted pre-request checkpoint and allows only one explicit recovery' {
  {Invoke-TokenForgeScopeProbe @opts -CheckpointAction {throw 'synthetic interruption'}}|Should -Throw
  (Get-TokenForgeFlowEvidence $flow).Attempts[-1].Outcome|Should -Be Started
  {Invoke-TokenForgeScopeProbe @opts}|Should -Throw '*unknown*'
  Should -Invoke Get-TokenForgeToken -ModuleName TokenForge -Times 0 -Exactly
  {Invoke-TokenForgeScopeProbe @opts -RecoverUnknown -CheckpointAction {throw 'synthetic interruption'}}|Should -Throw
  (Get-TokenForgeFlowEvidence $flow).Attempts.Count|Should -Be 2
  {Invoke-TokenForgeScopeProbe @opts -RecoverUnknown}|Should -Throw '*unknown*'
  Should -Invoke Get-TokenForgeToken -ModuleName TokenForge -Times 0 -Exactly
 }
 It 'retains terminal primary evidence when projection checkpoint is interrupted and preserves observation date' {
  $script:checks=0
  {Invoke-TokenForgeScopeProbe @opts -CheckpointAction {$script:checks++;if($script:checks -eq 2){throw 'synthetic projection interruption'}}}|Should -Throw
  $row=(Get-TokenForgeFlowEvidence $flow).Attempts[-1]
  $row.Outcome|Should -Be Succeeded
  $result=Invoke-TokenForgeScopeProbe @opts
  $result.ObservedAt|Should -Be $row.ObservedAt
  Should -Invoke Get-TokenForgeToken -ModuleName TokenForge -Times 1 -Exactly
 }
 It 'leaves remote result unknown if terminal durability fails' {
  $script:saveFlowImplementation=& (Get-Module TokenForge) {(Get-Item Function:Save-TokenForgeFlowEvidence).ScriptBlock}
  Mock Save-TokenForgeFlowEvidence -ModuleName TokenForge {param($Path,$Plan,$PlanFingerprint,$Attempt,$ExistingDocument,$NativeExecutablePath,$Changes) & $script:saveFlowImplementation -Path $Path -Plan $Plan -PlanFingerprint $PlanFingerprint -Attempt $Attempt -ExistingDocument $ExistingDocument -NativeExecutablePath $NativeExecutablePath -Changes $Changes }
  Mock Save-TokenForgeFlowEvidence -ModuleName TokenForge {throw 'synthetic lost checkpoint'} -ParameterFilter {$Attempt -and $Attempt.Outcome -eq 'Succeeded'}
  {Invoke-TokenForgeScopeProbe @opts}|Should -Throw '*checkpoint*'
  (Get-TokenForgeFlowEvidence $flow).Attempts[-1].Outcome|Should -Be Started
  {Invoke-TokenForgeScopeProbe @opts}|Should -Throw '*unknown*'
  Should -Invoke Get-TokenForgeToken -ModuleName TokenForge -Times 1 -Exactly
 }
 It 'distinguishes recognized throttling from uncertain interruption' {
  Mock Get-TokenForgeToken -ModuleName TokenForge {throw 'Token request failed (HTTP 429). Details suppressed.'}
  {Invoke-TokenForgeScopeProbe @opts}|Should -Throw '*transient*'
  (Get-TokenForgeFlowEvidence $flow).Attempts[-1].Outcome|Should -Be TransientFailure
 }
 It 'will not refresh or replay a saved mismatched account result' {
  Mock Get-TokenForgeToken -ModuleName TokenForge {param($Request) [pscustomobject]@{AccessToken=ConvertTo-SecureString synthetic -AsPlainText -Force;RefreshToken=$null;TokenClaims=[pscustomobject]@{TenantFingerprint=('a'*64);PrincipalFingerprint=('f'*64)}}}
  $result=Invoke-TokenForgeScopeProbe @opts
  $result.Outcome|Should -Be ContextMismatch
  {Invoke-TokenForgeScopeProbe @opts}|Should -Throw '*mismatch*'
  Should -Invoke Get-TokenForgeToken -ModuleName TokenForge -Times 1 -Exactly
 }
 It 'refuses refresh in a bounded same-plan invocation without replaying a complete cell' {
  $null=Invoke-TokenForgeScopeProbe @opts
  {Invoke-TokenForgeScopeProbe @opts -Refresh}|Should -Throw '*refresh is refused*'
  Should -Invoke Get-TokenForgeToken -ModuleName TokenForge -Times 1 -Exactly
 }
 It 'never automatically retries an uncertain transport failure' {
  Mock Get-TokenForgeToken -ModuleName TokenForge {throw 'Identity transport failed or timed out. Request and response details suppressed.'}
  {Invoke-TokenForgeScopeProbe @opts}|Should -Throw '*unknown*'
  (Get-TokenForgeFlowEvidence $flow).Attempts[-1].Outcome|Should -Be Started
  {Invoke-TokenForgeScopeProbe @opts}|Should -Throw '*unknown*'
  Should -Invoke Get-TokenForgeToken -ModuleName TokenForge -Times 1 -Exactly
 }
 It 'requires a finite budget before explicit uncertainty recovery' {
  $unbounded=$opts.Clone();$unbounded.Remove('OperationBudget')
  {Invoke-TokenForgeScopeProbe @unbounded -RecoverUnknown}|Should -Throw '*finite*'
  Should -Invoke Get-TokenForgeToken -ModuleName TokenForge -Times 0 -Exactly
 }
 It 'does not turn an uncertainty recovery throttle into further automatic requests' {
  {Invoke-TokenForgeScopeProbe @opts -CheckpointAction {throw 'synthetic interruption'}}|Should -Throw
  Mock Get-TokenForgeToken -ModuleName TokenForge {throw 'Token request failed (HTTP 429). Details suppressed.'}
  {Invoke-TokenForgeScopeProbe @opts -RecoverUnknown}|Should -Throw '*transient*'
  {Invoke-TokenForgeScopeProbe @opts -RecoverUnknown}|Should -Throw '*consumed*'
  Should -Invoke Get-TokenForgeToken -ModuleName TokenForge -Times 1 -Exactly
 }
}
Describe 'Read-only collector status contract' {
 BeforeEach {
  $root=Join-Path $TestDrive ([guid]::NewGuid().ToString());$null=New-Item -ItemType Directory $root
  if(-not $IsWindows){[IO.File]::SetUnixFileMode($root,[IO.UnixFileMode]448)}
  $path=Join-Path $root scopes.json;$flow="$path.flows.json";$id='d'*64
  $secret=ConvertTo-SecureString synthetic -AsPlainText -Force
  $client='11111111-1111-1111-1111-111111111111';$graph='00000003-0000-0000-c000-000000000000'
  $inventory=[pscustomobject]@{TenantFingerprint=('a'*64);PrincipalFingerprint=('b'*64);DiscoveryCatalogHash=('c'*64);Applications=@([pscustomobject]@{AppId=$client;Registration='Present';Ownership='VerifiedMicrosoftOwner';AccountEnabled=$true;RedirectUris=@('https://login.microsoftonline.com/common/oauth2/nativeclient');PreferredRedirectUri='https://login.microsoftonline.com/common/oauth2/nativeclient';IdentifierUris=@()})}
  $opts=@{Inventory=$inventory;EstsAuth=$secret;ResourceId=$graph;DatabasePath=$path;Protocols=@('OAuth2V2Pkce');DelayMilliseconds=0;CohortFingerprint=$id}
  Mock Get-TokenForgeResearchCohort -ModuleName TokenForge {[pscustomobject]@{PairCount=1;CompletedClients=0;Pending=@(@{ClientId=$client});Cohort=@{Authority='organizations';Protocols=@('OAuth2V2Pkce');MaxRedirects=1;TenantFingerprint=('a'*64);PrincipalFingerprint=('b'*64);CatalogHash=('c'*64);ExploreAllFlows=$true;Pairs=@(@{ClientId=$client;ResourceId=$graph})}}}
  Mock Get-TokenForgeToken -ModuleName TokenForge {throw 'AADSTS65001'}
 }
 AfterEach {$secret.Dispose()}
 It 'separates pair and cell counts with request-scoped blocking and zero status issuance' {
  $null=Invoke-TokenForgeScopeProbe @opts
  $before=(Get-FileHash $flow).Hash
  $result=Get-TokenForgeCollectorStatus -DatabasePath $path -CohortId $id -FlowPath $flow
  $result.Status|Should -Be RequestBlocked
  $result.SelectedPairs|Should -Be 1;$result.PlannedCells|Should -Be 1
  $result.Pairs.RequestBlocked|Should -Be 1;$result.Cells.RequestBlocked|Should -Be 1
  (Get-FileHash $flow).Hash|Should -Be $before
  Should -Invoke Get-TokenForgeToken -ModuleName TokenForge -Times 1 -Exactly
  ($result|ConvertTo-Json -Depth 6)|Should -Not -Match 'Fingerprint|ClientId|ResourceId|65001'
 }
 It 'rejects corrupt historical attempts even when current selected evidence is valid' {
  $null=Invoke-TokenForgeScopeProbe @opts
  $doc=Get-Content $flow -Raw|ConvertFrom-Json -AsHashtable
  $row=$doc.Attempts[0].Clone();$row.AttemptId=[guid]::NewGuid().ToString();$row.Cookie='synthetic-private';$doc.Attempts+=,$row
  [IO.File]::WriteAllText($flow,($doc|ConvertTo-Json -Depth 12))
  {Get-TokenForgeCollectorStatus -DatabasePath $path -CohortId $id -FlowPath $flow}|Should -Throw
 }
 It 'does not create missing status paths' {
  {Get-TokenForgeCollectorStatus -DatabasePath $path -CohortId $id -FlowPath $flow}|Should -Throw '*existing*'
  Test-Path $path|Should -BeFalse;Test-Path $flow|Should -BeFalse
 }
}
Describe 'Stable collector JSON consumer states' {
 BeforeEach {
  $path=Join-Path $TestDrive 'scope-fixture';$flow=Join-Path $TestDrive 'flow-fixture'
  [IO.File]::WriteAllText($path,'synthetic');[IO.File]::WriteAllText($flow,'synthetic')
  $id='d'*64;$client='11111111-1111-1111-1111-111111111111';$graph='00000003-0000-0000-c000-000000000000';$hash='e'*64
  $cell=@{Protocol='OAuth2V2Pkce';Spa=$false;RedirectFingerprint=('f'*64)}
  $plan=@{Tenant='organizations';TenantFingerprint=('a'*64);PrincipalFingerprint=('b'*64);CatalogHash=('c'*64);CohortFingerprint=$id;ClientId=$client;ResourceId=$graph;Eligibility='Eligible';Cells=@($cell)}
  $key=& (Get-Module TokenForge) {param($h,$c) Get-TokenForgeFingerprint ($h+'|'+$c.Protocol+'|'+[int]$c.Spa+'|'+$c.RedirectFingerprint)} $hash $cell
  $history=@{Plans=@{$hash=$plan};Attempts=@()}
  Mock Get-TokenForgeScopeDatabase -ModuleName TokenForge {New-TokenForgeScopeDatabase}
  Mock Get-TokenForgeFlowEvidence -ModuleName TokenForge {$history}
  Mock Get-TokenForgeResearchCohort -ModuleName TokenForge {[pscustomobject]@{PairCount=1;CompletedClients=0;Pending=@(@{ClientId=$client});Cohort=@{Authority='organizations';Protocols=@('OAuth2V2Pkce');MaxRedirects=1;TenantFingerprint=('a'*64);PrincipalFingerprint=('b'*64);CatalogHash=('c'*64);ExploreAllFlows=$true;Pairs=@(@{ClientId=$client;ResourceId=$graph})}}}
 }
 It 'emits typed <Expected> with independent exact-cell denominator' -ForEach @(
  @{Outcome='Succeeded';Expected='Complete';Exit=0},
  @{Outcome='SessionPaused';Expected='Paused';Exit=3},
  @{Outcome='RequestBlocked';Expected='RequestBlocked';Exit=4},
  @{Outcome='TransientFailure';Expected='TransientExhausted';Exit=5},
  @{Outcome='Started';Expected='InFlightUnknown';Exit=6},
  @{Outcome='Failed';Expected='Failed';Exit=1},
  @{Outcome='ContextMismatch';Expected='AccountMismatch';Exit=7}
 ) {
  $history.Attempts=@(@{PlanFingerprint=$hash;AttemptKey=$key;Outcome=$Outcome;ObservedAt=[DateTimeOffset]::UtcNow.ToString('o')})
  $r=Get-TokenForgeCollectorStatus -DatabasePath $path -CohortId $id -FlowPath $flow|ConvertTo-Json -Depth 6|ConvertFrom-Json
  $r.Status|Should -Be $Expected;$r.ExitCode|Should -Be $Exit
  $r.SelectedPairs|Should -Be 1;$r.PlannedCells|Should -Be 1
 }
 It 'reports structural exclusion separately from tested cells' {
  $plan.Eligibility='NoRedirect';$plan.Cells=@()
  $r=Get-TokenForgeCollectorStatus -DatabasePath $path -CohortId $id -FlowPath $flow
  $r.Status|Should -Be StructurallyExcluded;$r.Pairs.StructurallyExcluded|Should -Be 1;$r.PlannedCells|Should -Be 0
 }
 It 'reports unmaterialized pending pairs without inventing a cell denominator' {
  $history.Plans=@{}
  $r=Get-TokenForgeCollectorStatus -DatabasePath $path -CohortId $id -FlowPath $flow
  $r.Status|Should -Be Pending;$r.UnmaterializedPairs|Should -Be 1;$r.PlannedCells|Should -Be 0
 }
 It 'refuses a hash-valid plan attached to a different frozen authority' {
  $plan.Tenant='consumers'
  {Get-TokenForgeCollectorStatus -DatabasePath $path -CohortId $id -FlowPath $flow}|Should -Throw '*recipe*'
 }
}
