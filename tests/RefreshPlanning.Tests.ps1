BeforeAll { . "$PSScriptRoot/fixtures/refresh/RefreshFixture.ps1" }
Describe 'Goal 4 private refresh compatibility and freshness' {
 It 'plans missing declared evidence without authenticating or modifying legacy identities' {
  $i=New-RefreshInput;$p=Plan-Refresh $i
  $p.SelectedCount|Should -Be 1;$p.Candidates[0].Reason|Should -Be MissingEvidence;$p.AuthorizationEstablished|Should -BeFalse
  $p.Candidates[0].ExactIdentity.LegacyInventoryHash|Should -Be ('7'*64);$p.Candidates[0].RequiredIssuanceAttempts|Should -Be 2
 }
 It 'produces no issuance plan for all fresh compatible evidence and retains original references' {
  $i=New-WarmRefreshInput;$p=Plan-Refresh $i
  $p.HasIssuancePlan|Should -BeFalse;$p.ReusedCount|Should -Be 1
  $p.Candidates[0].ReuseReferences[0].ObservedAt|Should -Be $script:rfNow.AddMinutes(-9).ToString('o')
  $p.Candidates[0].ReuseExactIdentity.SourceRevision|Should -Be ('1'*40)
 }
 It 'preserves reuse after an unrelated display-name change while exact inventory identity changes' {
  $i=New-WarmRefreshInput;$before=Plan-Refresh $i;$i.Inventory.Applications[0].Name='Changed unrelated name';$after=Plan-Refresh $i
  $after.ReusedCount|Should -Be 1;$after.Candidates[0].CompatibilityKey|Should -Be $before.Candidates[0].CompatibilityKey
  $after.Candidates[0].ExactIdentity.InventorySha256|Should -Not -Be $before.Candidates[0].ExactIdentity.InventorySha256
  $after.Candidates[0].ReuseExactIdentity.InventorySha256|Should -Be $before.Candidates[0].ExactIdentity.InventorySha256
 }
 It 'invalidates relevant definition, callback, policy or collector changes' -TestCases @(@{Case='Definition'},@{Case='Callback'},@{Case='Policy'},@{Case='Semantics'}) {
  param($Case)
  $i=New-WarmRefreshInput
  switch($Case){Definition {$i.Inventory.Applications[2].DelegatedScopeDefinitions[0].Id='44444444-4444-4444-4444-444444444444'} Callback {$i.Inventory.Applications[0].RedirectUris=@('https://login.microsoftonline.com/organizations/oauth2/nativeclient')} Policy {$i.Profile.MaxAdditionalScopes=1} Semantics {$i.Pins.CollectorSemanticsSha256='9'*64}}
  $p=Plan-Refresh $i;$p.ReusedCount|Should -Be 0;$p.Candidates[0].Reason|Should -Be ToolCriticalRelevantChange;$p.SelectedCount|Should -Be 1
 }
 It 'keeps namespaces isolated rather than reusing another account history' {
  $i=New-WarmRefreshInput;$i.Profile.ExpectedPrincipalFingerprint='c'*64;$i.Inventory.PrincipalFingerprint='c'*64
  $p=Plan-Refresh $i;$p.ReusedCount|Should -Be 0;$p.Candidates[0].Reason|Should -Be MissingEvidence
 }
 It 'reports budget misses without broadening either the budget or freshness target' {
  $i=New-RefreshInput;$i.Policy.MaxIssuanceAttempts=1;$p=Plan-Refresh $i
  $p.HasIssuancePlan|Should -BeFalse;$p.FreshnessMisses[0].Reason|Should -Be GlobalBudget
 }
 It 'blocks issuance when private planning inventory is beyond the explicit age bound' {
  $i=New-RefreshInput;$i.Inventory.CapturedAt=$script:rfNow.AddDays(-2).ToString('o');$p=Plan-Refresh $i
  $p.HasIssuancePlan|Should -BeFalse;$p.Candidates[0].Deferral|Should -Be PlanningInventoryNotCurrent
 }
 It 'retains immutable original evidence when source/package pins advance compatibly' {
  $i=New-WarmRefreshInput;$i.Pins.SourceRevision='9'*40;$i.Pins.PackageManifestSha256='8'*64;$p=Plan-Refresh $i
  $p.ReusedCount|Should -Be 1;$p.Candidates[0].ExactIdentity.SourceRevision|Should -Be ('9'*40)
  $p.Candidates[0].ReuseExactIdentity.SourceRevision|Should -Be ('1'*40)
 }
 It 'is reproducible for identical frozen inputs and evaluation time' {
  $i=New-WarmRefreshInput;$a=Plan-Refresh $i;$b=Plan-Refresh $i;$a.PlanId|Should -Be $b.PlanId
 }
 It 'rejects malformed history keys and credential fields before selecting any work' -TestCases @(@{Case='Key'},@{Case='Credential'},@{Case='Reference'}) {
  param($Case)
  $i=New-WarmRefreshInput
  switch($Case){Key {$i.History.Entries[0].CompatibilityKey='9'*64} Credential {$i.History.Entries[0].CompatibilityDescriptor.Client.AccessToken='synthetic-private'} Reference {$i.History.Entries[0].ObservationReferences[0].RecordId='9'*64}}
  {Plan-Refresh $i}|Should -Throw '*Administrator workflow input*'
 }
 It 'does not migrate old observations by assigning a newly observed date or descriptor' {
  $i=New-RefreshInput;$p=Plan-Refresh $i;$s=New-RefreshObservation $p -At $script:rfNow.AddMinutes(-1)
  $h=Capture-Refresh $p $s $i.History;$h.Entries.Count|Should -Be 0
 }
}
Describe 'Goal 4 cooldown and bounded fairness' {
 It 'starts a stable-failure cooldown at 24 hours and resets it on relevant change' {
  $i=New-RefreshInput;$p=Plan-Refresh $i $script:rfNow.AddMinutes(-10);$s=New-RefreshObservation $p -Outcome RequestBlocked;$i.History=Capture-Refresh $p $s $i.History;$i.Snapshot=$s
  $q=Plan-Refresh $i;$q.Candidates[0].Deferral|Should -Be StableFailureCooldown
  $q.Candidates[0].CooldownUntil|Should -Be $script:rfNow.AddMinutes(-9).AddHours(24).ToString('o')
  $i.Inventory.Applications[0].AccountEnabled=$false;$changed=Plan-Refresh $i
  $changed.Candidates[0].FailureStreak|Should -Be 0;$changed.Candidates[0].CooldownUntil|Should -BeNullOrEmpty
 }
 It 'backs off stable failures without deleting last-known success or original dates' {
  $i=New-RefreshInput;$i.Inventory.CapturedAt=$script:rfNow.AddHours(-51).ToString('o');$old=Plan-Refresh $i $script:rfNow.AddHours(-50);$good=New-RefreshObservation $old -At $script:rfNow.AddHours(-49);$i.History=Capture-Refresh $old $good $i.History;$i.Snapshot=$good;$i.Inventory.CapturedAt=$script:rfNow.AddHours(-1).ToString('o');$p=Plan-Refresh $i $script:rfNow.AddMinutes(-8);$s=New-RefreshObservation $p -Outcome RequestBlocked -At $script:rfNow.AddMinutes(-7);$i.History=Capture-Refresh $p $s $i.History;$s2=New-RefreshObservation $p -Outcome RequestBlocked -At $script:rfNow.AddMinutes(-6);$i.History=Capture-Refresh $p $s2 $i.History;$i.Snapshot=$s2
  $q=Plan-Refresh $i;$q.Candidates[0].FailureStreak|Should -Be 2;$q.Candidates[0].LastKnownSuccess.Outcome|Should -Be Succeeded
  $q.Candidates[0].CooldownUntil|Should -Be $script:rfNow.AddMinutes(-6).AddHours(48).ToString('o')
 }
 It 'reserves a bounded fairness share for a lower priority class under a busy critical queue' {
  $i=New-RefreshInput;$base=$i.Requirements.Tools[0];$i.Requirements.Tools=@(for($n=0;$n -lt 20;$n++){$t=Copy-Refresh $base;$t.Id='tool-'+$n.ToString('00');$t});$i.Policy=Read-RefreshJson ([TokenForge.Core.AdminWorkflows]::CreateRefreshPolicy(($i.Requirements|ConvertTo-Json -Depth 30 -Compress),10));$i.Policy.CriticalToolIds=@($i.Requirements.Tools[0..17].Id)
  $q=Plan-Refresh $i;$q.SelectedCount|Should -Be 10;@($q.Candidates|Where-Object FairnessSelected).Count|Should -Be 1
  @($q.Candidates|Where-Object {$_.Selected -and $_.Reason -eq 'Exploration'}).Count|Should -Be 1
 }
}
Describe 'Goal 4 full validation and independent review regressions' {
 It 'rejects a modified saved selection even with a plausible plan digest' {
  $p=Plan-Refresh (New-RefreshInput);$p.Candidates[0].RequiredIssuanceAttempts=0
  {[TokenForge.Core.AdminWorkflows]::ValidateRefresh(($p|ConvertTo-Json -Depth 100 -Compress))}|Should -Throw
 }
 It 'captures only selected work and never manufactures compatible history for deferred evidence' {
  $i=New-RefreshInput;$i.Policy.MaxSelectedRequests=0;$p=Plan-Refresh $i $script:rfNow.AddMinutes(-10)
  (Capture-Refresh $p (New-RefreshObservation $p) $i.History).Entries.Count|Should -Be 0
 }
 It 'blocks old success reuse for a newer unattached failure or empty denied collection' -TestCases @(@{Denied=$false},@{Denied=$true}) {
  param($Denied)
  $i=New-WarmRefreshInput;$p=Plan-Refresh $i;$s=New-RefreshObservation $p -Outcome RequestBlocked -At $script:rfNow.AddMinutes(-1)
  if($Denied){$s.Collections[0].Status='Denied';$s.Collections[0].Records=@()}
  $i.Snapshot=$s;$q=Plan-Refresh $i;$q.ReusedCount|Should -Be 0;$q.Candidates[0].LastKnownSuccess.Outcome|Should -Be Succeeded
 }
 It 'resolves equal-time contradictory snapshots without history-order dependence' {
  $i=New-RefreshInput;$p=Plan-Refresh $i $script:rfNow.AddMinutes(-10)
  $good=New-RefreshObservation $p;$bad=New-RefreshObservation $p -Outcome RequestBlocked
  $i.History=Capture-Refresh $p $good $i.History;$i.History=Capture-Refresh $p $bad $i.History;$i.Snapshot=$bad
  $a=Plan-Refresh $i;[array]::Reverse($i.History.Entries);$b=Plan-Refresh $i
  $a.ReusedCount|Should -Be 0;$b.ReusedCount|Should -Be 0;$a.Candidates[0].Reason|Should -Be $b.Candidates[0].Reason
 }
 It 'invalidates bootstrap, assignment and required-scope consent metadata' -TestCases @(@{Case='Bootstrap'},@{Case='Assignment'},@{Case='Consent'}) {
  param($Case)
  $i=New-WarmRefreshInput
  switch($Case){Bootstrap {$i.Inventory.Applications[1].AccountEnabled=$false} Assignment {$i.Inventory.Applications[0].AssignmentRequired=$true} Consent {$i.Inventory.Applications[2].DelegatedScopeDefinitions[0].ConsentType='Admin'}}
  $p=Plan-Refresh $i;$p.ReusedCount|Should -Be 0
  if($Case -eq 'Bootstrap'){$p.SelectedCount|Should -Be 0;$p.Candidates[0].Deferral|Should -Be NoSilentBootstrapRoute}
 }
 It 'reports callback bound instead of silently truncating alternatives' {
  $i=New-RefreshInput;$i.Inventory.Applications[0].RedirectUris=@(for($n=0;$n -lt 9;$n++){"https://login.microsoftonline.com/tenant$n/oauth2/nativeclient"})
  $p=Plan-Refresh $i;$p.SelectedCount|Should -Be 0;$p.Excluded[0].Reason|Should -Be CallbackBoundExceeded
 }
 It 'reserves a fairness seat even with a two-request budget' {
  $i=New-RefreshInput;$base=$i.Requirements.Tools[0];$i.Requirements.Tools=@(for($n=0;$n -lt 4;$n++){$t=Copy-Refresh $base;$t.Id='small-'+$n;$t});$i.Policy=Read-RefreshJson ([TokenForge.Core.AdminWorkflows]::CreateRefreshPolicy(($i.Requirements|ConvertTo-Json -Depth 30 -Compress),2));$i.Policy.CriticalToolIds=@('small-0','small-1','small-2')
  $q=Plan-Refresh $i;@($q.Candidates|Where-Object FairnessSelected).Count|Should -Be 1
 }
}
Describe 'Goal 4 durable request accounting' {
 BeforeEach {
  $root=Join-Path $TestDrive ([guid]::NewGuid().ToString('N'));$null=[IO.Directory]::CreateDirectory($root,[IO.UnixFileMode]448)
  $i=New-RefreshInput;$i.Inventory.CapturedAt=[DateTimeOffset]::UtcNow.AddMinutes(-1).ToString('o');$p=Plan-Refresh $i ([DateTimeOffset]::UtcNow)
  $planJson=ConvertTo-Json -InputObject $p -Depth 100 -Compress;$id=$p.Candidates[0].RequestId;$path=Join-Path $root run.json
 }
 It 'saves intent before dispatch, charges unknown consumption and refuses automatic replay' {
  $r=[TokenForge.Core.AdminWorkflows]::OpenRefreshRun($planJson,$path)
  try{$seq=$r.Reserve($id,'FinalIssuance');$onDisk=Read-RefreshJson ([IO.File]::ReadAllText($path));$onDisk.Events[0].Outcome|Should -Be Intent}finally{$r.Dispose()}
  $r=[TokenForge.Core.AdminWorkflows]::OpenRefreshRun($planJson,$path)
  try{$status=Read-RefreshJson $r.Status();$status.IssuanceAttempts|Should -Be 1;$status.InFlightUnknownCount|Should -Be 1;{$r.Reserve($id,'FinalIssuance')}|Should -Throw;{$r.Reserve($id,'FinalIssuance',1,$true)}|Should -Throw}finally{$r.Dispose()}
 }
 It 'permits only one explicitly recorded recovery of a supported GET and retains both charges' {
  $i.Policy.MaxSourceRequests=4;$p=Plan-Refresh $i ([DateTimeOffset]::UtcNow);$planJson=ConvertTo-Json -InputObject $p -Depth 100 -Compress
  $r=[TokenForge.Core.AdminWorkflows]::OpenRefreshRun($planJson,$path);$first=$r.Reserve($id,'SourceGet');$r.Dispose()
  $r=[TokenForge.Core.AdminWorkflows]::OpenRefreshRun($planJson,$path)
  try{$recovery=$r.Reserve($id,'SourceGet',$first,$true);$r.Complete($recovery,200);$status=Read-RefreshJson $r.Status();$status.SourceRequests|Should -Be 2;$status.RecoveryRetries|Should -Be 1;{$r.Reserve($id,'SourceGet',$first,$true)}|Should -Throw}finally{$r.Dispose()}
 }
 It 'allows at most three recognized GET retries globally, within all HTTP ceilings' {
  $r=[TokenForge.Core.AdminWorkflows]::OpenRefreshRun($planJson,$path)
  try{$seq=$r.Reserve($id,'ApiGet');$r.Complete($seq,503);foreach($n in 1..3){$seq=$r.Reserve($id,'ApiGet',$seq);$r.Complete($seq,503)};{$r.Reserve($id,'ApiGet',$seq)}|Should -Throw;(Read-RefreshJson $r.Status()).TotalRequests|Should -Be 4}finally{$r.Dispose()}
 }
 It 'never retries an ordinary denial or a mutation-shaped operation' {
  $r=[TokenForge.Core.AdminWorkflows]::OpenRefreshRun($planJson,$path)
  try{$seq=$r.Reserve($id,'ApiGet');$r.Complete($seq,403);{$r.Reserve($id,'ApiGet',$seq)}|Should -Throw;{$r.Reserve($id,'ConsentPost')}|Should -Throw}finally{$r.Dispose()}
 }
 It 'enforces separate source, inventory, page, bootstrap and total ceilings before dispatch' -TestCases @(@{Kind='SourceGet';Limit='MaxSourceRequests'},@{Kind='InventoryGet';Limit='MaxInventoryRequests'},@{Kind='InventoryPageGet';Limit='MaxInventoryPages'},@{Kind='BootstrapHttp';Limit='MaxBootstrapRequests'},@{Kind='ApiGet';Limit='MaxTotalRequests'}) {
  param($Kind,$Limit)
  $i.Policy[$Limit]=0;$p=Plan-Refresh $i ([DateTimeOffset]::UtcNow);$planJson=ConvertTo-Json -InputObject $p -Depth 100 -Compress
  $r=[TokenForge.Core.AdminWorkflows]::OpenRefreshRun($planJson,$path)
  try{if($p.SelectedCount){{$r.Reserve($id,$Kind)}|Should -Throw};(Read-RefreshJson $r.Status()).TotalRequests|Should -Be 0}finally{$r.Dispose()}
 }
 It 'persists terminal evidence before completion and projects it repeatedly without issuance' {
  $r=[TokenForge.Core.AdminWorkflows]::OpenRefreshRun($planJson,$path)
  try{$b=$r.Reserve($id,'BootstrapIssuance');$r.Complete($b);$g=$r.Reserve($id,'IdentityGet');$r.Complete($g,200);$seq=$r.Reserve($id,'FinalIssuance');$r.Complete($seq);$s=New-RefreshObservation $p -At ([DateTimeOffset]::UtcNow);$r.SaveEvidence($id,($s|ConvertTo-Json -Depth 100 -Compress))}finally{$r.Dispose()}
  $r=[TokenForge.Core.AdminWorkflows]::OpenRefreshRun($planJson,$path)
  try{$status=Read-RefreshJson $r.Status();$status.CompletedCount|Should -Be 1;{$r.Reserve($id,'FinalIssuance')}|Should -Throw;$h=Read-RefreshJson $r.ProjectHistory();$h.Entries.Count|Should -Be 1;$h2=Read-RefreshJson $r.ProjectHistory(($h|ConvertTo-Json -Depth 100 -Compress));$h2.Entries.Count|Should -Be 1;(Read-RefreshJson $r.Status()).IssuanceAttempts|Should -Be 2}finally{$r.Dispose()}
 }
 It 'rejects a second writer and full journal tampering' {
  $r=[TokenForge.Core.AdminWorkflows]::OpenRefreshRun($planJson,$path)
  try{ {[TokenForge.Core.AdminWorkflows]::OpenRefreshRun($planJson,$path)}|Should -Throw }finally{$r.Dispose()}
  $saved=Read-RefreshJson ([IO.File]::ReadAllText($path));$saved.Cookie='synthetic-forbidden';[IO.File]::WriteAllText($path,($saved|ConvertTo-Json -Depth 100 -Compress))
  {[TokenForge.Core.AdminWorkflows]::OpenRefreshRun($planJson,$path)}|Should -Throw
 }
}
Describe 'Goal 4 actual process termination' -Tag Kill {
 It 'preserves durable state after a process kill at <Boundary>' -ForEach @(@{Boundary='BeforeRequest'},@{Boundary='RemoteResult'},@{Boundary='TerminalDurable'},@{Boundary='ProjectionStaged'}) {
  $root=Join-Path $TestDrive ([guid]::NewGuid().ToString('N'));$null=[IO.Directory]::CreateDirectory($root,[IO.UnixFileMode]448)
  $i=New-RefreshInput;$i.Inventory.CapturedAt=[DateTimeOffset]::UtcNow.AddMinutes(-1).ToString('o');$p=Plan-Refresh $i ([DateTimeOffset]::UtcNow);$json=$p|ConvertTo-Json -Depth 100 -Compress;$planPath=Join-Path $root plan.json;[IO.File]::WriteAllText($planPath,$json);$statePath=Join-Path $root run.json
  $start=[Diagnostics.ProcessStartInfo]::new();$start.FileName=(Get-Process -Id $PID).Path;$start.UseShellExecute=$false;$start.RedirectStandardOutput=$true;$start.RedirectStandardError=$true
  foreach($arg in @('-NoProfile','-File',"$PSScriptRoot/fixtures/refresh/InterruptedRefresh.ps1",'-PlanPath',$planPath,'-StatePath',$statePath,'-Boundary',$Boundary)){$start.ArgumentList.Add($arg)}
  $process=[Diagnostics.Process]::Start($start);$stdout=$process.StandardOutput.ReadToEndAsync();$stderr=$process.StandardError.ReadToEndAsync()
  try{
   $timer=[Diagnostics.Stopwatch]::StartNew();while(-not(Test-Path ($statePath+'.ready')) -and -not $process.HasExited -and $timer.Elapsed.TotalSeconds -lt 30){[Threading.Thread]::Sleep(50)}
   if(-not(Test-Path ($statePath+'.ready'))){if(-not $process.HasExited){$process.Kill($true);$null=$process.WaitForExit(5000)};throw ('Synthetic child failed: '+$stderr.GetAwaiter().GetResult())}
   $process.Kill($true);$process.WaitForExit(5000)|Should -BeTrue
  }finally{if(-not $process.HasExited){$process.Kill($true);$null=$process.WaitForExit(5000)};$process.Dispose()}
  $run=[TokenForge.Core.AdminWorkflows]::OpenRefreshRun($json,$statePath)
  try{
   $status=Read-RefreshJson $run.Status()
   if($Boundary -in @('BeforeRequest','RemoteResult')){$status.InFlightUnknownCount|Should -Be 1;$status.CompletedCount|Should -Be 0;{$run.Reserve($p.Candidates[0].RequestId,'FinalIssuance')}|Should -Throw}
   else{$status.CompletedCount|Should -Be 1;$h=Read-RefreshJson $run.ProjectHistory();$h.Entries.Count|Should -Be 1;(Read-RefreshJson $run.Status()).IssuanceAttempts|Should -Be 2}
   Test-Path ($statePath+'.simulated-call')|Should -Be ($Boundary -eq 'RemoteResult')
  }finally{$run.Dispose()}
 }
}
Describe 'Goal 4 bounded strict acquisition with synthetic HTTP' {
 BeforeEach {
  $root=Join-Path $TestDrive ([guid]::NewGuid().ToString('N'));$null=[IO.Directory]::CreateDirectory($root,[IO.UnixFileMode]448)
  $i=New-RefreshInput;$script:rfPrincipal='cccccccc-cccc-cccc-cccc-cccccccccccc';$script:rfTenant='aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'
  $i.Profile.ExpectedPrincipalFingerprint=[TokenForge.Core.ApplicationCatalogPolicy]::Hash($script:rfTenant+'/'+$script:rfPrincipal);$i.Inventory.PrincipalFingerprint=$i.Profile.ExpectedPrincipalFingerprint;$i.Inventory.CapturedAt=[DateTimeOffset]::UtcNow.AddMinutes(-1).ToString('o')
  $p=Plan-Refresh $i ([DateTimeOffset]::UtcNow);$json=$p|ConvertTo-Json -Depth 100 -Compress;$id=$p.Candidates[0].RequestId
  $script:rfHttpClient='';$script:rfFault='';$script:rfHttpCalls=0
  $http=[Func[Net.Http.HttpClient,uri,Collections.Generic.Dictionary[string,string],string,TokenForge.Core.V0180.OAuthHttpResponse]]{
   param($client,$uri,$form,$origin)
   $script:rfHttpCalls++
   if($uri.AbsolutePath.EndsWith('/authorize')){
    $q=[Web.HttpUtility]::ParseQueryString($uri.Query);$script:rfHttpClient=$q['client_id']
    if($script:rfHttpClient -eq $script:rfClient){if($script:rfFault -eq 'Transport'){throw 'synthetic-private-body'};if($script:rfFault -eq 'Denied'){return [TokenForge.Core.V0180.OAuthHttpResponse]::new(400,$null,'synthetic-private-body')}}
    return [TokenForge.Core.V0180.OAuthHttpResponse]::new(302,($q['redirect_uri']+'?code=fixture&state='+$q['state']),'')
   }
   $scope=if($script:rfFault -eq 'Extra' -and $script:rfHttpClient -eq $script:rfClient){'User.Read Mail.Read'}else{'User.Read'}
   $body=@{tid=$script:rfTenant;oid=$script:rfPrincipal;appid=$script:rfHttpClient;aud=$script:rfGraph;scp=$scope;exp=[DateTimeOffset]::UtcNow.AddMinutes(30).ToUnixTimeSeconds()}|ConvertTo-Json -Compress
   $jwt='e30.'+[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($body)).TrimEnd('=').Replace('+','-').Replace('/','_')+'.fixture'
   [TokenForge.Core.V0180.OAuthHttpResponse]::new(200,$null,(@{access_token=$jwt;token_type='Bearer';scope=$scope;expires_in=1800}|ConvertTo-Json -Compress))
  }
  $identity=[Func[Security.SecureString,string]]{param($token)$script:rfPrincipal}
  $proof=[Func[Security.SecureString,TokenForge.Core.ProfileApiCheck]]{param($token)[TokenForge.Core.ProfileApiCheck]::new(200,$true)}
  $cookie=ConvertTo-SecureString synthetic-cookie -AsPlainText -Force
  function Invoke-RefreshAdapter {Read-RefreshJson ([TokenForge.Core.AdminWorkflows]::AcquireRefresh($json,$root,$id,$cookie,'ESTSAUTH',[Threading.CancellationToken]::None,$http,$identity,$proof))}
 }
 AfterEach {$cookie.Dispose()}
 It 'counts actual synthetic exchanges and retains terminal evidence without broadening scopes' {
  $r=Invoke-RefreshAdapter;$r.Acquisition.Status|Should -Be IssuedWithinStrictPolicy;$r.Run.IssuanceAttempts|Should -Be 2;$r.Run.TotalRequests|Should -Be 5;$script:rfHttpCalls|Should -Be 4;$r.Run.CompletedCount|Should -Be 1
  $saved=[IO.File]::ReadAllText((Join-Path $root refresh-run.json));$saved|Should -Not -Match 'synthetic-cookie|synthetic-private-body|access_token|e30\.'
  {Invoke-RefreshAdapter}|Should -Throw
 }
 It 'records known rejection as terminal rather than an ambiguous pause' {
  $script:rfFault='Denied';$r=Invoke-RefreshAdapter;$r.Acquisition.Status|Should -Be Blocked;$r.Run.InFlightUnknownCount|Should -Be 0;$r.Run.CompletedCount|Should -Be 1
 }
 It 'retains true transport uncertainty and blocks a new plan in the same account store' {
  $script:rfFault='Transport';$r=Invoke-RefreshAdapter;$r.Run.InFlightUnknownCount|Should -BeGreaterThan 0;$r.Run.CompletedCount|Should -Be 0
  $p=Plan-Refresh $i ([DateTimeOffset]::UtcNow);$json=$p|ConvertTo-Json -Depth 100 -Compress
  {Invoke-RefreshAdapter}|Should -Throw
  {[TokenForge.Core.AdminWorkflows]::AdvanceRefreshRun($json,$root)}|Should -Throw
 }
 It 'revalidates actual issued scope ceilings on every acquisition' {
  $script:rfFault='Extra';$r=Invoke-RefreshAdapter;$r.Acquisition.Status|Should -Be Blocked;$r.Acquisition.FinalAdditionalScopes|Should -Contain Mail.Read;$r.Run.CompletedCount|Should -Be 1
 }
 It 'advances a completed canonical run only when exact original history is retained' {
  $null=Invoke-RefreshAdapter;$run=[TokenForge.Core.AdminWorkflows]::OpenRefreshRun($json,(Join-Path $root refresh-run.json));try{$history=Read-RefreshJson $run.ProjectHistory()}finally{$run.Dispose()}
  $next=Plan-Refresh $i ([DateTimeOffset]::UtcNow);{[TokenForge.Core.AdminWorkflows]::AdvanceRefreshRun(($next|ConvertTo-Json -Depth 100 -Compress),$root)}|Should -Throw
  $i.History=$history;$i.Snapshot=$history.Snapshots[0].Snapshot;$next=Plan-Refresh $i ([DateTimeOffset]::UtcNow)
  $next.ReusedCount|Should -Be 1;$null=[TokenForge.Core.AdminWorkflows]::AdvanceRefreshRun(($next|ConvertTo-Json -Depth 100 -Compress),$root)
  @(Get-ChildItem $root -Filter 'refresh-run-*.json').Count|Should -Be 1
  Remove-Item (Join-Path $root refresh-run.json)
  {Invoke-RefreshAdapter}|Should -Throw
 }
}
Describe 'Goal 4 independent phase freshness' {
 It 'cannot hide a newer API denial behind a newer issuance from another snapshot' {
  $i=New-RefreshInput;$i.Requirements.Tools[0].Operations=@('GraphMeV1');$p=Plan-Refresh $i $script:rfNow.AddMinutes(-10)
  $a=New-RefreshApiSnapshot $p $script:rfNow.AddMinutes(-2) $script:rfNow.AddMinutes(-4) 200
  $b=New-RefreshApiSnapshot $p $script:rfNow.AddMinutes(-3) $script:rfNow.AddMinutes(-1) 403
  $i.History=Capture-Refresh $p $a $i.History;$i.History=Capture-Refresh $p $b $i.History;$i.Snapshot=$b
  $q=Plan-Refresh $i;$q.ReusedCount|Should -Be 0
  [array]::Reverse($i.History.Entries);(Plan-Refresh $i).ReusedCount|Should -Be 0
  $c=New-RefreshApiSnapshot $p $script:rfNow.AddMinutes(-3) $script:rfNow.AddSeconds(-30) 200
  $i.History=Capture-Refresh $p $c $i.History;$i.Snapshot=$c;$q=Plan-Refresh $i;$q.ReusedCount|Should -Be 1;$q.Candidates[0].ReuseOrigins.Count|Should -Be 3
 }
 It 'ignores individual future observations without hiding an earlier failure in that snapshot' {
  $i=New-RefreshInput;$p=Plan-Refresh $i $script:rfNow.AddMinutes(-10);$s=New-RefreshObservation $p -Outcome RequestBlocked -At $script:rfNow.AddMinutes(-3)
  $future=Copy-Refresh $s.Collections[0].Records[0];$future.Outcome='Succeeded';$future.ObservedAt=$script:rfNow.AddMinutes(1).ToString('o');$future.RecordId='f'*64;$s.Collections[0].Records+=@($future);$s.Collections[0].Source.CollectedAt=$future.ObservedAt
  $i.History=Capture-Refresh $p $s $i.History;$i.Snapshot=$s;$q=Plan-Refresh $i;$q.ReusedCount|Should -Be 0;$q.Candidates[0].Deferral|Should -Be StableFailureCooldown
 }
 It 'does not create a fairness seat when all global selection budgets are zero' {
  $i=New-RefreshInput;$t=Copy-Refresh $i.Requirements.Tools[0];$t.Id='explore';$i.Requirements.Tools+=@($t);$i.Policy.CriticalToolIds=@('read-profile');$i.Policy.MaxSelectedRequests=0
  (Plan-Refresh $i).SelectedCount|Should -Be 0
 }
}
Describe 'Goal 4 deadline and recovery lifecycle regressions' {
 It 'keeps projection available after the cooperative run deadline without dispatching' {
  $root=Join-Path $TestDrive ([guid]::NewGuid().ToString('N'));$null=[IO.Directory]::CreateDirectory($root,[IO.UnixFileMode]448)
  $i=New-RefreshInput;$i.Policy.MaxSeconds=1;$p=Plan-Refresh $i;$r=[TokenForge.Core.AdminWorkflows]::OpenRefreshRun(($p|ConvertTo-Json -Depth 100 -Compress),(Join-Path $root run.json))
  try{[Threading.Thread]::Sleep(1100);{$r.Reserve($p.Candidates[0].RequestId,'FinalIssuance')}|Should -Throw '*deadline*';(Read-RefreshJson $r.Status()).DeadlineReached|Should -BeTrue;(Read-RefreshJson $r.ProjectHistory()).Entries.Count|Should -Be 0}finally{$r.Dispose()}
 }
 It 'resolves an explicitly recovered unknown GET while preserving both original charges' {
  $root=Join-Path $TestDrive ([guid]::NewGuid().ToString('N'));$null=[IO.Directory]::CreateDirectory($root,[IO.UnixFileMode]448)
  $i=New-RefreshInput;$p=Plan-Refresh $i;$json=$p|ConvertTo-Json -Depth 100 -Compress;$id=$p.Candidates[0].RequestId;$path=Join-Path $root run.json
  $r=[TokenForge.Core.AdminWorkflows]::OpenRefreshRun($json,$path);$first=$r.Reserve($id,'ApiGet');$r.Complete($first,$null,$false);$r.Dispose()
  $r=[TokenForge.Core.AdminWorkflows]::OpenRefreshRun($json,$path)
  try{$second=$r.Reserve($id,'ApiGet',$first,$true);$r.Complete($second,200);$status=Read-RefreshJson $r.Status();$status.InFlightUnknownCount|Should -Be 0;$status.InterruptedCount|Should -Be 0;$status.TotalRequests|Should -Be 2;$status.RecoveryRetries|Should -Be 1}finally{$r.Dispose()}
 }
}
Describe 'Goal 4 coverage supersession and future-only history' {
 It 'lets newer API acceptance supersede an older empty API denial independently of issuance time' {
  $i=New-RefreshInput;$i.Requirements.Tools[0].Operations=@('GraphMeV1');$p=Plan-Refresh $i $script:rfNow.AddMinutes(-10)
  $a=New-RefreshApiSnapshot $p $script:rfNow.AddMinutes(-4) $script:rfNow.AddMinutes(-3) 200
  $b=New-RefreshApiSnapshot $p $script:rfNow.AddMinutes(-4) $script:rfNow.AddMinutes(-2) 403;$b.Collections[1].Records=@();$b.Collections[1].Status='Denied'
  $i.History=Capture-Refresh $p $a $i.History;$i.History=Capture-Refresh $p $b $i.History;$i.Snapshot=$b;(Plan-Refresh $i).ReusedCount|Should -Be 0
  $c=New-RefreshApiSnapshot $p $script:rfNow.AddMinutes(-4) $script:rfNow.AddMinutes(-1) 200
  $i.History=Capture-Refresh $p $c $i.History;$i.Snapshot=$c;(Plan-Refresh $i).ReusedCount|Should -Be 1
 }
 It 'treats entirely later observations as not yet observed without a future sentinel error' {
  $i=New-RefreshInput;$p=Plan-Refresh $i $script:rfNow.AddMinutes(-10);$s=New-RefreshObservation $p -At $script:rfNow.AddMinutes(1);$i.History=Capture-Refresh $p $s $i.History;$i.Snapshot=$s
  $q=Plan-Refresh $i;$q.ReusedCount|Should -Be 0;$q.Candidates[0].Reason|Should -Be MissingEvidence
 }
}
Describe 'Goal 4 latest visibility with retained records' {
 It 'does not hide newer incomplete visibility behind retained older scope rows' {
  $i=New-RefreshInput;$p=Plan-Refresh $i $script:rfNow.AddMinutes(-10);$good=New-RefreshObservation $p -At $script:rfNow.AddMinutes(-4)
  $lost=New-RefreshObservation $p -At $script:rfNow.AddMinutes(-5);$lost.Collections[0].Status='Incomplete';$lost.Collections[0].Source.CollectedAt=$script:rfNow.AddMinutes(-1).ToString('o')
  $i.History=Capture-Refresh $p $good $i.History;$i.History=Capture-Refresh $p $lost $i.History;$i.Snapshot=$lost
  $q=Plan-Refresh $i;$q.ReusedCount|Should -Be 0;$q.Candidates[0].LastKnownSuccess.Outcome|Should -Be Succeeded
  $i.History.Entries[1].CoverageReferences.Count|Should -Be 1
 }
}
