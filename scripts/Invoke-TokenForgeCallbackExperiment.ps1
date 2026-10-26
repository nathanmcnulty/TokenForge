# Goal 5 laboratory only. Dot-source, then invoke the function in a fresh, network-isolated process.
# No production store, sign-in, transport, or promotion entry point exists in this script.
function ConvertFrom-TokenForgeCallbackCases {
 param([Parameter(Mandatory)][string]$Json)
 try {
  if([Text.Encoding]::UTF8.GetByteCount($Json) -gt 16384){throw 'bound'}
  $v=[TokenForge.Core.DiscoverySourceClaims]::ReadMetadataJson($Json)
  if(($v.Keys|Sort-Object)-join ',' -cne 'Cases,Format,SchemaVersion,StudyId' -or $v.Format -cne 'TokenForgeSyntheticCallbackCases' -or $v.SchemaVersion -ne 1 -or $v.StudyId -cne 'goal5-observed-callback-cap-v1' -or $v.Cases.Count -ne 12){throw 'format'}
  $ids=[Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
  foreach($case in $v.Cases){
   if(($case.Keys|Sort-Object)-join ',' -cne 'Id,Partition,Primary,Secondary' -or $case.Id -cnotmatch '^[dh]0[1-8]$' -or -not $ids.Add($case.Id) -or $case.Partition -cnotin @('Discovery','Holdout')){throw 'case'}
   if(($case.Id.StartsWith('d')) -ne ($case.Partition -ceq 'Discovery')){throw 'partition'}
   foreach($phase in @('Primary','Secondary')){if($case[$phase] -cnotin @('Success','Rejected','ExcessScopes','Opaque','WrongPrincipal','Throttled','SessionLost','PromptRequired')){throw 'outcome'}}
  }
  if(@($v.Cases|Where-Object Partition -CEQ Discovery).Count -ne 8 -or @($v.Cases|Where-Object Partition -CEQ Holdout).Count -ne 4){throw 'partition'}
  $v
 }catch{throw 'Synthetic callback cases are invalid; no experiment executed.'}
}
function Get-TokenForgeCallbackDisposition {
 param([object[]]$Pairs,[bool]$Complete)
 if(-not $Complete){return 'Inconclusive'}
 if(@($Pairs|Where-Object {$_.Baseline.Success -and -not $_.Candidate.Success}).Count){return 'Rejected'}
 $base=($Pairs|ForEach-Object {$_.Baseline.IssuanceAttempts}|Measure-Object -Sum).Sum
 $candidate=($Pairs|ForEach-Object {$_.Candidate.IssuanceAttempts}|Measure-Object -Sum).Sum
 if($Pairs.Count -ne 12 -or -not $base -or ($base-$candidate)/$base -lt 0.1){return 'Inconclusive'}
 # A favorable synthetic result is a recommendation for separate review, never runtime promotion.
 'Inconclusive'
}
function Invoke-TokenForgeCallbackExperiment {
 [CmdletBinding()]param([Parameter(Mandatory)][string]$NativeExecutable,[Parameter(Mandatory)][string]$OutputPath,[ValidateRange(1,72)][int]$MaxSyntheticIssuanceAttempts=72)
 $ErrorActionPreference='Stop'
 $experimentScript=$MyInvocation.MyCommand.ScriptBlock.File
 if(-not $IsLinux){throw 'This experiment supports local Linux only.'}
 $repo=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
 $package=Split-Path -Parent (Resolve-Path -LiteralPath $NativeExecutable).Path
 $manifestPath=Join-Path $package local-package-manifest.json
 $fileHash={param($path)(Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()}
 if((& $fileHash $manifestPath) -cne '7f5bf66466aae9ef68c81d7403ff055f4de650a04fd6ce5eaa2b490441245a66'){throw 'The experiment requires its exact reviewed package.'}
 $manifest=Get-Content -LiteralPath $manifestPath -Raw|ConvertFrom-Json -AsHashtable
 $members=@(Get-ChildItem -LiteralPath $package -Recurse -Force)
 if(@($members|Where-Object LinkTarget).Count){throw 'Linked package members are refused.'}
 $actual=@($members|Where-Object {-not $_.PSIsContainer}|ForEach-Object {[IO.Path]::GetRelativePath($package,$_.FullName)}|Sort-Object)
 $expected=@(@($manifest.files.Keys)+'local-package-manifest.json'|Sort-Object)
 if(($actual -join '|') -cne ($expected -join '|')){throw 'Package membership differs.'}
 foreach($p in $manifest.files.Keys){if((& $fileHash (Join-Path $package $p)) -cne $manifest.files[$p]){throw 'Package content differs.'}}
 if(-not ('TokenForge.Core.ProfileScopeAcquisition' -as [type])){Import-Module (Join-Path $package 'src/TokenForge/TokenForge.psd1') -Force}
 if((& $fileHash ([TokenForge.Core.ProfileScopeAcquisition].Assembly.Location)) -cne $manifest.files['src/TokenForge/lib/net10.0/TokenForge.Credentials.dll']){throw 'Loaded runtime differs.'}
 $casePath=Join-Path $repo 'tests/fixtures/lab/callback-cap-v1.json'
 $cohortHash=& $fileHash $casePath
 if($cohortHash -cne '36a2b88ae045959f41637f82ce000cfa9e64f2b5a8a5f07fa16ca3a7e3a25547'){throw 'Frozen study cases changed.'}
 $cases=(ConvertFrom-TokenForgeCallbackCases ([IO.File]::ReadAllText($casePath))).Cases
 $target=[IO.Path]::GetFullPath($OutputPath);$inputTarget=$target+'.inputs.json'
 foreach($p in @($target,$inputTarget)){
  if(Test-Path -LiteralPath $p){throw 'Experiment reports are create-new only.'}
  $cursor=[IO.FileInfo]::new($p)
  while($null -ne $cursor){if($cursor.LinkTarget){throw 'Linked output paths are refused.'};$cursor=if($cursor -is [IO.FileInfo]){$cursor.Directory}else{$cursor.Parent}}
 }
 if(-not (Test-Path -LiteralPath ([IO.Path]::GetDirectoryName($target)) -PathType Container)){throw 'An existing output directory is required.'}
 function Json($v){ConvertTo-Json -InputObject $v -Depth 64 -Compress}
 function Hash($v){[TokenForge.Core.ChangeReports]::FingerprintJson((Json $v))}
 $anchor=[DateTimeOffset]::UtcNow;$old=$anchor.AddMinutes(-1).ToString('o')
 $tenant='aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa';$principal='bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb';$boot='22222222-2222-2222-2222-222222222222';$graph='00000003-0000-0000-c000-000000000000'
 $primary='http://localhost';$secondary='https://login.microsoftonline.com/common/oauth2/nativeclient'
 $tenantFp=[TokenForge.Core.ApplicationCatalogPolicy]::Hash($tenant);$principalFp=[TokenForge.Core.ApplicationCatalogPolicy]::Hash($tenant+'/'+$principal)
 $profile=@{Format='TokenForgeProfile';SchemaVersion=1;Name='lab';Tenant=$tenant;StatePath='/synthetic/goal5-not-a-store';Storage='Memory';BootstrapClientId=$boot;MaxAdditionalScopes=0;MaxBootstrapAdditionalScopes=0;MaxAgeHours=24;SessionRetentionHours=1;PasskeyPath='';XdrModulePath='';ExpectedTenantFingerprint=$tenantFp;ExpectedPrincipalFingerprint=$principalFp;Revision='cccccccc-cccc-cccc-cccc-cccccccccccc';CreatedAt=$old;UpdatedAt=$old}
 $profileJson=Json $profile
 [TokenForge.Core.V0200.ProfilePolicy]::Validate($profileJson,'lab')
 # Build and validate ALL frozen inputs and both exact request lists before any synthetic issuance.
 $inputs=@();$index=0
 foreach($case in $cases){
  $index++;$client='11111111-1111-1111-1111-'+$index.ToString('000000000000')
  $apps=@(foreach($id in @($client,$boot,$graph)){@{AppId=$id;Name='Synthetic';Registration='Present';Ownership='VerifiedMicrosoftOwner';AccountEnabled=$true;RedirectUris=@(if($id -eq $client){$secondary;$primary}else{$secondary});PublishedGrants=@();DelegatedScopeDefinitions=@(@{Id='33333333-3333-3333-3333-333333333333';Value='User.Read';Enabled=$true})}})
  $inventory=@{SchemaVersion=1;CapturedAt=$old;TenantFingerprint=$tenantFp;PrincipalFingerprint=$principalFp;GrantEnumeration='Complete';Applications=$apps;TenantGrants=@()}
  $database=@{SchemaVersion=1;Observations=@(@{ClientId=$client;ResourceId=$graph;TenantFingerprint=$tenantFp;PrincipalFingerprint=$principalFp;ObservedAt=$old;Outcome='Succeeded';NamespaceVerification='Matched';RequestVerification='Matched';ScpScopes=@('User.Read');RequestedScopes=@('User.Read');RedirectFingerprint=[TokenForge.Core.ApplicationCatalogPolicy]::Hash($primary);Protocol='OAuth2V2Pkce';Spa=$false})}
  $ij=Json $inventory;$dj=Json $database
  $coverage=[TokenForge.Core.DiscoverySourceClaims]::ReadMetadataJson(('{"Rows":'+[TokenForge.Core.ScopePlanning]::Coverage($dj,$graph,[string[]]@('User.Read'),$tenantFp,$principalFp,24,$anchor)+'}'))
  if($coverage.Rows.Count -ne 1 -or -not $coverage.Rows[0].CoversAll){throw 'Frozen warm coverage is absent.'}
  $lists=@{}
  foreach($cap in @(2,1)){
   $requests=@([TokenForge.Core.ScopePlanning]::PlanRequests($ij,$dj,$graph,[string[]]@('User.Read'),$principalFp,$tenant,$true,$false,$true,1,$cap,24,$anchor))
   if($requests.Count -ne $cap -or $requests[0].RedirectUri -cne $primary -or ($cap -eq 2 -and $requests[1].RedirectUri -cne $secondary) -or @($requests|Where-Object {$_.ClientId -cne $client -or $_.Protocol -cne 'OAuth2V2Pkce' -or ($_.Scopes -join ',') -cne 'User.Read' -or ($_.OAuthScopes -join ',') -cne ($graph+'/User.Read,offline_access')}).Count){throw 'Exact frozen request list differs.'}
   $lists[[string]$cap]=@($requests|ForEach-Object {@{ClientId=$_.ClientId;RedirectUri=$_.RedirectUri;Scopes=@($_.Scopes);OAuthScopes=@($_.OAuthScopes);Protocol=$_.Protocol}})
  }
  $inputs+=@{Case=$case;ClientId=$client;Profile=$profile;Inventory=$inventory;Database=$database;Requests=$lists}
 }
 $inputsJson=Json @{Format='TokenForgeSyntheticCallbackInputs';SchemaVersion=1;Anchor=$anchor.ToString('o');Cases=$inputs}
 $globalBudget=@{Count=0;Max=$MaxSyntheticIssuanceAttempts;Stopped=$false};$outer=[Threading.CancellationTokenSource]::new();$outer.CancelAfter([TimeSpan]::FromSeconds(60));$watch=[Diagnostics.Stopwatch]::StartNew()
 $trials=[Collections.Generic.List[object]]::new();$pairs=[Collections.Generic.List[object]]::new()
 $cookie=ConvertTo-SecureString 'synthetic-goal5-not-a-session' -AsPlainText -Force
 $runStatus='Complete';$stopReason=$null
 try {
  $index=0
  foreach($inputRow in $inputs){
   $index++;$order=if($index%2){@('Baseline','Candidate')}else{@('Candidate','Baseline')};$pair=@{Id=$inputRow.Case.Id;Partition=$inputRow.Case.Partition;Order=$order}
   foreach($arm in $order){
    $cap=if($arm -eq 'Baseline'){2}else{1};$trialStop=[Threading.CancellationTokenSource]::CreateLinkedTokenSource($outer.Token);$trialStop.CancelAfter([TimeSpan]::FromSeconds(5))
    $state=@{Attempts=0;IdentityChecks=0;HarnessFailure=$false;InjectedCancellation=$false;Trace=[Collections.Generic.List[object]]::new();Created=[Collections.Generic.List[object]]::new()}
    $client=$inputRow.ClientId;$case=$inputRow.Case
    $execute=[Func[TokenForge.Core.ScopePlanning+RequestRow,TokenForge.Core.ProfileCredentialToken]]({
     param($request)
     if($trialStop.IsCancellationRequested -or $outer.IsCancellationRequested -or $globalBudget.Count -ge $globalBudget.Max){$globalBudget.Stopped=$true;$trialStop.Cancel();throw [OperationCanceledException]::new()}
     $phase=if($request.ClientId -ceq $boot){'Bootstrap'}elseif($request.ClientId -ceq $client){'Final'}else{$state.HarnessFailure=$true;throw 'Unexpected synthetic client.'}
     if($request.ResourceId -cne $graph -or $request.Protocol -cne 'OAuth2V2Pkce' -or ($request.Scopes -join ',') -cne 'User.Read' -or ($phase -eq 'Final' -and $request.RedirectUri -cnotin @($primary,$secondary))){$state.HarnessFailure=$true;throw 'Unexpected synthetic request.'}
     $globalBudget.Count++;$state.Attempts++
     $injected=if($phase -eq 'Bootstrap'){'Success'}elseif($request.RedirectUri -ceq $primary){$case.Primary}else{$case.Secondary}
     $state.Trace.Add(@{Phase=$phase;ClientId=$request.ClientId;ResourceId=$request.ResourceId;Callback=$request.RedirectUri;RequestedScopes=@($request.Scopes);OAuthScopes=@($request.OAuthScopes);InjectedScenario=$injected;ModeledHttpStatus=$(if($injected -eq 'Throttled'){429}else{$null})})
     if($injected -cin @('SessionLost','PromptRequired')){$state.InjectedCancellation=$true;$trialStop.Cancel();throw [OperationCanceledException]::new()}
     if($injected -cin @('Rejected','Throttled')){throw [InvalidOperationException]::new('Synthetic attempt did not return a token.')}
     $claims=@{tid=$tenant;oid=$(if($injected -eq 'WrongPrincipal'){'dddddddd-dddd-dddd-dddd-dddddddddddd'}else{$principal});appid=$request.ClientId;aud=$graph;scp=$(if($injected -eq 'ExcessScopes'){'User.Read Mail.Read'}else{'User.Read'});exp=[DateTimeOffset]::UtcNow.AddHours(1).ToUnixTimeSeconds()}
     $jwt=if($injected -eq 'Opaque'){'synthetic-opaque'}else{'e30.'+[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes((ConvertTo-Json $claims -Compress))).TrimEnd('=').Replace('+','-').Replace('/','_')+'.fixture'}
     $access=ConvertTo-SecureString $jwt -AsPlainText -Force
     try{$token=[TokenForge.Core.ProfileCredentialToken]::new($request.ToTransport(),$access,$null,[DateTimeOffset]::UtcNow.AddHours(1),0);$state.Created.Add($token);$token}finally{$access.Dispose()}
    }.GetNewClosure())
    $identity=[Func[Security.SecureString,string]]({param($token)$state.IdentityChecks++;$principal}.GetNewClosure())
    $checkpoint=[Action[string]]({param($json)$state.HarnessFailure=$true;throw 'Cold checkpoint is outside this warm study.'}.GetNewClosure())
    $trialWatch=[Diagnostics.Stopwatch]::StartNew();$result=$null;$success=$false;$observed='NoVerifiedToken';$acceptedExtra=0
    try{
     $result=[TokenForge.Core.ProfileScopeAcquisition]::Acquire('lab',$profileJson,(Json $inputRow.Inventory),(Json $inputRow.Database),$graph,[string[]]@('User.Read'),$cookie,'ESTSAUTH',1,$cap,$execute,$identity,$checkpoint,$trialStop.Token)
     $acceptedExtra=@($result.TokenClaims.Scopes|Where-Object {$_ -cnotin @('User.Read','openid','profile','email','offline_access')}).Count
     $success=$true;$observed='VerifiedScopedToken'
    }catch{if($trialStop.IsCancellationRequested){$observed='Cancelled'}else{$observed='NoVerifiedToken'}}
    finally{
     if($result){$result.Dispose()}
     foreach($created in $state.Created){$disposed=$false;try{$probe=$created.AccessToken.Copy();$probe.Dispose()}catch{$disposed=$true};if(-not $disposed){$created.Dispose();$state.HarnessFailure=$true}}
     $trialWatch.Stop();$trialStop.Dispose()
    }
    $stopped=($state.HarnessFailure -or $globalBudget.Stopped -or $outer.IsCancellationRequested -or ($observed -eq 'Cancelled' -and -not $state.InjectedCancellation) -or $state.IdentityChecks -ne 1 -or ($case.Primary -ceq 'Success' -and -not $success) -or $acceptedExtra -gt 0)
    $trial=@{TrialStatus=$(if($stopped){'Stopped'}else{'Complete'});StopReason=$(if($stopped){'HarnessBudgetOrSafetyGate'}else{$null});CaseId=$case.Id;Partition=$case.Partition;Arm=$arm;MaxRedirects=$cap;Success=$success;ObservedCoreOutcome=$observed;SyntheticCancellation=$state.InjectedCancellation;IssuanceAttempts=$state.Attempts;IdentityChecks=$state.IdentityChecks;AcceptedExtraScopes=$acceptedExtra;Trace=@($state.Trace.ToArray());TokenObjectsCreated=$state.Created.Count;TokenObjectsDisposed=$state.Created.Count;ElapsedMilliseconds=[Math]::Round($trialWatch.Elapsed.TotalMilliseconds,3);SharedProcessPeakWorkingSetBytes=[Diagnostics.Process]::GetCurrentProcess().PeakWorkingSet64}
    $trials.Add($trial);if($stopped){throw 'Study stopped by harness, budget or safety gate.'};$pair[$arm]=$trial
   }
   $pairs.Add($pair)
  }
 }catch{$runStatus='Stopped';$stopReason='HarnessBudgetOrSafetyGate'}
 finally{$cookie.Dispose();$outer.Dispose();$watch.Stop()}
 $completedTrials=@($trials|Where-Object TrialStatus -CEQ Complete).Count
 if($globalBudget.Count -ne [int](($trials|ForEach-Object IssuanceAttempts|Measure-Object -Sum).Sum)){$runStatus='Stopped';$stopReason='AttemptAccountingMismatch'}
 $complete=$runStatus -ceq 'Complete' -and $completedTrials -eq 24 -and $pairs.Count -eq 12
 $summaries=@(foreach($partition in @('Discovery','Holdout')){
  $selected=@($pairs|Where-Object Partition -CEQ $partition);$b=@($selected|ForEach-Object Baseline);$c=@($selected|ForEach-Object Candidate)
  $ba=[int](($b|ForEach-Object IssuanceAttempts|Measure-Object -Sum).Sum);$ca=[int](($c|ForEach-Object IssuanceAttempts|Measure-Object -Sum).Sum)
  @{Partition=$partition;Pairs=$selected.Count;BaselineSuccesses=@($b|Where-Object Success).Count;CandidateSuccesses=@($c|Where-Object Success).Count;LostBaselineSuccesses=@($selected|Where-Object {$_.Baseline.Success -and -not $_.Candidate.Success}).Count;NewCandidateSuccesses=@($selected|Where-Object {-not $_.Baseline.Success -and $_.Candidate.Success}).Count;BaselineIssuanceAttempts=$ba;CandidateIssuanceAttempts=$ca;AttemptReductionPercent=$(if($ba){[Math]::Round(100*($ba-$ca)/$ba,3)}else{$null})}
 })
 $report=[ordered]@{Format='TokenForgeCallbackExperiment';SchemaVersion=1;StudyId='goal5-observed-callback-cap-v1';RunStatus=$runStatus;StopReason=$stopReason;Disposition=(Get-TokenForgeCallbackDisposition -Pairs @($pairs.ToArray()) -Complete $complete);ProductionPromotion=$false;PolicyChanged=$false;Evidence='SyntheticExecutorUsingUnchangedProfileScopeAcquisition';Anchor=$anchor.ToString('o');ExperimentSourceRevision=([string](git -C $repo rev-parse HEAD)).Trim();ExperimentScriptSha256=(& $fileHash $experimentScript);RuntimeSourceRevision=$manifest.sourceRevision;PackageManifestSha256=(& $fileHash $manifestPath);FixtureSha256=$cohortHash;FrozenInputsSha256=[TokenForge.Core.ApplicationCatalogPolicy]::Hash($inputsJson);FrozenInputsPath=$inputTarget;Namespace=@{Kind='Synthetic';TenantFingerprint=$tenantFp;PrincipalFingerprint=$principalFp};Recipe=@{Version=1;BaselineMaxRedirects=2;CandidateMaxRedirects=1;MaxCandidates=1;Protocol='OAuth2V2Pkce';ApiScopes=@('User.Read');OAuthAdditionalRequestNames=@('offline_access');MaxAdditionalApiScopes=0;Warm=$true;ObservedCallback=$primary;FallbackCallback=$secondary;ResponsesKeyedBy='Case/Phase/ConcreteCallback';Order='AlternatingAB/BA;discoverythenpredeclaredholdout';Hypothesis='Observed-callback-only reduces logical issuance by at least10percent while retaining every baseline verified pair in both partitions';PrimaryOutcome='No lost baseline successes, then at least10percent attempt reduction';Holdout='Predeclared synthetic challenge set; not blind or a population sample'};Budgets=@{MaxTrials=24;MaxSyntheticIssuanceAttempts=$MaxSyntheticIssuanceAttempts;MaxSeconds=60;MaxTrialSeconds=5;MaxExternalRequests=0;MaxAuthenticationAttempts=0;MaxPromptInvocations=0;MaxConcurrency=1};CompletedTrials=$completedTrials;AttemptedTrials=$trials.Count;SyntheticIssuanceAttempts=$globalBudget.Count;ExternalRequests=0;AuthenticationAttempts=0;PromptInvocations=0;SourceRequests=0;InventoryPages=0;DatabaseReads=0;DatabaseWrites=0;ChildProcessStartsDuringTrials=0;RetryWaitMilliseconds=0;ElapsedMilliseconds=[Math]::Round($watch.Elapsed.TotalMilliseconds,3);Partitions=$summaries;Trials=@($trials.ToArray())}
 foreach($item in @(@{Path=$inputTarget;Text=$inputsJson},@{Path=$target;Text=($report|ConvertTo-Json -Depth 64)})){
  $stream=[IO.FileStream]::new($item.Path,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
  try{[IO.File]::SetUnixFileMode($item.Path,[IO.UnixFileMode]384);$stream.Write([Text.Encoding]::UTF8.GetBytes($item.Text));$stream.Flush($true)}finally{$stream.Dispose()}
 }
 [pscustomobject]$report
}
