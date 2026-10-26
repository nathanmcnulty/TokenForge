#Requires -Version 7.6
[CmdletBinding()]
param([Parameter(Mandatory)][string]$NativeExecutable,[Parameter(Mandatory)][string]$Workspace)
$ErrorActionPreference='Stop'
if(-not $IsLinux){throw 'This acceptance example supports Linux only.'}
$NativeExecutable=(Resolve-Path -LiteralPath $NativeExecutable).Path
$package=Split-Path $NativeExecutable
$Workspace=[IO.Path]::GetFullPath($Workspace)
# Create-new private example directory; never inspect existing operator state.
if(Test-Path -LiteralPath $Workspace){throw 'Workspace must be a new directory.'}
if(-not (Test-Path -LiteralPath (Join-Path $package 'src/TokenForge/lib/net10.0/TokenForge.Credentials.dll') -PathType Leaf)){throw 'The compiled package runtime is required.'}
Import-Module (Join-Path $package 'src/TokenForge/TokenForge.psd1') -Force
$null=[TokenForge.Core.V0220.PrivateFiles]::Resolve((Join-Path $Workspace 'placeholder'),$true)
$count=0
function Confirm([bool]$Condition){if(-not $Condition){throw 'Offline package acceptance assertion failed.'};$script:count++}
function Json($Value){ConvertTo-Json -InputObject $Value -Depth 100 -Compress}
function ReadJson([string]$Text){[TokenForge.Core.DiscoverySourceClaims]::ReadMetadataJson($Text)}
function Save([string]$Name,$Value){
 $path=Join-Path $Workspace $Name;$stream=[TokenForge.Core.V0220.PrivateFiles]::Open($path,$true)
 try{$bytes=[Text.Encoding]::UTF8.GetBytes((Json $Value));$stream.Write($bytes);$stream.Flush($true)}finally{$stream.Dispose()};$path
}
function Native([string[]]$Options,[int]$Expected=0){
 $start=[Diagnostics.ProcessStartInfo]::new($NativeExecutable);$start.UseShellExecute=$false
 $start.RedirectStandardOutput=$true;$start.RedirectStandardError=$true;$start.RedirectStandardInput=$true
 # Native examples must not find an implicit PowerShell authentication adapter.
 $start.Environment['PATH']=Join-Path $Workspace 'no-adapters'
 foreach($arg in $Options){$start.ArgumentList.Add($arg)}
 $process=[Diagnostics.Process]::Start($start)
 try{$process.StandardInput.Close();$out=$process.StandardOutput.ReadToEndAsync();$err=$process.StandardError.ReadToEndAsync()
  if(-not $process.WaitForExit(30000)){$process.Kill($true);throw 'Offline native example timed out.'}
  Confirm ($process.ExitCode -eq $Expected);$stdout=$out.GetAwaiter().GetResult();$stderr=$err.GetAwaiter().GetResult()
  if($Expected -eq 1){Confirm ([string]::IsNullOrEmpty($stdout));Confirm ((ReadJson $stderr).Code -eq 'OperationFailed');return}
  Confirm ([string]::IsNullOrEmpty($stderr));ReadJson $stdout
 }finally{$process.Dispose()}
}
$version=Native @('--version');Confirm ($version.Name -eq 'TokenForge')
$now=[DateTimeOffset]::UtcNow;$stamp=$now.AddMinutes(-9).ToString('o')
$client='11111111-1111-1111-1111-111111111111';$boot='22222222-2222-2222-2222-222222222222';$graph='00000003-0000-0000-c000-000000000000'
$profile=New-TokenForgeStrictProfile -TenantId aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa -PrincipalFingerprint ('b'*64) -BootstrapClientId $boot -ApprovedClientId @($client,$boot)
# This synthetic tool requires issuance only. It does not declare GraphMeV1 API proof.
$requirements=@{Format='TokenForgeToolRequirements';SchemaVersion=1;Tools=@(@{Id='read-profile';ClientIds=@($client);ResourceId=$graph;Scopes=@('User.Read');Protocol='OAuth2V2Pkce';CallbackClass='Native';Operations=@();Prerequisites=@();SecuritySensitive=$false})}
$inventory=@{SchemaVersion=1;CapturedAt=$now.AddHours(-1).ToString('o');TenantFingerprint=$profile.ExpectedTenantFingerprint;PrincipalFingerprint=$profile.ExpectedPrincipalFingerprint;GrantEnumeration='Complete';DiscoveryCatalogHash=('c'*64);TenantGrants=@();Applications=@(foreach($id in @($client,$boot,$graph)){@{AppId=$id;Name='Synthetic';Registration='Present';Ownership='VerifiedMicrosoftOwner';AccountEnabled=$true;RedirectUris=@('https://login.microsoftonline.com/common/oauth2/nativeclient');PublishedGrants=@();DelegatedScopeDefinitions=@(@{Id='33333333-3333-3333-3333-333333333333';Value='User.Read';Enabled=$true});AppRoleDefinitions=@()}})}
$plan=ReadJson ([TokenForge.Core.AdminWorkflows]::Plan((Json $profile),(Json $requirements),(Json $inventory),'read-profile'))
$snapshot=@{Format='TokenForgeChangeSnapshot';SchemaVersion=1;Collections=@(@{EvidenceType='IssuedScopes';Privacy='Private';Status='Complete';Context=$plan.Context;Source=@{Id='synthetic';Location=('urn:sha256:'+('d'*64));ContentSha256=('d'*64);HashKind='NormalizedDocument';SourceObservedAt=$null;CollectedAt=$stamp};Records=@(@{RecordId=('e'*64);ObservedAt=$stamp;Outcome='Succeeded';Identity=@{ClientId=$client;ResourceId=$graph};Value=@{Scopes=@('User.Read');NamespaceVerification='Matched';RequestVerification='Matched';ClaimsReadable=$true;HasScpClaim=$true;SignatureValidated=$false}})})}
$pp=Save profile.json $profile;$rp=Save requirements.json $requirements;$ip=Save inventory.json $inventory;$sp=Save snapshot.json $snapshot
$common=@('--profile-path',$pp,'--requirements-path',$rp,'--inventory-path',$ip,'--snapshot-path',$sp,'--tool','read-profile','--as-of',$now.ToString('o'),'--json')
$explanation=Native (@('admin','explain')+$common);Confirm ($explanation.Status -eq 'VerifiedWorking')
$health=Native (@('admin','check')+$common);Confirm ($health.Status -eq 'VerifiedWorking')
$acquisition=Native @('admin','acquire','--profile-path',$pp,'--requirements-path',$rp,'--inventory-path',$ip,'--tool','read-profile','--json') 4
Confirm ($acquisition.Reason -eq 'ExistingSilentSessionRequired' -and $acquisition.BootstrapAttempts -eq 0 -and $acquisition.FinalAttempts -eq 0)
$ap=Save saved-acquisition.json $acquisition;$null=Native @('admin','evidence','--acquisition-path',$ap,'--json')
$packet=Native @('admin','packet','--requirements-path',$rp,'--before-path',$sp,'--after-path',$sp,'--source-revision',('1'*40),'--package-sha256',('2'*64),'--as-of',$now.ToString('o'),'--json')
Confirm ($packet.Format -eq 'TokenForgeToolChangePacket' -and $packet.Status -eq 'PreparedForHumanReview' -and $packet.AutomaticCommunication -eq $false)
# Cold selection -> synthetic saved capture -> all-fresh zero-selection reuse.
$refresh=@{Format='TokenForgeRefreshInput';SchemaVersion=1;Profile=$profile;Requirements=$requirements;Inventory=$inventory;Snapshot=@{Format='TokenForgeChangeSnapshot';SchemaVersion=1;Collections=@()};Pins=@{SourceRevision=('1'*40);PackageManifestSha256=('2'*64);SchemaSha256=('3'*64);CollectorSemanticsSha256=('4'*64);CatalogHash=('5'*64);CohortHash=('6'*64);LegacyInventoryHash=('7'*64)};Policy=(ReadJson ([TokenForge.Core.AdminWorkflows]::CreateRefreshPolicy((Json $requirements))));History=(ReadJson ([TokenForge.Core.AdminWorkflows]::CreateRefreshHistory()))}
$cold=ReadJson ([TokenForge.Core.AdminWorkflows]::PlanRefresh((Json $refresh),$now.AddMinutes(-10)))
$warmSnapshot=ReadJson (Json $snapshot);$warmSnapshot.Collections[0].Context=$cold.Candidates[0].Context
$refresh.History=ReadJson ([TokenForge.Core.AdminWorkflows]::CaptureRefreshEvidence((Json $cold),(Json $warmSnapshot),(Json $refresh.History)));$refresh.Snapshot=$warmSnapshot
$fp=Save refresh-input.json $refresh
$fresh=Native @('refresh','plan','--input-path',$fp,'--as-of',$now.ToString('o'),'--json')
Confirm ($fresh.SelectedCount -eq 0 -and $fresh.ReusedCount -eq 1)
# Freeze a never-dispatched cohort, inspect status, and seal saved evidence twice.
$scopePath=Join-Path $Workspace scopes.sqlite;$flowPath=Join-Path $Workspace flows.sqlite
$cohort=New-TokenForgeResearchCohort -Inventory ([pscustomobject]$inventory) -DatabasePath $scopePath -GraphOnly -Protocols OAuth2V2Pkce -BatchSize 1 -MaxRedirects 1 -ExploreAllFlows -NativeExecutablePath $NativeExecutable
$flowInput=Save empty-flows.json @{Format='TokenForgeFlowEvidence';SchemaVersion=1;UpdatedAt=$stamp;Plans=@{};Attempts=@()}
$null=Native @('flows','import','--database',$flowPath,'--input',$flowInput)
$status=Get-TokenForgeCollectorStatus -DatabasePath $scopePath -FlowPath $flowPath -CohortId $cohort.PlanId -NativeExecutablePath $NativeExecutable
Confirm ($status.Status -eq 'Pending' -and $status.ApiAcceptance -eq 'NotEstablished')
. (Join-Path $package scripts/TokenForgeDiscoveryCandidate.ps1)
$options=@{ScopePath=$scopePath;FlowPath=$flowPath;CohortId=$cohort.PlanId;SourceCommit=('1'*40);ProducerRunId='1';ProducerAttempt='1';NativeExecutablePath=$NativeExecutable}
$hash=New-TfDiscoveryCandidate @options -OutputPath (Join-Path $Workspace candidate)
$null=Assert-TfDiscoveryCandidate (Join-Path $Workspace candidate) $hash
$hash2=New-TfDiscoveryCandidate @options -OutputPath (Join-Path $Workspace candidate-replay)
$null=Assert-TfDiscoveryCandidate (Join-Path $Workspace candidate-replay) $hash2
Confirm ((Get-TfCandidateFileHash (Join-Path $Workspace candidate/scopes.json)) -eq (Get-TfCandidateFileHash (Join-Path $Workspace candidate-replay/scopes.json)))
$backup=Join-Path $Workspace snapshot.sqlite;$restored=Join-Path $Workspace restored.sqlite
$receipt=Native @('storage','snapshot','--domain','scopes','--database',$scopePath,'--output-path',$backup,'--json')
Confirm ($receipt.Sha256 -eq (Get-FileHash $backup -Algorithm SHA256).Hash.ToLowerInvariant())
$null=Native @('storage','snapshot','--domain','scopes','--database',$backup,'--output-path',$restored,'--json')
$null=Native @('storage','snapshot','--domain','scopes','--database',$scopePath,'--output-path',$backup) 1
$restoredCohort=Get-TokenForgeResearchCohort -DatabasePath $restored -CohortId $cohort.PlanId -NativeExecutablePath $NativeExecutable
Confirm ($restoredCohort.PlanId -eq $cohort.PlanId)
[pscustomobject]@{SchemaVersion=1;Synthetic=$true;AsOf=$now.ToString('o');Checks=$count;Version=$version.Version;AdministratorWorkflows=4;Acquisition='BlockedWithoutSession';SelectedRefreshRequests=$fresh.SelectedCount;ReusedRefreshRequests=$fresh.ReusedCount;CollectorStatus=$status.Status;CandidateVerified=$true;SnapshotRestore=$true;LiveProof=$false;AuthorizationEstablished=$false}|ConvertTo-Json -Compress
