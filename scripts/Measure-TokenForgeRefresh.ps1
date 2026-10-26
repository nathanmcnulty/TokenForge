# Offline only. Frozen complete synthetic input, deterministic dispatch sink, no authentication or network.
[CmdletBinding()]param([ValidateRange(2,100)][int]$ToolCount=20,[Parameter(Mandatory)][string]$OutputPath)
$ErrorActionPreference='Stop'
. "$PSScriptRoot/../tests/fixtures/refresh/RefreshFixture.ps1"
$now=[DateTimeOffset]::UtcNow;$script:rfNow=$now
$i=New-RefreshInput;$script:benchPrincipal='cccccccc-cccc-cccc-cccc-cccccccccccc';$script:benchTenant='aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa';$i.Profile.ExpectedPrincipalFingerprint=[TokenForge.Core.ApplicationCatalogPolicy]::Hash($script:benchTenant+'/'+$script:benchPrincipal);$i.Inventory.PrincipalFingerprint=$i.Profile.ExpectedPrincipalFingerprint;$base=$i.Requirements.Tools[0]
$i.Requirements.Tools=@(for($n=0;$n -lt $ToolCount;$n++){$t=Copy-Refresh $base;$t.Id='benchmark-'+$n.ToString('00');$t})
$i.Policy=Read-RefreshJson ([TokenForge.Core.AdminWorkflows]::CreateRefreshPolicy(($i.Requirements|ConvertTo-Json -Depth 100 -Compress),$ToolCount));$i.Policy.MaxIssuanceAttempts=$ToolCount*2;$i.Policy.MaxBootstrapRequests=$ToolCount*11;$i.Policy.MaxTotalRequests=$ToolCount*24
$initial=Plan-Refresh $i $now.AddMinutes(-10)
$collections=@(foreach($row in $initial.Candidates){$one=New-RefreshObservation @{Candidates=@($row)} -At $now.AddMinutes(-9);$one.Collections[0].Records[0].RecordId=$row.RequestId;$one.Collections[0]})
$snapshot=@{Format='TokenForgeChangeSnapshot';SchemaVersion=1;Collections=$collections}
$i.History=Capture-Refresh $initial $snapshot $i.History;$i.Snapshot=$snapshot
$frozen=ConvertTo-Json -InputObject $i -Depth 100 -Compress;$frozenSha=[TokenForge.Core.ApplicationCatalogPolicy]::Hash($frozen)
$directory=[IO.Path]::GetDirectoryName([IO.Path]::GetFullPath($OutputPath));if(-not(Test-Path -LiteralPath $directory -PathType Container) -or (Test-Path -LiteralPath $OutputPath)){throw 'A new report path with an existing parent is required.'}
# Both paths pay full authoritative validation on identical frozen data. The baseline actually
# exercises the shared strict acquisition workflow with synthetic in-memory token/identity adapters.
$script:benchTokenCalls=0;$script:benchIdentityCalls=0
$execute=[Func[TokenForge.Core.ScopePlanning+RequestRow,TokenForge.Core.ProfileCredentialToken]]{
 param($request)
 $script:benchTokenCalls++
 $body=@{tid=$script:benchTenant;oid=$script:benchPrincipal;appid=$request.ClientId;aud=$request.ResourceId;scp=($request.Scopes -join ' ');exp=[DateTimeOffset]::UtcNow.AddMinutes(30).ToUnixTimeSeconds()}|ConvertTo-Json -Compress
 $jwt='e30.'+[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($body)).TrimEnd('=').Replace('+','-').Replace('/','_')+'.fixture'
 $access=ConvertTo-SecureString $jwt -AsPlainText -Force
 try{[TokenForge.Core.ProfileCredentialToken]::new($request.ToTransport(),$access,$null,[DateTimeOffset]::UtcNow.AddMinutes(30),0)}finally{$access.Dispose()}
}
$identity=[Func[Security.SecureString,string]]{param($token)$script:benchIdentityCalls++;$script:benchPrincipal}
$cookie=ConvertTo-SecureString synthetic-benchmark-cookie -AsPlainText -Force
function Measure-Dispatch($Replay) {
 $script:benchTokenCalls=0;$script:benchIdentityCalls=0
 $watch=[Diagnostics.Stopwatch]::StartNew();$validated=Get-TokenForgeRefreshPlan -InputJson $frozen -AsOf $now;$planningMs=$watch.Elapsed.TotalMilliseconds
 $acquisitions=0;$projectionMs=0.0;$facts=[Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
 foreach($row in $validated.Candidates){
  if($Replay -or $row.Selected){
   $acquisitions++
   $result=[TokenForge.Core.AdminWorkflows]::Acquire(($i.Profile|ConvertTo-Json -Depth 100 -Compress),($i.Requirements|ConvertTo-Json -Depth 100 -Compress),($i.Inventory|ConvertTo-Json -Depth 100 -Compress),$row.ToolId,$cookie,'ESTSAUTH',$row.CompatibilityDescriptor.Client.AppId,([TokenForge.Core.ApplicationCatalogPolicy]::Hash($row.CompatibilityDescriptor.CallbackUri)),$false,[NullString]::Value,$execute,$identity,$null,[Threading.CancellationToken]::None)
   try{
    $metadata=Read-RefreshJson $result.ToJson();if($metadata.Status -cne 'IssuedWithinStrictPolicy'){throw 'Synthetic baseline acquisition failed.'}
    $stage=[Diagnostics.Stopwatch]::StartNew();$evidence=Read-RefreshJson ([TokenForge.Core.AdminWorkflows]::AcquisitionEvidence($result.ToJson()));if($evidence.Collections[0].Records.Count -ne 1){throw 'Synthetic baseline projection failed.'};$null=$facts.Add($row.RequestId);$projectionMs+=$stage.Elapsed.TotalMilliseconds
   }finally{$result.Dispose()}
  }elseif($row.ReuseReferences.Count){$stage=[Diagnostics.Stopwatch]::StartNew();$null=$facts.Add($row.RequestId);$projectionMs+=$stage.Elapsed.TotalMilliseconds}
 }
 [pscustomobject]@{FullInputValidated=$true;Candidates=$validated.Candidates.Count;UsefulContextFacts=$facts.Count;StrictAcquisitionCalls=$acquisitions;SyntheticTokenAcquisitions=$script:benchTokenCalls;SyntheticIdentityChecks=$script:benchIdentityCalls;ModeledHttpExchanges=($acquisitions*5);ExternalRequests=0;TransientRetries=0;RetryWaitMilliseconds=0;SourceMilliseconds=0;InventoryFetchMilliseconds=0;SourceRequests=0;InventoryPages=0;PlanningMilliseconds=[Math]::Round($planningMs,3);ProjectionMilliseconds=[Math]::Round($projectionMs,3);ElapsedMilliseconds=[Math]::Round($watch.Elapsed.TotalMilliseconds,3);ChildProcessStarts=0;DatabaseReads=0;DatabaseWrites=0;SharedProcessPeakWorkingSetBytes=[Diagnostics.Process]::GetCurrentProcess().PeakWorkingSet64;Reused=$validated.ReusedCount;PlanId=$validated.PlanId}
}
try{
$baseline=Measure-Dispatch $true;$incremental=Measure-Dispatch $false
if($baseline.UsefulContextFacts -ne $ToolCount -or $incremental.UsefulContextFacts -ne $ToolCount -or  $incremental.SyntheticTokenAcquisitions -ne 0 -or $incremental.SyntheticIdentityChecks -ne 0 -or $baseline.SyntheticTokenAcquisitions -ne $ToolCount*2 -or $baseline.PlanId -cne $incremental.PlanId){throw 'Offline completeness or zero-dispatch gate failed.'}
$receipt=[ordered]@{Format='TokenForgeRefreshBenchmark';SchemaVersion=1;Evidence='SharedStrictAcquisitionWithSyntheticTokenAndIdentityAdapters';AsOf=$now.ToString('o');FrozenInputPath=([IO.Path]::GetFullPath($OutputPath)+'.input.json');BenchmarkScriptSha256=([Convert]::ToHexString([Security.Cryptography.SHA256]::HashData([IO.File]::ReadAllBytes($PSCommandPath))).ToLowerInvariant());FrozenInputSha256=$frozenSha;SourceRevision=([string](git -C "$PSScriptRoot/.." rev-parse HEAD)).Trim();Baseline=$baseline;Incremental=$incremental;NetworkPerformanceClaim=$false;InputBytes=[Text.Encoding]::UTF8.GetByteCount($frozen);ReportWrites=1}
if(Test-Path -LiteralPath $receipt.FrozenInputPath){throw 'Frozen input output already exists.'};[IO.File]::WriteAllText($receipt.FrozenInputPath,$frozen);if(-not $IsWindows){[IO.File]::SetUnixFileMode($receipt.FrozenInputPath,[IO.UnixFileMode]384)}
[IO.File]::WriteAllText([IO.Path]::GetFullPath($OutputPath),($receipt|ConvertTo-Json -Depth 100));$receipt

}finally{$cookie.Dispose()}
