# Offline only. Frozen complete synthetic input, deterministic dispatch sink, no authentication or network.
[CmdletBinding()]param([ValidateRange(2,100)][int]$ToolCount=20,[Parameter(Mandatory)][string]$OutputPath)
$ErrorActionPreference='Stop'
. "$PSScriptRoot/../tests/fixtures/refresh/RefreshFixture.ps1"
$now=[DateTimeOffset]::UtcNow;$script:rfNow=$now
$i=New-RefreshInput;$base=$i.Requirements.Tools[0]
$i.Requirements.Tools=@(for($n=0;$n -lt $ToolCount;$n++){$t=Copy-Refresh $base;$t.Id='benchmark-'+$n.ToString('00');$t})
$i.Policy=Read-RefreshJson ([TokenForge.Core.AdminWorkflows]::CreateRefreshPolicy(($i.Requirements|ConvertTo-Json -Depth 100 -Compress),$ToolCount));$i.Policy.MaxIssuanceAttempts=$ToolCount*2;$i.Policy.MaxBootstrapRequests=$ToolCount*11;$i.Policy.MaxTotalRequests=$ToolCount*24
$initial=Plan-Refresh $i $now.AddMinutes(-10)
$collections=@(foreach($row in $initial.Candidates){$one=New-RefreshObservation @{Candidates=@($row)} -At $now.AddMinutes(-9);$one.Collections[0].Records[0].RecordId=$row.RequestId;$one.Collections[0]})
$snapshot=@{Format='TokenForgeChangeSnapshot';SchemaVersion=1;Collections=$collections}
$i.History=Capture-Refresh $initial $snapshot $i.History;$i.Snapshot=$snapshot
$frozen=ConvertTo-Json -InputObject $i -Depth 100 -Compress;$frozenSha=[TokenForge.Core.ApplicationCatalogPolicy]::Hash($frozen)
$directory=[IO.Path]::GetDirectoryName([IO.Path]::GetFullPath($OutputPath));if(-not(Test-Path -LiteralPath $directory -PathType Container) -or (Test-Path -LiteralPath $OutputPath)){throw 'A new report path with an existing parent is required.'}
# Both paths pay full authoritative validation on identical frozen data. The baseline models serial replay.
function Measure-Dispatch($Replay) {
 $watch=[Diagnostics.Stopwatch]::StartNew();$validated=Get-TokenForgeRefreshPlan -InputJson $frozen -AsOf $now;$planningMs=$watch.Elapsed.TotalMilliseconds
 $dispatches=0;$issuances=0;$facts=[Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
 $projection=[Diagnostics.Stopwatch]::StartNew()
 foreach($row in $validated.Candidates){if($Replay -or $row.Selected){$issuances+=2;foreach($exchange in 1..5){$dispatches++};$null=$facts.Add($row.RequestId)}elseif($row.ReuseReferences.Count){$null=$facts.Add($row.RequestId)}}
 [pscustomobject]@{FullInputValidated=$true;Candidates=$validated.Candidates.Count;UsefulContextFacts=$facts.Count;IssuanceAttempts=$issuances;SyntheticHttpDispatches=$dispatches;ExternalRequests=0;TransientRetries=0;RetryWaitMilliseconds=0;SourceMilliseconds=0;InventoryMilliseconds=0;SourceRequests=0;InventoryPages=0;PlanningMilliseconds=[Math]::Round($planningMs,3);ProjectionMilliseconds=[Math]::Round($projection.Elapsed.TotalMilliseconds,3);ElapsedMilliseconds=[Math]::Round($watch.Elapsed.TotalMilliseconds,3);ProcessStarts=0;DatabaseReads=0;DatabaseWrites=0;PeakWorkingSetBytes=[Diagnostics.Process]::GetCurrentProcess().PeakWorkingSet64;Reused=$validated.ReusedCount;PlanId=$validated.PlanId}
}
$baseline=Measure-Dispatch $true;$incremental=Measure-Dispatch $false
if($baseline.UsefulContextFacts -ne $ToolCount -or $incremental.UsefulContextFacts -ne $ToolCount -or $incremental.IssuanceAttempts -ne 0 -or $incremental.SyntheticHttpDispatches -ne 0 -or $baseline.PlanId -cne $incremental.PlanId){throw 'Offline completeness or zero-dispatch gate failed.'}
$receipt=[ordered]@{Format='TokenForgeRefreshBenchmark';SchemaVersion=1;Evidence='SyntheticDispatchCountsAndLocalStageTiming';FrozenInputSha256=$frozenSha;SourceRevision=([string](git -C "$PSScriptRoot/.." rev-parse HEAD)).Trim();Baseline=$baseline;Incremental=$incremental;NetworkPerformanceClaim=$false;InputBytes=[Text.Encoding]::UTF8.GetByteCount($frozen);ReportWrites=1}
[IO.File]::WriteAllText([IO.Path]::GetFullPath($OutputPath),($receipt|ConvertTo-Json -Depth 100));$receipt
