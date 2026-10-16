# Credential-free planning only. A receipt proves assessment, never token issuance.
. (Join-Path $PSScriptRoot 'TokenForgeCiState.ps1')
function Get-TfCiEvidenceQueue {
 [CmdletBinding()]
 param(
  [Parameter(Mandatory)]$Discovery,
  $PreviousState,
  [ValidateRange(1,100)][int]$MaxApplications=100,
  [ValidateRange(1,90)][int]$FreshnessDays=7,
  [DateTimeOffset]$Now=[DateTimeOffset]::UtcNow
 )
 Assert-TfCiDiscovery $Discovery
 $nowUtc=$Now.ToUniversalTime()
 $resources=@('00000003-0000-0000-c000-000000000000','797f4846-ba00-4fd7-ba43-dac1f8f63013')
 $prior=@{};$history=@{};$assessed=@{}
 if($null -ne $PreviousState){
  Assert-TfCiState $PreviousState
  $created=[TokenForge.Core.V0240.TimestampPolicy]::Parse($PreviousState.Recipe.CreatedAt)
  if($created -gt $nowUtc){throw 'Evidence recipe is in the future.'}
  foreach($app in $PreviousState.Recipe.Discovery.Applications){$prior[$app.AppId]=Get-TfCiHash $app}
  if($PreviousState.Recipe.Mode -eq 'Deep'){
   if($PreviousState.Contains('DeepSelectionHistory')){foreach($id in $PreviousState.DeepSelectionHistory.Keys){$history[$id]=$PreviousState.DeepSelectionHistory[$id]}}
   foreach($id in $PreviousState.Recipe.AppIds){$history[$id]=$PreviousState.Recipe.Week}
   # A Graph-only legacy recipe cannot prove both requested resources assessed.
   if((@(Get-TfCiResources $PreviousState) -join '/') -ceq ($resources -join '/')){
    foreach($batch in $PreviousState.Batches){
     if($batch.Status -cne 'Complete'){continue}
     $observed=[TokenForge.Core.V0240.TimestampPolicy]::Parse($batch.ObservedAt)
     if($observed -gt $nowUtc -or $observed -lt $created -or $batch.Attempts -lt 1){throw 'Invalid deep assessment evidence timestamp or attempt.'}
     foreach($id in @(Get-TfCiMembers $PreviousState $batch.Index)){$assessed[$id]=$observed.ToUniversalTime()}
    }
   }
  }
 }
 $rows=@(foreach($app in $Discovery.Applications){
  if(-not $app.RedirectUris.Count){continue}
  $observed=$null;$expires=$null
  if($assessed.ContainsKey($app.AppId)){$observed=$assessed[$app.AppId];$expires=$observed.AddDays($FreshnessDays)}
  $reason=if($prior.ContainsKey($app.AppId) -and $prior[$app.AppId] -cne (Get-TfCiHash $app)){'ChangedPublicHints'}elseif($null -eq $observed){'MissingEvidence'}elseif($expires -le $nowUtc){'StaleEvidence'}else{'FreshEvidence'}
  [pscustomobject][ordered]@{
   AppId=$app.AppId;EvidenceType='CompletedDeepAssessment';ResourceIds=$resources
   Reason=$reason;Priority=$(switch($reason){ChangedPublicHints {0} MissingEvidence {1} StaleEvidence {2} FreshEvidence {3}})
   ObservedAt=$(if($null -ne $observed){$observed.ToString('o')}else{$null})
   FreshUntil=$(if($null -ne $expires){$expires.ToString('o')}else{$null})
   LastSelectedWeek=$(if($history.ContainsKey($app.AppId)){$history[$app.AppId]}else{''})
  }
 })
 $pending=@($rows|Where-Object Reason -cne FreshEvidence|Sort-Object Priority,ObservedAt,LastSelectedWeek,AppId)
 [pscustomobject][ordered]@{
  SchemaVersion=1;EvaluatedAt=$nowUtc.ToString('o');FreshnessDays=$FreshnessDays;MaxApplications=$MaxApplications
  EvidenceType='CompletedDeepAssessment';CandidateCount=$rows.Count;FreshCount=@($rows|Where-Object Reason -ceq FreshEvidence).Count
  PendingCount=$pending.Count;DeferredCount=[Math]::Max(0,$pending.Count-$MaxApplications)
  Items=@($pending|Select-Object -First $MaxApplications)
 }
}

function Assert-TfCiEvidenceSelection($State,$Snapshot) {
 Assert-TfCiKeys $Snapshot @('SchemaVersion','PlanId','SelectedAppIds','Queue')
 if($Snapshot.SchemaVersion -ne 1 -or $Snapshot.PlanId -cne $State.PlanId -or (Get-TfCiHash $Snapshot) -cne $State.EvidenceSelectionSha256 -or $Snapshot.SelectedAppIds -isnot [array] -or ($Snapshot.SelectedAppIds -join '/') -cne ($State.Recipe.AppIds -join '/')){throw 'Invalid frozen evidence selection binding.'}
 $q=$Snapshot.Queue
 Assert-TfCiKeys $q @('SchemaVersion','EvaluatedAt','FreshnessDays','MaxApplications','EvidenceType','CandidateCount','FreshCount','PendingCount','DeferredCount','Items')
 foreach($field in @('SchemaVersion','FreshnessDays','MaxApplications','CandidateCount','FreshCount','PendingCount','DeferredCount')){if($q[$field] -isnot [int] -and $q[$field] -isnot [long]){throw 'Invalid evidence queue number type.'}}
 $at=[TokenForge.Core.V0240.TimestampPolicy]::Parse($q.EvaluatedAt)
 $created=[TokenForge.Core.V0240.TimestampPolicy]::Parse($State.Recipe.CreatedAt)
 if($q.SchemaVersion -ne 1 -or $q.EvidenceType -cne 'CompletedDeepAssessment' -or $q.FreshnessDays -lt 1 -or $q.FreshnessDays -gt 90 -or $q.MaxApplications -lt 1 -or $q.MaxApplications -gt 100 -or $at -gt $created -or $q.Items -isnot [array] -or $q.Items.Count -ne $State.Recipe.AppIds.Count -or $q.Items.Count -gt $q.MaxApplications -or $q.PendingCount -lt $q.Items.Count -or $q.CandidateCount -ne $q.FreshCount+$q.PendingCount -or $q.DeferredCount -ne $q.PendingCount-$q.Items.Count -or $q.FreshCount -lt 0 -or $q.CandidateCount -gt $State.Recipe.Discovery.Applications.Count){throw 'Invalid frozen evidence queue policy.'}
 if((@($q.Items|ForEach-Object AppId|Sort-Object -Unique) -join '/') -cne ($State.Recipe.AppIds -join '/')){throw 'Invalid frozen evidence queue membership.'}
 foreach($row in $q.Items){
  Assert-TfCiKeys $row @('AppId','EvidenceType','ResourceIds','Reason','Priority','ObservedAt','FreshUntil','LastSelectedWeek')
  $priority=switch($row.Reason){ChangedPublicHints {0} MissingEvidence {1} StaleEvidence {2} default {throw 'Invalid evidence queue reason.'}}
  if($row.EvidenceType -cne 'CompletedDeepAssessment' -or $row.Priority -ne $priority -or $row.ResourceIds -isnot [array] -or ($row.ResourceIds -join '/') -cne (@(Get-TfCiResources $State) -join '/') -or $row.LastSelectedWeek -isnot [string] -or ($row.LastSelectedWeek -ne '' -and $row.LastSelectedWeek -notmatch '^\d{4}-W\d{2}$')){throw 'Invalid evidence queue fields.'}
  if($null -eq $row.ObservedAt){if($null -ne $row.FreshUntil -or $row.Reason -eq 'StaleEvidence'){throw 'Missing evidence queue timestamp.'}}
  else{
   $observed=[TokenForge.Core.V0240.TimestampPolicy]::Parse($row.ObservedAt);$expiry=[TokenForge.Core.V0240.TimestampPolicy]::Parse($row.FreshUntil)
   if($observed -gt $at -or $expiry -ne $observed.AddDays($q.FreshnessDays) -or $row.Reason -eq 'MissingEvidence' -or ($row.Reason -eq 'StaleEvidence' -and $expiry -gt $at)){throw 'Invalid evidence queue freshness.'}
  }
 }
 if((@($q.Items|ForEach-Object AppId) -join '/') -cne (@($q.Items|Sort-Object Priority,ObservedAt,LastSelectedWeek,AppId|ForEach-Object AppId) -join '/')){throw 'Invalid evidence queue order.'}
}
