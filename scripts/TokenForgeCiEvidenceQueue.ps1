# Credential-free planning only. A receipt proves assessment, never token issuance.
. (Join-Path $PSScriptRoot 'TokenForgeCiState.ps1')
# Separate reuse identity; the legacy full application/cohort hashes are unchanged.
function Get-TfCiPublicCompatibilityKey($Application) {
 $copy=[TokenForge.Core.DiscoverySourceClaims]::ReadMetadataJson((ConvertTo-Json -InputObject $Application -Depth 100))
 $copy.Remove('Name');$copy.Remove('PublishedName')
 if($copy.Contains('SourceClaims')){foreach($claim in $copy.SourceClaims){$claim.Remove('Name');$claim.Remove('PublishedName')}}
 if($copy.Contains('MetadataConflicts')){$copy.MetadataConflicts=@($copy.MetadataConflicts|Where-Object Field -cne Name)}
 Get-TfCiHash ([ordered]@{CompatibilityVersion=1;CollectorSemantics='public-deep-assessment/graph-arm/v1';Application=$copy})
}
function Get-TfCiEvidenceQueue {
 [CmdletBinding()]
 param(
  [Parameter(Mandatory)]$Discovery,
  $PreviousState,
  [ValidateRange(1,100)][int]$MaxApplications=100,
  [ValidateRange(1,90)][int]$FreshnessDays=1,
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
  foreach($app in $PreviousState.Recipe.Discovery.Applications){$prior[$app.AppId]=Get-TfCiPublicCompatibilityKey $app}
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
  $reason=if($prior.ContainsKey($app.AppId) -and $prior[$app.AppId] -cne (Get-TfCiPublicCompatibilityKey $app)){'ChangedPublicHints'}elseif($null -eq $observed){'MissingEvidence'}elseif($expires -le $nowUtc){'StaleEvidence'}else{'FreshEvidence'}
  [pscustomobject][ordered]@{
   AppId=$app.AppId;EvidenceType='CompletedDeepAssessment';ResourceIds=$resources
   Reason=$reason;Priority=$(switch($reason){ChangedPublicHints {0} MissingEvidence {1} StaleEvidence {2} FreshEvidence {3}})
   ObservedAt=$(if($null -ne $observed){$observed.ToString('o')}else{$null})
   FreshUntil=$(if($null -ne $expires){$expires.ToString('o')}else{$null})
   LastSelectedWeek=$(if($history.ContainsKey($app.AppId)){$history[$app.AppId]}else{''})
  }
 })
 $pending=@($rows|Where-Object Reason -cne FreshEvidence|Sort-Object Priority,ObservedAt,LastSelectedWeek,AppId)
 $fair=@($pending|Where-Object Priority -gt $(if($pending.Count){$pending[0].Priority}else{99})|Sort-Object LastSelectedWeek,ObservedAt,AppId|Select-Object -First 1)
 $chosen=if($fair.Count -and $pending.Count -gt $MaxApplications){@(@($pending|Where-Object AppId -cne $fair[0].AppId|Select-Object -First ($MaxApplications-1))+$fair|Sort-Object Priority,ObservedAt,LastSelectedWeek,AppId)}else{@($pending|Select-Object -First $MaxApplications)}
 [pscustomobject][ordered]@{
  SchemaVersion=1;EvaluatedAt=$nowUtc.ToString('o');FreshnessDays=$FreshnessDays;MaxApplications=$MaxApplications
  EvidenceType='CompletedDeepAssessment';CandidateCount=$rows.Count;FreshCount=@($rows|Where-Object Reason -ceq FreshEvidence).Count
  PendingCount=$pending.Count;DeferredCount=[Math]::Max(0,$pending.Count-$MaxApplications)
  Items=@($chosen)
 }
}

function Assert-TfCiEvidenceSelection($State,$Snapshot) {
 Assert-TfCiKeys $Snapshot @('SchemaVersion','PlanId','SelectedAppIds','Queue')
 if($Snapshot.SchemaVersion -ne 1 -or $Snapshot.PlanId -isnot [string] -or $Snapshot.PlanId -cnotmatch '^[a-f0-9]{64}$' -or $Snapshot.SelectedAppIds -isnot [array] -or @($Snapshot.SelectedAppIds|Where-Object {$_ -isnot [string] -or $_ -cnotmatch '^[a-f0-9]{8}-(?:[a-f0-9]{4}-){3}[a-f0-9]{12}$'}).Count -or ($Snapshot.SelectedAppIds -join '/') -cne (@($Snapshot.SelectedAppIds|Sort-Object -Unique) -join '/') -or ($null -ne $State -and ($Snapshot.PlanId -cne $State.PlanId -or (Get-TfCiHash $Snapshot) -cne $State.EvidenceSelectionSha256 -or ($Snapshot.SelectedAppIds -join '/') -cne ($State.Recipe.AppIds -join '/')))){throw 'Invalid frozen evidence selection binding.'}
 if($null -ne $State -and (@(Get-TfCiResources $State) -join '/') -cne (@('00000003-0000-0000-c000-000000000000','797f4846-ba00-4fd7-ba43-dac1f8f63013') -join '/')){throw 'Evidence selection resource mismatch.'}
 $q=$Snapshot.Queue
 Assert-TfCiKeys $q @('SchemaVersion','EvaluatedAt','FreshnessDays','MaxApplications','EvidenceType','CandidateCount','FreshCount','PendingCount','DeferredCount','Items')
 foreach($field in @('SchemaVersion','FreshnessDays','MaxApplications','CandidateCount','FreshCount','PendingCount','DeferredCount')){if($q[$field] -isnot [int] -and $q[$field] -isnot [long]){throw 'Invalid evidence queue number type.'}}
 $at=[TokenForge.Core.V0240.TimestampPolicy]::Parse($q.EvaluatedAt)
 $created=if($null -ne $State){[TokenForge.Core.V0240.TimestampPolicy]::Parse($State.Recipe.CreatedAt)}else{$at}
 if($q.SchemaVersion -ne 1 -or $q.EvidenceType -cne 'CompletedDeepAssessment' -or $q.FreshnessDays -lt 1 -or $q.FreshnessDays -gt 90 -or $q.MaxApplications -lt 1 -or $q.MaxApplications -gt 100 -or $at -gt $created -or $q.Items -isnot [array] -or $q.Items.Count -ne $Snapshot.SelectedAppIds.Count -or $q.Items.Count -gt $q.MaxApplications -or $q.PendingCount -lt $q.Items.Count -or $q.CandidateCount -ne $q.FreshCount+$q.PendingCount -or $q.DeferredCount -ne $q.PendingCount-$q.Items.Count -or $q.FreshCount -lt 0 -or ($null -ne $State -and $q.CandidateCount -gt $State.Recipe.Discovery.Applications.Count)){throw 'Invalid frozen evidence queue policy.'}
 if((@($q.Items|ForEach-Object AppId|Sort-Object -Unique) -join '/') -cne ($Snapshot.SelectedAppIds -join '/')){throw 'Invalid frozen evidence queue membership.'}
 foreach($row in $q.Items){
  Assert-TfCiKeys $row @('AppId','EvidenceType','ResourceIds','Reason','Priority','ObservedAt','FreshUntil','LastSelectedWeek')
  $priority=switch($row.Reason){ChangedPublicHints {0} MissingEvidence {1} StaleEvidence {2} default {throw 'Invalid evidence queue reason.'}}
  if($row.EvidenceType -cne 'CompletedDeepAssessment' -or $row.Priority -ne $priority -or $row.ResourceIds -isnot [array] -or ($row.ResourceIds -join '/') -cne (@('00000003-0000-0000-c000-000000000000','797f4846-ba00-4fd7-ba43-dac1f8f63013') -join '/') -or $row.LastSelectedWeek -isnot [string] -or ($row.LastSelectedWeek -ne '' -and $row.LastSelectedWeek -notmatch '^\d{4}-W\d{2}$')){throw 'Invalid evidence queue fields.'}
  if($null -eq $row.ObservedAt){if($null -ne $row.FreshUntil -or $row.Reason -eq 'StaleEvidence'){throw 'Missing evidence queue timestamp.'}}
  else{
   $observed=[TokenForge.Core.V0240.TimestampPolicy]::Parse($row.ObservedAt);$expiry=[TokenForge.Core.V0240.TimestampPolicy]::Parse($row.FreshUntil)
   if($observed -gt $at -or $expiry -ne $observed.AddDays($q.FreshnessDays) -or $row.Reason -eq 'MissingEvidence' -or ($row.Reason -eq 'StaleEvidence' -and $expiry -gt $at)){throw 'Invalid evidence queue freshness.'}
  }
 }
 if((@($q.Items|ForEach-Object AppId) -join '/') -cne (@($q.Items|Sort-Object Priority,ObservedAt,LastSelectedWeek,AppId|ForEach-Object AppId) -join '/')){throw 'Invalid evidence queue order.'}
}

# Immutable selections precede one atomic legacy-state replacement. Old generations remain readable.
function Get-TfCiEvidenceSelectionPath($Directory,$Digest) {
 if($Digest -isnot [string] -or $Digest -cnotmatch '^[a-f0-9]{64}$'){throw 'Invalid evidence generation digest.'}
 Join-Path $Directory ('selection-deep-'+$Digest+'.json')
}
function Read-TfCiEvidenceSelection($State,[string]$Directory) {
 $path=Get-TfCiEvidenceSelectionPath $Directory $State.EvidenceSelectionSha256
 if(-not (Test-Path -LiteralPath $path -PathType Leaf)){$path=Join-Path $Directory selection-deep.json}
 if(-not (Test-Path -LiteralPath $path -PathType Leaf) -or (Get-Item -LiteralPath $path -Force).LinkType){throw 'Missing frozen evidence selection or linked file.'}
 $snapshot=[TokenForge.Core.DiscoverySourceClaims]::ReadMetadataJson([IO.File]::ReadAllText($path))
 Assert-TfCiEvidenceSelection $State $snapshot
 $alias=Join-Path $Directory selection-deep.json
 if((Test-Path -LiteralPath $alias -PathType Leaf) -and $path -cne $alias){
  if((Get-Item -LiteralPath $alias -Force).LinkType){throw 'Linked selection alias.'}
  $legacy=[TokenForge.Core.DiscoverySourceClaims]::ReadMetadataJson([IO.File]::ReadAllText($alias));Assert-TfCiEvidenceSelection $State $legacy
 }
 $snapshot
}
function Save-TfCiAtomicJson($Value,[string]$Path,[switch]$Immutable) {
 $full=[IO.Path]::GetFullPath($Path);$directory=[IO.DirectoryInfo]::new((Split-Path $full -Parent))
 $cursor=$directory;while($cursor){if($cursor.LinkTarget){throw 'Linked evidence output directory.'};$cursor=$cursor.Parent}
 if((Test-Path -LiteralPath $full) -and (Get-Item -LiteralPath $full -Force).LinkType){throw 'Linked evidence output file.'}
 if($Immutable -and (Test-Path -LiteralPath $full)){
  $existing=[TokenForge.Core.DiscoverySourceClaims]::ReadMetadataJson([IO.File]::ReadAllText($full))
  if((Get-TfCiHash $existing) -cne (Get-TfCiHash $Value)){throw 'Immutable evidence generation differs.'};return
 }
 $temporary=$full+'.'+[guid]::NewGuid().ToString('N')+'.tmp'
 try{
  $stream=[IO.File]::Open($temporary,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
  try{if(-not $IsWindows){[IO.File]::SetUnixFileMode($temporary,[IO.UnixFileMode]384)};$bytes=[Text.Encoding]::UTF8.GetBytes((ConvertTo-Json -InputObject $Value -Depth 100));$stream.Write($bytes);$stream.Flush($true)}finally{$stream.Dispose()}
  [IO.File]::Move($temporary,$full,(-not $Immutable))
 }finally{if(Test-Path -LiteralPath $temporary){Remove-Item -LiteralPath $temporary -Force}}
}
function Save-TfCiEvidenceState($State,[string]$StatePath,$Selection,[scriptblock]$Boundary) {
 $directory=Split-Path ([IO.Path]::GetFullPath($StatePath)) -Parent
 # Upgrade an old fixed sidecar before it can be replaced or removed. Its bound old state stays valid.
 $legacy=Join-Path $directory selection-deep.json
 if(Test-Path -LiteralPath $legacy){
  $old=[TokenForge.Core.DiscoverySourceClaims]::ReadMetadataJson([IO.File]::ReadAllText($StatePath));Assert-TfCiState $old
  $prior=Read-TfCiEvidenceSelection $old $directory
  Save-TfCiAtomicJson $prior (Get-TfCiEvidenceSelectionPath $directory $old.EvidenceSelectionSha256) -Immutable
  Remove-Item -LiteralPath $legacy
 }
 if($State.Contains('EvidenceSelectionSha256')){
  if($null -eq $Selection){$Selection=Read-TfCiEvidenceSelection $State $directory}
  Assert-TfCiEvidenceSelection $State $Selection
  Save-TfCiAtomicJson $Selection (Get-TfCiEvidenceSelectionPath $directory $State.EvidenceSelectionSha256) -Immutable
 }elseif($null -ne $Selection){throw 'Unbound evidence selection.'}
 if($Boundary){& $Boundary 'SelectionDurable'}
 Assert-TfCiState $State;Save-TfCiAtomicJson $State $StatePath
 if($Boundary){& $Boundary 'StateDurable'}
}
