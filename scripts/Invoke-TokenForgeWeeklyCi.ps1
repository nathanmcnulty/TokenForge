#Requires -Version 7.4
[CmdletBinding()]
param(
 [Parameter(Mandatory)][ValidateSet('Prepare','Publish')][string]$Action,
 [Parameter(Mandatory)][string]$DataPath,[Parameter(Mandatory)][string]$BundlePath,
 [ValidateRange(1,4)][int]$Workers=4,[ValidateSet('Auto','Shallow','Deep')][string]$Mode='Auto',
 [ValidateRange(1,100)][int]$DeepMaxApplications=100,
 [guid[]]$AppId,[switch]$RetryExhausted,[switch]$ValidationOnly
)
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'TokenForgeCiState.ps1')
Import-Module (Join-Path $PSScriptRoot '../src/TokenForge/TokenForge.psd1') -Force
function Save-CiJson($Value,[string]$Path){$temp=$Path+'.'+[guid]::NewGuid()+'.tmp';try{$Value|ConvertTo-Json -Depth 100|Set-Content $temp;Move-Item -LiteralPath $temp -Destination $Path -Force}finally{if(Test-Path $temp){Remove-Item $temp -Force}}}
if($ValidationOnly){
 if($Mode -cne 'Deep'){throw 'Isolated validation requires Deep mode.'}
 if($Action -eq 'Prepare'){
  if(-not $AppId -or $AppId.Count -gt 4){throw 'Choose one to four explicit published validation IDs.'}
  if($Workers -lt [Math]::Ceiling(@($AppId|Sort-Object -Unique).Count/2)){throw 'Validation requires enough workers for every two-app chunk.'}
  if(Test-Path -LiteralPath $DataPath){if(@(Get-ChildItem -LiteralPath $DataPath -File -Filter 'weekly-*.json').Count){throw 'Validation requires an isolated directory without weekly state.'}}
  $DeepMaxApplications=4
 }
}
$null=New-Item -ItemType Directory $DataPath,$BundlePath,(Join-Path $DataPath reports) -Force
Assert-TfCiPublicData $DataPath
if($Mode -eq 'Auto'){
 $shallowPath=Join-Path $DataPath weekly-shallow.json
 $shallow=if(Test-Path $shallowPath){Get-Content $shallowPath -Raw|ConvertFrom-Json -AsHashtable}else{$null}
 $Mode=if($shallow -and $shallow.Recipe.Week -eq (Get-TfCiWeek) -and (Get-TfCiReport $shallow).Complete){'Deep'}else{'Shallow'}
}
if($AppId -and $Mode -ne 'Deep'){throw 'Targeted IDs are available only for Deep; weekly shallow coverage must include the full public catalog.'}
$statePath=Join-Path $DataPath ('weekly-'+$Mode.ToLowerInvariant()+'.json')
if($Action -eq 'Prepare'){
 $metadata=Join-Path $DataPath applications.json
 if(Test-Path $metadata){$null=Get-TokenForgeApplicationMetadata $metadata -PublicOnly}
 $discovery=Update-TokenForgeDiscovery -Path (Join-Path $BundlePath discovery.json) -MetadataPath $metadata
 $null=Get-TokenForgeApplicationMetadata $metadata -PublicOnly
 $state=if(Test-Path $statePath){Get-Content $statePath -Raw|ConvertFrom-Json -AsHashtable}else{$null}
 if($state){Assert-TfCiState $state}
 # History records public selection, not issuance or completed assessment.
 $history=@{}
 if($Mode -eq 'Deep' -and $state){
  if($state.Contains('DeepSelectionHistory')){foreach($id in $state.DeepSelectionHistory.Keys){$history[$id]=$state.DeepSelectionHistory[$id]}}
  foreach($id in $state.Recipe.AppIds){$history[$id]=$state.Recipe.Week}
 }
 if(-not $state -or $state.Recipe.Week -ne (Get-TfCiWeek)){
  if($state){$archive=Join-Path $DataPath reports;$null=New-Item -ItemType Directory $archive -Force;Save-CiJson (Get-TfCiReport $state) (Join-Path $archive ($state.Recipe.Week+'-'+$Mode.ToLowerInvariant()+'.json'))}
  # Freeze only public discovery, never eligible tenant membership.
  $public=$discovery|ConvertTo-Json -Depth 100|ConvertFrom-Json -AsHashtable
  $options=@{};if($AppId){$options.AppId=@($AppId|ForEach-Object ToString)}
  if($Mode -eq 'Deep'){
   $options.ChunkSize=if($ValidationOnly){2}else{25}
   $options.ResourceId=@('00000003-0000-0000-c000-000000000000','797f4846-ba00-4fd7-ba43-dac1f8f63013')
   if($AppId -and $AppId.Count -gt $DeepMaxApplications){throw 'Deep selection exceeds its independent weekly budget.'}
   if(-not $AppId){
    $prior=@{};if($state){foreach($app in $state.Recipe.Discovery.Applications){$prior[$app.AppId]=Get-TfCiHash $app}}
    $candidates=@($public.Applications|Where-Object {$_.RedirectUris.Count -gt 0}|Sort-Object AppId)
    $changed=@($candidates|Where-Object {-not $prior.ContainsKey($_.AppId) -or $prior[$_.AppId] -cne (Get-TfCiHash $_)}|ForEach-Object AppId)
    # Shallow successes do not establish coverage of other flows. Select
    # changed hints first, then never-selected and oldest selected candidates.
    $rotated=@($candidates|Sort-Object @{Expression={if($history.ContainsKey($_.AppId)){$history[$_.AppId]}else{''}}},AppId|ForEach-Object AppId)
    $selection=[Collections.Generic.List[string]]::new();foreach($id in @($changed)+@($rotated)){if(-not $selection.Contains($id)){$selection.Add($id)};if($selection.Count -ge $DeepMaxApplications){break}}
    $options.AppId=@($selection)
   }
  }
  if($Mode -eq 'Deep' -and (-not $options.AppId.Count -or $options.AppId.Count -gt $DeepMaxApplications)){throw 'No bounded deep selection is available; inspect public callback hints.'}
  $state=New-TfCiState $public -Mode $Mode @options
 }elseif($AppId){throw 'An existing weekly recipe cannot change membership.'}
 if($Mode -eq 'Deep'){
  $published=@($state.Recipe.Discovery.Applications|ForEach-Object AppId)
  foreach($id in @($history.Keys)){if($id -cnotin $published){$history.Remove($id)}}
  foreach($id in $state.Recipe.AppIds){$history[$id]=$state.Recipe.Week}
  $state.DeepSelectionHistory=$history
  Assert-TfCiState $state
 }
 $selection=@(Get-TfCiWork $state -Workers $(if($Mode -eq 'Deep'){[Math]::Min(2,$Workers)}else{$Workers}) -MaxAttempts $(if($RetryExhausted){10}else{3}))
 Save-CiJson $state $statePath
 Save-CiJson $state (Join-Path $BundlePath state.json)
 $base=git -C $DataPath rev-parse HEAD 2>$null;if($LASTEXITCODE -ne 0){throw 'Weekly CI requires an initialized data branch.'}
 $request=[ordered]@{SchemaVersion=1;PlanId=$state.PlanId;Mode=$Mode;Indices=$selection;BaseCommit=[string]$base}
 if($ValidationOnly){$request.SchemaVersion=2;$request.ValidationOnly=$true}
 Save-CiJson $request (Join-Path $BundlePath request.json)
 $report=Get-TfCiReport $state
 Save-CiJson $report (Join-Path $DataPath ('coverage-'+$Mode.ToLowerInvariant()+'.json'))
 $matrix=@{include=@($selection|ForEach-Object {@{index=$_;plan=$state.PlanId}})}|ConvertTo-Json -Compress
 if($env:GITHUB_OUTPUT){Add-Content $env:GITHUB_OUTPUT "matrix=$matrix";Add-Content $env:GITHUB_OUTPUT "mode=$Mode";Add-Content $env:GITHUB_OUTPUT "has_work=$([bool]$selection.Count)"}
 $report
}else{
 $null=Get-TokenForgeApplicationMetadata (Join-Path $DataPath applications.json) -PublicOnly
 $state=Get-Content (Join-Path $BundlePath state.json) -Raw|ConvertFrom-Json -AsHashtable;Assert-TfCiState $state
 $current=Get-Content $statePath -Raw|ConvertFrom-Json -AsHashtable;Assert-TfCiState $current
 if((Get-TfCiHash $state) -cne (Get-TfCiHash $current)){throw 'Publisher state changed after planning.'}
 $request=Get-Content (Join-Path $BundlePath request.json) -Raw|ConvertFrom-Json -AsHashtable
 $requestFields=@('SchemaVersion','PlanId','Mode','Indices','BaseCommit');if($ValidationOnly){$requestFields+='ValidationOnly'}
 Assert-TfCiKeys $request $requestFields
 if($ValidationOnly){
  if($request.SchemaVersion -ne 2 -or $request.ValidationOnly -isnot [bool] -or -not $request.ValidationOnly -or $state.SchemaVersion -ne 2 -or $state.Recipe.Mode -cne 'Deep' -or $state.Recipe.AppIds.Count -gt 4 -or $state.Recipe.ChunkSize -ne 2 -or @(Get-TfCiResources $state).Count -ne 2){throw 'Invalid isolated validation recipe.'}
 }

 if($request.BaseCommit -notmatch '^[a-f0-9]{40}$'){throw 'Invalid data parent.'}
 if($request.SchemaVersion -ne $(if($ValidationOnly){2}else{1}) -or $request.PlanId -cne $state.PlanId -or $request.Mode -cne $Mode -or @($request.Indices|Sort-Object -Unique).Count -ne $request.Indices.Count -or $request.Indices.Count -gt 4){throw 'Invalid publication request.'}
 $allowed=@('receipt.json','scopes.json')
 $null=New-Item -ItemType Directory (Join-Path $DataPath scopes) -Force
 foreach($index in $request.Indices){
  $members=@(Get-TfCiMembers $state $index)
  $result=Join-Path $BundlePath ('result-'+$index)
  if(Test-Path $result){foreach($file in Get-ChildItem $result -Force -Recurse){if($file.PSIsContainer -or $file.Name -notin $allowed -or ($file.Attributes -band [IO.FileAttributes]::ReparsePoint)){throw 'Unexpected worker output.'}}}
  $receiptPath=Join-Path $result receipt.json
  $receipt=if(Test-Path $receiptPath){Get-Content $receiptPath -Raw|ConvertFrom-Json -AsHashtable}else{[ordered]@{SchemaVersion=1;PlanId=$state.PlanId;Index=$index;Attempt=$state.Batches[$index].Attempts+1;Status='Failed';Assessed=0;Successful=0;DurationSeconds=0;ObservedAt=[DateTimeOffset]::UtcNow.ToString('o')}}
  if($state.SchemaVersion -eq 2 -and -not(Test-Path $receiptPath)){$receipt.SchemaVersion=2;$receipt.AssessedPairs=0;$receipt.SuccessfulPairs=0}
  if($receipt.Index -ne $index){throw 'Wrong worker partition.'}
  # Validate receipt before consuming any anonymous evidence.
  Merge-TfCiReceipt $state $receipt
  if($receipt.Status -eq 'Complete'){
   $source=Join-Path $result scopes.json
   if(-not(Test-Path $source)){throw 'Complete worker omitted its scope export.'}
   $export=Get-Content $source -Raw|ConvertFrom-Json -AsHashtable
   Assert-TfCiScopeExport $export
   if($export.SchemaVersion -ne 1 -or $export.Disclaimer -cne 'Observed scopes are session/tenant dependent, not universal consent or guaranteed API access.' -or $export.Observations -isnot [array]){throw 'Invalid anonymous worker export.'}
   $resources=@(Get-TfCiResources $state);$seenPairs=@{}
   foreach($row in $export.Observations){
    Assert-TfCiKeys $row @('ClientId','ResourceId','ObservedAt','Scopes','Evidence','SignatureValidated')
    if($row.ClientId -notin $members -or $row.ResourceId -cnotin $resources -or $row.Evidence -cne 'AnonymousTenantTokenObservation' -or $row.SignatureValidated -isnot [bool] -or $row.SignatureValidated -or $row.Scopes -isnot [array] -or @($row.Scopes|Where-Object {$_ -isnot [string] -or $_ -notmatch '^[A-Za-z0-9_.-]{1,256}$'}).Count){throw 'Private or foreign anonymous observation.'}
    $pair=$row.ClientId+'/'+$row.ResourceId;if($seenPairs.ContainsKey($pair)){throw 'Duplicate anonymous worker pair.'};$seenPairs[$pair]=$true
    $observed=[DateTimeOffset]::Parse([string]$row.ObservedAt)
    if($observed -lt [DateTimeOffset]::Parse($state.Recipe.CreatedAt) -or $observed -gt [DateTimeOffset]::UtcNow.AddMinutes(5)){throw 'Stale or future worker observation.'}
   }
   if(@($export.Observations|ForEach-Object ClientId|Sort-Object -Unique).Count -ne $receipt.Successful){throw 'Success receipt does not match export.'}
   if($state.SchemaVersion -eq 2 -and $export.Observations.Count -ne $receipt.SuccessfulPairs){throw 'Pair success receipt does not match export.'}
   $destination=Join-Path $DataPath ('scopes/chunk-{0:D4}.json' -f $index)
   # Preserve prior successful evidence, including IDs that moved between weekly chunks.
   $prior=if(Test-Path $destination){Get-Content $destination -Raw|ConvertFrom-Json -AsHashtable}else{@{Observations=@()}}
   if(Test-Path $destination){Assert-TfCiScopeExport $prior}
   $latest=@{};foreach($row in @(@($prior.Observations)+@($export.Observations)|Sort-Object {([DateTimeOffset]$_.ObservedAt)})){$latest[$row.ClientId+'/'+$row.ResourceId]=$row}
   $export.Observations=@($latest.Values|Sort-Object ClientId,ResourceId)
   Save-CiJson $export $destination
  }
 }
 Save-CiJson $state $statePath
 $report=Get-TfCiReport $state;Save-CiJson $report (Join-Path $DataPath ('coverage-'+$Mode.ToLowerInvariant()+'.json'))
 if($env:GITHUB_STEP_SUMMARY){
  Add-Content $env:GITHUB_STEP_SUMMARY ('### Weekly '+$Mode+' coverage')
  Add-Content $env:GITHUB_STEP_SUMMARY "Source catalog: $($report.SourceCatalogApplications) IDs; selected: $($report.SelectedApplications); assessed: $($report.AssessedApplications); successful token observations: $($report.SuccessfulApplications). Selected-set completion: $($report.Complete). Pending batches: $($report.PendingBatches); exhausted: $($report.ExhaustedBatches)."
  Add-Content $env:GITHUB_STEP_SUMMARY "Resource pairs: assessed $($report.AssessedPairs)/$($report.SelectedPairs); successful $($report.SuccessfulPairs), across $($report.ResourceIds.Count) resources. Successful apps count once even if multiple resources succeed."
  if($null -ne $report.DeepSelectionHistoryApplications){
   Add-Content $env:GITHUB_STEP_SUMMARY "Deep history: $($report.DeepSelectionHistoryApplications) public IDs selected; $($report.NeverDeepSelectedCallbackCandidates) callback candidates never selected. Selection history does not establish completed flow testing."
  }
 }
 $report
}
