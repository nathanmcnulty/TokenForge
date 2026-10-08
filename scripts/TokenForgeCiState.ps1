# Shared, credential-free weekly state and authenticated-encryption operations.
Set-StrictMode -Version Latest
function Get-TfCiHash($Value) {
 $json=ConvertTo-Json -InputObject $Value -Depth 100 -Compress
 # Date parsing uses the host time zone. Convert parsed dates to UTC offsets
 # before hashing so the frozen recipe verifies on every platform/time zone.
 # DateTimeOffset emits the same +00:00 representation as existing UTC CI hashes.
 $parsed=$json|ConvertFrom-Json -AsHashtable -NoEnumerate
 $normalize={param($value)
  if($value -is [Collections.IDictionary]){foreach($key in @($value.Keys)){if($value[$key] -is [datetime]){$value[$key]=[DateTimeOffset]$value[$key].ToUniversalTime()}else{& $normalize $value[$key]}}}
  elseif($value -is [array]){for($i=0;$i -lt $value.Count;$i++){if($value[$i] -is [datetime]){$value[$i]=[DateTimeOffset]$value[$i].ToUniversalTime()}else{& $normalize $value[$i]}}}
 }; if($parsed -is [datetime]){$parsed=[DateTimeOffset]$parsed.ToUniversalTime()}else{& $normalize $parsed}
 $json=ConvertTo-Json -InputObject $parsed -Depth 100 -Compress
 [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData([Text.Encoding]::UTF8.GetBytes($json))).ToLowerInvariant()
}
function Assert-TfCiKeys($Value,[string[]]$Keys) {
 if($Value -isnot [Collections.IDictionary] -or @($Value.Keys|Where-Object {$_ -cnotin $Keys}).Count -or @($Keys|Where-Object {-not $Value.Contains($_)}).Count){throw 'Invalid CI document fields.'}
}
function Get-TfCiWeek([DateTimeOffset]$Now=[DateTimeOffset]::UtcNow) {
 $date=$Now.UtcDateTime
 '{0}-W{1:D2}' -f [Globalization.ISOWeek]::GetYear($date),[Globalization.ISOWeek]::GetWeekOfYear($date)
}
function Assert-TfCiDiscovery($Discovery) {
 Assert-TfCiKeys $Discovery @('SchemaVersion','FetchedAt','Sources','CatalogContentSha256','InvalidSourceRecordCount','SourceSnapshots','Applications')
 if($Discovery.SchemaVersion -ne 1 -or $Discovery.CatalogContentSha256 -notmatch '^[a-f0-9]{64}$' -or $Discovery.Applications -isnot [array] -or $Discovery.Applications.Count -gt 100000){throw 'Invalid public discovery.'}
 foreach($snapshot in $Discovery.SourceSnapshots){Assert-TfCiKeys $snapshot @('Location','Sha256','HashKind')}
 if($Discovery.Sources -isnot [array] -or @($Discovery.Sources|Where-Object {$_ -isnot [string] -or $_.Length -gt 2048}).Count -or $Discovery.SourceSnapshots -isnot [array]){throw 'Invalid public source types.'}
 $seen=@{}
 foreach($app in $Discovery.Applications){
  Assert-TfCiKeys $app @('AppId','Name','OwnerTenantId','Ownership','Sources','PublicClient','Foci','RedirectUris','PreferredRedirectUri','Grants','IsResourceCandidate','IdentifierUris')
  $id=[guid]::Empty
  if(-not [guid]::TryParse($app.AppId,[ref]$id) -or $id -eq [guid]::Empty -or $seen.ContainsKey($id.ToString())){throw 'Invalid discovery app ID.'};$seen[$id.ToString()]=$true
  if($app.Name -isnot [string] -or $app.Name.Length -gt 2048 -or $app.Ownership -cnotin @('Unverified','PublishedMicrosoftOwner') -or ($null -ne $app.OwnerTenantId -and -not [guid]::TryParse([string]$app.OwnerTenantId,[ref]$id)) -or ($null -ne $app.PublicClient -and $app.PublicClient -isnot [bool]) -or ($null -ne $app.Foci -and $app.Foci -isnot [bool]) -or $app.IsResourceCandidate -isnot [bool] -or $app.PreferredRedirectUri -isnot [string]){throw 'Invalid public application types.'}
  foreach($field in @('RedirectUris','IdentifierUris')){if($app[$field] -isnot [array] -or @($app[$field]|Where-Object {$_ -isnot [string] -or $_.Length -gt 2048}).Count){throw 'Invalid public URI hints.'}}
  if($app.Sources -isnot [array] -or $app.Grants -isnot [array]){throw 'Invalid public application lists.'}
  foreach($source in $app.Sources){Assert-TfCiKeys $source @('Name','Location','Evidence');foreach($field in @('Name','Location','Evidence')){if($source[$field] -isnot [string] -or $source[$field].Length -gt 2048){throw 'Invalid public provenance.'}}}
  foreach($grant in $app.Grants){Assert-TfCiKeys $grant @('ResourceId','Scopes');$resource=[guid]::Empty;if(-not [guid]::TryParse($grant.ResourceId,[ref]$resource) -or $grant.Scopes -isnot [array] -or @($grant.Scopes|Where-Object {$_ -isnot [string] -or $_ -notmatch '^[A-Za-z0-9_.-]{1,256}$'}).Count){throw 'Invalid public scope hints.'}}
 }
}
function New-TfCiState($Discovery,[int]$ChunkSize=100,[string]$Mode='Shallow',[DateTimeOffset]$Now=[DateTimeOffset]::UtcNow,[string[]]$AppId=@(),[ValidateSet('00000003-0000-0000-c000-000000000000','797f4846-ba00-4fd7-ba43-dac1f8f63013')][string[]]$ResourceId=@()) {
 Assert-TfCiDiscovery $Discovery
 if($ChunkSize -lt 1 -or $ChunkSize -gt 200 -or $Mode -notin @('Shallow','Deep')){throw 'Invalid CI recipe bounds.'}
 $ids=@($Discovery.Applications|ForEach-Object AppId|Sort-Object -Unique)
 if($AppId.Count -and $Mode -ne 'Deep'){throw 'Shallow cohorts require all published IDs.'}
 if($AppId.Count){if(@($AppId|Where-Object {$_ -notin $ids}).Count){throw 'CI selection contains unpublished IDs.'};$ids=@($AppId|Sort-Object -Unique)}
 if(-not $ids.Count){throw 'Empty discovery cannot define a weekly cohort.'}
 $version=if($ResourceId.Count){2}else{1}
 if($version -eq 2 -and $Mode -ne 'Deep'){throw 'Explicit CI resources are available only for deep recipes.'}
 $recipe=[ordered]@{SchemaVersion=$version;Week=Get-TfCiWeek $Now;CreatedAt=$Now.ToUniversalTime().ToString('o');Mode=$Mode;ChunkSize=$ChunkSize;MaxRedirects=$(if($Mode -eq 'Deep'){4}else{2});AppIds=$ids;Discovery=$Discovery}
 if($version -eq 2){$recipe.ResourceIds=@($ResourceId|ForEach-Object ToLowerInvariant|Sort-Object -Unique)}
 $batches=@(for($index=0;$index -lt [Math]::Ceiling($ids.Count/$ChunkSize);$index++){
  $batch=[ordered]@{Index=$index;Status='Pending';Attempts=0;Assessed=0;Successful=0;DurationSeconds=0;ObservedAt=$null}
  if($version -eq 2){$batch.AssessedPairs=0;$batch.SuccessfulPairs=0}
  $batch
 })
 [ordered]@{SchemaVersion=$version;PlanId=Get-TfCiHash $recipe;Recipe=$recipe;Batches=$batches}
}
# One compatibility boundary shared by planning, workers, publication and reports.
function Get-TfCiResources($State) {
 if($State.SchemaVersion -eq 2){@($State.Recipe.ResourceIds)}else{'00000003-0000-0000-c000-000000000000'}
}
function Assert-TfCiState($State) {
 $fields=@('SchemaVersion','PlanId','Recipe','Batches');if($State -is [Collections.IDictionary] -and $State.Contains('DeepSelectionHistory')){$fields+='DeepSelectionHistory'}
 Assert-TfCiKeys $State $fields
 $recipeFields=@('SchemaVersion','Week','CreatedAt','Mode','ChunkSize','MaxRedirects','AppIds','Discovery');if($State.SchemaVersion -eq 2){$recipeFields+='ResourceIds'}
 Assert-TfCiKeys $State.Recipe $recipeFields
 $recipe=$State.Recipe;Assert-TfCiDiscovery $recipe.Discovery
 if($State.SchemaVersion -notin @(1,2) -or $recipe.SchemaVersion -ne $State.SchemaVersion -or $State.PlanId -cne (Get-TfCiHash $recipe) -or $recipe.Week -notmatch '^\d{4}-W\d{2}$' -or $recipe.Mode -notin @('Shallow','Deep') -or $recipe.ChunkSize -lt 1 -or $recipe.ChunkSize -gt 200 -or $recipe.MaxRedirects -ne $(if($recipe.Mode -eq 'Deep'){4}else{2})){throw 'Invalid frozen CI recipe.'}
 $resources=@(Get-TfCiResources $State)
 if($State.SchemaVersion -eq 2 -and ($recipe.Mode -cne 'Deep' -or $recipe.ResourceIds -isnot [array] -or $resources.Count -lt 1 -or $resources.Count -gt 2 -or @($resources|Where-Object {$_ -isnot [string] -or $_ -cnotin @('00000003-0000-0000-c000-000000000000','797f4846-ba00-4fd7-ba43-dac1f8f63013')}).Count -or ($resources -join '/') -cne (@($resources|Sort-Object -Unique) -join '/'))){throw 'Invalid frozen resource membership.'}
 $published=@($recipe.Discovery.Applications|ForEach-Object AppId)
 # Match PowerShell's case-insensitive GUID membership without rescanning the catalog per ID.
 $publishedIds=[Collections.Generic.HashSet[string]]::new([string[]]$published,[StringComparer]::OrdinalIgnoreCase)
 if($recipe.AppIds -isnot [array] -or -not $recipe.AppIds.Count -or @($recipe.AppIds|Sort-Object -Unique).Count -ne $recipe.AppIds.Count -or @($recipe.AppIds|Where-Object {-not $publishedIds.Contains([string]$_)}).Count -or ($recipe.AppIds -join '/') -cne (@($recipe.AppIds|Sort-Object) -join '/')){throw 'Invalid frozen membership.'}
 if($recipe.Mode -eq 'Shallow' -and $recipe.AppIds.Count -ne $published.Count){throw 'Incomplete public shallow membership.'}
 if($State.Contains('DeepSelectionHistory')){
  $history=$State.DeepSelectionHistory
  if($recipe.Mode -ne 'Deep' -or $history -isnot [Collections.IDictionary] -or $history.Count -gt $published.Count){throw 'Invalid deep selection history.'}
  foreach($id in $history.Keys){
   $week=$history[$id]
   if($id -cnotin $published -or $week -isnot [string] -or $week -notmatch '^([0-9]{4})-W([0-9]{2})$'){throw 'Invalid public deep selection history.'}
   $year=[int]$Matches[1];$number=[int]$Matches[2]
   if($year -lt 1 -or $number -lt 1 -or $number -gt [Globalization.ISOWeek]::GetWeeksInYear($year) -or $week -cgt $recipe.Week){throw 'Invalid deep selection week.'}
  }
  foreach($id in $recipe.AppIds){if(-not $history.Contains($id) -or $history[$id] -cne $recipe.Week){throw 'Missing current deep selection history.'}}
 }
 if($State.Batches -isnot [array] -or $State.Batches.Count -ne [Math]::Ceiling($recipe.AppIds.Count/$recipe.ChunkSize)){throw 'Invalid batch count.'}
 $index=0
 foreach($batch in $State.Batches){
  $batchFields=@('Index','Status','Attempts','Assessed','Successful','DurationSeconds','ObservedAt');if($State.SchemaVersion -eq 2){$batchFields+=@('AssessedPairs','SuccessfulPairs')}
  Assert-TfCiKeys $batch $batchFields
  $count=@(Get-TfCiMembers $State $index).Count
  if($State.SchemaVersion -eq 2){
   foreach($field in @('Assessed','Successful','AssessedPairs','SuccessfulPairs')){if($batch[$field] -isnot [int] -and $batch[$field] -isnot [long]){throw 'Invalid resource checkpoint counts.'}}
   if($batch.AssessedPairs -ne $batch.Assessed*$resources.Count -or $batch.SuccessfulPairs -lt $batch.Successful -or $batch.SuccessfulPairs -gt $batch.Successful*$resources.Count -or $batch.SuccessfulPairs -gt $batch.AssessedPairs){throw 'Invalid resource checkpoint coverage.'}
  }
  if($batch.Index -ne $index -or $batch.Status -notin @('Pending','Failed','Complete') -or $batch.Attempts -lt 0 -or $batch.Assessed -lt 0 -or $batch.Assessed -gt $count -or $batch.Successful -lt 0 -or $batch.Successful -gt $batch.Assessed -or $batch.DurationSeconds -lt 0 -or ($batch.Status -eq 'Complete' -and $batch.Assessed -ne $count)){throw 'Invalid CI checkpoint.'};$index++
 }
}
function Get-TfCiMembers($State,[int]$Index) {
 if($Index -lt 0 -or $Index -ge $State.Batches.Count){throw 'Invalid chunk index.'}
 @($State.Recipe.AppIds|Select-Object -Skip ($Index*$State.Recipe.ChunkSize) -First $State.Recipe.ChunkSize)
}
function Get-TfCiWork($State,[int]$Workers=4,[int]$MaxAttempts=3) {
 Assert-TfCiState $State
 if($Workers -lt 1 -or $Workers -gt 4 -or $MaxAttempts -lt 1 -or $MaxAttempts -gt 10){throw 'Invalid worker bounds.'}
 @($State.Batches|Where-Object {$_.Status -ne 'Complete' -and $_.Attempts -lt $MaxAttempts}|Sort-Object {[int]$_.Attempts},{[int]$_.Index}|Select-Object -First $Workers|ForEach-Object Index)
}
function Merge-TfCiReceipt($State,$Receipt) {
 Assert-TfCiState $State
 $fields=@('SchemaVersion','PlanId','Index','Attempt','Status','Assessed','Successful','DurationSeconds','ObservedAt');if($State.SchemaVersion -eq 2){$fields+=@('AssessedPairs','SuccessfulPairs')}
 Assert-TfCiKeys $Receipt $fields
 $index=$Receipt.Index;$ids=@(Get-TfCiMembers $State $index)
 $batch=$State.Batches[$index]
 if($Receipt.SchemaVersion -ne $State.SchemaVersion -or $Receipt.PlanId -cne $State.PlanId -or $Receipt.Attempt -ne ($batch.Attempts+1) -or $Receipt.Status -notin @('Failed','Complete') -or $Receipt.Assessed -lt 0 -or $Receipt.Assessed -gt $ids.Count -or $Receipt.Successful -lt 0 -or $Receipt.Successful -gt $Receipt.Assessed -or $Receipt.DurationSeconds -lt 0 -or $Receipt.DurationSeconds -gt 3600 -or ($Receipt.Status -eq 'Complete' -and $Receipt.Assessed -ne $ids.Count) -or $batch.Status -eq 'Complete'){throw 'Mismatched or invalid batch receipt.'}
 if($State.SchemaVersion -eq 2){
  $resources=@(Get-TfCiResources $State)
  foreach($field in @('Assessed','Successful','AssessedPairs','SuccessfulPairs')){if($Receipt[$field] -isnot [int] -and $Receipt[$field] -isnot [long]){throw 'Invalid resource receipt counts.'}}
  if($Receipt.AssessedPairs -ne $Receipt.Assessed*$resources.Count -or $Receipt.SuccessfulPairs -lt $Receipt.Successful -or $Receipt.SuccessfulPairs -gt $Receipt.Successful*$resources.Count -or $Receipt.SuccessfulPairs -gt $Receipt.AssessedPairs){throw 'Invalid resource receipt coverage.'}
 }
 $date=[DateTimeOffset]::Parse($Receipt.ObservedAt)
 if($date -lt [DateTimeOffset]::Parse($State.Recipe.CreatedAt) -or $date -gt [DateTimeOffset]::UtcNow.AddMinutes(5)){throw 'Invalid receipt observation date.'}
 $State.Batches[$index]=[ordered]@{Index=$index;Status=$Receipt.Status;Attempts=$Receipt.Attempt;Assessed=$Receipt.Assessed;Successful=$Receipt.Successful;DurationSeconds=$Receipt.DurationSeconds;ObservedAt=$date.ToUniversalTime().ToString('o')}
 if($State.SchemaVersion -eq 2){$State.Batches[$index].AssessedPairs=$Receipt.AssessedPairs;$State.Batches[$index].SuccessfulPairs=$Receipt.SuccessfulPairs}
}
function Get-TfCiReport($State,[DateTimeOffset]$Now=[DateTimeOffset]::UtcNow) {
 Assert-TfCiState $State
 $complete=@($State.Batches|Where-Object Status -eq Complete);$durations=@($complete|ForEach-Object DurationSeconds|Sort-Object)
 $pending=@($State.Batches|Where-Object Status -ne Complete)
 $assessed=0;$success=0;$assessedPairs=0;$successfulPairs=0
 foreach($batch in $complete){$assessed+=$batch.Assessed;$success+=$batch.Successful;if($State.SchemaVersion -eq 2){$assessedPairs+=$batch.AssessedPairs;$successfulPairs+=$batch.SuccessfulPairs}else{$assessedPairs+=$batch.Assessed;$successfulPairs+=$batch.Successful}}
 $resources=@(Get-TfCiResources $State)
 $oldest=if($complete.Count){@($complete|Sort-Object {([DateTimeOffset]$_.ObservedAt)})[0].ObservedAt}else{$null}
 $latest=if($complete.Count){@($complete|Sort-Object {([DateTimeOffset]$_.ObservedAt)})[-1].ObservedAt}else{$null}
 $median=if($durations.Count){$durations[[int][Math]::Floor(($durations.Count-1)/2)]}else{$null}
 $p95=if($durations.Count){$durations[[int][Math]::Ceiling($durations.Count*.95)-1]}else{$null}
 $callbacks=@($State.Recipe.Discovery.Applications|Where-Object {$_.RedirectUris.Count -gt 0})
 $hasHistory=$State.Recipe.Mode -eq 'Deep' -and $State.Contains('DeepSelectionHistory')
 $historyCount=if($hasHistory){$State.DeepSelectionHistory.Count}else{$null}
 $neverSelected=if($hasHistory){@($callbacks|Where-Object {-not $State.DeepSelectionHistory.Contains($_.AppId)}).Count}else{$null}
 [ordered]@{
  SchemaVersion=3
  ResourceIds=$resources
  SelectedPairs=$State.Recipe.AppIds.Count*$resources.Count
  AssessedPairs=$assessedPairs
  SuccessfulPairs=$successfulPairs
  SourceCatalogApplications=$State.Recipe.Discovery.Applications.Count
  SelectedApplications=$State.Recipe.AppIds.Count
  PublishedCallbackCandidates=$callbacks.Count
  DeepSelectionHistoryApplications=$historyCount
  NeverDeepSelectedCallbackCandidates=$neverSelected
  Week=$State.Recipe.Week
  Mode=$State.Recipe.Mode
  GeneratedAt=$Now.ToUniversalTime().ToString('o')
  PublishedApplications=$State.Recipe.AppIds.Count
  AssessedApplications=$assessed
  SuccessfulApplications=$success
  TotalBatches=$State.Batches.Count
  CompletedBatches=$complete.Count
  PendingBatches=$pending.Count
  ExhaustedBatches=@($pending|Where-Object Attempts -ge 3).Count
  Complete=($pending.Count -eq 0)
  OldestCompletedAssessmentAt=$oldest
  LatestCompletedAssessmentAt=$latest
  OldestPendingHours=$(if($pending.Count){[Math]::Round(($Now-[DateTimeOffset]::Parse($State.Recipe.CreatedAt)).TotalHours,2)}else{0})
  MedianBatchSeconds=$median
  P95BatchSeconds=$p95
  EstimatedRemainingRunnerSeconds=$(if($null -ne $median){$median*$pending.Count}else{$null})
  Evidence='AssessedForOneAccountNotUniversalSupport'
  SuccessfulScopeFreshness='InspectAnonymousObservationDates'
 }
}
function Protect-TfCiCheckpoint([byte[]]$Plaintext,[string]$Key,[string]$Context) {
 if($Plaintext.Length -eq 0 -or $Plaintext.Length -gt 134217728){throw 'Checkpoint exceeds bound.'}
 $keyBytes=[Convert]::FromBase64String($Key);if($keyBytes.Length -ne 32){throw 'A 256-bit checkpoint key is required.'}
 $nonce=[Security.Cryptography.RandomNumberGenerator]::GetBytes(12);$tag=[byte[]]::new(16);$cipher=[byte[]]::new($Plaintext.Length)
 $aes=[Security.Cryptography.AesGcm]::new($keyBytes,16)
 try{$aes.Encrypt($nonce,$Plaintext,$cipher,$tag,[Text.Encoding]::UTF8.GetBytes($Context));return ,([byte[]](@(1)+$nonce+$tag+$cipher))}
 finally{$aes.Dispose();[Security.Cryptography.CryptographicOperations]::ZeroMemory($keyBytes)}
}
function Unprotect-TfCiCheckpoint([byte[]]$Blob,[string]$Key,[string]$Context) {
 if($Blob.Length -le 29 -or $Blob.Length -gt 134217757 -or $Blob[0] -ne 1){throw 'Invalid encrypted checkpoint.'}
 $keyBytes=[Convert]::FromBase64String($Key);if($keyBytes.Length -ne 32){throw 'A 256-bit checkpoint key is required.'}
 $plain=[byte[]]::new($Blob.Length-29);$aes=[Security.Cryptography.AesGcm]::new($keyBytes,16)
 try{$aes.Decrypt([byte[]]$Blob[1..12],[byte[]]$Blob[29..($Blob.Length-1)],[byte[]]$Blob[13..28],$plain,[Text.Encoding]::UTF8.GetBytes($Context));return ,$plain}
 catch{[Security.Cryptography.CryptographicOperations]::ZeroMemory($plain);throw 'Checkpoint authentication failed.'}
 finally{$aes.Dispose();[Security.Cryptography.CryptographicOperations]::ZeroMemory($keyBytes)}
}

function Assert-TfCiScopeExport($Document) {
 Assert-TfCiKeys $Document @('SchemaVersion','Observations','Disclaimer')
 if($Document.SchemaVersion -ne 1 -or $Document.Observations -isnot [array] -or $Document.Disclaimer -cne 'Observed scopes are session/tenant dependent, not universal consent or guaranteed API access.'){throw 'Invalid anonymous scope schema.'}
 foreach($row in $Document.Observations){
  Assert-TfCiKeys $row @('ClientId','ResourceId','ObservedAt','Scopes','Evidence','SignatureValidated')
  $id=[guid]::Empty
  if($row.ClientId -isnot [string] -or -not [guid]::TryParse($row.ClientId,[ref]$id) -or $id -eq [guid]::Empty -or $row.ResourceId -isnot [string] -or -not [guid]::TryParse($row.ResourceId,[ref]$id) -or $id -eq [guid]::Empty -or $row.Scopes -isnot [array] -or @($row.Scopes|Where-Object {$_ -isnot [string] -or $_ -notmatch '^[A-Za-z0-9_.-]{1,256}$'}).Count -or $row.Evidence -cne 'AnonymousTenantTokenObservation' -or $row.SignatureValidated -isnot [bool] -or $row.SignatureValidated){throw 'Invalid public observation.'}
  if($row.ObservedAt -isnot [string] -and $row.ObservedAt -isnot [datetime]){throw 'Invalid public date.'}
  $null=[DateTimeOffset]::Parse([string]$row.ObservedAt)
 }
}
function Get-TfCiPublicStagePaths([string]$Path){
 # Artifact transport omits empty directories. Select existing allowlisted files
 # after Assert-TfCiPublicData rather than passing optional directories to git.
 foreach($file in Get-ChildItem -LiteralPath $Path -File){
  if($file.Name -cin @('applications.json','weekly-shallow.json','weekly-deep.json','coverage-shallow.json','coverage-deep.json')){$file.Name}
 }
 foreach($folder in @('reports','scopes')){
  $directory=Join-Path $Path $folder
  if(Test-Path -LiteralPath $directory -PathType Container){
   foreach($file in Get-ChildItem -LiteralPath $directory -File){$folder+'/'+$file.Name}
  }
 }
}
function Assert-TfCiPublicData([string]$Path){
 foreach($file in Get-ChildItem $Path -Recurse -Force|Where-Object {$_.FullName -notmatch '[/\\]\.git([/\\]|$)'}){if($file.Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'Linked public data is not allowed.'}}
 foreach($file in @(Get-ChildItem $Path -File -Filter 'coverage-*.json')){if($file.Name -cnotin @('coverage-shallow.json','coverage-deep.json')){throw 'Unexpected coverage path.'};Assert-TfCiReport (Get-Content $file.FullName -Raw|ConvertFrom-Json -AsHashtable)}
 if(Test-Path (Join-Path $Path reports)){foreach($file in Get-ChildItem (Join-Path $Path reports) -Force -Recurse){if($file.PSIsContainer -or $file.Name -notmatch '^\d{4}-W\d{2}-(shallow|deep)\.json$'){throw 'Unexpected history path.'};Assert-TfCiReport (Get-Content $file.FullName -Raw|ConvertFrom-Json -AsHashtable)}}
 if(Test-Path (Join-Path $Path scopes)){
  foreach($file in Get-ChildItem (Join-Path $Path scopes) -Recurse -Force){if($file.PSIsContainer -or ($file.Attributes -band [IO.FileAttributes]::ReparsePoint) -or $file.Name -notmatch '^chunk-[0-9]{4,6}\.json$'){throw 'Unexpected public scope file.'};Assert-TfCiScopeExport (Get-Content $file.FullName -Raw|ConvertFrom-Json -AsHashtable)}
 }
 foreach($file in @(Get-ChildItem $Path -File -Filter 'weekly-*.json')){Assert-TfCiState (Get-Content $file.FullName -Raw|ConvertFrom-Json -AsHashtable)}
}
function Assert-TfCiReport($Report){
 $fields=@('SchemaVersion','Week','Mode','GeneratedAt','PublishedApplications','AssessedApplications','SuccessfulApplications','TotalBatches','CompletedBatches','PendingBatches','ExhaustedBatches','Complete','OldestCompletedAssessmentAt','LatestCompletedAssessmentAt','OldestPendingHours','MedianBatchSeconds','P95BatchSeconds','EstimatedRemainingRunnerSeconds','Evidence','SuccessfulScopeFreshness')
 if($Report -is [Collections.IDictionary] -and $Report.SchemaVersion -in @(2,3)){$fields+=@('SourceCatalogApplications','SelectedApplications','PublishedCallbackCandidates','DeepSelectionHistoryApplications','NeverDeepSelectedCallbackCandidates')}
 if($Report -is [Collections.IDictionary] -and $Report.SchemaVersion -eq 3){$fields+=@('ResourceIds','SelectedPairs','AssessedPairs','SuccessfulPairs')}
 Assert-TfCiKeys $Report $fields
 if($Report.SchemaVersion -notin @(1,2,3) -or $Report.Week -notmatch '^\d{4}-W\d{2}$' -or $Report.Mode -notin @('Shallow','Deep') -or $Report.GeneratedAt -isnot [string] -and $Report.GeneratedAt -isnot [datetime] -or $Report.Complete -isnot [bool] -or $Report.Evidence -cne 'AssessedForOneAccountNotUniversalSupport' -or $Report.SuccessfulScopeFreshness -cne 'InspectAnonymousObservationDates'){throw 'Invalid public coverage report.'}
 $null=[DateTimeOffset]::Parse([string]$Report.GeneratedAt)
 foreach($field in @('OldestCompletedAssessmentAt','LatestCompletedAssessmentAt')){if($null -ne $Report[$field]){if($Report[$field] -isnot [string] -and $Report[$field] -isnot [datetime]){throw 'Invalid assessment date.'};$null=[DateTimeOffset]::Parse([string]$Report[$field])}}
 foreach($field in @('OldestPendingHours','PublishedApplications','AssessedApplications','SuccessfulApplications','TotalBatches','CompletedBatches','PendingBatches','ExhaustedBatches','MedianBatchSeconds','P95BatchSeconds','EstimatedRemainingRunnerSeconds')){
  $value=$Report[$field]
  if($null -eq $value -and $field -in @('MedianBatchSeconds','P95BatchSeconds','EstimatedRemainingRunnerSeconds')){continue}
  if($value -isnot [int] -and $value -isnot [long] -and $value -isnot [double] -and $value -isnot [decimal] -or $value -lt 0 -or -not [double]::IsFinite([double]$value)){throw 'Invalid public coverage numbers.'}
 }
 if($Report.SuccessfulApplications -gt $Report.AssessedApplications -or $Report.AssessedApplications -gt $Report.PublishedApplications){throw 'Invalid coverage counts.'}
 if($Report.SchemaVersion -in @(2,3)){
  foreach($field in @('PublishedApplications','AssessedApplications','SuccessfulApplications','TotalBatches','CompletedBatches','PendingBatches','ExhaustedBatches')){if($Report[$field] -isnot [int] -and $Report[$field] -isnot [long]){throw 'Invalid integer coverage counts.'}}
  if($Report.CompletedBatches+$Report.PendingBatches -ne $Report.TotalBatches -or $Report.ExhaustedBatches -gt $Report.PendingBatches -or $Report.Complete -ne ($Report.PendingBatches -eq 0)){throw 'Invalid batch coverage.'}
  foreach($field in @('SourceCatalogApplications','SelectedApplications','PublishedCallbackCandidates','DeepSelectionHistoryApplications','NeverDeepSelectedCallbackCandidates')){
   $value=$Report[$field]
   if($null -eq $value -and $field -in @('DeepSelectionHistoryApplications','NeverDeepSelectedCallbackCandidates')){continue}
   if($value -isnot [int] -and $value -isnot [long] -or $value -lt 0 -or $value -gt 100000){throw 'Invalid selection coverage numbers.'}
  }
  if($Report.SelectedApplications -ne $Report.PublishedApplications -or $Report.SelectedApplications -gt $Report.SourceCatalogApplications -or $Report.PublishedCallbackCandidates -gt $Report.SourceCatalogApplications -or ($Report.Mode -eq 'Shallow' -and $Report.SelectedApplications -ne $Report.SourceCatalogApplications)){throw 'Invalid source and selection coverage.'}
  $history=$Report.DeepSelectionHistoryApplications;$never=$Report.NeverDeepSelectedCallbackCandidates
  if(($null -eq $history) -ne ($null -eq $never) -or ($Report.Mode -eq 'Shallow' -and $null -ne $history)){throw 'Invalid selection history coverage.'}
  if($null -ne $history -and ($history -lt $Report.SelectedApplications -or $history -gt $Report.SourceCatalogApplications -or $never -gt $Report.PublishedCallbackCandidates -or $never -gt ($Report.SourceCatalogApplications-$history) -or $never -lt [Math]::Max(0,$Report.PublishedCallbackCandidates-$history))){throw 'Invalid deep selection coverage.'}
 }

 if($Report.SchemaVersion -eq 3){
  if($Report.ResourceIds -isnot [array] -or $Report.ResourceIds.Count -lt 1 -or $Report.ResourceIds.Count -gt 2 -or @($Report.ResourceIds|Where-Object {$_ -isnot [string] -or $_ -cnotin @('00000003-0000-0000-c000-000000000000','797f4846-ba00-4fd7-ba43-dac1f8f63013')}).Count -or ($Report.ResourceIds -join '/') -cne (@($Report.ResourceIds|Sort-Object -Unique) -join '/') -or ($Report.Mode -eq 'Shallow' -and ($Report.ResourceIds -join '/') -cne '00000003-0000-0000-c000-000000000000')){throw 'Invalid report resource membership.'}
  foreach($field in @('SelectedPairs','AssessedPairs','SuccessfulPairs')){if($Report[$field] -isnot [int] -and $Report[$field] -isnot [long] -or $Report[$field] -lt 0 -or $Report[$field] -gt 200000){throw 'Invalid report pair counts.'}}
  $count=$Report.ResourceIds.Count
  if($Report.SelectedPairs -ne $Report.SelectedApplications*$count -or $Report.AssessedPairs -ne $Report.AssessedApplications*$count -or $Report.SuccessfulPairs -lt $Report.SuccessfulApplications -or $Report.SuccessfulPairs -gt $Report.SuccessfulApplications*$count -or $Report.SuccessfulPairs -gt $Report.AssessedPairs){throw 'Invalid report pair coverage.'}
 }

}
