#Requires -Version 7.4
# Offline saved-evidence candidate contract, adapted from draft #119 e2aab00.
# Deliberately contains no collection, authentication, approval writer, or publication.
. (Join-Path $PSScriptRoot 'TokenForgeCiState.ps1')
Import-Module (Join-Path $PSScriptRoot '../src/TokenForge/TokenForge.psd1')

function Read-TfCandidateJson([string]$Path) {
 if((Get-Item -LiteralPath $Path -ErrorAction Stop).Length -gt 134217728){throw 'Candidate document exceeds bounds.'}
 [TokenForge.Core.DiscoverySourceClaims]::ReadMetadataJson((Get-Content -LiteralPath $Path -Raw -ErrorAction Stop))
}
function Get-TfCandidateFileHash([string]$Path) {(Get-FileHash -LiteralPath $Path -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant()}
function Write-TfCandidateJson($Value,[string]$Path) {ConvertTo-Json -InputObject $Value -Depth 100 | Set-Content -LiteralPath $Path -Encoding utf8 -ErrorAction Stop}
function Get-TfCandidateHash($Value) {
 $bytes=[Text.Encoding]::UTF8.GetBytes((ConvertTo-Json -InputObject $Value -Compress -Depth 100))
 [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($bytes)).ToLowerInvariant()
}
function Assert-TfCandidateUnlinked([string]$Path) {
 $full=[IO.Path]::GetFullPath($Path)
 for($part=$full;$part;$part=[IO.Path]::GetDirectoryName($part)){
  $item=Get-Item -LiteralPath $part -Force -ErrorAction SilentlyContinue
  if($item -and ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)){throw 'Linked candidate paths are forbidden.'}
 }
 if(Test-Path -LiteralPath $full -PathType Container){
  foreach($item in Get-ChildItem -LiteralPath $full -Recurse -Force){if($item.Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'Linked candidate paths are forbidden.'}}
 }
}
function Assert-TfCandidateGuid($Value) {
 $id=[guid]::Empty
 if($Value -isnot [string] -or -not [guid]::TryParse($Value,[ref]$id) -or $id -eq [guid]::Empty -or $Value -cne $id.ToString()){throw 'Invalid candidate application ID.'}
}
function Assert-TfCandidateRecipe($Recipe) {
 Assert-TfCiKeys $Recipe @('SchemaVersion','Protocols','MaxRedirects','ExploreAllFlows','Pairs')
 if(($Recipe.SchemaVersion -isnot [int] -and $Recipe.SchemaVersion -isnot [long]) -or $Recipe.SchemaVersion -ne 1 -or $Recipe.Protocols -isnot [array] -or -not $Recipe.Protocols.Count -or @($Recipe.Protocols|Where-Object {$_ -cnotin @('OAuth2V2Pkce','OAuth2V2Implicit','OAuth2V1Implicit')}).Count -or @($Recipe.Protocols|Sort-Object -Unique).Count -ne $Recipe.Protocols.Count -or $Recipe.MaxRedirects -isnot [long] -and $Recipe.MaxRedirects -isnot [int] -or $Recipe.MaxRedirects -lt 1 -or $Recipe.MaxRedirects -gt 1000 -or $Recipe.ExploreAllFlows -isnot [bool] -or $Recipe.Pairs -isnot [array] -or $Recipe.Pairs.Count -lt 1 -or $Recipe.Pairs.Count -gt 100000){throw 'Invalid candidate recipe.'}
 $seen=[Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
 foreach($pair in $Recipe.Pairs){
  Assert-TfCiKeys $pair @('ClientId','ResourceId','MatrixKnown','Excluded','Cells')
  Assert-TfCandidateGuid $pair.ClientId;Assert-TfCandidateGuid $pair.ResourceId
  if(-not $seen.Add($pair.ClientId+'/'+$pair.ResourceId) -or $pair.MatrixKnown -isnot [bool] -or $pair.Excluded -isnot [bool] -or $pair.Cells -isnot [array] -or $pair.Cells.Count -gt 4000 -or (-not $pair.MatrixKnown -and ($pair.Excluded -or $pair.Cells.Count)) -or ($pair.Excluded -and $pair.Cells.Count)){throw 'Invalid candidate pair matrix.'}
  foreach($cell in $pair.Cells){Assert-TfCiKeys $cell @('Protocol','Spa');if($cell.Protocol -cnotin $Recipe.Protocols -or $cell.Spa -isnot [bool] -or ($cell.Spa -and $cell.Protocol -cne 'OAuth2V2Pkce')){throw 'Invalid candidate cell.'}}
 }
}
function Get-TfCandidateValidation($Recipe,$Coverage,$Scopes,$Flows) {
 Assert-TfCandidateRecipe $Recipe
 Assert-TfCiKeys $Coverage @('SchemaVersion','Pairs')
 if(($Coverage.SchemaVersion -isnot [int] -and $Coverage.SchemaVersion -isnot [long]) -or $Coverage.SchemaVersion -ne 1 -or $Coverage.Pairs -isnot [array] -or $Coverage.Pairs.Count -ne $Recipe.Pairs.Count){throw 'Invalid candidate coverage.'}
 $planned=0;$terminal=0;$unknown=0;$pending=0;$excluded=0;$unknownMatrices=0;$paused=0;$blocked=0;$transient=0
 for($i=0;$i -lt $Recipe.Pairs.Count;$i++){
  $pair=$Recipe.Pairs[$i];$row=$Coverage.Pairs[$i]
  Assert-TfCiKeys $row @('CellOutcomes')
  if($row.CellOutcomes -isnot [array] -or $row.CellOutcomes.Count -ne $pair.Cells.Count -or @($row.CellOutcomes|Where-Object {$_ -isnot [string] -or $_ -cnotin @('Pending','InFlightUnknown','Succeeded','Failed','OpaqueToken','NoDelegatedScp','ContextMismatch','SessionPaused','RequestBlocked','TransientFailure')}).Count){throw 'Invalid candidate cell coverage.'}
  $planned+=$pair.Cells.Count
  $terminal+=@($row.CellOutcomes|Where-Object {$_ -cnotin @('Pending','InFlightUnknown','SessionPaused','TransientFailure')}).Count
  $unknown+=@($row.CellOutcomes|Where-Object {$_ -ceq 'InFlightUnknown'}).Count
  $pending+=@($row.CellOutcomes|Where-Object {$_ -ceq 'Pending'}).Count
  $paused+=@($row.CellOutcomes|Where-Object {$_ -ceq 'SessionPaused'}).Count
  $blocked+=@($row.CellOutcomes|Where-Object {$_ -ceq 'RequestBlocked'}).Count
  $transient+=@($row.CellOutcomes|Where-Object {$_ -ceq 'TransientFailure'}).Count
  if($pair.Excluded){$excluded++};if(-not $pair.MatrixKnown){$unknownMatrices++}
 }
 Assert-TfCiScopeExport $Scopes
 Assert-TfCiKeys $Flows @('Format','SchemaVersion','Observations','Disclaimer')
 if($Flows.Format -cne 'TokenForgeAnonymousFlows' -or ($Flows.SchemaVersion -isnot [int] -and $Flows.SchemaVersion -isnot [long]) -or $Flows.SchemaVersion -ne 1 -or $Flows.Observations -isnot [array] -or $Flows.Disclaimer -cne 'Account/session/tenant-dependent observations, not universal support or consent.'){throw 'Invalid anonymous candidate flows.'}
 foreach($row in $Flows.Observations){
  Assert-TfCiKeys $row @('ClientId','ResourceId','Protocol','Spa','Scopes','SignatureValidated','Evidence')
  Assert-TfCandidateGuid $row.ClientId;Assert-TfCandidateGuid $row.ResourceId
  if($row.Protocol -cnotin $Recipe.Protocols -or $row.Spa -isnot [bool] -or ($row.Spa -and $row.Protocol -cne 'OAuth2V2Pkce') -or $row.Scopes -isnot [array] -or -not $row.Scopes.Count -or @($row.Scopes|Where-Object {$_ -isnot [string] -or $_ -cnotmatch '^[A-Za-z0-9_.-]{1,256}$'}).Count -or $row.SignatureValidated -isnot [bool] -or $row.SignatureValidated -or $row.Evidence -cne 'AnonymousObservedFlowNotUniversalCapability'){throw 'Invalid candidate flow observation.'}
  $pair=@($Recipe.Pairs|Where-Object {$_.ClientId -ceq $row.ClientId -and $_.ResourceId -ceq $row.ResourceId})
  if($pair.Count -ne 1 -or -not @($pair[0].Cells|Where-Object {$_.Protocol -ceq $row.Protocol -and $_.Spa -eq $row.Spa}).Count){throw 'Flow observation outside frozen candidate recipe.'}
 }
 $scopeKeys=[Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
 $flowKeys=[Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
 foreach($row in $Flows.Observations){$null=$flowKeys.Add($row.ClientId+'/'+$row.ResourceId+'/'+(@($row.Scopes|Sort-Object -Unique -CaseSensitive) -join ' '))}
 foreach($row in $Scopes.Observations){
  Assert-TfCandidateGuid $row.ClientId;Assert-TfCandidateGuid $row.ResourceId
  if(-not @($Recipe.Pairs|Where-Object {$_.ClientId -ceq $row.ClientId -and $_.ResourceId -ceq $row.ResourceId}).Count){throw 'Scope observation outside frozen candidate recipe.'}
  if(-not $row.Scopes.Count -or [TokenForge.Core.V0240.TimestampPolicy]::Parse($row.ObservedAt) -gt [DateTimeOffset]::UtcNow.AddMinutes(5)){throw 'Invalid candidate scope observation.'}
  $null=$scopeKeys.Add($row.ClientId+'/'+$row.ResourceId+'/'+(@($row.Scopes|Sort-Object -Unique -CaseSensitive) -join ' '))
 }
 if(-not $scopeKeys.SetEquals($flowKeys)){throw 'Anonymous scope and flow projections disagree.'}
 [ordered]@{SchemaVersion=1;SelectedPairs=$Recipe.Pairs.Count;StructurallyExcludedPairs=$excluded;UnknownMatrixPairs=$unknownMatrices;PlannedCells=$planned;TerminalCells=$terminal;InFlightUnknownCells=$unknown;PendingCells=$pending;PausedCells=$paused;RequestBlockedCells=$blocked;TransientFailureCells=$transient;ScopeObservations=$Scopes.Observations.Count;FlowObservations=$Flows.Observations.Count;ReviewStatus='Pending';Evidence='AssessedForOneAccountNotUniversalSupport';CredentialOutput=$false}
}
function Get-TfCandidateReviewText($Validation) {
 # Only fixed text and validated numeric counters enter this Markdown document.
 "# Saved discovery evidence candidate`n`nSelected pairs: $($Validation.SelectedPairs); structurally excluded pairs: $($Validation.StructurallyExcludedPairs); pairs with an unknown matrix: $($Validation.UnknownMatrixPairs).`n`nKnown planned cells: $($Validation.PlannedCells); terminal: $($Validation.TerminalCells); in-flight unknown: $($Validation.InFlightUnknownCells); pending: $($Validation.PendingCells); paused: $($Validation.PausedCells); request-blocked: $($Validation.RequestBlockedCells); transient failure: $($Validation.TransientFailureCells).`n`nInspect recipe.json, coverage.json, scopes.json and flows.json in full. Historical matched successes are observations for one account, not universal support, consent or API access. Started attempts remain unknown. This export does not authenticate or issue tokens. Integrity and privacy validation do not constitute semantic approval. Approval and publication require separate authority.`n"
}
function New-TfDiscoveryCandidate {
 [CmdletBinding()]param(
  [Parameter(Mandatory)][string]$ScopePath,[Parameter(Mandatory)][string]$FlowPath,
  [Parameter(Mandatory)][ValidatePattern('^[a-f0-9]{64}$')][string]$CohortId,
  [Parameter(Mandatory)][string]$OutputPath,[Parameter(Mandatory)][ValidatePattern('^[a-f0-9]{40}$')][string]$SourceCommit,
  [Parameter(Mandatory)][ValidatePattern('^[1-9][0-9]*$')][string]$ProducerRunId,
  [Parameter(Mandatory)][ValidatePattern('^[1-9][0-9]*$')][string]$ProducerAttempt,
  [Parameter(Mandatory)][string]$NativeExecutablePath)
 $ErrorActionPreference='Stop'
 if(-not $ScopePath.EndsWith('.sqlite',[StringComparison]::OrdinalIgnoreCase) -or -not $FlowPath.EndsWith('.sqlite',[StringComparison]::OrdinalIgnoreCase)){throw 'Saved cohort candidates require existing SQLite stores.'}
 # Use the established private-path policy, without creating or changing source paths.
 $ScopePath=[TokenForge.Core.V0220.PrivateFiles]::Resolve([IO.Path]::GetFullPath($ScopePath),$false)
 $FlowPath=[TokenForge.Core.V0220.PrivateFiles]::Resolve([IO.Path]::GetFullPath($FlowPath),$false)
 foreach($path in @($ScopePath,$FlowPath)){if(-not(Test-Path -LiteralPath $path -PathType Leaf)){throw 'Saved evidence store does not exist.'}}
 $OutputPath=[IO.Path]::GetFullPath($OutputPath);Assert-TfCandidateUnlinked $OutputPath
 if(Test-Path -LiteralPath $OutputPath){throw 'Candidate destination already exists; candidates cannot be overwritten.'}
 $parent=Split-Path $OutputPath -Parent
 if(-not(Test-Path -LiteralPath $parent -PathType Container)){throw 'Candidate parent directory must exist.'}
 $locks=[Collections.Generic.List[IDisposable]]::new();$stage=$null
 try{
  # Cooperate with run and direct cohort writers. No source checkpoint is modified.
  foreach($lockPath in @((Join-Path (Split-Path $ScopePath) '.writer.lock'),($ScopePath+'.cohort.lock'))){
   $resolved=[TokenForge.Core.V0220.PrivateFiles]::Resolve($lockPath,$false)
   $locks.Add([TokenForge.Core.V0220.PrivateFiles]::Open($resolved,-not(Test-Path -LiteralPath $resolved)))
  }
  $cohort=Get-TokenForgeResearchCohort -DatabasePath $ScopePath -CohortId $CohortId -NativeExecutablePath $NativeExecutablePath
  if($cohort.PlanId -cne $CohortId){throw 'Saved cohort identity mismatch.'}
  $frozen=$cohort.Cohort
  # Unfiltered reads validate full history before namespace or cohort selection.
  $scopes=Get-TokenForgeScopeDatabase -Path $ScopePath -NativeExecutablePath $NativeExecutablePath
  $flows=Get-TokenForgeFlowEvidence -Path $FlowPath -NativeExecutablePath $NativeExecutablePath
  $scopeHash=Get-TfCandidateHash @($scopes.Observations,$scopes.RegistrationAttempts)
  $flowHash=Get-TfCandidateHash @($flows.Plans,$flows.Attempts)
  $plans=@{};$attempts=@();$pairs=@();$coveragePairs=@()
  foreach($hash in $flows.Plans.Keys){
   $plan=$flows.Plans[$hash]
   if(-not $plan.Contains('CohortFingerprint') -or $plan.CohortFingerprint -cne $CohortId){continue}
   if($plan.TenantFingerprint -cne $frozen.TenantFingerprint -or $plan.PrincipalFingerprint -cne $frozen.PrincipalFingerprint -or $plan.CatalogHash -cne $frozen.CatalogHash -or $plan.Tenant -cne $frozen.Authority -or -not @($frozen.Pairs|Where-Object {$_.ClientId -ceq $plan.ClientId -and $_.ResourceId -ceq $plan.ResourceId}).Count){throw 'Saved flow plan differs from frozen cohort namespace or membership.'}
   if(@($plan.Cells|Where-Object {$_.Protocol -cnotin $frozen.Protocols}).Count){throw 'Saved flow protocol differs from frozen cohort.'}
   $plans[$hash]=$plan
  }
  $attempts=@($flows.Attempts|Where-Object {$plans.ContainsKey($_.PlanFingerprint)})
  foreach($pair in $frozen.Pairs){
   $matches=@($plans.Keys|Where-Object {$plans[$_].ClientId -ceq $pair.ClientId -and $plans[$_].ResourceId -ceq $pair.ResourceId})
   if($matches.Count -gt 1){throw 'Multiple flow matrices for one frozen cohort pair require review.'}
   $cells=@();$outcomes=@();$excluded=$false
   if($matches.Count){
    $hash=$matches[0];$plan=$plans[$hash];$excluded=$plan.Eligibility -cne 'Eligible'
    foreach($cell in $plan.Cells){
     $cells+=,[ordered]@{Protocol=$cell.Protocol;Spa=$cell.Spa}
     $history=@($attempts|Where-Object {$_.PlanFingerprint -ceq $hash -and $_.Protocol -ceq $cell.Protocol -and $_.Spa -eq $cell.Spa -and $_.RedirectFingerprint -ceq $cell.RedirectFingerprint}|Sort-Object -Stable {([DateTimeOffset]$_.ObservedAt).UtcDateTime})
     $outcomes+=if(-not $history.Count){'Pending'}elseif($history[-1].Outcome -ceq 'Started'){'InFlightUnknown'}else{$history[-1].Outcome}
    }
   }
   $pairs+=,[ordered]@{ClientId=$pair.ClientId;ResourceId=$pair.ResourceId;MatrixKnown=[bool]$matches.Count;Excluded=$excluded;Cells=$cells}
   $coveragePairs+=,[ordered]@{CellOutcomes=$outcomes}
  }
  $recipe=[ordered]@{SchemaVersion=1;Protocols=@($frozen.Protocols);MaxRedirects=$frozen.MaxRedirects;ExploreAllFlows=$frozen.ExploreAllFlows;Pairs=$pairs}
  $coverage=[ordered]@{SchemaVersion=1;Pairs=$coveragePairs}
  $stage=Join-Path $parent ('.'+[IO.Path]::GetFileName($OutputPath)+'.partial-'+[guid]::NewGuid().ToString('N'))
  $null=[IO.Directory]::CreateDirectory($stage,[IO.UnixFileMode]448)
  # A private filtered snapshot lets the existing flow exporter retain its strict contract.
  $snapshot=Join-Path $stage 'filtered-private.json'
  $selected=@{Format='TokenForgeFlowEvidence';SchemaVersion=1;UpdatedAt=$flows.UpdatedAt;Plans=$plans;Attempts=$attempts}
  & (Get-Module TokenForge) {param($p,$d) Save-TokenForgeDocument -Path $p -Document $d} $snapshot $selected
  Export-TokenForgeFlowEvidence -Path $snapshot -OutputPath (Join-Path $stage 'flows.json')
  Remove-Item -LiteralPath $snapshot
  # Flow terminal checkpoints are primary. Rebuild missing aggregate projection offline.
  $projection=New-TokenForgeScopeDatabase
  $projection.Observations=@($attempts|Where-Object Outcome -CEQ 'Succeeded'|ForEach-Object {[pscustomobject]@{ClientId=$_.ClientId;ResourceId=$_.ResourceId;Outcome=$_.Outcome;ObservedAt=$_.ObservedAt;ScpScopes=$_.ScpScopes;NamespaceVerification=$_.NamespaceVerification;RequestVerification=$_.RequestVerification}})
  Export-TokenForgeScopeDatabase -Database $projection -Path (Join-Path $stage 'scopes.json')
  Write-TfCandidateJson $recipe (Join-Path $stage 'recipe.json')
  Write-TfCandidateJson $coverage (Join-Path $stage 'coverage.json')
  $validation=Get-TfCandidateValidation $recipe $coverage (Read-TfCandidateJson (Join-Path $stage 'scopes.json')) (Read-TfCandidateJson (Join-Path $stage 'flows.json'))
  Write-TfCandidateJson $validation (Join-Path $stage 'validation.json')
  [IO.File]::WriteAllText((Join-Path $stage 'review.md'),(Get-TfCandidateReviewText $validation),[Text.UTF8Encoding]::new($false))
  $files=@(Get-ChildItem -LiteralPath $stage -File|Sort-Object Name|ForEach-Object {[ordered]@{Path=$_.Name;Sha256=Get-TfCandidateFileHash $_.FullName}})
  $manifest=[ordered]@{SchemaVersion=1;SourceCommit=$SourceCommit;ProducerRunId=$ProducerRunId;ProducerAttempt=$ProducerAttempt;RecipeSha256=Get-TfCandidateFileHash (Join-Path $stage 'recipe.json');FrozenRecipeSha256=Get-TfCandidateHash $frozen;ScopeEvidenceSha256=$scopeHash;FlowEvidenceSha256=$flowHash;Files=$files}
  Write-TfCandidateJson $manifest (Join-Path $stage 'manifest.json')
  $candidateHash=Get-TfCandidateFileHash (Join-Path $stage 'manifest.json')
  $null=Assert-TfDiscoveryCandidate -CandidatePath $stage -CandidateHash $candidateHash
  # Check for non-cooperating writes across the snapshot, ignoring export-generated UpdatedAt.
  $again=Get-TokenForgeScopeDatabase -Path $ScopePath -NativeExecutablePath $NativeExecutablePath
  $againFlows=Get-TokenForgeFlowEvidence -Path $FlowPath -NativeExecutablePath $NativeExecutablePath
  if((Get-TfCandidateHash @($again.Observations,$again.RegistrationAttempts)) -cne $scopeHash -or (Get-TfCandidateHash @($againFlows.Plans,$againFlows.Attempts)) -cne $flowHash){throw 'Saved evidence changed during export; retry after the writer stops.'}
  [IO.Directory]::Move($stage,$OutputPath);$stage=$null
  $candidateHash
 }finally{
  if($stage -and (Test-Path -LiteralPath $stage)){Remove-Item -LiteralPath $stage -Recurse -Force}
  for($i=$locks.Count-1;$i -ge 0;$i--){$locks[$i].Dispose()}
 }
}
function Assert-TfDiscoveryCandidate {
 [CmdletBinding()]param([Parameter(Mandatory)][string]$CandidatePath,[Parameter(Mandatory)][ValidatePattern('^[a-f0-9]{64}$')][string]$CandidateHash,[string]$ReviewPath)
 $ErrorActionPreference='Stop'
 Assert-TfCandidateUnlinked $CandidatePath
 $manifestPath=Join-Path $CandidatePath 'manifest.json'
 if((Get-TfCandidateFileHash $manifestPath) -cne $CandidateHash){throw 'Candidate manifest hash mismatch.'}
 $m=Read-TfCandidateJson $manifestPath
 Assert-TfCiKeys $m @('SchemaVersion','SourceCommit','ProducerRunId','ProducerAttempt','RecipeSha256','FrozenRecipeSha256','ScopeEvidenceSha256','FlowEvidenceSha256','Files')
 if(($m.SchemaVersion -isnot [int] -and $m.SchemaVersion -isnot [long]) -or $m.SchemaVersion -ne 1 -or $m.SourceCommit -isnot [string] -or $m.SourceCommit -cnotmatch '^[a-f0-9]{40}$' -or $m.ProducerRunId -isnot [string] -or $m.ProducerRunId -cnotmatch '^[1-9][0-9]*$' -or $m.ProducerAttempt -isnot [string] -or $m.ProducerAttempt -cnotmatch '^[1-9][0-9]*$' -or $m.Files -isnot [array]){throw 'Invalid candidate manifest.'}
 foreach($field in @('RecipeSha256','FrozenRecipeSha256','ScopeEvidenceSha256','FlowEvidenceSha256')){if($m[$field] -isnot [string] -or $m[$field] -cnotmatch '^[a-f0-9]{64}$'){throw 'Invalid candidate evidence binding.'}}
 $required=@('coverage.json','flows.json','recipe.json','review.md','scopes.json','validation.json')
 $seen=[Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
 foreach($entry in $m.Files){
  Assert-TfCiKeys $entry @('Path','Sha256')
  if($entry.Path -isnot [string] -or $entry.Path -cnotin $required -or -not $seen.Add($entry.Path) -or $entry.Sha256 -isnot [string] -or $entry.Sha256 -cnotmatch '^[a-f0-9]{64}$'){throw 'Invalid or duplicate candidate file.'}
  if((Get-TfCandidateFileHash (Join-Path $CandidatePath $entry.Path)) -cne $entry.Sha256){throw 'Candidate file hash mismatch.'}
 }
 if($seen.Count -ne $required.Count){throw 'Missing required candidate file.'}
 foreach($item in Get-ChildItem -LiteralPath $CandidatePath -Force){if($item.PSIsContainer -or ($item.Name -cne 'manifest.json' -and -not $seen.Contains($item.Name))){throw 'Unexpected candidate file.'}}
 if((Get-TfCandidateFileHash (Join-Path $CandidatePath 'recipe.json')) -cne $m.RecipeSha256){throw 'Candidate recipe hash mismatch.'}
 $validation=Get-TfCandidateValidation (Read-TfCandidateJson (Join-Path $CandidatePath 'recipe.json')) (Read-TfCandidateJson (Join-Path $CandidatePath 'coverage.json')) (Read-TfCandidateJson (Join-Path $CandidatePath 'scopes.json')) (Read-TfCandidateJson (Join-Path $CandidatePath 'flows.json'))
 $saved=Read-TfCandidateJson (Join-Path $CandidatePath 'validation.json')
 Assert-TfCiKeys $saved @($validation.Keys)
 foreach($key in $validation.Keys){if((ConvertTo-Json $saved[$key] -Compress) -cne (ConvertTo-Json $validation[$key] -Compress)){throw 'Candidate validation reconstruction mismatch.'}}
 if((Get-Content -LiteralPath (Join-Path $CandidatePath 'review.md') -Raw) -cne (Get-TfCandidateReviewText $validation)){throw 'Candidate review reconstruction mismatch.'}
 if($ReviewPath){
  $review=Read-TfCandidateJson $ReviewPath
  Assert-TfCiKeys $review @('SchemaVersion','CandidateHash','SourceCommit','ProducerRunId','ProducerAttempt','Decision','Reviewer','ReviewedAt','Notes')
  if(($review.SchemaVersion -isnot [int] -and $review.SchemaVersion -isnot [long]) -or $review.SchemaVersion -ne 1 -or $review.CandidateHash -cne $CandidateHash -or $review.SourceCommit -cne $m.SourceCommit -or $review.ProducerRunId -cne $m.ProducerRunId -or $review.ProducerAttempt -cne $m.ProducerAttempt -or $review.Decision -cne 'Approved' -or $review.Reviewer -isnot [string] -or [string]::IsNullOrWhiteSpace($review.Reviewer) -or $review.Notes -isnot [string] -or [string]::IsNullOrWhiteSpace($review.Notes)){throw 'Missing or invalid explicit candidate approval.'}
  $date=[DateTimeOffset]::MinValue
  if($review.ReviewedAt -isnot [string] -or -not [DateTimeOffset]::TryParse($review.ReviewedAt,[ref]$date) -or $date -gt [DateTimeOffset]::UtcNow){throw 'Invalid review timestamp.'}
 }
 $m
}
