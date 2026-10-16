#Requires -Version 7.4
# Offline candidate/review contract. No authentication, collection, or network operations.
. (Join-Path $PSScriptRoot 'TokenForgeCiState.ps1')
Import-Module (Join-Path $PSScriptRoot '../src/TokenForge/TokenForge.psd1')
function Read-TfCandidateJson([string]$Path){[TokenForge.Core.DiscoverySourceClaims]::ReadMetadataJson((Get-Content -LiteralPath $Path -Raw -ErrorAction Stop))}
function Get-TfCandidateFileHash([string]$Path){(Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()}
function Write-TfCandidateJson($Value,[string]$Path){ConvertTo-Json -InputObject $Value -Depth 100 | Set-Content -LiteralPath $Path -Encoding utf8}
function Assert-TfCandidateData([string]$Path){
 Assert-TfCiPublicData $Path
 $allowed=@(Get-TfCiPublicStagePaths $Path)
 foreach($file in Get-ChildItem -LiteralPath $Path -File -Recurse -Force){
  $relative=[IO.Path]::GetRelativePath($Path,$file.FullName).Replace('\','/')
  if($relative -cnotin $allowed){throw "Unexpected candidate data file: $relative"}
 }
 $null=Get-TokenForgeApplicationMetadata (Join-Path $Path 'applications.json') -PublicOnly
}
function Get-TfCandidateLeaves($Value,[string]$Pointer=''){
 # JSON Pointer paths preserve case and expose semantic changes, ignoring object key order.
 if($Value -is [Collections.IDictionary]){
  if($Value.Count -eq 0){[pscustomobject]@{Path=$Pointer;Value='{}'}}
  foreach($key in @($Value.Keys|Sort-Object -CaseSensitive)){Get-TfCandidateLeaves $Value[$key] ($Pointer+'/'+$key.Replace('~','~0').Replace('/','~1'))}
 }elseif($Value -is [array]){
  if($Value.Count -eq 0){[pscustomobject]@{Path=$Pointer;Value='[]'}}
  for($i=0;$i -lt $Value.Count;$i++){Get-TfCandidateLeaves $Value[$i] ($Pointer+'/'+$i)}
 }else{[pscustomobject]@{Path=$Pointer;Value=(ConvertTo-Json -InputObject $Value -Compress -Depth 100)}}
}
function New-TfDiscoveryCandidate {
 [CmdletBinding()]param([Parameter(Mandatory)][string]$DataPath,[Parameter(Mandatory)][string]$BaselinePath,[Parameter(Mandatory)][string]$RequestPath,[Parameter(Mandatory)][string]$OutputPath,[Parameter(Mandatory)][ValidatePattern('^[a-f0-9]{40}$')][string]$SourceCommit,[Parameter(Mandatory)][ValidatePattern('^[1-9][0-9]*$')][string]$ProducerRunId,[Parameter(Mandatory)][ValidatePattern('^[1-9][0-9]*$')][string]$ProducerAttempt)
 $ErrorActionPreference='Stop'
 if(Test-Path -LiteralPath $OutputPath){throw 'Candidate destination already exists; candidates cannot be overwritten.'}
 Assert-TfCandidateData $DataPath
 Assert-TfCandidateData $BaselinePath
 $request=Read-TfCandidateJson $RequestPath
 Assert-TfCiKeys $request @('SchemaVersion','PlanId','Mode','Indices','BaseCommit')
 if($request.SchemaVersion -ne 1 -or $request.BaseCommit -cnotmatch '^[a-f0-9]{40}$' -or $request.PlanId -cnotmatch '^[a-f0-9]{64}$' -or $request.Mode -cnotin @('Shallow','Deep')){throw 'Invalid normal candidate request.'}
 $state=Read-TfCandidateJson (Join-Path $DataPath ('weekly-'+$request.Mode.ToLowerInvariant()+'.json'))
 if($state.PlanId -cne $request.PlanId -or $state.Recipe.Mode -cne $request.Mode){throw 'Candidate does not match its frozen request.'}
 $null=New-Item -ItemType Directory -Path $OutputPath
 $null=New-Item -ItemType Directory -Path (Join-Path $OutputPath 'data')
 $changes=[Collections.Generic.List[object]]::new()
 $paths=@(@(Get-TfCiPublicStagePaths $BaselinePath)+@(Get-TfCiPublicStagePaths $DataPath)|Sort-Object -Unique -CaseSensitive)
 foreach($path in $paths){
  $before=[Collections.Generic.Dictionary[string,string]]::new([StringComparer]::Ordinal)
  $after=[Collections.Generic.Dictionary[string,string]]::new([StringComparer]::Ordinal)
  foreach($side in @(@{Root=$BaselinePath;Map=$before},@{Root=$DataPath;Map=$after})){
   $file=Join-Path $side.Root $path
   if(Test-Path -LiteralPath $file){foreach($leaf in @(Get-TfCandidateLeaves (Read-TfCandidateJson $file))){$side.Map.Add($leaf.Path,$leaf.Value)}}
  }
  foreach($pointer in @(@($before.Keys)+@($after.Keys)|Sort-Object -Unique -CaseSensitive)){
   $hasBefore=$before.ContainsKey($pointer);$hasAfter=$after.ContainsKey($pointer)
   if(-not $hasBefore -or -not $hasAfter -or $before[$pointer] -cne $after[$pointer]){
    $changes.Add([ordered]@{File=$path;Path=$pointer;Change=$(if(-not $hasBefore){'Added'}elseif(-not $hasAfter){'Removed'}else{'Changed'});Before=$(if($hasBefore){$before[$pointer]}else{$null});After=$(if($hasAfter){$after[$pointer]}else{$null})})
   }
  }
 }
 foreach($path in @(Get-TfCiPublicStagePaths $DataPath)){
  $target=Join-Path $OutputPath ('data/'+$path);$null=New-Item -ItemType Directory -Path (Split-Path $target) -Force
  Copy-Item -LiteralPath (Join-Path $DataPath $path) -Destination $target
 }
 Copy-Item -LiteralPath $RequestPath -Destination (Join-Path $OutputPath 'request.json')
 Write-TfCandidateJson @($changes) (Join-Path $OutputPath 'changes.json')
 $coverage=Get-TfCiReport $state
 Write-TfCandidateJson ([ordered]@{SchemaVersion=1;Complete=$coverage.Complete;PendingBatches=$coverage.PendingBatches;ExhaustedBatches=$coverage.ExhaustedBatches;AssessedApplications=$coverage.AssessedApplications;SuccessfulApplications=$coverage.SuccessfulApplications;PublicSchemaValid=$true;PlanId=$request.PlanId;Mode=$request.Mode;ChangedValues=$changes.Count;ReviewStatus='Pending';Evidence='AssessedForOneAccountNotUniversalSupport'}) (Join-Path $OutputPath 'validation.json')
 $lines=[Collections.Generic.List[string]]::new()
 $lines.Add('# Discovery candidate review');$lines.Add('');$lines.Add("Base: $($request.BaseCommit)");$lines.Add("Source: $SourceCommit");$lines.Add("Plan: $($request.PlanId) ($($request.Mode))");$lines.Add("Semantic changed values: $($changes.Count)");$lines.Add('')
 $lines.Add("Coverage complete: $($coverage.Complete); pending batches: $($coverage.PendingBatches); exhausted batches: $($coverage.ExhaustedBatches); assessed applications: $($coverage.AssessedApplications); successful applications: $($coverage.SuccessfulApplications).");$lines.Add('')
 $lines.Add('Public schema validation passed. Semantic approval is still required. Account observations do not establish universal support. No automated reviewer is configured.');$lines.Add('')
 $lines.Add('Full JSON Pointer diff: changes.json. Arrays are compared by index. The readable preview is limited to 200 changed values; review the full diff when truncated.');$lines.Add('')
 foreach($change in @($changes|Select-Object -First 200)){
  # Encode untrusted values as JSON, with HTML escaped, rather than active Markdown.
  $entry=ConvertTo-Json -InputObject $change -Compress -EscapeHandling EscapeHtml
  $lines.Add('    '+$entry)
 }
 $lines|Set-Content -LiteralPath (Join-Path $OutputPath 'review.md') -Encoding utf8
 $files=@(Get-ChildItem -LiteralPath $OutputPath -File -Recurse|Sort-Object FullName|ForEach-Object {[ordered]@{Path=[IO.Path]::GetRelativePath($OutputPath,$_.FullName).Replace('\','/');Sha256=Get-TfCandidateFileHash $_.FullName}})
 $manifest=[ordered]@{SchemaVersion=1;BaseCommit=$request.BaseCommit;SourceCommit=$SourceCommit;ProducerRunId=$ProducerRunId;ProducerAttempt=$ProducerAttempt;PlanId=$request.PlanId;Mode=$request.Mode;Files=$files}
 Write-TfCandidateJson $manifest (Join-Path $OutputPath 'manifest.json')
 Get-TfCandidateFileHash (Join-Path $OutputPath 'manifest.json')
}
function Assert-TfDiscoveryCandidate {
 [CmdletBinding()]param([Parameter(Mandatory)][string]$CandidatePath,[Parameter(Mandatory)][ValidatePattern('^[a-f0-9]{64}$')][string]$CandidateHash,[string]$ReviewPath)
 $ErrorActionPreference='Stop'
 foreach($item in @(Get-Item -LiteralPath $CandidatePath)+@(Get-ChildItem -LiteralPath $CandidatePath -Recurse -Force)){if($item.Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'Linked candidate files are forbidden.'}}
 $manifestPath=Join-Path $CandidatePath 'manifest.json'
 if((Get-TfCandidateFileHash $manifestPath) -cne $CandidateHash){throw 'Candidate manifest hash mismatch.'}
 $manifest=Read-TfCandidateJson $manifestPath
 Assert-TfCiKeys $manifest @('SchemaVersion','BaseCommit','SourceCommit','ProducerRunId','ProducerAttempt','PlanId','Mode','Files')
 if($manifest.SchemaVersion -ne 1 -or $manifest.ProducerRunId -cnotmatch '^[1-9][0-9]*$' -or $manifest.ProducerAttempt -cnotmatch '^[1-9][0-9]*$' -or $manifest.BaseCommit -cnotmatch '^[a-f0-9]{40}$' -or $manifest.SourceCommit -cnotmatch '^[a-f0-9]{40}$' -or $manifest.PlanId -cnotmatch '^[a-f0-9]{64}$' -or $manifest.Mode -cnotin @('Shallow','Deep') -or $manifest.Files -isnot [array]){throw 'Invalid candidate manifest.'}
 $expected=[Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal);$null=$expected.Add('manifest.json')
 foreach($entry in $manifest.Files){
  Assert-TfCiKeys $entry @('Path','Sha256')
  if($entry.Path -isnot [string] -or $entry.Path -cnotmatch '^(data/(applications|selection-deep|weekly-(shallow|deep)|coverage-(shallow|deep)|reports/\d{4}-W\d{2}-(shallow|deep)|scopes/chunk-[0-9]{4,6})\.json|request\.json|changes\.json|validation\.json|review\.md)$' -or $entry.Sha256 -cnotmatch '^[a-f0-9]{64}$' -or -not $expected.Add($entry.Path)){throw 'Invalid or duplicate candidate file.'}
  if((Get-TfCandidateFileHash (Join-Path $CandidatePath $entry.Path)) -cne $entry.Sha256){throw "Candidate file hash mismatch: $($entry.Path)"}
 }
 foreach($item in Get-ChildItem -LiteralPath $CandidatePath -Recurse -Force){
  if($item.Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'Linked candidate files are forbidden.'}
  if(-not $item.PSIsContainer -and -not $expected.Contains([IO.Path]::GetRelativePath($CandidatePath,$item.FullName).Replace('\','/'))){throw 'Unexpected candidate file.'}
 }
 foreach($required in @('request.json','changes.json','validation.json','review.md','data/applications.json')){if(-not $expected.Contains($required)){throw 'Missing required candidate file.'}}
 Assert-TfCandidateData (Join-Path $CandidatePath 'data')
 $request=Read-TfCandidateJson (Join-Path $CandidatePath 'request.json')
 Assert-TfCiKeys $request @('SchemaVersion','PlanId','Mode','Indices','BaseCommit')
 if($request.SchemaVersion -ne 1 -or $request.BaseCommit -cne $manifest.BaseCommit -or $request.PlanId -cne $manifest.PlanId -or $request.Mode -cne $manifest.Mode){throw 'Candidate request mismatch.'}
 $state=Read-TfCandidateJson (Join-Path $CandidatePath ('data/weekly-'+$manifest.Mode.ToLowerInvariant()+'.json'))
 if($state.PlanId -cne $manifest.PlanId -or $state.Recipe.Mode -cne $manifest.Mode){throw 'Candidate plan mismatch.'}
 if($ReviewPath){
  $review=Read-TfCandidateJson $ReviewPath
  Assert-TfCiKeys $review @('SchemaVersion','CandidateHash','BaseCommit','SourceCommit','ProducerRunId','ProducerAttempt','Decision','Reviewer','ReviewedAt','Notes')
  if($review.SchemaVersion -ne 1 -or $review.ProducerRunId -cne $manifest.ProducerRunId -or $review.ProducerAttempt -cne $manifest.ProducerAttempt -or $review.CandidateHash -cne $CandidateHash -or $review.BaseCommit -cne $manifest.BaseCommit -or $review.SourceCommit -cne $manifest.SourceCommit -or $review.Decision -cne 'Approved' -or $review.Reviewer -isnot [string] -or [string]::IsNullOrWhiteSpace($review.Reviewer) -or $review.Notes -isnot [string] -or [string]::IsNullOrWhiteSpace($review.Notes)){throw 'Missing or invalid explicit candidate approval.'}
  $date=[DateTimeOffset]::MinValue
  if($review.ReviewedAt -isnot [string] -or -not [DateTimeOffset]::TryParse($review.ReviewedAt,[ref]$date) -or $date -gt [DateTimeOffset]::UtcNow){throw 'Invalid review timestamp.'}
 }
 $manifest
}
function Publish-TfDiscoveryGitCommit {
 # This is an exact compare-and-swap, not permission to overwrite divergent data.
 # The caller must already have verified the candidate and trusted approval.
 [CmdletBinding()]param([Parameter(Mandatory)][string]$RepositoryPath,[Parameter(Mandatory)][ValidatePattern('^[a-f0-9]{40}$')][string]$BaseCommit)
 $ErrorActionPreference='Stop'
 $parents=git -C $RepositoryPath rev-list --parents -n 1 HEAD
 if($LASTEXITCODE -ne 0){throw 'Candidate commit lookup failed.'}
 $parts=@(([string]$parents).Split(' ',[StringSplitOptions]::RemoveEmptyEntries))
 if($parts.Count -ne 2 -or $parts[1] -cne $BaseCommit){throw 'Candidate must be a direct single-parent child of the reviewed data parent.'}
 # A normal push alone permits branch recreation or a reset-to-ancestor race.
 # Explicit expected-old prevents those as well as concurrent forward updates.
 git -C $RepositoryPath push "--force-with-lease=refs/heads/discovery-data:$BaseCommit" origin HEAD:refs/heads/discovery-data
 if($LASTEXITCODE -ne 0){throw 'Publication compare-and-swap failed; retry this reviewed artifact without recollection.'}
}
