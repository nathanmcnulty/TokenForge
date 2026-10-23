#Requires -Version 7.4
# Read-only GitHub verification and private handoff. No remote mutation or writer.
. (Join-Path $PSScriptRoot TokenForgeDiscoveryCandidate.ps1)
. (Join-Path $PSScriptRoot TokenForgePublicationRecovery.ps1)

function Read-TfPublicationJson([byte[]]$Bytes) {
 if($Bytes.Length -gt 4MB){throw 'Response bound.'}
 $text=[Text.UTF8Encoding]::new($false,$true).GetString($Bytes)
 $options=[Text.Json.JsonDocumentOptions]::new();$options.MaxDepth=64
 $doc=[Text.Json.JsonDocument]::Parse($text,$options)
 try{return ,(ConvertFrom-TokenForgePermissionElement $doc.RootElement)}finally{$doc.Dispose()}
}
function Get-TfPublicationId($Value) {
 if($Value -isnot [string] -and $Value -isnot [long] -and $Value -isnot [int]){throw 'Identity type.'}
 $text=[string]$Value;if($text -cnotmatch '\A[1-9][0-9]{0,18}\z'){throw 'Identity shape.'};$text
}
function Test-TfPublicationBudget($Context) {
 if($Context.Watch.Elapsed.TotalSeconds -ge 60 -or $Context.Requests -gt 32 -or $Context.Bytes -gt 32MB){throw 'Verification budget exhausted.'}
}
function Get-TfPublicationNow($Context) {if($Context.Synthetic){$Context.FixtureTime}else{[DateTimeOffset]::UtcNow}}
function Get-TfPublicationBlobHash([byte[]]$Bytes) {
 $prefix=[Text.Encoding]::ASCII.GetBytes("blob $($Bytes.Length)`0");$all=[byte[]]::new($prefix.Length+$Bytes.Length)
 [Array]::Copy($prefix,0,$all,0,$prefix.Length);[Array]::Copy($Bytes,0,$all,$prefix.Length,$Bytes.Length)
 [Convert]::ToHexString([Security.Cryptography.SHA1]::HashData($all)).ToLowerInvariant()
}
function Invoke-TfPublicationHttp($Context,[string]$Route) {
 # Route is constructed by the adapter, never taken from API URL/link fields.
 if($Route -cnotmatch '\A/(user|repos/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+/[A-Za-z0-9_./?=&-]+|repos/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)\z' -or $Route -match '(^|/)\.\.?(/|$)'){throw 'API route.'}
 Test-TfPublicationBudget $Context;if($Context.Requests -ge 32){throw 'Request budget exhausted.'};$Context.Requests++
 if($Context.Synthetic){$response=& $Context.ReadFixture $Route}
 else{
  $handler=[Net.Http.HttpClientHandler]::new();$handler.AllowAutoRedirect=$false;$handler.UseCookies=$false;$handler.UseProxy=$false
  $client=[Net.Http.HttpClient]::new($handler);$client.Timeout=[TimeSpan]::FromSeconds([math]::Min(10,60-$Context.Watch.Elapsed.TotalSeconds))
  $cancel=[Threading.CancellationTokenSource]::new();$cancel.CancelAfter($client.Timeout)
  $request=[Net.Http.HttpRequestMessage]::new([Net.Http.HttpMethod]::Get,('https://api.github.com'+$Route))
  try{
   $request.Headers.UserAgent.ParseAdd('TokenForge-PublicationVerifier/1');$request.Headers.Accept.ParseAdd('application/vnd.github+json')
   $request.Headers.Add('X-GitHub-Api-Version','2022-11-28')
   $request.Headers.Authorization=[Net.Http.Headers.AuthenticationHeaderValue]::new('Bearer',[Net.NetworkCredential]::new('',$Context.Token).Password)
   $message=$client.Send($request,[Net.Http.HttpCompletionOption]::ResponseHeadersRead,$cancel.Token)
   try{
    if([int]$message.StatusCode -ne 200 -or $message.Headers.Contains('Link') -or $message.Content.Headers.ContentLength -gt 4MB){throw 'API refused or paginated.'}
    $stream=$message.Content.ReadAsStream();$memory=[IO.MemoryStream]::new();$buffer=[byte[]]::new(8192)
    try{while(($n=$stream.ReadAsync($buffer,0,$buffer.Length,$cancel.Token).GetAwaiter().GetResult()) -gt 0){if($memory.Length+$n -gt 4MB -or $memory.Length+$n+$Context.Bytes -gt 32MB){throw 'Response bound.'};$memory.Write($buffer,0,$n);Test-TfPublicationBudget $Context};$bytes=$memory.ToArray()}finally{$memory.Dispose();$stream.Dispose()}
    $response=@{Status=200;Paginated=$false;Bytes=$bytes}
   }finally{$message.Dispose()}
  }finally{$request.Dispose();$client.Dispose();$cancel.Dispose()}
 }
 if($response.Status -ne 200 -or $response.Paginated -ne $false -or $response.Bytes -isnot [byte[]] -or $response.Bytes.Length -gt 4MB){throw 'Invalid API response.'}
 $Context.Bytes+=$response.Bytes.Length;Test-TfPublicationBudget $Context
 return ,(Read-TfPublicationJson $response.Bytes)
}
function Invoke-TfPublicationAttestation($Context,[string]$Archive,[string]$Source,[string]$Scratch) {
 if($Context.Synthetic){return ,@(& $Context.VerifyFixture $Archive)}
 $sourcePath=[IO.Path]::GetFullPath($Context.VerifierPath);Assert-TfCandidateUnlinked $sourcePath
 if(-not (Test-Path -LiteralPath $sourcePath -PathType Leaf)){throw 'Verifier missing.'}
 $sourceStream=[IO.File]::Open($sourcePath,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::None)
 $path=Join-Path $Scratch verifier;$destination=[TokenForge.Core.V0220.PrivateFiles]::Open($path,$true)
 try{
  if($sourceStream.Length -lt 1 -or $sourceStream.Length -gt 128MB){throw 'Verifier size bound.'}
  $buffer=[byte[]]::new(8192);$copied=0L
  while(($n=$sourceStream.Read($buffer,0,$buffer.Length)) -gt 0){if(($copied+=$n) -gt 128MB){throw 'Verifier size bound.'};$destination.Write($buffer,0,$n)};$destination.Flush($true)
 }finally{$destination.Dispose();$sourceStream.Dispose()}
 if((Get-TfCandidateFileHash $path) -cne $Context.Policy.VerifierSha256){throw 'Untrusted verifier.'}
 [IO.File]::SetUnixFileMode($path,[IO.UnixFileMode]320)
 if(-not (Test-Path -LiteralPath /usr/bin/unshare -PathType Leaf)){throw 'Offline verifier isolation unavailable.'}
 $start=[Diagnostics.ProcessStartInfo]::new('/usr/bin/unshare');$start.ArgumentList.Add('-Urn');$start.ArgumentList.Add($path);$start.UseShellExecute=$false
 $start.RedirectStandardOutput=$true;$start.RedirectStandardError=$true;$start.RedirectStandardInput=$true
 # No ambient GitHub credentials/config/proxy/extension are consulted by the child.
 $start.Environment.Clear();$start.Environment['HOME']=$Scratch;$start.Environment['GH_CONFIG_DIR']=$Scratch
 $start.Environment['PATH']='/usr/bin:/bin';$start.Environment['GH_HOST']='github.com';$start.Environment['GH_PROMPT_DISABLED']='1'
 # The verifier is offline: pinned trust root and signed bundle; no token or network.
 $p=$Context.Policy
 foreach($arg in @('attestation','verify',$Archive,'--bundle',$Context.BundlePath,'--custom-trusted-root',$Context.TrustRootPath,'--repo',$p.Repository,'--signer-workflow',($p.Repository+'/'+$p.SealerPath),'--signer-digest',$p.SealerCommit,'--source-digest',$Source,'--source-ref',('refs/heads/'+$p.MainBranch),'--deny-self-hosted-runners','--cert-oidc-issuer','https://token.actions.githubusercontent.com','--limit','1','--format','json')){$start.ArgumentList.Add($arg)}
 $process=[Diagnostics.Process]::Start($start)
 try{
  $process.StandardInput.Close();$out=$process.StandardOutput.BaseStream;$err=$process.StandardError.BaseStream
  # Bounded readers execute on the CLR, avoiding unbounded ReadToEnd buffers.
  $output=[IO.MemoryStream]::new();$errors=[IO.MemoryStream]::new();$buffer=[byte[]]::new(8192);$ebuffer=[byte[]]::new(8192)
  $ot=$out.ReadAsync($buffer,0,$buffer.Length);$et=$err.ReadAsync($ebuffer,0,$ebuffer.Length);$oe=$false;$ee=$false
  try{
   while(-not ($process.HasExited -and $oe -and $ee)){
    Test-TfPublicationBudget $Context
    if(-not $oe -and $ot.IsCompleted){$n=$ot.GetAwaiter().GetResult();if($n -eq 0){$oe=$true}else{if($output.Length+$n -gt 4MB){throw 'Verifier output bound.'};$output.Write($buffer,0,$n);$ot=$out.ReadAsync($buffer,0,$buffer.Length)}}
    if(-not $ee -and $et.IsCompleted){$n=$et.GetAwaiter().GetResult();if($n -eq 0){$ee=$true}else{if($errors.Length+$n -gt 64KB){throw 'Verifier error bound.'};$errors.Write($ebuffer,0,$n);$et=$err.ReadAsync($ebuffer,0,$ebuffer.Length)}}
    [Threading.Thread]::Sleep(5)
   }
   if($process.ExitCode -ne 0){throw 'Attestation verifier refused.'}
   return ,(Read-TfPublicationJson $output.ToArray())
  }finally{$output.Dispose();$errors.Dispose()}
 }finally{if(-not $process.HasExited){$process.Kill($true);$process.WaitForExit()};$process.Dispose();$start.Environment.Clear()}
}
function Assert-TfPublicationPolicy($Policy) {
 Assert-TokenForgePermissionFields $Policy @('SchemaVersion','Repository','RepositoryId','MainBranch','DataBranch','WorkflowId','WorkflowPath','WorkflowSha256','SealerPath','SealerCommit','SealerSha256','VerifierSha256','TrustRootSha256','ProducerIds','ReviewerIds','MaintainerIds','ReaderIds','JournalRoot')
 if(($Policy.SchemaVersion -isnot [int] -and $Policy.SchemaVersion -isnot [long]) -or $Policy.SchemaVersion -ne 1 -or $Policy.Repository -cnotmatch '\A[A-Za-z0-9][A-Za-z0-9_.-]{0,99}/[A-Za-z0-9][A-Za-z0-9_.-]{0,99}\z'){throw 'Policy repository.'}
 foreach($name in @('Repository','RepositoryId','MainBranch','DataBranch','WorkflowId','WorkflowPath','WorkflowSha256','SealerPath','SealerCommit','SealerSha256','VerifierSha256','TrustRootSha256','JournalRoot')){if($Policy[$name] -isnot [string]){throw 'Policy scalar type.'}}
 $null=Get-TfPublicationId $Policy.RepositoryId;$null=Get-TfPublicationId $Policy.WorkflowId
 foreach($name in @('MainBranch','DataBranch')){if($Policy[$name] -cnotmatch '\A[a-zA-Z0-9][a-zA-Z0-9_-]{0,63}\z'){throw 'Policy branch.'}}
 if($Policy.MainBranch -ceq $Policy.DataBranch){throw 'Separate data branch required.'}
 foreach($name in @('WorkflowPath','SealerPath')){if($Policy[$name] -cnotmatch '\A\.github/workflows/[a-zA-Z0-9_-]+\.yml\z'){throw 'Policy workflow.'}}
 foreach($name in @('WorkflowSha256','SealerSha256','VerifierSha256','TrustRootSha256')){Assert-TokenForgePublicationPlanHash $Policy[$name]}
 Assert-TokenForgePublicationPlanHash $Policy.SealerCommit -Length 40
 foreach($name in @('ProducerIds','ReviewerIds','MaintainerIds','ReaderIds')){
  if($Policy[$name] -isnot [array] -or $Policy[$name].Count -lt 1 -or $Policy[$name].Count -gt 20){throw 'Policy actors.'}
  foreach($id in $Policy[$name]){if($id -isnot [string]){throw 'Policy actor type.'};$null=Get-TfPublicationId $id}
  if(@($Policy[$name]|Sort-Object -Unique).Count -ne $Policy[$name].Count){throw 'Duplicate actor.'}
 }
 if($Policy.JournalRoot -isnot [string] -or $Policy.JournalRoot -cne [IO.Path]::GetFullPath($Policy.JournalRoot) -or -not [IO.Path]::IsPathFullyQualified($Policy.JournalRoot)){throw 'Policy journal root.'}
}
function Copy-TfPublicationInput([string]$Source,[string]$Target,[long]$Maximum) {
 $sourcePath=[TokenForge.Core.V0220.PrivateFiles]::Resolve([IO.Path]::GetFullPath($Source),$false)
 $input=[IO.File]::Open($sourcePath,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::None)
 $output=$null
 try{
  $length=$input.Length;if($length -lt 1 -or $length -gt $Maximum){throw 'Input bound.'}
  $output=[TokenForge.Core.V0220.PrivateFiles]::Open($Target,$true);$buffer=[byte[]]::new(8192);$total=0L
  while(($n=$input.Read($buffer,0,$buffer.Length)) -gt 0){if(($total+=$n) -gt $Maximum){throw 'Input grew beyond bound.'};$output.Write($buffer,0,$n)}
  if($total -ne $length){throw 'Input changed size.'};$output.Flush($true)
 }finally{if($output){$output.Dispose()};$input.Dispose()}
}
function Save-TfPublicationLedger([string]$StatePath,$Ledger) {
 $bytes=[Text.Encoding]::UTF8.GetBytes((ConvertTo-Json -InputObject $Ledger -Depth 10 -Compress))
 if($bytes.Length -gt 16KB){throw 'Journal size bound; do not reset.'}
 $mode=if(Test-Path -LiteralPath $StatePath){'Update'}else{'Create'}
 $transaction=[TokenForge.Core.V0220.VaultFileTransaction]::Begin($StatePath,$mode)
 try{if($mode -ceq 'Update'){$null=$transaction.ReadEnvelope()};$transaction.Commit($bytes)}finally{$transaction.Dispose()}
}
function Expand-TfPublicationArchive([string]$Archive,[string]$Output) {
 $zip=[IO.Compression.ZipFile]::OpenRead($Archive);$seen=[Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase);$total=0L
 try{
  if($zip.Entries.Count -ne 7){throw 'Seven files required.'}
  foreach($entry in $zip.Entries){
   if($entry.FullName -cnotin @('manifest.json','coverage.json','flows.json','recipe.json','review.md','scopes.json','validation.json') -or -not $seen.Add($entry.FullName) -or $entry.Length -gt 8MB -or ($total+=$entry.Length) -gt 8MB -or (($entry.ExternalAttributes -shr 16) -band 0xf000) -notin @(0,0x8000)){throw 'Archive layout or size.'}
   $input=$entry.Open();$target=[TokenForge.Core.V0220.PrivateFiles]::Open((Join-Path $Output $entry.FullName),$true);$buffer=[byte[]]::new(8192);$written=0L
   try{while(($n=$input.Read($buffer,0,$buffer.Length)) -gt 0){if(($written+=$n) -gt $entry.Length){throw 'Archive expansion bound.'};$target.Write($buffer,0,$n)};if($written -ne $entry.Length){throw 'Archive truncation.'};$target.Flush($true)}finally{$target.Dispose();$input.Dispose()}
  }
 }finally{$zip.Dispose()}
}
function Assert-TfPublicationAttestation($Results,$Policy,[string]$Source,[string]$Run,[string]$Attempt,[string]$Digest) {
 if($Results -isnot [array] -or $Results.Count -ne 1){throw 'One verified sealing attestation required.'}
 $v=$Results[0].verificationResult;$c=$v.signature.certificate;$repo='https://github.com/'+$Policy.Repository
 $expected=@{issuer='https://token.actions.githubusercontent.com';sourceRepositoryURI=$repo;sourceRepositoryIdentifier=$Policy.RepositoryId;sourceRepositoryDigest=$Source;sourceRepositoryRef=('refs/heads/'+$Policy.MainBranch);buildSignerURI=($repo+'/'+$Policy.SealerPath+'@'+$Policy.SealerCommit);buildSignerDigest=$Policy.SealerCommit;runInvocationURI=($repo+'/actions/runs/'+$Run+'/attempts/'+$Attempt);runnerEnvironment='github-hosted'}
 foreach($field in $expected.Keys){if($c[$field] -isnot [string] -or $c[$field] -cne $expected[$field]){throw 'Sealing identity mismatch.'}}
 if($v.statement.predicateType -cne 'https://slsa.dev/provenance/v1' -or $v.statement.subject -isnot [array] -or $v.statement.subject.Count -ne 1 -or $v.statement.subject[0].digest.sha256 -cne $Digest -or $v.verifiedTimestamps -isnot [array] -or -not $v.verifiedTimestamps.Count){throw 'Sealing content mismatch.'}
}
function Get-TfPublicationTree($Context,[string]$Sha) {
 Assert-TokenForgePublicationPlanHash $Sha -Length 40
 $tree=Invoke-TfPublicationHttp $Context ($Context.Api+'/git/trees/'+$Sha+'?recursive=1')
 if($tree.sha -cne $Sha -or $tree.truncated -isnot [bool] -or $tree.truncated -ne $false -or $tree.tree -isnot [array] -or $tree.tree.Count -gt 10000){throw 'Incomplete tree.'}
 $map=[Collections.Generic.Dictionary[string,object]]::new([StringComparer]::Ordinal)
 foreach($entry in $tree.tree){
  if($entry.path -isnot [string] -or $entry.path.Length -gt 1024 -or $entry.path -match '(^/|\\|\x00|(^|/)\.\.?(/|$))' -or $map.ContainsKey($entry.path)){throw 'Tree path.'}
  Assert-TokenForgePublicationPlanHash $entry.sha -Length 40
  if(($entry.type -ceq 'tree' -and $entry.mode -ceq '040000') -or ($entry.type -ceq 'blob' -and $entry.mode -cin @('100644','100755','120000')) -or ($entry.type -ceq 'commit' -and $entry.mode -ceq '160000')){$map.Add($entry.path,$entry)}else{throw 'Tree mode.'}
 };return ,$map
}
function Assert-TfPublicationCommit($Context,$Approval,[string]$Candidate) {
 $old=Invoke-TfPublicationHttp $Context ($Context.Api+'/git/commits/'+$Approval.ExpectedParent)
 $new=Invoke-TfPublicationHttp $Context ($Context.Api+'/git/commits/'+$Approval.ProposedCommit)
 if($old.sha -cne $Approval.ExpectedParent -or $new.sha -cne $Approval.ProposedCommit -or $new.parents -isnot [array] -or $new.parents.Count -ne 1 -or $new.parents[0].sha -cne $Approval.ExpectedParent){throw 'Commit parent mismatch.'}
 $before=Get-TfPublicationTree $Context $old.tree.sha;$after=Get-TfPublicationTree $Context $new.tree.sha;$prefix='candidates/'+$Approval.CandidateHash
 $permitted=@('candidates',$prefix)
 foreach($key in $before.Keys){
  if($key -ceq $prefix -or $key.StartsWith($prefix+'/',[StringComparison]::Ordinal)){throw 'Candidate destination already exists.'}
  if(-not $after.ContainsKey($key)){throw 'Unrelated deletion.'}
  $a=$before[$key];$b=$after[$key]
  if($a.type -cne $b.type -or $a.mode -cne $b.mode -or ($key -cne 'candidates' -and $a.sha -cne $b.sha)){throw 'Unrelated change.'}
 }
 $leaves=0
 foreach($key in $after.Keys){
  if($before.ContainsKey($key)){continue};$entry=$after[$key]
  if($key -cin $permitted){if($entry.type -cne 'tree' -or $entry.mode -cne '040000'){throw 'Destination mode.'};continue}
  if(-not $key.StartsWith($prefix+'/',[StringComparison]::Ordinal)){throw 'Unrelated addition.'}
  $name=$key.Substring($prefix.Length+1)
  if($name -cnotin @('manifest.json','coverage.json','flows.json','recipe.json','review.md','scopes.json','validation.json') -or $entry.mode -cne '100644' -or $entry.type -cne 'blob' -or $entry.sha -cne (Get-TfPublicationBlobHash ([IO.File]::ReadAllBytes((Join-Path $Candidate $name))))){throw 'Candidate blob mismatch.'};$leaves++
 }
 if($leaves -ne 7 -or -not $after.ContainsKey($prefix) -or -not $after.ContainsKey('candidates')){throw 'Incomplete candidate tree.'}
}
function Get-TfPublicationPermission($Context,$Actor,[string[]]$Allowed,[string[]]$Roles) {
 $id=Get-TfPublicationId $Actor.id
 if($Actor.login -isnot [string] -or $Actor.type -isnot [string] -or $id -cnotin $Allowed -or $Actor.type -cne 'User' -or $Actor.login -cnotmatch '\A[A-Za-z0-9][A-Za-z0-9-]{0,38}\z'){throw 'Actor not approved.'}
 $permission=Invoke-TfPublicationHttp $Context ($Context.Api+'/collaborators/'+$Actor.login+'/permission')
 if((Get-TfPublicationId $permission.user.id) -cne $id -or $permission.user.login -cne $Actor.login -or $permission.permission -cnotin $Roles){throw 'Current actor permission refused.'}
 $id
}
function Get-TfPublicationApproval($Context,[string]$CommentId,[string]$Pull,[string]$Role,[string[]]$Allowed,[string[]]$Roles,$Comments) {
 $comment=Invoke-TfPublicationHttp $Context ($Context.Api+'/issues/comments/'+$CommentId)
 if((Get-TfPublicationId $comment.id) -cne $CommentId -or $comment.issue_url -cne ('https://api.github.com'+$Context.Api+'/issues/'+$Pull) -or $comment.created_at -isnot [string] -or $comment.created_at -cne $comment.updated_at){throw 'Approval edited or misplaced.'}
 $actor=Get-TfPublicationPermission $Context $comment.user $Allowed $Roles
 $listed=@($Comments|Where-Object {([string]$_.id) -ceq $CommentId})
 if($listed.Count -ne 1 -or $listed[0].body -cne $comment.body -or $listed[0].updated_at -cne $comment.updated_at -or ([string]$listed[0].user.id) -cne $actor){throw 'Approval stream mismatch.'}
 foreach($other in $Comments){if(([string]$other.user.id) -ceq $actor -and [long]$other.id -gt [long]$CommentId){throw 'Approval superseded.'}}
 if($comment.body -isnot [string] -or $comment.body.Length -gt 16KB){throw 'Approval body bound.'}
 $approval=Read-TokenForgePublicationPlanJson $comment.body
 Assert-TokenForgePermissionFields $approval @('SchemaVersion','Kind','PolicySha256','RepositoryId','Ref','Mapping','CandidateHash','ArtifactId','ArtifactSha256','SourceCommit','ProducerRunId','ProducerAttempt','ExpectedParent','ProposedCommit','CreatedAt','ExpiresAt','Decision')
 foreach($key in $approval.Keys){if($key -cne 'SchemaVersion' -and $approval[$key] -isnot [string]){throw 'Approval scalar type.'}}
 if(($approval.SchemaVersion -isnot [int] -and $approval.SchemaVersion -isnot [long]) -or $approval.SchemaVersion -ne 1 -or $approval.Kind -cne 'TokenForgePublicationApprovalV2' -or $approval.Decision -cne 'Approved' -or $approval.PolicySha256 -cne $Context.PolicyHash -or $approval.RepositoryId -cne $Context.Policy.RepositoryId -or $approval.Ref -cne ('refs/heads/'+$Context.Policy.DataBranch) -or $approval.Mapping -cne 'CandidateDirectoryV1'){throw 'Approval policy mismatch.'}
 foreach($name in @('CandidateHash','ArtifactSha256')){Assert-TokenForgePublicationPlanHash $approval[$name]}
 foreach($name in @('SourceCommit','ExpectedParent','ProposedCommit')){Assert-TokenForgePublicationPlanHash $approval[$name] -Length 40}
 foreach($name in @('ArtifactId','ProducerRunId','ProducerAttempt')){if($approval[$name] -isnot [string]){throw 'Approval ID type.'};$null=Get-TfPublicationId $approval[$name]}
 $created=Read-TokenForgePublicationPlanTime $approval.CreatedAt;$expires=Read-TokenForgePublicationPlanTime $approval.ExpiresAt
 if($created -gt (Get-TfPublicationNow $Context) -or $expires -le $created -or ($expires-$created).TotalHours -gt 24 -or [DateTimeOffset]::Parse($comment.created_at) -gt (Get-TfPublicationNow $Context) -or [DateTimeOffset]::Parse($comment.created_at) -lt $created -or [DateTimeOffset]::Parse($comment.created_at) -ge $expires){throw 'Approval time mismatch.'}
 @{Actor=$actor;Approval=$approval;Body=$comment.body;Created=$created;Expires=$expires;CommentId=$CommentId;Role=$Role}
}
function Assert-TfPublicationProposal($Pr,$Policy,[string]$Pull,[string]$Head) {
 if((Get-TfPublicationId $Pr.number) -cne $Pull -or $Pr.state -isnot [string] -or $Pr.state -cne 'open' -or $Pr.draft -isnot [bool] -or $Pr.draft -or $Pr.merged -isnot [bool] -or $Pr.merged -or (Get-TfPublicationId $Pr.base.repo.id) -cne $Policy.RepositoryId -or (Get-TfPublicationId $Pr.head.repo.id) -cne $Policy.RepositoryId -or $Pr.base.ref -isnot [string] -or $Pr.base.ref -cne $Policy.DataBranch){throw 'Proposal mismatch.'}
 Assert-TokenForgePublicationPlanHash $Pr.head.sha -Length 40
 if($Head -and $Pr.head.sha -cne $Head){throw 'Proposal head changed.'}
}
function Assert-TfPublicationMain($Main,$Protection,[string]$Source) {
 if($Main.commit.sha -isnot [string] -or $Main.commit.sha -cne $Source -or $Main.protected -isnot [bool] -or -not $Main.protected -or $Protection.enforce_admins.enabled -isnot [bool] -or -not $Protection.enforce_admins.enabled -or $Protection.required_pull_request_reviews.dismiss_stale_reviews -isnot [bool] -or -not $Protection.required_pull_request_reviews.dismiss_stale_reviews -or ($Protection.required_pull_request_reviews.required_approving_review_count -isnot [long] -and $Protection.required_pull_request_reviews.required_approving_review_count -isnot [int]) -or $Protection.required_pull_request_reviews.required_approving_review_count -lt 1){throw 'Current main/protection mismatch.'}
}
function Invoke-TokenForgePublicationVerification {
 <# .SYNOPSIS
 Verify an existing publication proposal. No remote write is performed or authorized.
 .DESCRIPTION
 Synthetic transports never establish authority. Live mode needs an explicitly supplied
 token and pinned attestation verifier; it consults no ambient GitHub credentials.
 A future writer must repeat verification and perform an exact expected-old CAS.
 #>
 [CmdletBinding(DefaultParameterSetName='Live')]
 param(
  [Parameter(Mandatory)][string]$PolicyPath,[Parameter(Mandatory)][string]$PolicySha256,
  [Parameter(Mandatory)][string]$ArchivePath,
  [Parameter(Mandatory)][ValidatePattern('^[1-9][0-9]{0,18}$')][string]$PullRequest,
  [Parameter(Mandatory)][ValidatePattern('^[1-9][0-9]{0,18}$')][string]$ReviewerComment,
  [Parameter(Mandatory)][ValidatePattern('^[1-9][0-9]{0,18}$')][string]$MaintainerComment,
  [Parameter(Mandatory,ParameterSetName='Live')][securestring]$AccessToken,
  [Parameter(Mandatory,ParameterSetName='Live')][string]$VerifierPath,
  [Parameter(Mandatory,ParameterSetName='Live')][string]$AttestationBundlePath,
  [Parameter(Mandatory,ParameterSetName='Live')][string]$TrustRootPath,
  [Parameter(Mandatory,ParameterSetName='Synthetic')][switch]$Synthetic,
  [Parameter(Mandatory,ParameterSetName='Synthetic')][scriptblock]$ReadFixture,
  [Parameter(Mandatory,ParameterSetName='Synthetic')][scriptblock]$VerifyFixtureAttestation,
  [Parameter(Mandatory,ParameterSetName='Synthetic')][DateTimeOffset]$FixtureTime
 )
 $ErrorActionPreference='Stop';$stage='Inputs';$lock=$null;$scratch=$null
 try{
  if(-not $IsLinux){throw 'Linux validation only.'}
  Assert-TokenForgePublicationPlanHash $PolicySha256
  $PolicyPath=[TokenForge.Core.V0220.PrivateFiles]::Resolve([IO.Path]::GetFullPath($PolicyPath),$false)
  # Hash and parse one bounded snapshot, never reopen the policy after pinning it.
  $policyStream=[IO.File]::Open($PolicyPath,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::None)
  try{
   if($policyStream.Length -lt 1 -or $policyStream.Length -gt 16KB){throw 'Policy bound.'}
   $policyBytes=[byte[]]::new($policyStream.Length);$policyStream.ReadExactly($policyBytes,0,$policyBytes.Length)
   if($policyStream.ReadByte() -ne -1){throw 'Policy grew beyond snapshot.'}
  }finally{$policyStream.Dispose()}
  if([Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($policyBytes)).ToLowerInvariant() -cne $PolicySha256){throw 'Policy pin mismatch.'}
  $policy=Read-TfPublicationJson $policyBytes;Assert-TfPublicationPolicy $policy
  $ArchivePath=[TokenForge.Core.V0220.PrivateFiles]::Resolve([IO.Path]::GetFullPath($ArchivePath),$false)
  if((Get-Item -LiteralPath $ArchivePath).Length -gt 8MB){throw 'Archive bound.'}
  $stateRoot=Join-Path $policy.JournalRoot ($policy.RepositoryId+'-'+$policy.DataBranch)
  $statePath=[TokenForge.Core.V0220.PrivateFiles]::Resolve((Join-Path $stateRoot 'publication.json'),$true)
  $lockPath=Join-Path $stateRoot '.writer.lock';$lock=[TokenForge.Core.V0220.PrivateFiles]::Open($lockPath,-not (Test-Path -LiteralPath $lockPath))
  $scratch=Join-Path $stateRoot ('.verify-'+[guid]::NewGuid().ToString('N'));$null=[IO.Directory]::CreateDirectory($scratch,[IO.UnixFileMode]448)
  $archive=Join-Path $scratch candidate.zip
  Copy-TfPublicationInput $ArchivePath $archive 8MB
  if($PSCmdlet.ParameterSetName -ceq 'Live'){
   Copy-TfPublicationInput $AttestationBundlePath (Join-Path $scratch bundle.json) 4MB
   Copy-TfPublicationInput $TrustRootPath (Join-Path $scratch trusted-root.json) 256KB
   if((Get-TfCandidateFileHash (Join-Path $scratch trusted-root.json)) -cne $policy.TrustRootSha256){throw 'Untrusted root.'}
  }
  $archiveHash=Get-TfCandidateFileHash $archive
  $context=@{Policy=$policy;PolicyHash=$PolicySha256;Api=('/repos/'+$policy.Repository);Synthetic=($PSCmdlet.ParameterSetName -ceq 'Synthetic');ReadFixture=$ReadFixture;VerifyFixture=$VerifyFixtureAttestation;FixtureTime=$FixtureTime;Token=$AccessToken;VerifierPath=$VerifierPath;BundlePath=(Join-Path $scratch bundle.json);TrustRootPath=(Join-Path $scratch trusted-root.json);Requests=0;Bytes=0L;Watch=[Diagnostics.Stopwatch]::StartNew()}
  $ledger=@{SchemaVersion=1;Synthetic=$context.Synthetic;RepositoryId=$policy.RepositoryId;Ref=('refs/heads/'+$policy.DataBranch);PolicySha256=$PolicySha256;Records=@()}
  $marker=Join-Path $stateRoot '.initialized'
  $null=[TokenForge.Core.V0220.PrivateFiles]::Resolve($marker,$false)
  if((Test-Path -LiteralPath $marker) -and -not (Test-Path -LiteralPath $statePath)){throw 'Missing canonical journal; do not reset.'}
  if(Test-Path -LiteralPath $statePath){
   $null=[TokenForge.Core.V0220.PrivateFiles]::Resolve($statePath,$false)
   if((Get-Item -LiteralPath $statePath).Length -gt 1MB){throw 'Journal bound.'}
   $ledger=Read-TokenForgePublicationPlanJson ([IO.File]::ReadAllText($statePath))
   Assert-TokenForgePermissionFields $ledger @('SchemaVersion','Synthetic','RepositoryId','Ref','PolicySha256','Records')
   if($ledger.Synthetic -isnot [bool] -or $ledger.Synthetic -ne $context.Synthetic -or $ledger.SchemaVersion -ne 1 -or $ledger.RepositoryId -cne $policy.RepositoryId -or $ledger.Ref -cne ('refs/heads/'+$policy.DataBranch) -or $ledger.PolicySha256 -cne $PolicySha256 -or $ledger.Records -isnot [array] -or $ledger.Records.Count -gt 100){throw 'Journal context mismatch.'}
  }
  $stage='Repository';$repo=Invoke-TfPublicationHttp $context $context.Api
  if((Get-TfPublicationId $repo.id) -cne $policy.RepositoryId -or $repo.full_name -cne $policy.Repository -or $repo.default_branch -cne $policy.MainBranch -or $repo.archived -isnot [bool] -or $repo.archived -ne $false -or $repo.disabled -isnot [bool] -or $repo.disabled -ne $false){throw 'Repository mismatch.'}
  $reader=Invoke-TfPublicationHttp $context '/user';$readerId=Get-TfPublicationPermission $context $reader $policy.ReaderIds @('admin','maintain')
  $stage='Proposal';$pr=Invoke-TfPublicationHttp $context ($context.Api+'/pulls/'+$PullRequest)
  Assert-TfPublicationProposal $pr $policy $PullRequest
  $stage='Approvals';$comments=Invoke-TfPublicationHttp $context ($context.Api+'/issues/'+$PullRequest+'/comments?per_page=100')
  if($comments -isnot [array] -or $comments.Count -gt 100){throw 'Approval stream bound.'}
  $review=Get-TfPublicationApproval $context $ReviewerComment $PullRequest Candidate $policy.ReviewerIds @('write','maintain','admin') $comments
  $main=Get-TfPublicationApproval $context $MaintainerComment $PullRequest Main $policy.MaintainerIds @('admin','maintain') $comments
  $approval=$review.Approval
  if($review.Body -cne $main.Body -or $review.Actor -ceq $main.Actor -or $review.Actor -ceq $readerId -or $main.Actor -ceq $readerId -or $ReviewerComment -ceq $MaintainerComment -or $pr.head.sha -cne $approval.ProposedCommit){throw 'Independent approvals differ.'}
  $stage='Producer';$run=Invoke-TfPublicationHttp $context ($context.Api+'/actions/runs/'+$approval.ProducerRunId)
  if((Get-TfPublicationId $run.id) -cne $approval.ProducerRunId -or (Get-TfPublicationId $run.run_attempt) -cne $approval.ProducerAttempt -or (Get-TfPublicationId $run.workflow_id) -cne $policy.WorkflowId -or $run.head_sha -cne $approval.SourceCommit -or $run.head_branch -cne $policy.MainBranch -or $run.path -cne $policy.WorkflowPath -or $run.event -cne 'workflow_dispatch' -or $run.status -cne 'completed' -or $run.conclusion -cne 'success' -or (Get-TfPublicationId $run.repository.id) -cne $policy.RepositoryId -or (Get-TfPublicationId $run.head_repository.id) -cne $policy.RepositoryId){throw 'Producer run mismatch.'}
  $actor=Get-TfPublicationId $run.actor.id;$trigger=Get-TfPublicationId $run.triggering_actor.id;$proposer=Get-TfPublicationId $pr.user.id
  if($actor -cnotin $policy.ProducerIds -or $trigger -cnotin $policy.ProducerIds -or $review.Actor -cin @($actor,$trigger,$proposer) -or $main.Actor -cin @($actor,$trigger,$proposer)){throw 'Producer/reviewer separation.'}
  $stage='Artifact';$artifact=Invoke-TfPublicationHttp $context ($context.Api+'/actions/artifacts/'+$approval.ArtifactId)
  if((Get-TfPublicationId $artifact.id) -cne $approval.ArtifactId -or $artifact.digest -cne ('sha256:'+$approval.ArtifactSha256) -or $archiveHash -cne $approval.ArtifactSha256 -or $artifact.size_in_bytes -isnot [long] -or $artifact.size_in_bytes -ne (Get-Item -LiteralPath $archive).Length -or (Get-TfPublicationId $artifact.workflow_run.id) -cne $approval.ProducerRunId -or (Get-TfPublicationId $artifact.workflow_run.repository_id) -cne $policy.RepositoryId -or (Get-TfPublicationId $artifact.workflow_run.head_repository_id) -cne $policy.RepositoryId -or $artifact.workflow_run.head_sha -cne $approval.SourceCommit -or $artifact.workflow_run.head_branch -cne $policy.MainBranch -or $artifact.expired -isnot [bool]){throw 'Artifact mismatch.'}
  $stage='Source';$mainRef=Invoke-TfPublicationHttp $context ($context.Api+'/branches/'+$policy.MainBranch)
  $protection=Invoke-TfPublicationHttp $context ($context.Api+'/branches/'+$policy.MainBranch+'/protection')
  Assert-TfPublicationMain $mainRef $protection $approval.SourceCommit
  $compare=Invoke-TfPublicationHttp $context ($context.Api+'/compare/'+$policy.SealerCommit+'...'+$approval.SourceCommit)
  if($compare.status -cnotin @('ahead','identical') -or $compare.merge_base_commit.sha -cne $policy.SealerCommit){throw 'Sealer not on trusted main history.'}
  foreach($source in @(@{Path=$policy.WorkflowPath;Commit=$approval.SourceCommit;Digest=$policy.WorkflowSha256},@{Path=$policy.SealerPath;Commit=$policy.SealerCommit;Digest=$policy.SealerSha256})){
   $content=Invoke-TfPublicationHttp $context ($context.Api+'/contents/'+$source.Path+'?ref='+$source.Commit)
   if($content.type -cne 'file' -or $content.encoding -cne 'base64' -or $content.path -cne $source.Path -or $content.content -isnot [string] -or $content.content.Length -gt 128KB){throw 'Workflow content.'}
   $bytes=[Convert]::FromBase64String($content.content)
   if((Get-TfPublicationBlobHash $bytes) -cne $content.sha -or [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($bytes)).ToLowerInvariant() -cne $source.Digest){throw 'Audited workflow changed.'}
  }
  $stage='Attestation';$verified=Invoke-TfPublicationAttestation $context $archive $approval.SourceCommit $scratch
  Assert-TfPublicationAttestation $verified $policy $approval.SourceCommit $approval.ProducerRunId $approval.ProducerAttempt $archiveHash
  $stage='Candidate';$candidate=Join-Path $scratch candidate;$null=[IO.Directory]::CreateDirectory($candidate,[IO.UnixFileMode]448)
  Expand-TfPublicationArchive $archive $candidate
  $manifest=Assert-TfDiscoveryCandidate $candidate $approval.CandidateHash
  if($manifest.SourceCommit -cne $approval.SourceCommit -or $manifest.ProducerRunId -cne $approval.ProducerRunId -or $manifest.ProducerAttempt -cne $approval.ProducerAttempt){throw 'Candidate/producer mismatch.'}
  $stage='Commit';Assert-TfPublicationCommit $context $approval $candidate
  $stage='Journal';$transaction=Get-TfCandidateHash ([ordered]@{Policy=$PolicySha256;ReviewerComment=$ReviewerComment;MaintainerComment=$MaintainerComment;Reviewer=$review.Actor;Maintainer=$main.Actor;ApprovalBodySha256=(Get-TokenForgePublicationPlanHash $review.Body)})
  $previous=@($ledger.Records|Where-Object Transaction -CEQ $transaction)
  if($previous.Count -gt 1){throw 'Ambiguous journal.'}
  foreach($record in $ledger.Records){
   Assert-TokenForgePermissionFields $record @('Transaction','ReviewerComment','MaintainerComment','ProposedCommit','ExpectedParent','PreparedBeforeObservation','Applied')
   Assert-TokenForgePublicationPlanHash $record.Transaction;Assert-TokenForgePublicationPlanHash $record.ProposedCommit -Length 40;Assert-TokenForgePublicationPlanHash $record.ExpectedParent -Length 40
   if($record.PreparedBeforeObservation -isnot [bool] -or $record.Applied -isnot [bool] -or (($record.ReviewerComment -ceq $ReviewerComment -or $record.MaintainerComment -ceq $MaintainerComment) -and $record.Transaction -cne $transaction)){throw 'Approval replay.'}
  }
  $stage='FinalObservations'
  # A final read pass closes ordinary metadata races, but is not atomic with a future CAS.
  foreach($id in @($ReviewerComment,$MaintainerComment)){
   $comment=Invoke-TfPublicationHttp $context ($context.Api+'/issues/comments/'+$id)
   $original=if($id -ceq $ReviewerComment){$review}else{$main}
   if($comment.body -cne $original.Body -or $comment.created_at -cne $comment.updated_at -or ([string]$comment.user.id) -cne $original.Actor){throw 'Approval changed during verification.'}
   $allowed=if($id -ceq $ReviewerComment){$policy.ReviewerIds}else{$policy.MaintainerIds};$roles=if($id -ceq $ReviewerComment){@('write','maintain','admin')}else{@('admin','maintain')}
   $null=Get-TfPublicationPermission $context $comment.user $allowed $roles
  }
  $finalComments=Invoke-TfPublicationHttp $context ($context.Api+'/issues/'+$PullRequest+'/comments?per_page=100')
  if($finalComments -isnot [array] -or $finalComments.Count -gt 100){throw 'Approval stream changed.'}
  foreach($actorApproval in @($review,$main)){
   if(@($finalComments|Where-Object {([string]$_.id) -ceq $actorApproval.CommentId -and $_.body -ceq $actorApproval.Body -and $_.created_at -ceq $_.updated_at -and ([string]$_.user.id) -ceq $actorApproval.Actor}).Count -ne 1 -or @($finalComments|Where-Object {([string]$_.user.id) -ceq $actorApproval.Actor -and [long]$_.id -gt [long]$actorApproval.CommentId}).Count){throw 'Approval revoked during verification.'}
  }
  $finalMain=Invoke-TfPublicationHttp $context ($context.Api+'/branches/'+$policy.MainBranch)
  $finalPr=Invoke-TfPublicationHttp $context ($context.Api+'/pulls/'+$PullRequest)
  $finalProtection=Invoke-TfPublicationHttp $context ($context.Api+'/branches/'+$policy.MainBranch+'/protection')
  Assert-TfPublicationMain $finalMain $finalProtection $approval.SourceCommit
  Assert-TfPublicationProposal $finalPr $policy $PullRequest $approval.ProposedCommit
  if((Get-TfPublicationId $finalPr.user.id) -cne $proposer){throw 'Proposal author changed.'}
  $null=Get-TfPublicationPermission $context $reader $policy.ReaderIds @('admin','maintain')
  $finalRun=Invoke-TfPublicationHttp $context ($context.Api+'/actions/runs/'+$approval.ProducerRunId)
  if((Get-TfPublicationId $finalRun.id) -cne $approval.ProducerRunId -or (Get-TfPublicationId $finalRun.run_attempt) -cne $approval.ProducerAttempt -or $finalRun.status -cne 'completed' -or $finalRun.conclusion -cne 'success' -or $finalRun.head_sha -cne $approval.SourceCommit){throw 'Producer changed.'}
  $finalArtifact=Invoke-TfPublicationHttp $context ($context.Api+'/actions/artifacts/'+$approval.ArtifactId)
  if((Get-TfCandidateHash $finalArtifact) -cne (Get-TfCandidateHash $artifact)){throw 'Artifact changed.'}

  $ref=Invoke-TfPublicationHttp $context ($context.Api+'/git/ref/heads/'+$policy.DataBranch)
  if($ref.ref -cne ('refs/heads/'+$policy.DataBranch) -or $ref.object.type -cne 'commit'){throw 'Data ref mismatch.'}
  Assert-TokenForgePublicationPlanHash $ref.object.sha -Length 40
  Test-TfPublicationBudget $context;$now=Get-TfPublicationNow $context
  $verdict=if($ref.object.sha -ceq $approval.ProposedCommit){if($previous.Count -and $previous[0].PreparedBeforeObservation){'AlreadyApplied'}else{'ObservedProposedWithoutPreparedState'}}elseif($previous.Count -and $previous[0].Applied){'ConsumedApproval'}elseif($ref.object.sha -cne $approval.ExpectedParent){'StaleParent'}elseif($artifact.expired -or $now -ge [DateTimeOffset]::Parse($artifact.expires_at) -or $now -ge $review.Expires -or $now -ge $main.Expires){'Expired'}else{'VerifiedForSeparateWriterReview'}
  if($previous.Count -and ($previous[0].ProposedCommit -cne $approval.ProposedCommit -or $previous[0].ExpectedParent -cne $approval.ExpectedParent)){throw 'Journal binding changed.'}
  if($previous.Count){if($ref.object.sha -ceq $approval.ProposedCommit){$previous[0].Applied=$true}}
  elseif($verdict -cin @('VerifiedForSeparateWriterReview','ObservedProposedWithoutPreparedState')){
   if($ledger.Records.Count -ge 100){throw 'Journal retention bound; do not reset.'}
   $ledger.Records+=@(@{Transaction=$transaction;ReviewerComment=$ReviewerComment;MaintainerComment=$MaintainerComment;ProposedCommit=$approval.ProposedCommit;ExpectedParent=$approval.ExpectedParent;PreparedBeforeObservation=($verdict -ceq 'VerifiedForSeparateWriterReview');Applied=($ref.object.sha -ceq $approval.ProposedCommit)})
  }
  $stage='Persist';Save-TfPublicationLedger $statePath $ledger
  if(-not (Test-Path -LiteralPath $marker)){$file=[TokenForge.Core.V0220.PrivateFiles]::Open($marker,$true);try{$file.Flush($true)}finally{$file.Dispose()}}
  [pscustomobject]@{SchemaVersion=1;Kind='TokenForgeTrustedPublicationVerification';Verdict=$verdict;Synthetic=$context.Synthetic;AuthorizationEstablished=$false;PublishAllowed=$false;RemoteMutationPerformed=$false;HostedExecutionProof=$false;ObservedAuthorityFromAuthenticatedApi=(-not $context.Synthetic);Transaction=$transaction;PolicySha256=$PolicySha256;CandidateHash=$approval.CandidateHash;ArchiveSha256=$archiveHash;RepositoryId=$policy.RepositoryId;Ref=$approval.Ref;ExpectedParent=$approval.ExpectedParent;ProposedCommit=$approval.ProposedCommit;ObservedParent=$ref.object.sha;Requests=$context.Requests;ResponseBytes=$context.Bytes;NextStep='SeparateApprovalAndFreshVerificationPlusExactExpectedOldCASRequired'}
 }catch{throw ('Publication verification failed at '+$stage+'; no remote write performed.')}
 finally{
  $cleanupFailed=$false
  try{if($scratch -and (Test-Path -LiteralPath $scratch)){Remove-Item -LiteralPath $scratch -Recurse -Force}}catch{$cleanupFailed=$true}
  finally{if($lock){try{$lock.Dispose()}catch{$cleanupFailed=$true}}}
  if($cleanupFailed){throw 'Publication verification cleanup failed; inspect saved handoff before retry; no remote write performed.'}
 }
}
