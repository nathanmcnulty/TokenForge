#Requires -Version 7.6
# Manual synthetic service experiment, not the production authorization entry point.
param([Parameter(Mandatory)][string]$Evidence,[switch]$DiagnosticOnly)
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
if($env:GITHUB_REPOSITORY -cne 'nathanmcnulty/TokenForge' -or $env:GITHUB_REF -cne 'refs/heads/codex/issue113-publication-acceptance' -or $env:GITHUB_RUN_ID -cnotmatch '\A[1-9][0-9]{0,18}\z'){throw 'Synthetic workflow context required.'}
$directory=Get-Item -LiteralPath $Evidence
$subject=Get-Content -Raw -LiteralPath (Join-Path $directory subject.json)|ConvertFrom-Json
$verification=Get-Content -Raw -LiteralPath (Join-Path $directory verification-checks.json)|ConvertFrom-Json
if($subject.OriginalArchiveSha256 -cne '47e533aa04a2683affa3ba709bd03441c26081c172664d99e7e41b905b89be08' -or $subject.CandidateHash -cne 'd43102cb46f2eb64ec43605c933f35e457b89ba14fbf587aea930a562b192568' -or $subject.SourceCommit -cne '7b6e62223944d99edde3b648749125247578e559' -or $subject.ArtifactId -cne '13479301224' -or $subject.ProducerRunId -cne '42166462125' -or $subject.ProducerAttempt -cne '1' -or -not $verification.OfflineNetworkNamespace -or -not $verification.CredentialFreeVerifier -or $verification.Checks[0].ActualExitCode -ne 0 -or $verification.Checks[1].ActualExitCode -ne 1){throw 'Reviewed signed public candidate required.'}
# Import only these existing pure/transport functions; do not load the module,
# native compilation path, policy planner or production approval facade.
$imports=@{
 'TokenForgePublicationWriter.ps1'=@('ConvertTo-TfGitPacket','Read-TfGitPackets','Assert-TfGitAdvertisement','New-TfGitUpdate','Read-TfGitAcknowledgement','Invoke-TfPublicationGitHttp','Update-TfPublicationWriterObservation')
 'TokenForgePublicationAdapter.ps1'=@('Test-TfPublicationBudget')
 'TokenForgePublicationRecovery.ps1'=@('Assert-TokenForgePublicationPlanHash')
}
foreach($file in $imports.Keys){
 $errors=$null;$tokens=$null;$ast=[Management.Automation.Language.Parser]::ParseFile((Join-Path $PSScriptRoot $file),[ref]$tokens,[ref]$errors)
 if($errors.Count){throw 'Source parse failed.'}
 foreach($name in $imports[$file]){
  $nodes=@($ast.FindAll({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -ceq $name},$true))
  if($nodes.Count -ne 1){throw 'Exact transport function required.'}
  . ([scriptblock]::Create($nodes[0].Extent.Text))
 }
}
$token=ConvertTo-SecureString $env:GH_TOKEN -AsPlainText -Force
Remove-Item Env:GH_TOKEN
$script:requests=0;$script:apiWrites=0;$script:bytes=0L;$watch=[Diagnostics.Stopwatch]::StartNew()
$handler=[Net.Http.HttpClientHandler]::new();$handler.AllowAutoRedirect=$false;$handler.UseCookies=$false;$handler.UseProxy=$false
$client=[Net.Http.HttpClient]::new($handler);$client.Timeout=[TimeSpan]::FromSeconds(15)
$ref='refs/heads/tokenforge-publication-canary-'+$env:GITHUB_RUN_ID
function Invoke-CanaryApi([string]$Method,[string]$Route,$Body=$null){
 if($watch.Elapsed.TotalSeconds -ge 120 -or $script:requests -ge 24){throw 'Synthetic API budget exhausted.'}
 $allowedRead=@('','git/ref/heads/main',('git/ref/'+$ref.Substring(5)))
 if($Method -ceq 'GET'){
  if($Route -cnotin $allowedRead -and $Route -cnotmatch '\Agit/(commits/[a-f0-9]{40}|trees/[a-f0-9]{40}\?recursive=1)\z'){throw 'Read route refused.'}
 }elseif($Method -cne 'POST' -or $Route -cne 'git/refs'){throw 'Write route refused.'}
 if($Route -ceq 'git/refs' -and $Body.ref -cne $ref){throw 'Only new disposable ref allowed.'}
 $script:requests++
 if($Method -ceq 'POST'){if($script:apiWrites -ge 1){throw 'REST mutation ceiling.'};$script:apiWrites++}
 $uri='https://api.github.com/repos/nathanmcnulty/TokenForge'+$(if($Route){'/'+$Route})
 $request=[Net.Http.HttpRequestMessage]::new([Net.Http.HttpMethod]::new($Method),$uri)
 $cancel=[Threading.CancellationTokenSource]::new();$cancel.CancelAfter([TimeSpan]::FromSeconds(15))
 try{
  $request.Headers.UserAgent.ParseAdd('TokenForge-PublicSyntheticTest/1')
  $request.Headers.Authorization=[Net.Http.Headers.AuthenticationHeaderValue]::new('Bearer',([Net.NetworkCredential]::new('',$token).Password))
  $request.Headers.Accept.ParseAdd('application/vnd.github+json')
  if($null -ne $Body){$request.Content=[Net.Http.StringContent]::new(($Body|ConvertTo-Json -Depth 12 -Compress),[Text.Encoding]::UTF8,'application/json')}
  $response=$client.Send($request,[Net.Http.HttpCompletionOption]::ResponseHeadersRead,$cancel.Token)
  try{
   if([int]$response.StatusCode -notin @(200,201) -or $response.Content.Headers.ContentLength -gt 2MB){throw 'GitHub API refused; no retry.'}
   $stream=$response.Content.ReadAsStream();$memory=[IO.MemoryStream]::new();$buffer=[byte[]]::new(8192)
   try{
    while(($n=$stream.ReadAsync($buffer,0,$buffer.Length,$cancel.Token).GetAwaiter().GetResult()) -gt 0){
     if($watch.Elapsed.TotalSeconds -ge 120 -or $memory.Length+$n -gt 2MB -or $script:bytes+$memory.Length+$n -gt 8MB){throw 'Response bound.'}
     $memory.Write($buffer,0,$n)
    }
    $data=$memory.ToArray();$script:bytes+=$data.Length
   }finally{$stream.Dispose();$memory.Dispose()}
   return [Text.Encoding]::UTF8.GetString($data)|ConvertFrom-Json
  }finally{$response.Dispose()}
 }finally{$request.Dispose();$cancel.Dispose()}
}
function Save-CanaryIntent($Value){
 $path=Join-Path $directory 'transport-journal.json'
 $data=[Text.Encoding]::UTF8.GetBytes(($Value|ConvertTo-Json -Depth 12))
 $stream=[IO.File]::Open($path,[IO.FileMode]::Create,[IO.FileAccess]::Write,[IO.FileShare]::None)
 try{$stream.Write($data);$stream.Flush($true)}finally{$stream.Dispose()}
}
function New-CanaryContext {
 @{Policy=@{Repository='nathanmcnulty/TokenForge'};Synthetic=$false;Token=$token;GitRequests=0;Requests=0;Bytes=0L;Watch=[Diagnostics.Stopwatch]::StartNew();DeadlineSeconds=30;MaxRequests=2;MaxBytes=8MB}
}
try{
 $repo=Invoke-CanaryApi GET ''
 if($repo.id -ne 1402673320 -or $repo.full_name -cne 'nathanmcnulty/TokenForge' -or $repo.private){throw 'Public synthetic repository binding.'}
 $baseRef=Invoke-CanaryApi GET 'git/ref/heads/main';$base=$baseRef.object.sha
 $baseCommit=Invoke-CanaryApi GET ('git/commits/'+$base)
 if($baseCommit.parents.Count -lt 1){throw 'Stale parent required.'}
 $stale=$baseCommit.parents[0].sha
 # Reuse the proposal created by the first stopped experiment, verifying every
 # leaf against main plus the exact signed fixture before creating a fresh ref.
 $commit=Invoke-CanaryApi GET 'git/commits/20f35ce3f15e8de7fbefeced166335e3ad5b94d4'
 if($commit.sha -cne '20f35ce3f15e8de7fbefeced166335e3ad5b94d4' -or $commit.parents.Count -ne 1 -or $commit.parents[0].sha -cne $base){throw 'Retained proposal/base mismatch.'}
 $baseTree=Invoke-CanaryApi GET ('git/trees/'+$baseCommit.tree.sha+'?recursive=1')
 $proposedTree=Invoke-CanaryApi GET ('git/trees/'+$commit.tree.sha+'?recursive=1')
 if($baseTree.truncated -or $proposedTree.truncated){throw 'Complete trees required.'}
 $expected=[Collections.Generic.Dictionary[string,string]]::new([StringComparer]::Ordinal)
 foreach($entry in $baseTree.tree){if($entry.type -cne 'tree'){$expected.Add($entry.path,($entry.mode+' '+$entry.type+' '+$entry.sha))}}
 $files=@(Get-ChildItem -LiteralPath (Join-Path $directory expected) -File)
 if($files.Count -ne 7){throw 'Seven validated fixture members required.'}
 foreach($file in $files){
  $data=[IO.File]::ReadAllBytes($file.FullName);$prefix=[Text.Encoding]::ASCII.GetBytes("blob $($data.Length)`0")
  $sha=[Convert]::ToHexString([Security.Cryptography.SHA1]::HashData([byte[]]($prefix+$data))).ToLowerInvariant()
  $expected.Add(('candidates/'+$subject.CandidateHash+'/'+$file.Name),('100644 blob '+$sha))
 }
 $seen=[Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
 foreach($entry in $proposedTree.tree){if($entry.type -cne 'tree'){
  if(-not $seen.Add($entry.path) -or -not $expected.ContainsKey($entry.path) -or $expected[$entry.path] -cne ($entry.mode+' '+$entry.type+' '+$entry.sha)){throw 'Proposal tree mismatch.'}
 }}
 if($seen.Count -ne $expected.Count){throw 'Proposal tree membership mismatch.'}
 $created=Invoke-CanaryApi POST 'git/refs' @{ref=$ref;sha=$base}
 if($created.ref -cne $ref -or $created.object.sha -cne $base){throw 'Disposable ref creation binding.'}
 $journal=@{Synthetic=$true;ProductionApprovalEstablished=$false;Ref=$ref;DriverSource=$env:GITHUB_SHA;ProducerSource=$subject.SourceCommit;OriginalArchiveSha256=$subject.OriginalArchiveSha256;CandidateHash=$subject.CandidateHash;Base=$base;Proposed=$commit.sha;Transactions=@()}
 # Wrong-old is intentionally an ancestor: ordinary fast-forward is insufficient.
 $context=New-CanaryContext
 $advertisement=Invoke-TfPublicationGitHttp $context GET
 Assert-TfGitAdvertisement $advertisement $ref $base
 $journal.Transactions+=@{Expected=$stale;State='DispatchStarted'};Save-CanaryIntent $journal
 $reply=Invoke-TfPublicationGitHttp $context POST (New-TfGitUpdate $stale $commit.sha $ref)
 [IO.File]::WriteAllBytes((Join-Path $directory wrong-old-reply.bin),$reply)
 if($DiagnosticOnly){
  $journal.Transactions[0].State='Unknown'
  $observed=Invoke-CanaryApi GET ('git/ref/'+$ref.Substring(5))
  $journal.DiagnosticOnly=$true;$journal.Observed=$observed.object.sha;$journal.GitRequests=2;$journal.Posts=1;$journal.ApiRequests=$script:requests;$journal.RestMutationAttempts=$script:apiWrites
  Save-CanaryIntent $journal
  return
 }
 $ack=Read-TfGitAcknowledgement $reply $ref
 $observed=Invoke-CanaryApi GET ('git/ref/'+$ref.Substring(5))
 if($ack -cne 'Rejected' -or $observed.object.sha -cne $base){throw 'Wrong-old must reject completely and leave ref unchanged.'}
 $journal.Transactions[0].State='Rejected';Save-CanaryIntent $journal
 # A distinct corrected transaction, never a replay of an uncertain request.
 $context=New-CanaryContext
 $advertisement=Invoke-TfPublicationGitHttp $context GET
 Assert-TfGitAdvertisement $advertisement $ref $base
 $record=@{ExpectedParent=$base;ProposedCommit=$commit.sha;State='DispatchStarted';Ack='None';ObservedCommit=$base}
 $journal.Transactions+= $record;Save-CanaryIntent $journal
 $reply=Invoke-TfPublicationGitHttp $context POST (New-TfGitUpdate $base $commit.sha $ref)
 [IO.File]::WriteAllBytes((Join-Path $directory correct-old-reply.bin),$reply)
 if((Read-TfGitAcknowledgement $reply $ref) -cne 'Accepted'){throw 'Corrected CAS rejected.'}
 # Explicit simulated loss AFTER known server acceptance. This proves GET-only
 # reconciliation, not a real crash or production-journal durability claim.
 $record.State='Unknown';$record.Ack='Unknown';Save-CanaryIntent $journal
 $observed=Invoke-CanaryApi GET ('git/ref/'+$ref.Substring(5))
 Update-TfPublicationWriterObservation $record $observed.object.sha
 if($record.State -cne 'Applied'){throw 'Read-only observation failed.'}
 Save-CanaryIntent $journal
 $journal.ApiRequests=$script:requests;$journal.GitRequests=4;$journal.Posts=2
 $journal.RestMutationAttempts=$script:apiWrites;$journal.TotalMutationAttempts=$script:apiWrites+2
 $journal.SimulatedAcknowledgementLoss=$true;$journal.RecoveryPosts=0;$journal.ProductionCrashRecoveryProven=$false
 $journal|ConvertTo-Json -Depth 12|Set-Content -LiteralPath (Join-Path $directory transport-result.json)
}finally{$client.Dispose();$token.Dispose()}
