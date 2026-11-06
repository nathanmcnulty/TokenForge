#Requires -Version 7.6
# Manual synthetic service experiment, not the production authorization entry point.
param([Parameter(Mandatory)][string]$Evidence)
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
$script:requests=0;$script:bytes=0L;$watch=[Diagnostics.Stopwatch]::StartNew()
$handler=[Net.Http.HttpClientHandler]::new();$handler.AllowAutoRedirect=$false;$handler.UseCookies=$false;$handler.UseProxy=$false
$client=[Net.Http.HttpClient]::new($handler);$client.Timeout=[TimeSpan]::FromSeconds(15)
$ref='refs/heads/tokenforge-publication-canary-'+$env:GITHUB_RUN_ID
function Invoke-CanaryApi([string]$Method,[string]$Route,$Body=$null){
 if($watch.Elapsed.TotalSeconds -ge 120 -or $script:requests -ge 24){throw 'Synthetic API budget exhausted.'}
 $allowedRead=@('','git/ref/heads/main',('git/ref/'+$ref.Substring(5)))
 if($Method -ceq 'GET'){
  if($Route -cnotin $allowedRead -and $Route -cnotmatch '\Agit/commits/[a-f0-9]{40}\z'){throw 'Read route refused.'}
 }elseif($Method -cne 'POST' -or $Route -cnotin @('git/blobs','git/trees','git/commits','git/refs')){throw 'Write route refused.'}
 if($Route -ceq 'git/refs' -and $Body.ref -cne $ref){throw 'Only new disposable ref allowed.'}
 $script:requests++
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
 $entries=@()
 foreach($file in Get-ChildItem -LiteralPath (Join-Path $directory expected) -File|Sort-Object Name){
  $blob=Invoke-CanaryApi POST 'git/blobs' @{content=[Convert]::ToBase64String([IO.File]::ReadAllBytes($file.FullName));encoding='base64'}
  $entries+=@{path=('candidates/'+$subject.CandidateHash+'/'+$file.Name);mode='100644';type='blob';sha=$blob.sha}
 }
 if($entries.Count -ne 7){throw 'Seven validated fixture members required.'}
 $tree=Invoke-CanaryApi POST 'git/trees' @{base_tree=$baseCommit.tree.sha;tree=$entries}
 $commit=Invoke-CanaryApi POST 'git/commits' @{message='Public synthetic publication transport acceptance (no operational evidence)';tree=$tree.sha;parents=@($base)}
 $created=Invoke-CanaryApi POST 'git/refs' @{ref=$ref;sha=$base}
 if($created.ref -cne $ref -or $created.object.sha -cne $base){throw 'Disposable ref creation binding.'}
 $journal=@{Synthetic=$true;ProductionApprovalEstablished=$false;Ref=$ref;DriverSource=$env:GITHUB_SHA;ProducerSource=$subject.SourceCommit;OriginalArchiveSha256=$subject.OriginalArchiveSha256;CandidateHash=$subject.CandidateHash;Base=$base;Proposed=$commit.sha;Transactions=@()}
 # Wrong-old is intentionally an ancestor: ordinary fast-forward is insufficient.
 $context=New-CanaryContext
 $advertisement=Invoke-TfPublicationGitHttp $context GET
 Assert-TfGitAdvertisement $advertisement $ref $base
 $journal.Transactions+=@{Expected=$stale;State='DispatchStarted'};Save-CanaryIntent $journal
 $reply=Invoke-TfPublicationGitHttp $context POST (New-TfGitUpdate $stale $commit.sha $ref)
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
 if((Read-TfGitAcknowledgement $reply $ref) -cne 'Accepted'){throw 'Corrected CAS rejected.'}
 # Explicit simulated loss AFTER known server acceptance. This proves GET-only
 # reconciliation, not a real crash or production-journal durability claim.
 $record.State='Unknown';$record.Ack='Unknown';Save-CanaryIntent $journal
 $observed=Invoke-CanaryApi GET ('git/ref/'+$ref.Substring(5))
 Update-TfPublicationWriterObservation $record $observed.object.sha
 if($record.State -cne 'Applied'){throw 'Read-only observation failed.'}
 Save-CanaryIntent $journal
 $journal.ApiRequests=$script:requests;$journal.GitRequests=4;$journal.Posts=2
 $journal.SimulatedAcknowledgementLoss=$true;$journal.RecoveryPosts=0;$journal.ProductionCrashRecoveryProven=$false
 $journal|ConvertTo-Json -Depth 12|Set-Content -LiteralPath (Join-Path $directory transport-result.json)
}finally{$client.Dispose();$token.Dispose()}
