#Requires -Version 7.4
# Trusted data-only validation. Import performs no network request or signing.
. (Join-Path $PSScriptRoot TokenForgePublicationAdapter.ps1)

function Assert-TfSealerInvocation($Invocation) {
 Assert-TokenForgePermissionFields $Invocation @('Repository','RepositoryId','SourceCommit','RunId','RunAttempt','Ref','EventName','WorkflowRef')
 foreach($key in $Invocation.Keys){if($Invocation[$key] -isnot [string]){throw 'Invocation scalar.'}}
 if($Invocation.Repository -cnotmatch '\A[A-Za-z0-9][A-Za-z0-9_.-]{0,99}/[A-Za-z0-9][A-Za-z0-9_.-]{0,99}\z' -or $Invocation.Ref -cne 'refs/heads/main' -or $Invocation.EventName -cne 'workflow_dispatch' -or $Invocation.WorkflowRef -cne ($Invocation.Repository+'/.github/workflows/discovery.yml@refs/heads/main')){throw 'Invocation source.'}
 foreach($key in @('RepositoryId','RunId','RunAttempt')){$null=Get-TfPublicationId $Invocation[$key]}
 Assert-TokenForgePublicationPlanHash $Invocation.SourceCommit -Length 40
}

function Invoke-TfSealerArchiveGet($Context,[ValidateSet('Redirect','Bytes')][string]$Phase,[string]$Uri) {
 Test-TfPublicationBudget $Context
 if($Context.DownloadRequests -ge 2){throw 'Download request bound.'};$Context.DownloadRequests++
 if($Context.Synthetic){return & $Context.FetchFixture $Phase $Uri}
 $handler=[Net.Http.HttpClientHandler]::new();$handler.AllowAutoRedirect=$false;$handler.UseCookies=$false;$handler.UseProxy=$false
 $client=[Net.Http.HttpClient]::new($handler);$cancel=[Threading.CancellationTokenSource]::new()
 $request=[Net.Http.HttpRequestMessage]::new([Net.Http.HttpMethod]::Get,$Uri)
 try{
  $client.Timeout=[TimeSpan]::FromSeconds([math]::Min(10,60-$Context.Watch.Elapsed.TotalSeconds));$cancel.CancelAfter($client.Timeout)
  $request.Headers.UserAgent.ParseAdd('TokenForge-Sealer/1')
  if($Phase -ceq 'Redirect'){
   $request.Headers.Add('X-GitHub-Api-Version','2022-11-28')
   $request.Headers.Authorization=[Net.Http.Headers.AuthenticationHeaderValue]::new('Bearer',[Net.NetworkCredential]::new('',$Context.Token).Password)
  }
  # The blob URL gets no GitHub Authorization header; no further redirects are followed.
  $message=$client.Send($request,[Net.Http.HttpCompletionOption]::ResponseHeadersRead,$cancel.Token)
  try{
   if($Phase -ceq 'Redirect'){return @{Status=[int]$message.StatusCode;Location=[string]$message.Headers.Location}}
   if([int]$message.StatusCode -ne 200 -or $message.Content.Headers.ContentLength -gt 8MB){throw 'Archive refused.'}
   $stream=$message.Content.ReadAsStream();$memory=[IO.MemoryStream]::new();$buffer=[byte[]]::new(8192)
   try{
    while(($n=$stream.ReadAsync($buffer,0,$buffer.Length,$cancel.Token).GetAwaiter().GetResult()) -gt 0){
     if($memory.Length+$n -gt 8MB -or $memory.Length+$n+$Context.Bytes -gt 16MB){throw 'Archive response bound.'}
     $memory.Write($buffer,0,$n);Test-TfPublicationBudget $Context
    }
    return @{Status=200;Bytes=$memory.ToArray()}
   }finally{$memory.Dispose();$stream.Dispose()}
  }finally{$message.Dispose()}
 }finally{$request.Dispose();$client.Dispose();$cancel.Dispose()}
}

function Save-TfSealerOriginalArchive($Context,[string]$ArtifactId,[string]$Path) {
 $redirect=Invoke-TfSealerArchiveGet $Context Redirect ('https://api.github.com'+$Context.Api+'/actions/artifacts/'+$ArtifactId+'/zip')
 $uri=$null
 if($redirect.Status -ne 302 -or $redirect.Location -isnot [string] -or $redirect.Location.Length -gt 8192 -or -not [Uri]::TryCreate($redirect.Location,[UriKind]::Absolute,[ref]$uri) -or $uri.Scheme -cne 'https' -or $uri.UserInfo -or $uri.Port -ne 443 -or ($uri.DnsSafeHost -cnotmatch '\A[a-z0-9-]+\.blob\.core\.windows\.net\z' -and $uri.DnsSafeHost -cnotmatch '\A[a-z0-9.-]+\.actions\.githubusercontent\.com\z') -or $uri.Fragment){throw 'Archive redirect origin refused.'}
 $response=Invoke-TfSealerArchiveGet $Context Bytes $uri.AbsoluteUri
 if($response.Status -ne 200 -or $response.Bytes -isnot [byte[]] -or $response.Bytes.Length -lt 1 -or $response.Bytes.Length -gt 8MB){throw 'Archive response refused.'}
 $Context.Bytes+=$response.Bytes.Length;Test-TfPublicationBudget $Context
 $file=[TokenForge.Core.V0220.PrivateFiles]::Open($Path,$true)
 try{$file.Write($response.Bytes,0,$response.Bytes.Length);$file.Flush($true)}finally{$file.Dispose()}
}

function Get-TokenForgeSealingSubject {
 <# .SYNOPSIS
 Independently bind and validate the original seven-file artifact ZIP. Does not sign.
 .DESCRIPTION
 Invocation comes from trusted GitHub execution context in the fixed reusable workflow.
 Caller inputs are restricted there to one artifact ID; no caller digest/path is used.
 #>
 [CmdletBinding(DefaultParameterSetName='Live')]
 param(
  [Parameter(Mandatory)]$Invocation,
  [Parameter(Mandatory)][ValidatePattern('^[1-9][0-9]{0,18}$')][string]$ArtifactId,
  [Parameter(Mandatory)][string]$OutputDirectory,
  [Parameter(Mandatory,ParameterSetName='Live')][securestring]$AccessToken,
  [Parameter(Mandatory,ParameterSetName='Synthetic')][switch]$Synthetic,
  [Parameter(Mandatory,ParameterSetName='Synthetic')][scriptblock]$ReadFixture,
  [Parameter(Mandatory,ParameterSetName='Synthetic')][scriptblock]$FetchFixture
 )
 $ErrorActionPreference='Stop';$stage='Invocation';$created=$false
 try{
  if(-not $IsLinux){throw 'Linux only.'};Assert-TfSealerInvocation $Invocation
  $isSynthetic=$PSCmdlet.ParameterSetName -ceq 'Synthetic'
  if(-not $isSynthetic -and ($env:GITHUB_ACTIONS -cne 'true' -or $Invocation.Repository -cne 'nathanmcnulty/TokenForge')){throw 'Trusted hosted invocation required.'}
  $OutputDirectory=[TokenForge.Core.V0220.PrivateFiles]::Resolve([IO.Path]::GetFullPath($OutputDirectory),$true)
  if(Test-Path -LiteralPath $OutputDirectory){throw 'Sealing destination must be new.'}
  $null=[IO.Directory]::CreateDirectory($OutputDirectory,[IO.UnixFileMode]448);$created=$true
  $context=@{Api=('/repos/'+$Invocation.Repository);Synthetic=$isSynthetic;Token=$AccessToken;ReadFixture=$ReadFixture;FetchFixture=$FetchFixture;Requests=0;DownloadRequests=0;Bytes=0L;Watch=[Diagnostics.Stopwatch]::StartNew();DeadlineSeconds=60;MaxRequests=7;MaxBytes=16MB}
  $stage='Origin'
  $repo=Invoke-TfPublicationHttp $context $context.Api
  if((Get-TfPublicationId $repo.id) -cne $Invocation.RepositoryId -or $repo.full_name -cne $Invocation.Repository -or $repo.default_branch -cne 'main' -or $repo.archived -isnot [bool] -or $repo.archived -or $repo.disabled -isnot [bool] -or $repo.disabled){throw 'Repository mismatch.'}
  $run=Invoke-TfPublicationHttp $context ($context.Api+'/actions/runs/'+$Invocation.RunId)
  $artifact=Invoke-TfPublicationHttp $context ($context.Api+'/actions/artifacts/'+$ArtifactId)
  $main=Invoke-TfPublicationHttp $context ($context.Api+'/branches/main')
  if((Get-TfPublicationId $run.id) -cne $Invocation.RunId -or (Get-TfPublicationId $run.run_attempt) -cne $Invocation.RunAttempt -or (Get-TfPublicationId $run.repository.id) -cne $Invocation.RepositoryId -or (Get-TfPublicationId $run.head_repository.id) -cne $Invocation.RepositoryId -or $run.head_sha -cne $Invocation.SourceCommit -or $run.head_branch -cne 'main' -or $run.event -cne 'workflow_dispatch' -or $run.path -cne '.github/workflows/discovery.yml' -or $run.status -cnotin @('in_progress','completed') -or ($run.status -ceq 'completed' -and $run.conclusion -cne 'success')){throw 'Caller run mismatch.'}
  $workflowId=Get-TfPublicationId $run.workflow_id
  if($main.commit.sha -cne $Invocation.SourceCommit -or $main.protected -isnot [bool] -or -not $main.protected){throw 'Main advanced or unprotected.'}
  if((Get-TfPublicationId $artifact.id) -cne $ArtifactId -or $artifact.expired -isnot [bool] -or $artifact.expired -or $artifact.digest -isnot [string] -or $artifact.digest -cnotmatch '\Asha256:[a-f0-9]{64}\z' -or $artifact.size_in_bytes -isnot [long] -or $artifact.size_in_bytes -lt 1 -or $artifact.size_in_bytes -gt 8MB -or (Get-TfPublicationId $artifact.workflow_run.id) -cne $Invocation.RunId -or (Get-TfPublicationId $artifact.workflow_run.repository_id) -cne $Invocation.RepositoryId -or (Get-TfPublicationId $artifact.workflow_run.head_repository_id) -cne $Invocation.RepositoryId -or $artifact.workflow_run.head_sha -cne $Invocation.SourceCommit -or $artifact.workflow_run.head_branch -cne 'main'){throw 'Original artifact mismatch.'}
  $stage='OriginalZip';$archive=Join-Path $OutputDirectory candidate.zip
  Save-TfSealerOriginalArchive $context $ArtifactId $archive
  $archiveHash=Get-TfCandidateFileHash $archive
  if((Get-Item $archive).Length -ne $artifact.size_in_bytes -or ('sha256:'+$archiveHash) -cne $artifact.digest){throw 'Original archive digest mismatch.'}
  $stage='Candidate';$extracted=Join-Path $OutputDirectory candidate;$null=[IO.Directory]::CreateDirectory($extracted,[IO.UnixFileMode]448)
  Expand-TfPublicationArchive $archive $extracted
  $candidateHash=Get-TfCandidateFileHash (Join-Path $extracted manifest.json)
  $manifest=Assert-TfDiscoveryCandidate $extracted $candidateHash
  if($manifest.SourceCommit -cne $Invocation.SourceCommit -or $manifest.ProducerRunId -cne $Invocation.RunId -or $manifest.ProducerAttempt -cne $Invocation.RunAttempt){throw 'Candidate caller binding mismatch.'}
  $stage='FinalOrigin'
  $finalArtifact=Invoke-TfPublicationHttp $context ($context.Api+'/actions/artifacts/'+$ArtifactId)
  $finalRun=Invoke-TfPublicationHttp $context ($context.Api+'/actions/runs/'+$Invocation.RunId)
  $finalMain=Invoke-TfPublicationHttp $context ($context.Api+'/branches/main')
  foreach($key in @('id','run_attempt','workflow_id','head_sha','head_branch','event','path','actor','triggering_actor','repository','head_repository')){
   if((Get-TfCandidateHash $finalRun[$key]) -cne (Get-TfCandidateHash $run[$key])){throw 'Caller changed during validation.'}
  }
  if((Get-TfCandidateHash $finalArtifact) -cne (Get-TfCandidateHash $artifact) -or $finalRun.status -cnotin @('in_progress','completed') -or ($finalRun.status -ceq 'completed' -and $finalRun.conclusion -cne 'success') -or $finalMain.commit.sha -cne $Invocation.SourceCommit -or $finalMain.protected -isnot [bool] -or -not $finalMain.protected -or [DateTimeOffset]::UtcNow -ge [DateTimeOffset]::Parse($artifact.expires_at)){throw 'Origin changed or artifact expired.'}
  Test-TfPublicationBudget $context
  Remove-Item -LiteralPath $extracted -Recurse -Force
  [IO.File]::SetUnixFileMode($archive,[IO.UnixFileMode]256)
  $result=[ordered]@{SchemaVersion=1;Kind='TokenForgeSealingSubject';Synthetic=$isSynthetic;RepositoryId=$Invocation.RepositoryId;SourceCommit=$Invocation.SourceCommit;ProducerRunId=$Invocation.RunId;ProducerAttempt=$Invocation.RunAttempt;WorkflowId=$workflowId;ArtifactId=$ArtifactId;SubjectPath=$archive;SubjectSha256=$archiveHash;CandidateHash=$candidateHash;SubjectCount=1;StructuralValidation=$true;SemanticApproval=$false;SigningPerformed=$false;MetadataRequests=$context.Requests;DownloadRequests=$context.DownloadRequests}
  $receipt=[TokenForge.Core.V0220.PrivateFiles]::Open((Join-Path $OutputDirectory subject.json),$true)
  try{$bytes=[Text.Encoding]::UTF8.GetBytes(($result|ConvertTo-Json -Compress));$receipt.Write($bytes,0,$bytes.Length);$receipt.Flush($true)}finally{$receipt.Dispose()}
  [pscustomobject]$result
 }catch{
  if($created -and (Test-Path -LiteralPath $OutputDirectory)){Remove-Item -LiteralPath $OutputDirectory -Recurse -Force}
  throw ('Sealing validation failed at '+$stage+'; no signing performed.')
 }
}
