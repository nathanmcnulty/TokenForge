#Requires -Version 7.6
# No invocation on import. Publish and read-only recovery are separate entry points.
. (Join-Path $PSScriptRoot TokenForgePublicationAdapter.ps1)

function ConvertTo-TfGitPacket([string]$Text) {
 $bytes=[Text.UTF8Encoding]::new($false,$true).GetBytes($Text)
 if($bytes.Length -gt 65516){throw 'Git packet bound.'}
 return ,([byte[]]([Text.Encoding]::ASCII.GetBytes(($bytes.Length+4).ToString('x4'))+$bytes))
}

function Read-TfGitPackets([byte[]]$Bytes) {
 if($Bytes.Length -gt 2MB){throw 'Git response bound.'}
 $packets=[Collections.Generic.List[string]]::new();$offset=0
 while($offset -lt $Bytes.Length){
  if($packets.Count -ge 10004 -or $offset+4 -gt $Bytes.Length){throw 'Git framing bound.'}
  $header=[Text.Encoding]::ASCII.GetString($Bytes,$offset,4)
  if($header -cnotmatch '\A[0-9a-f]{4}\z'){throw 'Git packet length.'}
  $length=[Convert]::ToInt32($header,16);$offset+=4
  if($length -eq 0){$packets.Add('');continue}
  if($length -lt 5 -or $length -gt 65520 -or $offset+$length-4 -gt $Bytes.Length){throw 'Git packet truncation.'}
  $packets.Add([Text.UTF8Encoding]::new($false,$true).GetString($Bytes,$offset,$length-4));$offset+=$length-4
 }
 return ,$packets.ToArray()
}

function Assert-TfGitAdvertisement([byte[]]$Bytes,[string]$Ref,[string]$Expected) {
 $packets=Read-TfGitPackets $Bytes
 if($packets.Count -lt 4 -or $packets[0] -cne "# service=git-receive-pack`n" -or $packets[1] -cne '' -or $packets[-1] -cne ''){throw 'Git service framing.'}
 $seen=[Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal);$found=$false
 for($i=2;$i -lt $packets.Count-1;$i++){
  $line=$packets[$i];if($line -ceq ''){throw 'Unexpected Git flush.'}
  $parts=$line.TrimEnd("`n").Split([char]0)
  if($i -eq 2){
   if($parts.Count -ne 2){throw 'Missing Git capabilities.'}
   $caps=$parts[1].Split(' ')
   if('report-status' -cnotin $caps -or @($caps|Where-Object {$_ -clike 'object-format=*' -and $_ -cne 'object-format=sha1'}).Count){throw 'Unsupported Git capabilities.'}
  }elseif($parts.Count -ne 1){throw 'Repeated Git capabilities.'}
  if($parts[0] -cnotmatch '\A([a-f0-9]{40}) ([^\s\x00-\x1f\x7f]+)\z' -or -not $seen.Add($Matches[2])){throw 'Invalid or duplicate Git ref.'}
  if($Matches[2] -ceq $Ref){if($Matches[1] -cne $Expected){throw 'Git expected parent changed.'};$found=$true}
 }
 if(-not $found){throw 'Git target ref missing.'}
}

function New-TfGitUpdate([string]$Expected,[string]$Proposed,[string]$Ref) {
 foreach($sha in @($Expected,$Proposed)){Assert-TokenForgePublicationPlanHash $sha -Length 40}
 if($Expected -ceq $Proposed -or $Ref -cnotmatch '\Arefs/heads/[A-Za-z0-9][A-Za-z0-9_-]{0,63}\z'){throw 'Git update target.'}
 # No new objects: the fully verified proposed commit already exists in this repository.
 $pack=[byte[]]@(80,65,67,75,0,0,0,2,0,0,0,0)
 return ,([byte[]]((ConvertTo-TfGitPacket ($Expected+' '+$Proposed+' '+$Ref+"`0report-status`n"))+[Text.Encoding]::ASCII.GetBytes('0000')+$pack+[Security.Cryptography.SHA1]::HashData($pack)))
}

function Read-TfGitAcknowledgement([byte[]]$Bytes,[string]$Ref) {
 $packets=Read-TfGitPackets $Bytes
 if($packets.Count -ne 3 -or $packets[2] -cne '' -or $packets[0] -cne "unpack ok`n"){throw 'Incomplete Git acknowledgement.'}
 if($packets[1] -ceq ('ok '+$Ref+"`n")){return 'Accepted'}
 if($packets[1] -cmatch ('\Ang '+[regex]::Escape($Ref)+' [^\x00-\x1f\x7f]+\n\z')){return 'Rejected'}
 throw 'Unexpected Git acknowledgement.'
}

function Invoke-TfPublicationGitHttp($Context,[ValidateSet('GET','POST')][string]$Method,[byte[]]$Body) {
 Test-TfPublicationBudget $Context
 if($Context.GitRequests -ge 2){throw 'Git request budget.'};$Context.GitRequests++
 $expectedType=if($Method -ceq 'GET'){'application/x-git-receive-pack-advertisement'}else{'application/x-git-receive-pack-result'}
 if($Context.Synthetic){$response=& $Context.WriteFixture $Method $Body}
 else{
  $suffix=if($Method -ceq 'GET'){'/info/refs?service=git-receive-pack'}else{'/git-receive-pack'}
  $uri='https://github.com/'+$Context.Policy.Repository+'.git'+$suffix
  $handler=[Net.Http.HttpClientHandler]::new();$handler.AllowAutoRedirect=$false;$handler.UseCookies=$false;$handler.UseProxy=$false
  $client=[Net.Http.HttpClient]::new($handler)
  $cancel=[Threading.CancellationTokenSource]::new()
  $request=[Net.Http.HttpRequestMessage]::new([Net.Http.HttpMethod]::new($Method),$uri)
  try{
   $request.Version=[Version]::new(1,1);$request.VersionPolicy=[Net.Http.HttpVersionPolicy]::RequestVersionExact
   $request.Headers.ConnectionClose=$true
   $client.Timeout=[TimeSpan]::FromSeconds([math]::Min(10,30-$Context.Watch.Elapsed.TotalSeconds));$cancel.CancelAfter($client.Timeout)
   $request.Headers.UserAgent.ParseAdd('TokenForge-PublicationWriter/1');$request.Headers.Accept.ParseAdd($expectedType)
   $authBytes=[Text.Encoding]::UTF8.GetBytes('x-access-token:'+([Net.NetworkCredential]::new('',$Context.Token).Password))
   try{$request.Headers.Authorization=[Net.Http.Headers.AuthenticationHeaderValue]::new('Basic',[Convert]::ToBase64String($authBytes))}finally{[Array]::Clear($authBytes)}
   if($Method -ceq 'POST'){
    $request.Content=[Net.Http.ByteArrayContent]::new($Body)
    $request.Content.Headers.ContentType=[Net.Http.Headers.MediaTypeHeaderValue]::new('application/x-git-receive-pack-request')
   }
   $message=$client.Send($request,[Net.Http.HttpCompletionOption]::ResponseHeadersRead,$cancel.Token)
   try{
    if([int]$message.StatusCode -ne 200 -or $message.Content.Headers.ContentLength -gt 2MB -or $message.Headers.Contains('Link')){throw 'Git HTTP refused.'}
    $stream=$message.Content.ReadAsStream();$memory=[IO.MemoryStream]::new();$buffer=[byte[]]::new(8192)
    try{
     while(($n=$stream.ReadAsync($buffer,0,$buffer.Length,$cancel.Token).GetAwaiter().GetResult()) -gt 0){
      if($memory.Length+$n -gt 2MB -or $memory.Length+$n+$Context.Bytes -gt $Context.MaxBytes){throw 'Git response bound.'}
      $memory.Write($buffer,0,$n);Test-TfPublicationBudget $Context
     }
     $response=@{Status=200;ContentType=$message.Content.Headers.ContentType.MediaType;Bytes=$memory.ToArray()}
    }finally{$memory.Dispose();$stream.Dispose()}
   }finally{$message.Dispose()}
  }finally{$request.Dispose();$client.Dispose();$cancel.Dispose()}
 }
 if($response.Status -ne 200 -or $response.ContentType -cne $expectedType -or $response.Bytes -isnot [byte[]] -or $response.Bytes.Length -gt 2MB){throw 'Invalid Git response.'}
 $Context.Bytes+=$response.Bytes.Length;Test-TfPublicationBudget $Context
 return ,$response.Bytes
}

function Read-TfPublicationWriterLedger($Policy,[string]$PolicyHash,[bool]$Synthetic,[string]$Root) {
 $path=[TokenForge.Core.V0220.PrivateFiles]::Resolve((Join-Path $Root 'writer.json'),$true)
 $marker=[TokenForge.Core.V0220.PrivateFiles]::Resolve((Join-Path $Root '.writer.initialized'),$false)
 if((Test-Path -LiteralPath $marker) -and -not (Test-Path -LiteralPath $path)){throw 'Missing writer journal; do not reset.'}
 $ledger=@{SchemaVersion=1;Synthetic=$Synthetic;RepositoryId=$Policy.RepositoryId;Ref=('refs/heads/'+$Policy.DataBranch);PolicySha256=$PolicyHash;Records=@()}
 if(Test-Path -LiteralPath $path){
  $stream=[IO.File]::Open($path,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::None)
  try{if($stream.Length -lt 1 -or $stream.Length -gt 16KB){throw 'Writer journal bound.'};$bytes=[byte[]]::new($stream.Length);$stream.ReadExactly($bytes,0,$bytes.Length);if($stream.ReadByte() -ne -1){throw 'Journal changed.'}}finally{$stream.Dispose()}
  $ledger=Read-TfPublicationJson $bytes
  Assert-TokenForgePermissionFields $ledger @('SchemaVersion','Synthetic','RepositoryId','Ref','PolicySha256','Records')
  if(($ledger.SchemaVersion -isnot [long] -and $ledger.SchemaVersion -isnot [int]) -or $ledger.SchemaVersion -ne 1 -or $ledger.Synthetic -isnot [bool] -or $ledger.Synthetic -ne $Synthetic -or $ledger.RepositoryId -cne $Policy.RepositoryId -or $ledger.Ref -cne ('refs/heads/'+$Policy.DataBranch) -or $ledger.PolicySha256 -cne $PolicyHash -or $ledger.Records -isnot [array] -or $ledger.Records.Count -gt 100){throw 'Writer journal context.'}
 }
 $seen=[Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
 foreach($r in $ledger.Records){
  Assert-TokenForgePermissionFields $r @('Transaction','ExpectedParent','ProposedCommit','ProposedTree','State','Ack','ObservedCommit','WriterId','PreparedAt')
  Assert-TokenForgePublicationPlanHash $r.Transaction
  foreach($key in @('ExpectedParent','ProposedCommit','ProposedTree','ObservedCommit')){Assert-TokenForgePublicationPlanHash $r[$key] -Length 40}
  $null=Get-TfPublicationId $r.WriterId;$null=Read-TokenForgePublicationPlanTime $r.PreparedAt
  if(-not $seen.Add($r.Transaction) -or $r.ExpectedParent -ceq $r.ProposedCommit -or $r.State -cnotin @('DispatchStarted','Unknown','Rejected','Applied','Consumed') -or $r.Ack -cnotin @('None','Unknown','Accepted','Rejected')){throw 'Invalid writer record.'}
 }
 return ,$ledger
}

function Save-TfPublicationWriterLedger([string]$Root,$Ledger) {
 Save-TfPublicationLedger (Join-Path $Root writer.json) $Ledger
 $marker=Join-Path $Root '.writer.initialized'
 if(-not (Test-Path -LiteralPath $marker)){$file=[TokenForge.Core.V0220.PrivateFiles]::Open($marker,$true);try{$file.Flush($true)}finally{$file.Dispose()}}
}

function Update-TfPublicationWriterObservation($Record,[string]$Observed) {
 Assert-TokenForgePublicationPlanHash $Observed -Length 40
 $Record.ObservedCommit=$Observed
 if($Record.State -cin @('Applied','Consumed')){
  if($Observed -ceq $Record.ExpectedParent){$Record.State='Consumed'}
 }elseif($Observed -ceq $Record.ProposedCommit){$Record.State='Applied'}
 elseif($Observed -ceq $Record.ExpectedParent -and $Record.Ack -ceq 'Rejected'){$Record.State='Rejected'}
 else{$Record.State='Unknown'}
}

function Get-TfPublicationWriteResult($Context,$Record,[string]$Status,[int]$Posts) {
 [pscustomobject]@{
  SchemaVersion=1;Kind='TokenForgePublicationWriterResult';Status=$Status;Synthetic=$Context.Synthetic
  Transaction=$Record.Transaction;ExpectedParent=$Record.ExpectedParent;ProposedCommit=$Record.ProposedCommit;ObservedCommit=$Record.ObservedCommit
  Ack=$Record.Ack;DispatchesThisInvocation=$Posts;AuthorizationEstablished=$false;PublishAllowed=$false
  RemoteMutationAttempted=(-not $Context.Synthetic -and $Posts -gt 0)
  RemoteMutationPerformed=if($Context.Synthetic){$false}else{$null}
  HostedExecutionProof=$false;NextStep=if($Status -cin @('Unknown','DispatchStarted','Consumed')){'ReadOnlyRecoveryOrSeparateAuditedInterventionRequired'}else{'SeparateApprovalRequiredForAnyNewPublication'}
 }
}

function Initialize-TfPublicationWrite($Context,$Approval,[string]$Transaction,[string]$Root,[string]$ApprovedTransaction) {
 if($Transaction -cne $ApprovedTransaction){throw 'Approved transaction mismatch.'}
 $ledger=Read-TfPublicationWriterLedger $Context.Policy $Context.PolicyHash $Context.Synthetic $Root
 $Context.WriterLedger=$ledger
 if(@($ledger.Records|Where-Object Transaction -CEQ $Transaction).Count){return $null}
 if(@($ledger.Records|Where-Object State -CIn @('DispatchStarted','Unknown','Consumed')).Count){throw 'Repository/ref has unresolved or consumed history; recovery only.'}
 $writer=@{Policy=$Context.Policy;PolicyHash=$Context.PolicyHash;Api=$Context.Api;Synthetic=$Context.Synthetic;Token=$Context.Token;ReadFixture=$Context.ReadFixture;WriteFixture=$Context.WriteFixture;Requests=0;GitRequests=0;Bytes=0L;Watch=[Diagnostics.Stopwatch]::StartNew();DeadlineSeconds=30;MaxRequests=2;MaxBytes=8MB}
 $advertisement=Invoke-TfPublicationGitHttp $writer GET
 Assert-TfGitAdvertisement $advertisement $Approval.Ref $Approval.ExpectedParent
 # Rebind the URL before the final authority pass. Discovery never writes.
 $repo=Invoke-TfPublicationHttp $writer $writer.Api
 if((Get-TfPublicationId $repo.id) -cne $Context.Policy.RepositoryId -or $repo.full_name -cne $Context.Policy.Repository){throw 'Repository changed before dispatch.'}
 return $writer
}

function Invoke-TfPublicationWrite($Context,$Approval,[string]$Transaction,[string]$Verdict,[string]$Root,[string]$ApprovedTransaction,$ReviewExpiry,$MainExpiry,[string]$ReaderId) {
 if($Transaction -cne $ApprovedTransaction){throw 'Approved transaction mismatch.'}
 $ledger=$Context.WriterLedger
 $prior=@($ledger.Records|Where-Object Transaction -CEQ $Transaction)
 if($prior.Count){
  $record=$prior[0]
  if($record.ExpectedParent -cne $Approval.ExpectedParent -or $record.ProposedCommit -cne $Approval.ProposedCommit -or $record.ProposedTree -cne $Context.ProposedTree){throw 'Writer record binding.'}
  Update-TfPublicationWriterObservation $record $Context.FinalObserved
  Save-TfPublicationWriterLedger $Root $ledger
  return Get-TfPublicationWriteResult $Context $record $record.State 0
 }
 if(@($ledger.Records|Where-Object State -CIn @('DispatchStarted','Unknown','Consumed')).Count){throw 'Repository/ref has unresolved or consumed history; recovery only.'}
 $applied=@($ledger.Records|Where-Object State -CEQ Applied)
 if($applied.Count -and $applied[-1].ProposedCommit -cne $Approval.ExpectedParent){throw 'Unreconciled repository/ref history.'}
 if($Verdict -cne 'VerifiedForSeparateWriterReview'){throw 'Fresh publication verification refused.'}
 if($ledger.Records.Count -ge 100){throw 'Writer retention bound; do not reset.'}
 $writer=$Context.WriterTransport
 if($null -eq $writer){throw 'Writer discovery was not prepared.'}
 Test-TfPublicationBudget $Context
 Test-TfPublicationBudget $writer
 $now=Get-TfPublicationNow $Context
 if($now -ge $ReviewExpiry -or $now -ge $MainExpiry -or $now -ge [DateTimeOffset]::Parse($Context.ArtifactExpiry)){throw 'Publication expired before dispatch.'}
 $body=New-TfGitUpdate $Approval.ExpectedParent $Approval.ProposedCommit $Approval.Ref
 $record=@{Transaction=$Transaction;ExpectedParent=$Approval.ExpectedParent;ProposedCommit=$Approval.ProposedCommit;ProposedTree=$Context.ProposedTree;State='DispatchStarted';Ack='None';ObservedCommit=$Approval.ExpectedParent;WriterId=$ReaderId;PreparedAt=$now.ToUniversalTime().ToString('o')}
 $ledger.Records+=@($record)
 Save-TfPublicationWriterLedger $Root $ledger
 # From this durable point every failure is recovery-only, even before Send starts.
 $Context.DispatchPossible=$true
 Test-TfPublicationBudget $Context
 Test-TfPublicationBudget $writer
 if((Get-TfPublicationNow $Context) -ge $ReviewExpiry -or (Get-TfPublicationNow $Context) -ge $MainExpiry -or (Get-TfPublicationNow $Context) -ge [DateTimeOffset]::Parse($Context.ArtifactExpiry)){throw 'Publication expired after intent.'}
 $record.State='Unknown';$record.Ack='Unknown'
 try{$reply=Invoke-TfPublicationGitHttp $writer POST $body;$record.Ack=Read-TfGitAcknowledgement $reply $Approval.Ref}catch{
  # Never retry an ambiguous POST.
 }
 try{
  $ref=Invoke-TfPublicationHttp $writer ($writer.Api+'/git/ref/heads/'+$Context.Policy.DataBranch)
  if($ref.ref -cne $Approval.Ref -or $ref.object.type -cne 'commit'){throw 'Observation mismatch.'}
  Update-TfPublicationWriterObservation $record $ref.object.sha
 }catch{$record.State='Unknown'}
 Save-TfPublicationWriterLedger $Root $ledger
 $result=Get-TfPublicationWriteResult $Context $record $record.State 1
 $result|Add-Member NoteProperty GitRequests $writer.GitRequests
 $result|Add-Member NoteProperty MetadataRequests $writer.Requests
 return $result
}

function Invoke-TokenForgePublication {
 <# .SYNOPSIS
 Explicitly publish one independently approved transaction after fresh verification.
 .DESCRIPTION
 Import performs no operation. ExecutePublication and ApprovedTransaction are required
 execution boundaries, not substitutes for separate human authorization. Synthetic mode
 can use only its supplied fixture; live mode never accepts a callback transport.
 #>
 [CmdletBinding(DefaultParameterSetName='Live')]
 param(
  [Parameter(Mandatory)][string]$PolicyPath,[Parameter(Mandatory)][string]$PolicySha256,
  [Parameter(Mandatory)][string]$ArchivePath,
  [Parameter(Mandatory)][ValidatePattern('^[1-9][0-9]{0,18}$')][string]$PullRequest,
  [Parameter(Mandatory)][ValidatePattern('^[1-9][0-9]{0,18}$')][string]$ReviewerComment,
  [Parameter(Mandatory)][ValidatePattern('^[1-9][0-9]{0,18}$')][string]$MaintainerComment,
  [Parameter(Mandatory)][string]$ApprovedTransaction,[switch]$ExecutePublication,
  [Parameter(Mandatory,ParameterSetName='Live')][securestring]$AccessToken,
  [Parameter(Mandatory,ParameterSetName='Live')][string]$VerifierPath,
  [Parameter(Mandatory,ParameterSetName='Live')][string]$AttestationBundlePath,
  [Parameter(Mandatory,ParameterSetName='Live')][string]$TrustRootPath,
  [Parameter(Mandatory,ParameterSetName='Synthetic')][switch]$Synthetic,
  [Parameter(Mandatory,ParameterSetName='Synthetic')][scriptblock]$ReadFixture,
  [Parameter(Mandatory,ParameterSetName='Synthetic')][scriptblock]$VerifyFixtureAttestation,
  [Parameter(Mandatory,ParameterSetName='Synthetic')][DateTimeOffset]$FixtureTime,
  [Parameter(Mandatory,ParameterSetName='Synthetic')][scriptblock]$WriteFixture
 )
 Invoke-TfPublicationOperation @PSBoundParameters -PublicationWriter
}

function Get-TokenForgePublicationWriterStatus {
 <# .SYNOPSIS
 Recover a recorded dispatch through authenticated read-only observation. Never POST.
 #>
 [CmdletBinding(DefaultParameterSetName='Live')]
 param(
  [Parameter(Mandatory)][string]$PolicyPath,[Parameter(Mandatory)][string]$PolicySha256,
  [Parameter(Mandatory)][string]$Transaction,
  [Parameter(Mandatory,ParameterSetName='Live')][securestring]$AccessToken,
  [Parameter(Mandatory,ParameterSetName='Synthetic')][switch]$Synthetic,
  [Parameter(Mandatory,ParameterSetName='Synthetic')][scriptblock]$ReadFixture
 )
 $ErrorActionPreference='Stop';$lock=$null
 try{
  if(-not $IsLinux){throw 'Linux only.'};Assert-TokenForgePublicationPlanHash $Transaction
  $policy=Read-TfPublicationPolicySnapshot $PolicyPath $PolicySha256
  $root=Join-Path $policy.JournalRoot ($policy.RepositoryId+'-'+$policy.DataBranch)
  $lockPath=[TokenForge.Core.V0220.PrivateFiles]::Resolve((Join-Path $root '.writer.lock'),$true)
  $lock=[TokenForge.Core.V0220.PrivateFiles]::Open($lockPath,-not (Test-Path -LiteralPath $lockPath))
  $context=@{Policy=$policy;PolicyHash=$PolicySha256;Synthetic=($PSCmdlet.ParameterSetName -ceq 'Synthetic');Token=$AccessToken;ReadFixture=$ReadFixture;Api=('/repos/'+$policy.Repository);Requests=0;Bytes=0L;Watch=[Diagnostics.Stopwatch]::StartNew();DeadlineSeconds=30;MaxRequests=4;MaxBytes=8MB}
  $ledger=Read-TfPublicationWriterLedger $policy $PolicySha256 $context.Synthetic $root
  $records=@($ledger.Records|Where-Object Transaction -CEQ $Transaction)
  if($records.Count -ne 1){throw 'Recorded transaction required.'};$record=$records[0]
  $repo=Invoke-TfPublicationHttp $context $context.Api
  if((Get-TfPublicationId $repo.id) -cne $policy.RepositoryId -or $repo.full_name -cne $policy.Repository){throw 'Repository mismatch.'}
  $reader=Invoke-TfPublicationHttp $context '/user'
  if((Get-TfPublicationId $reader.id) -cnotin $policy.ReaderIds -or $reader.type -cne 'User'){throw 'Recovery reader not allowlisted.'}
  $commit=Invoke-TfPublicationHttp $context ($context.Api+'/git/commits/'+$record.ProposedCommit)
  if($commit.sha -cne $record.ProposedCommit -or $commit.tree.sha -cne $record.ProposedTree -or $commit.parents -isnot [array] -or $commit.parents.Count -ne 1 -or $commit.parents[0].sha -cne $record.ExpectedParent){throw 'Immutable commit binding mismatch.'}
  $ref=Invoke-TfPublicationHttp $context ($context.Api+'/git/ref/heads/'+$policy.DataBranch)
  if($ref.ref -cne $ledger.Ref -or $ref.object.type -cne 'commit'){throw 'Ref mismatch.'}
  Update-TfPublicationWriterObservation $record $ref.object.sha
  Save-TfPublicationWriterLedger $root $ledger
  return Get-TfPublicationWriteResult $context $record $record.State 0
 }catch{throw 'Publication recovery failed; preserve writer custody and do not redispatch.'}
 finally{if($lock){$lock.Dispose()}}
}
