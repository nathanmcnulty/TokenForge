# Offline smart-HTTP/API simulation. No credential, network, or real GitHub authority.
function Invoke-LocalPublicationGitCommand([string]$Bare,[string[]]$Arguments,[byte[]]$InputBytes) {
 $start=[Diagnostics.ProcessStartInfo]::new('git');$start.UseShellExecute=$false
 $start.RedirectStandardInput=$true;$start.RedirectStandardOutput=$true;$start.RedirectStandardError=$true
 foreach($arg in $Arguments){$start.ArgumentList.Add($arg)}
 $process=[Diagnostics.Process]::Start($start);$output=[IO.MemoryStream]::new()
 try {
  $read=$process.StandardOutput.BaseStream.CopyToAsync($output)
  $errors=$process.StandardError.ReadToEndAsync()
  if($InputBytes){$process.StandardInput.BaseStream.Write($InputBytes)}
  $process.StandardInput.Close()
  if(-not $process.WaitForExit(10000)){$process.Kill($true);throw 'Local bare Git command timed out.'}
  $null=$read.GetAwaiter().GetResult();$null=$errors.GetAwaiter().GetResult()
  if($process.ExitCode -ne 0 -or $output.Length -gt 2MB){throw 'Local bare Git command refused.'}
  return ,$output.ToArray()
 }finally{$output.Dispose();$process.Dispose()}
}
function New-LocalPublicationServer([string]$Parent,[switch]$BareGit,[string]$ExistingRoot) {
 $bare=$null;$parentSha='d'*40;$raceSha=$null
 if($BareGit){
  $bare=Join-Path $Parent (([guid]::NewGuid().ToString('N'))+'.git')
  $null=& git init --bare -q $bare;if($LASTEXITCODE){throw 'Bare Git fixture initialization failed.'}
  $empty=(& git -C $bare hash-object -w -t tree /dev/null).Trim();if($LASTEXITCODE){throw 'Bare Git empty tree failed.'}
  $old=@{};foreach($key in @('GIT_AUTHOR_NAME','GIT_AUTHOR_EMAIL','GIT_COMMITTER_NAME','GIT_COMMITTER_EMAIL')){$old[$key]=[Environment]::GetEnvironmentVariable($key)}
  try{
   $env:GIT_AUTHOR_NAME='Fixture';$env:GIT_AUTHOR_EMAIL='fixture@example.invalid';$env:GIT_COMMITTER_NAME='Fixture';$env:GIT_COMMITTER_EMAIL='fixture@example.invalid'
   $parentSha=(& git -C $bare commit-tree $empty -m initial).Trim();if($LASTEXITCODE){throw 'Bare Git parent failed.'}
   $raceSha=(& git -C $bare commit-tree $empty -p $parentSha -m competing).Trim();if($LASTEXITCODE){throw 'Bare Git competing commit failed.'}
  }finally{foreach($key in $old.Keys){[Environment]::SetEnvironmentVariable($key,$old[$key])}}
  $null=& git -C $bare update-ref refs/heads/data $parentSha;if($LASTEXITCODE){throw 'Bare Git ref failed.'}
 }
 if($ExistingRoot){
  $packetPath=Join-Path $ExistingRoot packet
  $packetSha=Get-TfCandidateFileHash (Join-Path $packetPath packet.json)
  $packet=(Read-TfLocalDocument (Join-Path $packetPath packet.json) 32KB).Value
  $policy=(Read-TfLocalDocument (Join-Path $packetPath policy.json) 16KB).Value
  $approvalPath=Join-Path $ExistingRoot 'approved-body.json'
  $f=@{Root=$ExistingRoot;PacketPath=$packetPath;PacketSha256=$packetSha;Packet=$packet;Policy=$policy;ReviewPath=(Join-Path $ExistingRoot review.json);Draft=@{Body=[IO.File]::ReadAllText($approvalPath);BodySha256=(Get-TfCandidateFileHash $approvalPath)};CandidateHash=$packet.CandidateHash}
 }else{$f=New-LocalPublicationFixture $Parent -ExpectedParent $parentSha}
 $x=Read-TfLocalPacket $f.PacketPath $f.PacketSha256
 $bodyPath=Join-Path $f.Root 'approved-body.json'
 if(-not $ExistingRoot){$file=[TokenForge.Core.V0220.PrivateFiles]::Open($bodyPath,$true);try{$bytes=[Text.Encoding]::UTF8.GetBytes($f.Draft.Body);$file.Write($bytes);$file.Flush($true)}finally{$file.Dispose()}}
 $now=[DateTimeOffset]::Parse('2026-11-06T12:05:00+00:00')
 $actor=@{id=1;login='actor1';type='User'}
 $comment=@{id=101;node_id='IC_fixture101';user=$actor;issue_url='https://api.github.com/repos/example/TokenForge/issues/40';body=$f.Draft.Body;created_at='2026-11-06T12:01:00Z';updated_at='2026-11-06T12:01:00Z'}
 $blobs=@{};foreach($name in $x.Files.Keys){$sha=Get-TfPublicationBlobHash $x.Files[$name];$blobs[$sha]=[byte[]]$x.Files[$name]}
 $s=@{Fixture=$f;X=$x;Now=$now;Actor=$actor;Comment=$comment;Tip=$f.Packet.ExpectedParent;BareGit=$bare;RaceCommit=$raceSha;RaceAtPost=$false;Private=$true;PostMode='Apply';Posts=0;Reads=0;Log=[Collections.Generic.List[string]]::new();Blobs=$blobs;BlobTampered=$false;CommentEdited=$false;CommentSuperseded=$false;CommentAuthorWrong=$false;CommentBodyWrong=$false;PrHeadWrong=$false;RepositoryWrong=$false;PermissionWrong=$false}
 $gitCommand=(Get-Command Invoke-LocalPublicationGitCommand).ScriptBlock
 $s.ReadFixture={param($operation,$arguments)
  $s.Reads++;$s.Log.Add($operation+' '+$arguments.Route)
  $value=switch -CaseSensitive ($operation) {
   GetUser {$s.Actor}
   GetRepository {@{id=100;full_name=if($s.RepositoryWrong){'other/TokenForge'}else{'example/TokenForge'};private=[bool]$s.Private;visibility=if($s.Private){'private'}else{'public'};archived=$false;disabled=$false}}
   GetPermission {@{user=$s.Actor;permission=if($s.PermissionWrong){'read'}else{'admin'}}}
   GetPullRequest {@{number=40;state='open';merged=$false;head=@{repo=@{id=100};sha=if($s.PrHeadWrong){'f'*40}else{'a'*40}};base=@{repo=@{id=100}}}}
   GetComment {
    $copy=@{};foreach($key in $s.Comment.Keys){$copy[$key]=$s.Comment[$key]}
    if($s.CommentAuthorWrong){$copy.user=@{id=2;login='actor2';type='User'}}
    if($s.CommentBodyWrong){$copy.body='different approval'}
    $copy
   }
   GetComments {}
   GetCommentEdit {@{data=@{node=@{id=$s.Comment.node_id;lastEditedAt=if($s.CommentEdited){'2026-11-06T12:02:00Z'}else{$null}}}}}
   GetCommit {
    $sha=$arguments.Route.Split('/')[-1]
    if($sha -ceq $s.Fixture.Packet.ExpectedParent){@{sha=$sha;tree=@{sha=$s.Fixture.Packet.BaseTree};parents=@()}}
    elseif($sha -ceq $s.Fixture.Packet.ProposedCommit){@{sha=$sha;tree=@{sha=$s.Fixture.Packet.ProposedTree};parents=@(@{sha=$s.Fixture.Packet.ExpectedParent})}}
    else{throw 'Unexpected synthetic commit.'}
   }
   GetRef {@{ref=$s.Fixture.Packet.Ref;object=@{type='commit';sha=$s.Tip}}}
   GetTree {@{sha=$s.Fixture.Packet.ProposedTree;truncated=$false;tree=@($s.X.Git.Entries)}}
   GetBlob {
    $sha=$arguments.Route.Split('/')[-1]
    if(-not $s.Blobs.ContainsKey($sha)){throw 'Unexpected synthetic blob.'}
    $data=if($s.BareGit){& $gitCommand $s.BareGit @('-C',$s.BareGit,'cat-file','blob',$sha) $null}else{[byte[]]$s.Blobs[$sha]}
    if($s.BlobTampered){$data=[byte[]]$data.Clone();$data[0]=$data[0] -bxor 1}
    @{sha=$sha;encoding='base64';size=$s.Blobs[$sha].Length;content=[Convert]::ToBase64String($data)}
   }
   GetCompare {@{status='identical';merge_base_commit=@{sha=$s.Fixture.Packet.ExpectedParent}}}
   default {throw 'Unexpected synthetic read operation.'}
  }
  if($operation -ceq 'GetComments'){
   $copy=@{};foreach($key in $s.Comment.Keys){$copy[$key]=$s.Comment[$key]}
   if($s.CommentAuthorWrong){$copy.user=@{id=2;login='actor2';type='User'}}
   if($s.CommentBodyWrong){$copy.body='different approval'}
   $rows=[object[]]@($copy)
   if($s.CommentSuperseded){$rows+=@{id=102;node_id='IC_fixture102';user=$s.Actor;issue_url=$copy.issue_url;body='superseding comment';created_at='2026-11-06T12:02:00Z';updated_at='2026-11-06T12:02:00Z'}}
   $payload=ConvertTo-Json -InputObject $rows -Depth 100 -Compress
  }else{$payload=ConvertTo-Json -InputObject $value -Depth 100 -Compress}
  @{Status=200;Paginated=$false;Bytes=[Text.Encoding]::UTF8.GetBytes($payload);ServerDate=$s.Now;ContentType='application/json'}
 }.GetNewClosure()
 $packetizer=(Get-Command ConvertTo-TfGitPacket).ScriptBlock
 $s.GitFixture={param($operation,$arguments)
  $s.Log.Add($operation+' '+$arguments.Route)
  if($operation -ceq 'GetAdvertisement'){
   $bytes=[byte[]]((& $packetizer "# service=git-receive-pack`n")+[Text.Encoding]::ASCII.GetBytes('0000')+(& $packetizer ($s.Tip+' '+$s.Fixture.Packet.Ref+"`0report-status`n"))+[Text.Encoding]::ASCII.GetBytes('0000'))
   return @{Status=200;Paginated=$false;Bytes=$bytes;ServerDate=$s.Now;ContentType='application/x-git-receive-pack-advertisement'}
  }
  if($operation -cne 'PostUpdate'){throw 'Unexpected synthetic Git operation.'}
  $s.Posts++
  $expected=[byte[]]((& $packetizer ($s.Fixture.Packet.ExpectedParent+' '+$s.Fixture.Packet.ProposedCommit+' '+$s.Fixture.Packet.Ref+"`0report-status`n"))+[Text.Encoding]::ASCII.GetBytes('0000')+$s.X.Pack)
  if($arguments.Body.Length -ne $expected.Length){throw 'Unexpected synthetic outbound pack.'}
  for($i=0;$i -lt $expected.Length;$i++){if($arguments.Body[$i] -ne $expected[$i]){throw 'Unexpected synthetic outbound pack.'}}
  if($s.PostMode -ceq 'Interrupt'){throw 'Synthetic interruption before receive.'}
  if($s.PostMode -ceq 'Crash'){[Diagnostics.Process]::GetCurrentProcess().Kill();throw 'Unreachable after synthetic process kill.'}
  if($s.RaceAtPost -and $s.BareGit){
   $null=& git -C $s.BareGit update-ref refs/heads/data $s.RaceCommit $s.Fixture.Packet.ExpectedParent
   if($LASTEXITCODE){throw 'Bare Git competing update failed.'};$s.Tip=$s.RaceCommit
  }
  if($s.PostMode -ceq 'Reject' -or (-not $s.BareGit -and $s.Tip -cne $s.Fixture.Packet.ExpectedParent)){
   $ack=[byte[]]((& $packetizer "unpack ok`n")+(& $packetizer ('ng '+$s.Fixture.Packet.Ref+" non-fast-forward`n"))+[Text.Encoding]::ASCII.GetBytes('0000'))
  }else{
   if($s.BareGit){
    $ack=& $gitCommand $s.BareGit @('-c','core.hooksPath=/dev/null','receive-pack','--stateless-rpc',$s.BareGit) $arguments.Body
    $actual=(& git -C $s.BareGit rev-parse refs/heads/data).Trim();if($LASTEXITCODE){throw 'Bare Git ref read failed.'}
    $s.Tip=$actual
    if($s.PostMode -ceq 'LostAck'){throw 'Synthetic acknowledgement lost after apply.'}
    return @{Status=200;Paginated=$false;Bytes=$ack;ServerDate=$s.Now;ContentType='application/x-git-receive-pack-result'}
   }
   $s.Tip=$s.Fixture.Packet.ProposedCommit
   if($s.PostMode -ceq 'LostAck'){throw 'Synthetic acknowledgement lost after apply.'}
   $ack=[byte[]]((& $packetizer "unpack ok`n")+(& $packetizer ('ok '+$s.Fixture.Packet.Ref+"`n"))+[Text.Encoding]::ASCII.GetBytes('0000'))
  }
  @{Status=200;Paginated=$false;Bytes=$ack;ServerDate=$s.Now;ContentType='application/x-git-receive-pack-result'}
 }.GetNewClosure()
 $s.PublishOptions=@{PacketPath=$f.PacketPath;PacketSha256=$f.PacketSha256;ReviewPath=$f.ReviewPath;ApprovalBodyPath=$bodyPath;ApprovedApprovalSha256=$f.Draft.BodySha256;ApprovalCommentId='101';Synthetic=$true;ReadFixture=$s.ReadFixture;GitFixture=$s.GitFixture;FixtureTime=$now}
 $s.StatusOptions=@{PacketPath=$f.PacketPath;PacketSha256=$f.PacketSha256;Synthetic=$true;ReadFixture=$s.ReadFixture;GitFixture=$s.GitFixture;FixtureTime=$now}
 return $s
}
