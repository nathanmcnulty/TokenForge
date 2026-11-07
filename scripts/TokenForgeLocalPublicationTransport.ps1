#Requires -Version 7.6
# Fixed-operation HTTPS transport. Caller owns persistent request/dispatch charging.
function Invoke-TfLocalPublicationTransport {
 [CmdletBinding()]param(
  [Parameter(Mandatory)]$Context,
  [Parameter(Mandatory)][string]$Operation,
  [Collections.IDictionary]$Arguments=@{}
 )
 $repo=[string]$Context.Policy.Repository
 $branch=[string]$Context.Policy.DataBranch
 if($repo -cnotmatch '\A[A-Za-z0-9][A-Za-z0-9_.-]{0,99}/[A-Za-z0-9][A-Za-z0-9_.-]{0,99}\z' -or $branch -cnotmatch '\A[A-Za-z0-9][A-Za-z0-9_-]{0,63}\z'){throw 'Local transport policy target.'}
 if($null -eq $Arguments){$Arguments=@{}}
 $allowed=@{
  GetUser=@();GetRepository=@();GetPermission=@('Login');GetPullRequest=@('Number');GetComment=@('CommentId');GetComments=@('Number');GetCommentEdit=@('NodeId');GetRef=@();GetCommit=@('Sha');GetTree=@('Sha');GetBlob=@('Sha');GetCompare=@('Base','Head');GetAdvertisement=@();PostUpdate=@('Body')
 }
 if(-not $allowed.ContainsKey($Operation) -or $Arguments.Count -ne $allowed[$Operation].Count -or @($Arguments.Keys|Where-Object {$_ -cnotin $allowed[$Operation]}).Count){throw 'Local transport operation or arguments.'}
 $api='/repos/'+$repo;$method='GET';$body=$null;$kind='Api';$route=$null
 switch -CaseSensitive ($Operation) {
  GetUser {$route='/user'}
  GetRepository {$route=$api}
  GetPermission {
   $login=[string]$Arguments.Login
   if($login -cnotmatch '\A[A-Za-z0-9][A-Za-z0-9-]{0,38}\z'){throw 'Local transport login.'}
   $route="$api/collaborators/$login/permission"
  }
  GetPullRequest {
   $id=[string]$Arguments.Number;if($id -cnotmatch '\A[1-9][0-9]{0,18}\z'){throw 'Local transport pull request.'}
   $route="$api/pulls/$id"
  }
  GetComment {
   $id=[string]$Arguments.CommentId;if($id -cnotmatch '\A[1-9][0-9]{0,18}\z'){throw 'Local transport comment.'}
   $route="$api/issues/comments/$id"
  }
  GetComments {
   $id=[string]$Arguments.Number;if($id -cnotmatch '\A[1-9][0-9]{0,18}\z'){throw 'Local transport issue.'}
   $route="$api/issues/$id/comments?per_page=100"
  }
  GetCommentEdit {
   $nodeId=[string]$Arguments.NodeId
   if($nodeId -cnotmatch '\A[A-Za-z0-9_+/=-]{1,256}\z'){throw 'Local transport node ID.'}
   $route='/graphql';$method='POST';$kind='GraphQL'
   $query='query($id:ID!){node(id:$id){... on IssueComment{id lastEditedAt}}}'
   $body=[Text.UTF8Encoding]::new($false,$true).GetBytes((@{query=$query;variables=@{id=$nodeId}}|ConvertTo-Json -Compress -Depth 4))
  }
  GetRef {$route="$api/git/ref/heads/$branch"}
  GetCommit {
   $sha=[string]$Arguments.Sha;if($sha -cnotmatch '\A[a-f0-9]{40}\z'){throw 'Local transport Git SHA.'}
   $route="$api/git/commits/$sha"
  }
  GetTree {
   $sha=[string]$Arguments.Sha;if($sha -cnotmatch '\A[a-f0-9]{40}\z'){throw 'Local transport Git SHA.'}
   $route="$api/git/trees/$sha`?recursive=1"
  }
  GetBlob {
   $sha=[string]$Arguments.Sha;if($sha -cnotmatch '\A[a-f0-9]{40}\z'){throw 'Local transport Git SHA.'}
   $route="$api/git/blobs/$sha"
  }
  GetCompare {
   $base=[string]$Arguments.Base;$head=[string]$Arguments.Head
   if($base -cnotmatch '\A[a-f0-9]{40}\z' -or $head -cnotmatch '\A[a-f0-9]{40}\z'){throw 'Local transport comparison SHA.'}
   $route="$api/compare/$base...$head"
  }
  GetAdvertisement {$kind='GitAdvertisement';$route="https://github.com/$repo.git/info/refs?service=git-receive-pack"}
  PostUpdate {
   if($Arguments.Body -isnot [byte[]] -or $Arguments.Body.Length -lt 32 -or $Arguments.Body.Length -gt 8MB){throw 'Local transport pack body.'}
   $body=[byte[]]$Arguments.Body;$kind='GitResult';$method='POST';$route="https://github.com/$repo.git/git-receive-pack"
  }
 }
 $now=if($Context.Synthetic -and $Context.FixedNow){[DateTimeOffset]$Context.FixedNow}else{[DateTimeOffset]::UtcNow}
 $deadline=[DateTimeOffset]$Context.DeadlineUtc
 if($deadline -le $now){throw 'Local transport deadline.'}
 $responseLimit=if($Context.MaxResponseBytes){[long]$Context.MaxResponseBytes}else{4MB}
 $aggregateLimit=if($Context.MaxBytes){[long]$Context.MaxBytes}else{32MB}
 if($responseLimit -lt 1 -or $responseLimit -gt 4MB -or $aggregateLimit -lt 1 -or $aggregateLimit -gt 32MB -or [long]$Context.Bytes -lt 0){throw 'Local transport byte budget.'}
 $outbound=if($null -eq $body){0L}else{[long]$body.Length}
 if(([long]$Context.Bytes+$outbound) -gt $aggregateLimit){throw 'Local transport byte budget.'}
 $Context.Bytes=[long]$Context.Bytes+$outbound
 $normalized=[ordered]@{Route=$route;Method=$method}
 if($null -ne $body){$normalized.Body=$body}
 if($Context.Synthetic){
  if($kind -clike 'Git*'){
   if($Context.FixtureGit -isnot [scriptblock]){throw 'Local Git fixture missing.'}
   $response=& $Context.FixtureGit $Operation $normalized
  }else{
   if($Context.FixtureRead -isnot [scriptblock]){throw 'Local API fixture missing.'}
   $response=& $Context.FixtureRead $Operation $normalized
  }
 }else{
  if($Context.Token -isnot [Security.SecureString]){throw 'Local transport credential missing.'}
  $remaining=($deadline-[DateTimeOffset]::UtcNow).TotalSeconds
  if($remaining -le 0){throw 'Local transport deadline.'}
  $handler=[Net.Http.HttpClientHandler]::new();$handler.AllowAutoRedirect=$false;$handler.UseCookies=$false;$handler.UseProxy=$false
  $client=[Net.Http.HttpClient]::new($handler);$timeout=[TimeSpan]::FromSeconds([Math]::Min(10,$remaining));$client.Timeout=$timeout
  $cancel=[Threading.CancellationTokenSource]::new();$cancel.CancelAfter($timeout)
  $url=if($kind -clike 'Git*'){$route}else{'https://api.github.com'+$route}
  $request=[Net.Http.HttpRequestMessage]::new([Net.Http.HttpMethod]::new($method),$url)
  try {
   $request.Version=[Version]::new(1,1);$request.VersionPolicy=[Net.Http.HttpVersionPolicy]::RequestVersionExact
   $request.Headers.UserAgent.ParseAdd('TokenForge-LocalPublication/1.0')
   $request.Headers.ConnectionClose=$true
   if($kind -clike 'Git*'){
    $accept=if($kind -ceq 'GitAdvertisement'){'application/x-git-receive-pack-advertisement'}else{'application/x-git-receive-pack-result'}
    $request.Headers.Accept.ParseAdd($accept)
    $credential=[Net.NetworkCredential]::new('',$Context.Token).Password
    $auth=[Text.Encoding]::UTF8.GetBytes('x-access-token:'+$credential)
    try{$request.Headers.Authorization=[Net.Http.Headers.AuthenticationHeaderValue]::new('Basic',[Convert]::ToBase64String($auth))}finally{[Array]::Clear($auth)}
   }else{
    $request.Headers.Accept.ParseAdd('application/vnd.github+json')
    $request.Headers.Add('X-GitHub-Api-Version','2022-11-28')
    $request.Headers.Authorization=[Net.Http.Headers.AuthenticationHeaderValue]::new('Bearer',[Net.NetworkCredential]::new('',$Context.Token).Password)
   }
   if($null -ne $body){
    $request.Content=[Net.Http.ByteArrayContent]::new($body)
    $media=if($kind -ceq 'GitResult'){'application/x-git-receive-pack-request'}else{'application/json'}
    $request.Content.Headers.ContentType=[Net.Http.Headers.MediaTypeHeaderValue]::new($media)
   }
   try {
    $message=$client.Send($request,[Net.Http.HttpCompletionOption]::ResponseHeadersRead,$cancel.Token)
    try {
     if([int]$message.StatusCode -ne 200 -or $message.Headers.Contains('Link')){throw 'Local transport response refused.'}
     $media=[string]$message.Content.Headers.ContentType.MediaType
     if($message.Content.Headers.ContentLength -gt $responseLimit -or $message.Content.Headers.ContentLength+[long]$Context.Bytes -gt $aggregateLimit){throw 'Local transport response bound.'}
     $date=$message.Headers.Date;if(-not $date){throw 'Local transport server date missing.'}
     $stream=$message.Content.ReadAsStream();$memory=[IO.MemoryStream]::new();$buffer=[byte[]]::new(8192)
     try {
      while(($read=$stream.ReadAsync($buffer,0,$buffer.Length,$cancel.Token).GetAwaiter().GetResult()) -gt 0){
       if($memory.Length+$read -gt $responseLimit -or [long]$Context.Bytes+$memory.Length+$read -gt $aggregateLimit -or [DateTimeOffset]::UtcNow -ge $deadline){throw 'Local transport response bound.'}
       $memory.Write($buffer,0,$read)
      }
      $response=@{Status=200;Paginated=$false;Bytes=$memory.ToArray();ContentType=$media;ServerDate=$date}
     }finally{$memory.Dispose();$stream.Dispose()}
    }finally{$message.Dispose()}
   }catch{throw 'Local transport request refused.'}
  }finally{$request.Dispose();$client.Dispose();$handler.Dispose();$cancel.Dispose()}
 }
 if($response.Status -ne 200 -or $response.Paginated -ne $false -or $response.Bytes -isnot [byte[]] -or $response.Bytes.Length -gt $responseLimit -or [long]$Context.Bytes+$response.Bytes.Length -gt $aggregateLimit){throw 'Local transport response refused.'}
 if(-not $Context.Synthetic -and [string]::IsNullOrEmpty([string]$response.ContentType)){throw 'Local transport response type.'}
 if($kind -clike 'Git*'){
  $expectedType=if($kind -ceq 'GitAdvertisement'){'application/x-git-receive-pack-advertisement'}else{'application/x-git-receive-pack-result'}
  if(([string]$response.ContentType).Split(';')[0].Trim() -cne $expectedType){throw 'Local Git response type.'}
 }elseif($response.ContentType -and ([string]$response.ContentType).Split(';')[0].Trim() -cnotin @('application/json','application/vnd.github+json')){throw 'Local API response type.'}
 $serverDate=if($response.ServerDate){[DateTimeOffset]$response.ServerDate}elseif($Context.Synthetic -and $Context.FixedNow){[DateTimeOffset]$Context.FixedNow}else{throw 'Local transport server date missing.'}
 $now=if($Context.Synthetic -and $Context.FixedNow){[DateTimeOffset]$Context.FixedNow}else{[DateTimeOffset]::UtcNow}
 if([Math]::Abs(($serverDate-$now).TotalSeconds) -gt 300 -or $now -ge $deadline){throw 'Local transport server clock or deadline.'}
 $Context.ServerDate=$serverDate;$Context.Bytes=[long]$Context.Bytes+$response.Bytes.Length
 if($kind -clike 'Git*'){return ,([byte[]]$response.Bytes)}
 $value=Read-TfPublicationJson $response.Bytes
 if($kind -ceq 'GraphQL'){
  if($value -isnot [Collections.IDictionary] -or $value.Contains('errors') -or $value.data -isnot [Collections.IDictionary] -or $value.data.node -isnot [Collections.IDictionary] -or $value.data.node.Count -ne 2 -or $value.data.node.id -cne [string]$Arguments.NodeId -or -not $value.data.node.Contains('lastEditedAt') -or ($null -ne $value.data.node.lastEditedAt -and $value.data.node.lastEditedAt -isnot [string])){throw 'Local comment edit evidence.'}
  return ,$value.data.node
 }
 return ,$value
}
