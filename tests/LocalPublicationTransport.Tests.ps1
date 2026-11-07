BeforeAll {
 . "$PSScriptRoot/../scripts/TokenForgeLocalPublicationTransport.ps1"
 function Read-TfPublicationJson([byte[]]$Bytes) {return ,([Text.Encoding]::UTF8.GetString($Bytes)|ConvertFrom-Json -AsHashtable -Depth 64)}
 function New-LocalTransportContext {
  $now=[DateTimeOffset]::Parse('2026-11-06T12:00:00Z')
  return @{
   Policy=@{Repository='owner/private-repo';DataBranch='data_ref'};Synthetic=$true;FixedNow=$now;DeadlineUtc=$now.AddMinutes(1);MaxResponseBytes=4MB;MaxBytes=32MB;Bytes=0L;ServerDate=$null
   FixtureRead={param($operation,$arguments) $script:lastTransport=@($operation,$arguments);@{Status=200;Paginated=$false;Bytes=[Text.Encoding]::UTF8.GetBytes('{}');ServerDate=$now}}
   FixtureGit={param($operation,$arguments) $script:lastTransport=@($operation,$arguments);$media=if($operation -ceq 'GetAdvertisement'){'application/x-git-receive-pack-advertisement'}else{'application/x-git-receive-pack-result'};@{Status=200;Paginated=$false;ContentType=$media;Bytes=[byte[]]@(1,2,3);ServerDate=$now}}
  }
 }
}
Describe 'Local publication fixed transport' {
 BeforeEach {$script:lastTransport=$null;$c=New-LocalTransportContext}
 It 'maps only named read operations to pinned routes' {
  $cases=@(
   @{Op='GetUser';Args=@{};Route='/user'},
   @{Op='GetRepository';Args=@{};Route='/repos/owner/private-repo'},
   @{Op='GetPermission';Args=@{Login='Nathan-1'};Route='/repos/owner/private-repo/collaborators/Nathan-1/permission'},
   @{Op='GetPullRequest';Args=@{Number=12};Route='/repos/owner/private-repo/pulls/12'},
   @{Op='GetComment';Args=@{CommentId=99};Route='/repos/owner/private-repo/issues/comments/99'},
   @{Op='GetComments';Args=@{Number=12};Route='/repos/owner/private-repo/issues/12/comments?per_page=100'},
   @{Op='GetRef';Args=@{};Route='/repos/owner/private-repo/git/ref/heads/data_ref'},
   @{Op='GetCommit';Args=@{Sha=('a'*40)};Route=('/repos/owner/private-repo/git/commits/'+('a'*40))},
   @{Op='GetTree';Args=@{Sha=('a'*40)};Route=('/repos/owner/private-repo/git/trees/'+('a'*40)+'?recursive=1')},
   @{Op='GetBlob';Args=@{Sha=('a'*40)};Route=('/repos/owner/private-repo/git/blobs/'+('a'*40))},
   @{Op='GetCompare';Args=@{Base=('a'*40);Head=('b'*40)};Route=('/repos/owner/private-repo/compare/'+('a'*40)+'...'+('b'*40))}
  )
  foreach($case in $cases){
   $null=Invoke-TfLocalPublicationTransport $c $case.Op $case.Args
   $script:lastTransport[0] | Should -BeExactly $case.Op
   $script:lastTransport[1].Route | Should -BeExactly $case.Route
   $script:lastTransport[1].Method | Should -BeExactly 'GET'
  }
  $c.Bytes | Should -Be 22
 }
 It 'uses only fixed Git endpoints and accounts for the outbound body' {
  $reply=Invoke-TfLocalPublicationTransport $c 'GetAdvertisement' @{}
  $reply.Length | Should -Be 3
  $script:lastTransport[1].Route | Should -BeExactly 'https://github.com/owner/private-repo.git/info/refs?service=git-receive-pack'
  $body=[byte[]]::new(32)
  $reply=Invoke-TfLocalPublicationTransport $c 'PostUpdate' @{Body=$body}
  $script:lastTransport[1].Route | Should -BeExactly 'https://github.com/owner/private-repo.git/git-receive-pack'
  $script:lastTransport[1].Method | Should -BeExactly 'POST'
  $c.Bytes | Should -Be 38
 }
 It 'queries only IssueComment edit metadata and checks its node identity' {
  $c.FixtureRead={param($operation,$arguments)
   $script:lastTransport=@($operation,$arguments)
   @{Status=200;Paginated=$false;Bytes=[Text.Encoding]::UTF8.GetBytes('{"data":{"node":{"id":"IC_abc","lastEditedAt":null}}}');ServerDate=$c.FixedNow}
  }
  $node=Invoke-TfLocalPublicationTransport $c 'GetCommentEdit' @{NodeId='IC_abc'}
  $node.id | Should -BeExactly 'IC_abc'
  $node.Contains('lastEditedAt') | Should -BeTrue
  $script:lastTransport[1].Route | Should -BeExactly '/graphql'
  $script:lastTransport[1].Method | Should -BeExactly 'POST'
  $query=[Text.Encoding]::UTF8.GetString($script:lastTransport[1].Body)|ConvertFrom-Json -AsHashtable
  $query.variables.id | Should -BeExactly 'IC_abc'
  $query.query | Should -Match 'lastEditedAt'
  $c.FixtureRead={param($operation,$arguments) @{Status=200;Paginated=$false;Bytes=[Text.Encoding]::UTF8.GetBytes('{"errors":[{"message":"no"}],"data":{"node":{"id":"IC_abc","lastEditedAt":null}}}');ServerDate=$c.FixedNow}}
  {Invoke-TfLocalPublicationTransport $c 'GetCommentEdit' @{NodeId='IC_abc'}} | Should -Throw
 }
 It 'refuses routes, extra arguments, stale time and oversized or paginated replies' {
  {Invoke-TfLocalPublicationTransport $c 'CreateComment' @{}} | Should -Throw
  {Invoke-TfLocalPublicationTransport $c 'GetUser' @{Route='/user'}} | Should -Throw
  {Invoke-TfLocalPublicationTransport $c 'GetPermission' @{Login='../admin'}} | Should -Throw
  {Invoke-TfLocalPublicationTransport $c 'GetCommit' @{Sha=('A'*40)}} | Should -Throw
  {Invoke-TfLocalPublicationTransport $c 'PostUpdate' @{Body=[byte[]]@(1)}} | Should -Throw
  $c.Policy.DataBranch='../main';{Invoke-TfLocalPublicationTransport $c 'GetUser' @{}} | Should -Throw
  $c.Policy.DataBranch='data_ref';$c.DeadlineUtc=$c.FixedNow;{Invoke-TfLocalPublicationTransport $c 'GetUser' @{}} | Should -Throw
  $c.DeadlineUtc=$c.FixedNow.AddMinutes(1)
  $c.FixtureRead={param($operation,$arguments) @{Status=200;Paginated=$true;Bytes=[Text.Encoding]::UTF8.GetBytes('{}');ServerDate=$c.FixedNow}}
  {Invoke-TfLocalPublicationTransport $c 'GetUser' @{}} | Should -Throw
  $c.FixtureRead={param($operation,$arguments) @{Status=200;Paginated=$false;Bytes=[byte[]]::new(10);ServerDate=$c.FixedNow}}
  $c.MaxResponseBytes=9;{Invoke-TfLocalPublicationTransport $c 'GetUser' @{}} | Should -Throw
  $c.MaxResponseBytes=4MB;$c.MaxBytes=1;{Invoke-TfLocalPublicationTransport $c 'GetUser' @{}} | Should -Throw
  $c.MaxBytes=32MB;$c.FixtureRead={param($operation,$arguments) @{Status=200;Paginated=$false;Bytes=[Text.Encoding]::UTF8.GetBytes('{}');ServerDate=$c.FixedNow.AddMinutes(6)}}
  {Invoke-TfLocalPublicationTransport $c 'GetUser' @{}} | Should -Throw
 }
}
