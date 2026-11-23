BeforeAll {
 . "$PSScriptRoot/../scripts/TokenForgeLocalPublication.ps1"
 . "$PSScriptRoot/fixtures/publication/LocalPublicationFixture.ps1"
 . "$PSScriptRoot/fixtures/publication/LocalPublicationServer.ps1"
 function Get-LocalState($Server) {
  $path=Join-Path $Server.Fixture.Policy.JournalRoot '100-data/local-publication.json'
  Read-TfCandidateJson $path
 }
}
Describe 'Synthetic sole-administrator publication state machine' {
 BeforeEach {$s=New-LocalPublicationServer $TestDrive;$publish=$s.PublishOptions;$status=$s.StatusOptions}
 It 'applies one exact pack and verifies seven downloaded blob bytes' {
  $r=Invoke-TokenForgeLocalPublication @publish
  $r.Status | Should -BeExactly 'AppliedVerified'
  $r.Publication | Should -BeExactly 'SyntheticOnly'
  $r.AuthorizationEstablished | Should -BeFalse
  $s.Posts | Should -Be 1
  $s.Tip | Should -BeExactly $s.Fixture.Packet.ProposedCommit
  @($s.Log|Where-Object {$_ -clike 'GetBlob *'}).Count | Should -Be 7
  $state=Get-LocalState $s
  $state.Records[0].Dispatches | Should -Be 1
  $state.Records[0].State | Should -BeExactly 'AppliedVerified'
  $state.Records[0].Reads | Should -BeGreaterThan 0
  $state.Records[0].BytesReserved | Should -BeGreaterThan 0
  $state.Records[0].VerifiedAt | Should -Not -BeNullOrEmpty
 }
 It 'reconciles an applied write after losing its acknowledgement without another POST' {
  $s.PostMode='LostAck'
  $r=Invoke-TokenForgeLocalPublication @publish
  $r.Status | Should -BeExactly 'AppliedVerified'
  $s.Posts | Should -Be 1
  (Get-LocalState $s).Records[0].LastAck | Should -BeExactly 'Unknown'
  $again=Invoke-TokenForgeLocalPublication @publish
  $again.Status | Should -BeExactly 'AppliedVerified'
  $s.Posts | Should -Be 1
 }
 It 'requires an explicit reconciled retry after a rejected CAS' {
  $s.PostMode='Reject'
  $r=Invoke-TokenForgeLocalPublication @publish
  $r.Status | Should -BeExactly 'Rejected'
  $s.Posts | Should -Be 1
  {Invoke-TokenForgeLocalPublication @publish} | Should -Throw
  $s.Posts | Should -Be 1
  $s.PostMode='Apply';$publish.Retry=$true
  $r=Invoke-TokenForgeLocalPublication @publish
  $r.Status | Should -BeExactly 'AppliedVerified'
  $s.Posts | Should -Be 2
  (Get-LocalState $s).Records[0].Attempts.Count | Should -Be 2
 }
 It 'keeps an interrupted dispatch charged and status read-only until an explicit retry' {
  $s.PostMode='Interrupt'
  $r=Invoke-TokenForgeLocalPublication @publish
  $r.Status | Should -BeExactly 'UnknownAtParent'
  $s.Posts | Should -Be 1
  $state=Get-LocalState $s;$state.Records[0].Dispatches | Should -Be 1
  $state.Records[0].Attempts.Count | Should -Be 1
  $read=Get-TokenForgeLocalPublicationStatus @status
  $read.Status | Should -BeExactly 'UnknownAtParent'
  $s.Posts | Should -Be 1
  {Invoke-TokenForgeLocalPublication @publish} | Should -Throw
  $s.Posts | Should -Be 1
  $s.PostMode='Apply';$publish.Retry=$true
  (Invoke-TokenForgeLocalPublication @publish).Status | Should -BeExactly 'AppliedVerified'
  $s.Posts | Should -Be 2
 }
 It 'refuses edited, wrong-author, superseded or body-mismatched approval before dispatch' {
  foreach($flag in @('CommentEdited','CommentAuthorWrong','CommentSuperseded','CommentBodyWrong')){
   $case=New-LocalPublicationServer $TestDrive;$case[$flag]=$true;$options=$case.PublishOptions
   {Invoke-TokenForgeLocalPublication @options} | Should -Throw
   $case.Posts | Should -Be 0
  }
 }
 It 'refuses source-head drift and nonprivate destination before dispatch' {
  $s.Private=$false
  {Invoke-TokenForgeLocalPublication @publish} | Should -Throw
  $s.Posts | Should -Be 0
  $case=New-LocalPublicationServer $TestDrive;$case.PrHeadWrong=$true;$options=$case.PublishOptions
  {Invoke-TokenForgeLocalPublication @options} | Should -Throw
  $case.Posts | Should -Be 0
 }
 It 'retains uncertain state if downloaded blob bytes differ, then verifies on read-only recovery' {
  $s.BlobTampered=$true
  $r=Invoke-TokenForgeLocalPublication @publish
  $r.Status | Should -BeExactly 'Unknown'
  $s.Posts | Should -Be 1
  $s.BlobTampered=$false
  $read=Get-TokenForgeLocalPublicationStatus @status
  $read.Status | Should -BeExactly 'AppliedVerified'
  $s.Posts | Should -Be 1
 }
 It 'refuses expired approval and stops recovery after its bounded window' {
  $s.Now=[DateTimeOffset]::Parse('2026-11-06T12:16:00+00:00');$publish.FixtureTime=$s.Now
  {Invoke-TokenForgeLocalPublication @publish} | Should -Throw
  $s.Posts | Should -Be 0
  $case=New-LocalPublicationServer $TestDrive;$options=$case.PublishOptions;$readOptions=$case.StatusOptions
  (Invoke-TokenForgeLocalPublication @options).Status | Should -BeExactly 'AppliedVerified'
  $case.Now=[DateTimeOffset]::Parse('2026-11-06T13:01:00+00:00');$readOptions.FixtureTime=$case.Now
  {Get-TokenForgeLocalPublicationStatus @readOptions} | Should -Throw
  $case.Posts | Should -Be 1
 }
 It 'refuses a missing journal or marker and malformed accounting without another POST' {
  (Invoke-TokenForgeLocalPublication @publish).Status | Should -BeExactly 'AppliedVerified'
  $root=Join-Path $s.Fixture.Policy.JournalRoot '100-data'
  $ledgerPath=Join-Path $root 'local-publication.json';$marker=Join-Path $root '.local-publication.initialized'
  $original=(Read-TfLocalDocument $ledgerPath 16KB).Bytes
  Remove-Item -LiteralPath $marker -Force
  {Get-TokenForgeLocalPublicationStatus @status} | Should -Throw
  [IO.File]::WriteAllBytes($marker,[byte[]]@());[IO.File]::SetUnixFileMode($marker,[IO.UnixFileMode]384)
  Remove-Item -LiteralPath $ledgerPath -Force
  {Get-TokenForgeLocalPublicationStatus @status} | Should -Throw
  [IO.File]::WriteAllBytes($ledgerPath,$original);[IO.File]::SetUnixFileMode($ledgerPath,[IO.UnixFileMode]384)
  $state=Get-LocalState $s;$state.Records[0].Reads=-1
  Write-TfCandidateJson $state $ledgerPath
  {Get-TokenForgeLocalPublicationStatus @status} | Should -Throw
  $s.Posts | Should -Be 1
 }
 It 'honors a local exclusive lock before any transport call' {
  (Invoke-TokenForgeLocalPublication @publish).Status | Should -BeExactly 'AppliedVerified'
  $path=Join-Path $s.Fixture.Policy.JournalRoot '100-data/.local-publication.lock'
  $lock=[IO.File]::Open($path,[IO.FileMode]::Open,[IO.FileAccess]::ReadWrite,[IO.FileShare]::None)
  try{$before=$s.Reads;{Get-TokenForgeLocalPublicationStatus @status} | Should -Throw;$s.Reads | Should -Be $before}finally{$lock.Dispose()}
  $s.Posts | Should -Be 1
 }
 It 'refuses missing or changed retained authority before recovery reads' {
  (Invoke-TokenForgeLocalPublication @publish).Status | Should -BeExactly 'AppliedVerified'
  $root=Join-Path $s.Fixture.Policy.JournalRoot '100-data'
  $authority=Join-Path $root ($s.Fixture.PacketSha256+'.authority.json')
  $saved=[IO.File]::ReadAllBytes($authority)
  $before=$s.Reads
  Remove-Item -LiteralPath $authority -Force
  {Get-TokenForgeLocalPublicationStatus @status} | Should -Throw
  $s.Reads | Should -Be $before
  [IO.File]::WriteAllBytes($authority,[byte[]]($saved+[Text.Encoding]::ASCII.GetBytes(' ')))
  [IO.File]::SetUnixFileMode($authority,[IO.UnixFileMode]384)
  {Get-TokenForgeLocalPublicationStatus @status} | Should -Throw
  $s.Reads | Should -Be $before
  $s.Posts | Should -Be 1
 }
 It 'refuses to use a synthetic packet through the live parameter set before transport' {
  $token=ConvertTo-SecureString 'synthetic-only' -AsPlainText -Force
  $live=@{PacketPath=$s.Fixture.PacketPath;PacketSha256=$s.Fixture.PacketSha256;ReviewPath=$s.Fixture.ReviewPath;ApprovalBodyPath=$publish.ApprovalBodyPath;ApprovedApprovalSha256=$s.Fixture.Draft.BodySha256;ApprovalCommentId='101';Live=$true;AccessToken=$token}
  {Invoke-TokenForgeLocalPublication @live} | Should -Throw
  $s.Reads | Should -Be 0
  $s.Posts | Should -Be 0
 }
 It 'imports the proposed full pack and updates a real local bare Git ref with exact-old CAS' {
  $case=New-LocalPublicationServer $TestDrive -BareGit;$options=$case.PublishOptions
  $r=Invoke-TokenForgeLocalPublication @options
  $r.Status | Should -BeExactly 'AppliedVerified'
  $case.Posts | Should -Be 1
  (& git -C $case.BareGit rev-parse refs/heads/data).Trim() | Should -BeExactly $case.Fixture.Packet.ProposedCommit
  ((& git -C $case.BareGit cat-file -p $case.Fixture.Packet.ProposedCommit) -join "`n") | Should -Match ([regex]::Escape('parent '+$case.Fixture.Packet.ExpectedParent))
  $paths=@(& git -C $case.BareGit ls-tree -r --name-only $case.Fixture.Packet.ProposedCommit)
  @($paths|Where-Object {$_ -clike ('candidates/'+$case.Fixture.CandidateHash+'/*')}).Count | Should -Be 7
  foreach($name in $case.X.Files.Keys){
   $expected=[byte[]]$case.X.Files[$name];$sha=Get-TfPublicationBlobHash $expected
   $actual=Invoke-LocalPublicationGitCommand $case.BareGit @('-C',$case.BareGit,'cat-file','blob',$sha) $null
   $actual.Length | Should -Be $expected.Length
   (Get-TfLocalDigest $actual) | Should -BeExactly (Get-TfLocalDigest $expected)
  }
  $null=& git -C $case.BareGit update-ref refs/heads/data $case.Fixture.Packet.ExpectedParent $case.Fixture.Packet.ExpectedParent 2>$null
  $LASTEXITCODE | Should -Not -Be 0
  (& git -C $case.BareGit rev-parse refs/heads/data).Trim() | Should -BeExactly $case.Fixture.Packet.ProposedCommit
 }
 It 'receives a negative exact-old ACK after a competing bare-Git ref advance and never resends automatically' {
  $case=New-LocalPublicationServer $TestDrive -BareGit;$case.RaceAtPost=$true;$options=$case.PublishOptions
  $r=Invoke-TokenForgeLocalPublication @options
  $r.Status | Should -BeExactly 'Conflict'
  $case.Posts | Should -Be 1
  $r.ObjectTransfer | Should -BeExactly 'Unknown'
  (& git -C $case.BareGit rev-parse refs/heads/data).Trim() | Should -BeExactly $case.RaceCommit
  (Get-LocalState $case).Records[0].LastAck | Should -BeExactly 'Rejected'
  (Invoke-TokenForgeLocalPublication @options).Status | Should -BeExactly 'Conflict'
  $case.Posts | Should -Be 1
 }
 It 'retains dispatch charges after a killed publisher process and reconciles before retry' {
  $childScript=Join-Path $s.Fixture.Root 'crash-publisher.ps1'
  [IO.File]::WriteAllText($childScript,@'
param($SourcePath,$FixturePath,$ServerPath,$FixtureRoot)
$ErrorActionPreference='Stop'
. $SourcePath
. $FixturePath
. $ServerPath
$server=New-LocalPublicationServer '' -ExistingRoot $FixtureRoot
$server.PostMode='Crash'
$options=$server.PublishOptions
$null=Invoke-TokenForgeLocalPublication @options
exit 0
'@)
  $start=[Diagnostics.ProcessStartInfo]::new((Get-Command pwsh).Source)
  $start.UseShellExecute=$false
  foreach($arg in @('-NoProfile','-File',$childScript,(Join-Path $PSScriptRoot '../scripts/TokenForgeLocalPublication.ps1'),(Join-Path $PSScriptRoot 'fixtures/publication/LocalPublicationFixture.ps1'),(Join-Path $PSScriptRoot 'fixtures/publication/LocalPublicationServer.ps1'),$s.Fixture.Root)){$start.ArgumentList.Add($arg)}
  $child=[Diagnostics.Process]::Start($start)
  try{if(-not $child.WaitForExit(30000)){$child.Kill($true);throw 'Synthetic crash process timeout.'};$child.ExitCode|Should -Not -Be 0}finally{$child.Dispose()}
  $state=Get-LocalState $s
  $state.Records[0].Dispatches | Should -Be 1
  $state.Records[0].State | Should -BeExactly 'DispatchStarted'
  $state.Records[0].PendingRead.Operation | Should -BeExactly 'PostUpdate'
  $state.Records[0].Attempts.Count | Should -Be 1
  $recovered=New-LocalPublicationServer '' -ExistingRoot $s.Fixture.Root
  $readOptions=$recovered.StatusOptions
  (Get-TokenForgeLocalPublicationStatus @readOptions).Status | Should -BeExactly 'UnknownAtParent'
  $recovered.Posts | Should -Be 0
  $retry=$recovered.PublishOptions;$retry.Retry=$true
  (Invoke-TokenForgeLocalPublication @retry).Status | Should -BeExactly 'AppliedVerified'
  $recovered.Posts | Should -Be 1
  (Get-LocalState $recovered).Records[0].Dispatches | Should -Be 2
 }
}
