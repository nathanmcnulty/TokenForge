BeforeAll {
 . "$PSScriptRoot/../scripts/TokenForgePublicationWriter.ps1"
 . "$PSScriptRoot/fixtures/publication/WriterFixture.ps1"
}

Describe 'Explicit publication execution boundary' {
 BeforeEach {$f=New-PublicationWriterFixture $TestDrive;$options=$f.WriterOptions;$recovery=$f.RecoveryOptions}
 It 'requires execution intent before metadata or mutation transport' {
  $options.ExecutePublication=$false;$before=$f.Log.Count
  {Invoke-TokenForgePublication @options}|Should -Throw '*no remote write performed*'
  $f.Log.Count|Should -Be $before;$f.Posts|Should -Be 0
 }
 It 'refuses a different approved transaction after complete fresh verification' {
  $options.ApprovedTransaction='9'*64
  {Invoke-TokenForgePublication @options}|Should -Throw '*no remote write performed*'
  $f.Posts|Should -Be 0;$f.GitReads|Should -Be 0
 }
 It 'keeps the public verification entry point unable to accept mutation options' {
  {Invoke-TokenForgePublicationVerification @options}|Should -Throw
  $f.Posts|Should -Be 0
 }
 It 'cannot combine a synthetic write callback with live credentials' {
  $options.AccessToken=ConvertTo-SecureString 'synthetic' -AsPlainText -Force
  {Invoke-TokenForgePublication @options}|Should -Throw
  $f.Posts|Should -Be 0
 }
 It 'refuses using the producer as writer even when it has current repository permission' {
  $f.Server['/user']=$f.Actors['1'];$f.Policy.ReaderIds=@('1')
  [IO.File]::WriteAllText($f.PolicyPath,($f.Policy|ConvertTo-Json -Depth 10 -Compress))
  $f.PolicyHash=Get-TfCandidateFileHash $f.PolicyPath;$options.PolicySha256=$f.PolicyHash;$f.Approval.PolicySha256=$f.PolicyHash;Set-PublicationFixtureApproval $f
  [IO.Directory]::Delete((Split-Path $f.Journal),$true)
  $verify=$f.Options.Clone();$verify.PolicySha256=$f.PolicyHash
  $options.ApprovedTransaction=(Invoke-TokenForgePublicationVerification @verify).Transaction
  {Invoke-TokenForgePublication @options}|Should -Throw
  $f.Posts|Should -Be 0
 }
 It 'catches withdrawal during Git discovery in the final authority pass' {
  $options.WriteFixture={param($Method,$Body)
   $response=& $f.WriteFixture $Method $Body
   if($Method -ceq 'GET'){$f.Server[($f.Api+'/issues/comments/101')].body='withdrawn'}
   $response
  }
  {Invoke-TokenForgePublication @options}|Should -Throw '*FinalObservations*'
  $f.Posts|Should -Be 0;Test-Path $f.Journal|Should -BeFalse
 }
 It 'refuses stale Git discovery before any durable dispatch intent' {
  $options.WriteFixture={param($Method,$Body)
   $response=& $f.WriteFixture $Method $Body
   $response.Bytes=[byte[]]((ConvertTo-TfGitPacket "# service=git-receive-pack`n")+[Text.Encoding]::ASCII.GetBytes('0000')+(ConvertTo-TfGitPacket (('9'*40)+" refs/heads/discovery-data`0report-status`n"))+[Text.Encoding]::ASCII.GetBytes('0000'))
   $response
  }
  {Invoke-TokenForgePublication @options}|Should -Throw '*WriterDiscovery*'
  $f.Posts|Should -Be 0;Test-Path $f.Journal|Should -BeFalse
 }
}

Describe 'Durable one-shot publication and independent recovery' {
 BeforeAll {$script:SaveWriterOriginal=(Get-Command Save-TfPublicationWriterLedger).ScriptBlock}
 BeforeEach {$f=New-PublicationWriterFixture $TestDrive;$options=$f.WriterOptions;$recovery=$f.RecoveryOptions}
 It 'records intent before one CAS, reconciles the ref and never republishes that transaction' {
  $r=Invoke-TokenForgePublication @options
  $r.Status|Should -Be Applied;$r.DispatchesThisInvocation|Should -Be 1
  $r.GitRequests|Should -Be 2;$r.MetadataRequests|Should -Be 2
  $r.Synthetic|Should -BeTrue;$r.AuthorizationEstablished|Should -BeFalse;$r.RemoteMutationPerformed|Should -BeFalse;$r.HostedExecutionProof|Should -BeFalse
  $state=Read-TfCandidateJson $f.Journal;$state.Records[0].State|Should -Be Applied
  (Invoke-TokenForgePublication @options).DispatchesThisInvocation|Should -Be 0
  $f.Posts|Should -Be 1
 }
 It 'reconciles transport loss and malformed acknowledgements without retransmission (<Mode>)' -ForEach @(@{Mode='LostAck'},@{Mode='Malformed'}) {
  $f.Mode=$Mode
  (Invoke-TokenForgePublication @options).Status|Should -Be Applied
  (Get-TokenForgePublicationWriterStatus @recovery).Status|Should -Be Applied
  $f.Posts|Should -Be 1
 }
 It 'keeps a pre-application transport loss unknown even when the old ref is observed' {
  $f.Mode='PreSendLoss'
  (Invoke-TokenForgePublication @options).Status|Should -Be Unknown
  (Get-TokenForgePublicationWriterStatus @recovery).Status|Should -Be Unknown
  (Invoke-TokenForgePublication @options).DispatchesThisInvocation|Should -Be 0
  $f.Posts|Should -Be 1
 }
 It 'does not treat acknowledged success followed by rewind as rejection or permission to retry' {
  $f.Mode='Rewind'
  (Invoke-TokenForgePublication @options).Status|Should -Be Unknown
  (Get-TokenForgePublicationWriterStatus @recovery).Status|Should -Be Unknown
  $f.Posts|Should -Be 1
 }
 It 'records a definitive rejection but never resends the rejected transaction' {
  $f.Mode='Reject'
  (Invoke-TokenForgePublication @options).Status|Should -Be Rejected
  (Invoke-TokenForgePublication @options).DispatchesThisInvocation|Should -Be 0
  $f.Posts|Should -Be 1
 }
 It 'can retry preparation interrupted before durable intent without guessing that a POST occurred' {
  Mock Save-TfPublicationWriterLedger {throw 'Synthetic stop before durable intent.'}
  {Invoke-TokenForgePublication @options}|Should -Throw
  $f.Posts|Should -Be 0;Test-Path $f.Journal|Should -BeFalse
 }
 It 'recovers a crash after durable intent but before POST without resending' {
  Mock Save-TfPublicationWriterLedger {param($Root,$Ledger) & $script:SaveWriterOriginal $Root $Ledger;throw 'Synthetic stop after intent.'}
  {Invoke-TokenForgePublication @options}|Should -Throw
  $f.Posts|Should -Be 0
  (Read-TfCandidateJson $f.Journal).Records[0].State|Should -Be DispatchStarted
 }
 It 'preserves unknown intent if post-dispatch local acknowledgement is lost' {
  $script:Saves=0
  Mock Save-TfPublicationWriterLedger {param($Root,$Ledger) $script:Saves++;if($script:Saves -eq 2){throw 'Synthetic stop after remote application.'};& $script:SaveWriterOriginal $Root $Ledger}
  {Invoke-TokenForgePublication @options}|Should -Throw '*outcome may be unknown*'
  (Read-TfCandidateJson $f.Journal).Records[0].State|Should -Be DispatchStarted
  (Get-TokenForgePublicationWriterStatus @recovery).Status|Should -Be Applied
  $f.Posts|Should -Be 1
 }
 It 'checks expiry again after durable intent and never sends an expired command' {
  $script:Clock=[DateTimeOffset]'2026-10-23T12:05:00Z'
  Mock Get-TfPublicationNow {$script:Clock}
  Mock Save-TfPublicationWriterLedger {param($Root,$Ledger) & $script:SaveWriterOriginal $Root $Ledger;$script:Clock=[DateTimeOffset]'2026-10-23T13:05:00Z'}
  {Invoke-TokenForgePublication @options}|Should -Throw '*outcome may be unknown*'
  $f.Posts|Should -Be 0
  (Read-TfCandidateJson $f.Journal).Records[0].State|Should -Be DispatchStarted
  (Get-TokenForgePublicationWriterStatus @recovery).Status|Should -Be Unknown
 }
 It 'checks the original verification deadline after durable intent even while the writer still has time' {
  $script:BudgetOriginal=(Get-Command Test-TfPublicationBudget).ScriptBlock
  Mock Test-TfPublicationBudget {param($Context)
   if(-not $Context.ContainsKey('DeadlineSeconds')){$script:VerificationContext=$Context}
   & $script:BudgetOriginal $Context
  }
  Mock Save-TfPublicationWriterLedger {param($Root,$Ledger)
   & $script:SaveWriterOriginal $Root $Ledger
   $script:VerificationContext.Watch=@{Elapsed=@{TotalSeconds=60}}
  }
  {Invoke-TokenForgePublication @options}|Should -Throw '*outcome may be unknown*'
  $f.Posts|Should -Be 0
  (Read-TfCandidateJson $f.Journal).Records[0].State|Should -Be DispatchStarted
 }
 It 'preserves uncertainty if post-write observation fails, then recovers by GET only' {
  $f.OnRead={param($fixture,$route) if($fixture.Posts -gt 0 -and $route -clike '*/git/ref/*'){throw 'Synthetic observation failure.'}}
  (Invoke-TokenForgePublication @options).Status|Should -Be Unknown
  $f.OnRead=$null
  (Get-TokenForgePublicationWriterStatus @recovery).Status|Should -Be Applied
  $f.Posts|Should -Be 1
 }
 It 'recovers without fresh PR/main/artifact/approval predicates or the saved archive' {
  $null=Invoke-TokenForgePublication @options
  $f.Server[($f.Api+'/pulls/40')].state='closed';$f.Server[($f.Api+'/branches/main')].commit.sha='9'*40
  $f.Server[($f.Api+'/actions/artifacts/30')].expired=$true;$f.Server[($f.Api+'/collaborators/actor2/permission')].permission='read'
  Remove-Item $f.Zip
  $before=$f.Log.Count
  (Get-TokenForgePublicationWriterStatus @recovery).Status|Should -Be Applied
  $f.Log.Count-$before|Should -Be 4;$f.Posts|Should -Be 1
 }
 It 'blocks new approvals from bypassing uncertainty on the whole repository/ref' {
  $f.Mode='PreSendLoss';$null=Invoke-TokenForgePublication @options
  foreach($pair in @(@{Old='101';New=103},@{Old='102';New=104})){
   $c=$f.Server[($f.Api+'/issues/comments/'+$pair.Old)].Clone();$c.id=$pair.New;$f.Server[($f.Api+'/issues/comments/'+$pair.New)]=$c
  }
  $f.Server[($f.Api+'/issues/40/comments?per_page=100')]=@($f.Server[($f.Api+'/issues/comments/103')],$f.Server[($f.Api+'/issues/comments/104')])
  $verify=$f.Options.Clone();$verify.ReviewerComment='103';$verify.MaintainerComment='104'
  $options.ReviewerComment='103';$options.MaintainerComment='104';$options.ApprovedTransaction=(Invoke-TokenForgePublicationVerification @verify).Transaction
  {Invoke-TokenForgePublication @options}|Should -Throw '*no remote write performed*'
  $f.Posts|Should -Be 1
 }
 It 'retains consumed state after a known applied ref is rewound' {
  $null=Invoke-TokenForgePublication @options
  $f.Server[($f.Api+'/git/ref/heads/discovery-data')].object.sha=$f.Old
  (Get-TokenForgePublicationWriterStatus @recovery).Status|Should -Be Consumed
  (Invoke-TokenForgePublication @options).DispatchesThisInvocation|Should -Be 0
  $f.Posts|Should -Be 1
 }
 It 'fails closed if canonical writer custody disappears or changes (<Case>)' -ForEach @(@{Case='Missing'},@{Case='Mode'},@{Case='Linked'},@{Case='Broad'},@{Case='Commit'}) {
  $null=Invoke-TokenForgePublication @options
  switch($Case){
   Missing {Remove-Item $f.Journal}
   Mode {$j=Read-TfCandidateJson $f.Journal;$j.Synthetic=$false;[IO.File]::WriteAllText($f.Journal,($j|ConvertTo-Json -Depth 10 -Compress))}
   Linked {Move-Item $f.Journal ($f.Journal+'.saved');$null=New-Item -ItemType SymbolicLink -Path $f.Journal -Target ($f.Journal+'.saved')}
   Broad {[IO.File]::SetUnixFileMode($f.Journal,[IO.UnixFileMode]420)}
   Commit {$f.Server[($f.Api+'/git/commits/'+$f.New)].tree.sha='9'*40}
  }
  {Get-TokenForgePublicationWriterStatus @recovery}|Should -Throw '*preserve writer custody*'
  $f.Posts|Should -Be 1
 }
 It 'holds the shared custody lock during dispatch' {
  $options.WriteFixture={param($Method,$Body)
   if($Method -ceq 'POST'){
    {Get-TokenForgePublicationWriterStatus @recovery}|Should -Throw '*preserve writer custody*'
   }
   & $f.WriteFixture $Method $Body
  }
  (Invoke-TokenForgePublication @options).Status|Should -Be Applied
  $f.Posts|Should -Be 1
 }
}

Describe 'Strict Git protocol subset' {
 It 'rejects malformed packet framing (<Text>)' -ForEach @(@{Text='000'},@{Text='zzzz'},@{Text='0001'},@{Text='0002'},@{Text='0004'},@{Text='0009bad'}) {
  {Read-TfGitPackets ([Text.Encoding]::ASCII.GetBytes($Text))}|Should -Throw
 }
 It 'requires a complete service advertisement, exact old ref and supported capabilities (<Case>)' -ForEach @(@{Case='Missing'},@{Case='Stale'},@{Case='Capability'},@{Case='Format'},@{Case='Duplicate'},@{Case='Banner'}) {
  $sha='a'*40;$ref='refs/heads/discovery-data';$caps='report-status object-format=sha1';$banner="# service=git-receive-pack`n"
  switch($Case){Missing {$ref='refs/heads/other'} Stale {$sha='b'*40} Capability {$caps='report-status-v2'} Format {$caps='report-status object-format=sha256'} Banner {$banner="# service=git-upload-pack`n"}}
  $bytes=[byte[]]((ConvertTo-TfGitPacket $banner)+[Text.Encoding]::ASCII.GetBytes('0000')+(ConvertTo-TfGitPacket ($sha+' '+$ref+"`0"+$caps+"`n")))
  if($Case -eq 'Duplicate'){$bytes+=[byte[]](ConvertTo-TfGitPacket ($sha+' '+$ref+"`n"))}
  $bytes+=[Text.Encoding]::ASCII.GetBytes('0000')
  {Assert-TfGitAdvertisement $bytes 'refs/heads/discovery-data' ('a'*40)}|Should -Throw
 }
 It 'rejects incomplete, extra or unrelated status records (<Case>)' -ForEach @(@{Case='UnpackOnly'},@{Case='StatusOnly'},@{Case='WrongRef'},@{Case='Extra'},@{Case='NoFlush'}) {
  $bytes=[byte[]](ConvertTo-TfGitPacket "unpack ok`n")
  if($Case -ne 'UnpackOnly'){$bytes+=[byte[]](ConvertTo-TfGitPacket $(if($Case -eq 'WrongRef'){"ok refs/heads/main`n"}else{"ok refs/heads/discovery-data`n"}))}
  if($Case -eq 'StatusOnly'){$bytes=[byte[]](ConvertTo-TfGitPacket "ok refs/heads/discovery-data`n")}
  if($Case -eq 'Extra'){$bytes+=[byte[]](ConvertTo-TfGitPacket "ok refs/heads/main`n")}
  if($Case -ne 'NoFlush'){$bytes+=[Text.Encoding]::ASCII.GetBytes('0000')}
  {Read-TfGitAcknowledgement $bytes 'refs/heads/discovery-data'}|Should -Throw
 }
}

Describe 'Publication writer transport budgets' {
 It 'rejects bad Git response envelopes without interpreting their bytes (<Case>)' -ForEach @(@{Case='Redirect'},@{Case='Type'},@{Case='Size'}) {
  $context=@{Synthetic=$true;GitRequests=0;Requests=0;Bytes=0L;Watch=[Diagnostics.Stopwatch]::StartNew();DeadlineSeconds=30;MaxRequests=2;MaxBytes=8MB}
  $response=@{Status=200;ContentType='application/x-git-receive-pack-advertisement';Bytes=[byte[]]@(48,48,48,48)}
  switch($Case){Redirect {$response.Status=302} Type {$response.ContentType='text/html'} Size {$response.Bytes=[byte[]]::new(2MB+1)}}
  $context.WriteFixture={param($Method,$Body) $response}
  {Invoke-TfPublicationGitHttp $context GET}|Should -Throw '*Invalid Git response*'
 }
 It 'refuses depleted writer request, byte and time allowances before invoking transport (<Case>)' -ForEach @(@{Case='Requests'},@{Case='Bytes'},@{Case='Time'}) {
  $context=@{Synthetic=$true;GitRequests=0;Requests=0;Bytes=0L;Watch=@{Elapsed=@{TotalSeconds=0}};DeadlineSeconds=30;MaxRequests=2;MaxBytes=8MB;WriteFixture={throw 'Must not run.'}}
  switch($Case){Requests {$context.GitRequests=2} Bytes {$context.Bytes=8MB+1} Time {$context.Watch.Elapsed.TotalSeconds=30}}
  {Invoke-TfPublicationGitHttp $context GET}|Should -Throw '*budget*'
 }
}
