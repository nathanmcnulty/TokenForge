BeforeAll {
 . "$PSScriptRoot/../scripts/TokenForgePublicationAdapter.ps1"
 . "$PSScriptRoot/fixtures/publication/AdapterFixture.ps1"
}
Describe 'Trusted publication adapter synthetic boundary' {
 BeforeEach {$f=New-PublicationAdapterFixture $TestDrive;$options=$f.Options}
 It 'checks the complete proposal and persists a private synthetic-only handoff without dispatch' {
  $r=Invoke-TokenForgePublicationVerification @options
  $r.Verdict|Should -Be VerifiedForSeparateWriterReview
  $r.Synthetic|Should -BeTrue;$r.AuthorizationEstablished|Should -BeFalse;$r.PublishAllowed|Should -BeFalse;$r.RemoteMutationPerformed|Should -BeFalse;$r.ObservedAuthorityFromAuthenticatedApi|Should -BeFalse
  $r.Requests|Should -BeLessOrEqual 32;$r.CandidateHash|Should -BeExactly $f.Approval.CandidateHash
  $journal=Join-Path $f.Policy.JournalRoot '100-discovery-data/publication.json'
  ([int][IO.File]::GetUnixFileMode($journal) -band 511)|Should -Be 384
  (Read-TfCandidateJson $journal).Records.Count|Should -Be 1
 }
}
Describe 'Publication provenance and independent authority rejection' {
 BeforeEach {$f=New-PublicationAdapterFixture $TestDrive;$options=$f.Options}
 It 'fails closed on a changed authenticated fact (<Case>)' -ForEach @(
  @{Case='ReviewerRevoked'},@{Case='MaintainerRevoked'},@{Case='BotReviewer'},@{Case='ForgedActor'},@{Case='EditedApproval'},@{Case='SupersededApproval'},@{Case='SourceAdvanced'},@{Case='UnprotectedMain'},@{Case='DisabledProtection'},@{Case='WrongRepo'},@{Case='ForkProposal'},@{Case='WrongTarget'},@{Case='DraftProposal'},@{Case='WrongRunAttempt'},@{Case='WrongWorkflow'},@{Case='ProducerFailed'},@{Case='ForkRun'},@{Case='UnapprovedTrigger'},@{Case='WrongArtifact'},@{Case='WrongArtifactRun'},@{Case='ArtifactDigest'},@{Case='WorkflowBytes'},@{Case='SealerHistory'},@{Case='Pagination'},@{Case='Redirect'},@{Case='FutureApproval'}
 ) {
  switch($Case){
   ReviewerRevoked {$f.Server[($f.Api+'/collaborators/actor2/permission')].permission='read'}
   MaintainerRevoked {$f.Server[($f.Api+'/collaborators/actor3/permission')].permission='write'}
   BotReviewer {$f.Actors['2'].type='Bot'}
   ForgedActor {$f.Server[($f.Api+'/issues/comments/101')].user=$f.Actors['1']}
   EditedApproval {$f.Server[($f.Api+'/issues/comments/101')].updated_at='2026-10-23T12:02:00Z'}
   SupersededApproval {$f.Server[($f.Api+'/issues/40/comments?per_page=100')]+=@{id=103;user=$f.Actors['2'];body='withdrawn'}}
   SourceAdvanced {$f.Server[($f.Api+'/branches/main')].commit.sha='9'*40}
   UnprotectedMain {$f.Server[($f.Api+'/branches/main')].protected=$false}
   DisabledProtection {$f.Server[($f.Api+'/branches/main/protection')].enforce_admins.enabled=$false}
   WrongRepo {$f.Server[$f.Api].id=999}
   ForkProposal {$f.Server[($f.Api+'/pulls/40')].head.repo.id=999}
   WrongTarget {$f.Server[($f.Api+'/pulls/40')].base.ref='main'}
   DraftProposal {$f.Server[($f.Api+'/pulls/40')].draft=$true}
   WrongRunAttempt {$f.Server[($f.Api+'/actions/runs/10')].run_attempt=2}
   WrongWorkflow {$f.Server[($f.Api+'/actions/runs/10')].workflow_id=99}
   ProducerFailed {$f.Server[($f.Api+'/actions/runs/10')].conclusion='failure'}
   ForkRun {$f.Server[($f.Api+'/actions/runs/10')].head_repository.id=999}
   UnapprovedTrigger {$f.Server[($f.Api+'/actions/runs/10')].triggering_actor=$f.Actors['5']}
   WrongArtifact {$f.Server[($f.Api+'/actions/artifacts/30')].id=31}
   WrongArtifactRun {$f.Server[($f.Api+'/actions/artifacts/30')].workflow_run.id=11}
   ArtifactDigest {$f.Server[($f.Api+'/actions/artifacts/30')].digest='sha256:'+('9'*64)}
   WorkflowBytes {$f.Server[($f.Api+'/contents/'+$f.Policy.WorkflowPath+'?ref='+$f.Source)].content=[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes('changed'))}
   SealerHistory {$f.Server[($f.Api+'/compare/'+$f.Policy.SealerCommit+'...'+$f.Source)].merge_base_commit.sha='9'*40}
   Pagination {$f.Paginated=$true}
   Redirect {$f.Status=302}
   FutureApproval {foreach($id in @('101','102')){$f.Server[($f.Api+'/issues/comments/'+$id)].created_at='2026-10-23T12:55:00Z';$f.Server[($f.Api+'/issues/comments/'+$id)].updated_at='2026-10-23T12:55:00Z'}}
  }
  {Invoke-TokenForgePublicationVerification @options}|Should -Throw '*Publication verification failed*'
 }
 It 'refuses forged, rebound or nonscalar approval fields (<Field>)' -ForEach @(@{Field='ReviewerId'},@{Field='ExpectedParent'},@{Field='Ref'},@{Field='RepositoryId'},@{Field='CandidateHash'},@{Field='Mapping'},@{Field='PolicySha256'},@{Field='ScalarArray'}) {
  switch($Field){ReviewerId {$f.Approval.ReviewerId='2'} ExpectedParent {$f.Approval.ExpectedParent='9'*40} Ref {$f.Approval.Ref='refs/heads/main'} RepositoryId {$f.Approval.RepositoryId='999'} CandidateHash {$f.Approval.CandidateHash='9'*64} Mapping {$f.Approval.Mapping='LegacyData'} PolicySha256 {$f.Approval.PolicySha256='9'*64} ScalarArray {$f.Approval.Ref=@('refs/heads/discovery-data')}}
  Set-PublicationFixtureApproval $f
  {Invoke-TokenForgePublicationVerification @options}|Should -Throw '*Publication verification failed*'
 }
 It 'rejects duplicate JSON approval fields without echoing their contents' {
  $comment=$f.Server[($f.Api+'/issues/comments/101')];$comment.body=$comment.body.TrimEnd('}')+',"Decision":"Approved","PrivateDetail":"synthetic-sensitive"}'
  {Invoke-TokenForgePublicationVerification @options}|Should -Throw '*Publication verification failed*'
  try{Invoke-TokenForgePublicationVerification @options}catch{$_.Exception.Message|Should -Not -Match 'synthetic-sensitive|PrivateDetail'}
 }
 It 'rejects an altered policy before the first fixture request' {
  Add-Content -LiteralPath $f.PolicyPath ' '
  {Invoke-TokenForgePublicationVerification @options}|Should -Throw '*Publication verification failed*'
  $f.Log.Count|Should -Be 0
 }
 It 'uses the pinned policy snapshot if the original pathname changes before parsing' {
  $script:ReadJsonOriginal=(Get-Command Read-TfPublicationJson).ScriptBlock
  $script:ReplacePolicy=$true
  Mock Read-TfPublicationJson {param($Bytes)
   if($script:ReplacePolicy){$script:ReplacePolicy=$false;[IO.File]::WriteAllText($f.PolicyPath,'{"RepositoryId":"999"}')}
   & $script:ReadJsonOriginal $Bytes
  }
  (Invoke-TokenForgePublicationVerification @options).Verdict|Should -Be VerifiedForSeparateWriterReview
  [IO.File]::ReadAllText($f.PolicyPath)|Should -BeExactly '{"RepositoryId":"999"}'
 }
}
Describe 'Publication sealing and complete commit validation' {
 BeforeEach {$f=New-PublicationAdapterFixture $TestDrive;$options=$f.Options}
 It 'rejects sealing evidence with substituted certificate identity (<Field>)' -ForEach @(@{Field='issuer'},@{Field='sourceRepositoryIdentifier'},@{Field='sourceRepositoryDigest'},@{Field='sourceRepositoryRef'},@{Field='buildSignerURI'},@{Field='buildSignerDigest'},@{Field='runInvocationURI'},@{Field='runnerEnvironment'}) {
  $f.Attestation.verificationResult.signature.certificate[$Field]='untrusted'
  {Invoke-TokenForgePublicationVerification @options}|Should -Throw '*Publication verification failed at Attestation*'
 }
 It 'does not accept a caller-controlled predicate in place of a verified certificate' {
  $f.Attestation.verificationResult.signature.certificate=@{}
  $f.Attestation.verificationResult.statement.predicate=@{sourceRepositoryIdentifier='100';sourceRepositoryDigest=$f.Source}
  {Invoke-TokenForgePublicationVerification @options}|Should -Throw '*Publication verification failed at Attestation*'
 }
 It 'rejects an unverified digest or missing witnessed timestamp (<Case>)' -ForEach @(@{Case='Digest'},@{Case='Time'}) {
  if($Case -eq 'Digest'){$f.Attestation.verificationResult.statement.subject[0].digest.sha256='9'*64}else{$f.Attestation.verificationResult.verifiedTimestamps=@()}
  {Invoke-TokenForgePublicationVerification @options}|Should -Throw '*Publication verification failed at Attestation*'
 }
 It 'rejects an incomplete or altered full tree (<Case>)' -ForEach @(@{Case='Truncated'},@{Case='UnrelatedChange'},@{Case='UnrelatedDelete'},@{Case='UnrelatedAdd'},@{Case='Symlink'},@{Case='Executable'},@{Case='MissingFile'},@{Case='WrongBlob'},@{Case='EmptyDirectory'},@{Case='MergeCommit'}) {
  $tree=$f.Server[($f.Api+'/git/trees/'+$f.NewTree+'?recursive=1')]
  switch($Case){
   Truncated {$tree.truncated=$true}
   UnrelatedChange {$tree.tree[0]=@{path='README.md';mode='100644';type='blob';sha=('9'*40)}}
   UnrelatedDelete {$tree.tree=@($tree.tree|Where-Object path -CNE 'README.md')}
   UnrelatedAdd {$tree.tree+=@{path='.gitmodules';mode='100644';type='blob';sha=('9'*40)}}
   Symlink {$tree.tree[-1].mode='120000'}
   Executable {$tree.tree[-1].mode='100755'}
   MissingFile {$tree.tree=@($tree.tree|Select-Object -SkipLast 1)}
   WrongBlob {$tree.tree[-1].sha='9'*40}
   EmptyDirectory {$tree.tree+=@{path='extra';mode='040000';type='tree';sha=('9'*40)}}
   MergeCommit {$f.Server[($f.Api+'/git/commits/'+$f.New)].parents+=@{sha=('9'*40)}}
  }
  {Invoke-TokenForgePublicationVerification @options}|Should -Throw '*Publication verification failed at Commit*'
 }
 It 'refuses dangerous archive entries before candidate parsing (<Case>)' -ForEach @(@{Case='Traversal'},@{Case='Link'},@{Case='Duplicate'},@{Case='ExpandedSize'}) {
  [IO.File]::Delete($f.Zip);$zip=[IO.Compression.ZipFile]::Open($f.Zip,[IO.Compression.ZipArchiveMode]::Create)
  try{
   foreach($file in Get-ChildItem $f.Candidate -File){
    $name=$file.Name;if($name -ceq 'review.md' -and $Case -eq 'Traversal'){$name='../review.md'}
    $entry=$zip.CreateEntry($name);if($name -ceq 'review.md' -and $Case -eq 'Link'){$entry.ExternalAttributes=0xa000 -shl 16}
    $stream=$entry.Open();try{if($name -ceq 'review.md' -and $Case -eq 'ExpandedSize'){$bytes=[byte[]]::new(9MB)}else{$bytes=[IO.File]::ReadAllBytes($file.FullName)};$stream.Write($bytes,0,$bytes.Length)}finally{$stream.Dispose()}
   }
   if($Case -eq 'Duplicate'){$null=$zip.CreateEntry('MANIFEST.JSON')}
  }finally{$zip.Dispose()}
  [IO.File]::SetUnixFileMode($f.Zip,[IO.UnixFileMode]384)
  $digest=Get-TfCandidateFileHash $f.Zip;$f.Approval.ArtifactSha256=$digest;Set-PublicationFixtureApproval $f
  $artifact=$f.Server[($f.Api+'/actions/artifacts/30')];$artifact.digest='sha256:'+$digest;$artifact.size_in_bytes=(Get-Item $f.Zip).Length
  $f.Attestation.verificationResult.statement.subject[0].digest.sha256=$digest
  {Invoke-TokenForgePublicationVerification @options}|Should -Throw '*Publication verification failed at Candidate*'
  @(Get-ChildItem (Join-Path $f.Policy.JournalRoot '100-discovery-data') -Directory -Force).Count|Should -Be 0
 }
}
Describe 'Publication final observation, private recovery and budgets' {
 BeforeEach {$f=New-PublicationAdapterFixture $TestDrive;$options=$f.Options}
 It 'rejects authority/proposal changes during attestation (<Case>)' -ForEach @(@{Case='MainProtection'},@{Case='MainSha'},@{Case='BaseRef'},@{Case='Fork'},@{Case='Draft'},@{Case='Merged'},@{Case='ReaderRevoked'},@{Case='ReviewerRevoked'},@{Case='NewWithdrawal'},@{Case='Rerun'},@{Case='ArtifactExpiry'}) {
  $options.VerifyFixtureAttestation={
   switch($Case){
    MainProtection {$f.Server[($f.Api+'/branches/main/protection')].enforce_admins.enabled=$false}
    MainSha {$f.Server[($f.Api+'/branches/main')].commit.sha='9'*40}
    BaseRef {$f.Server[($f.Api+'/pulls/40')].base.ref='main'}
    Fork {$f.Server[($f.Api+'/pulls/40')].head.repo.id=999}
    Draft {$f.Server[($f.Api+'/pulls/40')].draft=$true}
    Merged {$f.Server[($f.Api+'/pulls/40')].merged=$true}
    ReaderRevoked {$f.Server[($f.Api+'/collaborators/actor4/permission')].permission='read'}
    ReviewerRevoked {$f.Server[($f.Api+'/collaborators/actor2/permission')].permission='read'}
    NewWithdrawal {$f.Server[($f.Api+'/issues/40/comments?per_page=100')]+=@{id=103;user=$f.Actors['2'];body='withdrawn'}}
    Rerun {$f.Server[($f.Api+'/actions/runs/10')].run_attempt=2}
    ArtifactExpiry {$f.Server[($f.Api+'/actions/artifacts/30')].expired=$true}
   };,@($f.Attestation)
  }.GetNewClosure()
  {Invoke-TokenForgePublicationVerification @options}|Should -Throw '*Publication verification failed*'
 }
 It 'keeps stale parents and expired inputs from being prepared' -ForEach @(@{Kind='Stale';Verdict='StaleParent'},@{Kind='Expired';Verdict='Expired'}) {
  if($Kind -eq 'Stale'){$f.Server[($f.Api+'/git/ref/heads/discovery-data')].object.sha='9'*40}else{$options.FixtureTime=[DateTimeOffset]'2026-10-23T13:01:00Z'}
  $r=Invoke-TokenForgePublicationVerification @options;$r.Verdict|Should -Be $Verdict
  (Read-TfCandidateJson (Join-Path $f.Policy.JournalRoot '100-discovery-data/publication.json')).Records.Count|Should -Be 0
 }
 It 'recovers an observed applied commit after expiry and blocks reuse after an observed rewind' {
  $first=Invoke-TokenForgePublicationVerification @options
  $f.Server[($f.Api+'/git/ref/heads/discovery-data')].object.sha=$f.New;$options.FixtureTime=[DateTimeOffset]'2026-10-23T13:01:00Z'
  $second=Invoke-TokenForgePublicationVerification @options;$second.Verdict|Should -Be AlreadyApplied;$second.Transaction|Should -BeExactly $first.Transaction
  $f.Server[($f.Api+'/git/ref/heads/discovery-data')].object.sha=$f.Old;$options.FixtureTime=[DateTimeOffset]'2026-10-23T12:06:00Z'
  (Invoke-TokenForgePublicationVerification @options).Verdict|Should -Be ConsumedApproval
 }
 It 'does not invent prepared provenance when the first observation already shows the proposed commit' {
  $f.Server[($f.Api+'/git/ref/heads/discovery-data')].object.sha=$f.New
  (Invoke-TokenForgePublicationVerification @options).Verdict|Should -Be ObservedProposedWithoutPreparedState
  (Invoke-TokenForgePublicationVerification @options).Verdict|Should -Be ObservedProposedWithoutPreparedState
  $journal=Read-TfCandidateJson (Join-Path $f.Policy.JournalRoot '100-discovery-data/publication.json')
  $journal.Records[0].PreparedBeforeObservation|Should -BeFalse
 }
 It 'rejects missing canonical state, symlinks, broad permissions and concurrent custody' -ForEach @(@{Case='Missing'},@{Case='Linked'},@{Case='Broad'},@{Case='Locked'}) {
  $null=Invoke-TokenForgePublicationVerification @options;$journal=Join-Path $f.Policy.JournalRoot '100-discovery-data/publication.json';$held=$null
  try{
   switch($Case){Missing {Remove-Item $journal} Linked {Move-Item $journal "$journal.saved";$null=New-Item -ItemType SymbolicLink -Path $journal -Target "$journal.saved"} Broad {[IO.File]::SetUnixFileMode($journal,[IO.UnixFileMode]420)} Locked {$held=[TokenForge.Core.V0220.PrivateFiles]::Open((Join-Path (Split-Path $journal) '.writer.lock'),$false)}}
   {Invoke-TokenForgePublicationVerification @options}|Should -Throw '*Publication verification failed*'
  }finally{if($held){$held.Dispose()}}
 }
 It 'does not exceed the fixed API request allowance' {
  $r=Invoke-TokenForgePublicationVerification @options;$r.Requests|Should -Be 32
  $f.Log.Count|Should -Be 32
  $f.Log|Should -Not -Match '^https?://'
 }
 It 'rejects credential and synthetic parameter sets combined before any request' {
  $options.AccessToken=ConvertTo-SecureString synthetic -AsPlainText -Force;$options.VerifierPath='/not-executed'
  {Invoke-TokenForgePublicationVerification @options}|Should -Throw
  $f.Log.Count|Should -Be 0
 }
}
Describe 'Publication durable handoff fault boundaries' {
 BeforeAll {$script:SaveJournalOriginal=(Get-Command Save-TfPublicationLedger).ScriptBlock}
 BeforeEach {$f=New-PublicationAdapterFixture $TestDrive;$options=$f.Options;$script:FailOnce=$true}
 It 'can reverify after interruption before the first journal commit' {
  Mock Save-TfPublicationLedger {param($StatePath,$Ledger) if($script:FailOnce){$script:FailOnce=$false;throw 'Synthetic stop before commit.'};& $script:SaveJournalOriginal $StatePath $Ledger}
  {Invoke-TokenForgePublicationVerification @options}|Should -Throw '*Publication verification failed at Persist*'
  Test-Path (Join-Path $f.Policy.JournalRoot '100-discovery-data/publication.json')|Should -BeFalse
  (Invoke-TokenForgePublicationVerification @options).Verdict|Should -Be VerifiedForSeparateWriterReview
 }
 It 'preserves applied observation when the local commit acknowledgement is lost' {
  $null=Invoke-TokenForgePublicationVerification @options
  $f.Server[($f.Api+'/git/ref/heads/discovery-data')].object.sha=$f.New
  Mock Save-TfPublicationLedger {param($StatePath,$Ledger) & $script:SaveJournalOriginal $StatePath $Ledger;if($script:FailOnce){$script:FailOnce=$false;throw 'Synthetic stop after commit.'}}
  {Invoke-TokenForgePublicationVerification @options}|Should -Throw '*Publication verification failed at Persist*'
  $f.Server[($f.Api+'/git/ref/heads/discovery-data')].object.sha=$f.Old
  (Invoke-TokenForgePublicationVerification @options).Verdict|Should -Be ConsumedApproval
 }
 It 'refuses synthetic/live journal laundering and altered bound records' -ForEach @(@{Kind='Mode'},@{Kind='Binding'},@{Kind='Replay'}) {
  $null=Invoke-TokenForgePublicationVerification @options
  $journal=Join-Path $f.Policy.JournalRoot '100-discovery-data/publication.json';$ledger=Read-TfCandidateJson $journal
  switch($Kind){Mode {$ledger.Synthetic=$false} Binding {$ledger.Records[0].ExpectedParent='9'*40} Replay {$ledger.Records+=@{Transaction=('9'*64);ReviewerComment='101';MaintainerComment='102';ProposedCommit=$f.New;ExpectedParent=$f.Old;PreparedBeforeObservation=$true;Applied=$true}}}
  [IO.File]::WriteAllText($journal,(ConvertTo-Json -InputObject $ledger -Depth 10 -Compress))
  {Invoke-TokenForgePublicationVerification @options}|Should -Throw '*Publication verification failed*'
 }
 It 'reports expiry reached during verification without preparing work' {
  $script:Clock=[DateTimeOffset]'2026-10-23T12:05:00Z'
  Mock Get-TfPublicationNow {$script:Clock}
  $options.VerifyFixtureAttestation={ $script:Clock=[DateTimeOffset]'2026-10-23T13:05:00Z';,@($f.Attestation) }
  (Invoke-TokenForgePublicationVerification @options).Verdict|Should -Be Expired
 }
}
Describe 'Pinned offline verifier process boundary' {
 BeforeEach {
  $f=New-PublicationAdapterFixture $TestDrive
  $scratch=Join-Path $f.Root verifier-stage;$null=[IO.Directory]::CreateDirectory($scratch,[IO.UnixFileMode]448)
  $tool=Join-Path $f.Root verifier.sh
  $payload=ConvertTo-Json -InputObject @($f.Attestation) -Depth 30 -Compress
  Write-PublicationFixtureFile $tool ("#!/bin/sh`nprintf '%s' '"+$payload+"'`n")
  [IO.File]::SetUnixFileMode($tool,[IO.UnixFileMode]448)
  $context=@{Synthetic=$false;VerifierPath=$tool;Policy=$f.Policy;BundlePath='/synthetic/bundle';TrustRootPath='/synthetic/root';Requests=0;Bytes=0;Watch=[Diagnostics.Stopwatch]::StartNew()}
  $context.Policy.VerifierSha256=Get-TfCandidateFileHash $tool
 }
 It 'executes a private pinned copy with no credential or ambient configuration inheritance' {
  $text="#!/bin/sh`n[ -z `"`$GH_TOKEN`" ] || exit 9`n[ -z `"`$GITHUB_TOKEN`" ] || exit 9`n[ `"`$HOME`" = `"`$GH_CONFIG_DIR`" ] || exit 9`nprintf '%s' '"+$payload+"'`n"
  [IO.File]::WriteAllText($tool,$text);$context.Policy.VerifierSha256=Get-TfCandidateFileHash $tool
  $old=$env:GH_TOKEN;$env:GH_TOKEN='synthetic-not-to-inherit'
  try{$result=Invoke-TfPublicationAttestation $context $f.Zip $f.Source $scratch}finally{$env:GH_TOKEN=$old}
  $result.Count|Should -Be 1
  Test-Path (Join-Path $scratch verifier)|Should -BeTrue
  (Get-TfCandidateFileHash (Join-Path $scratch verifier))|Should -BeExactly $context.Policy.VerifierSha256
  ([int][IO.File]::GetUnixFileMode((Join-Path $scratch verifier)) -band 511)|Should -Be 320
 }
 It 'refuses an unpinned executable and never falls back to ambient gh' {
  $context.Policy.VerifierSha256='9'*64
  {Invoke-TfPublicationAttestation $context $f.Zip $f.Source $scratch}|Should -Throw '*Untrusted verifier*'
 }
 It 'runs the staged bytes if the source pathname changes after copy verification' {
  $script:OriginalFileHash=(Get-Command Get-TfCandidateFileHash).ScriptBlock
  Mock Get-TfCandidateFileHash {param($Path) $hash=& $script:OriginalFileHash $Path;if($Path -ceq (Join-Path $scratch verifier)){[IO.File]::WriteAllText($tool,"#!/bin/sh`nexit 99`n")};$hash}
  (Invoke-TfPublicationAttestation $context $f.Zip $f.Source $scratch).Count|Should -Be 1
 }
 It 'bounds verifier output and refuses nonzero exits (<Case>)' -ForEach @(@{Case='Output'},@{Case='Error'},@{Case='Exit'}) {
  $command=switch($Case){Output {'head -c 4194305 /dev/zero'} Error {'head -c 65537 /dev/zero >&2'} Exit {'exit 7'}}
  [IO.File]::WriteAllText($tool,("#!/bin/sh`n"+$command+"`n"));$context.Policy.VerifierSha256=Get-TfCandidateFileHash $tool
  {Invoke-TfPublicationAttestation $context $f.Zip $f.Source $scratch}|Should -Throw
 }
 It 'stops an existing verifier when the aggregate elapsed budget is exhausted' {
  $context.Watch=@{Elapsed=@{TotalSeconds=60}}
  {Invoke-TfPublicationAttestation $context $f.Zip $f.Source $scratch}|Should -Throw '*budget exhausted*'
 }
}
Describe 'Publication metadata transport resource limits' {
 It 'refuses exhausted aggregate budgets before invoking the transport (<Case>)' -ForEach @(@{Case='Requests'},@{Case='Bytes'},@{Case='Time'}) {
  $context=@{Synthetic=$true;Requests=0;Bytes=0L;Watch=@{Elapsed=@{TotalSeconds=0}};ReadFixture={throw 'Transport must not run.'}}
  switch($Case){Requests {$context.Requests=32} Bytes {$context.Bytes=32MB+1} Time {$context.Watch.Elapsed.TotalSeconds=60}}
  {Invoke-TfPublicationHttp $context '/user'}|Should -Throw '*budget exhausted*'
 }
}
