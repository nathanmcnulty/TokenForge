BeforeAll {
 . "$PSScriptRoot/../scripts/TokenForgePublicationRecovery.ps1"
 function Set-PublicationFixtureDocuments {
  param($Candidate,$Approval,$Journal,$Options)
  $Options.CandidateJson=ConvertTo-Json -InputObject $Candidate -Compress
  $Options.CandidateSha256=Get-TokenForgePublicationPlanHash $Options.CandidateJson
  $Approval.CandidateSha256=$Options.CandidateSha256
  $Options.ApprovalJson=ConvertTo-Json -InputObject $Approval -Compress
  $Options.ApprovalSha256=Get-TokenForgePublicationPlanHash $Options.ApprovalJson
  $Journal.CandidateSha256=$Options.CandidateSha256;$Journal.ApprovalSha256=$Options.ApprovalSha256
  $Journal.TransactionSha256=Get-TokenForgePublicationTransactionHash -CandidateSha256 $Options.CandidateSha256 -ApprovalSha256 $Options.ApprovalSha256 -SourceCommit $Candidate.SourceCommit -ProducerRunId $Candidate.ProducerRunId -ProducerAttempt $Candidate.ProducerAttempt -ExpectedParent $Options.ExpectedParent -ProposedCommit $Options.ProposedCommit
  $Options.JournalJson=ConvertTo-Json -InputObject $Journal -Compress
 }
}
Describe 'Offline publication compare-and-swap and recovery planning' {
 BeforeEach {
  $now=[DateTimeOffset]'2026-10-23T12:00:00+00:00'
  $candidate=[ordered]@{SchemaVersion=1;Kind='TokenForgePublicationCandidate';ContentSha256=('e'*64);SourceCommit=('a'*40);ProducerRunId='12345';ProducerAttempt='1';CreatedAt=$now.AddHours(-2).ToString('o');ExpiresAt=$now.AddHours(4).ToString('o')}
  $approval=[ordered]@{SchemaVersion=1;Kind='TokenForgePublicationApproval';CandidateSha256=('a'*64);SourceCommit=$candidate.SourceCommit;ProducerRunId=$candidate.ProducerRunId;ProducerAttempt=$candidate.ProducerAttempt;Decision='Approved';ReviewerId='67890';ReviewedAt=$now.AddHours(-1).ToString('o');ExpiresAt=$now.AddHours(3).ToString('o')}
  $options=@{CandidateJson='';CandidateSha256='';ApprovalJson='';ApprovalSha256='';ExpectedParent=('b'*40);ProposedCommit=('c'*40);ObservedParent=('b'*40);Now=$now}
  $journal=[ordered]@{SchemaVersion=1;Kind='TokenForgePublicationPreparedTransaction';TransactionSha256=('a'*64);CandidateSha256=('a'*64);ApprovalSha256=('b'*64);SourceCommit=$candidate.SourceCommit;ProducerRunId=$candidate.ProducerRunId;ProducerAttempt=$candidate.ProducerAttempt;ExpectedParent=$options.ExpectedParent;ProposedCommit=$options.ProposedCommit;PreparedAt=$now.AddMinutes(-30).ToString('o')}
  Set-PublicationFixtureDocuments $candidate $approval $journal $options
 }
 It 'requires separately verified hosted authorization for a current unexpired transaction' {
  $plan=Get-TokenForgePublicationRecoveryPlan @options
  $plan.Verdict|Should -BeExactly NeedsVerifiedHostedAuthorization
  $plan.NewWritePlanned|Should -BeTrue
  $plan.AuthorizationEstablished|Should -BeFalse
  $plan.ExecutionPerformed|Should -BeFalse
  $plan.ProducerIdentityEstablished|Should -BeFalse
  $plan.ReviewerAuthorityEstablished|Should -BeFalse
  $plan.JournalAuthenticityEstablished|Should -BeFalse
  $plan.CommitContentsEstablished|Should -BeFalse
  $plan.ObservedParentVerified|Should -BeFalse
 }
 It 'can plan a new write without mistaking journal absence for permission' {
  $options.Remove('JournalJson')
  $plan=Get-TokenForgePublicationRecoveryPlan @options
  $plan.Verdict|Should -BeExactly NeedsVerifiedHostedAuthorization
  $plan.JournalBoundToTransaction|Should -BeFalse
  $plan.AuthorizationEstablished|Should -BeFalse
 }
 It 'rejects a stale unrelated parent before any new write can be planned' {
  $options.ObservedParent='d'*40
  $plan=Get-TokenForgePublicationRecoveryPlan @options
  $plan.Verdict|Should -BeExactly StaleParent
  $plan.NewWritePlanned|Should -BeFalse
  $plan.AuthorizationEstablished|Should -BeFalse
 }
 It 'expires new writes at the exact approval deadline' {
  $options.Now=[DateTimeOffset]$approval.ExpiresAt
  $plan=Get-TokenForgePublicationRecoveryPlan @options
  $plan.Verdict|Should -BeExactly Expired
  $plan.NewWritePlanned|Should -BeFalse
 }
 It 'retains stale-parent diagnosis even when the review has expired' {
  $options.Now=$now.AddDays(2);$options.ObservedParent='d'*40
  (Get-TokenForgePublicationRecoveryPlan @options).Verdict|Should -BeExactly StaleParent
 }
 It 'recovers a lost acknowledgement for the exact journal transaction after expiry' {
  $options.ObservedParent=$options.ProposedCommit;$options.Now=$now.AddDays(2)
  $plan=Get-TokenForgePublicationRecoveryPlan @options
  $plan.Verdict|Should -BeExactly AlreadyApplied
  $plan.RecoveryOnly|Should -BeTrue
  $plan.NewWritePlanned|Should -BeFalse
  $plan.AuthorizationEstablished|Should -BeFalse
  $plan.JournalBoundToTransaction|Should -BeTrue
  $plan.JournalAuthenticityEstablished|Should -BeFalse
 }
 It 'returns the same recovery transaction on repeated acknowledgement-only retries' {
  $options.ObservedParent=$options.ProposedCommit
  $first=Get-TokenForgePublicationRecoveryPlan @options
  $options.Now=$now.AddDays(10)
  $next=Get-TokenForgePublicationRecoveryPlan @options
  $first.Verdict|Should -BeExactly AlreadyApplied
  $next.Verdict|Should -BeExactly AlreadyApplied
  $next.TransactionSha256|Should -BeExactly $first.TransactionSha256
  $next.ExecutionPerformed|Should -BeFalse
 }
 It 'does not accept matching caller commit strings alone as recovery evidence' {
  $options.Remove('JournalJson');$options.ObservedParent=$options.ProposedCommit
  $plan=Get-TokenForgePublicationRecoveryPlan @options
  $plan.Verdict|Should -BeExactly RecoveryEvidenceRequired
  $plan.RecoveryOnly|Should -BeFalse
  $plan.NewWritePlanned|Should -BeFalse
  $plan.AuthorizationEstablished|Should -BeFalse
 }
 It 'refuses changed candidate bytes despite the same artifact content digest' {
  $options.CandidateJson=$options.CandidateJson.Replace('"ProducerAttempt":"1"','"ProducerAttempt":"2"')
  {Get-TokenForgePublicationRecoveryPlan @options}|Should -Throw '*pinned digest*'
 }
 It 'refuses changed approval bytes despite an unchanged candidate reference' {
  $options.ApprovalJson=$options.ApprovalJson.Replace('67890','67891')
  {Get-TokenForgePublicationRecoveryPlan @options}|Should -Throw '*pinned digest*'
 }
 It 'treats whitespace changes as changes to the pinned immutable document' {
  $options.CandidateJson+=' '
  {Get-TokenForgePublicationRecoveryPlan @options}|Should -Throw '*pinned digest*'
 }
 It 'refuses producer identity substitution in an otherwise correctly rehashed approval (<Field>)' -ForEach @(
  @{Field='SourceCommit';Value=('d'*40)},@{Field='ProducerRunId';Value='12346'},@{Field='ProducerAttempt';Value='2'}
 ) {
  $approval[$Field]=$Value
  $options.ApprovalJson=ConvertTo-Json -InputObject $approval -Compress
  $options.ApprovalSha256=Get-TokenForgePublicationPlanHash $options.ApprovalJson
  {Get-TokenForgePublicationRecoveryPlan @options}|Should -Throw '*exact candidate and producer*'
 }
 It 'refuses a review of a different candidate even when its own digest is correct' {
  $approval.CandidateSha256='f'*64
  $options.ApprovalJson=ConvertTo-Json -InputObject $approval -Compress
  $options.ApprovalSha256=Get-TokenForgePublicationPlanHash $options.ApprovalJson
  {Get-TokenForgePublicationRecoveryPlan @options}|Should -Throw '*exact candidate and producer*'
 }
 It 'refuses journal transaction substitution (<Field>) before acknowledging recovery' -ForEach @(
  @{Field='CandidateSha256';Value=('f'*64)},@{Field='ApprovalSha256';Value=('f'*64)},
  @{Field='TransactionSha256';Value=('f'*64)},@{Field='SourceCommit';Value=('d'*40)},
  @{Field='ProducerRunId';Value='999'},@{Field='ProducerAttempt';Value='2'},
  @{Field='ExpectedParent';Value=('d'*40)},@{Field='ProposedCommit';Value=('d'*40)}
 ) {
  $options.ObservedParent=$options.ProposedCommit
  $journal[$Field]=$Value;$options.JournalJson=ConvertTo-Json -InputObject $journal -Compress
  {Get-TokenForgePublicationRecoveryPlan @options}|Should -Throw '*exact transaction*'
 }
 It 'refuses a journal prepared outside the reviewed window (<Case>)' -ForEach @(
  @{Case='before review';Offset=-90},@{Case='at expiry';Offset=180},@{Case='future';Offset=1}
 ) {
  $journal.PreparedAt=$now.AddMinutes($Offset).ToString('o')
  $options.JournalJson=ConvertTo-Json -InputObject $journal -Compress
  $options.ObservedParent=$options.ProposedCommit
  {Get-TokenForgePublicationRecoveryPlan @options}|Should -Throw '*validity window*'
 }
 It 'rejects an approval that claims permission through a self-attested flag' {
  $approval.AuthorizationEstablished=$true
  $options.ApprovalJson=ConvertTo-Json -InputObject $approval -Compress
  $options.ApprovalSha256=Get-TokenForgePublicationPlanHash $options.ApprovalJson
  {Get-TokenForgePublicationRecoveryPlan @options}|Should -Throw '*Unknown*field*'
 }
 It 'rejects a self-attested journal authenticity flag rather than treating it as proof' {
  $journal.Verified=$true;$options.JournalJson=ConvertTo-Json -InputObject $journal -Compress
  {Get-TokenForgePublicationRecoveryPlan @options}|Should -Throw '*Unknown*field*'
 }
 It 'rejects duplicate JSON fields even when the input digest matches those bytes' {
  $options.CandidateJson=$options.CandidateJson.Replace('"SchemaVersion":1','"SchemaVersion":1,"SchemaVersion":1')
  $options.CandidateSha256=Get-TokenForgePublicationPlanHash $options.CandidateJson
  {Get-TokenForgePublicationRecoveryPlan @options}|Should -Throw '*Duplicate*field*'
 }
 It 'rejects mismatched field casing rather than interpreting aliases' {
  $options.CandidateJson=$options.CandidateJson.Replace('SourceCommit','sourceCommit')
  $options.CandidateSha256=Get-TokenForgePublicationPlanHash $options.CandidateJson
  {Get-TokenForgePublicationRecoveryPlan @options}|Should -Throw '*field*'
 }
 It 'rejects oversized input before parsing' {
  {Read-TokenForgePublicationPlanJson (' '*16385)}|Should -Throw '*bounds*'
 }
 It 'rejects a malformed digest or commit (<Field>)' -ForEach @(
  @{Field='CandidateSha256';Value=('A'*64)},@{Field='ApprovalSha256';Value=('0'*64)},
  @{Field='ObservedParent';Value=('a'*39)},@{Field='ExpectedParent';Value=('a'*40)+"`n"},
  @{Field='ProposedCommit';Value=('0'*40)}
 ) {
  $options[$Field]=$Value
  {Get-TokenForgePublicationRecoveryPlan @options}|Should -Throw '*digest or commit*'
 }
 It 'rejects a no-op transaction that cannot distinguish recovery from a new write' {
  $options.ProposedCommit=$options.ExpectedParent
  {Get-TokenForgePublicationRecoveryPlan @options}|Should -Throw '*distinct proposed commit*'
 }
 It 'rejects unbounded or inconsistent validity (<Case>)' -ForEach @(
  @{Case='candidate over 24 hours';Target='Candidate';Field='ExpiresAt';Offset=25},
  @{Case='approval past candidate';Target='Approval';Field='ExpiresAt';Offset=5},
  @{Case='review before candidate';Target='Approval';Field='ReviewedAt';Offset=-3},
  @{Case='approval empty window';Target='Approval';Field='ExpiresAt';Offset=-1}
 ) {
  if($Target -eq 'Candidate'){$candidate[$Field]=$now.AddHours($Offset).ToString('o')}else{$approval[$Field]=$now.AddHours($Offset).ToString('o')}
  Set-PublicationFixtureDocuments $candidate $approval $journal $options
  {Get-TokenForgePublicationRecoveryPlan @options}|Should -Throw '*validity windows*'
 }
 It 'rejects noncanonical timestamps instead of silently reinterpreting them' {
  $candidate.CreatedAt='2026-10-23T10:00:00Z'
  Set-PublicationFixtureDocuments $candidate $approval $journal $options
  {Get-TokenForgePublicationRecoveryPlan @options}|Should -Throw '*canonical UTC*'
 }
 It 'rejects future review evidence' {
  $approval.ReviewedAt=$now.AddMinutes(1).ToString('o')
  Set-PublicationFixtureDocuments $candidate $approval $journal $options
  {Get-TokenForgePublicationRecoveryPlan @options}|Should -Throw '*future*'
 }
 It 'rejects numeric producer identifiers rather than coercing identity values' {
  $candidate.ProducerRunId=12345
  $options.CandidateJson=ConvertTo-Json -InputObject $candidate -Compress
  $options.CandidateSha256=Get-TokenForgePublicationPlanHash $options.CandidateJson
  {Get-TokenForgePublicationRecoveryPlan @options}|Should -Throw '*producer identifier*'
 }
 It 'keeps coherently substituted identities unverified even when every caller digest is recomputed' {
  $candidate.SourceCommit='d'*40;$candidate.ProducerRunId='98765';$candidate.ProducerAttempt='9'
  foreach($field in @('SourceCommit','ProducerRunId','ProducerAttempt')){$approval[$field]=$candidate[$field];$journal[$field]=$candidate[$field]}
  $approval.ReviewerId='98766'
  Set-PublicationFixtureDocuments $candidate $approval $journal $options
  $result=Get-TokenForgePublicationRecoveryPlan @options
  $result.Verdict|Should -BeExactly NeedsVerifiedHostedAuthorization
  $result.AuthorizationEstablished|Should -BeFalse
  $result.ProducerIdentityEstablished|Should -BeFalse
  $result.ReviewerAuthorityEstablished|Should -BeFalse
  $result.JournalAuthenticityEstablished|Should -BeFalse
 }
 It 'rejects negative-zero UTC notation rather than treating unknown offset text as canonical' {
  $candidate.CreatedAt=$candidate.CreatedAt.Replace('+00:00','-00:00')
  Set-PublicationFixtureDocuments $candidate $approval $journal $options
  {Get-TokenForgePublicationRecoveryPlan @options}|Should -Throw '*canonical UTC*'
 }
 It 'has no permission or execution side effects for any verdict' {
  Mock Invoke-WebRequest {throw 'Unexpected network call.'}
  Mock Invoke-RestMethod {throw 'Unexpected network call.'}
  Mock Set-Content {throw 'Unexpected write.'}
  Mock New-Item {throw 'Unexpected write.'}
  Mock git {throw 'Unexpected Git call.'}
  foreach($observed in @($options.ExpectedParent,$options.ProposedCommit,('d'*40))){
   $options.ObservedParent=$observed
   $result=Get-TokenForgePublicationRecoveryPlan @options
   $result.AuthorizationEstablished|Should -BeFalse
   $result.ExecutionPerformed|Should -BeFalse
  }
  Should -Invoke Invoke-WebRequest -Times 0 -Exactly
  Should -Invoke Invoke-RestMethod -Times 0 -Exactly
  Should -Invoke Set-Content -Times 0 -Exactly
  Should -Invoke New-Item -Times 0 -Exactly
  Should -Invoke git -Times 0 -Exactly
 }
}
