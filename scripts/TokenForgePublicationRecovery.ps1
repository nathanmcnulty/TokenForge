#Requires -Version 7.4
# Pure offline publication/recovery planning. This file performs no Git operation,
# network request, authentication, filesystem mutation, or authorization decision.
# Caller-provided hashes and journals establish consistency, never identity or authority.
. (Join-Path $PSScriptRoot 'TokenForgePublicPermissions.ps1')

function Read-TokenForgePublicationPlanJson {
 param([Parameter(Mandatory)][string]$Json)
 if($Json.Length -lt 2 -or $Json.Length -gt 16384){throw 'Publication planning document exceeds bounds.'}
 $bytes=[Text.UTF8Encoding]::new($false,$true).GetBytes($Json)
 if($bytes.Length -gt 16384){throw 'Publication planning document exceeds bounds.'}
 Read-TokenForgePermissionJson -Bytes $bytes
}

function Get-TokenForgePublicationPlanHash {
 param([Parameter(Mandatory)][string]$Text)
 if($Text.Length -gt 16384){throw 'Publication planning document exceeds bounds.'}
 [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData([Text.UTF8Encoding]::new($false,$true).GetBytes($Text))).ToLowerInvariant()
}

function Assert-TokenForgePublicationPlanHash {
 param($Value,[ValidateSet(40,64)][int]$Length=64)
 if($Value -isnot [string] -or $Value -cnotmatch ('\A[a-f0-9]{'+$Length+'}\z') -or $Value -ceq ('0'*$Length)){throw 'Invalid publication digest or commit.'}
}

function Assert-TokenForgePublicationProducer {
 param($Document)
 Assert-TokenForgePublicationPlanHash $Document.SourceCommit -Length 40
 foreach($name in @('ProducerRunId','ProducerAttempt')){
  if($Document[$name] -isnot [string] -or $Document[$name] -cnotmatch '\A[1-9][0-9]{0,19}\z'){throw 'Invalid publication producer identifier.'}
 }
}

function Read-TokenForgePublicationPlanTime {
 param($Value)
 $parsed=[DateTimeOffset]::MinValue
 if($Value -isnot [string] -or -not [DateTimeOffset]::TryParseExact($Value,'o',[Globalization.CultureInfo]::InvariantCulture,[Globalization.DateTimeStyles]::None,[ref]$parsed) -or $parsed.Offset -ne [TimeSpan]::Zero -or $parsed.Year -lt 2020 -or $parsed.Year -gt 2100 -or $Value -cne $parsed.ToUniversalTime().ToString('o')){throw 'Invalid canonical UTC publication timestamp.'}
 return $parsed
}

function Get-TokenForgePublicationTransactionHash {
 param(
  [Parameter(Mandatory)][string]$CandidateSha256,[Parameter(Mandatory)][string]$ApprovalSha256,
  [Parameter(Mandatory)][string]$SourceCommit,[Parameter(Mandatory)][string]$ProducerRunId,
  [Parameter(Mandatory)][string]$ProducerAttempt,[Parameter(Mandatory)][string]$ExpectedParent,
  [Parameter(Mandatory)][string]$ProposedCommit
 )
 foreach($value in @($CandidateSha256,$ApprovalSha256)){Assert-TokenForgePublicationPlanHash $value}
 foreach($value in @($SourceCommit,$ExpectedParent,$ProposedCommit)){Assert-TokenForgePublicationPlanHash $value -Length 40}
 Assert-TokenForgePublicationProducer @{SourceCommit=$SourceCommit;ProducerRunId=$ProducerRunId;ProducerAttempt=$ProducerAttempt}
 if($ExpectedParent -ceq $ProposedCommit){throw 'Publication planning requires a distinct proposed commit.'}
 $identity=[ordered]@{SchemaVersion=1;Kind='TokenForgePublicationTransaction';CandidateSha256=$CandidateSha256;ApprovalSha256=$ApprovalSha256;SourceCommit=$SourceCommit;ProducerRunId=$ProducerRunId;ProducerAttempt=$ProducerAttempt;ExpectedParent=$ExpectedParent;ProposedCommit=$ProposedCommit}
 Get-TokenForgePublicationPlanHash (ConvertTo-Json -InputObject $identity -Depth 4 -Compress)
}

function Get-TokenForgePublicationRecoveryPlan {
 <#
 .SYNOPSIS
 Plan a compare-and-swap publication or lost-acknowledgement recovery without executing it.
 .DESCRIPTION
 CandidateSha256 and ApprovalSha256 pin exact UTF-8 JSON bytes, including whitespace.
 Validity windows are at most 24 hours; approval must fall within the candidate window.
 AlreadyApplied requires a matching transaction journal plus the supplied observation of
 the proposed commit, and remains available after expiry because it proposes no new write.
 These are unverified caller inputs. The model does not inspect commit contents/ancestry,
 producer provenance, reviewer authority, journal authenticity, or the real remote ref.
 Every verdict requires separate verified hosted authorization before any new write.
 #>
 [CmdletBinding()]
 param(
  [Parameter(Mandatory)][string]$CandidateJson,[Parameter(Mandatory)][string]$CandidateSha256,
  [Parameter(Mandatory)][string]$ApprovalJson,[Parameter(Mandatory)][string]$ApprovalSha256,
  [Parameter(Mandatory)][string]$ExpectedParent,[Parameter(Mandatory)][string]$ProposedCommit,
  [Parameter(Mandatory)][string]$ObservedParent,[string]$JournalJson,
  [DateTimeOffset]$Now=[DateTimeOffset]::UtcNow
 )
 foreach($value in @($CandidateSha256,$ApprovalSha256)){Assert-TokenForgePublicationPlanHash $value}
 foreach($value in @($ExpectedParent,$ProposedCommit,$ObservedParent)){Assert-TokenForgePublicationPlanHash $value -Length 40}
 if((Get-TokenForgePublicationPlanHash $CandidateJson) -cne $CandidateSha256 -or (Get-TokenForgePublicationPlanHash $ApprovalJson) -cne $ApprovalSha256){throw 'Publication document differs from its pinned digest.'}
 $candidate=Read-TokenForgePublicationPlanJson $CandidateJson
 $approval=Read-TokenForgePublicationPlanJson $ApprovalJson
 Assert-TokenForgePermissionFields $candidate @('SchemaVersion','Kind','ContentSha256','SourceCommit','ProducerRunId','ProducerAttempt','CreatedAt','ExpiresAt')
 Assert-TokenForgePermissionFields $approval @('SchemaVersion','Kind','CandidateSha256','SourceCommit','ProducerRunId','ProducerAttempt','Decision','ReviewerId','ReviewedAt','ExpiresAt')
 foreach($document in @($candidate,$approval)){
  if(($document.SchemaVersion -isnot [int] -and $document.SchemaVersion -isnot [long]) -or $document.SchemaVersion -ne 1){throw 'Unsupported publication planning schema.'}
  Assert-TokenForgePublicationProducer $document
 }
 if($candidate.Kind -cne 'TokenForgePublicationCandidate' -or $approval.Kind -cne 'TokenForgePublicationApproval'){throw 'Invalid publication planning document kind.'}
 Assert-TokenForgePublicationPlanHash $candidate.ContentSha256
 Assert-TokenForgePublicationPlanHash $approval.CandidateSha256
 if($approval.CandidateSha256 -cne $CandidateSha256 -or $approval.SourceCommit -cne $candidate.SourceCommit -or $approval.ProducerRunId -cne $candidate.ProducerRunId -or $approval.ProducerAttempt -cne $candidate.ProducerAttempt){throw 'Approval does not bind the exact candidate and producer.'}
 if($approval.Decision -cne 'Approved' -or $approval.ReviewerId -isnot [string] -or $approval.ReviewerId -cnotmatch '\A[1-9][0-9]{0,19}\z'){throw 'Invalid publication review record.'}
 $created=Read-TokenForgePublicationPlanTime $candidate.CreatedAt
 $candidateExpires=Read-TokenForgePublicationPlanTime $candidate.ExpiresAt
 $reviewed=Read-TokenForgePublicationPlanTime $approval.ReviewedAt
 $approvalExpires=Read-TokenForgePublicationPlanTime $approval.ExpiresAt
 if($candidateExpires -le $created -or ($candidateExpires-$created).TotalHours -gt 24 -or $reviewed -lt $created -or $approvalExpires -le $reviewed -or ($approvalExpires-$reviewed).TotalHours -gt 24 -or $approvalExpires -gt $candidateExpires){throw 'Publication validity windows are inconsistent or exceed 24 hours.'}
 if($created -gt $Now -or $reviewed -gt $Now){throw 'Publication candidate or review is dated in the future.'}
 $transactionHash=Get-TokenForgePublicationTransactionHash -CandidateSha256 $CandidateSha256 -ApprovalSha256 $ApprovalSha256 -SourceCommit $candidate.SourceCommit -ProducerRunId $candidate.ProducerRunId -ProducerAttempt $candidate.ProducerAttempt -ExpectedParent $ExpectedParent -ProposedCommit $ProposedCommit
 $journalBound=$false
 if($PSBoundParameters.ContainsKey('JournalJson')){
  $journal=Read-TokenForgePublicationPlanJson $JournalJson
  Assert-TokenForgePermissionFields $journal @('SchemaVersion','Kind','TransactionSha256','CandidateSha256','ApprovalSha256','SourceCommit','ProducerRunId','ProducerAttempt','ExpectedParent','ProposedCommit','PreparedAt')
  if(($journal.SchemaVersion -isnot [int] -and $journal.SchemaVersion -isnot [long]) -or $journal.SchemaVersion -ne 1 -or $journal.Kind -cne 'TokenForgePublicationPreparedTransaction'){throw 'Invalid publication transaction journal.'}
  foreach($value in @($journal.TransactionSha256,$journal.CandidateSha256,$journal.ApprovalSha256)){Assert-TokenForgePublicationPlanHash $value}
  foreach($value in @($journal.ExpectedParent,$journal.ProposedCommit)){Assert-TokenForgePublicationPlanHash $value -Length 40}
  Assert-TokenForgePublicationProducer $journal
  if($journal.TransactionSha256 -cne $transactionHash -or $journal.CandidateSha256 -cne $CandidateSha256 -or $journal.ApprovalSha256 -cne $ApprovalSha256 -or $journal.SourceCommit -cne $candidate.SourceCommit -or $journal.ProducerRunId -cne $candidate.ProducerRunId -or $journal.ProducerAttempt -cne $candidate.ProducerAttempt -or $journal.ExpectedParent -cne $ExpectedParent -or $journal.ProposedCommit -cne $ProposedCommit){throw 'Publication journal does not bind the exact transaction.'}
  $prepared=Read-TokenForgePublicationPlanTime $journal.PreparedAt
  if($prepared -lt $reviewed -or $prepared -ge $approvalExpires -or $prepared -ge $candidateExpires -or $prepared -gt $Now){throw 'Publication transaction was not prepared within the reviewed validity window.'}
  $journalBound=$true
 }
 $verdict=if($ObservedParent -ceq $ProposedCommit){if($journalBound){'AlreadyApplied'}else{'RecoveryEvidenceRequired'}}elseif($ObservedParent -cne $ExpectedParent){'StaleParent'}elseif($Now -ge $candidateExpires -or $Now -ge $approvalExpires){'Expired'}else{'NeedsVerifiedHostedAuthorization'}
 [pscustomobject]@{
  SchemaVersion=1;Kind='TokenForgeOfflinePublicationRecoveryPlan';Verdict=$verdict
  AuthorizationEstablished=$false;ProducerIdentityEstablished=$false;ReviewerAuthorityEstablished=$false
  JournalAuthenticityEstablished=$false;CommitContentsEstablished=$false;ObservedParentVerified=$false
  JournalBoundToTransaction=$journalBound;TransactionSha256=$transactionHash
  CandidateSha256=$CandidateSha256;ApprovalSha256=$ApprovalSha256
  SourceCommit=$candidate.SourceCommit;ProducerRunId=$candidate.ProducerRunId;ProducerAttempt=$candidate.ProducerAttempt
  ExpectedParent=$ExpectedParent;ProposedCommit=$ProposedCommit;ObservedParent=$ObservedParent
  NewWritePlanned=($verdict -ceq 'NeedsVerifiedHostedAuthorization');ExecutionPerformed=$false
  RecoveryOnly=($verdict -ceq 'AlreadyApplied');Evidence='CallerSuppliedOfflinePlanningInputsRequireIndependentHostedVerification'
 }
}
