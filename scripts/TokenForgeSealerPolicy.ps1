#Requires -Version 7.4
. (Join-Path $PSScriptRoot TokenForgePublicationAdapter.ps1)

function Read-TfSealerGitFile([string]$RepositoryPath,[string]$Commit,[string]$Path) {
 Assert-TokenForgePublicationPlanHash $Commit -Length 40
 if($Path -cnotmatch '\A[A-Za-z0-9_./-]+\z' -or $Path -match '(^|/)\.\.?(/|$)'){throw 'Source path.'}
 $start=[Diagnostics.ProcessStartInfo]::new('/usr/bin/git');$start.UseShellExecute=$false
 $start.RedirectStandardInput=$true;$start.RedirectStandardOutput=$true;$start.RedirectStandardError=$true
 $start.Environment.Clear();$start.Environment['PATH']='/usr/bin:/bin';$start.Environment['HOME']='/nonexistent'
 $start.Environment['GIT_CONFIG_NOSYSTEM']='1';$start.Environment['GIT_CONFIG_GLOBAL']='/dev/null';$start.Environment['GIT_NO_REPLACE_OBJECTS']='1';$start.Environment['GIT_OPTIONAL_LOCKS']='0'
 $start.Environment['GIT_NO_LAZY_FETCH']='1';$start.Environment['GIT_TERMINAL_PROMPT']='0';$start.Environment['GIT_ALLOW_PROTOCOL']=''
 $start.Environment['GIT_CONFIG_COUNT']='2';$start.Environment['GIT_CONFIG_KEY_0']='credential.helper';$start.Environment['GIT_CONFIG_VALUE_0']=''
 $start.Environment['GIT_CONFIG_KEY_1']='protocol.allow';$start.Environment['GIT_CONFIG_VALUE_1']='never'
 foreach($arg in @('--no-pager','-C',[IO.Path]::GetFullPath($RepositoryPath),'cat-file','blob',($Commit+':'+$Path))){$start.ArgumentList.Add($arg)}
 $process=[Diagnostics.Process]::Start($start);$memory=[IO.MemoryStream]::new();$cancel=[Threading.CancellationTokenSource]::new();$cancel.CancelAfter(10000)
 try{
  $process.StandardInput.Close();$errors=$process.StandardError.ReadToEndAsync();$buffer=[byte[]]::new(8192)
  while(($n=$process.StandardOutput.BaseStream.ReadAsync($buffer,0,$buffer.Length,$cancel.Token).GetAwaiter().GetResult()) -gt 0){if($memory.Length+$n -gt 128KB){throw 'Source size bound.'};$memory.Write($buffer,0,$n)}
  if(-not $process.WaitForExit(1000) -or $process.ExitCode -ne 0 -or $errors.GetAwaiter().GetResult().Length -gt 64KB){throw 'Pinned source unavailable.'}
  return ,$memory.ToArray()
 }finally{if(-not $process.HasExited){$process.Kill($true)};$process.Dispose();$memory.Dispose();$cancel.Dispose()}
}

function Test-TfSealerCaller([string]$Yaml,[string]$Commit) {
 $start=[Diagnostics.ProcessStartInfo]::new('/usr/bin/python3');$start.UseShellExecute=$false
 $start.RedirectStandardInput=$true;$start.RedirectStandardOutput=$true;$start.RedirectStandardError=$true
 $start.Environment.Clear();$start.Environment['PATH']='/usr/bin:/bin';$start.Environment['HOME']='/nonexistent'
 $start.ArgumentList.Add('-I');$start.ArgumentList.Add((Join-Path $PSScriptRoot Test-TokenForgeSealerCaller.py))
 $process=[Diagnostics.Process]::Start($start)
 try{
  $out=$process.StandardOutput.ReadToEndAsync();$err=$process.StandardError.ReadToEndAsync()
  $process.StandardInput.Write((@{yaml=$Yaml;commit=$Commit}|ConvertTo-Json -Compress));$process.StandardInput.Close()
  if(-not $process.WaitForExit(10000)){throw 'Caller parser timeout.'}
  $result=$out.GetAwaiter().GetResult().Trim()
  if($process.ExitCode -ne 0 -or $err.GetAwaiter().GetResult().Length -ne 0 -or $result -cnotin @('true','false')){throw 'Caller parser unavailable.'}
  return $result -ceq 'true'
 }finally{if(-not $process.HasExited){$process.Kill($true)};$process.Dispose()}
}

function Get-TokenForgeSealerPolicyPlan {
 <# .SYNOPSIS
 Derive a review-only binding plan. Operational output is currently blocked.
 .DESCRIPTION
 No network, authentication or publication. Exact local Git objects are the reviewed
 source input, not proof of current main, permissions or hosted execution. Operational
 emission remains blocked pending canonical-original producer interoperability and
 independent review; source,
 caller and independent identity binding checks remain necessary.
 #>
 [CmdletBinding()]
 param(
  [Parameter(Mandatory)][string]$RepositoryPath,
  [Parameter(Mandatory)][string]$SealerCommit,
  [Parameter(Mandatory)][string]$ProducerCommit,
  [Parameter(Mandatory)][string]$JournalRoot,
  [string]$BindingsPath,
  [switch]$Operational
 )
 $ErrorActionPreference='Stop'
 try{
  Assert-TokenForgePublicationPlanHash $SealerCommit -Length 40
  Assert-TokenForgePublicationPlanHash $ProducerCommit -Length 40
  if(-not [IO.Path]::IsPathFullyQualified($JournalRoot) -or $JournalRoot -cne [IO.Path]::GetFullPath($JournalRoot)){throw 'Explicit normalized custody root required.'}
  $workflowBytes=Read-TfSealerGitFile $RepositoryPath $SealerCommit '.github/workflows/tokenforge-sealer.yml'
  $workflow=[Text.UTF8Encoding]::new($false,$true).GetString($workflowBytes)
  $match=[regex]::Match($workflow,'(?m)^  TF_SEALER_CODE_COMMIT: ([a-f0-9]{40})$')
  if(-not $match.Success){throw 'Fixed implementation commit required.'}
  $codeCommit=$match.Groups[1].Value
  $code=Read-TfSealerGitFile $RepositoryPath $codeCommit 'scripts/TokenForgeSealer.ps1'
  $templateBytes=Read-TfSealerGitFile $RepositoryPath $codeCommit 'publication/tokenforge-sealer.template.yml'
  $template=[Text.UTF8Encoding]::new($false,$true).GetString($templateBytes)
  $fixed=$template.Replace('@TOKENFORGE_CODE_COMMIT@',$codeCommit)
  $quarantineText=$fixed.Replace('@TOKENFORGE_SEAL_GUARD@','${{ false }}')
  $activeText=$fixed.Replace('@TOKENFORGE_SEAL_GUARD@',"`${{ github.event_name == 'workflow_dispatch' && github.ref == 'refs/heads/main' && github.repository == 'nathanmcnulty/TokenForge' }}")
  if($workflow -cne $quarantineText -and $workflow -cne $activeText){throw 'Workflow differs from reviewed immutable template.'}
  $producerBytes=Read-TfSealerGitFile $RepositoryPath $ProducerCommit '.github/workflows/discovery.yml'
  $producer=[Text.UTF8Encoding]::new($false,$true).GetString($producerBytes)
  $attestationPin=Read-TfSealerGitFile $RepositoryPath $codeCommit 'tests/fixtures/attestation/manifest.json'
  $pin=Read-TfPublicationJson $attestationPin
  $rootBytes=Read-TfSealerGitFile $RepositoryPath $codeCommit 'tests/fixtures/attestation/provisioned-root.jsonl'
  $rootHash=[Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($rootBytes)).ToLowerInvariant()
  if($rootHash -cne $pin.files['provisioned-root.jsonl'].sha256){throw 'Pinned trust root mismatch.'}
  $profileImplemented=$false;$helperHash=$null;$declarationHash=$null
  try{
   $declarationBytes=Read-TfSealerGitFile $RepositoryPath $codeCommit 'publication/zip-profile.json'
   $helperBytes=Read-TfSealerGitFile $RepositoryPath $codeCommit 'scripts/TokenForgeSealerZip.ps1'
   $declaration=Read-TfPublicationJson $declarationBytes
   Assert-TokenForgePermissionFields $declaration @('SchemaVersion','Profile','SealerSha256','ZipHelperSha256')
   $helperHash=[Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($helperBytes)).ToLowerInvariant()
   $declarationHash=[Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($declarationBytes)).ToLowerInvariant()
   $codeHash=[Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($code)).ToLowerInvariant()
   $profileImplemented=($declaration.SchemaVersion -is [long] -and $declaration.SchemaVersion -eq 1 -and $declaration.Profile -is [string] -and $declaration.SealerSha256 -is [string] -and $declaration.ZipHelperSha256 -is [string] -and $declaration.Profile -ceq 'CanonicalStoredOriginalZipV1' -and $declaration.SealerSha256 -ceq $codeHash -and $declaration.ZipHelperSha256 -ceq $helperHash)
  }catch{
   # Old/missing/mismatched declarations establish no implementation claim.
   $profileImplemented=$false
  }
  $quarantined=$workflow -ceq $quarantineText
  $connected=Test-TfSealerCaller $producer $SealerCommit
  $bindings=$null;$missing=[Collections.Generic.List[string]]::new()
  if($BindingsPath){
   $bindingFile=[TokenForge.Core.V0220.PrivateFiles]::Resolve([IO.Path]::GetFullPath($BindingsPath),$false)
   $stream=[IO.File]::Open($bindingFile,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::None)
   try{if($stream.Length -lt 1 -or $stream.Length -gt 16KB){throw 'Bindings bound.'};$bytes=[byte[]]::new($stream.Length);$stream.ReadExactly($bytes,0,$bytes.Length);if($stream.ReadByte() -ne -1){throw 'Bindings changed.'}}finally{$stream.Dispose()}
   $bindings=Read-TfPublicationJson $bytes
   Assert-TokenForgePermissionFields $bindings @('RepositoryId','WorkflowId','ProducerIds','ReviewerIds','MaintainerIds','ReaderIds')
  }else{foreach($name in @('RepositoryId','WorkflowId','ProducerIds','ReviewerIds','MaintainerIds','ReaderIds')){$missing.Add($name)}}
  $policy=$null
  if($bindings){
   $policy=[ordered]@{SchemaVersion=1;Repository='nathanmcnulty/TokenForge';RepositoryId=$bindings.RepositoryId;MainBranch='main';DataBranch='discovery-data';WorkflowId=$bindings.WorkflowId;WorkflowPath='.github/workflows/discovery.yml';WorkflowSha256=([Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($producerBytes)).ToLowerInvariant());SealerPath='.github/workflows/tokenforge-sealer.yml';SealerCommit=$SealerCommit;SealerSha256=([Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($workflowBytes)).ToLowerInvariant());VerifierSha256=$pin.executable.sha256;TrustRootSha256=$rootHash;ProducerIds=$bindings.ProducerIds;ReviewerIds=$bindings.ReviewerIds;MaintainerIds=$bindings.MaintainerIds;ReaderIds=$bindings.ReaderIds;JournalRoot=$JournalRoot}
   Assert-TfPublicationPolicy $policy
   $actors=[Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
   foreach($role in @('ProducerIds','ReviewerIds','MaintainerIds','ReaderIds')){foreach($id in $policy[$role]){if(-not $actors.Add($id)){throw 'Independent disjoint role bindings required.'}}}
  }
  # Offline canonical-container coverage does not prove hosted producer
  # interoperability or authorize activation. Keep runtime output blocked.
  if($Operational){
   throw 'Operational policy emission remains blocked pending independent review and hosted producer interoperability.'
  }
  [pscustomobject]@{SchemaVersion=1;Kind='TokenForgeSealerPolicyReviewPlan';Operational=$false;AuthorizationEstablished=$false;CurrentMainVerified=$false;RolePermissionsVerified=$false;HostedSealingProven=$false;CompleteOriginalZipPrivacyValidated=$false;RequiredArchiveProfile='CanonicalStoredOriginalZipV1';OfflineArchiveProfileImplemented=$profileImplemented;HostedProducerInteroperabilityProven=$false;BlockingReasons=@('IndependentReviewAndHostedProducerInteroperabilityRequired';if(-not $profileImplemented){'PinnedCanonicalProfileNotEstablished'});SealerCommit=$SealerCommit;ProducerCommit=$ProducerCommit;ImplementationCommit=$codeCommit;ImplementationSha256=([Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($code)).ToLowerInvariant());PinnedInputs=@{ZipHelperSha256=$helperHash;ZipProfileDeclarationSha256=$declarationHash;SealerWorkflowSha256=([Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($workflowBytes)).ToLowerInvariant());ProducerWorkflowSha256=([Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($producerBytes)).ToLowerInvariant());VerifierSha256=$pin.executable.sha256;TrustRootSha256=$rootHash};Quarantined=$quarantined;CallerPinsSealer=$connected;MissingBindings=@($missing.ToArray());ProposedPolicy=$null;BindingPreview=$(if($policy){@{Kind='TokenForgeSealerBindingPreview';Operational=$false;Bindings=$bindings}}else{$null});RequiredGates=@('CanonicalOriginalZipProfileReview','HostedCanonicalOriginalZipProducerInteroperability','SeparateActivationApproval','ImmutableSameRepositoryCallerPin','TrustedOperatorIdentityBindings','HostedOriginalZipAndCertificateProof','SeparatePublicationPermissionAndRecoveryProof')}
 }catch{throw 'Sealer policy planning failed; no operational policy emitted.'}
}
