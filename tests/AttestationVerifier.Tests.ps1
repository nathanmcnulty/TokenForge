BeforeAll {
 . "$PSScriptRoot/../scripts/TokenForgePublicationAdapter.ps1"
 $fixtureRoot=Join-Path $PSScriptRoot fixtures/attestation
 $lock=Get-Content (Join-Path $fixtureRoot manifest.json) -Raw|ConvertFrom-Json -AsHashtable
}

Describe 'Pinned public attestation fixture integrity' {
 It 'retains every exact public artifact, bundle, root and license byte' {
  foreach($name in $lock.files.Keys){
   $path=Join-Path $fixtureRoot $name
   (Get-Item $path).Length|Should -Be $lock.files[$name].bytes
   (Get-FileHash $path -Algorithm SHA256).Hash.ToLowerInvariant()|Should -BeExactly $lock.files[$name].sha256
  }
 }
}

Describe 'Real pinned offline attestation verifier' -Tag ExternalVerifier -Skip:([string]::IsNullOrWhiteSpace($env:TOKENFORGE_TEST_ATTESTATION_VERIFIER) -or -not $IsLinux) {
 BeforeAll {
  $verifier=$env:TOKENFORGE_TEST_ATTESTATION_VERIFIER
  $release=$env:TOKENFORGE_TEST_ATTESTATION_ARCHIVE
  if([string]::IsNullOrWhiteSpace($release)){throw 'Pinned release archive is required; no download fallback.'}
  (Get-FileHash $verifier -Algorithm SHA256).Hash.ToLowerInvariant()|Should -BeExactly $lock.executable.sha256
  (Get-FileHash $release -Algorithm SHA256).Hash.ToLowerInvariant()|Should -BeExactly $lock.archive.sha256
  foreach($name in $lock.files.Keys){(Get-FileHash (Join-Path $fixtureRoot $name) -Algorithm SHA256).Hash.ToLowerInvariant()|Should -BeExactly $lock.files[$name].sha256}
  $toolRoot=Join-Path $TestDrive pinned-tool;$null=[IO.Directory]::CreateDirectory($toolRoot,[IO.UnixFileMode]448)
  $toolCopy=Join-Path $toolRoot gh
  Copy-TfPublicationInput $verifier $toolCopy 128MB
  (Get-FileHash $toolCopy -Algorithm SHA256).Hash.ToLowerInvariant()|Should -BeExactly $lock.executable.sha256
  [IO.File]::SetUnixFileMode($toolCopy,[IO.UnixFileMode]320);$verifier=$toolCopy

  function Invoke-OfflineAttestation([string]$Artifact,[string]$Bundle,$Case,[string]$Root,[string]$OidcIssuer='https://token.actions.githubusercontent.com') {
   $homePath=Join-Path $TestDrive ([guid]::NewGuid().ToString('N'));$null=[IO.Directory]::CreateDirectory($homePath,[IO.UnixFileMode]448)
   $start=[Diagnostics.ProcessStartInfo]::new('/usr/bin/unshare');$start.UseShellExecute=$false
   $start.RedirectStandardInput=$true;$start.RedirectStandardOutput=$true;$start.RedirectStandardError=$true
   $start.Environment.Clear();$start.Environment['HOME']=$homePath;$start.Environment['GH_CONFIG_DIR']=$homePath;$start.Environment['PATH']='/usr/bin:/bin';$start.Environment['GH_PROMPT_DISABLED']='1'
   foreach($a in @('-Urn',$verifier,'attestation','verify',$Artifact,'--bundle',$Bundle,'--custom-trusted-root',$Root,'--repo',$Case.repository,'--signer-workflow',$Case.signerWorkflow,'--signer-digest',$Case.signerCommit,'--source-digest',$Case.source,'--source-ref',$Case.ref,'--deny-self-hosted-runners','--cert-oidc-issuer',$OidcIssuer,'--limit','1','--format','json')){$start.ArgumentList.Add($a)}
   $process=[Diagnostics.Process]::Start($start)
   try{
    $process.StandardInput.Close();$out=$process.StandardOutput.ReadToEndAsync();$err=$process.StandardError.ReadToEndAsync()
    if(-not $process.WaitForExit(10000)){$process.Kill($true);throw 'Offline test verifier exceeded deadline.'}
    $output=$out.GetAwaiter().GetResult();$errorText=$err.GetAwaiter().GetResult()
    if($output.Length -gt 4MB -or $errorText.Length -gt 64KB){throw 'Offline test output exceeded bound.'}
    return @{ExitCode=$process.ExitCode;Json=$output}
   }finally{if(-not $process.HasExited){$process.Kill($true)};$process.Dispose()}
  }
 }
 BeforeEach {
  $scratch=Join-Path $TestDrive ([guid]::NewGuid().ToString('N'));$null=[IO.Directory]::CreateDirectory($scratch,[IO.UnixFileMode]448)
  foreach($name in @('same-repo-artifact.whl','same-repo-bundle.json','provisioned-root.jsonl')){
   [IO.File]::Copy((Join-Path $fixtureRoot $name),(Join-Path $scratch $name));[IO.File]::SetUnixFileMode((Join-Path $scratch $name),[IO.UnixFileMode]384)
  }
  $case=$lock.cases.sameRepo
  $policy=@{Repository=$case.repository;RepositoryId=$case.repositoryId;MainBranch=$case.mainBranch;SealerPath=$case.sealerPath;SealerCommit=$case.sealerCommit;VerifierSha256=$lock.executable.sha256}
  $context=@{Synthetic=$false;Policy=$policy;VerifierPath=$verifier;BundlePath=(Join-Path $scratch same-repo-bundle.json);TrustRootPath=(Join-Path $scratch provisioned-root.jsonl);Requests=0;Bytes=0L;Watch=[Diagnostics.Stopwatch]::StartNew()}
  $artifact=Join-Path $scratch same-repo-artifact.whl
 }
 It 'verifies genuine GitHub-signed bytes through the unchanged adapter process boundary and exact flags' {
  $result=Invoke-TfPublicationAttestation $context $artifact $case.source $scratch
  $result.Count|Should -Be 1
  $v=$result[0].verificationResult;$c=$v.signature.certificate
  $c.sourceRepositoryIdentifier|Should -BeExactly $case.repositoryId
  $c.sourceRepositoryDigest|Should -BeExactly $case.source
  $c.runInvocationURI|Should -BeExactly ('https://github.com/'+$case.repository+'/actions/runs/'+$case.run+'/attempts/'+$case.attempt)
  $v.statement.subject[0].digest.sha256|Should -BeExactly $case.artifactSha256
  $v.verifiedTimestamps.Count|Should -BeGreaterThan 0
 }
 It 'keeps mutable certified workflow refs ineligible for the stricter production sealer policy' {
  $result=Invoke-TfPublicationAttestation $context $artifact $case.source $scratch
  {Assert-TfPublicationAttestation $result $policy $case.source $case.run $case.attempt $case.artifactSha256}|Should -Throw '*Sealing identity mismatch*'
 }
 It 'cryptographically verifies the genuine public-good reusable-workflow bundle with explicit signer identity' {
  $c=$lock.cases.reusable
  $r=Invoke-OfflineAttestation (Join-Path $fixtureRoot reusable-artifact) (Join-Path $fixtureRoot reusable-bundle.json) $c (Join-Path $fixtureRoot provisioned-root.jsonl)
  $r.ExitCode|Should -Be 0
  $result=ConvertFrom-Json $r.Json -AsHashtable -NoEnumerate
  $result.Count|Should -Be 1
  $certificate=$result[0].verificationResult.signature.certificate
  $certificate.sourceRepositoryIdentifier|Should -BeExactly $c.repositoryId
  $certificate.buildSignerURI|Should -BeExactly ('https://github.com/'+$c.signerWorkflow+'@'+$c.signerCommit)
  $certificate.runInvocationURI|Should -BeExactly ('https://github.com/'+$c.repository+'/actions/runs/'+$c.run+'/attempts/'+$c.attempt)
  $policy=@{Repository=$c.repository;RepositoryId=$c.repositoryId;MainBranch='main';SealerPath='.github/workflows/attest.yml';SealerCommit=$c.signerCommit}
  {Assert-TfPublicationAttestation $result $policy $c.source $c.run $c.attempt $c.artifactSha256}|Should -Throw '*Sealing identity mismatch*'
 }
 It 'verifies the installed release archive against its public signed provenance and exact release source' {
  $c=$lock.cases.cliRelease
  $r=Invoke-OfflineAttestation $release (Join-Path $fixtureRoot cli-release-bundle.json) $c (Join-Path $fixtureRoot provisioned-root.jsonl)
  $r.ExitCode|Should -Be 0
  $result=ConvertFrom-Json $r.Json -AsHashtable -NoEnumerate
  $certificate=$result[0].verificationResult.signature.certificate
  $certificate.sourceRepositoryIdentifier|Should -BeExactly $c.repositoryId
  $certificate.sourceRepositoryDigest|Should -BeExactly $lock.sourceCommit
  $certificate.buildSignerDigest|Should -BeExactly $lock.sourceCommit
  $result[0].verificationResult.statement.subject.Count|Should -Be $c.subjectCount
  @($result[0].verificationResult.statement.subject|Where-Object {$_.digest.sha256 -ceq $lock.archive.sha256}).Count|Should -Be 1
 }
 It 'rejects corrupted signed material or an unrelated trust domain (<CaseName>)' -ForEach @(@{CaseName='Artifact'},@{CaseName='Signature'},@{CaseName='Certificate'},@{CaseName='Payload'},@{CaseName='TrustRoot'},@{CaseName='MissingCertificate'}) {
  switch($CaseName){
   Artifact {[IO.File]::WriteAllText($artifact,'tampered public fixture')}
   TrustRoot {$context.TrustRootPath=Join-Path $fixtureRoot public-good-root.json}
   default {
    $bundle=Read-TfCandidateJson $context.BundlePath
    switch($CaseName){
     Signature {$key=$bundle.dsseEnvelope.signatures[0];$bytes=[Convert]::FromBase64String($key.sig);$bytes[0]=$bytes[0] -bxor 1;$key.sig=[Convert]::ToBase64String($bytes)}
     Certificate {$key=$bundle.verificationMaterial.certificate;$bytes=[Convert]::FromBase64String($key.rawBytes);$bytes[-1]=$bytes[-1] -bxor 1;$key.rawBytes=[Convert]::ToBase64String($bytes)}
     Payload {$bundle.dsseEnvelope.payload=[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes('{"_type":"forged"}'))}
     MissingCertificate {$null=$bundle.verificationMaterial.Remove('certificate')}
    }
    [IO.File]::WriteAllText($context.BundlePath,($bundle|ConvertTo-Json -Depth 64 -Compress))
   }
  }
  {Invoke-TfPublicationAttestation $context $artifact $case.source $scratch}|Should -Throw '*Attestation verifier refused*'
 }
 It 'rejects a different expected OIDC issuer rather than accepting a valid signature alone' {
  $c=$lock.cases.reusable
  $r=Invoke-OfflineAttestation (Join-Path $fixtureRoot reusable-artifact) (Join-Path $fixtureRoot reusable-bundle.json) $c (Join-Path $fixtureRoot provisioned-root.jsonl) 'https://example.invalid'
  $r.ExitCode|Should -Not -Be 0
 }
 It 'rejects a mismatched certified workflow/source constraint (<Field>)' -ForEach @(@{Field='Repository'},@{Field='MainBranch'},@{Field='SealerPath'},@{Field='SealerCommit'},@{Field='Source'}) {
  $source=$case.source
  switch($Field){Repository {$policy.Repository='example/wrong'} MainBranch {$policy.MainBranch='wrong'} SealerPath {$policy.SealerPath='.github/workflows/wrong.yml'} SealerCommit {$policy.SealerCommit='9'*40} Source {$source='9'*40}}
  {Invoke-TfPublicationAttestation $context $artifact $source $scratch}|Should -Throw '*Attestation verifier refused*'
 }
}
