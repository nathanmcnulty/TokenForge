BeforeAll {
 . "$PSScriptRoot/../scripts/TokenForgeSealer.ps1"
 . "$PSScriptRoot/fixtures/publication/AdapterFixture.ps1"
 function New-SealerFixture([string]$Parent) {
  $f=New-PublicationAdapterFixture $Parent
  foreach($file in Get-ChildItem $f.Candidate -File){[IO.File]::SetUnixFileMode($file.FullName,[IO.UnixFileMode]384)}
  $canonical=Join-Path $f.Root reference.zip
  & /usr/bin/python3 -I "$PSScriptRoot/fixtures/publication/MutateSealerZip.py" $f.Candidate $canonical canonical-from-directory
  if($LASTEXITCODE){throw 'Independent canonical fixture encoder failed.'}
  [IO.File]::Copy($canonical,$f.Zip,$true)
  $f.Server[($f.Api+'/actions/artifacts/30')].digest='sha256:'+(Get-TfCandidateFileHash $f.Zip)
  $f.Server[($f.Api+'/actions/artifacts/30')].size_in_bytes=(Get-Item $f.Zip).Length
  $f.Invocation=@{Repository='example/TokenForge';RepositoryId='100';SourceCommit=$f.Source;RunId='10';RunAttempt='1';Ref='refs/heads/main';EventName='workflow_dispatch';WorkflowRef='example/TokenForge/.github/workflows/discovery.yml@refs/heads/main'}
  $f.Server[($f.Api+'/actions/runs/10')].path='.github/workflows/discovery.yml'
  $f.Server[($f.Api+'/actions/runs/10')].status='in_progress';$f.Server[($f.Api+'/actions/runs/10')].conclusion=$null
  $f.Server[($f.Api+'/actions/artifacts/30')].expires_at='2099-01-01T00:00:00Z'
  $f.Redirect='https://fixture.blob.core.windows.net/candidate';$f.DownloadStatus=200;$f.FetchLog=[Collections.Generic.List[string]]::new();$f.OnFetch=$null
  $f.SealerOptions=@{Invocation=$f.Invocation;ArtifactId='30';OutputDirectory=(Join-Path $f.Root sealed);Synthetic=$true;ReadFixture=$f.Options.ReadFixture;FetchFixture=({param($Phase,$Uri)
   $f.FetchLog.Add($Phase);if($f.OnFetch){& $f.OnFetch $f $Phase}
   if($Phase -ceq 'Redirect'){@{Status=302;Location=$f.Redirect}}else{@{Status=$f.DownloadStatus;Bytes=[IO.File]::ReadAllBytes($f.Zip)}}
  }.GetNewClosure())}
  return $f
 }
 function Update-SealerFixtureArchive($Fixture) {
  Remove-Item $Fixture.Zip
  [IO.Compression.ZipFile]::CreateFromDirectory($Fixture.Candidate,$Fixture.Zip);[IO.File]::SetUnixFileMode($Fixture.Zip,[IO.UnixFileMode]384)
  $Fixture.Server[($Fixture.Api+'/actions/artifacts/30')].digest='sha256:'+(Get-TfCandidateFileHash $Fixture.Zip)
  $Fixture.Server[($Fixture.Api+'/actions/artifacts/30')].size_in_bytes=(Get-Item $Fixture.Zip).Length
 }
}

Describe 'Trusted original-ZIP sealing subject' {
 BeforeEach {$f=New-SealerFixture $TestDrive;$options=$f.SealerOptions}
 It 'hashes and validates the original ZIP bytes without signing or executing the candidate' {
  $hash=Get-TfCandidateFileHash $f.Zip;$r=Get-TokenForgeSealingSubject @options
  $r.SubjectSha256|Should -BeExactly $hash;$r.CandidateHash|Should -BeExactly $f.Approval.CandidateHash
  $r.MetadataRequests|Should -Be 7;$r.DownloadRequests|Should -Be 2
  $r.SubjectCount|Should -Be 1;$r.Synthetic|Should -BeTrue;$r.SigningPerformed|Should -BeFalse;$r.SemanticApproval|Should -BeFalse
  (Get-TfCandidateFileHash $r.SubjectPath)|Should -BeExactly $hash
  ([int][IO.File]::GetUnixFileMode($r.SubjectPath) -band 511)|Should -Be 256
  @(Get-ChildItem $options.OutputDirectory -Force).Count|Should -Be 2
 }
 It 'does not turn Synthetic false into live execution' {
  $options.Synthetic=$false
  (Get-TokenForgeSealingSubject @options).Synthetic|Should -BeTrue
 }
 It 'refuses live credentials combined with fixture callbacks before any request' {
  $options.AccessToken=ConvertTo-SecureString synthetic -AsPlainText -Force
  {Get-TokenForgeSealingSubject @options}|Should -Throw
  $f.Log.Count|Should -Be 0
 }
 It 'accepts a completed successful current run but not arbitrary completion' {
  $f.Server[($f.Api+'/actions/runs/10')].status='completed';$f.Server[($f.Api+'/actions/runs/10')].conclusion='success'
  (Get-TokenForgeSealingSubject @options).StructuralValidation|Should -BeTrue
 }
 It 'refuses caller-controlled subject/digest/path and non-main/event contexts (<Case>)' -ForEach @(@{Case='Digest'},@{Case='Path'},@{Case='Ref'},@{Case='Event'},@{Case='Caller'}) {
  switch($Case){Digest {$f.Invocation.SubjectSha256='9'*64} Path {$f.Invocation.SubjectPath='/tmp/producer.sh'} Ref {$f.Invocation.Ref='refs/heads/topic'} Event {$f.Invocation.EventName='pull_request'} Caller {$f.Invocation.WorkflowRef='example/TokenForge/.github/workflows/evil.yml@refs/heads/main'}}
  {Get-TokenForgeSealingSubject @options}|Should -Throw '*Invocation*'
  $f.Log.Count|Should -Be 0
 }
 It 'fails closed on wrong authenticated origin (<Case>)' -ForEach @(@{Case='Repository'},@{Case='Run'},@{Case='Attempt'},@{Case='Source'},@{Case='Fork'},@{Case='Workflow'},@{Case='Failed'},@{Case='ArtifactRun'},@{Case='ArtifactSource'},@{Case='ArtifactDigest'},@{Case='Main'},@{Case='Unprotected'},@{Case='Expired'},@{Case='Oversize'}) {
  switch($Case){
   Repository {$f.Server[$f.Api].id=999}
   Run {$f.Server[($f.Api+'/actions/runs/10')].id=11}
   Attempt {$f.Server[($f.Api+'/actions/runs/10')].run_attempt=2}
   Source {$f.Server[($f.Api+'/actions/runs/10')].head_sha='9'*40}
   Fork {$f.Server[($f.Api+'/actions/runs/10')].head_repository.id=999}
   Workflow {$f.Server[($f.Api+'/actions/runs/10')].path='.github/workflows/evil.yml'}
   Failed {$f.Server[($f.Api+'/actions/runs/10')].status='completed';$f.Server[($f.Api+'/actions/runs/10')].conclusion='failure'}
   ArtifactRun {$f.Server[($f.Api+'/actions/artifacts/30')].workflow_run.id=11}
   ArtifactSource {$f.Server[($f.Api+'/actions/artifacts/30')].workflow_run.head_sha='9'*40}
   ArtifactDigest {$f.Server[($f.Api+'/actions/artifacts/30')].digest='sha256:'+('9'*64)}
   Main {$f.Server[($f.Api+'/branches/main')].commit.sha='9'*40}
   Unprotected {$f.Server[($f.Api+'/branches/main')].protected=$false}
   Expired {$f.Server[($f.Api+'/actions/artifacts/30')].expired=$true}
   Oversize {$f.Server[($f.Api+'/actions/artifacts/30')].size_in_bytes=[long](8MB+1)}
  }
  {Get-TokenForgeSealingSubject @options}|Should -Throw '*no signing performed*'
  Test-Path $options.OutputDirectory|Should -BeFalse
 }
 It 'refuses unsafe redirect origins and additional redirects (<Case>)' -ForEach @(@{Case='Http'},@{Case='Foreign'},@{Case='UserInfo'},@{Case='Port'},@{Case='Fragment'},@{Case='SecondRedirect'}) {
  switch($Case){Http {$f.Redirect='http://fixture.blob.core.windows.net/candidate'} Foreign {$f.Redirect='https://attacker.example/candidate'} UserInfo {$f.Redirect='https://user@fixture.blob.core.windows.net/candidate'} Port {$f.Redirect='https://fixture.blob.core.windows.net:444/candidate'} Fragment {$f.Redirect='https://fixture.blob.core.windows.net/candidate#secret'} SecondRedirect {$f.DownloadStatus=302}}
  {Get-TokenForgeSealingSubject @options}|Should -Throw '*OriginalZip*'
  Test-Path $options.OutputDirectory|Should -BeFalse
 }
 It 'does not confuse a wrapped or altered candidate with the original seven-file artifact (<Case>)' -ForEach @(@{Case='Wrapped'},@{Case='ManifestSource'},@{Case='ManifestAttempt'},@{Case='ExtraCode'},@{Case='Privacy'},@{Case='BlobChange'}) {
  switch($Case){
   Wrapped {Get-ChildItem $f.Candidate|Remove-Item;[IO.File]::WriteAllText((Join-Path $f.Candidate candidate.zip),'not the original ZIP')}
   ManifestSource {$m=Read-TfCandidateJson (Join-Path $f.Candidate manifest.json);$m.SourceCommit='9'*40;Write-TfCandidateJson $m (Join-Path $f.Candidate manifest.json)}
   ManifestAttempt {$m=Read-TfCandidateJson (Join-Path $f.Candidate manifest.json);$m.ProducerAttempt='2';Write-TfCandidateJson $m (Join-Path $f.Candidate manifest.json)}
   ExtraCode {[IO.File]::WriteAllText((Join-Path $f.Candidate evil.ps1),'throw "must not execute"')}
   Privacy {[IO.File]::WriteAllText((Join-Path $f.Candidate scopes.json),'{"AccessToken":"synthetic-secret"}')}
   BlobChange {[IO.File]::WriteAllText((Join-Path $f.Candidate review.md),'different')}
  }
  Update-SealerFixtureArchive $f
  {Get-TokenForgeSealingSubject @options}|Should -Throw '*Candidate*'
  Test-Path $options.OutputDirectory|Should -BeFalse
 }
 It 'refuses authority changes while bytes are downloaded (<Case>)' -ForEach @(@{Case='Rerun'},@{Case='MainAdvance'},@{Case='DeletedDigest'},@{Case='Failure'}) {
  $f.OnFetch={param($fixture,$phase)
   if($phase -ceq 'Bytes'){
    switch($Case){Rerun {$fixture.Server[($fixture.Api+'/actions/runs/10')].run_attempt=2} MainAdvance {$fixture.Server[($fixture.Api+'/branches/main')].commit.sha='9'*40} DeletedDigest {$fixture.Server[($fixture.Api+'/actions/artifacts/30')].digest='sha256:'+('9'*64)} Failure {$fixture.Server[($fixture.Api+'/actions/runs/10')].status='completed';$fixture.Server[($fixture.Api+'/actions/runs/10')].conclusion='failure'}}
   }
  }
  {Get-TokenForgeSealingSubject @options}|Should -Throw '*FinalOrigin*'
  Test-Path $options.OutputDirectory|Should -BeFalse
 }
 It 'never overwrites an existing output or leaks fixture errors into its public error' {
  $null=[IO.Directory]::CreateDirectory($options.OutputDirectory,[IO.UnixFileMode]448)
  $saved=Join-Path $options.OutputDirectory saved;[IO.File]::WriteAllText($saved,'completed evidence')
  {Get-TokenForgeSealingSubject @options}|Should -Throw
  [IO.File]::ReadAllText($saved)|Should -BeExactly 'completed evidence'
  $options.OutputDirectory=Join-Path $f.Root next
  $options.FetchFixture={throw 'synthetic-sensitive-SAS'}
  try{Get-TokenForgeSealingSubject @options}catch{$_.Exception.Message|Should -Not -Match 'synthetic-sensitive-SAS'}
 }
}

Describe 'Sealing download budgets' {
 BeforeEach {
  $calls=[Collections.Generic.List[string]]::new()
  $ctx=@{Synthetic=$true;FetchFixture=({param($Phase,$Uri) $calls.Add($Phase);@{Status=200;Bytes=[byte[]]@(1)}}.GetNewClosure());Watch=[Diagnostics.Stopwatch]::StartNew();Requests=0;DownloadRequests=0;Bytes=0L;DeadlineSeconds=60;MaxRequests=7;MaxBytes=16MB}
 }
 It 'rejects a third download request before transport' {
  $ctx.DownloadRequests=2
  {Invoke-TfSealerArchiveGet $ctx Bytes 'https://fixture.blob.core.windows.net/file'}|Should -Throw
  $calls.Count|Should -Be 0
 }
 It 'rejects an exhausted wall clock before transport without waiting' {
  $ctx.Watch=@{Elapsed=[TimeSpan]::FromSeconds(60)}
  {Invoke-TfSealerArchiveGet $ctx Bytes 'https://fixture.blob.core.windows.net/file'}|Should -Throw
  $calls.Count|Should -Be 0
 }
 It 'rejects exhausted aggregate bytes before transport' {
  $ctx.Bytes=16MB+1
  {Invoke-TfSealerArchiveGet $ctx Bytes 'https://fixture.blob.core.windows.net/file'}|Should -Throw
  $calls.Count|Should -Be 0
 }
 It 'rejects exhausted metadata requests before transport' {
  $ctx.Requests=8
  {Invoke-TfSealerArchiveGet $ctx Bytes 'https://fixture.blob.core.windows.net/file'}|Should -Throw
  $calls.Count|Should -Be 0
 }
}

Describe 'Hosted temporary-root ingress' {
 BeforeEach {
  $f=New-SealerFixture $TestDrive;$options=$f.SealerOptions
  $root=Join-Path $f.Root runner-temp;$null=[IO.Directory]::CreateDirectory($root)
  [IO.File]::SetUnixFileMode($root,[IO.UnixFileMode]493)
 }
 It 'creates a dedicated 0700 parent before resolving an output under a 0755 temporary root' {
  $options.OutputDirectory=New-TfSealerOutputPath $root
  [int][IO.File]::GetUnixFileMode((Split-Path $options.OutputDirectory))|Should -Be 448
  [int][IO.File]::GetUnixFileMode($root)|Should -Be 493
  $r=Get-TokenForgeSealingSubject @options
  $r.SubjectPath|Should -BeExactly (Join-Path $root tokenforge-sealer-private/sealed/candidate.zip)
  [int][IO.File]::GetUnixFileMode((Split-Path $r.SubjectPath))|Should -Be 448
  [int][IO.File]::GetUnixFileMode($r.SubjectPath)|Should -Be 256
 }
 It 'preserves an existing private parent and completed output' {
  $path=New-TfSealerOutputPath $root;$parent=Split-Path $path
  $saved=Join-Path $parent completed;[IO.File]::WriteAllText($saved,'completed evidence')
  {New-TfSealerOutputPath $root}|Should -Throw
  [IO.File]::ReadAllText($saved)|Should -BeExactly 'completed evidence'
 }
 It 'refuses an existing nonprivate parent without chmod or deletion' {
  $parent=Join-Path $root tokenforge-sealer-private;$null=[IO.Directory]::CreateDirectory($parent)
  [IO.File]::SetUnixFileMode($parent,[IO.UnixFileMode]493)
  {New-TfSealerOutputPath $root}|Should -Throw
  [int][IO.File]::GetUnixFileMode($parent)|Should -Be 493
 }
 It 'refuses a linked temporary root before creating anything' {
  $link=Join-Path $f.Root linked-root;$null=New-Item -ItemType SymbolicLink -Path $link -Target $root
  {New-TfSealerOutputPath $link}|Should -Throw
  Test-Path (Join-Path $root tokenforge-sealer-private)|Should -BeFalse
 }
 It 'keeps validator, signing and retained subject paths consistent' {
  $entry=Get-Content "$PSScriptRoot/../scripts/Invoke-TokenForgeSealer.ps1" -Raw
  $entry|Should -Match '\$outputPath=New-TfSealerOutputPath \$env:RUNNER_TEMP'
  $entry|Should -Match '-OutputDirectory \$outputPath'
  $workflow=Get-Content "$PSScriptRoot/../.github/workflows/tokenforge-sealer.yml" -Raw
  $workflow|Should -Match 'subject-path: \$\{\{ runner.temp \}\}/tokenforge-sealer-private/sealed/candidate.zip'
  $workflow|Should -Match '(?m)^            \$\{\{ runner.temp \}\}/tokenforge-sealer-private/sealed/candidate.zip$'
  $workflow|Should -Match '(?m)^            \$\{\{ runner.temp \}\}/tokenforge-sealer-private/sealed/subject.json$'
  $workflow|Should -Not -Match '/tokenforge-sealed/'
 }
}

# Former unsafe acceptances are now fail-closed safety regressions. The exact
# original digest remains the subject identity; no canonical replacement is used.
Describe 'Complete original-ZIP privacy safety regressions' {
 BeforeEach {$f=New-SealerFixture $TestDrive;$options=$f.SealerOptions}
 It 'enforces the complete original representation for <Case>' -ForEach @(
  @{Case='baseline-canonical';Accept=$true;Marker=$false},
  @{Case='archive-comment';Accept=$false;Marker=$true},
  @{Case='entry-comment';Accept=$false;Marker=$true},
  @{Case='local-and-central-extra';Accept=$false;Marker=$true},
  @{Case='appended-bytes';Accept=$false;Marker=$true},
  @{Case='prepended-unadjusted';Accept=$false;Marker=$false},
  @{Case='prepended-adjusted';Accept=$false;Marker=$true},
  @{Case='gap-before-central-directory';Accept=$false;Marker=$true},
  @{Case='gap-before-end-record';Accept=$false;Marker=$true}
 ) {
  $mutated=Join-Path $f.Root mutated.zip
  & /usr/bin/python3 -I "$PSScriptRoot/fixtures/publication/MutateSealerZip.py" $f.Zip $mutated $Case
  if($LASTEXITCODE){throw 'Synthetic ZIP mutator failed.'}
  [IO.File]::Copy($mutated,$f.Zip,$true)
  $f.Server[($f.Api+'/actions/artifacts/30')].digest='sha256:'+(Get-TfCandidateFileHash $f.Zip)
  $f.Server[($f.Api+'/actions/artifacts/30')].size_in_bytes=(Get-Item $f.Zip).Length
  if(-not $Accept){
   {Get-TokenForgeSealingSubject @options}|Should -Throw '*no signing performed*'
   Test-Path $options.OutputDirectory|Should -BeFalse
  }else{
   $r=Get-TokenForgeSealingSubject @options
   (Get-TfCandidateFileHash $r.SubjectPath)|Should -BeExactly (Get-TfCandidateFileHash $f.Zip)
   [Text.Encoding]::UTF8.GetString([IO.File]::ReadAllBytes($r.SubjectPath)).Contains('SYNTHETIC_METADATA_MARKER')|Should -Be $Marker
   $r.StructuralValidation|Should -BeTrue
   $r.CompleteOriginalZipPrivacyValidated|Should -BeTrue
   $r.SigningPerformed|Should -BeFalse
  }
 }
}

Describe 'Canonical stored original profile boundaries' {
 BeforeEach {$f=New-SealerFixture $TestDrive;$options=$f.SealerOptions}
 It 'rejects <Case> despite matching service digest and size' -ForEach @(
  @{Case='local-crc'},@{Case='central-crc'},@{Case='local-size'},@{Case='central-size'},
  @{Case='local-name'},@{Case='central-name'},@{Case='offset'},@{Case='timestamp'},@{Case='attributes'},
  @{Case='encryption'},@{Case='descriptor'},@{Case='unsupported-method'},@{Case='zip64-extra'},
  @{Case='deflate'},@{Case='reordered'},@{Case='duplicate-record'}
 ) {
  $mutated=Join-Path $f.Root altered.zip
  & /usr/bin/python3 -I "$PSScriptRoot/fixtures/publication/MutateSealerZip.py" $f.Zip $mutated $Case
  if($LASTEXITCODE){throw 'ZIP mutation failed.'}
  [IO.File]::Copy($mutated,$f.Zip,$true)
  $f.Server[($f.Api+'/actions/artifacts/30')].digest='sha256:'+(Get-TfCandidateFileHash $f.Zip)
  $f.Server[($f.Api+'/actions/artifacts/30')].size_in_bytes=(Get-Item $f.Zip).Length
  {Get-TokenForgeSealingSubject @options}|Should -Throw '*no signing performed*'
  Test-Path $options.OutputDirectory|Should -BeFalse
 }
 It 'explicitly refuses an ordinary .NET compressed archive as unsupported' {
  Update-SealerFixtureArchive $f
  {Get-TokenForgeSealingSubject @options}|Should -Throw '*ArchivePrivacy*'
 }
 It 'derives a deterministic archive without filesystem timestamps or mode metadata' {
  $before=Get-TfSealerCanonicalZipBytes $f.Candidate
  foreach($file in Get-ChildItem $f.Candidate -File){[IO.File]::SetLastWriteTimeUtc($file.FullName,[datetime]'2020-01-01T00:00:00Z')}
  $after=Get-TfSealerCanonicalZipBytes $f.Candidate
  [Linq.Enumerable]::SequenceEqual[byte]($before,$after)|Should -BeTrue
  $r=Get-TokenForgeSealingSubject @options
  $r.ArchiveProfile|Should -BeExactly CanonicalStoredOriginalZipV1
  $r.CompleteOriginalZipPrivacyValidated|Should -BeTrue
  $r.SubjectSha256|Should -BeExactly (Get-TfCandidateFileHash $f.Zip)
 }
 It 'refuses invalid UTF-8 rather than allowing a replacing decoder' {
  $path=Join-Path $f.Candidate review.md
  [IO.File]::WriteAllBytes($path,([IO.File]::ReadAllBytes($path)+[byte]255))
  {Get-TfSealerCanonicalZipBytes $f.Candidate}|Should -Throw
 }
}
