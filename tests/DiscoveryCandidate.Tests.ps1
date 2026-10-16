BeforeAll {
 . "$PSScriptRoot/../scripts/TokenForgeDiscoveryCandidate.ps1"
 $catalog=Get-TokenForgeCatalog -Path "$PSScriptRoot/fixtures/catalog.json"
 $catalog.Source='https://raw.githubusercontent.com/example/public/main/scopes.json'
 $discovery=Get-TokenForgeDiscovery -Catalog $catalog|ConvertTo-Json -Depth 100|ConvertFrom-Json -AsHashtable
 function New-ReviewFixture([switch]$Changed) {
  $root=Join-Path $TestDrive ([guid]::NewGuid().ToString())
  $data=Join-Path $root data;$baseline=Join-Path $root baseline;$candidate=Join-Path $root candidate
  $null=New-Item -ItemType Directory $data,$baseline
  $state=New-TfCiState $discovery
  Write-TfCandidateJson $state (Join-Path $data weekly-shallow.json)
  $null=Update-TokenForgeApplicationMetadata (Join-Path $data applications.json) $discovery Discovery
  Remove-Item "$data/*.lock" -ErrorAction SilentlyContinue
  Copy-Item "$data/*" $baseline
  $request=[ordered]@{SchemaVersion=1;PlanId=$state.PlanId;Mode='Shallow';Indices=@(0);BaseCommit=('a'*40)}
  $requestPath=Join-Path $root request.json;Write-TfCandidateJson $request $requestPath
  if($Changed){$state.Batches[0].Attempts=1;Write-TfCandidateJson $state (Join-Path $data weekly-shallow.json)}
  $hash=New-TfDiscoveryCandidate -DataPath $data -BaselinePath $baseline -RequestPath $requestPath -OutputPath $candidate -SourceCommit ('b'*40) -ProducerRunId '123' -ProducerAttempt '1'
  $review=[ordered]@{SchemaVersion=1;CandidateHash=$hash;BaseCommit=('a'*40);SourceCommit=('b'*40);ProducerRunId='123';ProducerAttempt='1';Decision='Approved';Reviewer='repository-maintainer';ReviewedAt='2026-01-01T00:00:00Z';Notes='Reviewed full semantic diff and public validation.'}
  $reviewPath=Join-Path $root review.json;Write-TfCandidateJson $review $reviewPath
  @{Root=$root;Data=$data;Baseline=$baseline;Candidate=$candidate;Hash=$hash;Review=$review;ReviewPath=$reviewPath;RequestPath=$requestPath}
 }
}
Describe 'Immutable discovery review candidates' {
 BeforeEach {$f=New-ReviewFixture}
 It 'validates a candidate separately from its explicit review' {
  (Assert-TfDiscoveryCandidate $f.Candidate $f.Hash).BaseCommit|Should -Be ('a'*40)
  (Assert-TfDiscoveryCandidate $f.Candidate $f.Hash $f.ReviewPath).ProducerRunId|Should -Be '123'
  @(Get-Content "$($f.Candidate)/changes.json" -Raw|ConvertFrom-Json).Count|Should -Be 0
 }
 It 'writes a full semantic before/after diff for changed evidence' {
  $changed=New-ReviewFixture -Changed
  $diff=@(Get-Content "$($changed.Candidate)/changes.json" -Raw|ConvertFrom-Json)
  $diff.Count|Should -Be 1
  $diff[0].Path|Should -Be '/Batches/0/Attempts'
  $diff[0].Before|Should -Be '0'
  $diff[0].After|Should -Be '1'
 }
 It 'does not overwrite an existing sealed output' {
  {New-TfDiscoveryCandidate -DataPath $f.Data -BaselinePath $f.Baseline -RequestPath $f.RequestPath -OutputPath $f.Candidate -SourceCommit ('b'*40) -ProducerRunId '123' -ProducerAttempt '1'}|Should -Throw '*cannot be overwritten*'
 }
 It 'rejects payload tampering and a different manifest digest' {
  Add-Content "$($f.Candidate)/data/applications.json" ' '
  {Assert-TfDiscoveryCandidate $f.Candidate $f.Hash}|Should -Throw '*hash mismatch*'
  {Assert-TfDiscoveryCandidate $f.Candidate ('c'*64)}|Should -Throw '*hash mismatch*'
 }
 It 'rejects extra files and symbolic links' {
  Set-Content "$($f.Candidate)/extra.json" '{}'
  {Assert-TfDiscoveryCandidate $f.Candidate $f.Hash}|Should -Throw '*Unexpected*'
  Remove-Item "$($f.Candidate)/extra.json"
  $null=New-Item -ItemType SymbolicLink -Path "$($f.Candidate)/link" -Target $f.ReviewPath
  {Assert-TfDiscoveryCandidate $f.Candidate $f.Hash}|Should -Throw '*Linked*'
 }
 It 'rejects traversal and duplicate manifest paths even with recomputed digest' {
  $path="$($f.Candidate)/manifest.json";$m=Get-Content $path -Raw|ConvertFrom-Json -AsHashtable
  $m.Files[0].Path='../review.json';Write-TfCandidateJson $m $path
  {Assert-TfDiscoveryCandidate $f.Candidate (Get-TfCandidateFileHash $path)}|Should -Throw '*Invalid or duplicate*'
 }
 It 'rejects absent, pending, mismatched and invalid-date approval' {
  {Assert-TfDiscoveryCandidate $f.Candidate $f.Hash "$($f.Root)/missing.json" -ErrorAction Stop}|Should -Throw
  foreach($field in @('CandidateHash','BaseCommit','SourceCommit','ProducerRunId','ProducerAttempt','Decision','Reviewer','ReviewedAt','Notes')){
   $review=[TokenForge.Core.DiscoverySourceClaims]::ReadMetadataJson(($f.Review|ConvertTo-Json));$review[$field]='';Write-TfCandidateJson $review $f.ReviewPath
   {Assert-TfDiscoveryCandidate $f.Candidate $f.Hash $f.ReviewPath}|Should -Throw
  }
 }
 It 'rejects duplicate JSON keys in the trusted approval contract' {
  $text=Get-Content $f.ReviewPath -Raw
  $text=$text.Replace('"Decision": "Approved"','"Decision": "Rejected", "Decision": "Approved"')
  Set-Content $f.ReviewPath $text
  {Assert-TfDiscoveryCandidate $f.Candidate $f.Hash $f.ReviewPath}|Should -Throw
 }
 It 'rejects duplicate manifest entries even with recomputed manifest digest' {
  $path="$($f.Candidate)/manifest.json";$m=Read-TfCandidateJson $path
  $m.Files+=@($m.Files[0]);Write-TfCandidateJson $m $path
  {Assert-TfDiscoveryCandidate $f.Candidate (Get-TfCandidateFileHash $path)}|Should -Throw '*Invalid or duplicate*'
 }
 It 'reports semantic JSON pointer values and ignores object property order' {
  $left=@(Get-TfCandidateLeaves ([ordered]@{b=2;a=@('first','second')}))
  $right=@(Get-TfCandidateLeaves ([ordered]@{a=@('first','second');b=2}))
  ($left|ConvertTo-Json -Compress)|Should -BeExactly ($right|ConvertTo-Json -Compress)
  $left.Path|Should -Contain '/a/0'
 }
 It 'fails closed for unknown data files before creating output' {
  Set-Content "$($f.Data)/private.json" '{}'
  {New-TfDiscoveryCandidate -DataPath $f.Data -BaselinePath $f.Baseline -RequestPath $f.RequestPath -OutputPath "$($f.Root)/other" -SourceCommit ('b'*40) -ProducerRunId '123' -ProducerAttempt '1'}|Should -Throw '*Unexpected candidate data*'
  Test-Path "$($f.Root)/other"|Should -BeFalse
 }
}
Describe 'Discovery workflow trust boundary' {
 It 'has no branch writer or review impersonation in collection' {
  $text=Get-Content "$PSScriptRoot/../.github/workflows/discovery.yml" -Raw
  $text|Should -Not -Match 'contents: write|git push|schedule:|pull_request:|\n  push:'
  ([regex]::Matches($text, "steps.plan.outputs.has_plan != 'False'")).Count|Should -Be 2
  $text|Should -Match 'discovery-candidate-\$\{\{ github.run_attempt \}\}'
 }
 It 'publishes only an explicit main-branch review and never runs collection or candidate code' {
  $text=Get-Content "$PSScriptRoot/../.github/workflows/discovery-publish.yml" -Raw
  $text|Should -Match "github.ref == 'refs/heads/main'"
  $text|Should -Match 'discovery-reviews/\$env:CANDIDATE_HASH.json'
  $text|Should -Match 'Assert-TfDiscoveryCandidate.*-ReviewPath'
  $text|Should -Not -Match 'action-passkey-login|Invoke-TokenForgeCiDiscovery|Invoke-TokenForgeWeeklyCi|schedule:|--force(?:\s|$)'
  $text|Should -Match 'Data parent advanced'
  $text|Should -Match 'attempts/\$env:CANDIDATE_ATTEMPT/jobs'
  $text|Should -Match 'exact candidate sealing job must have succeeded'
 }
}
Describe 'Exact reviewed-parent publication compare-and-swap' {
 BeforeEach {
  $root=Join-Path $TestDrive ([guid]::NewGuid().ToString())
  $remote=Join-Path $root remote.git;$writer=Join-Path $root writer
  $null=New-Item -ItemType Directory $root
  git init --quiet --bare $remote
  git init --quiet $writer
  git -C $writer config user.name 'Offline Test'
  git -C $writer config user.email 'offline@example.invalid'
  git -C $writer commit --quiet --allow-empty -m ancestor
  $ancestor=git -C $writer rev-parse HEAD
  git -C $writer commit --quiet --allow-empty -m base
  $base=git -C $writer rev-parse HEAD
  git -C $writer remote add origin $remote
  git -C $writer push --quiet origin HEAD:refs/heads/discovery-data
  if($LASTEXITCODE -ne 0){throw 'Offline bare-remote fixture failed.'}
  git -C $writer commit --quiet --allow-empty -m candidate
  $candidate=git -C $writer rev-parse HEAD
 }
 It 'advances exactly the reviewed parent to its direct child' {
  Publish-TfDiscoveryGitCommit $writer $base
  (git --git-dir=$remote rev-parse refs/heads/discovery-data)|Should -BeExactly $candidate
 }
 It 'rejects branch deletion between precheck and push' {
  git --git-dir=$remote update-ref -d refs/heads/discovery-data
  {Publish-TfDiscoveryGitCommit $writer $base}|Should -Throw '*compare-and-swap*'
  git --git-dir=$remote show-ref --verify --quiet refs/heads/discovery-data
  $LASTEXITCODE|Should -Be 1
 }
 It 'rejects reset to an ancestor between precheck and push' {
  git --git-dir=$remote update-ref refs/heads/discovery-data $ancestor
  {Publish-TfDiscoveryGitCommit $writer $base}|Should -Throw '*compare-and-swap*'
  (git --git-dir=$remote rev-parse refs/heads/discovery-data)|Should -BeExactly $ancestor
 }
 It 'rejects concurrent advancement between precheck and push' {
  git -C $writer commit --quiet --allow-empty -m concurrent-update
  $other=git -C $writer rev-parse HEAD
  git -C $writer push --quiet origin HEAD:refs/heads/other
  git -C $writer reset --quiet --hard $candidate
  git --git-dir=$remote update-ref refs/heads/discovery-data $other
  {Publish-TfDiscoveryGitCommit $writer $base}|Should -Throw '*compare-and-swap*'
  (git --git-dir=$remote rev-parse refs/heads/discovery-data)|Should -BeExactly $other
 }
 It 'rejects a candidate that is not a direct child of its reviewed parent' {
  git -C $writer commit --quiet --allow-empty -m extra
  {Publish-TfDiscoveryGitCommit $writer $base}|Should -Throw '*direct single-parent child*'
  (git --git-dir=$remote rev-parse refs/heads/discovery-data)|Should -BeExactly $base
 }
}
