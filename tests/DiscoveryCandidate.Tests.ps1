BeforeAll {
 . "$PSScriptRoot/../scripts/TokenForgeDiscoveryCandidate.ps1"
 function New-SavedCandidateFixture {
  $root=Join-Path $TestDrive ([guid]::NewGuid().ToString())
  $null=[IO.Directory]::CreateDirectory($root,[IO.UnixFileMode]448)
  $scopePath=Join-Path $root 'scopes.sqlite';$flowPath=Join-Path $root 'flows.sqlite'
  foreach($p in @($scopePath,$flowPath)){[IO.File]::WriteAllText($p,'synthetic store');[IO.File]::SetUnixFileMode($p,[IO.UnixFileMode]384)}
  $client='11111111-1111-1111-1111-111111111111';$resource='00000003-0000-0000-c000-000000000000';$id='c'*64
  $date='2026-01-01T00:00:00+00:00'
  $frozen=@{TenantFingerprint=('a'*64);PrincipalFingerprint=('b'*64);CatalogHash=('d'*64);Authority='organizations';Protocols=@('OAuth2V2Pkce');MaxRedirects=1;ExploreAllFlows=$true;Pairs=@(@{ClientId=$client;ResourceId=$resource})}
  $plan=@{TenantFingerprint=('a'*64);PrincipalFingerprint=('b'*64);ClientId=$client;ResourceId=$resource;Tenant='organizations';CatalogHash=('d'*64);Eligibility='Eligible';ResourceAliases=@($resource);Cells=@(@{Protocol='OAuth2V2Pkce';Spa=$false;RedirectFingerprint=('e'*64)});PlannedAt=$date;CohortFingerprint=$id}
  $hash=& (Get-Module TokenForge) {param($p) Get-TokenForgeFlowPlanHash $p} $plan
  $key=& (Get-Module TokenForge) {param($s) Get-TokenForgeFingerprint $s} ($hash+'|OAuth2V2Pkce|0|'+('e'*64))
  $attempt=@{AttemptId='22222222-2222-2222-2222-222222222222';PlanFingerprint=$hash;AttemptKey=$key;ClientId=$client;ResourceId=$resource;TenantFingerprint=('a'*64);PrincipalFingerprint=('b'*64);StartedAt=$date;ObservedAt=$date;Protocol='OAuth2V2Pkce';Spa=$false;RedirectFingerprint=('e'*64);Outcome='Succeeded';ResponseScopes=@('User.Read');ScpScopes=@('User.Read');ClaimsReadable=$true;HasScpClaim=$true;NamespaceVerification='Matched';RequestVerification='Matched';SignatureValidated=$false;ErrorCodes=@();ElapsedSeconds=1}
  $flows=@{Format='TokenForgeFlowEvidence';SchemaVersion=1;UpdatedAt=$date;Plans=@{};Attempts=@($attempt)};$flows.Plans[$hash]=$plan
  $cohort=[pscustomobject]@{PlanId=$id;Cohort=$frozen}
  $scopes=New-TokenForgeScopeDatabase
  @{Root=$root;Scope=$scopePath;Flow=$flowPath;Flows=$flows;Scopes=$scopes;Cohort=$cohort;Hash=$hash;Options=@{ScopePath=$scopePath;FlowPath=$flowPath;CohortId=$id;OutputPath=(Join-Path $root 'candidate');SourceCommit=('f'*40);ProducerRunId='1';ProducerAttempt='1';NativeExecutablePath='/synthetic/tokenforge'}}
 }
 function Update-CandidateDigests([string]$Path) {
  $manifestPath=Join-Path $Path 'manifest.json';$m=Read-TfCandidateJson $manifestPath
  foreach($entry in $m.Files){$entry.Sha256=Get-TfCandidateFileHash (Join-Path $Path $entry.Path)}
  $m.RecipeSha256=Get-TfCandidateFileHash (Join-Path $Path 'recipe.json')
  Write-TfCandidateJson $m $manifestPath
  Get-TfCandidateFileHash $manifestPath
 }
}
Describe 'Saved evidence candidate integrity and offline recovery' {
 BeforeEach {
  $f=New-SavedCandidateFixture;$options=$f.Options
  Mock Get-TokenForgeResearchCohort {$f.Cohort}
  Mock Get-TokenForgeScopeDatabase {$f.Scopes}
  Mock Get-TokenForgeFlowEvidence {$f.Flows}
  Mock Get-TokenForgeToken -ModuleName TokenForge {throw 'Authentication is forbidden in this suite.'}
 }
 AfterEach {Should -Invoke Get-TokenForgeToken -ModuleName TokenForge -Times 0 -Exactly}
 It 'reconstructs an interrupted aggregate from primary flow evidence with original dates' {
  $before=Get-TfCandidateFileHash $f.Scope
  $hash=New-TfDiscoveryCandidate @options
  $m=Assert-TfDiscoveryCandidate $f.Options.OutputPath $hash
  $m.SourceCommit|Should -BeExactly ('f'*40)
  $scopes=Read-TfCandidateJson "$($f.Options.OutputPath)/scopes.json"
  $scopes.Observations.Count|Should -Be 1
  $scopes.Observations[0].ObservedAt|Should -Be '2026-01-01T00:00:00.0000000+00:00'
  (Read-TfCandidateJson "$($f.Options.OutputPath)/validation.json").TerminalCells|Should -Be 1
  (Get-TfCandidateFileHash $f.Scope)|Should -BeExactly $before
  Should -Invoke Get-TokenForgeFlowEvidence -Times 2 -Exactly -ParameterFilter {-not $Latest -and -not $TenantFingerprint -and -not $PrincipalFingerprint -and -not $PlanFingerprint}
  Should -Invoke Get-TokenForgeScopeDatabase -Times 2 -Exactly -ParameterFilter {-not $Latest -and -not $TenantFingerprint -and -not $PrincipalFingerprint -and -not $PlanFingerprint}
 }
 It 'exports a strict public allowlist without private namespace or callback fields' {
  $hash=New-TfDiscoveryCandidate @options
  $null=Assert-TfDiscoveryCandidate $f.Options.OutputPath $hash
  $text=Get-ChildItem $f.Options.OutputPath -File|Where-Object Name -ne manifest.json|ForEach-Object {Get-Content $_.FullName -Raw}
  ($text -join '')|Should -Not -Match 'TenantFingerprint|PrincipalFingerprint|AttemptId|AttemptKey|RedirectFingerprint|CohortFingerprint|PlanFingerprint|organizations|private-access|private-cookie'
  @(Get-ChildItem $f.Options.OutputPath -Force).Count|Should -Be 7
 }
 It 'leaves a newer Started attempt unknown while preserving historical observed success' {
  $row=$f.Flows.Attempts[0].Clone();$row.AttemptId='33333333-3333-3333-3333-333333333333';$row.Outcome='Started';$row.StartedAt='2026-01-02T00:00:00Z';$row.ObservedAt=$row.StartedAt
  $f.Flows.Attempts+=@($row)
  $hash=New-TfDiscoveryCandidate @options
  $null=Assert-TfDiscoveryCandidate $f.Options.OutputPath $hash
  $v=Read-TfCandidateJson "$($f.Options.OutputPath)/validation.json"
  $v.InFlightUnknownCells|Should -Be 1;$v.TerminalCells|Should -Be 0;$v.ScopeObservations|Should -Be 1
 }
 It 'preserves bounded failure classification without claiming successful cells (<Outcome>)' -ForEach @(
  @{Outcome='SessionPaused';Counter='PausedCells';Terminal=0},
  @{Outcome='RequestBlocked';Counter='RequestBlockedCells';Terminal=1},
  @{Outcome='TransientFailure';Counter='TransientFailureCells';Terminal=0}
 ) {
  $f.Flows.Attempts[0].Outcome=$Outcome
  $hash=New-TfDiscoveryCandidate @options
  $null=Assert-TfDiscoveryCandidate $f.Options.OutputPath $hash
  $v=Read-TfCandidateJson "$($f.Options.OutputPath)/validation.json"
  $v[$Counter]|Should -Be 1;$v.TerminalCells|Should -Be $Terminal;$v.ScopeObservations|Should -Be 0
 }
 It 'keeps missing matrices pending without inventing exact cell coverage' {
  $f.Flows.Plans=@{};$f.Flows.Attempts=@()
  $hash=New-TfDiscoveryCandidate @options
  $v=Read-TfCandidateJson "$($f.Options.OutputPath)/validation.json"
  $v.SelectedPairs|Should -Be 1;$v.UnknownMatrixPairs|Should -Be 1;$v.PlannedCells|Should -Be 0
  $null=Assert-TfDiscoveryCandidate $f.Options.OutputPath $hash
 }
 It 'excludes unrelated valid account and cohort evidence' {
  $other=$f.Flows.Plans[$f.Hash].Clone();$other.CohortFingerprint='9'*64;$other.TenantFingerprint='8'*64
  $otherHash=& (Get-Module TokenForge) {param($p) Get-TokenForgeFlowPlanHash $p} $other
  $f.Flows.Plans[$otherHash]=$other
  $hash=New-TfDiscoveryCandidate @options
  (Read-TfCandidateJson "$($f.Options.OutputPath)/flows.json").Observations.Count|Should -Be 1
  $null=Assert-TfDiscoveryCandidate $f.Options.OutputPath $hash
 }
 It 'rejects a namespace mismatch inside the selected cohort' {
  $f.Flows.Plans[$f.Hash].TenantFingerprint='9'*64
  {New-TfDiscoveryCandidate @options}|Should -Throw '*namespace*'
  Test-Path $f.Options.OutputPath|Should -BeFalse
 }
 It 'rejects full-history corruption before creating a candidate' {
  Mock Get-TokenForgeFlowEvidence {throw 'Synthetic corrupt old history.'}
  {New-TfDiscoveryCandidate @options}|Should -Throw '*corrupt old history*'
  Test-Path $f.Options.OutputPath|Should -BeFalse
 }
 It 'retries an interrupted export from saved stores and removes its partial projection' {
  $script:interruptExport=$true
  Mock Write-TfCandidateJson {if($script:interruptExport -and $Path.EndsWith('coverage.json')){throw 'Synthetic export interruption.'};ConvertTo-Json -InputObject $Value -Depth 100|Set-Content -LiteralPath $Path -Encoding utf8}
  {New-TfDiscoveryCandidate @options}|Should -Throw '*export interruption*'
  Test-Path $f.Options.OutputPath|Should -BeFalse
  @(Get-ChildItem $f.Root -Force -Directory).Count|Should -Be 0
  $script:interruptExport=$false
  $hash=New-TfDiscoveryCandidate @options
  $null=Assert-TfDiscoveryCandidate $f.Options.OutputPath $hash
 }
 It 'refuses publication of a mixed snapshot when evidence changes during export' {
  Mock Get-TokenForgeScopeDatabase {if($script:readCount++){ $f.Scopes.Observations=@('changed') };$f.Scopes}
  $script:readCount=0
  {New-TfDiscoveryCandidate @options}|Should -Throw '*changed during export*'
  Test-Path $f.Options.OutputPath|Should -BeFalse
 }
 It 'does not overwrite a sealed output or supersede authoritative checkpoints' {
  $hash=New-TfDiscoveryCandidate @options
  {New-TfDiscoveryCandidate @options}|Should -Throw '*cannot be overwritten*'
  $null=Assert-TfDiscoveryCandidate $f.Options.OutputPath $hash
 }
 It 'refuses broad-access private stores and linked output paths' {
  [IO.File]::SetUnixFileMode($f.Scope,[IO.UnixFileMode]420)
  {New-TfDiscoveryCandidate @options}|Should -Throw '*exclude group*'
  [IO.File]::SetUnixFileMode($f.Scope,[IO.UnixFileMode]384)
  $linked=Join-Path $f.Root 'linked';$null=New-Item -ItemType SymbolicLink -Path $linked -Target $f.Root
  $f.Options.OutputPath=Join-Path $linked 'candidate'
  {New-TfDiscoveryCandidate @options}|Should -Throw '*Linked*'
 }
 It 'rejects changed bytes, extra files, linked files and a different manifest digest' {
  $hash=New-TfDiscoveryCandidate @options
  {Assert-TfDiscoveryCandidate $f.Options.OutputPath ('1'*64)}|Should -Throw '*hash mismatch*'
  $extra=Join-Path $f.Options.OutputPath 'extra.json';Set-Content $extra '{}'
  {Assert-TfDiscoveryCandidate $f.Options.OutputPath $hash}|Should -Throw '*Unexpected*'
  Remove-Item $extra
  $null=New-Item -ItemType SymbolicLink -Path $extra -Target $f.Scope
  {Assert-TfDiscoveryCandidate $f.Options.OutputPath $hash}|Should -Throw '*Linked*'
  Remove-Item $extra
  Add-Content "$($f.Options.OutputPath)/flows.json" ' '
  {Assert-TfDiscoveryCandidate $f.Options.OutputPath $hash}|Should -Throw '*hash mismatch*'
 }
 It 'rejects private injected fields even when all content hashes are recomputed' {
  $null=New-TfDiscoveryCandidate @options
  $path="$($f.Options.OutputPath)/flows.json";$d=Read-TfCandidateJson $path;$d.Observations[0].AccessToken='private-access';Write-TfCandidateJson $d $path
  $hash=Update-CandidateDigests $f.Options.OutputPath
  {Assert-TfDiscoveryCandidate $f.Options.OutputPath $hash}|Should -Throw '*fields*'
 }
 It 'rejects inconsistent public projections even with recomputed hashes' {
  $null=New-TfDiscoveryCandidate @options
  $path="$($f.Options.OutputPath)/scopes.json";$d=Read-TfCandidateJson $path;$d.Observations[0].Scopes=@('Mail.Read');Write-TfCandidateJson $d $path
  $hash=Update-CandidateDigests $f.Options.OutputPath
  {Assert-TfDiscoveryCandidate $f.Options.OutputPath $hash}|Should -Throw '*projections disagree*'
 }
 It 'reconstructs validation and fixed review text independently of content hashes' {
  $null=New-TfDiscoveryCandidate @options
  $path="$($f.Options.OutputPath)/validation.json";$d=Read-TfCandidateJson $path;$d.TerminalCells=99;Write-TfCandidateJson $d $path
  $hash=Update-CandidateDigests $f.Options.OutputPath
  {Assert-TfDiscoveryCandidate $f.Options.OutputPath $hash}|Should -Throw '*reconstruction mismatch*'
 }
 It 'rejects traversal, duplicate manifest entries and duplicate JSON keys' {
  $null=New-TfDiscoveryCandidate @options
  $path="$($f.Options.OutputPath)/manifest.json";$m=Read-TfCandidateJson $path
  $m.Files[0].Path='../secret';Write-TfCandidateJson $m $path
  {Assert-TfDiscoveryCandidate $f.Options.OutputPath (Get-TfCandidateFileHash $path)}|Should -Throw '*Invalid or duplicate*'
  $m.Files[0].Path='coverage.json';$m.Files+=@($m.Files[0]);Write-TfCandidateJson $m $path
  {Assert-TfDiscoveryCandidate $f.Options.OutputPath (Get-TfCandidateFileHash $path)}|Should -Throw '*Invalid or duplicate*'
  [IO.File]::WriteAllText($path,'{"SchemaVersion":1,"SchemaVersion":1}')
  {Assert-TfDiscoveryCandidate $f.Options.OutputPath (Get-TfCandidateFileHash $path)}|Should -Throw
 }
 It 'requires a separate exact producer source and candidate-bound approval when supplied' {
  $hash=New-TfDiscoveryCandidate @options
  $review=@{SchemaVersion=1;CandidateHash=$hash;SourceCommit=('f'*40);ProducerRunId='1';ProducerAttempt='1';Decision='Approved';Reviewer='offline-reviewer';ReviewedAt='2026-01-02T00:00:00Z';Notes='Reviewed offline fixture.'}
  $path=Join-Path $f.Root 'review.json';Write-TfCandidateJson $review $path
  $null=Assert-TfDiscoveryCandidate $f.Options.OutputPath $hash $path
  foreach($field in @('CandidateHash','SourceCommit','ProducerRunId','ProducerAttempt','Decision','Reviewer','ReviewedAt','Notes')){
   $bad=$review.Clone();$bad[$field]='';Write-TfCandidateJson $bad $path
   {Assert-TfDiscoveryCandidate $f.Options.OutputPath $hash $path}|Should -Throw
  }
 }
}
