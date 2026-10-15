BeforeAll {Import-Module "$PSScriptRoot/../src/TokenForge/TokenForge.psd1" -Force}
Describe 'Read-only discovery progress' {
 BeforeEach {
  $state=Join-Path $TestDrive ([guid]::NewGuid().ToString())
  $path=Join-Path $state scopes.sqlite
  $id='c'*64
  & (Get-Module TokenForge) {param($p,$id) Save-TokenForgeDocument -Path $p -Document @{SchemaVersion=1;CohortId=$id}} (Join-Path $state discovery-run.json) $id
  if(-not $IsWindows){[IO.File]::SetUnixFileMode($state,[IO.UnixFileMode]448)}
  [IO.File]::WriteAllText($path,'synthetic fixture')
  Mock Import-Module {}
  Mock Invoke-TokenForgeNativeEvidence -ModuleName TokenForge {
   if($Operation -eq 'cohort-export'){@{PlanId=('c'*64);BatchSize=1;Cohort=@{TenantFingerprint=('a'*64);PrincipalFingerprint=('b'*64);Pairs=@(@{ClientId='11111111-1111-1111-1111-111111111111';ResourceId='00000003-0000-0000-c000-000000000000'},@{ClientId='22222222-2222-2222-2222-222222222222';ResourceId='00000003-0000-0000-c000-000000000000'})}}}
   elseif($Operation -eq 'pending'){@{ClientId='22222222-2222-2222-2222-222222222222';Chunk=1}}
   else{throw 'Unexpected write.'}
  }
 }
 It 'returns bounded counts without the recipe or pending membership' {
  $r=Get-TokenForgeResearchCohort $path $id -NativeExecutablePath '/synthetic/tokenforge' -SummaryOnly
  $r.Status|Should -Be Pending
  $r.ClientCount|Should -Be 2
  $r.CompletedClients|Should -Be 1
  $r.PendingClients|Should -Be 1
  $r.CredentialOutput|Should -BeFalse
  $r.PSObject.Properties.Name|Should -Not -Contain Cohort
  $r.PSObject.Properties.Name|Should -Not -Contain Pending
  ($r|ConvertTo-Json)|Should -Not -Match 'TenantFingerprint|PrincipalFingerprint|ClientId|ResourceId'
 }
 It 'reports complete only when no clients remain pending' {
  Mock Invoke-TokenForgeNativeEvidence -ModuleName TokenForge {} -ParameterFilter {$Operation -eq 'pending'}
  $r=Get-TokenForgeResearchCohort $path $id -NativeExecutablePath '/synthetic/tokenforge' -SummaryOnly
  $r.Status|Should -Be Complete
  $r.CompletedClients|Should -Be 2
 }
 It 'preserves detailed status for existing callers' {
  $r=Get-TokenForgeResearchCohort $path $id -NativeExecutablePath '/synthetic/tokenforge'
  $r.Pending.Count|Should -Be 1
  $r.Cohort.PrincipalFingerprint|Should -Be ('b'*64)
 }
 It 'reads the saved cohort while a writer holds its exclusive lock' {
  $lock=[IO.File]::Open((Join-Path $state '.writer.lock'),[IO.FileMode]::OpenOrCreate,[IO.FileAccess]::ReadWrite,[IO.FileShare]::None)
  try{
   $before=Get-FileHash (Join-Path $state discovery-run.json)
   $r=& "$PSScriptRoot/../scripts/Invoke-TokenForgeInventory.ps1" -Action CohortStatus -StatePath $state -NativeExecutablePath '/synthetic/tokenforge' -SummaryOnly
   $r.PlanId|Should -BeExactly $id
   $r.PendingClients|Should -Be 1
   (Get-FileHash (Join-Path $state discovery-run.json)).Hash|Should -BeExactly $before.Hash
  }finally{$lock.Dispose()}
 }
 It 'does not create a state directory for a missing run' {
  $missing=Join-Path $TestDrive ([guid]::NewGuid().ToString())
  {& "$PSScriptRoot/../scripts/Invoke-TokenForgeInventory.ps1" -Action CohortStatus -StatePath $missing -SummaryOnly}|Should -Throw '*existing scope database*'
  Test-Path $missing|Should -BeFalse
 }
 It 'rejects an invalid resume manifest (<Case>) without echoing its contents' -ForEach @(
  @{Case='empty';Json=''},
  @{Case='oversize';Json=('x'*1025)},
  @{Case='unknown field';Json=('{"SchemaVersion":1,"CohortId":"'+('c'*64)+'","AccessToken":"synthetic-private"}')},
  @{Case='string schema';Json=('{"SchemaVersion":"1","CohortId":"'+('c'*64)+'"}')},
  @{Case='array cohort';Json=('{"SchemaVersion":1,"CohortId":["'+('c'*64)+'"]}')},
  @{Case='wrong schema';Json=('{"SchemaVersion":2,"CohortId":"'+('c'*64)+'"}')},
  @{Case='invalid cohort';Json='{"SchemaVersion":1,"CohortId":"synthetic-private"}'},
  @{Case='malformed JSON';Json='synthetic-private'}
 ) {
  [IO.File]::WriteAllText((Join-Path $state discovery-run.json),$Json)
  {& (Get-Module TokenForge) {param($p) Get-TokenForgeDiscoveryRunId $p} (Join-Path $state discovery-run.json)}|Should -Throw -ExpectedMessage 'Invalid discovery run manifest.'
 }
}
