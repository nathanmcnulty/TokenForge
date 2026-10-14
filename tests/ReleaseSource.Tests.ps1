BeforeAll {
 $validator=Join-Path $PSScriptRoot '../scripts/Test-TokenForgeReleaseSource.ps1'
 $commit='a'*40
 function gh {param($Command,$Path,[Parameter(ValueFromRemainingArguments)]$Other);throw 'A release guard test attempted a real gh call.'}
}
Describe 'Release source and existing-version guard' {
 AfterAll {Remove-Variable tfReleaseFixture -Scope Global -ErrorAction SilentlyContinue}
 BeforeEach {
  $global:tfReleaseFixture=@{}
  $global:tfReleaseFixture.current=$commit;$global:tfReleaseFixture.tags=@();$global:tfReleaseFixture.releases=@();$global:tfReleaseFixture.apiFailed=$false
  $global:tfReleaseFixture.runs=@(
   @{id=1;path='.github/workflows/ci.yml';head_branch='main';head_sha=$commit;run_number=10;status='completed';conclusion='success'},
   @{id=2;path='.github/workflows/native.yml';head_branch='main';head_sha=$commit;run_number=10;status='completed';conclusion='success'}
  )
  $global:tfReleaseFixture.jobs=@{
   '1'=@(@{name='test (ubuntu-latest)';conclusion='success'},@{name='test (windows-latest)';conclusion='success'},@{name='test (macos-latest)';conclusion='success'})
   '2'=@(@{name='native (ubuntu-latest, linux-x64)';conclusion='success'},@{name='native (windows-latest, win-x64)';conclusion='success'},@{name='native (macos-latest, osx-arm64)';conclusion='success'},@{name='native (ubuntu-24.04-arm, linux-arm64)';conclusion='success'},@{name='native (windows-11-arm, win-arm64)';conclusion='success'},@{name='native (macos-15-intel, osx-x64)';conclusion='success'})
  }
  Mock gh {
   param($Command,$Path)
   $global:LASTEXITCODE=if($global:tfReleaseFixture.apiFailed){1}else{0}
   if($Path.EndsWith('/commits/main')){return $global:tfReleaseFixture.current}
   if($Path -match '/actions/runs\?'){return (@{workflow_runs=$global:tfReleaseFixture.runs}|ConvertTo-Json -Depth 6)}
   if($Path -match '/actions/runs/(\d+)/jobs\?'){return (@{jobs=$global:tfReleaseFixture.jobs[$Matches[1]]}|ConvertTo-Json -Depth 6)}
   if($Path -match '/releases\?'){return $global:tfReleaseFixture.releases}
   if($Path -match '/git/matching-refs/'){return (ConvertTo-Json -InputObject @($global:tfReleaseFixture.tags) -Depth 4)}
   throw 'Unexpected API request.'
  }
 }
 It 'accepts exact current main only with all nine successful platform gates' {
  {& $validator -Repository owner/repo -SourceCommit $commit -Version 1.2.3}|Should -Not -Throw
 }
 It 'accepts explicitly selected manual Linux validation without requiring other platforms' {
  $global:tfReleaseFixture.jobs['1']=@(@{name='test (ubuntu-latest)';conclusion='success'})
  $global:tfReleaseFixture.jobs['2']=@(@{name='native (ubuntu-latest, linux-x64)';conclusion='success'})
  {& $validator -Repository owner/repo -SourceCommit $commit -Version 1.2.3 -ValidationPlatform Linux -ValidationEvent workflow_dispatch}|Should -Not -Throw
  Should -Invoke gh -Exactly -Times 1 -ParameterFilter {$Path -like '*event=workflow_dispatch*'}
 }
 It 'rejects incomplete Linux validation even when other platforms passed' {
  $global:tfReleaseFixture.jobs['2']=@($global:tfReleaseFixture.jobs['2']|Where-Object {$_.name -notlike '*linux-x64*'})
  {& $validator -Repository owner/repo -SourceCommit $commit -Version 1.2.3 -ValidationPlatform Linux -ValidationEvent workflow_dispatch}|Should -Throw '*platform gate*'
 }
 It 'rejects an existing exact version tag without changing it' {
  $global:tfReleaseFixture.tags=@(@{ref='refs/tags/v1.2.3';object=@{sha=$commit}})
  {& $validator -Repository owner/repo -SourceCommit $commit -Version 1.2.3}|Should -Throw '*never overwritten*'
  Should -Invoke gh -Times 5 -Exactly
 }
 It 'rejects an existing draft even when no exact tag exists yet' {
  $global:tfReleaseFixture.releases=@(99)
  {& $validator -Repository owner/repo -SourceCommit $commit -Version 1.2.3}|Should -Throw '*drafts are never overwritten*'
  Should -Invoke gh -Times 6 -Exactly
 }
 It 'does not confuse a longer tag prefix with the exact version' {
  $global:tfReleaseFixture.tags=@(@{ref='refs/tags/v1.2.30'})
  {& $validator -Repository owner/repo -SourceCommit $commit -Version 1.2.3}|Should -Not -Throw
 }
 It 'rejects a main branch that advanced after the package build' {
  $global:tfReleaseFixture.current='b'*40
  {& $validator -Repository owner/repo -SourceCommit $commit -Version 1.2.3}|Should -Throw '*current main*'
 }
 It 'rejects a successful workflow missing a required platform job' {
  $global:tfReleaseFixture.jobs['2']=@($global:tfReleaseFixture.jobs['2']|Where-Object {$_.name -notlike '*windows*'})
  {& $validator -Repository owner/repo -SourceCommit $commit -Version 1.2.3}|Should -Throw '*platform gate*'
 }
 It 'rejects legacy three-target native coverage even when that workflow succeeded' {
  $global:tfReleaseFixture.jobs['2']=$global:tfReleaseFixture.jobs['2'][0..2]
  {& $validator -Repository owner/repo -SourceCommit $commit -Version 1.2.3}|Should -Throw '*platform gate*'
 }
 It 'rejects duplicate platform jobs rather than choosing an arbitrary result' {
  $global:tfReleaseFixture.jobs['1']+=@{name='test (ubuntu-latest)';conclusion='failure'}
  {& $validator -Repository owner/repo -SourceCommit $commit -Version 1.2.3}|Should -Throw '*platform gate*'
 }
 It 'rejects a failed platform job even when workflow status says success' {
  $global:tfReleaseFixture.jobs['2'][0].conclusion='failure'
  {& $validator -Repository owner/repo -SourceCommit $commit -Version 1.2.3}|Should -Throw '*platform gate*'
 }
 It 'rejects an unfinished newer validation run instead of using an older success' {
  $global:tfReleaseFixture.runs+=@{id=3;path='.github/workflows/ci.yml';head_branch='main';head_sha=$commit;run_number=11;status='in_progress';conclusion=''}
  {& $validator -Repository owner/repo -SourceCommit $commit -Version 1.2.3}|Should -Throw '*not complete*'
 }
 It 'rejects validation associated with another commit' {
  $global:tfReleaseFixture.runs[1].head_sha='b'*40
  {& $validator -Repository owner/repo -SourceCommit $commit -Version 1.2.3}|Should -Throw '*not complete*'
 }
 It 'rejects API failures instead of treating missing evidence as permission' {
  $global:tfReleaseFixture.apiFailed=$true
  {& $validator -Repository owner/repo -SourceCommit $commit -Version 1.2.3}|Should -Throw '*current main*'
 }
}
