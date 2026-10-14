#Requires -Version 7.4
[CmdletBinding()]
param([Parameter(Mandatory)][ValidatePattern('^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$')][string]$Repository,
 [Parameter(Mandatory)][ValidatePattern('^[a-f0-9]{40}$')][string]$SourceCommit,
 [Parameter(Mandatory)][ValidatePattern('^\d+\.\d+\.\d+$')][string]$Version,
 [ValidateSet('All','Linux')][string]$ValidationPlatform='All',
 [ValidateSet('push','workflow_dispatch')][string]$ValidationEvent='push')
$ErrorActionPreference='Stop'
$current=gh api "repos/$Repository/commits/main" --jq .sha
if($LASTEXITCODE -or $current -cne $SourceCommit){throw 'Release source must still be current main.'}
$runs=gh api "repos/$Repository/actions/runs?head_sha=$SourceCommit&event=$ValidationEvent&per_page=100"|ConvertFrom-Json
if($LASTEXITCODE){throw 'Cannot verify validation runs.'}
foreach($workflow in @('ci.yml','native.yml')){
  $run=@($runs.workflow_runs|Where-Object {$_.path -ceq ".github/workflows/$workflow" -and $_.head_branch -ceq 'main'}|Sort-Object run_number -Descending)[0]
  if(-not $run -or $run.head_sha -cne $SourceCommit -or $run.status -cne 'completed' -or $run.conclusion -cne 'success'){throw 'Exact-source validation is not complete.'}
  $jobs=gh api "repos/$Repository/actions/runs/$($run.id)/jobs?per_page=100"|ConvertFrom-Json
  if($LASTEXITCODE){throw 'Cannot verify validation jobs.'}
  $expected=if($workflow -ceq 'ci.yml'){@('test (ubuntu-latest)','test (windows-latest)','test (macos-latest)')}else{@('native (ubuntu-latest, linux-x64)','native (windows-latest, win-x64)','native (macos-latest, osx-arm64)','native (ubuntu-24.04-arm, linux-arm64)','native (windows-11-arm, win-arm64)','native (macos-15-intel, osx-x64)')}
  if($ValidationPlatform -eq 'Linux'){$expected=if($workflow -ceq 'ci.yml'){@('test (ubuntu-latest)')}else{@('native (ubuntu-latest, linux-x64)')}}
  foreach($name in $expected){$job=@($jobs.jobs|Where-Object {$_.name -ceq $name});if($job.Count -ne 1 -or $job[0].conclusion -cne 'success'){throw 'Required platform gate did not pass.'}}
}
$tag="v$Version"
$existing=gh api "repos/$Repository/git/matching-refs/tags/$tag"|ConvertFrom-Json
if($LASTEXITCODE -or @($existing|Where-Object {$_.ref -ceq "refs/tags/$tag"}).Count){throw 'Existing release tags are never overwritten.'}
$filter='.[] | select(.tag_name == "'+$tag+'") | .id'
$releaseIds=@(gh api "repos/$Repository/releases?per_page=100" --paginate --jq $filter)
if($LASTEXITCODE -or $releaseIds.Count){throw 'Existing releases and drafts are never overwritten.'}
