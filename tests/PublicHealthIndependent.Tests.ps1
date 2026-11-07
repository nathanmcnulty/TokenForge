BeforeAll {
 $repo=Split-Path $PSScriptRoot -Parent
 $native=$env:TOKENFORGE_TEST_NATIVE
 if(-not $native){throw 'Independent health tests require the approved existing Linux package.'}
 . "$repo/scripts/TokenForgePublicHealth.ps1"
 . "$repo/scripts/TokenForgePublicHealthSync.ps1"
 Initialize-TokenForgeHealthRuntime $native
 function New-IndependentFixture {
  $p=Join-Path $TestDrive ([guid]::NewGuid().ToString('N'))
  $null=[IO.Directory]::CreateDirectory($p,[IO.UnixFileMode]448)
  Copy-Item "$repo/tests/fixtures/public-health/*" $p
  return $p
 }
 function Write-IndependentJson([string]$Path,$Data){
  if(Test-Path $Path){[IO.File]::SetUnixFileMode($Path,[IO.UnixFileMode]384)}
  ConvertTo-Json -InputObject $Data -Depth 100|Set-Content -LiteralPath $Path -Encoding utf8NoBOM
 }
 function Collect-Independent([string]$Fixture,[string]$Previous){
  $out=Join-Path $TestDrive ([guid]::NewGuid().ToString('N'))
  $opts=@{OutputPath=$out;NativeExecutablePath=$native;SourceRevision=('a'*40);FixturePath=$Fixture}
  if($Previous){$opts.PreviousExchangePath=$Previous}
  $null=& "$repo/scripts/Invoke-TokenForgePublicHealth.ps1" @opts
  return $out
 }
 function Rehash-Independent([string]$Path){
  $p=Join-Path $Path manifest.json;$m=Read-TokenForgeHealthJson ([IO.File]::ReadAllBytes($p))
  foreach($n in $m.files.Keys){$bytes=[IO.File]::ReadAllBytes((Join-Path $Path $n));$m.files[$n].bytes=$bytes.Length;$m.files[$n].sha256=Get-TokenForgeHealthHash $bytes}
  Write-IndependentJson $p $m
 }
}
Describe 'Independent public health trust and recovery cases' {
 It 'refuses forged source hashes even after the payload manifest is recomputed' {
  $out=Collect-Independent (New-IndependentFixture)
  $h=Read-TokenForgeHealthJson ([IO.File]::ReadAllBytes((Join-Path $out health.json)))
  $h.sources[0].sha256='b'*64
  Write-IndependentJson (Join-Path $out health.json) $h;Rehash-Independent $out
  {Read-TokenForgeHealthExchange $out}|Should -Throw '*binding*'
 }
 It 'refuses freshness claims that disagree with retained partial catalog dates' {
  $fixture=New-IndependentFixture;$old=Collect-Independent $fixture
  Remove-Item (Join-Path $fixture resources.json)
  $out=Collect-Independent $fixture $old
  $h=Read-TokenForgeHealthJson ([IO.File]::ReadAllBytes((Join-Path $out health.json)))
  $h.lastCompleteAt='2020-01-01T00:00:00Z'
  Write-IndependentJson (Join-Path $out health.json) $h;Rehash-Independent $out
  {Read-TokenForgeHealthExchange $out}|Should -Throw '*date disagrees*'
 }
 It 'rejects unknown data in an optional upstream field rather than dropping it' {
  $fixture=New-IndependentFixture;$p=Join-Path $fixture roadtools.json
  $d=Read-TokenForgeHealthJson ([IO.File]::ReadAllBytes($p))
  $d.apps.Values|Select-Object -First 1|ForEach-Object {$_.Add('result',@{AccessToken='synthetic-secret'})}
  Write-IndependentJson $p $d
  $out=Collect-Independent $fixture
  $h=(Read-TokenForgeHealthExchange $out).Health
  $h.complete|Should -BeFalse
  @($h.sources|Where-Object name -CEQ roadtools)[0].status|Should -BeExactly Invalid
 }
 It 'validates privacy in older versions before admitting an entire ledger' {
  $fixture=New-IndependentFixture;$first=Collect-Independent $fixture
  $p=Join-Path $fixture roadtools.json;$d=Read-TokenForgeHealthJson ([IO.File]::ReadAllBytes($p))
  $d.apps.Values|Select-Object -First 1|ForEach-Object {$_.name='Changed public name'}
  Write-IndependentJson $p $d;$out=Collect-Independent $fixture $first
  $ledger=(Read-TokenForgeHealthExchange $out).Ledger
  $record=$ledger.Applications['11111111-1111-1111-1111-111111111111'].Records['Discovery///']
  $record.PreviousVersions.Count|Should -BeGreaterThan 0
  $record.PreviousVersions[0].Attributes.Add('AccessToken','synthetic-secret')
  Write-IndependentJson (Join-Path $out metadata.json) $ledger;Rehash-Independent $out
  {Read-TokenForgeHealthExchange $out}|Should -Throw
 }
 It 'does not treat a complete empty unlinked snapshot as tombstones for omitted local records' {
  $fixture=New-IndependentFixture;$first=Collect-Independent $fixture
  $state=Join-Path $TestDrive ([guid]::NewGuid().ToString('N'))
  $null=Import-TokenForgePublicHealthExchange $first $state $native
  Write-IndependentJson (Join-Path $fixture roadtools.json) @{apps=@{};resourceidentifiers=@{}}
  Write-IndependentJson (Join-Path $fixture microsoftApps.json) @()
  Write-IndependentJson (Join-Path $fixture resources.json) @()
  $empty=Collect-Independent $fixture
  $null=Import-TokenForgePublicHealthExchange $empty $state $native
  $db=Get-TokenForgeApplicationMetadata (Join-Path $state applications.sqlite) -NativeExecutablePath $native
  $db.Applications.Count|Should -Be 3
  @($db.Applications.Values|Where-Object {$_.Records['Discovery///'].PresentInLatestRun}).Count|Should -Be 3
 }
 It 'carries a retained complete catalog date into the first imported partial receipt' {
  $fixture=New-IndependentFixture;$first=Collect-Independent $fixture
  Remove-Item (Join-Path $fixture resources.json)
  $partial=Collect-Independent $fixture $first
  $state=Join-Path $TestDrive ([guid]::NewGuid().ToString('N'))
  $result=Import-TokenForgePublicHealthExchange $partial $state $native
  $result.collection|Should -BeExactly Incomplete
  $result.lastCompleteAt|Should -BeExactly (Read-TokenForgeHealthExchange $first).Health.lastCompleteAt
 }
 It 'does not fetch when the monotonic deadline has already elapsed' {
  $b=New-TokenForgeHealthBudget -MaxSeconds 1
  $b.Timer.Stop();$b.MaxSeconds=0
  {Invoke-TokenForgeHealthGet -Uri $script:HealthSources.roadtools -MaxBytes 1 -Budget $b -AllowedHosts @('raw.githubusercontent.com')}|Should -Throw '*deadline*'
  $b.Requests|Should -Be 0
 }
 It 'rejects an unapproved source receipt hidden in otherwise complete history' {
  $out=Collect-Independent (New-IndependentFixture)
  $d=(Read-TokenForgeHealthExchange $out).Ledger
  $d.Runs[0].SourceSnapshots[0].Location='https://raw.githubusercontent.com/other/public/main/catalog.json'
  Write-IndependentJson (Join-Path $out metadata.json) $d;Rehash-Independent $out
  {Read-TokenForgeHealthExchange $out}|Should -Throw
 }
 It 'uses the real CLI health path while excluding a known validated zero-ID placeholder' {
  $fixture=New-IndependentFixture;$p=Join-Path $fixture roadtools.json
  $d=Read-TokenForgeHealthJson ([IO.File]::ReadAllBytes($p))
  $d.apps.Add('00000000-0000-0000-0000-000000000000',@{name='Known upstream placeholder';public_client=$false;foci=$false;redirect_uris=@();preferred_noninteractive_redirurl=$null;scopes=@{}})
  Write-IndependentJson $p $d
  $out=Join-Path $TestDrive ([guid]::NewGuid().ToString('N'))
  $result=& "$repo/scripts/tokenforge.ps1" health collect -FixturePath $fixture -OutputPath $out -NativeExecutablePath $native -SourceRevision ('a'*40) -Json|ConvertFrom-Json
  $result.CollectionComplete|Should -BeTrue
  (Read-TokenForgeHealthExchange $out).Ledger.Applications.Contains('00000000-0000-0000-0000-000000000000')|Should -BeFalse
 }
 It 'rejects account authentication flags before CLI module initialization or account code' {
  Mock Import-Module {throw 'Unexpected module initialization.'}
  {& "$repo/scripts/tokenforge.ps1" health status -StatePath $TestDrive -NativeExecutablePath $native -Interactive}|Should -Throw '*does not accept account authentication*'
  Should -Invoke Import-Module -Exactly -Times 0
 }
 It 'refuses duplicate identity properties through the strict GitHub response parser' {
  $bytes=[Text.Encoding]::UTF8.GetBytes('{"id":123,"id":456,"repository":{"id":123}}')
  {Read-TokenForgeHealthJson $bytes}|Should -Throw
 }
 It 'refuses packaging a source label other than the owning checkpoint before creating output' {
  $out=Join-Path $TestDrive ([guid]::NewGuid().ToString('N'))
  $base=$env:TOKENFORGE_TEST_BASE_PACKAGE
  if(-not $base){$base=Split-Path $native -Parent}
  {& "$repo/scripts/New-TokenForgePublicHealthPackage.ps1" -BasePackagePath $base -OutputPath $out -SourceRevision ('0'*40)}|Should -Throw '*owning HEAD*'
  Test-Path $out|Should -BeFalse
 }
 It 'refuses a substituted base manifest despite unchanged approved executable and DLL' {
  $base=Join-Path $TestDrive ([guid]::NewGuid().ToString('N'))
  $dllDir=Join-Path $base src/TokenForge/lib/net10.0
  $null=[IO.Directory]::CreateDirectory($dllDir,[IO.UnixFileMode]448)
  Copy-Item -LiteralPath $native -Destination (Join-Path $base tokenforge)
  Copy-Item -LiteralPath (Join-Path (Split-Path $native -Parent) src/TokenForge/lib/net10.0/TokenForge.Credentials.dll) -Destination $dllDir
  Write-IndependentJson (Join-Path $base local-package-manifest.json) @{sourceRevision='0a1704d057417e58b92fd5eac8c546541d3f7ec2';nativeInputs=@{};files=@{'private.json'='a'*64}}
  $out=Join-Path $TestDrive ([guid]::NewGuid().ToString('N'))
  {& "$repo/scripts/New-TokenForgePublicHealthPackage.ps1" -BasePackagePath $base -OutputPath $out -SourceRevision ((& git -C $repo rev-parse HEAD).Trim())}|Should -Throw '*accepted receipt*'
  Test-Path $out|Should -BeFalse
 }
 It 'copies only tracked source through the packaging helper under StrictMode Latest' {
  . "$repo/scripts/Copy-TokenForgePackageSource.ps1"
  $source=Join-Path $TestDrive ([guid]::NewGuid().ToString('N'));$destination=Join-Path $TestDrive ([guid]::NewGuid().ToString('N'))
  $module=Join-Path $source src/TokenForge
  $null=[IO.Directory]::CreateDirectory($module,[IO.UnixFileMode]448)
  [IO.File]::WriteAllText((Join-Path $module public.ps1),'# reviewed fixture')
  [IO.File]::WriteAllText((Join-Path $module private.passkey),'synthetic excluded data')
  & git -C $source init --quiet
  & git -C $source add -- src/TokenForge/public.ps1
  if($LASTEXITCODE){throw 'Fixture Git tracking failed.'}
  & {Set-StrictMode -Version Latest;Copy-TokenForgePackageSource -SourceRoot $source -DestinationRoot $destination -Prefix src/TokenForge}
  @(Get-ChildItem $destination -File -Recurse).Count|Should -Be 1
  [IO.File]::ReadAllText((Join-Path $destination src/TokenForge/public.ps1))|Should -BeExactly '# reviewed fixture'
 }
}
Describe 'Independently qualified runtime pairs' {
 BeforeEach {
  $pairRoot=Join-Path $TestDrive ([guid]::NewGuid().ToString('N'))
  $null=[IO.Directory]::CreateDirectory((Join-Path $pairRoot src/TokenForge/lib/net10.0),[IO.UnixFileMode]448)
  [IO.File]::WriteAllText((Join-Path $pairRoot tokenforge),'synthetic executable')
  [IO.File]::WriteAllText((Join-Path $pairRoot src/TokenForge/lib/net10.0/TokenForge.Credentials.dll),'synthetic library')
  # Exercise only the pin gate. Synthetic bytes must never be loaded/executed.
  Mock Add-Type {}
  Mock Import-Module {}
  Mock Get-FileHash {
   [pscustomobject]@{Hash=$(if($LiteralPath.EndsWith('.dll')){$script:pairLibrary}else{$script:pairNative})}
  }
 }
 It 'separates the qualified disk-pair gate from real assembly verification (<Case>)' -ForEach @(
  @{Case='historical runtime';Native='42773ca3e048d5d29dd3edf488ca33ace5116d47afdd4513fa8df95b24a3047e';Library='a96664feb04f767cd48360a706292e2577e36472a1b27ac282c6e67899fa1a52';Accepted=$true},
  @{Case='offline-v1';Native='aa1ad0d814970379376ee5da6ddf531ccb22b1b738ad65709599ee64c4a2f61b';Library='a96664feb04f767cd48360a706292e2577e36472a1b27ac282c6e67899fa1a52';Accepted=$true},
  @{Case='ARM build';Native='d76e2ebbedde15e9fd962d3977f02516cf731cfacda55d72ef3ab7f145bf7dc8';Library='77ce122e7d7bde9b3bd6dccbd6539eec8f80cabae274b5c304c87d19dc3e5837';Accepted=$true},
  @{Case='assembly binding build';Native='21e1f3c5b8005fae99dae2290d9bfdee8a080402c1346175f3ad80712efc79b1';Library='14a12d434306eace18ca14195ef682c92ea9c79e7ceb3b16f0c0707c4006c789';Accepted=$true},
  @{Case='old executable new library';Native='aa1ad0d814970379376ee5da6ddf531ccb22b1b738ad65709599ee64c4a2f61b';Library='77ce122e7d7bde9b3bd6dccbd6539eec8f80cabae274b5c304c87d19dc3e5837';Accepted=$false},
  @{Case='new executable old library';Native='d76e2ebbedde15e9fd962d3977f02516cf731cfacda55d72ef3ab7f145bf7dc8';Library='a96664feb04f767cd48360a706292e2577e36472a1b27ac282c6e67899fa1a52';Accepted=$false}
 ) {
  $script:pairNative=$Native;$script:pairLibrary=$Library
  if($Accepted){ {Initialize-TokenForgeHealthRuntime (Join-Path $pairRoot tokenforge)}|Should -Throw '*loaded TokenForge credential runtime cannot be verified*' }
  else{ {Initialize-TokenForgeHealthRuntime (Join-Path $pairRoot tokenforge)}|Should -Throw '*qualified executable/library pair*' }
 }
}
