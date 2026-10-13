BeforeAll {
 . (Join-Path $PSScriptRoot '../scripts/Copy-TokenForgePackageSource.ps1')
 if(-not ('TfPackageSourceUnix' -as [type])){
  Add-Type @'
using System.Runtime.InteropServices;
public static class TfPackageSourceUnix {
 [DllImport("libc", EntryPoint="open")] public static extern int LinuxOpen(byte[] path,int flags,uint mode);
 [DllImport("libc", EntryPoint="close")] public static extern int LinuxClose(int descriptor);
 [DllImport("libc", EntryPoint="unlink")] public static extern int LinuxUnlink(byte[] path);
 [DllImport("libSystem.B.dylib", EntryPoint="open")] public static extern int MacOpen(byte[] path,int flags,uint mode);
 [DllImport("libSystem.B.dylib", EntryPoint="close")] public static extern int MacClose(int descriptor);
 [DllImport("libSystem.B.dylib", EntryPoint="unlink")] public static extern int MacUnlink(byte[] path);
}
'@
 }
 function New-TrackedSource([string]$Root,[string]$Relative,[string]$Content='synthetic source'){
  $file=Join-Path $Root $Relative
  $null=New-Item -ItemType Directory -Path (Split-Path $file -Parent) -Force
  [IO.File]::WriteAllText($file,$Content)
  & git -C $Root add -- $Relative
  if($LASTEXITCODE){throw 'Fixture tracking failed.'}
 }
}
Describe 'Package tracked-source boundary' {
 BeforeEach {
  $source=Join-Path $TestDrive ([guid]::NewGuid().ToString('N'))
  $destination=Join-Path $TestDrive ([guid]::NewGuid().ToString('N'))
  if($IsMacOS){$source=$source -replace '^/var/','/private/var/'}
  $null=New-Item -ItemType Directory $source,$destination
  & git -C $source init --quiet
  if($LASTEXITCODE){throw 'Fixture initialization failed.'}
 }
 It 'copies tracked module files but excludes arbitrary untracked credentials and scripts' {
  New-TrackedSource $source 'src/TokenForge/Public/Session.ps1'
  foreach($name in @('session.json','local.passkey','local.passkey.registered.json','unexpected.ps1')){
   [IO.File]::WriteAllText((Join-Path $source "src/TokenForge/$name"),'synthetic private state')
  }
  Copy-TokenForgePackageSource $source $destination src/TokenForge
  @(Get-ChildItem $destination -File -Recurse).Count | Should -Be 1
  Get-Content (Join-Path $destination 'src/TokenForge/Public/Session.ps1') | Should -Be 'synthetic source'
 }
 It 'preserves tracked manifests and includes only tracked Markdown documentation' {
  New-TrackedSource $source 'manifests/self-profile.json' '{}'
  New-TrackedSource $source 'docs/public.md'
  New-TrackedSource $source 'docs/report.json' '{}'
  [IO.File]::WriteAllText((Join-Path $source 'docs/private.md'),'synthetic private state')
  Copy-TokenForgePackageSource $source $destination manifests
  Copy-TokenForgePackageSource $source $destination docs
  @(Get-ChildItem $destination -File -Recurse).Count | Should -Be 2
  Test-Path (Join-Path $destination 'manifests/self-profile.json') | Should -BeTrue
  Test-Path (Join-Path $destination 'docs/public.md') | Should -BeTrue
 }
 It 'fails if tracked required source was removed locally' {
  New-TrackedSource $source 'src/TokenForge/TokenForge.psm1'
  Remove-Item (Join-Path $source 'src/TokenForge/TokenForge.psm1')
  {Copy-TokenForgePackageSource $source $destination src/TokenForge} | Should -Throw
 }
 It 'requires Git source provenance rather than copying an arbitrary source directory' {
  $plain=Join-Path $TestDrive ([guid]::NewGuid().ToString('N'))
  $null=New-Item -ItemType Directory $plain
  {Copy-TokenForgePackageSource $plain $destination src/TokenForge} | Should -Throw
 }
 It 'rejects tracked names with control characters instead of collapsing them to another file' -Skip:($IsWindows) {
  New-TrackedSource $source ("src/TokenForge/line"+[char]10+"break.ps1")
  [IO.File]::WriteAllText((Join-Path $source 'src/TokenForge/linebreak.ps1'),'synthetic private state')
  {Copy-TokenForgePackageSource $source $destination src/TokenForge} | Should -Throw '*Invalid package source*'
  @(Get-ChildItem $destination -File -Recurse).Count | Should -Be 0
 }
 It 'rejects source names that collide on case-insensitive platforms' -Skip:($IsWindows -or $IsMacOS) {
  New-TrackedSource $source 'src/TokenForge/Session.ps1'
  New-TrackedSource $source 'src/TokenForge/session.ps1'
  {Copy-TokenForgePackageSource $source $destination src/TokenForge} | Should -Throw '*Invalid package source*'
 }
 It 'rejects invalid UTF-8 filenames instead of copying an untracked replacement-character decoy' -Skip:($IsWindows) {
  $module=Join-Path $source 'src/TokenForge';$null=New-Item -ItemType Directory $module -Force
  $raw=[byte[]]([Text.Encoding]::UTF8.GetBytes("$module/")+@(255)+[Text.Encoding]::UTF8.GetBytes('.ps1')+@(0))
  $descriptor=if($IsMacOS){[TfPackageSourceUnix]::MacOpen($raw,513,384)}else{[TfPackageSourceUnix]::LinuxOpen($raw,65,384)}
  if($descriptor -lt 0){
   if($IsMacOS){Set-ItResult -Skipped -Because 'The macOS filesystem rejected the invalid UTF-8 filename fixture.';return}
   throw 'Raw filename fixture failed.'
  }
  if($IsMacOS){$null=[TfPackageSourceUnix]::MacClose($descriptor)}else{$null=[TfPackageSourceUnix]::LinuxClose($descriptor)}
  try{
   & git -C $source add --all
   if($LASTEXITCODE){throw 'Raw filename fixture tracking failed.'}
   [IO.File]::WriteAllText((Join-Path $module ([string][char]0xfffd+'.ps1')),'synthetic private decoy')
   {Copy-TokenForgePackageSource $source $destination src/TokenForge} | Should -Throw '*valid UTF-8*'
   @(Get-ChildItem $destination -File -Recurse).Count | Should -Be 0
  }finally{if($IsMacOS){$null=[TfPackageSourceUnix]::MacUnlink($raw)}else{$null=[TfPackageSourceUnix]::LinuxUnlink($raw)}}
 }
 It 'rejects a tracked source symlink' -Skip:($IsWindows) {
  $outside=Join-Path $TestDrive 'outside.txt';[IO.File]::WriteAllText($outside,'synthetic private state')
  $module=Join-Path $source 'src/TokenForge';$null=New-Item -ItemType Directory $module -Force
  $null=New-Item -ItemType SymbolicLink -Path (Join-Path $module 'linked.ps1') -Target $outside
  & git -C $source add -- src/TokenForge/linked.ps1
  {Copy-TokenForgePackageSource $source $destination src/TokenForge} | Should -Throw '*links*'
  @(Get-ChildItem $destination -File -Recurse).Count | Should -Be 0
 }
}
