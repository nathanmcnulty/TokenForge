BeforeAll {
 . "$PSScriptRoot/../scripts/TokenForgePublicationWriter.ps1"
 # Test-only plumbing. No remote URL, credentials or inherited Git configuration.
 function Invoke-LocalFixtureGit([string[]]$Arguments,[byte[]]$InputBytes=@()) {
  $start=[Diagnostics.ProcessStartInfo]::new('/usr/bin/git');$start.UseShellExecute=$false
  $start.RedirectStandardInput=$true;$start.RedirectStandardOutput=$true;$start.RedirectStandardError=$true
  $start.Environment.Clear();$start.Environment['PATH']='/usr/bin:/bin';$start.Environment['HOME']=$TestDrive
  $start.Environment['GIT_CONFIG_NOSYSTEM']='1';$start.Environment['GIT_CONFIG_GLOBAL']='/dev/null'
  $start.Environment['GIT_AUTHOR_DATE']='2026-10-23T12:00:00Z';$start.Environment['GIT_COMMITTER_DATE']='2026-10-23T12:00:00Z'
  foreach($a in @('-c','user.name=Synthetic','-c','user.email=fixture@example.invalid')+$Arguments){$start.ArgumentList.Add($a)}
  $process=[Diagnostics.Process]::Start($start);$output=[IO.MemoryStream]::new()
  try{
   $copy=$process.StandardOutput.BaseStream.CopyToAsync($output);$errorRead=$process.StandardError.ReadToEndAsync()
   $process.StandardInput.BaseStream.Write($InputBytes,0,$InputBytes.Length);$process.StandardInput.Close()
   if(-not $process.WaitForExit(10000)){$process.Kill($true);throw 'Local fixture Git exceeded deadline.'}
   $null=$copy.GetAwaiter().GetResult();$null=$errorRead.GetAwaiter().GetResult()
   if($output.Length -gt 2MB){throw 'Local fixture output bound.'}
   return @{Bytes=$output.ToArray();ExitCode=$process.ExitCode}
  }finally{if(-not $process.HasExited){$process.Kill($true)};$output.Dispose();$process.Dispose()}
 }
 function Get-LocalFixtureText([string[]]$Arguments,[string]$Text='') {
  $r=Invoke-LocalFixtureGit $Arguments ([Text.Encoding]::UTF8.GetBytes($Text))
  if($r.ExitCode -ne 0){throw 'Local fixture Git setup failed.'}
  [Text.Encoding]::UTF8.GetString($r.Bytes).Trim()
 }
}

Describe 'Actual local Git receive-pack exact-old protocol proof' {
 BeforeEach {
  $bare=Join-Path $TestDrive ([guid]::NewGuid().ToString('N'))
  $null=Get-LocalFixtureText @('init','--quiet','--bare','--template=',$bare)
  $tree=Get-LocalFixtureText @('--git-dir',$bare,'hash-object','-t','tree','-w','--stdin')
  $ancestor=Get-LocalFixtureText @('--git-dir',$bare,'commit-tree',$tree) "synthetic ancestor`n"
  $old=Get-LocalFixtureText @('--git-dir',$bare,'commit-tree',$tree,'-p',$ancestor) "synthetic old`n"
  $new=Get-LocalFixtureText @('--git-dir',$bare,'commit-tree',$tree,'-p',$old) "synthetic proposed`n"
  $null=Get-LocalFixtureText @('--git-dir',$bare,'update-ref','refs/heads/discovery-data',$old)
  $null=Get-LocalFixtureText @('--git-dir',$bare,'update-ref','refs/heads/proposal',$new)
 }
 It 'discovers the advertised exact ref and publishes an existing commit using only an empty pack' {
  $advert=Invoke-LocalFixtureGit @('receive-pack','--stateless-rpc','--advertise-refs',$bare)
  $httpBytes=[byte[]]((ConvertTo-TfGitPacket "# service=git-receive-pack`n")+[Text.Encoding]::ASCII.GetBytes('0000')+$advert.Bytes)
  Assert-TfGitAdvertisement $httpBytes 'refs/heads/discovery-data' $old
  $body=New-TfGitUpdate $old $new 'refs/heads/discovery-data'
  $result=Invoke-LocalFixtureGit @('receive-pack','--stateless-rpc',$bare) $body
  (Read-TfGitAcknowledgement $result.Bytes 'refs/heads/discovery-data')|Should -Be Accepted
  (Get-LocalFixtureText @('--git-dir',$bare,'rev-parse','refs/heads/discovery-data'))|Should -BeExactly $new
  $body.Length|Should -BeLessThan 256
 }
 It 'rejects an exact-old mismatch even when the proposed update would be a fast forward' {
  (Invoke-LocalFixtureGit @('--git-dir',$bare,'merge-base','--is-ancestor',$ancestor,$new)).ExitCode|Should -Be 0
  # Rewind to a real ancestor: an ordinary fast-forward could wrongly succeed here.
  $null=Get-LocalFixtureText @('--git-dir',$bare,'update-ref','refs/heads/discovery-data',$ancestor)
  $result=Invoke-LocalFixtureGit @('receive-pack','--stateless-rpc',$bare) (New-TfGitUpdate $old $new 'refs/heads/discovery-data')
  (Read-TfGitAcknowledgement $result.Bytes 'refs/heads/discovery-data')|Should -Be Rejected
  (Get-LocalFixtureText @('--git-dir',$bare,'rev-parse','refs/heads/discovery-data'))|Should -BeExactly $ancestor
 }
 It 'rejects branch disappearance instead of recreating a ref with an expected-old command' {
  $null=Get-LocalFixtureText @('--git-dir',$bare,'update-ref','-d','refs/heads/discovery-data')
  $result=Invoke-LocalFixtureGit @('receive-pack','--stateless-rpc',$bare) (New-TfGitUpdate $old $new 'refs/heads/discovery-data')
  (Read-TfGitAcknowledgement $result.Bytes 'refs/heads/discovery-data')|Should -Be Rejected
 }
 It 'fails closed when the proposed object is absent from the repository' {
  $result=Invoke-LocalFixtureGit @('receive-pack','--stateless-rpc',$bare) (New-TfGitUpdate $old ('9'*40) 'refs/heads/discovery-data')
  try{$ack=Read-TfGitAcknowledgement $result.Bytes 'refs/heads/discovery-data'}catch{$ack='Unknown'}
  $ack|Should -Not -Be Accepted
  (Get-LocalFixtureText @('--git-dir',$bare,'rev-parse','refs/heads/discovery-data'))|Should -BeExactly $old
 }
 It 'observes server hook rejection without changing the ref' {
  # Only this isolated test server runs this deliberately rejecting hook.
  $hook=Join-Path $bare hooks/pre-receive;$null=[IO.Directory]::CreateDirectory((Split-Path $hook))
  [IO.File]::WriteAllText($hook,"#!/bin/sh`nexit 1`n");[IO.File]::SetUnixFileMode($hook,[IO.UnixFileMode]448)
  $result=Invoke-LocalFixtureGit @('receive-pack','--stateless-rpc',$bare) (New-TfGitUpdate $old $new 'refs/heads/discovery-data')
  (Read-TfGitAcknowledgement $result.Bytes 'refs/heads/discovery-data')|Should -Be Rejected
  (Get-LocalFixtureText @('--git-dir',$bare,'rev-parse','refs/heads/discovery-data'))|Should -BeExactly $old
 }
}
