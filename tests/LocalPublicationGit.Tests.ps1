BeforeAll {
 . "$PSScriptRoot/../scripts/TokenForgeLocalPublicationGit.ps1"
 function New-LocalGitTestFiles {
  $files=@{}
  foreach($name in @('coverage.json','flows.json','manifest.json','recipe.json','review.md','scopes.json','validation.json')){$files[$name]=[Text.Encoding]::UTF8.GetBytes("$name`n")}
  return $files
 }
 function New-LocalGitTestProposal([object[]]$Entries,[string]$BaseTree) {
  New-TfLocalGitProposal -Parent ('a'*40) -BaseTreeSha $BaseTree -BaseEntries $Entries -Files (New-LocalGitTestFiles) -CandidateHash ('b'*64) -UnixSeconds 42 -AuthorName 'Offline Test' -AuthorEmail 'offline@example.test'
 }
}
Describe 'Offline local Git proposal and canonical pack' {
 It 'is deterministic and preserves existing recursive paths, modes and object identities' {
  $blob=Get-TfLocalGitObject blob ([Text.Encoding]::UTF8.GetBytes('kept'))
  $inner=Get-TfLocalGitTree @([ordered]@{Name='tool';Mode='100755';Type='blob';Sha=$blob.Sha})
  $existing=Get-TfLocalGitTree @([ordered]@{Name='older';Mode='040000';Type='tree';Sha=$inner.Sha})
  $root=Get-TfLocalGitTree @([ordered]@{Name='candidates';Mode='040000';Type='tree';Sha=$existing.Sha})
  $base=@(
   [ordered]@{path='candidates';mode='040000';type='tree';sha=$existing.Sha},
   [ordered]@{path='candidates/older';mode='040000';type='tree';sha=$inner.Sha},
   [ordered]@{path='candidates/older/tool';mode='100755';type='blob';sha=$blob.Sha}
  )
  $p=New-LocalGitTestProposal $base $root.Sha
  $again=New-LocalGitTestProposal $base $root.Sha
  $p.PackSha256 | Should -BeExactly $again.PackSha256
  $p.ProposedCommit | Should -BeExactly $again.ProposedCommit
  @($p.Entries|Where-Object {$_.path -ceq 'candidates/older/tool' -and $_.mode -ceq '100755' -and $_.sha -ceq $blob.Sha}).Count | Should -Be 1
  @($p.Objects|Where-Object {$_.Sha -ceq $blob.Sha -or $_.Sha -ceq $inner.Sha}).Count | Should -Be 0
  (Assert-TfLocalGitPack -Bytes $p.Pack -Objects $p.Objects) | Should -BeTrue
  {New-LocalGitTestProposal (@($base)+@([ordered]@{path=('candidates/'+('b'*64));mode='040000';type='tree';sha=$inner.Sha})) $root.Sha} | Should -Throw
  $bad=@($base|ForEach-Object {[ordered]@{path=$_.path;mode=$_.mode;type=$_.type;sha=$_.sha}});$bad[-1].mode='040000'
  {New-LocalGitTestProposal $bad $root.Sha} | Should -Throw
  {New-TfLocalGitProposal -Parent ('a'*40) -BaseTreeSha $root.Sha -BaseEntries $base -Files (New-LocalGitTestFiles) -CandidateHash ('b'*64) -UnixSeconds 42 -AuthorName "Injected`nName" -AuthorEmail 'offline@example.test'} | Should -Throw
  $badPath=@($base|ForEach-Object {[ordered]@{path=$_.path;mode=$_.mode;type=$_.type;sha=$_.sha}});$badPath[-1].path='candidates/../tool'
  {New-LocalGitTestProposal $badPath $root.Sha} | Should -Throw
 }
 It 'rejects tampering, appended bytes and surplus objects' {
  $p=New-LocalGitTestProposal @() '4b825dc642cb6eb9a060e54bf8d69288fbee4904'
  $changed=[byte[]]$p.Pack.Clone();$changed[18]=$changed[18] -bxor 1
  {Assert-TfLocalGitPack -Bytes $changed -Objects $p.Objects} | Should -Throw
  {Assert-TfLocalGitPack -Bytes ([byte[]]($p.Pack+[byte[]]0)) -Objects $p.Objects} | Should -Throw
  $extra=Get-TfLocalGitObject blob ([Text.Encoding]::ASCII.GetBytes('surplus'))
  $larger=New-TfLocalGitPack @($p.Objects+$extra|Sort-Object Sha)
  {Assert-TfLocalGitPack -Bytes $larger -Objects $p.Objects} | Should -Throw
  {Assert-TfLocalGitPack -Bytes $larger -Objects @($p.Objects+$extra|Sort-Object Sha)} | Should -Throw
  $wrong=@($p.Objects|ForEach-Object {$_});$wrong[0]=Get-TfLocalGitObject blob ([Text.Encoding]::ASCII.GetBytes('wrong'))
  {Assert-TfLocalGitPack -Bytes $p.Pack -Objects $wrong} | Should -Throw
 }
 It 'round trips a stored zlib block boundary without changing the pack profile' {
  $files=New-LocalGitTestFiles;$files['coverage.json']=[byte[]]::new(65536)
  $p=New-TfLocalGitProposal -Parent ('a'*40) -BaseTreeSha '4b825dc642cb6eb9a060e54bf8d69288fbee4904' -BaseEntries @() -Files $files -CandidateHash ('b'*64) -UnixSeconds 42 -AuthorName 'Offline Test' -AuthorEmail 'offline@example.test'
  (Assert-TfLocalGitPack -Bytes $p.Pack -Objects $p.Objects) | Should -BeTrue
 }
 It 'imports the exact pack into a local bare Git repository and exposes all seven blobs' {
  $bare=Join-Path $TestDrive 'bare.git';$null=& git init --bare -q $bare
  $existingPath=Join-Path $TestDrive 'existing.bin';[IO.File]::WriteAllBytes($existingPath,[Text.Encoding]::ASCII.GetBytes('preserved'))
  $existingBlob=(& git -C $bare hash-object -w $existingPath).Trim()
  $existingTree=("100755 blob $existingBlob`ttool"|& git -C $bare mktree).Trim()
  $baseTree=("040000 tree $existingTree`tunchanged"|& git -C $bare mktree).Trim()
  $baseEntries=@(
   [ordered]@{path='unchanged';mode='040000';type='tree';sha=$existingTree},
   [ordered]@{path='unchanged/tool';mode='100755';type='blob';sha=$existingBlob}
  )
  $old=@{};foreach($key in @('GIT_AUTHOR_NAME','GIT_AUTHOR_EMAIL','GIT_COMMITTER_NAME','GIT_COMMITTER_EMAIL')){$old[$key]=[Environment]::GetEnvironmentVariable($key)}
  try {
   $env:GIT_AUTHOR_NAME='Offline Test';$env:GIT_AUTHOR_EMAIL='offline@example.test';$env:GIT_COMMITTER_NAME='Offline Test';$env:GIT_COMMITTER_EMAIL='offline@example.test'
   $parent=(& git -C $bare commit-tree $baseTree -m initial).Trim()
  }finally{foreach($key in $old.Keys){[Environment]::SetEnvironmentVariable($key,$old[$key])}}
  $files=New-LocalGitTestFiles
  $p=New-TfLocalGitProposal -Parent $parent -BaseTreeSha $baseTree -BaseEntries $baseEntries -Files $files -CandidateHash ('b'*64) -UnixSeconds 42 -AuthorName 'Offline Test' -AuthorEmail 'offline@example.test'
  $packPath=Join-Path $bare 'objects/pack/pack-offline.pack';[IO.File]::WriteAllBytes($packPath,$p.Pack)
  $null=& git -C $bare index-pack $packPath;$LASTEXITCODE | Should -Be 0
  ((& git -C $bare cat-file -p $p.ProposedCommit) -join "`n") | Should -Match ([regex]::Escape("parent $parent"))
  ((& git -C $bare ls-tree $p.ProposedCommit unchanged) -join "`n") | Should -Match ([regex]::Escape($existingTree))
  @($p.Objects|Where-Object {$_.Sha -ceq $existingBlob -or $_.Sha -ceq $existingTree}).Count | Should -Be 0
  foreach($name in $files.Keys){
   $path="candidates/$('b'*64)/$name"
   $actual=(& git -C $bare rev-parse "$($p.ProposedCommit):$path").Trim()
   $expected=(Get-TfLocalGitObject blob $files[$name]).Sha
   $actual | Should -BeExactly $expected
  }
 }
}
