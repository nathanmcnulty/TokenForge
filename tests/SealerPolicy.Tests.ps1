BeforeAll {
 . "$PSScriptRoot/../scripts/TokenForgeSealerPolicy.ps1"
 $script:repoRoot=[IO.Path]::GetFullPath("$PSScriptRoot/..")
 function Invoke-FixtureGit([string]$Root,[string[]]$Arguments) {
  $s=[Diagnostics.ProcessStartInfo]::new('/usr/bin/git');$s.UseShellExecute=$false;$s.RedirectStandardOutput=$true;$s.RedirectStandardError=$true
  $s.Environment.Clear();$s.Environment['PATH']='/usr/bin:/bin';$s.Environment['HOME']='/nonexistent';$s.Environment['GIT_CONFIG_NOSYSTEM']='1';$s.Environment['GIT_CONFIG_GLOBAL']='/dev/null'
  foreach($a in @('-C',$Root,'-c','core.hooksPath=/dev/null','-c','user.name=Synthetic','-c','user.email=fixture@example.invalid')+$Arguments){$s.ArgumentList.Add($a)}
  $p=[Diagnostics.Process]::Start($s);try{$o=$p.StandardOutput.ReadToEndAsync();$e=$p.StandardError.ReadToEndAsync();if(-not $p.WaitForExit(10000) -or $p.ExitCode -ne 0){throw 'fixture git failed'};return $o.GetAwaiter().GetResult().Trim()}finally{$p.Dispose()}
 }
 function Save-FixtureCommit($Root) {
  $null=Invoke-FixtureGit $Root @('add','--all');$null=Invoke-FixtureGit $Root @('commit','--quiet','-m','Synthetic fixture');Invoke-FixtureGit $Root @('rev-parse','HEAD')
 }
 function Get-FixtureCaller([string]$Commit) {
  @'
on:
  workflow_dispatch:
permissions:
  contents: read
jobs:
  produce:
    runs-on: ubuntu-24.04
    outputs:
      candidate-artifact-id: ${{ steps.archive.outputs.artifact-id }}
    steps: []
  seal:
    needs: produce
    uses: nathanmcnulty/TokenForge/.github/workflows/tokenforge-sealer.yml@COMMIT
    permissions:
      contents: read
      actions: read
      id-token: write
      attestations: write
    with:
      artifact-id: ${{ needs.produce.outputs.candidate-artifact-id }}
'@.Replace('COMMIT',$Commit)+"`n"
 }
 function New-PolicyFixture([string]$Parent,[switch]$Active) {
  [IO.File]::SetUnixFileMode($Parent,[IO.UnixFileMode]448)
  $root=Join-Path $Parent ([guid]::NewGuid().ToString('N'));$null=New-Item $root -ItemType Directory
  $null=Invoke-FixtureGit $root @('init','--quiet','--template=')
  foreach($path in @('scripts/TokenForgeSealer.ps1','publication/tokenforge-sealer.template.yml','tests/fixtures/attestation/manifest.json','tests/fixtures/attestation/provisioned-root.jsonl')){
   $dest=Join-Path $root $path;$null=New-Item (Split-Path $dest) -ItemType Directory -Force;[IO.File]::Copy((Join-Path $repoRoot $path),$dest)
  }
  $a=Save-FixtureCommit $root
  $template=[IO.File]::ReadAllText((Join-Path $root publication/tokenforge-sealer.template.yml))
  $guard=if($Active){"`${{ github.event_name == 'workflow_dispatch' && github.ref == 'refs/heads/main' && github.repository == 'nathanmcnulty/TokenForge' }}"}else{'${{ false }}'}
  $null=New-Item (Join-Path $root .github/workflows) -ItemType Directory -Force
  [IO.File]::WriteAllText((Join-Path $root .github/workflows/tokenforge-sealer.yml),$template.Replace('@TOKENFORGE_CODE_COMMIT@',$a).Replace('@TOKENFORGE_SEAL_GUARD@',$guard))
  $b=Save-FixtureCommit $root
  [IO.File]::WriteAllText((Join-Path $root .github/workflows/discovery.yml),(Get-FixtureCaller $b))
  $c=Save-FixtureCommit $root
  $bindings=Join-Path $Parent ([guid]::NewGuid().ToString('N')+'.json')
  [IO.File]::WriteAllText($bindings,(@{RepositoryId='100';WorkflowId='20';ProducerIds=@('1');ReviewerIds=@('2');MaintainerIds=@('3');ReaderIds=@('4')}|ConvertTo-Json))
  [IO.File]::SetUnixFileMode($bindings,[IO.UnixFileMode]384)
  @{Root=$root;A=$a;B=$b;C=$c;Options=@{RepositoryPath=$root;SealerCommit=$b;ProducerCommit=$c;JournalRoot=(Join-Path $Parent custody);BindingsPath=$bindings}}
 }
}
Describe 'Strict reusable caller contract' {
 BeforeEach {$sha='a'*40;$caller=Get-FixtureCaller $sha}
 It 'recognizes a real immutable caller with isolated signing permissions' {Test-TfSealerCaller $caller $sha|Should -BeTrue}
 It 'rejects <Case>' -ForEach @(
  @{Case='block scalar spoof';Change='block'},@{Case='comment spoof';Change='comment'},@{Case='secrets inheritance';Change='secrets'},
  @{Case='caller-controlled artifact';Change='artifact'},@{Case='elevated global permissions';Change='global'},@{Case='unsigned caller permission';Change='permission'},
  @{Case='extra trigger';Change='trigger'},@{Case='duplicate key';Change='duplicate'},@{Case='YAML alias';Change='alias'},@{Case='other active signing job';Change='other'}
 ) {
  $bad=switch($Change){
   block {"on:`n  workflow_dispatch:`npermissions: {}`njobs:`n  worker:`n    run: |`n      uses: nathanmcnulty/TokenForge/.github/workflows/tokenforge-sealer.yml@$sha`n"}
   comment {$caller.Replace('    uses:','    # uses:')}
   secrets {$caller.Replace('    needs: produce',"    secrets: inherit`n    needs: produce")}
   artifact {$caller.Replace('${{ needs.produce.outputs.candidate-artifact-id }}','30')}
   global {$caller.Replace("permissions:`n  contents: read","permissions:`n  contents: write")}
   permission {$caller.Replace('attestations: write','attestations: read')}
   trigger {$caller.Replace('  workflow_dispatch:',"  push:`n  workflow_dispatch:")}
   duplicate {$caller.Replace('    needs: produce',"    needs: produce`n    needs: produce")}
   alias {$caller+"  alias: &a {x: value}`n  reused: *a`n"}
   other {$caller+"  attacker:`n    permissions: {id-token: write}`n"}
  }
  Test-TfSealerCaller $bad $sha|Should -BeFalse
 }
}
Describe 'Immutable local sealer policy planning' {
 BeforeEach {$f=New-PolicyFixture $TestDrive;$o=$f.Options}
 It 'emits a review plan with no runtime-valid nested policy' {
  $p=Get-TokenForgeSealerPolicyPlan @o
  $p.Operational|Should -BeFalse;$p.Quarantined|Should -BeTrue;$p.CallerPinsSealer|Should -BeTrue
  $p.ImplementationCommit|Should -BeExactly $f.A;$p.ProposedPolicy|Should -BeNullOrEmpty
  $p.BindingPreview.Kind|Should -BeExactly TokenForgeSealerBindingPreview
  {Assert-TfPublicationPolicy $p.BindingPreview}|Should -Throw
 }
 It 'lists missing real identities without inventing bindings' {
  $o.Remove('BindingsPath');$p=Get-TokenForgeSealerPolicyPlan @o
  $p.MissingBindings.Count|Should -Be 6;$p.ProposedPolicy|Should -BeNullOrEmpty;$p.BindingPreview|Should -BeNullOrEmpty
 }
 It 'refuses operational emission while quarantined' {{Get-TokenForgeSealerPolicyPlan @o -Operational}|Should -Throw}
 It 'requires independent actor role bindings' {
  $b=Get-Content $o.BindingsPath -Raw|ConvertFrom-Json -AsHashtable;$b.ReaderIds=@('1');[IO.File]::WriteAllText($o.BindingsPath,($b|ConvertTo-Json))
  {Get-TokenForgeSealerPolicyPlan @o}|Should -Throw
 }
 It 'rejects an extra active job in the immutable workflow' {
  [IO.File]::AppendAllText((Join-Path $f.Root .github/workflows/tokenforge-sealer.yml),"  extra:`n    runs-on: ubuntu-24.04`n")
  $o.SealerCommit=Save-FixtureCommit $f.Root
  {Get-TokenForgeSealerPolicyPlan @o}|Should -Throw
 }
 It 'rejects an extra trigger in the immutable workflow' {
  $path=Join-Path $f.Root .github/workflows/tokenforge-sealer.yml
  [IO.File]::WriteAllText($path,([IO.File]::ReadAllText($path).Replace('  workflow_call:',"  repository_dispatch:`n  workflow_call:")))
  $o.SealerCommit=Save-FixtureCommit $f.Root
  {Get-TokenForgeSealerPolicyPlan @o}|Should -Throw
 }
 It 'refuses missing source without invoking a configured promisor transport' {
  $marker=Join-Path $TestDrive invoked;$helper=Join-Path $TestDrive helper
  [IO.File]::WriteAllText($helper,"#!/bin/sh`ntouch '$marker'`nexit 1`n");[IO.File]::SetUnixFileMode($helper,[IO.UnixFileMode]448)
  $null=Invoke-FixtureGit $f.Root @('config','extensions.partialClone','origin')
  $null=Invoke-FixtureGit $f.Root @('config','remote.origin.promisor','true')
  $null=Invoke-FixtureGit $f.Root @('config','remote.origin.url',('ext::'+$helper))
  $null=Invoke-FixtureGit $f.Root @('config','protocol.ext.allow','always')
  {Read-TfSealerGitFile $f.Root ('f'*40) scripts/missing.ps1}|Should -Throw
  Test-Path $marker|Should -BeFalse
 }
}
Describe 'Synthetic activation boundary' {
 It 'emits the runtime schema only for explicitly requested fully bound active fixtures' {
  $f=New-PolicyFixture $TestDrive -Active;$o=$f.Options
  $p=Get-TokenForgeSealerPolicyPlan @o -Operational
  {Assert-TfPublicationPolicy $p}|Should -Not -Throw
 }
 It 'refuses an active workflow with a block-scalar fake caller' {
  $f=New-PolicyFixture $TestDrive -Active;$o=$f.Options
  [IO.File]::WriteAllText((Join-Path $f.Root .github/workflows/discovery.yml),"on:`n  workflow_dispatch:`npermissions: {}`njobs:`n  worker:`n    run: |`n      uses: nathanmcnulty/TokenForge/.github/workflows/tokenforge-sealer.yml@$($f.B)`n")
  $o.ProducerCommit=Save-FixtureCommit $f.Root
  (Get-TokenForgeSealerPolicyPlan @o).CallerPinsSealer|Should -BeFalse
  {Get-TokenForgeSealerPolicyPlan @o -Operational}|Should -Throw
 }
}
