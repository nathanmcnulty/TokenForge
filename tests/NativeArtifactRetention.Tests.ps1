BeforeAll {
 $tokens=$null;$errors=$null
 $ast=[System.Management.Automation.Language.Parser]::ParseFile("$PSScriptRoot/../scripts/Remove-TokenForgeNativeArtifacts.ps1",[ref]$tokens,[ref]$errors)
 $function=$ast.Find({param($node)$node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'Select-TfSupersededNativeArtifacts'},$true)
 Invoke-Expression $function.Extent.Text
 function New-Artifact($Id,$Name,$Run,$Branch,$Date){[pscustomobject]@{id=$Id;name=$Name;created_at=$Date;expired=$false;size_in_bytes=100;workflow_run=[pscustomobject]@{id=$Run;head_branch=$Branch}}}
}
Describe 'Native artifact retention boundaries' {
 BeforeEach {
  $artifacts=@(
   (New-Artifact 1 tokenforge-linux-x64 101 main '2026-10-07T10:00:00Z'),
   (New-Artifact 2 tokenforge-win-x64 101 main '2026-10-07T10:00:00Z'),
   (New-Artifact 3 tokenforge-osx-arm64 101 main '2026-10-07T10:00:00Z'),
   (New-Artifact 9 tokenforge-win-x64 102 main '2026-10-07T11:00:00Z'),
   (New-Artifact 10 tokenforge-osx-arm64 102 main '2026-10-07T11:00:00Z'),
   (New-Artifact 4 tokenforge-linux-x64 102 main '2026-10-07T11:00:00Z'),
   (New-Artifact 5 tokenforge-linux-x64 103 feature '2026-10-07T09:00:00Z'),
   (New-Artifact 6 maintenance-snapshot-v1 104 main '2026-10-07T12:00:00Z'),
   (New-Artifact 7 checkpoint-public-plan-0 104 main '2026-10-07T12:00:00Z'),
   (New-Artifact 8 tokenforge-linux-x64 104 main '2026-10-07T12:00:00Z')
  )
  $runs=@{};foreach($id in '101','102','103','104'){$runs[$id]=@{WorkflowId=$(if($id -eq '104'){99L}else{42L});Status='completed';Conclusion='success'}}
 }
 It 'keeps latest main packages while excluding encrypted and other-workflow artifacts' {
  $selected=@(Select-TfSupersededNativeArtifacts $artifacts 42 $runs)
  (@($selected.id|Sort-Object) -join ',')|Should -Be '1,2,3,5'
 }
 It 'refuses deletion when a supported main package is missing' {
  {Select-TfSupersededNativeArtifacts @($artifacts|Where-Object name -CNE tokenforge-osx-arm64) 42 $runs}|Should -Throw '*no artifacts*'
 }
 It 'preserves an unfinished newer build and keeps a coherent successful build' {
  $runs['102'].Status='in_progress'
  (@((Select-TfSupersededNativeArtifacts $artifacts 42 $runs).id) -join ',')|Should -Be '5'
 }
 It 'accepts the current build after its native matrix has succeeded' {
  $runs['102'].Status='in_progress'
  (@((Select-TfSupersededNativeArtifacts $artifacts 42 $runs 102).id|Sort-Object) -join ',')|Should -Be '1,2,3,5'
 }
 It 'fails before deletion when current build artifacts are incomplete' {
  {Select-TfSupersededNativeArtifacts @($artifacts|Where-Object id -ne 10) 42 $runs 102}|Should -Throw '*no artifacts*'
 }
 It 'keeps a newer successful build when an older cleanup starts late' {
  (@((Select-TfSupersededNativeArtifacts $artifacts 42 $runs 101).id|Sort-Object) -join ',')|Should -Be '1,2,3,5'
 }
 It 'leaves newer failed packages until retention expires or a later build supersedes them' {
  $artifacts += New-Artifact 11 tokenforge-linux-x64 105 main '2026-10-07T13:00:00Z'
  $runs['105']=@{WorkflowId=42L;Status='completed';Conclusion='failure'}
  (Select-TfSupersededNativeArtifacts $artifacts 42 $runs).id|Should -Not -Contain 11
 }
 It 'never selects an artifact whose workflow provenance is unavailable' {
  $runs.Remove('103')
  (@((Select-TfSupersededNativeArtifacts $artifacts 42 $runs).id|Sort-Object) -join ',')|Should -Be '1,2,3'
 }
}
