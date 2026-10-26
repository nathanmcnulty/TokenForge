Describe 'Offline release readiness policy' {
 It 'retains only manual hosted entrypoints and quarantines the legacy discovery writer' {
  foreach($file in Get-ChildItem "$PSScriptRoot/../.github/workflows" -Filter '*.yml'){
   $text=Get-Content $file.FullName -Raw
   if($file.Name -ceq 'tokenforge-sealer.yml'){
    $pin=[regex]::Match($text,'(?m)^  TF_SEALER_CODE_COMMIT: ([a-f0-9]{40})$')
    $pin.Success|Should -BeTrue
    $template=Get-Content "$PSScriptRoot/../publication/tokenforge-sealer.template.yml" -Raw
    $text|Should -BeExactly ($template.Replace('@TOKENFORGE_CODE_COMMIT@',$pin.Groups[1].Value).Replace('@TOKENFORGE_SEAL_GUARD@','${{ false }}'))
   }else{
    $text|Should -Match '(?m)^on:\r?\n  workflow_dispatch:'
    $text|Should -Not -Match '(?m)^  workflow_call:'
   }
   ($text -split '(?m)^permissions:|^jobs:',2)[0]|Should -Not -Match '(?m)^  (push|pull_request|schedule|workflow_run):'
  }
  $discovery=Get-Content "$PSScriptRoot/../.github/workflows/discovery.yml" -Raw
  $discovery|Should -Match '(?s)\n  push:\n    needs:.*?\n    if: \$\{\{ false \}\}'
 }
 It 'ships current recovery guides and the standalone synthetic smoke with the native package' {
  $builder=Get-Content "$PSScriptRoot/../scripts/Build-TokenForgeNative.ps1" -Raw
  foreach($name in @('Get-TokenForgeCollectorStatus.ps1','Invoke-TokenForgeDiscoveryRun.ps1','Invoke-TokenForgeInventory.ps1','TokenForgeDiscoveryCandidate.ps1','Test-TokenForgeOfflinePackage.ps1','goal1-collector.md','goal1-export.md','goal2-change-reports.md','goal4-bounded-refresh.md','goal6-operator-runbook.md')){
   $builder|Should -Match ([regex]::Escape($name))
  }
 }
}
