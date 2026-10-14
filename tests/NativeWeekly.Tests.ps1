BeforeDiscovery {
 $nativeAvailable=[bool]($env:TOKENFORGE_TEST_NATIVE -and (Test-Path -LiteralPath $env:TOKENFORGE_TEST_NATIVE -PathType Leaf))
}
Describe 'Native offline weekly reports without PowerShell' -Skip:(-not $nativeAvailable) {
 BeforeAll {
  . "$PSScriptRoot/../scripts/TokenForgeCiState.ps1"
  Import-Module "$PSScriptRoot/../src/TokenForge/TokenForge.psd1" -Force
  $catalog=Get-TokenForgeCatalog -Path "$PSScriptRoot/fixtures/catalog.json"
  $catalog.Source='https://raw.githubusercontent.com/example/public/main/scopes.json'
  $discovery=Get-TokenForgeDiscovery -Catalog $catalog|ConvertTo-Json -Depth 100|ConvertFrom-Json -AsHashtable
  function Invoke-Weekly([string[]]$Options=@(),[int]$Exit=0) {
   $start=[Diagnostics.ProcessStartInfo]::new($env:TOKENFORGE_TEST_NATIVE)
   $start.UseShellExecute=$false;$start.RedirectStandardOutput=$true;$start.RedirectStandardError=$true
   $start.Environment['PATH']=Join-Path $root no-powershell
   foreach($arg in (@('research','weekly','--state-path',$root,'--json')+$Options)){$start.ArgumentList.Add($arg)}
   $p=[Diagnostics.Process]::Start($start)
   try{
    $stdout=$p.StandardOutput.ReadToEndAsync();$stderr=$p.StandardError.ReadToEndAsync()
    if(-not $p.WaitForExit(30000)){$p.Kill($true);throw 'Weekly fixture timed out.'}
    $p.ExitCode|Should -Be $Exit
    $output=$stdout.GetAwaiter().GetResult();$errorText=$stderr.GetAwaiter().GetResult()
    if($Exit){$output|Should -BeNullOrEmpty;$errorText|Should -Not -Match 'synthetic-private';($errorText|ConvertFrom-Json).Code|Should -Be OperationFailed}
    else{$errorText|Should -BeNullOrEmpty;$output|ConvertFrom-Json}
   }finally{$p.Dispose()}
  }
 }
 BeforeEach {
  $root=Join-Path $TestDrive ([guid]::NewGuid().ToString());$null=New-Item -ItemType Directory $root
  $state=New-TfCiState $discovery -Mode Deep -ResourceId @('00000003-0000-0000-c000-000000000000','797f4846-ba00-4fd7-ba43-dac1f8f63013')
  ConvertTo-Json -InputObject $state -Depth 100|Set-Content "$root/weekly-deep.json"
 }
 It 'reads public recipe files without private ACL requirements or writes' {
  $before=(Get-FileHash "$root/weekly-deep.json").Hash
  $r=Invoke-Weekly
  $r.Reports[0].PlanId|Should -BeExactly $state.PlanId
  $r.Reports[0].RemainingPairs|Should -Be ($state.Recipe.AppIds.Count*2)
  $r.CredentialOutput|Should -BeFalse
  (Get-FileHash "$root/weekly-deep.json").Hash|Should -BeExactly $before
  @(Get-ChildItem $root -Force).Count|Should -Be 1
 }
 It 'rejects authentication options before any adapter can run' {Invoke-Weekly @('--interactive') 1}
 It 'rejects duplicate options' {Invoke-Weekly @('--json') 1}
 It 'rejects a changed plan hash' {
  $state.PlanId='a'*64;ConvertTo-Json -InputObject $state -Depth 100|Set-Content "$root/weekly-deep.json"
  Invoke-Weekly @() 1
 }
 It 'rejects unknown private recipe fields' {
  $state.Recipe.AccessToken='synthetic-private';ConvertTo-Json -InputObject $state -Depth 100|Set-Content "$root/weekly-deep.json"
  Invoke-Weekly @() 1
 }
 It 'rejects dangling recipe links' -Skip:($IsWindows) {
  Remove-Item "$root/weekly-deep.json";$null=New-Item -ItemType SymbolicLink -Path "$root/weekly-deep.json" -Target "$root/missing.json"
  Invoke-Weekly @() 1
 }
 It 'rejects empty recipe sets' {Remove-Item "$root/weekly-deep.json";Invoke-Weekly @() 1}
}
