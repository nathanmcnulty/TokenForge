BeforeDiscovery {$nativeAvailable=[bool]($env:TOKENFORGE_TEST_NATIVE -and (Test-Path -LiteralPath $env:TOKENFORGE_TEST_NATIVE))}
Describe 'Native scope explanation without authentication or PowerShell' -Skip:(-not $nativeAvailable) {
 BeforeAll {
  Import-Module "$PSScriptRoot/../src/TokenForge/TokenForge.psd1" -Force
  function Invoke-NativeScope([string[]]$Arguments,[int]$ExitCode=0){
   $start=[Diagnostics.ProcessStartInfo]::new($env:TOKENFORGE_TEST_NATIVE)
   $start.UseShellExecute=$false;$start.RedirectStandardOutput=$true;$start.RedirectStandardError=$true
   $start.Environment['PATH']=Join-Path $root no-pwsh
   foreach($arg in @('scopes','explain','--profile','lab','--root',$root)+$Arguments){$start.ArgumentList.Add($arg)}
   $process=[Diagnostics.Process]::Start($start)
   try{
    $output=$process.StandardOutput.ReadToEndAsync();$errorText=$process.StandardError.ReadToEndAsync()
    if(-not $process.WaitForExit(20000)){$process.Kill($true);throw 'Scope explanation timed out.'}
    $process.ExitCode|Should -Be $ExitCode
    if($ExitCode){$output.GetAwaiter().GetResult()|Should -BeNullOrEmpty;$errorText.GetAwaiter().GetResult()|Should -Not -Match 'synthetic-private';return}
    $errorText.GetAwaiter().GetResult()|Should -BeNullOrEmpty;$output.GetAwaiter().GetResult().Trim()
   }finally{$process.Dispose()}
  }
 }
 BeforeEach {
  $root=Join-Path $TestDrive ([guid]::NewGuid().ToString('N'));if($IsMacOS){$root=$root -replace '^/var/','/private/var/'}
  $p=New-TokenForgeProfile lab example.onmicrosoft.com -Root $root -Storage Passphrase
  $path=Join-Path $root lab/profile.json;$config=Get-Content $path -Raw|ConvertFrom-Json -AsHashtable
  $config.ExpectedTenantFingerprint='a'*64;$config.ExpectedPrincipalFingerprint='b'*64
  [IO.File]::WriteAllText($path,($config|ConvertTo-Json -Depth 6))
  $graph='00000003-0000-0000-c000-000000000000';$client='11111111-1111-1111-1111-111111111111'
  $app=[pscustomobject]@{AppId=$client;Name='Synthetic';Registration='Present';Ownership='VerifiedMicrosoftOwner';AccountEnabled=$true;RedirectUris=@('http://localhost');PublishedGrants=@([pscustomobject]@{ResourceId=$graph;Scopes=@('User.Read')});Cookie='synthetic-private-cookie'}
  $resource=$app.PSObject.Copy();$resource.AppId=$graph;$resource.PublishedGrants=@()
  $inventory=[pscustomobject]@{CapturedAt=[DateTimeOffset]::UtcNow.ToString('o');TenantFingerprint=('a'*64);GrantEnumeration='Complete';Applications=@($app,$resource);TenantGrants=@()}
  $db=New-TokenForgeScopeDatabase;$db.Observations=@([pscustomobject]@{ClientId=$client;ResourceId=$graph;TenantFingerprint=('a'*64);PrincipalFingerprint=('b'*64);ObservedAt=[DateTimeOffset]::UtcNow.ToString('o');Outcome='Succeeded';NamespaceVerification='Matched';RequestVerification='Matched';ScpScopes=@('User.Read');RequestedScopes=@('User.Read');Protocol='OAuth2V2Pkce';AccessToken='synthetic-private-token'})
  $inventoryPath=Join-Path $p.StatePath inventory.json;$databasePath=Join-Path $p.StatePath scopes.json
  & (Get-Module TokenForge) {param($i,$d,$ip,$dp)Save-TokenForgeDocument $i $ip;Save-TokenForgeDocument $d $dp} $inventory $db $inventoryPath $databasePath
 }
 It 'matches module JSON planning without PowerShell and writes no files' {
  $before=@{};Get-ChildItem $root -Recurse -File -Force|ForEach-Object {$before[$_.FullName]=(Get-FileHash $_.FullName).Hash}
  $actual=Invoke-NativeScope @('--scope','User.Read','--json')
  $expected=Get-TokenForgeScopeCandidates -Inventory $inventory -Database $db -ResourceId $graph -Scope User.Read -PrincipalFingerprint ('b'*64)|ConvertTo-Json -Depth 12 -Compress -AsArray
  ([Text.Json.Nodes.JsonNode]::Parse($actual).ToJsonString())|Should -Be ([Text.Json.Nodes.JsonNode]::Parse($expected).ToJsonString())
  $actual|Should -Not -Match 'synthetic-private|TenantFingerprint|PrincipalFingerprint|AccessToken|Cookie'
  @(Get-ChildItem $root -Recurse -File -Force).Count|Should -Be $before.Count
  foreach($file in $before.Keys){(Get-FileHash $file).Hash|Should -Be $before[$file]}
  Test-Path (Join-Path $root lab/session.tfvault)|Should -BeFalse
 }
 It 'reads a SQLite history through the native evidence store with the same scope evidence' {
  $db.Observations[0].PSObject.Properties.Remove('AccessToken')
  & (Get-Module TokenForge) {param($d,$dp)Save-TokenForgeDocument $d $dp} $db $databasePath
  $sqlite=Join-Path $p.StatePath scopes.sqlite
  $null=Import-TokenForgeScopeDatabase -Path $sqlite -InputPath $databasePath -NativeExecutablePath $env:TOKENFORGE_TEST_NATIVE
  $before=(Get-FileHash $sqlite).Hash
  $row=(Invoke-NativeScope @('--scope','User.Read')|ConvertFrom-Json)
  $row.CandidateRank|Should -Be 0;$row.ObservationStatus|Should -Be FreshCoverage
  (Get-FileHash $sqlite).Hash|Should -Be $before
 }
 It 'explains published hints without history and without creating it' {
  Remove-Item $databasePath
  $row=Invoke-NativeScope @('--scope','User.Read')|ConvertFrom-Json
  $row.ObservationStatus|Should -Be NotObserved
  $row.PublishedScopes|Should -Contain 'User.Read'
  Test-Path $databasePath|Should -BeFalse;Test-Path (Join-Path $p.StatePath scopes.sqlite)|Should -BeFalse

  # The same missing-history path also supports a custom resource GUID.
  $custom='22222222-2222-2222-2222-222222222222'
  $inventory.Applications[0].PublishedGrants[0].ResourceId=$custom
  $inventory.Applications[1].AppId=$custom
  & (Get-Module TokenForge) {param($i,$ip)Save-TokenForgeDocument $i $ip} $inventory $inventoryPath
  $row=Invoke-NativeScope @('--resource',$custom,'--scope','User.Read')|ConvertFrom-Json
  $row.ResourceId|Should -Be $custom;$row.ObservationStatus|Should -Be NotObserved
  $row.ResourceEligible|Should -BeTrue
  foreach($bad in @('https://example.test','00000000-0000-0000-0000-000000000000','invalid')){Invoke-NativeScope @('--resource',$bad,'--scope','User.Read') 1}
 }
 It 'rejects malformed history and unsafe paths rather than treating them as absent' {
  [IO.File]::WriteAllText($databasePath,'{"SchemaVersion":1,"Observations":[],"observations":[],"AccessToken":"synthetic-private-token"}')
  Invoke-NativeScope @('--scope','User.Read') 1
  Remove-Item $databasePath
  foreach($candidate in @($databasePath,(Join-Path $p.StatePath scopes.sqlite))){
   $null=New-Item -ItemType Directory -Path $candidate
   try{Invoke-NativeScope @('--scope','User.Read') 1}finally{Remove-Item $candidate}
   if(-not $IsWindows){
    $null=New-Item -ItemType SymbolicLink -Path $candidate -Target (Join-Path $p.StatePath missing-history)
    try{Invoke-NativeScope @('--scope','User.Read') 1}finally{Remove-Item $candidate}
   }
  }
 }
 It 'accepts legacy UTF8 BOM metadata without relaxing validation' {
  $text=Get-Content $inventoryPath -Raw
  [IO.File]::WriteAllText($inventoryPath,$text,[Text.UTF8Encoding]::new($true))
  ((Invoke-NativeScope @('--scope','User.Read')|ConvertFrom-Json).CandidateRank)|Should -Be 0
 }
 It 'rejects wrong-tenant inventory before presenting account-specific evidence' {
  $inventory.TenantFingerprint='c'*64
  & (Get-Module TokenForge) {param($i,$ip)Save-TokenForgeDocument $i $ip} $inventory $inventoryPath
  Invoke-NativeScope @('--scope','User.Read') 1
 }
 It 'rejects auth options, duplicate options, empty scopes and broad scopes' {
  foreach($case in @(@('--scope','User.Read','--prompt-passphrase'),@('--scope','User.Read','--scope','Mail.Read'),@('--scope','User.Read,'),@('--scope','.default'),@('--scope','offline_access'))){Invoke-NativeScope $case 1}
 }
}
