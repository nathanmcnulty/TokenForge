BeforeAll {
 Import-Module "$PSScriptRoot/../src/TokenForge/TokenForge.psd1" -Force
 $runner="$PSScriptRoot/../scripts/Invoke-TokenForgeVmCycle.ps1"
}
Describe 'Offline Linux VM operational cycle' -Skip:(-not $IsLinux) {
 BeforeEach {
  $state=Join-Path $TestDrive ([guid]::NewGuid().ToString())
  $null=New-Item -ItemType Directory $state
  [IO.File]::SetUnixFileMode($state,[IO.UnixFileMode]448)
  $native=Join-Path $state 'synthetic-native'
  foreach($entry in @(@{Name='inventory.json';Text=('{"Applications":[],"CapturedAt":"'+[DateTimeOffset]::UtcNow.ToString('o')+'"}')},@{Name='discovery-run.json';Text=('{"SchemaVersion":1,"CohortId":"'+('c'*64)+'"}')},@{Name='synthetic-native';Text='offline fixture, never executed'})){
   $path=Join-Path $state $entry.Name
   [IO.File]::WriteAllText($path,$entry.Text)
   [IO.File]::SetUnixFileMode($path,[IO.UnixFileMode]384)
  }
  $cookie=ConvertTo-SecureString synthetic-private-session -AsPlainText -Force
  $options=@{StatePath=$state;NativeExecutablePath=$native;NativeSha256=(Get-FileHash $native).Hash.ToLowerInvariant();EstsAuth=$cookie;SessionExpiresAt=[DateTimeOffset]::UtcNow.AddHours(1)}
  Mock Import-Module {}
  Mock Invoke-TokenForgeDiscoveryRun {[pscustomobject]@{CohortId=('c'*64);Status='BudgetReached';Clients=3;CompletedClients=1;PendingClients=2}}
 }
 AfterEach {$cookie.Dispose()}
 It 'records a bounded resumable result and never claims publication' {
  $r=& $runner @options|ConvertFrom-Json
  $r.Status|Should -Be BudgetReached
  $r.Publication|Should -Be NotAttempted
  $r.CompletedClients|Should -Be 1
  $saved=Get-Content (Join-Path $state 'vm-cycle.json') -Raw
  $saved|Should -Not -Match 'synthetic-private-session'
  ($saved|ConvertFrom-Json).CycleId|Should -Be $r.CycleId
  ([int][IO.File]::GetUnixFileMode((Join-Path $state 'vm-cycle.json')) -band 63)|Should -Be 0
  $cookie.Length|Should -BeGreaterThan 0
  Should -Invoke Invoke-TokenForgeDiscoveryRun -Times 1 -Exactly -ParameterFilter {$MaxChunks -eq 1 -and $MaxMinutes -eq 15 -and -not $NewRun -and $SessionExpiresAt -eq $options.SessionExpiresAt}
 }
 It 'stops stale frozen inventory before collection without replacing its contents' {
  $path=Join-Path $state 'inventory.json'
  $expired='{"Applications":[],"CapturedAt":"'+[DateTimeOffset]::UtcNow.AddHours(-25).ToString('o')+'"}'
  [IO.File]::WriteAllText($path,$expired)
  (& $runner @options|ConvertFrom-Json).Reason|Should -Be InventoryStale
  (Get-Content $path -Raw)|Should -Be $expired
  (Get-Content (Join-Path $state 'vm-cycle.json') -Raw|ConvertFrom-Json).Reason|Should -Be InventoryStale
  Should -Invoke Invoke-TokenForgeDiscoveryRun -Times 0 -Exactly
 }
 It 'refuses changed package bytes before collection' {
  $options.NativeSha256='0'*64
  (& $runner @options|ConvertFrom-Json).Reason|Should -Be Configuration
  Should -Invoke Invoke-TokenForgeDiscoveryRun -Times 0 -Exactly
 }
 It 'requires a prepared frozen run before collection' {
  Remove-Item (Join-Path $state 'discovery-run.json')
  (& $runner @options|ConvertFrom-Json).Reason|Should -Be Configuration
  Should -Invoke Invoke-TokenForgeDiscoveryRun -Times 0 -Exactly
 }
 It 'refuses concurrent cycles without overwriting the active receipt' {
  $lock=[TokenForge.Core.V0220.PrivateFiles]::Open((Join-Path $state '.discovery.lock'),$true)
  try{
   (& $runner @options|ConvertFrom-Json).Reason|Should -Be Busy
   Test-Path (Join-Path $state 'vm-cycle.json')|Should -BeFalse
   Should -Invoke Invoke-TokenForgeDiscoveryRun -Times 0 -Exactly
  }finally{$lock.Dispose()}
  (& $runner @options|ConvertFrom-Json).Status|Should -Be BudgetReached
 }
 It 'sanitizes errors, retains checkpoints, and releases the cycle lock' {
  Mock Invoke-TokenForgeDiscoveryRun {throw 'synthetic-private-session'}
  $raw=& $runner @options
  $raw|Should -Not -Match 'synthetic-private-session'
  ($raw|ConvertFrom-Json).Reason|Should -Be CollectionFailed
  (Get-Content (Join-Path $state 'vm-cycle.json') -Raw|ConvertFrom-Json).Status|Should -Be Stopped
  Mock Invoke-TokenForgeDiscoveryRun {[pscustomobject]@{CohortId=('c'*64);Status='Complete';Clients=3;CompletedClients=3;PendingClients=0}}
  (& $runner @options|ConvertFrom-Json).Status|Should -Be Complete
 }
 It 'rejects a collector result belonging to another cohort' {
  Mock Invoke-TokenForgeDiscoveryRun {[pscustomobject]@{CohortId=('e'*64);Status='Complete';Clients=3;CompletedClients=3;PendingClients=0}}
  (& $runner @options|ConvertFrom-Json).Reason|Should -Be CollectionFailed
  (Get-Content (Join-Path $state 'vm-cycle.json') -Raw|ConvertFrom-Json).Status|Should -Be Stopped
 }
 It 'records session expiry as a stop requiring operator renewal' {
  Mock Invoke-TokenForgeDiscoveryRun {[pscustomobject]@{CohortId=('c'*64);Status='SessionExpired';Clients=3;CompletedClients=1;PendingClients=2}}
  (& $runner @options|ConvertFrom-Json).Status|Should -Be SessionExpired
  $LASTEXITCODE|Should -Be 2
  Should -Invoke Invoke-TokenForgeDiscoveryRun -Times 1 -Exactly
 }
}

Describe 'Abrupt process interruption and restart with synthetic checkpoints' -Skip:(-not $IsLinux) {
 It 'releases OS locks after kill and resumes without repeating a completed synthetic request' {
  $state=Join-Path $TestDrive ([guid]::NewGuid().ToString())
  $null=New-Item -ItemType Directory $state
  [IO.File]::SetUnixFileMode($state,[IO.UnixFileMode]448)
  $files=@{
   'inventory.json'='{"CapturedAt":"'+[DateTimeOffset]::UtcNow.ToString('o')+'","TenantFingerprint":"'+('a'*64)+'","PrincipalFingerprint":"'+('b'*64)+'","DiscoveryCatalogHash":"'+('d'*64)+'","Applications":[]}'
   'discovery-run.json'='{"SchemaVersion":1,"CohortId":"'+('c'*64)+'"}'
   'synthetic-native'='never executed'
   'pending'='3'
  }
  foreach($name in $files.Keys){$p=Join-Path $state $name;[IO.File]::WriteAllText($p,$files[$name]);[IO.File]::SetUnixFileMode($p,[IO.UnixFileMode]384)}
  $info=[Diagnostics.ProcessStartInfo]::new((Join-Path $PSHOME 'pwsh'))
  $info.UseShellExecute=$false;$info.RedirectStandardOutput=$true;$info.RedirectStandardError=$true
  foreach($arg in @('-NoProfile','-File',"$PSScriptRoot/fixtures/vm-cycle/InterruptedCycle.ps1",'-Repository',([IO.Path]::GetFullPath("$PSScriptRoot/..")),'-State',$state,'-Interrupt')){$info.ArgumentList.Add($arg)}
  $first=[Diagnostics.Process]::Start($info)
  try{
   $timer=[Diagnostics.Stopwatch]::StartNew()
   while(-not (Test-Path (Join-Path $state 'checkpoint-written')) -and -not $first.HasExited -and $timer.Elapsed.TotalSeconds -lt 30){Start-Sleep -Milliseconds 100}
   Test-Path (Join-Path $state 'checkpoint-written')|Should -BeTrue
   (Get-Content (Join-Path $state 'vm-cycle.json') -Raw|ConvertFrom-Json).Status|Should -Be Running
  }finally{if(-not $first.HasExited){$first.Kill($true)};$first.WaitForExit();$first.Dispose()}
  # No PID-based lock removal and no manual checkpoint edits.
  $info.ArgumentList.RemoveAt($info.ArgumentList.Count-1)
  $second=[Diagnostics.Process]::Start($info)
  try{
   $second.WaitForExit(30000)|Should -BeTrue
   $second.ExitCode|Should -Be 0
   $result=$second.StandardOutput.ReadToEnd()|ConvertFrom-Json
   $result.Status|Should -Be Complete
   $result.CompletedClients|Should -Be 3
   @(Get-Content (Join-Path $state 'attempts'))|Should -Be @('3','2','1')
  }finally{if(-not $second.HasExited){$second.Kill($true)};$second.Dispose()}
 }
}
