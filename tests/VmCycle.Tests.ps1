BeforeAll {
 Import-Module "$PSScriptRoot/../src/TokenForge/TokenForge.psd1" -Force
 $cycleSource="$PSScriptRoot/../scripts/Invoke-TokenForgeDiscoveryRun.ps1"
 function Write-TfVmFixture($Path,$Value){$Value|ConvertTo-Json -Depth 30|Set-Content -LiteralPath $Path;if(-not $IsWindows){[IO.File]::SetUnixFileMode($Path,[IO.UnixFileMode]384)}}
 function Seal-TfVmFixture {
  $files=[ordered]@{}
  foreach($file in Get-ChildItem -LiteralPath $package -Recurse -File|Where-Object FullName -cne $manifest){$files[[IO.Path]::GetRelativePath($package,$file.FullName)]=@{sha256=(Get-FileHash $file.FullName).Hash.ToLowerInvariant();bytes=$file.Length}}
  Write-TfVmFixture $manifest @{schemaVersion=1;sourceRevision=('1'*40);files=$files}
  $options.PackageManifestSha256=(Get-FileHash $manifest).Hash.ToLowerInvariant()
 }
}
Describe 'Frozen bounded collector cycles' -Skip:(-not $IsLinux) {
 BeforeEach {
  $package=Join-Path $TestDrive ([guid]::NewGuid().ToString('N'))
  $null=New-Item -ItemType Directory (Join-Path $package scripts),(Join-Path $package src/TokenForge) -Force
  $runner=Join-Path $package scripts/Invoke-TokenForgeDiscoveryRun.ps1
  Copy-Item $cycleSource $runner
  'synthetic'|Set-Content (Join-Path $package tokenforge)
  'synthetic'|Set-Content (Join-Path $package src/TokenForge/TokenForge.psd1)
  'synthetic'|Set-Content (Join-Path $package src/TokenForge/TokenForge.psm1)
  $manifest=Join-Path $package public-health-package.json
  $state=Join-Path $TestDrive ([guid]::NewGuid().ToString('N'))
  $null=[IO.Directory]::CreateDirectory($state,[IO.UnixFileMode]448)
  $inventory=@{TenantFingerprint=('a'*64);PrincipalFingerprint=('b'*64);CapturedAt=[DateTimeOffset]::UtcNow.ToString('o')}
  Write-TfVmFixture (Join-Path $state inventory.json) $inventory
  Write-TfVmFixture (Join-Path $state discovery.json) @{}
  Write-TfVmFixture (Join-Path $state discovery-run.json) @{SchemaVersion=1;CohortId=('c'*64)}
  $cookie=ConvertTo-SecureString synthetic-session -AsPlainText -Force
  $options=@{FrozenCycle=$true;StatePath=$state;NativeExecutablePath=(Join-Path $package tokenforge);EstsAuth=$cookie;SessionExpiresAt=[DateTimeOffset]::UtcNow.AddMinutes(10);PackageManifestPath=$manifest;PackageSourceRevision=('1'*40)}
  Seal-TfVmFixture
  $claims=[pscustomobject]@{TenantFingerprint=('a'*64);PrincipalFingerprint=('b'*64);ClientId='14d82eec-204b-4c2f-b7e8-296a70dab67e';Audience='00000003-0000-0000-c000-000000000000';Scopes=@('User.Read','Application.Read.All')}
  Mock Import-Module {}
  Mock Get-TokenForgeToken {[pscustomobject]@{AccessToken=(ConvertTo-SecureString synthetic-access -AsPlainText -Force);TokenClaims=$claims}}
  Mock ConvertFrom-TokenForgeJwtPayload -ModuleName TokenForge {@{oid='synthetic'}}
  Mock Invoke-TokenForgeGraph -ModuleName TokenForge {@{id='synthetic'}}
  Mock Invoke-TokenForgeDiscoveryRun {[pscustomobject]@{Status='Complete';Reason='Complete';Clients=3;CompletedClients=3;PendingClients=0;CredentialOutput=$false}}
 }
 AfterEach {$cookie.Dispose()}
 It 'retains the exact cohort and inputs, records a sanitized receipt and forwards finite bounds' {
  $before=(Get-FileHash (Join-Path $state inventory.json)).Hash
  $r=& $runner @options|ConvertFrom-Json
  $r.Status|Should -Be Complete
  $receipt=Get-Content (Join-Path $state vm-cycle.json) -Raw|ConvertFrom-Json
  $receipt.CohortId|Should -Be ('c'*64)
  $receipt.PackageManifestSha256|Should -Be $options.PackageManifestSha256
  $receipt.Publication|Should -Be NotAttempted
  $receipt.CompletedClients|Should -Be 3
  $receipt.CredentialOutput|Should -BeFalse
  ($receipt|ConvertTo-Json -Depth 20)|Should -Not -Match 'synthetic-session|synthetic-access'
  (Get-FileHash (Join-Path $state inventory.json)).Hash|Should -Be $before
  Should -Invoke Invoke-TokenForgeDiscoveryRun -Times 1 -Exactly -ParameterFilter {$OperationBudget -and $OperationBudget.SessionExpiresAt -and $OperationBudget.StopFilePath.EndsWith('stop.requested') -and -not $NewRun -and -not $ResumePaused -and -not $RecoverUnknown}
 }
 It 'preserves terminal <Outcome> in the result and receipt with exit <ExitCode>' -ForEach @(
  @{Outcome='Complete';ExitCode=0},@{Outcome='StructurallyExcluded';ExitCode=0},@{Outcome='Failed';ExitCode=1}
 ) {
  Mock Invoke-TokenForgeDiscoveryRun {[pscustomobject]@{Status=$Outcome;Reason=$Outcome;Clients=3;CompletedClients=3;PendingClients=0;CredentialOutput=$false}}
  $result=& $runner @options|ConvertFrom-Json
  $LASTEXITCODE|Should -Be $ExitCode
  $result.Status|Should -Be $Outcome
  $result.Reason|Should -Be $Outcome
  $receipt=Get-Content (Join-Path $state vm-cycle.json) -Raw|ConvertFrom-Json
  $receipt.Status|Should -Be $Outcome
  $receipt.Reason|Should -Be $Outcome
 }
 It 'keeps unknown consumption above an otherwise structurally excluded terminal result' {
  Mock Invoke-TokenForgeDiscoveryRun {
   $OperationBudget.PendingRequest=$true
   [pscustomobject]@{Status='StructurallyExcluded';Reason='StructurallyExcluded';Clients=3;CompletedClients=3;PendingClients=0;CredentialOutput=$false}
  }
  $result=& $runner @options|ConvertFrom-Json
  $LASTEXITCODE|Should -Be 1
  $result.Status|Should -Be InFlightUnknown
  (Get-Content (Join-Path $state vm-cycle.json) -Raw|ConvertFrom-Json).Status|Should -Be InFlightUnknown
 }
 It 'refuses <Case> before authentication' -ForEach @(
  @{Case='stale inventory';Change='Stale'},@{Case='future inventory';Change='Future'},@{Case='missing inventory';Change='MissingInventory'},
  @{Case='missing cohort';Change='MissingCohort'},@{Case='conflicting refresh';Change='Refresh'},@{Case='new run';Change='NewRun'},
  @{Case='missing expiry';Change='Expiry'},@{Case='expired session';Change='Expired'},@{Case='stop marker';Change='Stop'},
  @{Case='manifest pin';Change='Pin'},@{Case='source pin';Change='Source'},@{Case='changed payload';Change='Payload'},@{Case='extra payload';Change='Extra'},@{Case='linked payload';Change='Link'},@{Case='traversal manifest';Change='Traversal'}
 ) {
  switch($Change){
   Stale {$inventory.CapturedAt=[DateTimeOffset]::UtcNow.AddDays(-2).ToString('o');Write-TfVmFixture (Join-Path $state inventory.json) $inventory}
   Future {$inventory.CapturedAt=[DateTimeOffset]::UtcNow.AddHours(1).ToString('o');Write-TfVmFixture (Join-Path $state inventory.json) $inventory}
   MissingInventory {Remove-Item (Join-Path $state inventory.json)}
   MissingCohort {Remove-Item (Join-Path $state discovery-run.json)}
   Refresh {$options.RefreshInventory=$true}
   NewRun {$options.NewRun=$true}
   Expiry {$options.Remove('SessionExpiresAt')}
   Expired {$options.SessionExpiresAt=[DateTimeOffset]::UtcNow.AddMinutes(-1)}
   Stop {Write-TfVmFixture (Join-Path $state stop.requested) @{}}
   Pin {$options.PackageManifestSha256='0'*64}
   Source {$options.PackageSourceRevision='2'*40}
   Payload {'changed'|Set-Content (Join-Path $package tokenforge)}
   Extra {'extra'|Set-Content (Join-Path $package unexpected)}
   Link {Remove-Item (Join-Path $package tokenforge);$null=New-Item -ItemType SymbolicLink -Path (Join-Path $package tokenforge) -Target $cycleSource}
   Traversal {$d=Get-Content $manifest -Raw|ConvertFrom-Json -AsHashtable;$d.files['../escape']=@{sha256=('a'*64);bytes=1};Write-TfVmFixture $manifest $d;$options.PackageManifestSha256=(Get-FileHash $manifest).Hash.ToLowerInvariant()}
  }
  $r=& $runner @options|ConvertFrom-Json
  $r.Status|Should -Not -Be Complete
  if($Change -eq 'Expired'){$r.Status|Should -Be SessionExpired}
  if($Change -eq 'Stop'){$r.Status|Should -Be Cancelled}
  Should -Invoke Get-TokenForgeToken -Times 0 -Exactly
  Should -Invoke Invoke-TokenForgeDiscoveryRun -Times 0 -Exactly
 }
 It 'restarts a bounded cycle using the same frozen cohort without creating new inputs' {
  Mock Invoke-TokenForgeDiscoveryRun {[pscustomobject]@{Status='BudgetReached';Reason='BudgetReached';Clients=3;CompletedClients=1;PendingClients=2;CredentialOutput=$false}}
  $first=& $runner @options|ConvertFrom-Json
  $first.Status|Should -Be BudgetReached
  $receipt1=Get-Content (Join-Path $state vm-cycle.json) -Raw|ConvertFrom-Json
  Mock Invoke-TokenForgeDiscoveryRun {[pscustomobject]@{Status='Complete';Reason='Complete';Clients=3;CompletedClients=3;PendingClients=0;CredentialOutput=$false}}
  (& $runner @options|ConvertFrom-Json).Status|Should -Be Complete
  $receipt2=Get-Content (Join-Path $state vm-cycle.json) -Raw|ConvertFrom-Json
  $receipt2.CohortId|Should -Be $receipt1.CohortId
  $receipt2.CycleId|Should -Not -Be $receipt1.CycleId
  $receipt2.CompletedClients|Should -Be 3
  Should -Invoke Invoke-TokenForgeDiscoveryRun -Times 2 -Exactly -ParameterFilter {-not $NewRun -and -not $ResumePaused -and -not $RecoverUnknown}
 }
 It 'retains unknown consumption over a coincident declared session expiry' {
  Mock Invoke-TokenForgeDiscoveryRun {
   $OperationBudget.PendingRequest=$true;$OperationBudget.StopReason='SessionExpired'
   [pscustomobject]@{Status='BudgetReached';Reason='BudgetReached';Clients=3;CompletedClients=1;PendingClients=2;CredentialOutput=$false}
  }
  (& $runner @options|ConvertFrom-Json).Status|Should -Be InFlightUnknown
  (Get-Content (Join-Path $state vm-cycle.json) -Raw|ConvertFrom-Json).Status|Should -Be InFlightUnknown
 }
 It 'retains a started bootstrap intent when the declared deadline interrupts acceptance' {
  Mock Get-TokenForgeToken {
   $OperationBudget.StopReason='SessionExpired'
   throw [Management.Automation.ErrorRecord]::new([InvalidOperationException]::new('private'), 'TokenForge.BudgetReached',[Management.Automation.ErrorCategory]::LimitsExceeded,$null)
  }
  (& $runner @options|ConvertFrom-Json).Status|Should -Be InFlightUnknown
  (Get-Content (Join-Path $state bootstrap-intent.json) -Raw|ConvertFrom-Json).State|Should -Be Started
  (Get-Content (Join-Path $state vm-cycle.json) -Raw|ConvertFrom-Json).Status|Should -Be InFlightUnknown
  Should -Invoke Invoke-TokenForgeDiscoveryRun -Times 0 -Exactly
 }
 It 'leaves a live lock holder receipt untouched and does not acquire a session' {
  Write-TfVmFixture (Join-Path $state vm-cycle.json) @{Status='Running';CycleId='old'}
  $before=(Get-FileHash (Join-Path $state vm-cycle.json)).Hash
  $lock=[TokenForge.Core.V0220.PrivateFiles]::Open((Join-Path $state '.discovery.lock'),$true)
  try{$null=& $runner @options}finally{$lock.Dispose()}
  (Get-FileHash (Join-Path $state vm-cycle.json)).Hash|Should -Be $before
  Should -Invoke Get-TokenForgeToken -Times 0 -Exactly
 }
 It 'preserves typed <Outcome> stops and does not automatically resume' -ForEach @(
  @{Outcome='SessionPaused';Expected='Paused'},@{Outcome='InFlightUnknown';Expected='InFlightUnknown'},@{Outcome='AccountMismatch';Expected='AccountMismatch'}
 ) {
  Mock Invoke-TokenForgeDiscoveryRun {throw [Management.Automation.ErrorRecord]::new([InvalidOperationException]::new('sensitive detail'),("TokenForge."+$Outcome),[Management.Automation.ErrorCategory]::InvalidOperation,$null)}
  $r=& $runner @options|ConvertFrom-Json
  $r.Status|Should -Be $Expected
  (Get-Content (Join-Path $state vm-cycle.json) -Raw|ConvertFrom-Json).Status|Should -Be $Expected
  Should -Invoke Invoke-TokenForgeDiscoveryRun -Times 1 -Exactly
  (Get-Content (Join-Path $state vm-cycle.json) -Raw)|Should -Not -Match 'sensitive detail'
 }
}
