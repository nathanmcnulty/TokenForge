BeforeAll {
 # These tests load only PowerShell helpers: no credential source, native package or network.
 . "$PSScriptRoot/../src/TokenForge/Private/OperationBudget.ps1"
 . "$PSScriptRoot/../src/TokenForge/Private/Graph.ps1"
 . "$PSScriptRoot/../src/TokenForge/Private/Vault.ps1"
 . "$PSScriptRoot/../src/TokenForge/Public/Discovery.ps1"
 . "$PSScriptRoot/../src/TokenForge/Private/ProbeFailure.ps1"
}
Describe 'Finite discovery operation budgets' {
 It 'reserves bootstrap issuance in both the bootstrap and complete issuance envelope' {
  $b=New-TokenForgeOperationBudget -MaxIssuanceAttempts 2 -MaxBootstrapAttempts 1
  Start-TokenForgeBudgetIssuance -Budget $b -Kind Bootstrap
  Start-TokenForgeBudgetIssuance -Budget $b
  {Start-TokenForgeBudgetIssuance -Budget $b}|Should -Throw '*IssuanceAttempts*'
  $b.Counts.IssuanceAttempts|Should -Be 2
  $b.Counts.BootstrapAttempts|Should -Be 1
 }
 It 'allows explicitly zero bootstrap work without disabling later logical issuance' {
  $b=New-TokenForgeOperationBudget -MaxBootstrapAttempts 0
  {Start-TokenForgeBudgetIssuance -Budget $b -Kind Bootstrap}|Should -Throw '*BootstrapAttempts*'
  $b.Counts.IssuanceAttempts|Should -Be 0
 }
 It 'counts every preflight and retry dispatch against its category and total ceilings' {
  $b=New-TokenForgeOperationBudget -MaxTotalRequests 4 -MaxBootstrapRequests 1 -MaxInventoryRequests 2 -MaxSourceRequests 1
  Start-TokenForgeBudgetRequest -Budget $b -Category Bootstrap
  Start-TokenForgeBudgetRequest -Budget $b -Category Source
  $b.Preflight=$false
  Start-TokenForgeBudgetRequest -Budget $b -Category Inventory
  Start-TokenForgeBudgetRequest -Budget $b -Category Inventory -Retry
  {Start-TokenForgeBudgetRequest -Budget $b -Category Identity}|Should -Throw '*TotalRequests*'
  $b.Counts.TotalRequests|Should -Be 4
  $b.Counts.PreflightRequests|Should -Be 2
  $b.Counts.InventoryRequests|Should -Be 2
  $b.Counts.RequestRetries|Should -Be 1
 }
 It 'enforces the <Category> request sublimit before consuming the total' -ForEach @(
  @{Category='Bootstrap';Option='MaxBootstrapRequests'},
  @{Category='Inventory';Option='MaxInventoryRequests'},
  @{Category='Source';Option='MaxSourceRequests'}
 ) {
  $options=@{};$options[$Option]=0
  $b=New-TokenForgeOperationBudget @options
  {Start-TokenForgeBudgetRequest -Budget $b -Category $Category}|Should -Throw "*$($Category)Requests*"
  $b.Counts.TotalRequests|Should -Be 0
 }
 It 'bounds issuance retries by operation and counts them within issuance attempts' {
  $b=New-TokenForgeOperationBudget -MaxTransientRetries 1
  Start-TokenForgeBudgetIssuance -Budget $b -OperationId cell1
  Start-TokenForgeBudgetIssuance -Budget $b -OperationId cell1 -Retry
  {Start-TokenForgeBudgetIssuance -Budget $b -OperationId cell1 -Retry}|Should -Throw '*TransientRetries*'
  $b.Counts.IssuanceAttempts|Should -Be 2
  $b.Counts.IssuanceRetries|Should -Be 1
 }
 It 'rejects an unidentified issuance retry without changing counters' {
  $b=New-TokenForgeOperationBudget
  {Start-TokenForgeBudgetIssuance -Budget $b -Retry}|Should -Throw '*safe operation identifier*'
  $b.Counts.IssuanceAttempts|Should -Be 0
 }
 It 'refuses a fifth inventory page before sending it' {
  $b=New-TokenForgeOperationBudget -MaxInventoryPages 4
  1..4|ForEach-Object {Start-TokenForgeBudgetPage $b}
  {Start-TokenForgeBudgetPage $b}|Should -Throw '*InventoryPages*'
  $b.Counts.InventoryPages|Should -Be 4
 }
 It 'checks an already cancelled operator token before issuing or dispatching' {
  $cancel=[Threading.CancellationTokenSource]::new();$cancel.Cancel()
  try{
   $b=New-TokenForgeOperationBudget -CancellationToken $cancel.Token
   {Start-TokenForgeBudgetIssuance -Budget $b}|Should -Throw '*Cancelled*'
   $b.Counts.IssuanceAttempts|Should -Be 0
   $b.Counts.TotalRequests|Should -Be 0
  }finally{$cancel.Dispose()}
 }
 It 'stops before an operation after its wall deadline' {
  $b=New-TokenForgeOperationBudget -MaxSeconds 0.001
  [Threading.Thread]::Sleep(10)
  {Start-TokenForgeBudgetRequest -Budget $b}|Should -Throw '*DeadlineReached*'
  $b.Counts.TotalRequests|Should -Be 0
 }
 It 'uses subsecond cancellation within the remaining wall deadline' {
  $b=New-TokenForgeOperationBudget -MaxSeconds 0.1 -TransportTimeoutSeconds 30
  $c=New-TokenForgeBudgetCancellation $b
  try{$c.Token.WaitHandle.WaitOne(1000)|Should -BeTrue}finally{$c.Dispose()}
 }
 It 'records an in-flight overrun before reporting the deadline stop' {
  $b=New-TokenForgeOperationBudget -MaxSeconds 0.01
  Start-TokenForgeBudgetRequest -Budget $b
  [Threading.Thread]::Sleep(30)
  {Complete-TokenForgeBudgetRequest $b}|Should -Throw '*DeadlineReached*'
  $s=Get-TokenForgeOperationBudgetSummary $b
  $s.Counts.TotalRequests|Should -Be 1
  $s.Counts.InFlightOverruns|Should -Be 1
  $s.OverrunSeconds|Should -BeGreaterThan 0
 }
 It 'does not sleep for a retry that cannot fit the remaining deadline' {
  Mock Start-Sleep {}
  $b=New-TokenForgeOperationBudget -MaxSeconds 1
  {Wait-TokenForgeOperationBudget -Budget $b -Seconds 2}|Should -Throw '*DeadlineReached*'
  Should -Invoke Start-Sleep -Times 0 -Exactly
 }
 It 'honors cancellation during a retry wait' {
  $b=New-TokenForgeOperationBudget
  Mock Start-Sleep {$b.Cancelled=$true}
  {Wait-TokenForgeOperationBudget -Budget $b -Seconds 1}|Should -Throw '*Cancelled*'
  Should -Invoke Start-Sleep -Times 1 -Exactly
 }
 It 'reports a detached numeric summary without transport credentials or mutable counts' {
  $b=New-TokenForgeOperationBudget
  Start-TokenForgeBudgetRequest -Budget $b -Category Identity
  $s=Get-TokenForgeOperationBudgetSummary $b
  Start-TokenForgeBudgetRequest -Budget $b -Category Identity
  $s.Counts.TotalRequests|Should -Be 1
  $json=$s|ConvertTo-Json -Depth 8 -Compress
  $json|Should -Not -Match 'CancellationToken|RetryCounts|Timer|Cookie|AccessToken|Uri'
  $s.Scope|Should -Be 'CurrentInvocationIncludingPreflight'
 }
 It 'blocks Graph before touching transport when inventory requests are disallowed' {
  $b=New-TokenForgeOperationBudget -MaxInventoryRequests 0
  $token=ConvertTo-SecureString synthetic -AsPlainText -Force
  try{{Invoke-TokenForgeGraph -AccessToken $token -Uri 'https://graph.microsoft.com/v1.0/me' -OperationBudget $b}|Should -Throw '*InventoryRequests*'}finally{$token.Dispose()}
  $b.Counts.TotalRequests|Should -Be 0
 }
 It 'blocks Graph pages before the first mocked HTTP operation' {
  Mock Invoke-TokenForgeGraph {throw 'Unexpected synthetic transport.'}
  $b=New-TokenForgeOperationBudget -MaxInventoryPages 0
  $token=ConvertTo-SecureString synthetic -AsPlainText -Force
  try{{Get-TokenForgeGraphCollection -AccessToken $token -Uri 'https://graph.microsoft.com/v1.0/users' -OperationBudget $b}|Should -Throw '*InventoryPages*'}finally{$token.Dispose()}
  Should -Invoke Invoke-TokenForgeGraph -Times 0 -Exactly
 }
 It 'counts pages and requests independently and never returns an incomplete inventory' {
  Mock Invoke-TokenForgeGraph {param($OperationBudget) Start-TokenForgeBudgetRequest -Budget $OperationBudget -Category Inventory;@{value=@(@{id='synthetic'});'@odata.nextLink'='https://graph.microsoft.com/v1.0/users?$skiptoken=synthetic'}}
  $b=New-TokenForgeOperationBudget -MaxInventoryPages 1
  $token=ConvertTo-SecureString synthetic -AsPlainText -Force
  try{{Get-TokenForgeGraphCollection -AccessToken $token -Uri 'https://graph.microsoft.com/v1.0/users' -OperationBudget $b}|Should -Throw '*InventoryPages*'}finally{$token.Dispose()}
  $b.Counts.InventoryPages|Should -Be 1
  $b.Counts.InventoryRequests|Should -Be 1
 }
 It 'blocks a source refresh before any network request when its source budget is zero' {
  $b=New-TokenForgeOperationBudget -MaxSourceRequests 0
  {Invoke-TokenForgeBudgetSource -Uri 'https://example.invalid/synthetic.json' -Budget $b}|Should -Throw '*SourceRequests*'
  $b.Counts.TotalRequests|Should -Be 0
 }
}

Describe 'Durable synthetic request intents' {
 BeforeEach {
  $directory=Join-Path $TestDrive ([guid]::NewGuid().ToString('N'))
  $null=New-Item -ItemType Directory -Path $directory
  if(-not $IsWindows){[IO.File]::SetUnixFileMode($directory,[IO.UnixFileMode]448)}
  $ledger=Join-Path $directory 'budget.json'
  # Isolate atomic persistence from the native private-path policy, covered by its own suite.
  Mock Resolve-TokenForgeVaultPath {param($Path) $Path}
 }
 It 'durably reserves counts and pending state before any simulated dispatch' {
  $b=New-TokenForgeOperationBudget -LedgerPath $ledger
  Start-TokenForgeBudgetRequest -Budget $b -Category Bootstrap
  $saved=Get-Content $ledger -Raw|ConvertFrom-Json
  $saved.PendingRequest|Should -BeTrue
  $saved.Budget.Counts.TotalRequests|Should -Be 1
  $saved.Budget.Counts.BootstrapRequests|Should -Be 1
  $saved.LastRequest.Sequence|Should -Be 1
  $saved.LastRequest.Category|Should -Be Bootstrap
  $saved.ExactlyOnceGuaranteed|Should -BeFalse
  # Simulate a crash by never invoking completion; a new reader still sees the intent.
  (Get-Content $ledger -Raw|ConvertFrom-Json).PendingRequest|Should -BeTrue
 }
 It 'records bounded transport ending without claiming remote exactly-once success' {
  $b=New-TokenForgeOperationBudget -LedgerPath $ledger
  Start-TokenForgeBudgetRequest -Budget $b -Category Inventory
  Complete-TokenForgeBudgetRequest $b
  $saved=Get-Content $ledger -Raw|ConvertFrom-Json
  $saved.PendingRequest|Should -BeFalse
  $saved.LastRequest.EndedAt|Should -Not -BeNullOrEmpty
  $saved.Budget.Counts.TotalRequests|Should -Be 1
  $saved.ExactlyOnceGuaranteed|Should -BeFalse
 }
 It 'refuses dispatch when durable intent cannot be written' {
  Mock Save-TokenForgeDocument {throw 'Synthetic intent persistence failure.'}
  $b=New-TokenForgeOperationBudget -LedgerPath $ledger
  {Start-TokenForgeBudgetRequest -Budget $b -Category Identity}|Should -Throw '*intent persistence failure*'
  Test-Path $ledger|Should -BeFalse
  $b.Counts.TotalRequests|Should -Be 1
 }
 It 'uses the private path guard before persisting an intent' {
  Mock Resolve-TokenForgeVaultPath {throw 'Synthetic private path refusal.'}
  $b=New-TokenForgeOperationBudget -LedgerPath $ledger
  {Start-TokenForgeBudgetRequest -Budget $b -Category Source}|Should -Throw '*private path refusal*'
  Test-Path $ledger|Should -BeFalse
 }
 It 'persists deadline overruns and keeps only allowlisted request metadata' {
  $b=New-TokenForgeOperationBudget -MaxSeconds 0.1 -LedgerPath $ledger
  Start-TokenForgeBudgetRequest -Budget $b -Category Identity
  [Threading.Thread]::Sleep(150)
  {Complete-TokenForgeBudgetRequest $b}|Should -Throw '*DeadlineReached*'
  $saved=Get-Content $ledger -Raw|ConvertFrom-Json
  $saved.Budget.Counts.InFlightOverruns|Should -Be 1
  $saved.Budget.StopReason|Should -Be DeadlineReached
  @(($saved.LastRequest.PSObject.Properties.Name)|Sort-Object)|Should -Be @('Category','EndedAt','Retry','Sequence','StartedAt')
 }
}

Describe 'Bootstrap uncertainty and stable collector stop receipts' {
 BeforeEach {
  $directory=Join-Path $TestDrive ([guid]::NewGuid().ToString('N'))
  $null=New-Item -ItemType Directory -Path $directory
  if(-not $IsWindows){[IO.File]::SetUnixFileMode($directory,[IO.UnixFileMode]448)}
  $intentPath=Join-Path $directory 'bootstrap-intent.json'
  Mock Resolve-TokenForgeVaultPath {param($Path) $Path}
 }
 It 'writes bootstrap intent before simulated issuance and refuses silent bootstrap replay' {
  $first=New-TokenForgeOperationBudget
  Start-TokenForgeBootstrapIntent -Path $intentPath -Budget $first
  (Get-Content $intentPath -Raw|ConvertFrom-Json).State|Should -Be Started
  $next=New-TokenForgeOperationBudget
  {Start-TokenForgeBootstrapIntent -Path $intentPath -Budget $next}|Should -Throw '*InFlightUnknown*'
  $next.Counts.IssuanceAttempts|Should -Be 0
 }
 It 'allows one explicit recovery only within ceilings including the unknown prior requests' {
  $first=New-TokenForgeOperationBudget
  Start-TokenForgeBootstrapIntent -Path $intentPath -Budget $first
  Start-TokenForgeBudgetRequest -Budget $first -Category Bootstrap
  $next=New-TokenForgeOperationBudget -MaxBootstrapAttempts 2
  Start-TokenForgeBootstrapIntent -Path $intentPath -Budget $next -RecoverUnknown
  $next.Counts.IssuanceAttempts|Should -Be 2
  $next.Counts.BootstrapAttempts|Should -Be 2
  $next.Counts.BootstrapRequests|Should -Be 1
  $next.Counts.ReservedUnknownRequests|Should -Be 1
  $next.Counts.IssuanceRetries|Should -Be 1
  $third=New-TokenForgeOperationBudget -MaxBootstrapAttempts 2
  {Start-TokenForgeBootstrapIntent -Path $intentPath -Budget $third -RecoverUnknown}|Should -Throw '*RecoveryExhausted*'
  $third.Counts.IssuanceAttempts|Should -Be 0
 }
 It 'requires sufficient bootstrap attempt budget even for explicitly authorized recovery' {
  $first=New-TokenForgeOperationBudget
  Start-TokenForgeBootstrapIntent -Path $intentPath -Budget $first
  $next=New-TokenForgeOperationBudget -MaxBootstrapAttempts 1
  {Start-TokenForgeBootstrapIntent -Path $intentPath -Budget $next -RecoverUnknown}|Should -Throw '*BootstrapAttempts*'
  (Get-Content $intentPath -Raw|ConvertFrom-Json).RecoveryCount|Should -Be 0
 }
 It 'permits a new explicit invocation after a durably completed bootstrap' {
  $first=New-TokenForgeOperationBudget
  Start-TokenForgeBootstrapIntent -Path $intentPath -Budget $first
  Complete-TokenForgeBootstrapIntent $first
  $next=New-TokenForgeOperationBudget
  Start-TokenForgeBootstrapIntent -Path $intentPath -Budget $next
  $next.Counts.IssuanceAttempts|Should -Be 1
 }
 It 'refuses corrupt bootstrap intent before reserving or dispatching work' {
  Set-Content $intentPath '{"SchemaVersion":1,"SchemaVersion":1}'
  $b=New-TokenForgeOperationBudget
  {Start-TokenForgeBootstrapIntent -Path $intentPath -Budget $b -RecoverUnknown}|Should -Throw '*Failed*'
  $b.Counts.IssuanceAttempts|Should -Be 0
 }
 It 'retains the single recovery limit after a known unsuccessful recovery (<State>)' -ForEach @(@{State='SessionPaused'},@{State='TransientFailure'},@{State='RequestBlocked'}) {
  $first=New-TokenForgeOperationBudget
  Start-TokenForgeBootstrapIntent -Path $intentPath -Budget $first
  $next=New-TokenForgeOperationBudget -MaxBootstrapAttempts 2
  Start-TokenForgeBootstrapIntent -Path $intentPath -Budget $next -RecoverUnknown
  Complete-TokenForgeBootstrapIntent -Budget $next -State $State
  $third=New-TokenForgeOperationBudget -MaxBootstrapAttempts 2
  {Start-TokenForgeBootstrapIntent -Path $intentPath -Budget $third -RecoverUnknown -ResumePaused}|Should -Throw '*RecoveryExhausted*'
  $third.Counts.IssuanceAttempts|Should -Be 0
 }
 It 'requires explicit renewed-session continuation after a paused bootstrap' {
  $first=New-TokenForgeOperationBudget
  Start-TokenForgeBootstrapIntent -Path $intentPath -Budget $first
  Complete-TokenForgeBootstrapIntent -Budget $first -State SessionPaused
  $next=New-TokenForgeOperationBudget
  {Start-TokenForgeBootstrapIntent -Path $intentPath -Budget $next}|Should -Throw '*SessionPaused*'
  $next.Counts.IssuanceAttempts|Should -Be 0
  Start-TokenForgeBootstrapIntent -Path $intentPath -Budget $next -ResumePaused
  $next.Counts.IssuanceAttempts|Should -Be 1
 }
 It 'rejects noncanonical or future bootstrap times before issuance' {
  $first=New-TokenForgeOperationBudget
  Start-TokenForgeBootstrapIntent -Path $intentPath -Budget $first
  $saved=Get-Content $intentPath -Raw|ConvertFrom-Json -AsHashtable
  $saved.StartedAt=[DateTimeOffset]::UtcNow.AddDays(1).ToString('o')
  Save-TokenForgeDocument -Path $intentPath -Document $saved
  $next=New-TokenForgeOperationBudget
  {Start-TokenForgeBootstrapIntent -Path $intentPath -Budget $next -RecoverUnknown}|Should -Throw '*Failed*'
  $next.Counts.IssuanceAttempts|Should -Be 0
 }
 It 'maps typed <Id> to stable status <Status>' -ForEach @(
  @{Id='SessionPaused';Status='Paused';Reason='SessionPaused'},
  @{Id='InFlightUnknown';Status='InFlightUnknown';Reason='InFlightUnknown'},
  @{Id='RecoveryExhausted';Status='InFlightUnknown';Reason='RecoveryExhausted'},
  @{Id='AccountMismatch';Status='AccountMismatch';Reason='AccountMismatch'},
  @{Id='TransientIdentity';Status='TransientExhausted';Reason='TransientExhausted'}
 ) {
  $err=[Management.Automation.ErrorRecord]::new([InvalidOperationException]::new('synthetic'),('TokenForge.'+$Id),$(if($Id -eq 'TransientIdentity'){[Management.Automation.ErrorCategory]::ResourceUnavailable}else{[Management.Automation.ErrorCategory]::InvalidOperation}),$null)
  $receipt=Get-TokenForgeCollectorStopSummary -ErrorRecord $err -Stage Discovery -Budget (New-TokenForgeOperationBudget)
  $receipt.Status|Should -Be $Status
  $receipt.Reason|Should -Be $Reason
 }
 It 'classifies expired bootstrap sessions safely without storing raw identity bodies' {
  $err=[Management.Automation.ErrorRecord]::new([InvalidOperationException]::new('Identity request failed (AADSTS700082).'), 'Synthetic',[Management.Automation.ErrorCategory]::InvalidOperation,$null)
  $receipt=Get-TokenForgeCollectorStopSummary -ErrorRecord $err -Stage Authorization -Budget (New-TokenForgeOperationBudget)
  $receipt.Status|Should -Be Paused
  $receipt.Reason|Should -Be SessionPaused
  ($receipt|ConvertTo-Json -Depth 8)|Should -Not -Match AADSTS
 }
}

Describe 'Unknown read-only preflight request recovery' {
 BeforeEach {
  $directory=Join-Path $TestDrive ([guid]::NewGuid().ToString('N'))
  $null=New-Item -ItemType Directory -Path $directory
  if(-not $IsWindows){[IO.File]::SetUnixFileMode($directory,[IO.UnixFileMode]448)}
  Mock Resolve-TokenForgeVaultPath {param($Path) $Path}
  $first=New-TokenForgeOperationBudget -LedgerPath (Join-Path $directory 'budget-intent-old.json')
 }
 It 'requires explicit recovery of a pending <Category> request before any bootstrap issuance' -ForEach @(@{Category='Source'},@{Category='Inventory'}) {
  Start-TokenForgeBudgetRequest -Budget $first -Category $Category
  $next=New-TokenForgeOperationBudget
  {Assert-TokenForgePendingRequestRecovery -StatePath $directory -Budget $next}|Should -Throw '*InFlightUnknown*'
  $next.Counts.TotalRequests|Should -Be 0
  $next.Counts.IssuanceAttempts|Should -Be 0
 }
 It 'conservatively charges one unknown inventory request and page then inherits its recovery cap' {
  Start-TokenForgeBudgetRequest -Budget $first -Category Inventory
  $next=New-TokenForgeOperationBudget -LedgerPath (Join-Path $directory 'budget-intent-next.json')
  Assert-TokenForgePendingRequestRecovery -StatePath $directory -Budget $next -RecoverUnknown
  $next.Counts.TotalRequests|Should -Be 1
  $next.Counts.InventoryRequests|Should -Be 1
  $next.Counts.InventoryPages|Should -Be 1
  $next.Counts.ReservedUnknownRequests|Should -Be 1
  $prior=Get-Content $first.LedgerPath -Raw|ConvertFrom-Json
  $prior.PendingRequest|Should -BeTrue
  $prior.RecoveryAuthorized|Should -BeTrue
  Start-TokenForgeBudgetRequest -Budget $next -Category Inventory
  $third=New-TokenForgeOperationBudget
  {Assert-TokenForgePendingRequestRecovery -StatePath $directory -Budget $third -RecoverUnknown}|Should -Throw '*RecoveryExhausted*'
  $third.Counts.IssuanceAttempts|Should -Be 0
 }
 It 'preserves the <Category> uncertainty snapshot and separate writer lock during recovery' -ForEach @(@{Category='Source'},@{Category='Inventory'}) {
  Start-TokenForgeBudgetRequest -Budget $first -Category $Category
  $expected=Get-Content $first.LedgerPath -Raw|ConvertFrom-Json -AsHashtable -DateKind String
  $expected.RecoveryCount=1;$expected.RecoveryAuthorized=$true
  $lockPath=Join-Path $directory '.discovery.lock'
  $writerLock=[IO.File]::Open($lockPath,[IO.FileMode]::CreateNew,[IO.FileAccess]::ReadWrite,[IO.FileShare]::None)
  try{
   $next=New-TokenForgeOperationBudget -LedgerPath (Join-Path $directory 'budget-intent-next.json')
   Assert-TokenForgePendingRequestRecovery -StatePath $directory -Budget $next -RecoverUnknown
   $saved=Get-Content $first.LedgerPath -Raw|ConvertFrom-Json -AsHashtable -DateKind String
   ($saved|ConvertTo-Json -Depth 100 -Compress)|Should -BeExactly ($expected|ConvertTo-Json -Depth 100 -Compress)
   $next.Counts.TotalRequests|Should -Be 1;$next.Counts.ReservedUnknownRequests|Should -Be 1
   $next.Counts.IssuanceAttempts|Should -Be 0
   {[IO.File]::Open($lockPath,[IO.FileMode]::Open,[IO.FileAccess]::ReadWrite,[IO.FileShare]::None).Dispose()}|Should -Throw
  }finally{$writerLock.Dispose()}
 }
 It 'retains the unknown ledger and refuses continuation if recovery publication fails' {
  Start-TokenForgeBudgetRequest -Budget $first -Category Source
  $before=(Get-FileHash $first.LedgerPath).Hash
  $next=New-TokenForgeOperationBudget -LedgerPath (Join-Path $directory 'budget-intent-next.json')
  Mock Save-TokenForgeDocument {throw 'synthetic replacement failure'} -ParameterFilter {$Path -eq $first.LedgerPath}
  {Assert-TokenForgePendingRequestRecovery -StatePath $directory -Budget $next -RecoverUnknown}|Should -Throw '*Failed*'
  (Get-FileHash $first.LedgerPath).Hash|Should -Be $before
  Test-Path $next.LedgerPath|Should -BeFalse
  $third=New-TokenForgeOperationBudget
  {Assert-TokenForgePendingRequestRecovery -StatePath $directory -Budget $third}|Should -Throw '*InFlightUnknown*'
  $third.Counts.TotalRequests|Should -Be 0;$third.Counts.IssuanceAttempts|Should -Be 0
 }
 It 'permits a normal later run after the explicitly authorized read-only retry completed' {
  Start-TokenForgeBudgetRequest -Budget $first -Category Source
  $next=New-TokenForgeOperationBudget -LedgerPath (Join-Path $directory 'budget-intent-next.json')
  Assert-TokenForgePendingRequestRecovery -StatePath $directory -Budget $next -RecoverUnknown
  Start-TokenForgeBudgetRequest -Budget $next -Category Source
  Complete-TokenForgeBudgetRequest $next
  $third=New-TokenForgeOperationBudget
  {Assert-TokenForgePendingRequestRecovery -StatePath $directory -Budget $third}|Should -Not -Throw
 }
 It 'does not double charge pending identity requests handled by durable flow or bootstrap intents' {
  Start-TokenForgeBudgetRequest -Budget $first -Category Identity
  $next=New-TokenForgeOperationBudget
  {Assert-TokenForgePendingRequestRecovery -StatePath $directory -Budget $next}|Should -Not -Throw
  $next.Counts.TotalRequests|Should -Be 0
 }
 It 'keeps transport failures unknown and blocks another unapproved read-only dispatch' {
  Start-TokenForgeBudgetRequest -Budget $first -Category Source
  Complete-TokenForgeBudgetRequest -Budget $first -OutcomeKnown $false
  $prior=Get-Content $first.LedgerPath -Raw|ConvertFrom-Json
  $prior.PendingRequest|Should -BeTrue
  $prior.LastRequest.EndedAt|Should -BeNullOrEmpty
  $next=New-TokenForgeOperationBudget -LedgerPath (Join-Path $directory 'budget-intent-next.json')
  {Assert-TokenForgePendingRequestRecovery -StatePath $directory -Budget $next}|Should -Throw '*InFlightUnknown*'
  Assert-TokenForgePendingRequestRecovery -StatePath $directory -Budget $next -RecoverUnknown
  Start-TokenForgeBudgetRequest -Budget $next -Category Source
  Complete-TokenForgeBudgetRequest -Budget $next -OutcomeKnown $false
  $third=New-TokenForgeOperationBudget
  {Assert-TokenForgePendingRequestRecovery -StatePath $directory -Budget $third -RecoverUnknown}|Should -Throw '*RecoveryExhausted*'
 }
 It 'inherits consumed authorization even when a prior recovery stopped before any new dispatch' {
  Start-TokenForgeBudgetRequest -Budget $first -Category Source
  $authorized=New-TokenForgeOperationBudget
  Assert-TokenForgePendingRequestRecovery -StatePath $directory -Budget $authorized -RecoverUnknown
  # The prior process ends before it writes another receipt or dispatches any HTTP.
  $next=New-TokenForgeOperationBudget -LedgerPath (Join-Path $directory 'budget-intent-next.json')
  Assert-TokenForgePendingRequestRecovery -StatePath $directory -Budget $next
  $next.GenericRecoveryCount|Should -Be 1
  Start-TokenForgeBudgetRequest -Budget $next -Category Inventory
  Complete-TokenForgeBudgetRequest -Budget $next -OutcomeKnown $false
  $third=New-TokenForgeOperationBudget
  {Assert-TokenForgePendingRequestRecovery -StatePath $directory -Budget $third -RecoverUnknown}|Should -Throw '*RecoveryExhausted*'
 }
 It 'refuses inconsistent or malformed request completion time (<Case>)' -ForEach @(
  @{Case='completed null';Pending=$false;EndKind='Null'},
  @{Case='completed object';Pending=$false;EndKind='Object'},
  @{Case='completed noncanonical';Pending=$false;EndKind='Noncanonical'},
  @{Case='completed before request';Pending=$false;EndKind='Past'},
  @{Case='completed future';Pending=$false;EndKind='Future'},
  @{Case='pending with completion';Pending=$true;EndKind='Now'}
 ) {
  Start-TokenForgeBudgetRequest -Budget $first -Category Source
  Complete-TokenForgeBudgetRequest $first
  $saved=Get-Content $first.LedgerPath -Raw|ConvertFrom-Json -AsHashtable
  $saved.Budget.StartedAt=$first.StartedAt
  $saved.LastRequest.StartedAt=$first.LastRequest.StartedAt
  $saved.PendingRequest=$Pending
  $saved.LastRequest.EndedAt=switch($EndKind){
   'Null' {$null}
   'Object' {@{Invalid='synthetic'}}
   'Noncanonical' {'2026-01-01'}
   'Past' {[DateTimeOffset]::UtcNow.AddDays(-1).ToString('o')}
   'Future' {[DateTimeOffset]::UtcNow.AddMinutes(6).ToString('o')}
   'Now' {[DateTimeOffset]::UtcNow.ToString('o')}
  }
  Save-TokenForgeDocument -Path $first.LedgerPath -Document $saved
  $next=New-TokenForgeOperationBudget
  {Assert-TokenForgePendingRequestRecovery -StatePath $directory -Budget $next -RecoverUnknown}|Should -Throw '*Failed*'
  $next.Counts.TotalRequests|Should -Be 0
 }
 It 'refuses malformed request ledgers before any further operation' {
  Set-Content $first.LedgerPath '{"SchemaVersion":1,"Credential":"synthetic"}'
  $next=New-TokenForgeOperationBudget
  {Assert-TokenForgePendingRequestRecovery -StatePath $directory -Budget $next -RecoverUnknown}|Should -Throw '*Failed*'
  $next.Counts.TotalRequests|Should -Be 0
 }
 It 'refuses uncertainty recovery when prior reservation cannot fit the source budget' {
  Start-TokenForgeBudgetRequest -Budget $first -Category Source
  $next=New-TokenForgeOperationBudget -MaxSourceRequests 0
  {Assert-TokenForgePendingRequestRecovery -StatePath $directory -Budget $next -RecoverUnknown}|Should -Throw '*SourceRequests*'
  (Get-Content $first.LedgerPath -Raw|ConvertFrom-Json).RecoveryAuthorized|Should -BeFalse
 }
}
