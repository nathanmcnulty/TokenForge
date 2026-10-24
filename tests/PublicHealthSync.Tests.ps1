BeforeAll {
 $repo=Split-Path $PSScriptRoot -Parent
 . "$repo/scripts/TokenForgePublicHealth.ps1"
 . "$repo/scripts/TokenForgePublicHealthSync.ps1"
 $native=$env:TOKENFORGE_TEST_NATIVE
 if(-not $native){throw 'Sync tests require the reviewed Linux package.'}
 Initialize-TokenForgeHealthRuntime $native
 $id='11111111-1111-1111-1111-111111111111'
 function New-SyncExchange([string]$Root,[string]$Name='Example',[switch]$Empty,[switch]$Partial,[string]$Previous){
  $fixture=Join-Path $Root ('fixtures-'+[guid]::NewGuid().ToString('N'));$null=[IO.Directory]::CreateDirectory($fixture,[IO.UnixFileMode]448)
  $apps=@{};if(-not $Empty){$apps[$id]=@{name=$Name;public_client=$true;foci=$false;redirect_uris=@('https://example.invalid/callback');preferred_noninteractive_redirurl='';scopes=@{}}}
  @{apps=$apps;resourceidentifiers=@{}}|ConvertTo-Json -Depth 20|Set-Content (Join-Path $fixture roadtools.json)
  '[]'|Set-Content (Join-Path $fixture microsoftApps.json)
  '[]'|Set-Content (Join-Path $fixture resources.json)
  if($Partial){Remove-Item (Join-Path $fixture resources.json)}
  $output=Join-Path $Root ('exchange-'+[guid]::NewGuid().ToString('N'))
  $args=@{OutputPath=$output;NativeExecutablePath=$native;SourceRevision=('a'*40);FixturePath=$fixture}
  if($Previous){$args.PreviousExchangePath=$Previous}
  $null=& "$repo/scripts/Invoke-TokenForgePublicHealth.ps1" @args
  return $output
 }
}
Describe 'Workstation public health sync actual entry points' {
 BeforeEach {$root=Join-Path $TestDrive ([guid]::NewGuid().ToString('N'));$null=[IO.Directory]::CreateDirectory($root,[IO.UnixFileMode]448);$state=Join-Path $root state}
 It 'collects imports and repeats without duplicate catalog history' {
  $exchange=New-SyncExchange $root
  $result=& "$repo/scripts/Sync-TokenForgePublicHealth.ps1" -ExchangePath $exchange -StatePath $state -NativeExecutablePath $native
  $result.import|Should -Be Complete
  $catalog=Get-TokenForgeApplicationMetadata (Join-Path $state applications.sqlite) -NativeExecutablePath $native
  $runs=$catalog.Runs.Count
  $result=& "$repo/scripts/Sync-TokenForgePublicHealth.ps1" -ExchangePath $exchange -StatePath $state -NativeExecutablePath $native
  (Get-TokenForgeApplicationMetadata (Join-Path $state applications.sqlite) -NativeExecutablePath $native).Runs.Count|Should -Be $runs
  $status=& "$repo/scripts/Sync-TokenForgePublicHealth.ps1" -Status -StatePath $state -NativeExecutablePath $native
  $status.collection|Should -Be Complete;$status.publication|Should -Be NotRequested
 }
 It 'preserves private origins and frozen discovery manifest' {
  $null=Resolve-TokenForgeHealthPrivateFile (Join-Path $state '.state') -CreateDirectory
  $snapshot=@{CapturedAt='2026-01-01T00:00:00Z';TenantFingerprint=('b'*64);Applications=@(@{AppId=$id;Name='Private';Ownership='Unverified';PublicClient=$false;Foci=0;Grants=@();Sources=@()})}
  $null=Update-TokenForgeApplicationMetadata (Join-Path $state applications.sqlite) $snapshot Inventory -NativeExecutablePath $native
  $plan=Join-Path $state discovery-run.json;[IO.File]::WriteAllText($plan,'{"SchemaVersion":1,"CohortId":"frozen"}');[IO.File]::SetUnixFileMode($plan,[IO.UnixFileMode]384)
  $planHash=(Get-FileHash $plan).Hash
  $exchange=New-SyncExchange $root
  $null=Import-TokenForgePublicHealthExchange $exchange $state $native
  $catalog=Get-TokenForgeApplicationMetadata (Join-Path $state applications.sqlite) -NativeExecutablePath $native
  $catalog.Applications[$id].Records.Count|Should -Be 2
  (Get-FileHash $plan).Hash|Should -BeExactly $planHash
 }
 It 'retains complete date and values on partial collection and honors explicit empty tombstones' {
  $complete=New-SyncExchange $root;$null=Import-TokenForgePublicHealthExchange $complete $state $native
  $before=Get-TokenForgePublicHealthStatus $state
  $partial=New-SyncExchange $root -Name Changed -Partial -Previous $complete
  $result=Import-TokenForgePublicHealthExchange $partial $state $native
  $result.collection|Should -Be Incomplete;$result.lastCompleteAt|Should -BeExactly $before.lastCompleteAt
  (Get-FileHash (Join-Path $partial metadata.json)).Hash|Should -BeExactly (Get-FileHash (Join-Path $complete metadata.json)).Hash
  $empty=New-SyncExchange $root -Empty -Previous $complete
  $null=Import-TokenForgePublicHealthExchange $empty $state $native
  $record=(Get-TokenForgeApplicationMetadata (Join-Path $state applications.sqlite) -NativeExecutablePath $native).Applications[$id].Records['Discovery///']
  $record.PresentInLatestRun|Should -BeFalse
 }
 It 'preserves the retained historical complete date when first import is partial' {
  $complete=New-SyncExchange $root
  $partial=New-SyncExchange $root -Partial -Previous $complete
  $result=Import-TokenForgePublicHealthExchange $partial $state $native
  $result.collection|Should -Be Incomplete
  $result.lastCompleteAt|Should -BeExactly (Read-TokenForgeHealthExchange $complete).Health.lastCompleteAt
 }
 It 'refuses corrupt exchange and unexpected file without creating private state' {
  $exchange=New-SyncExchange $root
  [IO.File]::SetUnixFileMode((Join-Path $exchange metadata.json),[IO.UnixFileMode]384)
  Add-Content (Join-Path $exchange metadata.json) 'corrupt'
  {Import-TokenForgePublicHealthExchange $exchange $state $native}|Should -Throw
  Test-Path $state|Should -BeFalse
  $other=New-SyncExchange $root;[IO.File]::SetUnixFileMode($other,[IO.UnixFileMode]448);Set-Content (Join-Path $other extra.txt) 'unexpected'
  {Import-TokenForgePublicHealthExchange $other $state $native}|Should -Throw
 }
 It 'refuses discovery and catalog writers before import and can retry afterward' {
  $exchange=New-SyncExchange $root
  $null=Resolve-TokenForgeHealthPrivateFile (Join-Path $state '.state') -CreateDirectory
  $lock=[TokenForge.Core.V0220.PrivateFiles]::Open((Join-Path $state '.writer.lock'),$true)
  try{{Import-TokenForgePublicHealthExchange $exchange $state $native}|Should -Throw '*another writer*'}finally{$lock.Dispose()}
  $lock=[TokenForge.Core.V0220.PrivateFiles]::Open((Join-Path $state 'applications.sqlite.lock'),$true)
  try{{Import-TokenForgePublicHealthExchange $exchange $state $native}|Should -Throw '*another writer*'}finally{$lock.Dispose()}
  (Get-TokenForgePublicHealthStatus $state).import|Should -Be RecoveryRequired
  (Import-TokenForgePublicHealthExchange $exchange $state $native).import|Should -Be Complete
 }
 It 'reconciles interrupted committed import idempotently from immutable staged evidence' {
  $exchange=New-SyncExchange $root;$null=Import-TokenForgePublicHealthExchange $exchange $state $native
  $before=(Get-TokenForgeApplicationMetadata (Join-Path $state applications.sqlite) -NativeExecutablePath $native).Runs.Count
  $hash=(Get-FileHash (Join-Path $exchange manifest.json)).Hash.ToLowerInvariant()
  Write-TokenForgeHealthPrivateJson (Join-Path $state public-health-pending.json) @{schemaVersion=1;exchangeId=$hash} -Immutable
  (Get-TokenForgePublicHealthStatus $state).import|Should -Be RecoveryRequired
  $null=Import-TokenForgePublicHealthExchange $exchange $state $native
  (Get-TokenForgeApplicationMetadata (Join-Path $state applications.sqlite) -NativeExecutablePath $native).Runs.Count|Should -Be $before
  (Get-TokenForgePublicHealthStatus $state).import|Should -Be Complete
 }
 It 'imports older complete evidence without regressing newer incomplete collection status' {
  $older=New-SyncExchange $root
  $newer=New-SyncExchange $root -Partial -Previous $older
  $null=Import-TokenForgePublicHealthExchange $newer $state $native
  $newest=(Get-TokenForgePublicHealthStatus $state).lastCollectedAt
  $null=Import-TokenForgePublicHealthExchange $older $state $native
  $status=Get-TokenForgePublicHealthStatus $state
  $status.lastCollectedAt|Should -BeExactly $newest
  $status.lastCompleteAt|Should -BeExactly (Read-TokenForgeHealthExchange $older).Health.lastCompleteAt
 }
 It 'reports retention history gap after a later complete receipt without inventing observations' {
  $first=New-SyncExchange $root;$null=Import-TokenForgePublicHealthExchange $first $state $native
  $saved=Get-TokenForgePublicHealthStatus $state
  $saved.lastCompleteAt=[DateTimeOffset]::UtcNow.AddDays(-15).ToString('o')
  Write-TokenForgeHealthPrivateJson (Join-Path $state public-health-status.json) $saved
  $next=New-SyncExchange $root -Name Updated -Previous $first
  (Import-TokenForgePublicHealthExchange $next $state $native).collectionHistoryGap|Should -BeTrue
 }
 It 'repairs uncommitted interrupted staging and exposes stale saved status cheaply' {
  $exchange=New-SyncExchange $root
  Initialize-TokenForgeHealthSyncModule $native
  $hash=(Get-FileHash (Join-Path $exchange manifest.json)).Hash.ToLowerInvariant()
  $stage=Join-Path $state ('public-health-receipts/'+$hash+'/exchange')
  New-TokenForgeHealthSyncPrivateDirectory $stage
  $dest=Resolve-TokenForgeHealthPrivateFile (Join-Path $stage metadata.json)
  $f=[TokenForge.Core.V0220.PrivateFiles]::Open($dest,$true);try{$f.WriteByte(123)}finally{$f.Dispose()}
  $null=Import-TokenForgePublicHealthExchange $exchange $state $native
  (Get-TokenForgePublicHealthStatus $state -Now ([DateTimeOffset]::UtcNow.AddDays(3))).stale|Should -BeTrue
 }
}
Describe 'Named GitHub health transfer with fake transport only' {
 BeforeEach {
  $root=Join-Path $TestDrive ([guid]::NewGuid().ToString('N'));$null=[IO.Directory]::CreateDirectory($root,[IO.UnixFileMode]448);$state=Join-Path $root state
  $exchange=New-SyncExchange $root
  $manifestPath=Join-Path $exchange manifest.json
  $manifest=Get-Content $manifestPath -Raw|ConvertFrom-Json -DateKind String -AsHashtable
  $manifest.context=@{repository='owner/repo';repositoryId='123';workflowId='456';runId='789';attempt='1';event='workflow_dispatch';headSha=('a'*40);headBranch='trusted'}
  [IO.File]::SetUnixFileMode($manifestPath,[IO.UnixFileMode]384)
  $manifest|ConvertTo-Json -Depth 32|Set-Content $manifestPath
  $zip=Join-Path $root fixture.zip;[IO.Compression.ZipFile]::CreateFromDirectory($exchange,$zip)
  $script:downloadBytes=[IO.File]::ReadAllBytes($zip)
  $script:run=@{id=789;repository=@{id=123;full_name='owner/repo'};head_repository=@{id=123;full_name='owner/repo'};workflow_id=456;event='workflow_dispatch';head_sha=('a'*40);head_branch='trusted';status='completed';conclusion='success';run_attempt=1}
  $script:listing=@{total_count=1;artifacts=@(@{id=101;name='tokenforge-public-health';expired=$false;size_in_bytes=$script:downloadBytes.Length;workflow_run=@{id=789;repository_id=123;head_repository_id=123;head_sha=('a'*40);head_branch='trusted'}})}
  $script:requests=[Collections.Generic.List[object]]::new()
  Mock Invoke-TokenForgeHealthGet {
   param($Uri,$MaxBytes,$TimeoutSeconds,$Headers,$Budget,$AllowedHosts)
   $script:requests.Add(@{uri=[string]$Uri;headers=$Headers.Clone()})
   if(([string]$Uri).EndsWith('/zip')){return @{StatusCode=200;Bytes=$script:downloadBytes;Headers=@{}}}
   $value=if(([string]$Uri).Contains('/artifacts?')){$script:listing}else{$script:run}
   @{StatusCode=200;Bytes=[Text.Encoding]::UTF8.GetBytes(($value|ConvertTo-Json -Depth 32 -Compress));Headers=@{}}
  }
  $receive=@{Repository='owner/repo';RepositoryId='123';WorkflowId='456';RunId='789';SourceRevision=('a'*40);SourceBranch='trusted';StatePath=$state;NativeExecutablePath=$native}
 }
 It 'checks independent run provenance and imports exact validated members' {
  (Receive-TokenForgePublicHealthRun @receive).import|Should -Be Complete
  $script:requests.Count|Should -Be 3
  @($script:requests|Where-Object {$_.headers.ContainsKey('Authorization')}).Count|Should -Be 0
 }
 It 'rejects wrong source and rerun before download' {
  $script:run.head_sha='b'*40
  {Receive-TokenForgePublicHealthRun @receive}|Should -Throw
  $script:requests.Count|Should -Be 1
  $script:run.head_sha='a'*40;$script:run.run_attempt=2
  {Receive-TokenForgePublicHealthRun @receive}|Should -Throw
  Test-Path (Join-Path $state applications.sqlite)|Should -BeFalse
 }
 It 'exposes explicit authorization requirement without echoing provider body or reading environment credentials' {
  Mock Invoke-TokenForgeHealthGet { @{StatusCode=401;Bytes=[Text.Encoding]::UTF8.GetBytes('provider-secret-value');Headers=@{}} }
  {Receive-TokenForgePublicHealthRun @receive}|Should -Throw '*ExplicitReadAuthorizationRequired*'
  (Get-TokenForgePublicHealthStatus $state).transfer|Should -Be RefusedOrInterrupted
  (Get-Content (Join-Path $state public-health-transfer.json) -Raw)|Should -Not -Match 'provider-secret-value'
 }
 It 'rejects ambiguous artifact selection before download' {
  $script:listing.artifacts+=@($script:listing.artifacts[0]);$script:listing.total_count=2
  {Receive-TokenForgePublicHealthRun @receive}|Should -Throw
  $script:requests.Count|Should -Be 2
 }
 It 'rejects traversal ZIP before importing any catalog row' {
  $zip=Join-Path $root malicious.zip;$z=[IO.Compression.ZipFile]::Open($zip,[IO.Compression.ZipArchiveMode]::Create)
  try{foreach($name in @('../manifest.json','health.json','metadata.json')){$entry=$z.CreateEntry($name);$s=$entry.Open();try{$s.WriteByte(120)}finally{$s.Dispose()}}}finally{$z.Dispose()}
  $script:downloadBytes=[IO.File]::ReadAllBytes($zip)
  {Receive-TokenForgePublicHealthRun @receive}|Should -Throw
  Test-Path (Join-Path $state applications.sqlite)|Should -BeFalse
 }
 It 'does not forward explicitly supplied synthetic authorization onto artifact capability host' {
  Mock Invoke-TokenForgeHealthGet {
   param($Uri,$MaxBytes,$TimeoutSeconds,$Headers,$Budget,$AllowedHosts)
   $script:requests.Add(@{uri=[string]$Uri;headers=$Headers.Clone()})
   if(([string]$Uri).StartsWith('https://fixture.blob.core.windows.net')){return @{StatusCode=200;Bytes=$script:downloadBytes;Headers=@{}}}
   if(([string]$Uri).EndsWith('/zip')){return @{StatusCode=302;Bytes=[byte[]]@();Headers=@{Location='https://fixture.blob.core.windows.net/container/artifact?sig=dummy'}}}
   $value=if(([string]$Uri).Contains('/artifacts?')){$script:listing}else{$script:run}
   @{StatusCode=200;Bytes=[Text.Encoding]::UTF8.GetBytes(($value|ConvertTo-Json -Depth 32 -Compress));Headers=@{}}
  }
  $receive.GitHubToken=ConvertTo-SecureString 'synthetic-token-no-authority' -AsPlainText -Force
  (Receive-TokenForgePublicHealthRun @receive).import|Should -Be Complete
  $script:requests.Count|Should -Be 4
  $script:requests[0].headers.ContainsKey('Authorization')|Should -BeTrue
  $script:requests[3].headers.ContainsKey('Authorization')|Should -BeFalse
 }
}
