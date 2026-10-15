BeforeAll {Import-Module "$PSScriptRoot/../src/TokenForge/TokenForge.psd1" -Force}
Describe 'Research chunk pending membership' {
 BeforeEach {
  $root=Join-Path $TestDrive ([guid]::NewGuid().ToString())
  $id='c'*64;$first='11111111-1111-1111-1111-111111111111';$second='22222222-2222-2222-2222-222222222222';$graph='00000003-0000-0000-c000-000000000000'
  $inventory=[pscustomobject]@{CapturedAt=[DateTimeOffset]::UtcNow.ToString('o');TenantFingerprint=('a'*64);PrincipalFingerprint=('b'*64);DiscoveryCatalogHash=('d'*64);Applications=@()}
  $recipe=@{TenantFingerprint=$inventory.TenantFingerprint;PrincipalFingerprint=$inventory.PrincipalFingerprint;CatalogHash=$inventory.DiscoveryCatalogHash;InventoryHash=(& (Get-Module TokenForge) {Get-TokenForgeFingerprint '[]'});Pairs=@(@{ClientId=$first;ResourceId=$graph},@{ClientId=$second;ResourceId=$graph});Protocols=@('OAuth2V2Pkce');Authority='organizations';MaxRedirects=1;ExploreAllFlows=$false}
  $plan=[pscustomobject]@{Cohort=$recipe;PlanId=$id;BatchSize=2;ChunkCount=1;ClientCount=2;CompletedClients=1;Pending=@(@{ClientId=$second;Chunk=0})}
  $secret=ConvertTo-SecureString synthetic -AsPlainText -Force
  $options=@{Inventory=$inventory;EstsAuth=$secret;DatabasePath=(Join-Path $root scopes.sqlite);CohortId=$id;NativeExecutablePath='/synthetic/tokenforge';DelayMilliseconds=0}
  Mock Get-TokenForgeResearchCohort -ModuleName TokenForge {$plan}
  Mock Invoke-TokenForgeScopeProbe -ModuleName TokenForge {
   foreach($pair in $Plan){$ScopeChanges["$($pair.ClientId)/$($pair.ResourceId)"]=[pscustomobject]@{ClientId=$pair.ClientId;ResourceId=$pair.ResourceId;Outcome='Succeeded'}}
  }
  Mock Update-TokenForgeApplicationMetadata -ModuleName TokenForge {}
  Mock Invoke-TokenForgeNativeEvidence -ModuleName TokenForge {}
 }
 AfterEach {$secret.Dispose()}
 It 'probes and checkpoints only pending members in a partial batch' {
  $r=Invoke-TokenForgeResearchChunk @options
  $r.SelectedClients|Should -Be 1
  $r.CompletedClients|Should -Be 2
  $r.PendingClients|Should -Be 0
  Should -Invoke Invoke-TokenForgeScopeProbe -ModuleName TokenForge -Times 1 -Exactly -ParameterFilter {$ClientId.Count -eq 1 -and $ClientId[0] -eq $second -and $Plan.Count -eq 1 -and $Plan[0].ClientId -eq $second}
  Should -Invoke Invoke-TokenForgeNativeEvidence -ModuleName TokenForge -Times 1 -Exactly -ParameterFilter {$Operation -eq 'checkpoint' -and $ClientId -eq $second}
  Should -Invoke Invoke-TokenForgeNativeEvidence -ModuleName TokenForge -Times 0 -Exactly -ParameterFilter {$Operation -eq 'checkpoint' -and $ClientId -eq $first}
  Should -Invoke Get-TokenForgeResearchCohort -ModuleName TokenForge -Times 1 -Exactly
  Should -Invoke Invoke-TokenForgeNativeEvidence -ModuleName TokenForge -Times 1 -Exactly -ParameterFilter {$Operation -eq 'pending' -and $PlanFingerprint -eq $id -and $Domain -eq 'evidence'}
 }
 It 'retains explicit completed-chunk metadata repair when other chunks remain' {
  $plan.BatchSize=1;$plan.ChunkCount=2;$plan.Pending[0].Chunk=1
  Mock Invoke-TokenForgeNativeEvidence -ModuleName TokenForge {@{ClientId=$second;Chunk=1}} -ParameterFilter {$Operation -eq 'pending'}
  $r=Invoke-TokenForgeResearchChunk @options -ChunkIndex 0
  $r.SelectedClients|Should -Be 1
  $r.PendingClients|Should -Be 1
  $r.Complete|Should -BeFalse
  Should -Invoke Invoke-TokenForgeScopeProbe -ModuleName TokenForge -Times 1 -ParameterFilter {$ClientId.Count -eq 1 -and $ClientId[0] -eq $first}
  Should -Invoke Update-TokenForgeApplicationMetadata -ModuleName TokenForge -Times 1
 }
 It 'retains explicit metadata repair when the entire cohort is complete' {
  $plan.Pending=@();$plan.CompletedClients=2
  $r=Invoke-TokenForgeResearchChunk @options -ChunkIndex 0
  $r.SelectedClients|Should -Be 2
  $r.Complete|Should -BeTrue
  Should -Invoke Invoke-TokenForgeScopeProbe -ModuleName TokenForge -Times 1
  Should -Invoke Update-TokenForgeApplicationMetadata -ModuleName TokenForge -Times 1
 }
 It 'keeps all selected members pending when metadata projection fails' {
  Mock Update-TokenForgeApplicationMetadata -ModuleName TokenForge {throw 'Synthetic projection failure.'}
  {Invoke-TokenForgeResearchChunk @options}|Should -Throw '*projection failure*'
  Should -Invoke Invoke-TokenForgeNativeEvidence -ModuleName TokenForge -Times 0 -ParameterFilter {$Operation -eq 'checkpoint'}
 }
 It 'counts pending clients in other chunks from durable membership after completion' {
  $plan.BatchSize=1;$plan.ChunkCount=2;$plan.CompletedClients=0;$plan.Pending=@(@{ClientId=$first;Chunk=0},@{ClientId=$second;Chunk=1})
  Mock Invoke-TokenForgeNativeEvidence -ModuleName TokenForge {@{ClientId=$second;Chunk=1}} -ParameterFilter {$Operation -eq 'pending'}
  $r=Invoke-TokenForgeResearchChunk @options
  $r.CompletedClients|Should -Be 1
  $r.PendingClients|Should -Be 1
  $r.Complete|Should -BeFalse
 }
 It 'combines pending clients across stored chunks without selecting completed clients' {
  $third='33333333-3333-3333-3333-333333333333';$fourth='44444444-4444-4444-4444-444444444444'
  $recipe.Pairs+=@(@{ClientId=$third;ResourceId=$graph},@{ClientId=$fourth;ResourceId=$graph})
  $plan.BatchSize=1;$plan.ChunkCount=4;$plan.ClientCount=4
  $plan.Pending=@(@{ClientId=$fourth;Chunk=3},@{ClientId=$second;Chunk=1},@{ClientId=$third;Chunk=2})
  Mock Invoke-TokenForgeNativeEvidence -ModuleName TokenForge {@{ClientId=$fourth;Chunk=3}} -ParameterFilter {$Operation -eq 'pending'}
  $r=Invoke-TokenForgeResearchChunk @options -MaxPendingClients 2
  $r.SelectedClients|Should -Be 2
  $r.ChunkIndex|Should -Be 1
  $r.CompletedClients|Should -Be 3
  $r.PendingClients|Should -Be 1
  Should -Invoke Invoke-TokenForgeScopeProbe -ModuleName TokenForge -Times 1 -Exactly -ParameterFilter {$ClientId.Count -eq 2 -and $ClientId[0] -eq $second -and $ClientId[1] -eq $third -and $CohortFingerprint -ceq $id -and $Plan.Count -eq 2}
  Should -Invoke Update-TokenForgeApplicationMetadata -ModuleName TokenForge -Times 1 -Exactly -ParameterFilter {$Kind -eq 'ScopeObservations' -and $Document.Observations.Count -eq 2}
  Should -Invoke Invoke-TokenForgeNativeEvidence -ModuleName TokenForge -Times 2 -Exactly -ParameterFilter {$Operation -eq 'checkpoint'}
  Should -Invoke Invoke-TokenForgeNativeEvidence -ModuleName TokenForge -Times 0 -ParameterFilter {$Operation -eq 'cohort' -or ($Operation -eq 'checkpoint' -and $ClientId -in @($first,$fourth))}
 }
 It 'does not checkpoint any combined client when metadata projection fails' {
  $plan.BatchSize=1;$plan.ChunkCount=2;$plan.CompletedClients=0;$plan.Pending=@(@{ClientId=$first;Chunk=0},@{ClientId=$second;Chunk=1})
  Mock Update-TokenForgeApplicationMetadata -ModuleName TokenForge {throw 'Synthetic projection failure.'}
  {Invoke-TokenForgeResearchChunk @options -MaxPendingClients 2}|Should -Throw '*projection failure*'
  Should -Invoke Invoke-TokenForgeNativeEvidence -ModuleName TokenForge -Times 0 -ParameterFilter {$Operation -eq 'checkpoint'}
 }
 It 'checkpoints only handled combined clients after an interrupted probe' {
  $plan.BatchSize=1;$plan.ChunkCount=2;$plan.CompletedClients=0;$plan.Pending=@(@{ClientId=$first;Chunk=0},@{ClientId=$second;Chunk=1})
  Mock Invoke-TokenForgeScopeProbe -ModuleName TokenForge {
   $ScopeChanges["$first/$graph"]=[pscustomobject]@{ClientId=$first;ResourceId=$graph;Outcome='Succeeded'}
   throw 'Synthetic interrupted probe.'
  }
  {Invoke-TokenForgeResearchChunk @options -MaxPendingClients 2}|Should -Throw '*interrupted probe*'
  Should -Invoke Invoke-TokenForgeNativeEvidence -ModuleName TokenForge -Times 1 -Exactly -ParameterFilter {$Operation -eq 'checkpoint' -and $ClientId -eq $first}
  Should -Invoke Invoke-TokenForgeNativeEvidence -ModuleName TokenForge -Times 0 -ParameterFilter {$Operation -eq 'checkpoint' -and $ClientId -eq $second}
 }
 It 'rejects combined execution with an explicit repair chunk before probing' {
  {Invoke-TokenForgeResearchChunk @options -ChunkIndex 0 -MaxPendingClients 2}|Should -Throw '*explicit ChunkIndex*'
  Should -Invoke Invoke-TokenForgeScopeProbe -ModuleName TokenForge -Times 0
  Should -Invoke Get-TokenForgeResearchCohort -ModuleName TokenForge -Times 0
 }
 It 'performs no probe for a completed combined cohort' {
  $plan.Pending=@();$plan.CompletedClients=2
  $r=Invoke-TokenForgeResearchChunk @options -MaxPendingClients 2
  $r.PendingClients|Should -Be 0
  Should -Invoke Invoke-TokenForgeScopeProbe -ModuleName TokenForge -Times 0
 }
 It 'caps clients while retaining all frozen resource pairs for each selected client' {
  $arm='797f4846-ba00-4fd7-ba43-dac1f8f63013'
  $recipe.Pairs+=@(@{ClientId=$first;ResourceId=$arm})
  $plan.BatchSize=1;$plan.ChunkCount=2;$plan.CompletedClients=0;$plan.Pending=@(@{ClientId=$first;Chunk=0},@{ClientId=$second;Chunk=1})
  Mock Invoke-TokenForgeNativeEvidence -ModuleName TokenForge {@{ClientId=$second;Chunk=1}} -ParameterFilter {$Operation -eq 'pending'}
  $r=Invoke-TokenForgeResearchChunk @options -MaxPendingClients 1
  $r.SelectedClients|Should -Be 1
  $r.HandledPairs|Should -Be 2
  $r.PendingClients|Should -Be 1
  Should -Invoke Invoke-TokenForgeScopeProbe -ModuleName TokenForge -Times 1 -Exactly -ParameterFilter {$ClientId.Count -eq 1 -and $ClientId[0] -eq $first -and $Plan.Count -eq 2 -and @($Plan|Where-Object {$_.ClientId -ne $first}).Count -eq 0 -and $arm -in $Plan.ResourceId -and $graph -in $Plan.ResourceId}
  Should -Invoke Invoke-TokenForgeNativeEvidence -ModuleName TokenForge -Times 1 -Exactly -ParameterFilter {$Operation -eq 'checkpoint' -and $ClientId -eq $first}
 }
 It 'preserves existing positional optional path bindings' {
  $flow=Join-Path $root explicit-flows.sqlite;$metadata=Join-Path $root explicit-apps.sqlite
  $null=Invoke-TokenForgeResearchChunk $inventory $secret $options.DatabasePath $id -1 $flow $metadata '/synthetic/tokenforge' -DelayMilliseconds 0
  Should -Invoke Invoke-TokenForgeScopeProbe -ModuleName TokenForge -Times 1 -Exactly -ParameterFilter {$FlowDatabasePath -eq $flow -and $NativeExecutablePath -eq '/synthetic/tokenforge'}
  Should -Invoke Update-TokenForgeApplicationMetadata -ModuleName TokenForge -Times 1 -Exactly -ParameterFilter {$Path -eq $metadata}
 }
}
