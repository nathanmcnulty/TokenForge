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
}
