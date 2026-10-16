# Synthetic offline checkpoint boundary. No authentication, native execution, or networking.
param([string]$Repository,[string]$State,[switch]$Interrupt)
$ErrorActionPreference='Stop'
Import-Module (Join-Path $Repository 'src/TokenForge/TokenForge.psd1') -Force
# Preserve the synthetic module functions when the wrapper imports the same module.
function Import-Module {}
& (Get-Module TokenForge) {
 param($state,$interrupt)
 $script:fixtureState=$state;$script:fixtureInterrupt=$interrupt
 function script:Get-TokenForgeResearchCohort {
  $n=[int](Get-Content (Join-Path $script:fixtureState 'pending'))
  [pscustomobject]@{PlanId=('c'*64);ClientCount=3;Pending=@(1..$n|Where-Object {$n -gt 0});Cohort=@{TenantFingerprint=('a'*64);PrincipalFingerprint=('b'*64);CatalogHash=('d'*64);InventoryHash=(Get-TokenForgeFingerprint '[]')}}
 }
 function script:Invoke-TokenForgeResearchChunk {
  $n=[int](Get-Content (Join-Path $script:fixtureState 'pending'))
  Add-Content (Join-Path $script:fixtureState 'attempts') $n
  Set-Content (Join-Path $script:fixtureState 'pending') ($n-1)
  if($script:fixtureInterrupt){
   Set-Content (Join-Path $script:fixtureState 'checkpoint-written') 'ready'
   Start-Sleep -Seconds 120
  }
  [pscustomobject]@{PlanId=('c'*64);PendingClients=($n-1)}
 }
} $State ([bool]$Interrupt)
$cookie=ConvertTo-SecureString synthetic -AsPlainText -Force
try {
 $native=Join-Path $State 'synthetic-native'
 & (Join-Path $Repository 'scripts/Invoke-TokenForgeVmCycle.ps1') -StatePath $State -NativeExecutablePath $native -NativeSha256 (Get-FileHash $native).Hash.ToLowerInvariant() -EstsAuth $cookie -SessionExpiresAt ([DateTimeOffset]::UtcNow.AddHours(1)) -MaxChunks 5
}finally{$cookie.Dispose()}
