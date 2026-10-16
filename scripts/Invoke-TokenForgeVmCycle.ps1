#Requires -Version 7.6
<# .SYNOPSIS
Resume one bounded Linux VM collection cycle using an existing session and frozen inputs.
#>
[CmdletBinding()]
param(
 [Parameter(Mandatory)][string]$StatePath,
 [Parameter(Mandatory)][string]$NativeExecutablePath,
 [Parameter(Mandatory)][ValidatePattern('^[a-f0-9]{64}$')][string]$NativeSha256,
 [Parameter(Mandatory)][securestring]$EstsAuth,
 [Parameter(Mandatory)][DateTimeOffset]$SessionExpiresAt,
 [ValidateRange(1,100000)][int]$MaxChunks=1,
 [ValidateRange(1,10080)][int]$MaxMinutes=15,
 [ValidateRange(0,10)][int]$MaxTransientRetries=3,
 [ValidateRange(1,300)][int]$RetryDelaySeconds=30
)
$ErrorActionPreference='Stop'
Import-Module (Join-Path $PSScriptRoot '../src/TokenForge/TokenForge.psd1') -Force -Verbose:$false
$lock=$null;$cookie=$null;$receipt=$null;$receiptPath=$null;$reason='Configuration'
try {
 if(-not $IsLinux){throw 'Linux only.'}
 $root=Split-Path ([TokenForge.Core.V0220.PrivateFiles]::Resolve((Join-Path $StatePath '.state'),$false)) -Parent
 $lockPath=[TokenForge.Core.V0220.PrivateFiles]::Resolve((Join-Path $root '.discovery.lock'),$false)
 $reason='Busy'
 $lock=[TokenForge.Core.V0220.PrivateFiles]::Open($lockPath,(-not (Test-Path -LiteralPath $lockPath)))
 $reason='Configuration'
 if((Get-FileHash -LiteralPath $NativeExecutablePath -Algorithm SHA256).Hash.ToLowerInvariant() -cne $NativeSha256){throw 'Native package pin mismatch.'}
 $cohortId=& (Get-Module TokenForge) {param($p) Get-TokenForgeDiscoveryRunId $p} (Join-Path $root 'discovery-run.json')
 $inventoryPath=[TokenForge.Core.V0220.PrivateFiles]::Resolve((Join-Path $root 'inventory.json'),$false)
 if((Get-Item -LiteralPath $inventoryPath).Length -gt 134217728){throw 'Oversized inventory.'}
 $inventory=[TokenForge.Core.DiscoverySourceClaims]::ReadMetadataJson((Get-Content -LiteralPath $inventoryPath -Raw))
 $receiptPath=[TokenForge.Core.V0220.PrivateFiles]::Resolve((Join-Path $root 'vm-cycle.json'),$false)
 $receipt=[ordered]@{SchemaVersion=1;CycleId=[guid]::NewGuid().ToString('N');CohortId=$cohortId;NativeSha256=$NativeSha256;ModuleVersion=(Get-Module TokenForge).Version.ToString();StartedAt=[DateTimeOffset]::UtcNow.ToString('o');UpdatedAt=[DateTimeOffset]::UtcNow.ToString('o');Status='Running';Reason='Collection';Clients=$null;CompletedClients=$null;PendingClients=$null;Publication='NotAttempted';CheckpointsRetained=$true;CredentialOutput=$false}
 & (Get-Module TokenForge) {param($p,$d) Save-TokenForgeDocument -Path $p -Document $d} $receiptPath $receipt
 # Retain the collector's 24-hour freshness gate; never refresh frozen inputs here.
 $captured=[TokenForge.Core.V0240.TimestampPolicy]::Parse($inventory.CapturedAt)
 if($captured -lt [DateTimeOffset]::UtcNow.AddHours(-24) -or $captured -gt [DateTimeOffset]::UtcNow.AddMinutes(5)){$reason='InventoryStale';throw 'Inventory requires reviewed refresh.'}
 $reason='CollectionFailed'
 $cookie=$EstsAuth.Copy()
 $result=Invoke-TokenForgeDiscoveryRun -Inventory $inventory -EstsAuth $cookie -StatePath $root -NativeExecutablePath $NativeExecutablePath -SessionExpiresAt $SessionExpiresAt -StopFilePath (Join-Path $root 'stop.requested') -MaxChunks $MaxChunks -MaxMinutes $MaxMinutes -MaxTransientRetries $MaxTransientRetries -RetryDelaySeconds $RetryDelaySeconds -Verbose:$false -WarningAction SilentlyContinue
 if($result.CohortId -cne $cohortId -or $result.Status -cnotin @('Complete','BudgetReached','SessionExpired','Cancelled')){throw 'Invalid collector result.'}
 foreach($key in @('Clients','CompletedClients','PendingClients')){
  if(($result.$key -isnot [int] -and $result.$key -isnot [long]) -or $result.$key -lt 0){throw 'Invalid collector counts.'}
 }
 if($result.CompletedClients+$result.PendingClients -ne $result.Clients){throw 'Invalid collector counts.'}
 $receipt.Status=$result.Status;$receipt.Reason=$result.Status
 foreach($key in @('Clients','CompletedClients','PendingClients')){$receipt[$key]=$result.$key}
 $receipt.UpdatedAt=[DateTimeOffset]::UtcNow.ToString('o')
 & (Get-Module TokenForge) {param($p,$d) Save-TokenForgeDocument -Path $p -Document $d} $receiptPath $receipt
 $receipt|ConvertTo-Json -Compress
 # A scheduler may repeat budget stops. All other stops require operator review.
 if($result.Status -in @('SessionExpired','Cancelled')){exit 2}
}catch{
 if($_.FullyQualifiedErrorId.Split(',')[0] -ceq 'TokenForge.TransientIdentity' -and $_.CategoryInfo.Category -eq [Management.Automation.ErrorCategory]::ResourceUnavailable){$reason='TransientExhausted'}
 if($receipt){
  $receipt.Status='Stopped';$receipt.Reason=$reason;$receipt.UpdatedAt=[DateTimeOffset]::UtcNow.ToString('o')
  try{& (Get-Module TokenForge) {param($p,$d) Save-TokenForgeDocument -Path $p -Document $d} $receiptPath $receipt}catch{}
 }
 [pscustomobject]@{SchemaVersion=1;Status='Stopped';Reason=$reason;CheckpointsRetained=$true;Publication='NotAttempted';CredentialOutput=$false}|ConvertTo-Json -Compress
 exit 1
}finally{
 if($cookie){$cookie.Dispose()}
 if($lock){$lock.Dispose()}
}
