#Requires -Version 7.4
<# .SYNOPSIS
Run local application discovery without an agent or hosted runner.
#>
[CmdletBinding()]
param(
 [Parameter(Mandatory)][string]$StatePath,
 [Parameter(Mandatory)][string]$NativeExecutablePath,
 [securestring]$EstsAuth,
 [string]$PasskeyPath,[string]$XdrModulePath,
 [switch]$NewRun,[switch]$RefreshDiscovery,[switch]$RefreshInventory,[switch]$GraphOnly,
 [switch]$ExploreAllFlows=$true,
 [ValidateRange(1,1000)][int]$BatchSize=25,
 [ValidateRange(1,1000)][int]$MaxRedirects=8,
 [ValidateRange(1,100000)][int]$MaxChunks=100000,
 [ValidateRange(1,10080)][int]$MaxMinutes=15,
 [ValidateRange(0,3)][int]$MaxTransientRetries=3,
 [ValidateRange(1,300)][int]$RetryDelaySeconds=30,
 [ValidateRange(0,1000)][int]$MaxPendingClients=0,
 [switch]$RecoverUnknown,[switch]$ResumePaused,
 [ValidateRange(0,1000000)][int]$MaxIssuanceAttempts=30,
 [ValidateRange(0,1000000)][int]$MaxBootstrapAttempts=1,
 [ValidateRange(0,1000000)][int]$MaxBootstrapRequests=20,
 [ValidateRange(0,1000000)][int]$MaxInventoryRequests=100,
 [ValidateRange(0,1000000)][int]$MaxInventoryPages=50,
 [ValidateRange(0,1000000)][int]$MaxSourceRequests=3,
 [ValidateRange(0,1000000)][int]$MaxTotalRequests=300,
 [ValidateRange(0.001,30)][double]$TransportTimeoutSeconds=30,
 [Threading.CancellationToken]$CancellationToken=[Threading.CancellationToken]::None
)
$ErrorActionPreference='Stop'
Import-Module (Join-Path $PSScriptRoot '../src/TokenForge/TokenForge.psd1') -Force -Verbose:$false
$cookie=$null;$graph=$null;$runLock=$null;$budget=$null;$failure='Configuration'
$budgetOptions=@{MaxSeconds=($MaxMinutes*60);MaxIssuanceAttempts=$MaxIssuanceAttempts;MaxBootstrapAttempts=$MaxBootstrapAttempts;MaxBootstrapRequests=$MaxBootstrapRequests;MaxInventoryRequests=$MaxInventoryRequests;MaxInventoryPages=$MaxInventoryPages;MaxSourceRequests=$MaxSourceRequests;MaxTotalRequests=$MaxTotalRequests;MaxTransientRetries=$MaxTransientRetries;TransportTimeoutSeconds=$TransportTimeoutSeconds;CancellationToken=$CancellationToken}
$budget=& (Get-Module TokenForge) {param($options) $script:OperationBudget=New-TokenForgeOperationBudget @options;$script:OperationBudget} $budgetOptions
try{
 Write-Verbose 'Discovery stage: Configuration'
 if(-not $EstsAuth -or $PasskeyPath -or $XdrModulePath){throw 'Bounded discovery requires an explicitly supplied existing SecureString session; obtain or renew it separately.'}
 & (Get-Module TokenForge) {param($budget) Assert-TokenForgeOperationBudget $budget} $budget
 $root=Split-Path ([TokenForge.Core.V0220.PrivateFiles]::Resolve((Join-Path $StatePath '.state'),$true)) -Parent
 $lockPath=[TokenForge.Core.V0220.PrivateFiles]::Resolve((Join-Path $root '.discovery.lock'),$true)
 $runLock=[TokenForge.Core.V0220.PrivateFiles]::Open($lockPath,(-not (Test-Path -LiteralPath $lockPath)))
 $budget.LedgerPath=Join-Path $root ('budget-intent-'+[guid]::NewGuid().ToString('N')+'.json')
 & (Get-Module TokenForge) {param($budget) Save-TokenForgeBudgetLedger $budget} $budget
 $inventoryPath=Join-Path $root 'inventory.json'
 $old=$null
 if(Test-Path -LiteralPath $inventoryPath){
  $path=[TokenForge.Core.V0220.PrivateFiles]::Resolve($inventoryPath,$false)
  $file=Get-Item -LiteralPath $path
  if($file.Length -gt 134217728){throw 'Oversized saved inventory.'}
  $old=[TokenForge.Core.DiscoverySourceClaims]::ReadMetadataJson((Get-Content -LiteralPath $path -Raw))
 }
 & (Get-Module TokenForge) {param($root,$budget,$recover) Assert-TokenForgePendingRequestRecovery -StatePath $root -Budget $budget -RecoverUnknown:$recover} $root $budget ([bool]$RecoverUnknown)
 $failure='Authentication'
 Write-Verbose 'Discovery stage: Authentication'
 $cookie=$EstsAuth.Copy()
 $request=[pscustomobject]@{ClientId='14d82eec-204b-4c2f-b7e8-296a70dab67e';ResourceId='00000003-0000-0000-c000-000000000000';ResourceUri='00000003-0000-0000-c000-000000000000';Scopes=@('User.Read','Application.Read.All');OAuthScopes=@('00000003-0000-0000-c000-000000000000/User.Read','00000003-0000-0000-c000-000000000000/Application.Read.All');RedirectUri='https://login.microsoftonline.com/common/oauth2/nativeclient';Tenant='organizations';Spa=$false;Discovery=$false}
 $failure='Authorization'
 Write-Verbose 'Discovery stage: Authorization'
 & (Get-Module TokenForge) {param($root,$budget,$recover,$resume) Start-TokenForgeBootstrapIntent -Path (Join-Path $root 'bootstrap-intent.json') -Budget $budget -RecoverUnknown:$recover -ResumePaused:$resume} $root $budget ([bool]$RecoverUnknown) ([bool]$ResumePaused)
 try{
  $graph=Get-TokenForgeToken -Request $request -EstsAuth $cookie -OperationBudget $budget -WarningAction SilentlyContinue -Verbose:$false
 }catch{
  & (Get-Module TokenForge) {param($budget,$errorRecord) $classification=Get-TokenForgeProbeFailure $errorRecord;if($classification.Status -notin @('BudgetReached','InFlightUnknown')){Complete-TokenForgeBootstrapIntent -Budget $budget -State $classification.Status}} $budget $_
  throw
 }finally{$budget.IdentityCategory='Identity'}
 $claims=$graph.TokenClaims
 if(-not $claims -or $claims.TenantFingerprint -cnotmatch '^[a-f0-9]{64}$' -or $claims.PrincipalFingerprint -cnotmatch '^[a-f0-9]{64}$' -or $claims.ClientId -cne $request.ClientId -or $claims.Audience -notin @($request.ResourceId,'https://graph.microsoft.com','https://graph.microsoft.com/')){& (Get-Module TokenForge) {param($budget) Complete-TokenForgeBootstrapIntent -Budget $budget -State AccountMismatch;Throw-TokenForgeCollectorState AccountMismatch} $budget}
 if(-not @($claims.Scopes|Where-Object {$_ -cin @('Application.Read.All','Application.ReadWrite.All','Directory.Read.All','Directory.ReadWrite.All')}).Count){& (Get-Module TokenForge) {param($budget) Complete-TokenForgeBootstrapIntent -Budget $budget -State RequestBlocked;Throw-TokenForgeCollectorState RequestBlocked} $budget}
 if($old -and ($old.TenantFingerprint -cne $claims.TenantFingerprint -or $old.PrincipalFingerprint -cne $claims.PrincipalFingerprint)){& (Get-Module TokenForge) {param($budget) Complete-TokenForgeBootstrapIntent -Budget $budget -State AccountMismatch;Throw-TokenForgeCollectorState AccountMismatch} $budget}
 & (Get-Module TokenForge) {param($budget) Complete-TokenForgeBootstrapIntent $budget} $budget
 $failure='Identity'
 Write-Verbose 'Discovery stage: Identity'
 & (Get-Module TokenForge) {
  param($token)
  $VerbosePreference='SilentlyContinue'
  $payload=ConvertFrom-TokenForgeJwtPayload -AccessToken $token
  $me=Invoke-TokenForgeGraph -AccessToken $token -Uri 'https://graph.microsoft.com/v1.0/me?$select=id'
  if(-not $payload['oid'] -or [string]$me['id'] -ine [string]$payload['oid']){Throw-TokenForgeCollectorState AccountMismatch}
 } $graph.AccessToken
 $stage=Join-Path $PSScriptRoot 'Invoke-TokenForgeInventory.ps1'
 $common=@{StatePath=$root;NativeExecutablePath=$NativeExecutablePath;MetadataPath=(Join-Path $root 'applications.sqlite');DatabasePath=(Join-Path $root 'scopes.sqlite');FlowPath=(Join-Path $root 'flows.sqlite');OperationBudget=$budget}
 $failure='PublicSources'
 Write-Verbose 'Discovery stage: PublicSources'
 if($RefreshDiscovery -or -not (Test-Path (Join-Path $root 'discovery.json'))){$null=& $stage -Action Discover @common -Verbose:$false}
 $expired=-not $old -or [TokenForge.Core.V0240.TimestampPolicy]::Parse($old.CapturedAt) -lt [DateTimeOffset]::UtcNow.AddHours(-24)
 $failure='Inventory'
 Write-Verbose 'Discovery stage: Inventory'
 if($RefreshInventory -or $RefreshDiscovery -or $expired){$inventory=& $stage -Action Inventory -GraphToken $graph.AccessToken @common -Verbose:$false}else{$inventory=$old}
 if($inventory.TenantFingerprint -cne $claims.TenantFingerprint -or $inventory.PrincipalFingerprint -cne $claims.PrincipalFingerprint){& (Get-Module TokenForge) {Throw-TokenForgeCollectorState AccountMismatch}}
 $failure='Discovery'
 Write-Verbose 'Discovery stage: Discovery'
 $result=Invoke-TokenForgeDiscoveryRun -Inventory $inventory -EstsAuth $cookie -StatePath $root -NativeExecutablePath $NativeExecutablePath -NewRun:$NewRun -GraphOnly:$GraphOnly -BatchSize $BatchSize -MaxPendingClients $MaxPendingClients -MaxRedirects $MaxRedirects -MaxChunks $MaxChunks -MaxMinutes $MaxMinutes -MaxTransientRetries $MaxTransientRetries -RetryDelaySeconds $RetryDelaySeconds -ExploreAllFlows:$ExploreAllFlows -OperationBudget $budget -RecoverUnknown:$RecoverUnknown -ResumePaused:$ResumePaused -Verbose:$false
 Write-Verbose 'Discovery stage: Finished'
 $result|ConvertTo-Json -Depth 8 -Compress
 if($result.Status -cne 'Complete'){exit 1}
}catch{
 $summary=& (Get-Module TokenForge) {param($errorRecord,$stage,$budget) Get-TokenForgeCollectorStopSummary -ErrorRecord $errorRecord -Stage $stage -Budget $budget} $_ $failure $budget
 $summary|ConvertTo-Json -Depth 8 -Compress
 exit 1
}finally{
 & (Get-Module TokenForge) {$script:OperationBudget=$null}
 if($runLock){$runLock.Dispose()}
 if($cookie){$cookie.Dispose()}
 if($graph){foreach($name in @('AccessToken','RefreshToken')){if($graph.PSObject.Properties[$name] -and $graph.$name){$graph.$name.Dispose()}}}
}
