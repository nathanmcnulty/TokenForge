# Saved metadata only. Planning and projection never acquire or renew a session.
function Get-TokenForgeRefreshPlan {
 [CmdletBinding()]param([Parameter(Mandatory)][string]$InputJson,[DateTimeOffset]$AsOf)
 $json=if($PSBoundParameters.ContainsKey('AsOf')){[TokenForge.Core.AdminWorkflows]::PlanRefresh($InputJson,$AsOf)}else{[TokenForge.Core.AdminWorkflows]::PlanRefresh($InputJson)}
 [TokenForge.Core.DiscoverySourceClaims]::ReadMetadataJson($json)
}
function ConvertTo-TokenForgeRefreshHistory {
 [CmdletBinding()]param([Parameter(Mandatory)][string]$PlanJson,[Parameter(Mandatory)][string]$SnapshotJson,[string]$HistoryJson)
 [TokenForge.Core.DiscoverySourceClaims]::ReadMetadataJson([TokenForge.Core.AdminWorkflows]::CaptureRefreshEvidence($PlanJson,$SnapshotJson,$HistoryJson))
}
function Get-TokenForgeRefreshStatus {
 [CmdletBinding()]param([Parameter(Mandatory)][string]$PlanJson,[Parameter(Mandatory)][string]$StatePath)
 if(-not(Test-Path -LiteralPath $StatePath -PathType Leaf)){throw 'Saved refresh state is required.'}
 $run=[TokenForge.Core.AdminWorkflows]::OpenRefreshRun($PlanJson,$StatePath)
 try{[TokenForge.Core.DiscoverySourceClaims]::ReadMetadataJson($run.Status())}finally{$run.Dispose()}
}
function Export-TokenForgeRefreshHistory {
 [CmdletBinding()]param([Parameter(Mandatory)][string]$PlanJson,[Parameter(Mandatory)][string]$StatePath,[string]$HistoryJson)
 if(-not(Test-Path -LiteralPath $StatePath -PathType Leaf)){throw 'Saved refresh state is required.'}
 $run=[TokenForge.Core.AdminWorkflows]::OpenRefreshRun($PlanJson,$StatePath)
 try{[TokenForge.Core.DiscoverySourceClaims]::ReadMetadataJson($run.ProjectHistory($HistoryJson))}finally{$run.Dispose()}
}
function Invoke-TokenForgeRefresh {
 [CmdletBinding()]param([Parameter(Mandatory)][string]$PlanJson,[Parameter(Mandatory)][string]$AccountStateDirectory,[securestring]$EstsAuth,[ValidateSet('ESTSAUTH','ESTSAUTHPERSISTENT')][string]$CookieName='ESTSAUTH',[Threading.CancellationToken]$CancellationToken=[Threading.CancellationToken]::None,[switch]$OperationCheck)
 $plan=[TokenForge.Core.DiscoverySourceClaims]::ReadMetadataJson([TokenForge.Core.AdminWorkflows]::ValidateRefresh($PlanJson))
 $path=Join-Path $AccountStateDirectory refresh-run.json
 foreach($row in @($plan.Candidates|Where-Object Selected)){
  if(Test-Path -LiteralPath $path){$status=Get-TokenForgeRefreshStatus -PlanJson $PlanJson -StatePath $path;$request=@($status.Requests|Where-Object RequestId -CEQ $row.RequestId)[0];if($request.Status -ceq 'Complete'){continue};if($request.Status -cin @('InFlightUnknown','Interrupted')){return $status}}
  $result=[TokenForge.Core.DiscoverySourceClaims]::ReadMetadataJson([TokenForge.Core.AdminWorkflows]::AcquireRefresh($PlanJson,$AccountStateDirectory,$row.RequestId,$EstsAuth,$CookieName,$CancellationToken,$null,$null,$null,$OperationCheck.IsPresent))
  $result
  if(-not $EstsAuth -or ($result.Contains('Run') -and $result.Run.InFlightUnknownCount -gt 0)){return}
 }
}
function Move-TokenForgeRefreshPlan {
 [CmdletBinding()]param([Parameter(Mandatory)][string]$PlanJson,[Parameter(Mandatory)][string]$AccountStateDirectory)
 $null=[TokenForge.Core.AdminWorkflows]::AdvanceRefreshRun($PlanJson,$AccountStateDirectory)
}
