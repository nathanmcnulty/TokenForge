<# .SYNOPSIS
Import public metadata into the workstation's private catalog, or report saved status.
#>
[CmdletBinding(DefaultParameterSetName='Local')]
param(
 [Parameter(Mandatory,ParameterSetName='Local')][string]$ExchangePath,
 [Parameter(Mandatory)][string]$StatePath,
 [string]$NativeExecutablePath,
 [Parameter(Mandatory,ParameterSetName='Status')][switch]$Status,
 [Parameter(Mandatory,ParameterSetName='GitHub')][string]$Repository,
 [Parameter(Mandatory,ParameterSetName='GitHub')][string]$RepositoryId,
 [Parameter(Mandatory,ParameterSetName='GitHub')][string]$WorkflowId,
 [Parameter(Mandatory,ParameterSetName='GitHub')][string]$RunId,
 [Parameter(Mandatory,ParameterSetName='GitHub')][string]$SourceRevision,
 [Parameter(Mandatory,ParameterSetName='GitHub')][string]$SourceBranch,
 [Parameter(ParameterSetName='GitHub')][securestring]$GitHubToken
)
$ErrorActionPreference='Stop'
. "$PSScriptRoot/TokenForgePublicHealth.ps1"
. "$PSScriptRoot/TokenForgePublicHealthSync.ps1"
if($Status){
 Initialize-TokenForgeHealthRuntime -NativeExecutablePath $NativeExecutablePath
 Get-TokenForgePublicHealthStatus $StatePath
}elseif($PSCmdlet.ParameterSetName -eq 'GitHub'){
 Receive-TokenForgePublicHealthRun -Repository $Repository -RepositoryId $RepositoryId -WorkflowId $WorkflowId -RunId $RunId -SourceRevision $SourceRevision -SourceBranch $SourceBranch -StatePath $StatePath -NativeExecutablePath $NativeExecutablePath -GitHubToken $GitHubToken
}else{Import-TokenForgePublicHealthExchange -ExchangePath $ExchangePath -StatePath $StatePath -NativeExecutablePath $NativeExecutablePath}
