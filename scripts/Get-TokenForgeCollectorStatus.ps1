#Requires -Version 7.6
[CmdletBinding()]
param([Parameter(Mandatory)][string]$StatePath,[Parameter(Mandatory)][string]$NativeExecutablePath,
 [ValidatePattern('^[a-f0-9]{64}$')][string]$CohortId)
$ErrorActionPreference='Stop'
try{
 Import-Module (Join-Path $PSScriptRoot '../src/TokenForge/TokenForge.psd1') -Force
 if(-not $CohortId){$CohortId=& (Get-Module TokenForge) {param($p) Get-TokenForgeDiscoveryRunId $p} (Join-Path $StatePath 'discovery-run.json')}
 $result=Get-TokenForgeCollectorStatus -DatabasePath (Join-Path $StatePath 'scopes.sqlite') -CohortId $CohortId -FlowPath (Join-Path $StatePath 'flows.sqlite') -NativeExecutablePath $NativeExecutablePath
 $result|ConvertTo-Json -Depth 6 -Compress
 exit $result.ExitCode
}catch{
 [pscustomobject]@{SchemaVersion=1;Status='Failed';Reason='InvalidSavedEvidence';ExitCode=1;CredentialOutput=$false}|ConvertTo-Json -Compress
 exit 1
}
