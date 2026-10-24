[CmdletBinding()]
param([Parameter(Mandatory)][string]$InputPath,[Parameter(Mandatory)][string]$NativeExecutablePath,[string]$ExchangePath)
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'TokenForgePublicHealth.ps1')
Initialize-TokenForgeHealthRuntime $NativeExecutablePath
$inputBytes=Read-TokenForgeHealthBytes $InputPath 1048576
$document=Read-TokenForgeHealthJson $inputBytes
Assert-TokenForgeHealthKeys $document @('appId','claims')
Assert-TokenForgeHealthGuid $document.appId
if($document.claims -isnot [array] -or $document.claims.Count -gt 32){throw 'Invalid quarantined contribution.'}
$walk={param($v) if($v -is [Collections.IDictionary]){foreach($k in $v.Keys){& $walk $v[$k]}}elseif($v -is [array]){foreach($x in $v){& $walk $x}}elseif($v -is [string]){Assert-TokenForgeHealthText $v}}
& $walk $document
foreach($claim in $document.claims){[TokenForge.Core.DiscoverySourceClaims]::ValidatePublicLocation($claim.Location)}
$normalized=[TokenForge.Core.DiscoverySourceClaims]::NormalizeMetadata((ConvertTo-Json -InputObject $document.claims -Depth 50 -Compress),$document.appId)
$match=$false
if($ExchangePath){
    $exchange=Read-TokenForgeHealthExchange $ExchangePath
    if($exchange.Ledger.Applications.Contains($document.appId)){
        $published=$exchange.Ledger.Applications[$document.appId].Records['Discovery///'].Attributes.SourceClaims
        $match=(ConvertTo-Json -InputObject @($published) -Depth 50 -Compress) -ceq (ConvertTo-Json -InputObject @($normalized.SourceClaims) -Depth 50 -Compress)
    }
}
[ordered]@{schemaVersion=1;kind='TokenForgeQuarantinedClaims';status='Quarantined';appId=$document.appId;inputSha256=Get-TokenForgeHealthHash $inputBytes;sourceClaims=@($normalized.SourceClaims);metadataConflicts=@($normalized.MetadataConflicts);matchesSuppliedPublicExchange=$match;proofStillNeeded=@('TenantOwnership','Consent','TokenIssuance','ApiAcceptance');catalogImported=$false;operationalApproval=$false}|ConvertTo-Json -Depth 50
