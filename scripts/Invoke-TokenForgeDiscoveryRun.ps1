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
 [ValidateRange(1,10080)][int]$MaxMinutes=60,
 [ValidateRange(0,10)][int]$MaxTransientRetries=3,
 [ValidateRange(1,300)][int]$RetryDelaySeconds=30
)
$ErrorActionPreference='Stop'
Import-Module (Join-Path $PSScriptRoot '../src/TokenForge/TokenForge.psd1') -Force -Verbose:$false
$cookie=$null;$graph=$null;$runLock=$null;$failure='Configuration'
try{
 Write-Verbose 'Discovery stage: Configuration'
 if([bool]$EstsAuth -eq [bool]$PasskeyPath){throw 'Choose an existing SecureString session or a passkey file.'}
 if($PasskeyPath -and -not $XdrModulePath){throw 'Passkey authentication requires XdrModulePath.'}
 $root=Split-Path ([TokenForge.Core.V0220.PrivateFiles]::Resolve((Join-Path $StatePath '.state'),$true)) -Parent
 $lockPath=[TokenForge.Core.V0220.PrivateFiles]::Resolve((Join-Path $root '.discovery.lock'),$true)
 $runLock=[TokenForge.Core.V0220.PrivateFiles]::Open($lockPath,(-not (Test-Path -LiteralPath $lockPath)))
 $inventoryPath=Join-Path $root 'inventory.json'
 $old=$null
 if(Test-Path -LiteralPath $inventoryPath){
  $path=[TokenForge.Core.V0220.PrivateFiles]::Resolve($inventoryPath,$false)
  $file=Get-Item -LiteralPath $path
  if($file.Length -gt 134217728){throw 'Oversized saved inventory.'}
  $old=[TokenForge.Core.DiscoverySourceClaims]::ReadMetadataJson((Get-Content -LiteralPath $path -Raw))
 }
 $failure='Authentication'
 Write-Verbose 'Discovery stage: Authentication'
 $cookie=if($EstsAuth){$EstsAuth.Copy()}else{Get-TokenForgeEstsCookie -PasskeyPath $PasskeyPath -XdrModulePath $XdrModulePath -Verbose:$false}
 $request=[pscustomobject]@{ClientId='14d82eec-204b-4c2f-b7e8-296a70dab67e';ResourceId='00000003-0000-0000-c000-000000000000';ResourceUri='00000003-0000-0000-c000-000000000000';Scopes=@('User.Read','Application.Read.All');OAuthScopes=@('00000003-0000-0000-c000-000000000000/User.Read','00000003-0000-0000-c000-000000000000/Application.Read.All');RedirectUri='https://login.microsoftonline.com/common/oauth2/nativeclient';Tenant='organizations';Spa=$false;Discovery=$false}
 $failure='Authorization'
 Write-Verbose 'Discovery stage: Authorization'
 $graph=Get-TokenForgeToken -Request $request -EstsAuth $cookie -WarningAction SilentlyContinue -Verbose:$false
 $claims=$graph.TokenClaims
 if(-not $claims -or $claims.TenantFingerprint -cnotmatch '^[a-f0-9]{64}$' -or $claims.PrincipalFingerprint -cnotmatch '^[a-f0-9]{64}$' -or $claims.ClientId -cne $request.ClientId -or $claims.Audience -notin @($request.ResourceId,'https://graph.microsoft.com','https://graph.microsoft.com/')){throw 'Graph bootstrap context mismatch.'}
 if(-not @($claims.Scopes|Where-Object {$_ -cin @('Application.Read.All','Application.ReadWrite.All','Directory.Read.All','Directory.ReadWrite.All')}).Count){throw 'Existing Graph authorization does not permit application inventory.'}
 if($old -and ($old.TenantFingerprint -cne $claims.TenantFingerprint -or $old.PrincipalFingerprint -cne $claims.PrincipalFingerprint)){throw 'The authenticated account differs from this workspace.'}
 $failure='Identity'
 Write-Verbose 'Discovery stage: Identity'
 & (Get-Module TokenForge) {
  param($token)
  $VerbosePreference='SilentlyContinue'
  $payload=ConvertFrom-TokenForgeJwtPayload -AccessToken $token
  $me=Invoke-TokenForgeGraph -AccessToken $token -Uri 'https://graph.microsoft.com/v1.0/me?$select=id'
  if(-not $payload['oid'] -or [string]$me['id'] -ine [string]$payload['oid']){throw 'Graph identity mismatch.'}
 } $graph.AccessToken
 $stage=Join-Path $PSScriptRoot 'Invoke-TokenForgeInventory.ps1'
 $common=@{StatePath=$root;NativeExecutablePath=$NativeExecutablePath;MetadataPath=(Join-Path $root 'applications.sqlite');DatabasePath=(Join-Path $root 'scopes.sqlite');FlowPath=(Join-Path $root 'flows.sqlite')}
 $failure='PublicSources'
 Write-Verbose 'Discovery stage: PublicSources'
 if($RefreshDiscovery -or -not (Test-Path (Join-Path $root 'discovery.json'))){$null=& $stage -Action Discover @common -Verbose:$false}
 $expired=-not $old -or [TokenForge.Core.V0240.TimestampPolicy]::Parse($old.CapturedAt) -lt [DateTimeOffset]::UtcNow.AddHours(-24)
 $failure='Inventory'
 Write-Verbose 'Discovery stage: Inventory'
 if($RefreshInventory -or $RefreshDiscovery -or $expired){$inventory=& $stage -Action Inventory -GraphToken $graph.AccessToken @common -Verbose:$false}else{$inventory=$old}
 if($inventory.TenantFingerprint -cne $claims.TenantFingerprint -or $inventory.PrincipalFingerprint -cne $claims.PrincipalFingerprint){throw 'Inventory account mismatch.'}
 $failure='Discovery'
 Write-Verbose 'Discovery stage: Discovery'
 $result=Invoke-TokenForgeDiscoveryRun -Inventory $inventory -EstsAuth $cookie -StatePath $root -NativeExecutablePath $NativeExecutablePath -NewRun:$NewRun -GraphOnly:$GraphOnly -BatchSize $BatchSize -MaxRedirects $MaxRedirects -MaxChunks $MaxChunks -MaxMinutes $MaxMinutes -MaxTransientRetries $MaxTransientRetries -RetryDelaySeconds $RetryDelaySeconds -ExploreAllFlows:$ExploreAllFlows -Verbose:$false
 Write-Verbose 'Discovery stage: Finished'
 $result|ConvertTo-Json -Compress
}catch{
 if($_.FullyQualifiedErrorId.Split(',')[0] -ceq 'TokenForge.TransientIdentity' -and $_.CategoryInfo.Category -eq [Management.Automation.ErrorCategory]::ResourceUnavailable){$failure='TransientIdentity'}
 [pscustomobject]@{SchemaVersion=1;Status='Stopped';Reason=$failure;CheckpointsRetained=$true;CredentialOutput=$false}|ConvertTo-Json -Compress
 exit 1
}finally{
 if($runLock){$runLock.Dispose()}
 if($cookie){$cookie.Dispose()}
 if($graph){foreach($name in @('AccessToken','RefreshToken')){if($graph.PSObject.Properties[$name] -and $graph.$name){$graph.$name.Dispose()}}}
}
