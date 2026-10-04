#Requires -Version 7.4
<# .SYNOPSIS
Refresh public metadata and one rotating Graph scope batch using an action-provided cookie.
.DESCRIPTION
DataPath contains ONLY public discovery and anonymous exports. Private state is temporary.
No registration, consent, sign-in log collection, or token persistence is performed.
#>
[CmdletBinding()]
param(
 [Parameter(Mandatory)][string]$DataPath,
 [ValidateRange(1,200)][int]$ChunkSize=100,
 [ValidateRange(-1,100000)][int]$ChunkIndex=-1,
 [ValidateRange(1,2147483647)][int]$RunNumber=1,
 [switch]$PublicOnly
)
$ErrorActionPreference='Stop'
Import-Module (Join-Path $PSScriptRoot '../src/TokenForge/TokenForge.psd1') -Force
function Assert-PublicScopeExports {
 param([string]$Path)
 foreach($file in @(Get-ChildItem -LiteralPath (Join-Path $Path 'scopes') -Force -Recurse -ErrorAction SilentlyContinue)){
  if($file.PSIsContainer -or ($file.Attributes -band [IO.FileAttributes]::ReparsePoint) -or $file.Name -notmatch '^chunk-[0-9]{4,6}\.json$'){throw 'Unexpected scope export path.'}
  $doc=Get-Content $file.FullName -Raw|ConvertFrom-Json -AsHashtable
  if($doc.SchemaVersion -ne 1 -or @($doc.Keys|Where-Object {$_ -cnotin @('SchemaVersion','Observations','Disclaimer')}).Count -or $doc.Disclaimer -cne 'Observed scopes are session/tenant dependent, not universal consent or guaranteed API access.'){throw 'Invalid public scope export.'}
  if($doc.Observations -isnot [array]){throw 'Invalid export observations array.'}
  foreach($row in $doc.Observations){
   if(@($row.Keys|Where-Object {$_ -cnotin @('ClientId','ResourceId','ObservedAt','Scopes','Evidence','SignatureValidated')}).Count -or $row.Evidence -cne 'AnonymousTenantTokenObservation' -or $row.SignatureValidated -ne $false){throw 'Private or invalid export fields.'}
   $date=[DateTimeOffset]::MinValue
   if($row.ObservedAt -isnot [string] -and $row.ObservedAt -isnot [datetime] -or -not [DateTimeOffset]::TryParse([string]$row.ObservedAt,[ref]$date) -or $row.Scopes -isnot [array] -or $row.SignatureValidated -isnot [bool]){throw 'Invalid anonymous scope value types.'}
   $client=[guid]::Empty;$resource=[guid]::Empty
   if($row.ClientId -isnot [string] -or $row.ResourceId -isnot [string] -or -not [guid]::TryParse($row.ClientId,[ref]$client) -or -not [guid]::TryParse($row.ResourceId,[ref]$resource) -or @($row.Scopes|Where-Object {$_ -isnot [string] -or $_ -notmatch '^[A-Za-z0-9_.-]{1,256}$'}).Count){throw 'Invalid public scope attributes.'}
  }
 }
}
$state=Join-Path ([IO.Path]::GetTempPath()) ('TokenForge-ci-'+[guid]::NewGuid())
$cookie=$null;$graph=$null
try {
 $null=New-Item -ItemType Directory -Path $state
 if(-not $IsWindows){[IO.File]::SetUnixFileMode($state,[IO.UnixFileMode]448)}
 $null=New-Item -ItemType Directory -Path $DataPath -Force
 Assert-PublicScopeExports $DataPath
 $metadata=Join-Path $DataPath 'applications.json'
 if(Test-Path $metadata){$null=Get-TokenForgeApplicationMetadata $metadata -PublicOnly}
 $discovery=Update-TokenForgeDiscovery -Path (Join-Path $state 'discovery.json') -MetadataPath $metadata
 $null=Get-TokenForgeApplicationMetadata $metadata -PublicOnly
 if($PublicOnly){return [pscustomobject]@{Applications=$discovery.Applications.Count;Stage='PublicDiscovery'}}
 if(-not $env:TOKENFORGE_ESTS_COOKIE){throw 'The passkey action must supply an ESTS cookie.'}
 $cookie=ConvertTo-SecureString $env:TOKENFORGE_ESTS_COOKIE -AsPlainText -Force
 $env:TOKENFORGE_ESTS_COOKIE=$null
 # Fixed Microsoft Graph Command Line Tools bootstrap. Entra enforces existing consent.
 # This client is absent from the published scope dataset; the request is not catalog evidence.
 $request=[pscustomobject]@{ClientId='14d82eec-204b-4c2f-b7e8-296a70dab67e';ResourceId='00000003-0000-0000-c000-000000000000';ResourceUri='00000003-0000-0000-c000-000000000000';Scopes=@('User.Read');OAuthScopes=@('00000003-0000-0000-c000-000000000000/User.Read');RedirectUri='https://login.microsoftonline.com/common/oauth2/nativeclient';Tenant='organizations';Spa=$false;Discovery=$false}
 $graph=Get-TokenForgeToken -Request $request -EstsAuth $cookie -CookieName $env:TOKENFORGE_COOKIE_NAME
 $claims=$graph.TokenClaims
 if($env:TOKENFORGE_TENANT_FINGERPRINT -notmatch '^[a-f0-9]{64}$' -or $env:TOKENFORGE_PRINCIPAL_FINGERPRINT -notmatch '^[a-f0-9]{64}$' -or
    $claims.TenantFingerprint -cne $env:TOKENFORGE_TENANT_FINGERPRINT -or $claims.PrincipalFingerprint -cne $env:TOKENFORGE_PRINCIPAL_FINGERPRINT -or
    $claims.ClientId -cne $request.ClientId -or $claims.Audience -notin @($request.ResourceId,'https://graph.microsoft.com','https://graph.microsoft.com/')){throw 'Bootstrap context mismatch.'}
 & (Get-Module TokenForge) {
  param($token)
  $payload=ConvertFrom-TokenForgeJwtPayload -AccessToken $token.AccessToken
  $me=Invoke-TokenForgeGraph -AccessToken $token.AccessToken -Uri 'https://graph.microsoft.com/v1.0/me?$select=id'
  if([string]$me['id'] -ine [string]$payload['oid']){throw 'Graph identity mismatch.'}
 } $graph
 $inventory=Get-TokenForgeTenantInventory -GraphToken $graph.AccessToken -Discovery $discovery -SkipGrants
 $ids=@($inventory.Applications|Where-Object {$_.Registration -eq 'Present' -and $_.Ownership -eq 'VerifiedMicrosoftOwner' -and $_.AccountEnabled}|Sort-Object AppId|Select-Object -ExpandProperty AppId)
 if(-not $ids.Count){throw 'No enabled Microsoft-owned applications were found.'}
 $chunkCount=[int][Math]::Ceiling($ids.Count/$ChunkSize)
 $index=if($ChunkIndex -lt 0){($RunNumber-1)%$chunkCount}else{$ChunkIndex}
 if($index -ge $chunkCount){throw 'ChunkIndex exceeds the current inventory.'}
 $selected=@($ids|Select-Object -Skip ($index*$ChunkSize) -First $ChunkSize)
 $databasePath=Join-Path $state 'scopes.json'
 $plan=Get-TokenForgeProbePlan -Inventory $inventory -ClientId $selected -GraphOnly
 $outcomes=@{}
 Invoke-TokenForgeScopeProbe -Inventory $inventory -EstsAuth $cookie -CookieName $env:TOKENFORGE_COOKIE_NAME -Plan $plan -DatabasePath $databasePath -ClientId $selected -Tenant organizations -MaxApplications $ChunkSize -MaxRedirects 2|ForEach-Object {
  if(-not $outcomes.ContainsKey($_.Outcome)){$outcomes[$_.Outcome]=0};$outcomes[$_.Outcome]++
 }
 $exportDirectory=Join-Path $DataPath 'scopes'
 $null=New-Item -ItemType Directory -Path $exportDirectory -Force
 $exportPath=Join-Path $exportDirectory ('chunk-{0:D4}.json' -f $index)
 $freshPath=Join-Path $state 'anonymous-scopes.json'
 Export-TokenForgeScopeDatabase -Database (Get-TokenForgeScopeDatabase $databasePath) -Path $freshPath
 $public=Get-Content $freshPath -Raw|ConvertFrom-Json
 $previous=if(Test-Path $exportPath){@((Get-Content $exportPath -Raw|ConvertFrom-Json).Observations)}else{@()}
 $latest=@{}
 foreach($row in @(@($previous)+@($public.Observations)|Sort-Object {([DateTimeOffset]$_.ObservedAt)})){$row.ObservedAt=([DateTimeOffset]$row.ObservedAt).ToUniversalTime().ToString('o');$latest["$($row.ClientId)/$($row.ResourceId)"]=$row}
 $public.Observations=@($latest.Values|Sort-Object ClientId,ResourceId)
 & (Get-Module TokenForge) {param($document,$path) Save-TokenForgeDocument -Document $document -Path $path} $public $exportPath
 Assert-PublicScopeExports $DataPath
 $null=Get-TokenForgeApplicationMetadata $metadata -PublicOnly
 [pscustomobject]@{Applications=$discovery.Applications.Count;EligibleApplications=$ids.Count;ChunkIndex=$index;ChunkCount=$chunkCount;Selected=$selected.Count;Outcomes=$outcomes}
} catch {
 # Do not allow external action/identity response bodies into the runner log.
 throw 'CI discovery failed. No private state is published; inspect bounded action status and rerun.'
} finally {
 if($graph){foreach($name in @('AccessToken','RefreshToken')){if($graph.PSObject.Properties[$name] -and $graph.$name){$graph.$name.Dispose()}}}
 if($cookie){$cookie.Dispose()};$env:TOKENFORGE_ESTS_COOKIE=$null
 if(Test-Path $state){Remove-Item -LiteralPath $state -Recurse -Force}
}
