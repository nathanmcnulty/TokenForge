#Requires -Version 7.4
<# .SYNOPSIS
Refresh a private diagnostic catalog and save only authenticated-encrypted metadata.
.DESCRIPTION
Read-only: public sources, tenant inventory, and optional bounded sign-in summaries.
No registration, consent, scope probing, credential persistence, or public catalog publication.
A failed enumeration preserves the previous origin and never advances its observation date.
#>
[CmdletBinding()]
param(
 [Parameter(Mandatory)][string]$CheckpointPath,
 [string]$CheckpointInputPath,
 [ValidateRange(1,31)][int]$SignInDays=7,
 [ValidateRange(1,1000)][int]$MaxPages=20,
 [switch]$SkipSignIns
)
$ErrorActionPreference='Stop'
Import-Module (Join-Path $PSScriptRoot '../src/TokenForge/TokenForge.psd1') -Force
. (Join-Path $PSScriptRoot 'TokenForgeCiState.ps1')
. (Join-Path $PSScriptRoot 'TokenForgeCiAuthentication.ps1')
function Assert-MaintenanceCatalog($Catalog) {
 Assert-TfCiKeys $Catalog @('Format','SchemaVersion','CreatedAt','UpdatedAt','Applications','Origins','Runs')
 # The module's reader validates format/IDs; this envelope additionally rejects
 # credential fields and account namespaces before any restored state is reused.
 $check={param($value)
  if($value -is [Collections.IDictionary]){
   foreach($key in $value.Keys){
    if($key -iin @('AccessToken','RefreshToken','IdToken','EstsAuth','EstsAuthPersistent','AuthCookie','Password','PrivateKey','ClientSecret','Assertion','RawSignIns','RawResponse','Headers')){throw 'Credential fields are not maintenance metadata.'}
    & $check $value[$key]
   }
  }elseif($value -is [array]){foreach($item in $value){& $check $item}}
  elseif($null -ne $value -and $value -isnot [string] -and $value -isnot [ValueType]){throw 'Unsupported maintenance metadata value.'}
 }; & $check $Catalog
 foreach($app in $Catalog.Applications.Values){foreach($record in $app.Records.Values){
  if($record.Kind -cnotin @('Discovery','Inventory','SignIns','RegistrationAttempts','ScopeObservations','FlowAttempts')){throw 'Unknown private metadata kind.'}
  if($record.TenantFingerprint -and $record.TenantFingerprint -cne $env:TOKENFORGE_TENANT_FINGERPRINT){throw 'Private catalog tenant mismatch.'}
  if($record.PrincipalFingerprint -and $record.PrincipalFingerprint -cne $env:TOKENFORGE_PRINCIPAL_FINGERPRINT){throw 'Private catalog observer mismatch.'}
 }}
}
function Assert-MaintenanceGrants($History) {
 if($History -isnot [array] -or $History.Count -gt 10000){throw 'Invalid grant history.'}
 foreach($snapshot in $History){
  Assert-TfCiKeys $snapshot @('FirstSeenAt','LastSeenAt','Grants')
  if(($snapshot.FirstSeenAt -isnot [string] -and $snapshot.FirstSeenAt -isnot [datetime]) -or ($snapshot.LastSeenAt -isnot [string] -and $snapshot.LastSeenAt -isnot [datetime])){throw 'Invalid grant date types.'}
  if([DateTimeOffset]$snapshot.FirstSeenAt -gt [DateTimeOffset]$snapshot.LastSeenAt -or [DateTimeOffset]$snapshot.LastSeenAt -gt [DateTimeOffset]::UtcNow.AddMinutes(5) -or $snapshot.Grants -isnot [array]){throw 'Invalid grant snapshot.'}
  foreach($grant in $snapshot.Grants){
   Assert-TfCiKeys $grant @('ClientId','ResourceId','Scopes','PrincipalFingerprint','ConsentType','AppliesToCurrentPrincipal','Evidence')
   foreach($field in @('ClientId','ResourceId')){$id=[guid]::Empty;if($grant[$field] -isnot [string] -or -not [guid]::TryParse($grant[$field],[ref]$id) -or $id -eq [guid]::Empty){throw 'Invalid grant application ID.'}}
   if($grant.Scopes -isnot [array] -or @($grant.Scopes|Where-Object {$_ -isnot [string] -or $_.Length -gt 256}).Count -or ($null -ne $grant.PrincipalFingerprint -and ($grant.PrincipalFingerprint -isnot [string] -or $grant.PrincipalFingerprint -notmatch '^[a-f0-9]{64}$')) -or $grant.ConsentType -cnotin @('AllPrincipals','Principal') -or $grant.AppliesToCurrentPrincipal -isnot [bool] -or $grant.Evidence -cne 'TenantConfiguredGrant'){throw 'Invalid grant metadata.'}
  }
 }
}
$tempRoot=[IO.Path]::GetTempPath()
if($IsMacOS -and $tempRoot.StartsWith('/var/',[StringComparison]::Ordinal)){$tempRoot='/private'+$tempRoot}
$state=Join-Path $tempRoot ('TokenForge-maintenance-'+[guid]::NewGuid())
$metadata=Join-Path $state 'applications.json'
$grantHistory=@();$cookie=$null;$graph=$null;$started=[DateTimeOffset]::UtcNow
$lastRun=[ordered]@{StartedAt=$started.ToString('o');FinishedAt=$null;Discovery='NotRun';Inventory='NotRun';Grants='NotRun';SignIns='NotRun';SignInFailureReason=$null;SignInSince=$started.AddDays(-$SignInDays).ToString('o');SignInUntil=$started.ToString('o');SignInMaxPages=$MaxPages;Registration='NotRun';Status='Failed'}
try{
 $output=Get-Item -LiteralPath $CheckpointPath -Force -ErrorAction SilentlyContinue
 if($output -and ($output.PSIsContainer -or ($output.Attributes -band [IO.FileAttributes]::ReparsePoint))){throw 'Snapshot output must be a regular file.'}
 if($env:TOKENFORGE_TENANT_FINGERPRINT -notmatch '^[a-f0-9]{64}$' -or $env:TOKENFORGE_PRINCIPAL_FINGERPRINT -notmatch '^[a-f0-9]{64}$' -or -not $env:TOKENFORGE_CHECKPOINT_KEY -or -not $env:TOKENFORGE_ESTS_COOKIE){throw 'Verified CI credentials and context are required.'}
 $context="private-maintenance/v1/$($env:TOKENFORGE_TENANT_FINGERPRINT)/$($env:TOKENFORGE_PRINCIPAL_FINGERPRINT)"
 $null=New-Item -ItemType Directory $state
 if(-not $IsWindows){[IO.File]::SetUnixFileMode($state,[IO.UnixFileMode]448)}
 $cookie=ConvertTo-SecureString $env:TOKENFORGE_ESTS_COOKIE -AsPlainText -Force;$env:TOKENFORGE_ESTS_COOKIE=$null
 # Verify identity before accepting or modifying any saved account state.
 $graph=Get-TfCiGraphSession -EstsAuth $cookie
 if($CheckpointInputPath -and (Test-Path -LiteralPath $CheckpointInputPath)){
  $file=Get-Item -LiteralPath $CheckpointInputPath
  if($file.PSIsContainer -or ($file.Attributes -band [IO.FileAttributes]::ReparsePoint) -or $file.Length -gt 134217757){throw 'Invalid encrypted maintenance file.'}
  $plain=Unprotect-TfCiCheckpoint ([IO.File]::ReadAllBytes($file.FullName)) $env:TOKENFORGE_CHECKPOINT_KEY $context
  try{
   $saved=[Text.Encoding]::UTF8.GetString($plain)|ConvertFrom-Json -AsHashtable -Depth 100
   Assert-TfCiKeys $saved @('SchemaVersion','Context','Metadata','GrantHistory','LastRun')
   if($saved.SchemaVersion -ne 1 -or $saved.Context -cne $context){throw 'Invalid maintenance envelope.'}
   $grantHistory=$saved.GrantHistory;Assert-MaintenanceGrants $grantHistory
   $saved.Metadata|ConvertTo-Json -Depth 100|Set-Content -LiteralPath $metadata
  }finally{[Security.Cryptography.CryptographicOperations]::ZeroMemory($plain)}
  if(-not $IsWindows){[IO.File]::SetUnixFileMode($metadata,[IO.UnixFileMode]384)}
  $restored=Get-TokenForgeApplicationMetadata $metadata;Assert-MaintenanceCatalog $restored
 }
 $prior=if(Test-Path $metadata){Get-TokenForgeApplicationMetadata $metadata}else{$null}
 try{
  $discovery=Update-TokenForgeDiscovery -Path (Join-Path $state 'discovery.json') -MetadataPath $metadata
  $lastRun.Discovery='Complete'
 }catch{$lastRun.Discovery='Failed';throw 'Public discovery refresh failed.'}
 # Preserve private sign-in-only candidates even when logs are unreadable this run.
 $known=@{};foreach($app in $discovery.Applications){$known[$app.AppId]=$app}
 if($prior){foreach($app in $prior.Applications.Values){
  if($known.ContainsKey($app.AppId) -or -not @($app.Records.Values|Where-Object {$_.Kind -eq 'SignIns' -and $_.TenantFingerprint -ceq $env:TOKENFORGE_TENANT_FINGERPRINT}).Count){continue}
  $known[$app.AppId]=[pscustomobject]@{AppId=$app.AppId;Name=$app.AppId;OwnerTenantId=$null;Ownership='Unverified';Sources=@([pscustomobject]@{Name='SignInLogs';Location='https://graph.microsoft.com/beta/auditLogs/signIns';Evidence='ObservedSignInNotOwnership'});PublicClient=$null;Foci=$null;RedirectUris=@();PreferredRedirectUri='';Grants=@();IsResourceCandidate=$false;IdentifierUris=@()}
 }}
 $discovery.Applications=@($known.Values|Sort-Object AppId)
 try{
  $inventory=Get-TokenForgeTenantInventory -GraphToken $graph.AccessToken -Discovery $discovery
  if($inventory.TenantFingerprint -cne $env:TOKENFORGE_TENANT_FINGERPRINT -or $inventory.PrincipalFingerprint -cne $env:TOKENFORGE_PRINCIPAL_FINGERPRINT){throw 'Inventory identity mismatch.'}
  $null=Update-TokenForgeApplicationMetadata $metadata -Document $inventory -Kind Inventory
  $lastRun.Inventory='Complete';$lastRun.Grants=$inventory.GrantEnumeration
  if($lastRun.Grants -eq 'Complete'){
   $orderedGrants=@($inventory.TenantGrants|ForEach-Object {
    [ordered]@{ClientId=$_.ClientId;ResourceId=$_.ResourceId;Scopes=@($_.Scopes|Sort-Object -Unique);PrincipalFingerprint=$_.PrincipalFingerprint;ConsentType=$_.ConsentType;AppliesToCurrentPrincipal=$_.AppliesToCurrentPrincipal;Evidence=$_.Evidence}
   }|Sort-Object {[string]$_.ClientId},{[string]$_.ResourceId},{[string]$_.ConsentType},{[string]$_.PrincipalFingerprint},{($_.Scopes -join ' ')})
   $grants=ConvertTo-Json -InputObject $orderedGrants -Depth 100|ConvertFrom-Json -AsHashtable -NoEnumerate
   # Hash only the grant set, retaining dates of each distinct complete snapshot.
   if($grantHistory.Count -and (Get-TfCiHash $grantHistory[-1].Grants) -ceq (Get-TfCiHash $grants)){$grantHistory[-1].LastSeenAt=$inventory.CapturedAt}
   else{$grantHistory+=@{FirstSeenAt=$inventory.CapturedAt;LastSeenAt=$inventory.CapturedAt;Grants=$grants}}
   Assert-MaintenanceGrants $grantHistory
  }
 }catch{$lastRun.Inventory='Failed'}
 if($SkipSignIns){$lastRun.SignIns='Skipped'}elseif($lastRun.Inventory -ne 'Complete'){$lastRun.SignIns='SkippedInventoryUnavailable'}else{
  try{
   $report=Get-TokenForgeSignInApplications -GraphToken $graph.AccessToken -Inventory $inventory -Since $started.AddDays(-$SignInDays) -Until $started -MaxPages $MaxPages
   $null=Update-TokenForgeApplicationMetadata $metadata -Document $report -Kind SignIns
   $lastRun.SignIns='Complete'
  }catch{
   $lastRun.SignIns=if($_.Exception.Message -match 'HTTP 403'){'Forbidden'}else{'Failed'}
   $lastRun.SignInFailureReason=if($lastRun.SignIns -eq 'Forbidden'){'Forbidden'}elseif($_.Exception.Message -match 'page limit|pagination loop'){'EnumerationBounded'}elseif($_.Exception.Message -match 'HTTP 429|HTTP 5[0-9][0-9]|transport'){'TransientTransport'}else{'OtherFailure'}
  }
 }
 $lastRun.Status=if($lastRun.Inventory -ne 'Complete' -or $lastRun.SignIns -eq 'Failed'){'Failed'}elseif($lastRun.SignIns -eq 'Forbidden' -or $lastRun.Grants -ne 'Complete'){'Partial'}else{'Complete'}
}catch{throw 'Private metadata maintenance failed; details suppressed. Prior snapshots remain available.'}finally{
 try{
  # Only the projected application catalog is serialized; never the token object,
  # raw sign-in events, browser state, profile, cookie, or authentication directories.
  if($graph -and (Test-Path -LiteralPath $metadata)){
   $catalog=Get-TokenForgeApplicationMetadata $metadata;Assert-MaintenanceCatalog $catalog
   $lastRun.FinishedAt=[DateTimeOffset]::UtcNow.ToString('o')
   Assert-MaintenanceGrants $grantHistory
   $payload=@{SchemaVersion=1;Context=$context;Metadata=$catalog;GrantHistory=$grantHistory;LastRun=$lastRun}|ConvertTo-Json -Depth 100 -Compress
   $plain=[Text.Encoding]::UTF8.GetBytes($payload)
   try{
    $blob=Protect-TfCiCheckpoint $plain $env:TOKENFORGE_CHECKPOINT_KEY $context
    $temp=$CheckpointPath+'.'+[guid]::NewGuid()+'.tmp'
    $options=[IO.FileStreamOptions]::new();$options.Mode=[IO.FileMode]::CreateNew;$options.Access=[IO.FileAccess]::Write
    if(-not $IsWindows){$options.UnixCreateMode=[IO.UnixFileMode]384}
    $stream=[IO.FileStream]::new($temp,$options)
    try{$stream.Write($blob)}finally{$stream.Dispose()}
    try{Move-Item -LiteralPath $temp -Destination $CheckpointPath -Force}finally{if(Test-Path -LiteralPath $temp){Remove-Item -LiteralPath $temp -Force}}
   }finally{[Security.Cryptography.CryptographicOperations]::ZeroMemory($plain)}
  }
 }finally{
  if($graph){foreach($name in @('AccessToken','RefreshToken')){if($graph.PSObject.Properties[$name] -and $graph.$name){$graph.$name.Dispose()}}}
  if($cookie){$cookie.Dispose()};$env:TOKENFORGE_ESTS_COOKIE=$null
  if(Test-Path -LiteralPath $state){Remove-Item -LiteralPath $state -Recurse -Force}
 }
}
if($lastRun.Status -eq 'Failed'){throw 'Private maintenance did not finish all required stages; encrypted recovery metadata retains the previous observations.'}
# Aggregate statuses only; no IDs, account fingerprints, or private counts in logs.
[pscustomobject]@{Status=$lastRun.Status;Inventory=$lastRun.Inventory;SignIns=$lastRun.SignIns;Grants=$lastRun.Grants;Registration='NotRun';EncryptedSnapshotSaved=$true}
