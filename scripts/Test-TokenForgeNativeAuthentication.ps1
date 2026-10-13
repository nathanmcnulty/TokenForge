#Requires -Version 7.4
<# .SYNOPSIS
Validate native lab authentication without publishing credentials or identity metadata.
.DESCRIPTION
Reads existing authorization only. Requires expected account fingerprints and UPN.
Repository secrets supply TOKENFORGE_PASSKEY_* and TOKENFORGE_EXPECTED_* values.
An explicit local passkey path can replace the three private-key input fields.
#>
[CmdletBinding()]
param(
 [Parameter(Mandatory)][string]$NativeExecutablePath,
 [Parameter(Mandatory)][ValidateSet('linux-x64','linux-arm64','win-x64','win-arm64','osx-x64','osx-arm64')][string]$Runtime,
 [Parameter(Mandatory)][ValidatePattern('^[a-f0-9]{40}$')][string]$SourceCommit,
 [Parameter(Mandatory)][string]$ReportPath,
 [ValidateRange(1,1000)][int]$RunAttempt=1,
 [string]$PasskeyPath
)
$ErrorActionPreference='Stop'

function Assert-TfNativeMetadata($Value) {
 if($Value -is [Collections.IDictionary]){
  foreach($name in $Value.Keys){
   if($name -imatch '^(AccessToken|RefreshToken|IdToken|Cookie|EstsAuth|EstsAuthPersistent|AuthCookie|PrivateKey|keyValue|clientSecret|Password|Assertion|RawResponse|Headers)$'){throw 'Credential-bearing native output refused.'}
   Assert-TfNativeMetadata $Value[$name]
  }
 }elseif($Value -is [array]){foreach($entry in $Value){Assert-TfNativeMetadata $entry}}
 elseif($Value -is [string] -and $Value -match '^eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$'){throw 'Credential-bearing native output refused.'}
}
function Copy-TfNativeValidationPasskey {
 param([string]$SourcePath,[string]$DestinationPath)
 $bytes=$null;$receiptBytes=$null
 try {
  $source=[TokenForge.Core.V0220.PrivateFiles]::Resolve($SourcePath,$false)
  $validate=[TokenForge.Core.SoftwarePasskey]::Open($source);$validate.Dispose()
  $file=[IO.File]::Open($source,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
  try{if($file.Length -lt 2 -or $file.Length -gt 65536){throw 'Invalid passkey size.'};$bytes=[byte[]]::new($file.Length);$file.ReadExactly($bytes)}finally{$file.Dispose()}
  $target=[TokenForge.Core.V0220.PrivateFiles]::Resolve($DestinationPath,$false)
  $output=[TokenForge.Core.V0220.PrivateFiles]::Open($target,$true);try{$output.Write($bytes);$output.Flush($true)}finally{$output.Dispose()}
  if(Test-Path -LiteralPath ($source+'.registered.json')){
   $receipt=[TokenForge.Core.V0220.PrivateFiles]::Resolve(($source+'.registered.json'),$false)
   $file=[IO.File]::Open($receipt,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
   try{if($file.Length -lt 2 -or $file.Length -gt 4096){throw 'Invalid passkey receipt size.'};$receiptBytes=[byte[]]::new($file.Length);$file.ReadExactly($receiptBytes)}finally{$file.Dispose()}
   $output=[TokenForge.Core.V0220.PrivateFiles]::Open(($target+'.registered.json'),$true);try{$output.Write($receiptBytes);$output.Flush($true)}finally{$output.Dispose()}
  }
  $validate=[TokenForge.Core.SoftwarePasskey]::Open($target);$validate.Dispose()
  [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($bytes))
 }catch{throw 'Private passkey pair copy failed; details suppressed.'}
 finally{foreach($buffer in @($bytes,$receiptBytes)){if($buffer){[Security.Cryptography.CryptographicOperations]::ZeroMemory($buffer)}}}
}
function Invoke-TfNativeValidationCommand {
 param([string]$Executable,[string]$PrivateRoot,[string[]]$Arguments,[string]$InputValue)
 $start=[Diagnostics.ProcessStartInfo]::new($Executable)
 $start.UseShellExecute=$false;$start.RedirectStandardInput=$true;$start.RedirectStandardOutput=$true;$start.RedirectStandardError=$true
 # Pass no repository credentials, Actions tokens, or ambient authentication to the child.
 $start.Environment.Clear()
 foreach($name in @('SystemRoot','WINDIR')){if($IsWindows){$start.Environment[$name]=[Environment]::GetEnvironmentVariable($name)}}
 $start.Environment['PATH']=Join-Path $PrivateRoot 'no-powershell'
 foreach($name in @('TEMP','TMP','TMPDIR')){$start.Environment[$name]=$PrivateRoot}
 $start.Environment['DOTNET_BUNDLE_EXTRACT_BASE_DIR']=Join-Path $PrivateRoot 'bundle-cache'
 foreach($argument in $Arguments){$start.ArgumentList.Add($argument)}
 $process=$null;$text=$null
 try{
  $process=[Diagnostics.Process]::Start($start)
  $stdout=$process.StandardOutput.ReadToEndAsync();$stderr=$process.StandardError.ReadToEndAsync()
  if($InputValue){$process.StandardInput.WriteLine($InputValue)};$process.StandardInput.Close()
  if(-not $process.WaitForExit(180000)){$process.Kill($true);$null=$process.WaitForExit(10000);throw 'Native validation command timed out.'}
  $text=$stdout.GetAwaiter().GetResult()
  if($process.ExitCode -ne 0 -or $stderr.GetAwaiter().GetResult() -or $text.Length -gt 1048576){throw 'Native validation command failed.'}
  $value=$text|ConvertFrom-Json -AsHashtable -Depth 64
  if($value -isnot [Collections.IDictionary]){throw 'Invalid native validation metadata.'}
  Assert-TfNativeMetadata $value
  return $value
 }catch{throw 'Native validation command failed; output suppressed.'}
 finally{$text=$null;if($process){$process.Dispose()}}
}
# Tests load only the output/child-process boundaries and never invoke live authentication.
if($MyInvocation.InvocationName -eq '.'){return}

$secretNames=@('TOKENFORGE_PASSKEY_CREDENTIAL_ID','TOKENFORGE_PASSKEY_USER_HANDLE','TOKENFORGE_PASSKEY_PRIVATE_KEY','TOKENFORGE_PASSKEY_UPN','TOKENFORGE_EXPECTED_TENANT','TOKENFORGE_EXPECTED_PRINCIPAL')
$inputValues=@{};foreach($name in $secretNames){$inputValues[$name]=[Environment]::GetEnvironmentVariable($name);[Environment]::SetEnvironmentVariable($name,$null)}
$stage='Inputs';$root=$null;$failed=$false;$report=$null;$originalHash=$null
try{
 $expectedUser=$inputValues.TOKENFORGE_PASSKEY_UPN;$expectedTenant=$inputValues.TOKENFORGE_EXPECTED_TENANT;$expectedPrincipal=$inputValues.TOKENFORGE_EXPECTED_PRINCIPAL
 if(-not $expectedUser -or $expectedUser.Length -gt 320 -or $expectedUser -match '[\x00-\x1f\x7f]' -or $expectedTenant -cnotmatch '^[a-f0-9]{64}$' -or $expectedPrincipal -cnotmatch '^[a-f0-9]{64}$'){throw 'Invalid expected account.'}
 $exe=(Get-Item -LiteralPath $NativeExecutablePath).FullName
 $package=Split-Path $exe -Parent
 Import-Module (Join-Path $package 'src/TokenForge/TokenForge.psd1') -Force
 . (Join-Path $PSScriptRoot TokenForgeCiAuthentication.ps1)
 $temp=[IO.Path]::GetTempPath();if($IsMacOS -and $temp.StartsWith('/var/')){$temp='/private'+$temp}
 $root=Join-Path $temp ('TokenForge-native-auth-'+[guid]::NewGuid().ToString('N'))
 $null=[TokenForge.Core.V0220.PrivateFiles]::Resolve((Join-Path $root '.owned'),$true)
 $keyPath=Join-Path $root 'test.passkey';$keyBytes=$null
 try{
  if($PasskeyPath){
   $original=[TokenForge.Core.V0220.PrivateFiles]::Resolve($PasskeyPath,$false)
   $originalHash=Copy-TfNativeValidationPasskey -SourcePath $original -DestinationPath $keyPath
  }else{
   foreach($name in $secretNames[0..2]){if(-not $inputValues[$name]){throw 'Missing passkey input.'}}
   $keyJson=@{username=$expectedUser;credentialId=$inputValues.TOKENFORGE_PASSKEY_CREDENTIAL_ID;userHandle=$inputValues.TOKENFORGE_PASSKEY_USER_HANDLE;privateKey=$inputValues.TOKENFORGE_PASSKEY_PRIVATE_KEY;relyingParty='login.microsoft.com';url='https://login.microsoft.com';counter=0}|ConvertTo-Json -Compress
   $keyBytes=[Text.Encoding]::UTF8.GetBytes($keyJson);$keyJson=$null
  }
  if($keyBytes -and $keyBytes.Length -gt 65536){throw 'Oversized software passkey.'}
  if($keyBytes){$stream=[TokenForge.Core.V0220.PrivateFiles]::Open($keyPath,$true);try{$stream.Write($keyBytes);$stream.Flush($true)}finally{$stream.Dispose()}}
 }finally{if($keyBytes){[Security.Cryptography.CryptographicOperations]::ZeroMemory($keyBytes)};$inputValues.Clear()}
 $invoke=@{Executable=$exe;PrivateRoot=$root}
 $version=Invoke-TfNativeValidationCommand @invoke -Arguments @('--version')
 if($version.Name -cne 'TokenForge' -or $version.Version -cne [TokenForge.Core.CredentialRuntime]::Version){throw 'Package runtime mismatch.'}

 $stage='BaselineIdentity';$signer=$null;$session=$null;$graph=$null
 try{
  $signer=[TokenForge.Core.SoftwarePasskey]::Open($keyPath);$session=$signer.Authenticate([Threading.CancellationToken]::None)
  $env:TOKENFORGE_COOKIE_NAME=$session.CookieName;$env:TOKENFORGE_TENANT_FINGERPRINT=$expectedTenant;$env:TOKENFORGE_PRINCIPAL_FINGERPRINT=$expectedPrincipal
  $graph=Get-TfCiGraphSession -EstsAuth $session.Cookie
  $identity=& (Get-Module TokenForge) {
   param($access,$expected)
   $payload=ConvertFrom-TokenForgeJwtPayload -AccessToken $access
   $me=Invoke-TokenForgeGraph -AccessToken $access -Uri 'https://graph.microsoft.com/v1.0/me?$select=id,userPrincipalName'
   if([string]$me['id'] -ine [string]$payload['oid'] -or [string]$me['userPrincipalName'] -ine $expected){throw 'Unexpected Graph account.'}
   [string]$payload['tid']
  } $graph.AccessToken $expectedUser
  $tenant=[guid]::Empty;if(-not [guid]::TryParse($identity,[ref]$tenant) -or $tenant -eq [guid]::Empty){throw 'Invalid tenant identity.'}
  $stage='Inventory'
  $discovery=[pscustomobject]@{CatalogContentSha256=('0'*64);Applications=@(
   [pscustomobject]@{AppId='14d82eec-204b-4c2f-b7e8-296a70dab67e';Name='Fixed Graph bootstrap';Sources=@();PublicClient=$true;Foci=$null;RedirectUris=@('https://login.microsoftonline.com/common/oauth2/nativeclient');PreferredRedirectUri='https://login.microsoftonline.com/common/oauth2/nativeclient';Grants=@();OwnerTenantId=$null;Ownership='Unverified';IsResourceCandidate=$false;IdentifierUris=@()},
   [pscustomobject]@{AppId='00000003-0000-0000-c000-000000000000';Name='Microsoft Graph';Sources=@();PublicClient=$false;Foci=$null;RedirectUris=@();PreferredRedirectUri='';Grants=@();OwnerTenantId=$null;Ownership='Unverified';IsResourceCandidate=$true;IdentifierUris=@()})}
  $inventory=Get-TokenForgeTenantInventory -GraphToken $graph.AccessToken -Discovery $discovery
  if($inventory.TenantFingerprint -cne $expectedTenant -or $inventory.PrincipalFingerprint -cne $expectedPrincipal -or $inventory.GrantEnumeration -cne 'Complete'){throw 'Fresh inventory context or grants unavailable.'}
  $ids=@('14d82eec-204b-4c2f-b7e8-296a70dab67e','00000003-0000-0000-c000-000000000000')
  $inventory.Applications=@($inventory.Applications|Where-Object AppId -In $ids)
  $inventory.TenantGrants=@($inventory.TenantGrants|Where-Object {$_.ClientId -eq $ids[0] -and $_.ResourceId -eq $ids[1]})
  $inventoryJson=$inventory|ConvertTo-Json -Depth 40
  $null=[TokenForge.Core.ScopePlanning]::BootstrapRequest($inventoryJson,$tenant.ToString(),$ids[0],1)
  if([TokenForge.Core.ScopePlanning]::PlanRequests($inventoryJson,'{"SchemaVersion":1,"Observations":[],"RegistrationAttempts":[]}',$ids[1],@('User.Read'),$expectedPrincipal,$tenant.ToString(),$false,$false,$true,1,1,1).Length -ne 1){throw 'Fixed cold candidate unavailable.'}
 }finally{
  if($graph){foreach($name in @('AccessToken','RefreshToken')){if($graph.$name){$graph.$name.Dispose()}}}
  if($session){$session.Dispose()};if($signer){$signer.Dispose()}
  foreach($name in @('TOKENFORGE_COOKIE_NAME','TOKENFORGE_TENANT_FINGERPRINT','TOKENFORGE_PRINCIPAL_FINGERPRINT')){[Environment]::SetEnvironmentVariable($name,$null)}
 }

 $profileResults=@()
 foreach($storage in @('Memory','Passphrase')){
  $stage=$storage+'Create';$profiles=Join-Path $root ($storage+'-profiles');$state=Join-Path $root ($storage+'-state')
  $inventoryPath=[TokenForge.Core.V0220.PrivateFiles]::Resolve((Join-Path $state 'inventory.json'),$true)
  $bytes=[Text.Encoding]::UTF8.GetBytes($inventoryJson)
  try{$file=[TokenForge.Core.V0220.PrivateFiles]::Open($inventoryPath,$true);try{$file.Write($bytes)}finally{$file.Dispose()}}finally{[Security.Cryptography.CryptographicOperations]::ZeroMemory($bytes)}
  $null=Invoke-TfNativeValidationCommand @invoke -Arguments @('profile','create','--profile','lab','--storage',$storage,'--root',$profiles,'--state-path',$state,'--tenant',$tenant.ToString(),'--bootstrap-client',$ids[0],'--max-extra-scopes','128','--max-bootstrap-extra-scopes','128','--max-age-hours','1')
  $password=$null;$credentialOptions=@()
  if($storage -eq 'Passphrase'){$random=[Security.Cryptography.RandomNumberGenerator]::GetBytes(32);try{$password=[Convert]::ToBase64String($random)}finally{[Security.Cryptography.CryptographicOperations]::ZeroMemory($random)};$credentialOptions=@('--stdin')}
  try{
   $stage=$storage+'Login'
   $login=Invoke-TfNativeValidationCommand @invoke -Arguments (@('login','--profile','lab','--root',$profiles,'--passkey-file',$keyPath)+$credentialOptions) -InputValue $password
   $persisted=$storage -eq 'Passphrase'
   if($login.Result.CookieSaved -ne $persisted -or $login.Result.CredentialOutput -or $login.Result.SignatureValidated){throw 'Invalid login status.'}
   $config=Get-Content (Join-Path $profiles 'lab/profile.json') -Raw|ConvertFrom-Json
   if($config.ExpectedTenantFingerprint -cne $expectedTenant -or $config.ExpectedPrincipalFingerprint -cne $expectedPrincipal){throw 'Incorrect native identity binding.'}
   $get=@('token','get','--profile','lab','--root',$profiles,'--scope','User.Read','--max-candidates','1','--max-redirects','1','--api-uri','https://graph.microsoft.com/v1.0/me','--json')+$credentialOptions
   if(-not $persisted){$get+=@('--passkey-file',$keyPath)}
   $stage=$storage+'Cold';$cold=Invoke-TfNativeValidationCommand @invoke -Arguments $get -InputValue $password
   $stage=$storage+'Repeat';$repeat=Invoke-TfNativeValidationCommand @invoke -Arguments $get -InputValue $password
   $expectedRepeat=if($persisted){'CachedVerifiedContextNotNewIssuance'}else{'SilentExplicitScopeAcquisition'}
   if($cold.Evidence -cne 'BoundedTargetedSilentExplicitScopeAcquisition' -or $repeat.Evidence -cne $expectedRepeat){throw 'Unexpected issuance/cache evidence.'}
   foreach($result in @($cold,$repeat)){
    if($result.ClientId -cne $ids[0] -or $result.ResourceId -cne $ids[1] -or $result.RequestedScopes.Count -ne 1 -or $result.RequestedScopes[0] -cne 'User.Read' -or $result.ApiCheck.Status -ne 200 -or $result.CredentialOutput){throw 'Unexpected native token/API evidence.'}
   }
   $vault=Join-Path $profiles 'lab/session.tfvault'
   if([bool](Test-Path $vault) -ne $persisted){throw 'Unexpected credential persistence.'}
   foreach($file in Get-ChildItem $state -File -Filter '*.json'){Assert-TfNativeMetadata (Get-Content $file.FullName -Raw|ConvertFrom-Json -AsHashtable)}
   $stage=$storage+'Logout';$logout=Invoke-TfNativeValidationCommand @invoke -Arguments (@('logout','--profile','lab','--root',$profiles)+$credentialOptions) -InputValue $password
   if(-not $logout.Removed -or $logout.Evidence -cne 'LocalLogoutNotServerRevocation'){throw 'Invalid logout evidence.'}
   if($persisted){
    # Logout removes this session, preserving the encrypted vault container.
    $empty=Invoke-TfNativeValidationCommand @invoke -Arguments @('profile','inspect-vault','--profile','lab','--root',$profiles,'--stdin') -InputValue $password
    if($empty.Sessions.Count -ne 0){throw 'Logout retained credential sessions.'}
   }elseif(Test-Path $vault){throw 'Memory profile created a credential vault.'}
   $profileResults+=@{Storage=$storage;NativeLogin=$true;NativeWithoutPowerShell=$true;IdentityBound=$true;CookieSaved=$persisted;CredentialVaultCreated=$persisted;Cold=$cold.Evidence;Repeat=$repeat.Evidence;ApiStatuses=@(200,200);CredentialOutput=$false;LogoutSucceeded=$true;MaximumAdditionalScopes=128;MaximumBootstrapAdditionalScopes=128;InventoryMaxAgeHours=1}
  }finally{$password=$null}
 }
 $stage='OriginalKey';if($PasskeyPath -and (Get-FileHash -LiteralPath $original).Hash -cne $originalHash){throw 'Original software passkey changed.'}
 $report=[ordered]@{SchemaVersion=1;DateUTC=[DateTimeOffset]::UtcNow.ToString('yyyy-MM-dd');Runtime=$Runtime;Version=$version.Version;SourceCommit=$SourceCommit;RunAttempt=$RunAttempt;ExecutableSha256=(Get-FileHash $exe).Hash.ToLowerInvariant();CredentialAssemblySha256=(Get-FileHash (Join-Path $package 'src/TokenForge/lib/net8.0/TokenForge.Credentials.dll')).Hash.ToLowerInvariant();ExpectedAccountIndependentlyConfirmed=$true;FreshInventoryConfirmed=$true;Profiles=$profileResults;OriginalPasskeyUnchanged=$true;OwnedPrivateStateRemoved=$true;CredentialsPublished=$false;ConsentChanges=$false;RegistrationsCreated=$false;SignatureValidated=$false;Scope='FixedGraphUserReadForOneLabAccountNotUniversalFlowSupport'}
}catch{$failed=$true}
finally{
 $inputValues.Clear();foreach($name in $secretNames){[Environment]::SetEnvironmentVariable($name,$null)}
 if($root -and (Test-Path -LiteralPath $root)){Remove-Item -LiteralPath $root -Recurse -Force}
 if($root -and (Test-Path -LiteralPath $root)){throw 'Native authentication private-state cleanup failed.'}
}
if($failed){throw "Native authentication validation failed during $stage; details suppressed."}
# Only this fixed projection leaves private storage, after successful cleanup.
$report|ConvertTo-Json -Depth 10|Set-Content -LiteralPath $ReportPath
'NATIVE_AUTHENTICATION_VALIDATION_OK'
