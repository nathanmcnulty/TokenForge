#Requires -Version 7.4
[CmdletBinding()]
param(
 [Parameter(Position=0,Mandatory)][ValidateSet('profile','login','logout','status','doctor','token','scopes','graph')][string]$Command,
 [Parameter(Position=1)][ValidateSet('create','forget-key','show','get','explain','permissions','connect','disconnect')][string]$Operation,
 [ValidatePattern('^[a-z][a-z0-9_-]{0,63}$')][string]$Profile='default',
 [string]$Root,[string]$Tenant,[string]$StatePath,
 [ValidateSet('Memory','Passphrase','OperatingSystem')][string]$Storage='Memory',
 [ValidateSet('graph','arm')][string]$Resource='graph',[string[]]$Scope,
 [securestring]$VaultPassword,[securestring]$EstsAuth,
 [string]$PasskeyPath,[string]$XdrModulePath,[ValidateLength(0,320)][string]$LoginHint,[switch]$Browser,[switch]$Interactive,
 [guid]$BootstrapClientId='038ddad9-5bbe-4f64-b0cd-12434d1e633b',
 [ValidateRange(0,8760)][int]$MaxAdditionalScopes=0,[ValidateRange(0,8760)][int]$MaxBootstrapAdditionalScopes=0,
 [uri]$ApiUri,[string]$GraphCommand,[switch]$PromptPassphrase,[switch]$Json
)
$ErrorActionPreference='Stop'
$manifest=Join-Path $PSScriptRoot '../src/TokenForge/TokenForge.psd1'
if(-not (Get-Module TokenForge)){Import-Module $manifest}
$common=@{Name=$Profile;Root=$Root}
try{
 if($PromptPassphrase){
  if($VaultPassword){throw 'Choose a provided passphrase or an interactive prompt.'}
  $VaultPassword=Read-Host 'Vault passphrase' -AsSecureString
 }
 if($Scope -and $Scope.Count -eq 1 -and $Scope[0].Contains(',')){$Scope=@($Scope[0].Split(','))}
 $result=switch($Command){
  profile {
   switch($Operation){
    create {if(-not $Tenant){throw 'Tenant is required.'};New-TokenForgeProfile @common -Tenant $Tenant -StatePath $StatePath -Storage $Storage -BootstrapClientId $BootstrapClientId -MaxAdditionalScopes $MaxAdditionalScopes -MaxBootstrapAdditionalScopes $MaxBootstrapAdditionalScopes -PasskeyPath $PasskeyPath -XdrModulePath $XdrModulePath}
    forget-key {Remove-TokenForgeProfileKey @common}
    show {Get-TokenForgeProfile @common}
    default {throw 'Use profile create or profile show.'}
   }
  }
  login {Connect-TokenForgeProfile @common -VaultPassword $VaultPassword -EstsAuth $EstsAuth -Browser:$Browser -Interactive:$Interactive -LoginHint $LoginHint}
  logout {Disconnect-TokenForgeProfile @common -VaultPassword $VaultPassword}
  status {Get-TokenForgeProfileStatus @common -VaultPassword $VaultPassword}
  doctor {Test-TokenForgeProfile @common -VaultPassword $VaultPassword}
  token {
   if($Operation -ne 'get' -or -not $Scope){throw 'Use token get -Scope with explicit API scopes.'}
   $token=Get-TokenForgeProfileToken @common -VaultPassword $VaultPassword -Resource $Resource -Scope $Scope -ApiUri $ApiUri -LoginHint $LoginHint
   try{[pscustomobject]@{SchemaVersion=1;Profile=$Profile;ClientId=$token.Request.ClientId;ResourceId=$token.Request.ResourceId;RequestedScopes=@($token.Request.Scopes);IssuedScopes=@($token.TokenClaims.Scopes);ExpiresAt=$token.ExpiresAt;Evidence=$token.Evidence;ApiCheck=$token.ApiCheck;CredentialOutput=$false}}
   finally{$token.AccessToken.Dispose();if($token.RefreshToken){$token.RefreshToken.Dispose()}}
  }
  scopes {
   if($Operation -ne 'explain' -or -not $Scope){throw 'Use scopes explain -Scope with explicit API scopes.'}
   $p=Get-TokenForgeProfile @common
   if(-not $p.ExpectedPrincipalFingerprint){throw 'Log in before selecting account-specific evidence.'}
   $id=if($Resource -eq 'graph'){'00000003-0000-0000-c000-000000000000'}else{'797f4846-ba00-4fd7-ba43-dac1f8f63013'}
   Get-TokenForgeScopeCandidates -Inventory (Get-Content (Join-Path $p.StatePath inventory.json) -Raw|ConvertFrom-Json) -Database (Get-TokenForgeScopeDatabase (Join-Path $p.StatePath scopes.json)) -ResourceId $id -Scope $Scope -PrincipalFingerprint $p.ExpectedPrincipalFingerprint -MaxAgeHours $p.MaxAgeHours
  }
  graph {
   switch($Operation){
    permissions {Find-TokenForgeGraphPermission -Command $GraphCommand}
    connect {Connect-TokenForgeGraph @common -VaultPassword $VaultPassword -Scope $Scope}
    disconnect {Disconnect-TokenForgeGraph}
    default {throw 'Use graph permissions, graph connect, or graph disconnect in a dedicated PowerShell process.'}
   }
  }
 }
 if($Json){ConvertTo-Json -InputObject $result -Depth 15}else{$result}
 $global:LASTEXITCODE=0
}catch{
 # Do not echo dependency exception messages or invocation lines that may contain credentials.
 if($Json){[pscustomobject]@{SchemaVersion=1;Succeeded=$false;Code='OperationFailed';Message='Operation failed. Use the module API for bounded diagnostic errors.'}|ConvertTo-Json -Compress}else{Write-Warning 'Operation failed. Use the module API for bounded diagnostic errors.'}
 $global:LASTEXITCODE=1
 if($MyInvocation.InvocationName -ne '.'){exit 1}
}finally{if($PromptPassphrase -and $VaultPassword){$VaultPassword.Dispose()}}
