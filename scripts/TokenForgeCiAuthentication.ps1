# Shared only by the two CI metadata producers; authentication context is identical.
function Get-TfCiGraphSession {
 [CmdletBinding()]
 param([Parameter(Mandatory)][securestring]$EstsAuth)
 $session=$null
 try {
 # Fixed Microsoft Graph Command Line Tools bootstrap. Entra enforces existing consent.
 # This client is absent from the published scope dataset; the request is not catalog evidence.
 $request=[pscustomobject]@{ClientId='14d82eec-204b-4c2f-b7e8-296a70dab67e';ResourceId='00000003-0000-0000-c000-000000000000';ResourceUri='00000003-0000-0000-c000-000000000000';Scopes=@('User.Read');OAuthScopes=@('00000003-0000-0000-c000-000000000000/User.Read');RedirectUri='https://login.microsoftonline.com/common/oauth2/nativeclient';Tenant='organizations';Spa=$false;Discovery=$false}
 $session=Get-TokenForgeToken -Request $request -EstsAuth $EstsAuth -CookieName $env:TOKENFORGE_COOKIE_NAME
 $claims=$session.TokenClaims
 if($env:TOKENFORGE_TENANT_FINGERPRINT -notmatch '^[a-f0-9]{64}$' -or $env:TOKENFORGE_PRINCIPAL_FINGERPRINT -notmatch '^[a-f0-9]{64}$' -or
    $claims.TenantFingerprint -cne $env:TOKENFORGE_TENANT_FINGERPRINT -or $claims.PrincipalFingerprint -cne $env:TOKENFORGE_PRINCIPAL_FINGERPRINT -or
    $claims.ClientId -cne $request.ClientId -or $claims.Audience -notin @($request.ResourceId,'https://graph.microsoft.com','https://graph.microsoft.com/')){throw 'Bootstrap context mismatch.'}
 & (Get-Module TokenForge) {
  param($token)
  $payload=ConvertFrom-TokenForgeJwtPayload -AccessToken $token.AccessToken
  $me=Invoke-TokenForgeGraph -AccessToken $token.AccessToken -Uri 'https://graph.microsoft.com/v1.0/me?$select=id'
  if([string]$me['id'] -ine [string]$payload['oid']){throw 'Graph identity mismatch.'}
 } $session
 $session
 }catch{
  if($session){foreach($name in @('AccessToken','RefreshToken')){if($session.PSObject.Properties[$name] -and $session.$name){$session.$name.Dispose()}}}
  throw 'CI bootstrap identity verification failed; details suppressed.'
 }
}
