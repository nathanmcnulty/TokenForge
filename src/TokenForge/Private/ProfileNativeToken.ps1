# Bridge the existing planner to the shared in-process credential lifecycle.
function Get-TokenForgePersistedProfileToken {
 param($Record,[string]$Name,[string]$Root,[securestring]$Password,[string]$LoginHint,[guid]$ResourceId,[string[]]$Scope,[int]$MaxCandidates,[int]$MaxRedirects)
 $p=$Record.Configuration
 $copyResult={param($token,$request,$evidence)
  $plan=[TokenForge.Core.V0180.OAuthRequest]::new()
  foreach($field in @('ClientId','ResourceId','Tenant','RedirectUri')){$plan.$field=[string]$request.$field}
  $plan.ResourceUri=$plan.ResourceId;$plan.Scopes=[string[]]@($request.Scopes);$plan.OAuthScopes=[string[]]@($request.OAuthScopes);$plan.Spa=[bool]$request.Spa;$plan.Protocol='OAuth2V2Pkce'
  $extras=if($token.PSObject.Properties['AdditionalScopes']){@($token.AdditionalScopes).Count}else{0}
  [TokenForge.Core.ProfileCredentialToken]::new($plan,$token.AccessToken,$token.RefreshToken,[Nullable[DateTimeOffset]]$token.ExpiresAt,$extras,$evidence)
 }
 $fresh=[Func[TokenForge.Core.ProfileFreshRequest,TokenForge.Core.ProfileCredentialToken]] {
  param($inputRequest)
  $auth=if($inputRequest.Cookie){@{EstsAuth=$inputRequest.Cookie;CookieName=$inputRequest.CookieName}}else{@{Browser=$true;NoConsent=$true;LoginHint=$LoginHint}}
  $issued=$null
  try {
   $issued=Request-TokenForgeProfileScope -Profile $p -ResourceId $ResourceId -Scope $Scope -Authentication $auth -MaxCandidates $MaxCandidates -MaxRedirects $MaxRedirects
   & $copyResult $issued $issued.Request $issued.Evidence
  }finally{if($issued){$issued.AccessToken.Dispose();if($issued.RefreshToken){$issued.RefreshToken.Dispose()}}}
 }
 $renew=[Func[TokenForge.Core.V0180.OAuthRequest,securestring,TokenForge.Core.ProfileCredentialToken]] {
  param($request,$refresh)
  $issued=$null
  try{$issued=Get-TokenForgeToken -Request $request -RefreshToken $refresh;& $copyResult $issued $request 'SameClientRefreshMatchedIssuedContext'}
  finally{if($issued){$issued.AccessToken.Dispose();if($issued.RefreshToken){$issued.RefreshToken.Dispose()}}}
 }
 $native=$null;$access=$null;$refresh=$null
 try {
  $native=[TokenForge.Core.ProfileTokenLifecycle]::Acquire($Name,$Root,$ResourceId.ToString(),[string[]]$Scope,$Password,$fresh,$renew,[Threading.CancellationToken]::None,$Record.ConfigurationJson)
  $access=$native.AccessToken.Copy();if($native.RefreshToken){$refresh=$native.RefreshToken.Copy()}
  $claims=$native.TokenClaims
  $result=[pscustomobject]@{PSTypeName='TokenForge.Token';AccessToken=$access;RefreshToken=$refresh;Request=$native.Request;ClientId=$native.Request.ClientId;ResourceId=$native.Request.ResourceId;RequestedScopes=@($native.Request.Scopes);GrantedScopes=@($claims.Scopes);AdditionalScopes=@($claims.Scopes|Where-Object {$_ -cnotin $native.Request.Scopes -and $_ -cnotin @('openid','profile','email','offline_access')});ScopeEvidence='JwtPayloadUnverified';ExpiresAt=$native.ExpiresAt;Protocol=$native.Request.Protocol;Evidence=$native.Evidence;TokenClaims=$claims}
  $access=$null;$refresh=$null;$result
 }finally{if($native){$native.Dispose()};if($access){$access.Dispose()};if($refresh){$refresh.Dispose()}}
}
