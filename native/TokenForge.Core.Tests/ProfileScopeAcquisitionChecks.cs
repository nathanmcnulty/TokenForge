using System.Security;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using TokenForge.Core;
using TokenForge.Core.V0180;

static class ProfileScopeAcquisitionChecks
{
 public static void Run(Action<bool> check,Action<Action> reject)
 {
  const string graph="00000003-0000-0000-c000-000000000000",client="11111111-1111-1111-1111-111111111111",second="22222222-2222-2222-2222-222222222222",bootstrap="33333333-3333-3333-3333-333333333333";
  const string tenant="aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",principal="bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb",native="https://login.microsoftonline.com/common/oauth2/nativeclient";
  string Hash(string value)=>Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(value))).ToLowerInvariant();
  string root=Path.Combine(Path.GetTempPath(),"TokenForge-fresh-checks-"+Guid.NewGuid().ToString("N"));
  if(OperatingSystem.IsMacOS() && root.StartsWith("/var/"))root="/private"+root;
  using var cookie=Secret("synthetic-cookie");
  try
  {
   var profile=JsonNode.Parse(ProfileStore.Create("lab",tenant,root))!.AsObject();
   profile["ExpectedTenantFingerprint"]=Hash(tenant);profile["ExpectedPrincipalFingerprint"]=Hash(tenant+"/"+principal);profile["BootstrapClientId"]=bootstrap;
   JsonObject App(string id)=>new(){["AppId"]=id,["Registration"]="Present",["Ownership"]="VerifiedMicrosoftOwner",["AccountEnabled"]=true,["RedirectUris"]=new JsonArray(native,"http://localhost/"),["PublishedGrants"]=new JsonArray(new JsonObject{["ResourceId"]=graph,["Scopes"]=new JsonArray("Mail.Read")})};
   var inventory=new JsonObject{["TenantFingerprint"]=Hash(tenant),["CapturedAt"]=DateTimeOffset.UtcNow.ToString("o"),["GrantEnumeration"]="Complete",["Applications"]=new JsonArray(App(client),App(second),App(bootstrap),App(graph)),["TenantGrants"]=new JsonArray()};
   inventory["Applications"]![3]!["DelegatedScopeDefinitions"]=new JsonArray(new JsonObject{["Value"]="User.Read",["Enabled"]=true});
   var empty=new JsonObject{["SchemaVersion"]=1,["Observations"]=new JsonArray()};
   var warm=empty.DeepClone().AsObject();warm["Observations"]!.AsArray().Add(new JsonObject{["ClientId"]=client,["ResourceId"]=graph,["TenantFingerprint"]=Hash(tenant),["PrincipalFingerprint"]=Hash(tenant+"/"+principal),["ObservedAt"]=DateTimeOffset.UtcNow.ToString("o"),["Outcome"]="Succeeded",["NamespaceVerification"]="Matched",["RequestVerification"]="Matched",["ScpScopes"]=new JsonArray("Mail.Read"),["RequestedScopes"]=new JsonArray("Mail.Read"),["Protocol"]="OAuth2V2Pkce"});
   ProfileCredentialToken Token(ScopePlanning.RequestRow row,string? oid=null,string? scope=null,int minutes=60,int extras=0)
   {
    string jwt="e30."+Convert.ToBase64String(JsonSerializer.SerializeToUtf8Bytes(new{tid=tenant,oid=oid??principal,appid=row.ClientId,aud=graph,scp=scope??string.Join(" ",row.Scopes),exp=DateTimeOffset.UtcNow.AddMinutes(minutes).ToUnixTimeSeconds()})).TrimEnd('=').Replace('+','-').Replace('/','_')+".synthetic";
    using var access=Secret(jwt);using var refresh=Secret("synthetic-refresh");
    return new ProfileCredentialToken(row.ToTransport(),access,refresh,DateTimeOffset.UtcNow.AddHours(1),extras);
   }
   ProfileCredentialToken Acquire(JsonObject db,Func<ScopePlanning.RequestRow,ProfileCredentialToken> execute,Action<string>? checkpoint=null,Func<SecureString,string>? identity=null,CancellationToken ct=default,bool browser=false)=>
    ProfileScopeAcquisition.Acquire("lab",profile.ToJsonString(),inventory.ToJsonString(),db.ToJsonString(),graph,new[]{"Mail.Read"},browser?null:cookie,maxCandidates:2,execute:execute,readIdentity:identity,checkpoint:checkpoint,cancellation:ct,browser:browser);
   int calls=0,writes=0;ProfileCredentialToken? supplied=null;string? saved=null;
   using(var result=Acquire(empty,row=>{calls++;return supplied=Token(row);},value=>{writes++;saved=value;}))
   {check(result.Evidence=="BoundedTargetedSilentExplicitScopeAcquisition" && result.TokenClaims.Scopes.SequenceEqual(new[]{"Mail.Read"}));check(result.AccessToken.Length>0);}
   check(calls==1 && writes==1 && cookie.Length>0);reject(()=>{_ = supplied!.AccessToken.Length;});
   using(var observation=JsonDocument.Parse(saved!)){var r=observation.RootElement;check(r.GetProperty("PrincipalFingerprint").GetString()==Hash(tenant+"/"+principal));check(r.GetProperty("RequestedScopes")[0].GetString()=="Mail.Read");check(!saved!.Contains("synthetic"));}
   var history=empty.DeepClone().AsObject();history["Observations"]!.AsArray().Add(JsonNode.Parse(saved!));history["RegistrationAttempts"]=new JsonArray();
   using(var merged=JsonDocument.Parse(EvidenceStore.AppendPortableObservation(history.ToJsonString(),saved!)))check(merged.RootElement.GetProperty("Observations").GetArrayLength()==2);
   history["Observations"]![0]!["Cookie"]="synthetic-private";reject(()=>EvidenceStore.AppendPortableObservation(history.ToJsonString(),saved!));
   reject(()=>EvidenceStore.AppendPortableObservation("{\"SchemaVersion\":1,\"Observations\":[],\"observations\":[]}",saved!));
   calls=0;reject(()=>Acquire(empty,row=>{calls++;return supplied=Token(row);},_=>throw new Exception("synthetic-private")));check(calls==1);reject(()=>{_ = supplied!.AccessToken.Length;});
   calls=0;reject(()=>Acquire(empty,row=>{calls++;return Token(row);}));check(calls==0); // Cold evidence must be checkpointed.
   calls=0;using(var result=Acquire(empty,row=>{calls++;if(calls==1){row.Scopes[0]="Other.Read";row.OAuthScopes[0]=graph+"/Other.Read";}return Token(row);},_=>{}))check(result.Request.Scopes.SequenceEqual(new[]{"Mail.Read"}));check(calls==2);
   foreach(string poison in new[]{"identity","scope-case","expiry","claim-extras","response-extras"})
   {
    calls=0;writes=0;reject(()=>Acquire(empty,row=>{calls++;return supplied=Token(row,poison=="identity"?Guid.NewGuid().ToString():null,poison=="scope-case"?"mail.read":poison=="claim-extras"?"Mail.Read Other.Read":null,poison=="expiry"?1:60,poison=="response-extras"?1:0);},_=>writes++));
    check(calls==2 && writes==0);reject(()=>{_ = supplied!.AccessToken.Length;});
   }
   calls=0;ProfileCredentialToken? bootstrapToken=null;int identities=0;
   using(var result=Acquire(warm,row=>{calls++;if(row.ClientId==bootstrap)return bootstrapToken=Token(row);reject(()=>{_ = bootstrapToken!.AccessToken.Length;});return Token(row);},_=>throw new Exception(),token=>{identities++;check(token.Length>0);return principal;}))check(result.Evidence=="SilentExplicitScopeAcquisition");
   check(calls==2 && identities==1);
   calls=0;reject(()=>Acquire(warm,row=>{calls++;return Token(row);},_=>writes++,token=>Guid.NewGuid().ToString()));check(calls==1); // Failed warm observer never falls back to cold.
   calls=0;inventory["Applications"]![3]!["DelegatedScopeDefinitions"]![0]!["Enabled"]=false;
   reject(()=>Acquire(warm,row=>{calls++;return Token(row);},identity:_=>principal));check(calls==0);
   inventory["Applications"]![3]!["DelegatedScopeDefinitions"]![0]!["Enabled"]=true;
   using var cancel=new CancellationTokenSource();calls=0;writes=0;
   reject(()=>Acquire(empty,row=>{calls++;supplied=Token(row);cancel.Cancel();return supplied;},_=>writes++,ct:cancel.Token));check(calls==1 && writes==0);reject(()=>{_ = supplied!.AccessToken.Length;});
   calls=0;writes=0;
   using(var result=Acquire(empty,row=>{calls++;check(row.RedirectUri=="http://localhost/");return Token(row);},_=>writes++,browser:true))
    check(result.Evidence=="BoundedTargetedSilentExplicitScopeAcquisition" && result.Request.OAuthScopes.Contains("offline_access"));
   check(calls==1 && writes==1 && cookie.Length>0);
   calls=0;identities=0;
   using(var result=Acquire(warm,row=>{calls++;check(row.RedirectUri=="http://localhost/");return Token(row);},identity:_=>{identities++;return principal;},browser:true))
    check(result.Evidence=="SilentExplicitScopeAcquisition");
   check(calls==2 && identities==1);
   reject(()=>ProfileScopeAcquisition.Acquire("lab",profile.ToJsonString(),inventory.ToJsonString(),empty.ToJsonString(),graph,new[]{"Mail.Read"},null,checkpoint:_=>{},browser:true));
   calls=0;inventory["CapturedAt"]=DateTimeOffset.UtcNow.AddDays(-2).ToString("o");reject(()=>Acquire(empty,row=>{calls++;return Token(row);},_=>{}));check(calls==0);
  }
  finally{if(Directory.Exists(root))Directory.Delete(root,true);}
 }
 static SecureString Secret(string text){var value=new SecureString();foreach(char c in text)value.AppendChar(c);return value;}
}
