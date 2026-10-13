using System.Security;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using TokenForge.Core;
using TokenForge.Core.V0180;
using TokenForge.Core.V0190;
using TokenForge.Core.V0220;

static class ProfileTokenLifecycleChecks
{
 public static void Run(Action<bool> check,Action<Action> reject)
 {
  string root=Path.Combine(Path.GetTempPath(),"TokenForge-lifecycle-"+Guid.NewGuid().ToString("N"));
  if(OperatingSystem.IsMacOS() && root.StartsWith("/var/"))root="/private"+root;
  using var password=Secret("synthetic-lifecycle-passphrase");using var wrong=Secret("synthetic-wrong-passphrase");
  const string resource="00000003-0000-0000-c000-000000000000",client="11111111-1111-1111-1111-111111111111";
  string tenant="aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",principal="bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb";
  string Hash(string value)=>Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(value))).ToLowerInvariant();
  string Jwt(int minutes=60,string? oid=null,string scopes="User.Read")=>"e30."+Convert.ToBase64String(JsonSerializer.SerializeToUtf8Bytes(new{tid=tenant,oid=oid??principal,appid=client,aud=resource,scp=scopes,exp=DateTimeOffset.UtcNow.AddMinutes(minutes).ToUnixTimeSeconds()})).TrimEnd('=').Replace('+','-').Replace('/','_')+".synthetic";
  var request=new OAuthRequest{ClientId=client,ResourceId=resource,ResourceUri=resource,Tenant=tenant,RedirectUri="http://localhost/",Scopes=new[]{"User.Read"},OAuthScopes=new[]{resource+"/User.Read","offline_access"}};
  ProfileCredentialToken Token(OAuthRequest? r=null,bool refresh=true,string? oid=null,string scopes="User.Read")
  {using var access=Secret(Jwt(60,oid,scopes));using var rt=refresh?Secret("synthetic-refresh"):null;return new ProfileCredentialToken(r??request,access,rt,DateTimeOffset.UtcNow.AddHours(1));}
  try
  {
   var profile=JsonNode.Parse(ProfileStore.Create("lab",tenant,root))!.AsObject();string path=Path.Combine(root,"lab","profile.json"),vault=Path.Combine(root,"lab","session.tfvault");
   profile["ExpectedTenantFingerprint"]=Hash(tenant);profile["ExpectedPrincipalFingerprint"]=Hash(tenant+"/"+principal);File.WriteAllText(path,profile.ToJsonString());
   var now=DateTimeOffset.UtcNow;
   JsonObject Fixture()=>new(){["SchemaVersion"]=1,["Sessions"]=new JsonObject{["lab"]=new JsonObject{["TenantFingerprint"]=Hash(tenant),["PrincipalFingerprint"]=Hash(tenant+"/"+principal),["Revision"]=Guid.NewGuid().ToString(),["CreatedAt"]=now.AddHours(-1).ToString("o"),["LastConfirmedAt"]=now.AddHours(-1).ToString("o"),["RetainUntil"]=now.AddHours(2).ToString("o"),["Cookie"]="synthetic-cookie",["CookieName"]="ESTSAUTH",["Tokens"]=new JsonObject()}}};
   void Write(JsonObject value){byte[] bytes=JsonSerializer.SerializeToUtf8Bytes(value);try{using var tx=VaultFileTransaction.Begin(vault,File.Exists(vault)?"Update":"Create");if(File.Exists(vault))tx.ReadEnvelope();tx.Commit(VaultEnvelope.Encrypt(bytes,password));}finally{Array.Clear(bytes);}}
   JsonObject Read(){byte[] bytes=VaultEnvelope.Decrypt(File.ReadAllBytes(vault),password);try{return JsonNode.Parse(bytes)!.AsObject();}finally{Array.Clear(bytes);}}
   var fixture=Fixture();fixture["Sessions"]!["other"]=fixture["Sessions"]!["lab"]!.DeepClone();Write(fixture);
   string original=File.ReadAllText(path);int fresh=0,renew=0;ProfileCredentialToken? supplied=null;
   using(var issued=ProfileTokenLifecycle.Acquire("lab",root,resource,new[]{"User.Read"},password,input=>{fresh++;check(input.Cookie!.Length>0 && input.CookieName=="ESTSAUTH");return supplied=Token();}))
   {check(issued.Evidence=="SilentExplicitScopeAcquisition" && issued.TokenClaims.Scopes.SequenceEqual(new[]{"User.Read"}));check(issued.AccessToken.Length>0);check(!JsonSerializer.Serialize(issued).Contains("synthetic-refresh"));}
   reject(()=>{_ = supplied!.AccessToken.Length;});check(fresh==1 && File.ReadAllText(path)==original);
   var saved=Read();check(JsonNode.DeepEquals(saved["Sessions"]!["other"],fixture["Sessions"]!["other"]));
   foreach(string field in new[]{"Cookie","CookieName","RetainUntil","LastConfirmedAt","CreatedAt"})check(JsonNode.DeepEquals(saved["Sessions"]!["lab"]![field],fixture["Sessions"]!["lab"]![field]));
   byte[] before=File.ReadAllBytes(vault);
   using(var cached=ProfileTokenLifecycle.Acquire("lab",root,resource,new[]{"User.Read"},password,input=>{fresh++;return Token();},(r,s)=>{renew++;return Token(r);}))check(cached.Evidence=="CachedVerifiedContextNotNewIssuance");
   check(fresh==1 && renew==0 && File.ReadAllBytes(vault).SequenceEqual(before));
   var expired=saved.DeepClone().AsObject();var token=expired["Sessions"]!["lab"]!["Tokens"]!.AsObject().First().Value!;
   token["AccessToken"]=Jwt(-10);token["ExpiresAt"]=DateTimeOffset.UtcNow.AddMinutes(-10).ToString("o");Write(expired);
   using(var renewed=ProfileTokenLifecycle.Acquire("lab",root,resource,new[]{"User.Read"},password,input=>{fresh++;return Token();},(r,s)=>{renew++;check(r.ClientId==client && s.Length>0);return Token(r,false);}))check(renewed.Evidence=="SameClientRefreshMatchedIssuedContext" && renewed.RefreshToken!.Length>0);
   check(renew==1 && fresh==1);var after=Read();var renewedEntry=after["Sessions"]!["lab"]!["Tokens"]!.AsObject().First().Value!;
   check(renewedEntry["RefreshToken"]!.GetValue<string>()=="synthetic-refresh");check(JsonNode.DeepEquals(after["Sessions"]!["other"],fixture["Sessions"]!["other"]));
   foreach(string field in new[]{"Cookie","RetainUntil","LastConfirmedAt","CreatedAt"})check(JsonNode.DeepEquals(after["Sessions"]!["lab"]![field],fixture["Sessions"]!["lab"]![field]));
   foreach(var poison in new[]{"identity","expiry","authority","scopes"})
   {
    var bad=expired.DeepClone().AsObject();var entry=bad["Sessions"]!["lab"]!["Tokens"]!.AsObject().First().Value!;
    if(poison=="identity")entry["AccessToken"]=Jwt(-10,"cccccccc-cccc-cccc-cccc-cccccccccccc");
    if(poison=="expiry")entry["ExpiresAt"]=null;
    if(poison=="authority")entry["Tenant"]="other.example";
    if(poison=="scopes")entry["AccessToken"]=Jwt(-10,scopes:"User.Read Other.Read");
    Write(bad);before=File.ReadAllBytes(vault);int attempts=0;
    reject(()=>ProfileTokenLifecycle.Acquire("lab",root,resource,new[]{"User.Read"},password,input=>{attempts++;return Token();},(r,s)=>{attempts++;return Token(r);}));
    check(attempts==0 && File.ReadAllBytes(vault).SequenceEqual(before));
   }
   Write(expired);before=File.ReadAllBytes(vault);int fallbacks=0;
   reject(()=>ProfileTokenLifecycle.Acquire("lab",root,resource,new[]{"User.Read"},password,input=>{fallbacks++;return Token();},(r,s)=>throw new Exception("synthetic-private")));
   check(fallbacks==0 && File.ReadAllBytes(vault).SequenceEqual(before));
   Write(Fixture());before=File.ReadAllBytes(vault);using var cancellation=new CancellationTokenSource();
   reject(()=>ProfileTokenLifecycle.Acquire("lab",root,resource,new[]{"User.Read"},password,input=>{supplied=Token();cancellation.Cancel();return supplied;},cancellation:cancellation.Token));
   reject(()=>{_ = supplied!.AccessToken.Length;});check(File.ReadAllBytes(vault).SequenceEqual(before));
   reject(()=>ProfileTokenLifecycle.Acquire("lab",root,resource,new[]{"User.Read"},wrong,input=>Token()));check(File.ReadAllBytes(vault).SequenceEqual(before));
   foreach(string leaf in new[]{".operation.lock","session.tfvault.lock"}){using var held=PrivateFiles.Open(Path.Combine(root,"lab",leaf),false);reject(()=>ProfileTokenLifecycle.Acquire("lab",root,resource,new[]{"User.Read"},password,input=>Token()));}
   reject(()=>ProfileTokenLifecycle.Acquire("lab",root,resource,new[]{"User.Read"},password,input=>{var changed=Read();changed["Sessions"]!.AsObject().Remove("lab");Write(changed);return supplied=Token();}));
   check(Read()["Sessions"]!.AsObject().Count==0);reject(()=>{_ = supplied!.AccessToken.Length;});
   Write(Fixture());before=File.ReadAllBytes(vault);
   reject(()=>ProfileTokenLifecycle.Acquire("lab",root,resource,new[]{"User.Read"},password,input=>{var p=JsonNode.Parse(File.ReadAllText(path))!;p["Revision"]=Guid.NewGuid().ToString();File.WriteAllText(path,p.ToJsonString());return supplied=Token();}));
   check(File.ReadAllBytes(vault).SequenceEqual(before));reject(()=>{_ = supplied!.AccessToken.Length;});File.WriteAllText(path,original);
   int staleCalls=0;var stale=JsonNode.Parse(original)!;stale["Revision"]=Guid.NewGuid().ToString();
   reject(()=>ProfileTokenLifecycle.Acquire("lab",root,resource,new[]{"User.Read"},password,input=>{staleCalls++;return Token();},expectedProfileJson:stale.ToJsonString()));check(staleCalls==0);
   using(var tx=VaultFileTransaction.Begin(vault,"Read")){check(tx.ReadEnvelope().SequenceEqual(before));}
  }
  finally{if(Directory.Exists(root))Directory.Delete(root,true);}
 }
 public static void RunMemory(Action<bool> check,Action<Action> reject)
 {
  const string tenant="aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",principal="bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb",client="11111111-1111-1111-1111-111111111111",resource="00000003-0000-0000-c000-000000000000";
  string Hash(string s)=>Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(s))).ToLowerInvariant();
  string root=Path.Combine(Path.GetTempPath(),"TokenForge-memory-checks-"+Guid.NewGuid().ToString("N"));if(OperatingSystem.IsMacOS()&&root.StartsWith("/var/"))root="/private"+root;
  ProfileCredentialToken Token(string? oid=null,string scope="User.Read",DateTimeOffset? expiry=null,string evidence="SilentExplicitScopeAcquisition")
  {
   var until=expiry??DateTimeOffset.UtcNow.AddHours(1);
   var request=new OAuthRequest{ClientId=client,ResourceId=resource,ResourceUri=resource,Tenant=tenant,RedirectUri="http://localhost/",Scopes=new[]{"User.Read"},OAuthScopes=new[]{resource+"/User.Read"}};
   string jwt="e30."+Convert.ToBase64String(JsonSerializer.SerializeToUtf8Bytes(new{tid=tenant,oid=oid??principal,appid=client,aud=resource,scp=scope,exp=until.ToUnixTimeSeconds()})).TrimEnd('=').Replace('+','-').Replace('/','_')+".synthetic-memory";
   using var secret=Secret(jwt);return new ProfileCredentialToken(request,secret,null,until,evidence:evidence);
  }
  try
  {
   string path=Path.Combine(root,"lab","profile.json"),vault=Path.Combine(root,"lab","session.tfvault");
   var profile=JsonNode.Parse(ProfileStore.Create("lab",tenant,root,storage:"Memory"))!.AsObject();int calls=0;
   reject(()=>ProfileTokenLifecycle.AcquireMemory("lab",root,resource,new[]{"User.Read"},_=>{calls++;return Token();}));check(calls==0 && !File.Exists(vault));
   profile["ExpectedTenantFingerprint"]=Hash(tenant);profile["ExpectedPrincipalFingerprint"]=Hash(tenant+"/"+principal);string configuration=profile.ToJsonString()+"\n";File.WriteAllText(path,configuration);
   ProfileCredentialToken? supplied=null;
   using(var result=ProfileTokenLifecycle.AcquireMemory("lab",root,resource,new[]{"User.Read"},input=>{calls++;check(input.Cookie==null);input.Scopes[0]="Mail.Read";return supplied=Token();},expectedProfileJson:configuration))
    check(result.TokenClaims.Scopes.SequenceEqual(new[]{"User.Read"}) && !JsonSerializer.Serialize(result).Contains("synthetic-memory"));
   reject(()=>{_=supplied!.AccessToken.Length;});check(ProfileStore.Read("lab",root)==configuration && !File.Exists(vault));
   foreach(string poison in new[]{"identity","scope","expiry","cache"})
   {
    reject(()=>ProfileTokenLifecycle.AcquireMemory("lab",root,resource,new[]{"User.Read"},_=>supplied=Token(poison=="identity"?Guid.NewGuid().ToString():null,poison=="scope"?"User.Read Mail.Read":"User.Read",poison=="expiry"?DateTimeOffset.UtcNow.AddSeconds(30):null,poison=="cache"?"CachedVerifiedContextNotNewIssuance":"SilentExplicitScopeAcquisition")));
    reject(()=>{_=supplied!.AccessToken.Length;});check(ProfileStore.Read("lab",root)==configuration && !File.Exists(vault));
   }
   using(var held=PrivateFiles.Open(Path.Combine(root,"lab",".operation.lock"),false))
   {int before=calls;reject(()=>ProfileTokenLifecycle.AcquireMemory("lab",root,resource,new[]{"User.Read"},_=>{calls++;return Token();}));check(calls==before);}
   using var cancellation=new CancellationTokenSource();
   reject(()=>ProfileTokenLifecycle.AcquireMemory("lab",root,resource,new[]{"User.Read"},_=>{cancellation.Cancel();return supplied=Token();},cancellation.Token));reject(()=>{_=supplied!.AccessToken.Length;});
   var changed=profile.DeepClone().AsObject();changed["Revision"]=Guid.NewGuid().ToString();string replacement=changed.ToJsonString();
   reject(()=>ProfileTokenLifecycle.AcquireMemory("lab",root,resource,new[]{"User.Read"},_=>{File.WriteAllText(path,replacement);return supplied=Token();}));
   reject(()=>{_=supplied!.AccessToken.Length;});check(ProfileStore.Read("lab",root)==replacement && !File.Exists(vault));File.WriteAllText(path,configuration);
   int stale=0;reject(()=>ProfileTokenLifecycle.AcquireMemory("lab",root,resource,new[]{"User.Read"},_=>{stale++;return Token();},expectedProfileJson:replacement));check(stale==0);
   var instant=DateTimeOffset.UtcNow;int clocks=0;var core=typeof(ProfileTokenLifecycle).GetMethod("AcquireMemoryCore",System.Reflection.BindingFlags.NonPublic|System.Reflection.BindingFlags.Static)!;
   reject(()=>core.Invoke(null,new object?[]{"lab",root,resource,new[]{"User.Read"},(Func<ProfileFreshRequest,ProfileCredentialToken>)(_=>supplied=Token(expiry:instant.AddMinutes(5))),CancellationToken.None,configuration,(Func<DateTimeOffset>)(()=>++clocks==1?instant:instant.AddMinutes(4))}));
   check(clocks==2 && ProfileStore.Read("lab",root)==configuration && !File.Exists(vault));reject(()=>{_=supplied!.AccessToken.Length;});
   ProfileStore.Create("saved",tenant,root);int savedCalls=0;reject(()=>ProfileTokenLifecycle.AcquireMemory("saved",root,resource,new[]{"User.Read"},_=>{savedCalls++;return Token();}));check(savedCalls==0);
   check(Directory.EnumerateFiles(Path.Combine(root,"lab")).Select(Path.GetFileName).OrderBy(x=>x).SequenceEqual(new[]{".operation.lock","profile.json"}));
  }
  finally{if(Directory.Exists(root))Directory.Delete(root,true);}
 }
 private static SecureString Secret(string text){var s=new SecureString();foreach(char c in text)s.AppendChar(c);return s;}
}
