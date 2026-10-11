using System.Reflection;
using System.Security;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using TokenForge.Core;
using TokenForge.Core.V0110;
using TokenForge.Core.V0180;
using TokenForge.Core.V0190;
using TokenForge.Core.V0220;
using TokenForge.Core.V0230;
using TokenForge.Core.V0200;

static class ProfileLoginChecks
{
 const string Tenant="aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",Principal="bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb";
 const string Client="33333333-3333-3333-3333-333333333333",Graph="00000003-0000-0000-c000-000000000000";
 static string Hash(string text)=>Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(text))).ToLowerInvariant();
 static SecureString Secret(string text){var secret=new SecureString();foreach(char c in text)secret.AppendChar(c);return secret;}
 static string Inventory()
 {
  JsonObject App(string id)=>new(){["AppId"]=id,["Registration"]="Present",["Ownership"]="VerifiedMicrosoftOwner",["AccountEnabled"]=true,["RedirectUris"]=new JsonArray("http://localhost/")};
  var resource=App(Graph);resource["DelegatedScopeDefinitions"]=new JsonArray(new JsonObject{["Value"]="User.Read",["Enabled"]=true});
  return new JsonObject{["TenantFingerprint"]=Hash(Tenant),["CapturedAt"]=DateTimeOffset.UtcNow.ToString("o"),["Applications"]=new JsonArray(App(Client),resource),["TenantGrants"]=new JsonArray(),["GrantEnumeration"]="Complete"}.ToJsonString();
 }
 static ProfileCredentialToken Token(OAuthRequest request,DateTimeOffset expiry)
 {
  string jwt="e30."+Convert.ToBase64String(JsonSerializer.SerializeToUtf8Bytes(new{tid=Tenant,oid=Principal,appid=Client,aud=Graph,scp="User.Read",exp=expiry.ToUnixTimeSeconds()})).TrimEnd('=').Replace('+','-').Replace('/','_')+".synthetic";
  using var secret=Secret(jwt);return new ProfileCredentialToken(request,secret,null,expiry,0);
 }
 static string Root(){string root=Path.Combine(Path.GetTempPath(),"TokenForge-login-checks-"+Guid.NewGuid().ToString("N"));return OperatingSystem.IsMacOS()&&root.StartsWith("/var/")?"/private"+root:root;}
 public static void Run(Action<bool> check,Action<Action> reject)
 {
  string root=Root();using var password=Secret("synthetic-login-passphrase");
  try
  {
   foreach(string storage in new[]{"Passphrase","Memory"})
   {
    string name=storage.ToLowerInvariant();ProfileStore.Create(name,Tenant,root,storage:storage,bootstrapClient:Client);
    var supplied=new List<ProfileCredentialToken>();int identities=0;
    var result=ProfileLogin.Login(name,root,Inventory(),request=>{var token=Token(request,DateTimeOffset.UtcNow.AddHours(1));supplied.Add(token);return token;},storage=="Passphrase"?password:null,_=>{identities++;return Principal;});
    check(identities==1 && result.CookieSaved==false && result.CredentialOutput==false && !result.SignatureValidated);
    check(result.SessionState==(storage=="Memory"?"NotPersisted":"Available"));reject(()=>{_=supplied[0].AccessToken.Length;});
    using var bound=JsonDocument.Parse(ProfileStore.Read(name,root));check(bound.RootElement.GetProperty("ExpectedPrincipalFingerprint").GetString()==Hash(Tenant+"/"+Principal));
    string vault=Path.Combine(root,name,"session.tfvault");check(File.Exists(vault)==(storage=="Passphrase"));
    if(storage=="Passphrase")
    {
     byte[] decrypted=VaultEnvelope.Decrypt(File.ReadAllBytes(vault),password);
     try
     {
      var contents=JsonNode.Parse(decrypted)!.AsObject();var sessions=contents["Sessions"]!.AsObject();
      sessions["unrelated"]=sessions[name]!.DeepClone();string unrelated=sessions["unrelated"]!.ToJsonString();
      byte[] amended=JsonSerializer.SerializeToUtf8Bytes(contents);
      try{using var transaction=VaultFileTransaction.Begin(vault,"Update");CryptographicOperations.ZeroMemory(transaction.ReadEnvelope());transaction.Commit(VaultEnvelope.Encrypt(amended,password));}
      finally{CryptographicOperations.ZeroMemory(amended);}
      ProfileLogin.Login(name,root,Inventory(),request=>Token(request,DateTimeOffset.UtcNow.AddHours(1)),password,_=>Principal);
      byte[] after=VaultEnvelope.Decrypt(File.ReadAllBytes(vault),password);
      try{check(JsonNode.Parse(after)!["Sessions"]!["unrelated"]!.ToJsonString()==unrelated);}
      finally{CryptographicOperations.ZeroMemory(after);}
     }
     finally{CryptographicOperations.ZeroMemory(decrypted);}
    }
    string before=ProfileStore.Read(name,root);byte[]? ciphertext=File.Exists(vault)?File.ReadAllBytes(vault):null;
    reject(()=>ProfileLogin.Login(name,root,Inventory(),request=>Token(request,DateTimeOffset.UtcNow.AddHours(1)),storage=="Passphrase"?password:null,_=>Guid.NewGuid().ToString()));
    check(ProfileStore.Read(name,root)==before);if(ciphertext!=null)check(File.ReadAllBytes(vault).SequenceEqual(ciphertext));
    // Advance only the internal clock: acquisition and identity checks pass, commit-time validation fails.
    var instant=DateTimeOffset.UtcNow;int clocks=0;
    var core=typeof(ProfileLogin).GetMethod("LoginCore",BindingFlags.NonPublic|BindingFlags.Static)!;
    reject(()=>core.Invoke(null,new object?[]{name,root,Inventory(),(Func<OAuthRequest,ProfileCredentialToken>)(request=>Token(request,instant.AddMinutes(5))),storage=="Passphrase"?password:null,(Func<SecureString,string>)(_=>Principal),CancellationToken.None,(Func<DateTimeOffset>)(()=>++clocks>=4?instant.AddMinutes(4):instant)}));
    check(clocks==4);check(ProfileStore.Read(name,root)==before);if(ciphertext!=null)check(File.ReadAllBytes(vault).SequenceEqual(ciphertext));
    clocks=0;
    reject(()=>core.Invoke(null,new object?[]{name,root,Inventory(),(Func<OAuthRequest,ProfileCredentialToken>)(request=>Token(request,instant.AddHours(12))),storage=="Passphrase"?password:null,(Func<SecureString,string>)(_=>Principal),CancellationToken.None,(Func<DateTimeOffset>)(()=>++clocks>=4?instant.AddHours(9):instant)}));
    check(clocks==5);check(ProfileStore.Read(name,root)==before);if(ciphertext!=null)check(File.ReadAllBytes(vault).SequenceEqual(ciphertext));
    reject(()=>ProfileLogin.Login(name,root,Inventory(),request=>{request.Scopes[0]="Mail.Read";return Token(request,DateTimeOffset.UtcNow.AddHours(1));},storage=="Passphrase"?password:null,_=>Principal));
    check(ProfileStore.Read(name,root)==before);if(ciphertext!=null)check(File.ReadAllBytes(vault).SequenceEqual(ciphertext));
    using var canceled=new CancellationTokenSource();
    reject(()=>ProfileLogin.Login(name,root,Inventory(),request=>Token(request,DateTimeOffset.UtcNow.AddHours(1)),storage=="Passphrase"?password:null,_=>{canceled.Cancel();return Principal;},canceled.Token));
    check(ProfileStore.Read(name,root)==before);if(ciphertext!=null)check(File.ReadAllBytes(vault).SequenceEqual(ciphertext));
    if(storage=="Memory")
    {
     clocks=0;string profilePath=Path.Combine(root,name,"profile.json");
     var concurrent=JsonNode.Parse(before)!.AsObject();concurrent["Revision"]=Guid.NewGuid().ToString();string replacement=concurrent.ToJsonString();
     reject(()=>core.Invoke(null,new object?[]{name,root,Inventory(),(Func<OAuthRequest,ProfileCredentialToken>)(request=>Token(request,instant.AddHours(1))),null,(Func<SecureString,string>)(_=>Principal),CancellationToken.None,(Func<DateTimeOffset>)(()=>{if(++clocks==4)File.WriteAllText(profilePath,replacement);return instant;})}));
     check(clocks==5 && ProfileStore.Read(name,root)==replacement);
    }
    check(!Directory.EnumerateFiles(Path.Combine(root,name),".login-*.tmp").Any());
   }
  }
  finally{if(Directory.Exists(root))Directory.Delete(root,true);}
 }
 public static void RunOsStore(Action<bool> check,Action<Action> reject)
 {
  string root=Root();string? handle=null;
  try
  {
   ProfileStore.Create("lab",Tenant,root,storage:"OperatingSystem",bootstrapClient:Client);
   using var profile=JsonDocument.Parse(ProfileStore.Read("lab",root));
   handle=ProfileKeyIdentity.Compute(Path.Combine(root,"lab"),profile.RootElement.GetProperty("KeyId").GetString()!);
   string vault=Path.Combine(root,"lab","session.tfvault");int calls=0;
   Func<OAuthRequest,ProfileCredentialToken> acquire=_=>{calls++;throw new Exception("Acquisition must not run.");};
   using(var locked=VaultFileTransaction.Begin(vault,"Create"))
   {
    reject(()=>ProfileLogin.Login("lab",root,Inventory(),acquire));check(calls==0);
    reject(()=>PlatformVaultKey.Open(handle,false));check(!File.Exists(vault));
   }
   using(var key=PlatformVaultKey.Open(handle,true))
   {
    byte[] plain=Encoding.UTF8.GetBytes("{\"SchemaVersion\":1,\"Sessions\":{}}");
    try{using var create=VaultFileTransaction.Begin(vault,"Create");create.Commit(VaultEnvelope.Encrypt(plain,key));}
    finally{CryptographicOperations.ZeroMemory(plain);}
   }
   var inspection=ProfileStore.InspectVault("lab",root);
   check(inspection.Protection==(OperatingSystem.IsWindows()?"WindowsCredentialManager-AES-256-GCM":"LinuxSecretService-AES-256-GCM") && inspection.Sessions.Length==0);
   PlatformVaultKey.Delete(handle);byte[] before=File.ReadAllBytes(vault);
   reject(()=>ProfileLogin.Login("lab",root,Inventory(),acquire));check(calls==0 && File.ReadAllBytes(vault).SequenceEqual(before));
   reject(()=>PlatformVaultKey.Open(handle,false));check(!Directory.EnumerateFiles(Path.Combine(root,"lab"),".login-*.tmp").Any());
  }
  finally{if(handle!=null)PlatformVaultKey.Delete(handle);if(Directory.Exists(root))Directory.Delete(root,true);}
 }
}
