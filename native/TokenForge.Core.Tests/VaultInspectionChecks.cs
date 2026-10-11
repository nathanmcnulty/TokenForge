using System.Security;
using System.Text.Json;
using System.Text.Json.Nodes;
using TokenForge.Core;
using TokenForge.Core.V0190;
using TokenForge.Core.V0220;

static class VaultInspectionChecks
{
 public static void Run(Action<bool> check,Action<Action> reject)
 {
  string root=Path.Combine(Path.GetTempPath(),"TokenForge-inspection-"+Guid.NewGuid().ToString("N"));
  if(OperatingSystem.IsMacOS() && root.StartsWith("/var/"))root="/private"+root;
  using var password=new SecureString();foreach(char c in "synthetic-inspection-passphrase")password.AppendChar(c);
  using var wrong=new SecureString();foreach(char c in "synthetic-wrong-passphrase")wrong.AppendChar(c);
  string id=new string('c',64),tenant=new string('a',64),principal=new string('b',64);
  try {
   reject(()=>ProfileStore.InspectVault("lab",root,password));check(!Directory.Exists(root));
   var p=JsonNode.Parse(ProfileStore.Create("lab","example.test",root))!.AsObject();
   string profilePath=Path.Combine(root,"lab","profile.json"),vaultPath=Path.Combine(root,"lab","session.tfvault");
   p["ExpectedTenantFingerprint"]=tenant;p["ExpectedPrincipalFingerprint"]=principal;File.WriteAllText(profilePath,p.ToJsonString());
   reject(()=>ProfileStore.InspectVault("lab",root,password));check(!File.Exists(vaultPath));
   var now=DateTimeOffset.UtcNow;
   JsonObject Fixture()=>new() { ["SchemaVersion"]=1,["Sessions"]=new JsonObject { ["Lab"]=new JsonObject {
    ["TenantFingerprint"]=tenant,["PrincipalFingerprint"]=principal,["Revision"]=Guid.NewGuid().ToString(),["CreatedAt"]=now.AddHours(-2).ToString("o"),["LastConfirmedAt"]=now.AddHours(-1).ToString("o"),["RetainUntil"]=now.AddMinutes(-5).UtcDateTime.ToString("o"),["Cookie"]="synthetic-cookie",["CookieName"]="ESTSAUTH",["Tokens"]=new JsonObject { [id]=new JsonObject {
     ["Id"]=id,["ClientId"]="11111111-1111-1111-1111-111111111111",["ResourceId"]="00000003-0000-0000-c000-000000000000",["Tenant"]="example.test",["Audience"]="00000003-0000-0000-c000-000000000000",["Scopes"]=new JsonArray("User.Read"),["IssuedScopes"]=new JsonArray("User.Read"),["AdditionalScopeCount"]=0,["RedirectUri"]="http://localhost/",["Spa"]=false,["OfflineAccess"]=true,["Protocol"]="OAuth2V2Pkce",["AcquiredAt"]=now.ToString("o"),["ExpiresAt"]=now.AddHours(2).UtcDateTime.ToString("o"),["AccessToken"]="synthetic-access",["RefreshToken"]="synthetic-refresh",["ConsentEvidence"]="SyntheticOnly"
    } } } } };
   void Write(JsonObject value){var bytes=JsonSerializer.SerializeToUtf8Bytes(value);try{using var tx=VaultFileTransaction.Begin(vaultPath,File.Exists(vaultPath)?"Update":"Create");if(File.Exists(vaultPath))tx.ReadEnvelope();tx.Commit(VaultEnvelope.Encrypt(bytes,password));}finally{Array.Clear(bytes);}}
   Write(Fixture());byte[] before=File.ReadAllBytes(vaultPath);
   var result=ProfileStore.InspectVault("lab",root,password);check(result.Sessions.Length==1);check(result.Sessions[0].Name=="Lab");check(result.Sessions[0].RetentionExpired);
   check(result.Sessions[0].HasCookie && result.Sessions[0].Tokens[0].HasRefreshToken);check(result.Sessions[0].Tokens[0].ExpiryStatus=="WithinReportedLifetime");
   check(result.Evidence=="StoredMetadataNotNewIssuanceOrApiAuthorization" && !result.Sessions[0].Tokens[0].SignatureValidated);
   string output=JsonSerializer.Serialize(result);check(!output.Contains("synthetic-cookie") && !output.Contains("synthetic-access") && !output.Contains("synthetic-refresh"));
   check(File.ReadAllBytes(vaultPath).SequenceEqual(before));check(password.Length==31);
   reject(()=>ProfileStore.InspectVault("lab",root));reject(()=>ProfileStore.InspectVault("lab",root,wrong));check(password.Length==31 && wrong.Length==26);
   foreach(string leaf in new[]{".operation.lock","session.tfvault.lock"}){using var held=PrivateFiles.Open(Path.Combine(root,"lab",leaf),false);reject(()=>ProfileStore.InspectVault("lab",root,password));}
   check(File.ReadAllBytes(vaultPath).SequenceEqual(before));
   var unknown=Fixture();unknown["Sessions"]!["Lab"]!["Cookie"]=null;unknown["Sessions"]!["Lab"]!["Tokens"]![id]!["ExpiresAt"]=null;unknown["Sessions"]!["Lab"]!["Tokens"]![id]!["RefreshToken"]=null;Write(unknown);
   var view=ProfileStore.InspectVault("lab",root,password);check(!view.Sessions[0].HasCookie && !view.Sessions[0].Tokens[0].HasRefreshToken && view.Sessions[0].Tokens[0].ExpiryStatus=="Unknown");
   var near=Fixture();near["Sessions"]!["Lab"]!["Tokens"]![id]!["ExpiresAt"]=now.AddMinutes(1).ToString("o");Write(near);check(ProfileStore.InspectVault("lab",root,password).Sessions[0].Tokens[0].ExpiryStatus=="ExpiredOrNearExpiry");
   var foreign=Fixture();foreign["Sessions"]!["Lab"]!["PrincipalFingerprint"]=new string('d',64);Write(foreign);reject(()=>ProfileStore.InspectVault("lab",root,password));
   var malformed=Fixture();malformed["Sessions"]!["Lab"]!["Tokens"]![id]!["ConsentEvidence"]=new JsonObject{["AccessToken"]="synthetic-private"};Write(malformed);reject(()=>ProfileStore.InspectVault("lab",root,password));
   try{ProfileStore.InspectVault("lab",root,password);throw new Exception("Expected rejection.");}catch(InvalidOperationException error){check(error.InnerException==null && !error.ToString().Contains("synthetic-private"));}
   var onlyOther=Fixture();var session=onlyOther["Sessions"]!["Lab"]!.DeepClone();onlyOther["Sessions"]!.AsObject().Clear();onlyOther["Sessions"]!["other"]=session;Write(onlyOther);check(ProfileStore.InspectVault("lab",root,password).Sessions.Length==0);
   var badBefore=File.ReadAllBytes(vaultPath);Write(malformed);badBefore=File.ReadAllBytes(vaultPath);
   reject(()=>ProfileStore.Logout("lab",root,password));check(File.ReadAllBytes(vaultPath).SequenceEqual(badBefore));
   Write(foreign);check(ProfileStore.Logout("lab",root,password).Removed);check(ProfileStore.InspectVault("lab",root,password).Sessions.Length==0);
   var expanded=Fixture();var large=Fixture()["Sessions"]!["Lab"]!.DeepClone();
   large["Cookie"]=new string('é',1000000);large["Tokens"]![id]!["AccessToken"]=new string('é',1000000);
   expanded["Sessions"]!["other"]=large;
   var compact=JsonSerializer.SerializeToUtf8Bytes(expanded,new JsonSerializerOptions{Encoder=System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping});
   try{using var tx=VaultFileTransaction.Begin(vaultPath,"Update");tx.ReadEnvelope();tx.Commit(VaultEnvelope.Encrypt(compact,password));}finally{Array.Clear(compact);}
   var boundedBefore=File.ReadAllBytes(vaultPath);SecureString? failurePassword=null;
   reject(()=>ProfileStore.Logout("lab",root,passwordProvider:()=>failurePassword=password.Copy()));
   reject(()=>{_ = failurePassword!.Length;});check(File.ReadAllBytes(vaultPath).SequenceEqual(boundedBefore));
   // Acquiring a new transaction proves failure released both profile and vault locks.
   using(var tx=VaultFileTransaction.Begin(vaultPath,"Read")){check(tx.ReadEnvelope().SequenceEqual(boundedBefore));}
   check(ProfileStore.InspectVault("lab",root,password).Sessions.Length==1);
   Write(Fixture());var preserved=Fixture()["Sessions"]!["Lab"]!.DeepClone();var multi=Fixture();multi["Sessions"]!["other"]=preserved.DeepClone();Write(multi);
   var profileBefore=File.ReadAllBytes(profilePath);var vaultBefore=File.ReadAllBytes(vaultPath);
   reject(()=>ProfileStore.Logout("lab",root,wrong));check(File.ReadAllBytes(vaultPath).SequenceEqual(vaultBefore));
   int prompts=0;
   foreach(string leaf in new[]{".operation.lock","session.tfvault.lock"}){using var held=PrivateFiles.Open(Path.Combine(root,"lab",leaf),false);reject(()=>ProfileStore.Logout("lab",root,passwordProvider:()=>{prompts++;return password.Copy();}));}
   check(prompts==0 && File.ReadAllBytes(vaultPath).SequenceEqual(vaultBefore));
   var loggedOut=ProfileStore.Logout("lab",root,password);check(loggedOut.Removed && loggedOut.Evidence=="LocalLogoutNotServerRevocation");check(File.ReadAllBytes(profilePath).SequenceEqual(profileBefore));check(password.Length==31);
   var remaining=VaultEnvelope.Decrypt(File.ReadAllBytes(vaultPath),password);
   try{var doc=JsonNode.Parse(remaining)!;check(doc["Sessions"]!.AsObject().Count==1 && JsonNode.DeepEquals(doc["Sessions"]!["other"],preserved));}finally{Array.Clear(remaining);}
   var after=File.ReadAllBytes(vaultPath);check(ProfileStore.Logout("lab",root,password).Removed && File.ReadAllBytes(vaultPath).SequenceEqual(after));
   Write(Fixture());SecureString? provided=null;check(ProfileStore.Logout("lab",root,passwordProvider:()=>provided=password.Copy()).Removed);reject(()=>{_ = provided!.Length;});check(password.Length==31);
   File.Delete(vaultPath);check(ProfileStore.Logout("lab",root,passwordProvider:()=>throw new Exception("synthetic-private")).Removed);check(!File.Exists(vaultPath));
   Write(Fixture());p["ExpectedTenantFingerprint"]=null;p["ExpectedPrincipalFingerprint"]=null;File.WriteAllText(profilePath,p.ToJsonString());reject(()=>ProfileStore.InspectVault("lab",root,password));
   p["Storage"]="Memory";File.WriteAllText(profilePath,p.ToJsonString());reject(()=>ProfileStore.InspectVault("lab",root,password));check(ProfileStore.Logout("lab",root).Removed);
  }finally{if(Directory.Exists(root))Directory.Delete(root,true);}
 }
}
