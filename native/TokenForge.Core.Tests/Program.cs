using System.Text.Json;
using Microsoft.Data.Sqlite;
using TokenForge.Core;
using TokenForge.Core.V0100;

var count=0;
void Check(bool condition){if(!condition) throw new Exception("Check failed.");count++;}
void Reject(Action action){try{action();}catch{count++;return;}throw new Exception("Expected rejection.");}
var now=DateTimeOffset.UtcNow;
int Policy(string tenant="a",string audience="https://graph.microsoft.com",string[]? scopes=null,int extras=0,DateTimeOffset? expiry=null) =>
 TokenPolicy.Validate(tenant,"b","c",audience,"a","b","c","00000003-0000-0000-c000-000000000000",scopes??new[]{"User.Read","openid"},new[]{"User.Read"},true,expiry??now.AddHours(1),now.AddHours(1),0,extras,false,now);
Check(Policy()==0);Reject(()=>Policy(tenant:"wrong"));Reject(()=>Policy(audience:"https://example.test"));Reject(()=>Policy(scopes:new[]{"User.Read","Mail.Read"}));Reject(()=>Policy(extras:1));Reject(()=>Policy(expiry:now.AddMinutes(1)));Reject(()=>Policy(extras:-1));
Reject(()=>TokenPolicy.Validate("a","b","","https://graph.microsoft.com","a","b","","00000003-0000-0000-c000-000000000000",new[]{"User.Read"},new[]{"User.Read"},true,now.AddHours(1),now.AddHours(1),0,0,false,now));
var root=Path.Combine(Path.GetTempPath(),"TokenForge-core-test-"+Guid.NewGuid());
if(OperatingSystem.IsMacOS() && root.StartsWith("/var/")) root="/private"+root;
var path=Path.Combine(root,"evidence.sqlite");
var row=new Dictionary<string,object?>{{"ClientId","11111111-1111-1111-1111-111111111111"},{"ResourceId","00000003-0000-0000-c000-000000000000"},{"Outcome","Succeeded"},{"TenantFingerprint",new string('a',64)},{"PrincipalFingerprint",new string('b',64)},{"ObservedAt",now.ToString("o")},{"ScpScopes",new[]{"User.Read"}},{"NamespaceVerification","Matched"},{"RequestVerification","Matched"}};
string Input(params object[] rows)=>JsonSerializer.Serialize(new{SchemaVersion=1,Observations=rows,RegistrationAttempts=Array.Empty<object>()});
try
{
 using(var store=new EvidenceStore(path))
 {
  var legacy=JsonSerializer.Serialize(new{SchemaVersion=1,Observations=Array.Empty<object>(),RegistrationAttempts=new[]{new{AppId=Guid.Empty.ToString(),TenantFingerprint=new string('a',64),AttemptedAt=now.ToString("o"),Outcome="Failed",HttpStatus=400}}});
  Check(store.Import(legacy,"synthetic-history")==0);Check(JsonDocument.Parse(store.Export()).RootElement.GetProperty("RegistrationAttempts").GetArrayLength()==1);
  Check(store.Import(Input(row),"synthetic-source")==1);Check(store.Import(Input(row),"synthetic-source")==0);
  var bad=new Dictionary<string,object?>(row){{"AccessToken","synthetic-secret"}};var second=new Dictionary<string,object?>(row);second["ClientId"]="22222222-2222-2222-2222-222222222222";
  Reject(()=>store.Import(Input(second,bad),"synthetic-source"));Check(JsonDocument.Parse(store.Export()).RootElement.GetProperty("Observations").GetArrayLength()==1);
  Check(!store.Export(true).Contains("TenantFingerprint"));Check(!store.Export(true).Contains("PrincipalFingerprint"));Check(!store.Export().Contains("synthetic-secret"));
  Reject(()=>store.Plan(new[]{Guid.Empty.ToString()},1));
  var members=new[]{"22222222-2222-2222-2222-222222222222","11111111-1111-1111-1111-111111111111"};
  var plan=store.Plan(members,1);Check(plan==store.Plan(members.Reverse(),1));Check(JsonDocument.Parse(store.Pending(plan)).RootElement.GetArrayLength()==2);
  store.Complete(plan,members[0],"Failed");var pending=JsonDocument.Parse(store.Pending(plan)).RootElement;Check(pending.GetArrayLength()==1);Check(pending[0].GetProperty("Chunk").GetInt32()==0);
  using(var raw=new SqliteConnection(new SqliteConnectionStringBuilder{DataSource=path,Pooling=false}.ToString()))
  {
   raw.Open();using var command=raw.CreateCommand();
   command.CommandText="INSERT INTO registration_attempts VALUES('synthetic', $payload);";
   command.Parameters.AddWithValue("$payload","{\"AppId\":\"11111111-1111-1111-1111-111111111111\",\"AccessToken\":\"synthetic-secret\"}");command.ExecuteNonQuery();
   Reject(()=>store.Export());command.CommandText="DELETE FROM registration_attempts;";command.Parameters.Clear();command.ExecuteNonQuery();
   command.CommandText="UPDATE plans SET payload='[\"synthetic-secret\"]' WHERE id=$id;";command.Parameters.AddWithValue("$id",plan);command.ExecuteNonQuery();
   Reject(()=>store.Pending(plan));
  }
  Reject(()=>store.Complete(plan,"33333333-3333-3333-3333-333333333333","Succeeded"));
 }
 using(var reopened=new EvidenceStore(path,true)){Check(JsonDocument.Parse(reopened.Export()).RootElement.GetProperty("Observations").GetArrayLength()==1);}
 if(!OperatingSystem.IsWindows())
 {
  Check(((int)File.GetUnixFileMode(path)&63)==0);
  File.SetUnixFileMode(path,UnixFileMode.UserRead|UnixFileMode.UserWrite|UnixFileMode.GroupRead);
  Reject(()=>{using var unsafeStore=new EvidenceStore(path);});
  File.SetUnixFileMode(path,UnixFileMode.UserRead|UnixFileMode.UserWrite);
  var link=Path.Combine(root,"linked.sqlite");File.CreateSymbolicLink(link,path);Reject(()=>{using var linked=new EvidenceStore(link);});
 }

}
finally{Directory.Delete(root,true);}

// Explicit synthetic integration checks: no tenant authentication or production credentials.
if(args.Contains("--os-store"))
{
 var handle=Convert.ToHexString(System.Security.Cryptography.RandomNumberGenerator.GetBytes(32)).ToLowerInvariant();
 var other=Convert.ToHexString(System.Security.Cryptography.RandomNumberGenerator.GetBytes(32)).ToLowerInvariant();
 try
 {
  Reject(()=>TokenForge.Core.V0110.PlatformVaultKey.Open(handle,false));
  using var first=TokenForge.Core.V0110.PlatformVaultKey.Open(handle,true);
  using var reopened=TokenForge.Core.V0110.PlatformVaultKey.Open(handle,false);
  using var duplicate=TokenForge.Core.V0110.PlatformVaultKey.Open(handle,true);
  Check(first.Length==44 && reopened.Length==44);
  Check(new System.Net.NetworkCredential("",first).Password==new System.Net.NetworkCredential("",reopened).Password);
  Check(new System.Net.NetworkCredential("",first).Password==new System.Net.NetworkCredential("",duplicate).Password);
  Reject(()=>TokenForge.Core.V0110.PlatformVaultKey.Open(other,false));
  var write=typeof(TokenForge.Core.V0110.PlatformVaultKey).GetMethod("Write",System.Reflection.BindingFlags.NonPublic|System.Reflection.BindingFlags.Static)!;
  write.Invoke(null,new object[]{handle,new string('!',44)});
  Reject(()=>TokenForge.Core.V0110.PlatformVaultKey.Open(handle,true)); // Corruption cannot trigger replacement.
  TokenForge.Core.V0110.PlatformVaultKey.Delete(handle);
  Reject(()=>TokenForge.Core.V0110.PlatformVaultKey.Open(handle,false));
  TokenForge.Core.V0110.PlatformVaultKey.Delete(handle); // Idempotent cleanup.
  Console.WriteLine("Synthetic OS-store create/reopen/retain/corruption/delete checks passed.");
 }
 finally {TokenForge.Core.V0110.PlatformVaultKey.Delete(handle);}
}
Reject(()=>TokenForge.Core.V0110.PlatformVaultKey.Open("invalid",true));

FlowEvidenceTests.Run(Check, Reject);
Console.WriteLine($"{count} native checks passed, including flow evidence transactions and resume.");
return 0;
