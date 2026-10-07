using System.Text.Json;
using Microsoft.Data.Sqlite;
using TokenForge.Core;
internal static class ScopeHistoryTests
{
 public static int Run()
 {
  var count=0;void Check(bool value){if(!value)throw new Exception("Scope history check failed.");count++;}
  void Reject(Action action){try{action();}catch{count++;return;}throw new Exception("Expected scope history rejection.");}
  var root=Path.Combine(Path.GetTempPath(),"TokenForge-scope-tests-"+Guid.NewGuid());if(OperatingSystem.IsMacOS()&&root.StartsWith("/var/"))root="/private"+root;
  var path=Path.Combine(root,"scopes.sqlite");var client="11111111-1111-1111-1111-111111111111";var resource="00000003-0000-0000-c000-000000000000";var tenant=new string('a',64);var principal=new string('b',64);var other=new string('c',64);
  object Observation(string date,string user,string outcome="Succeeded")=>new{ClientId=client,ResourceId=resource,TenantFingerprint=tenant,PrincipalFingerprint=user,ObservedAt=date,Outcome=outcome,ScpScopes=new[]{"User.Read"},NamespaceVerification="Matched",RequestVerification="Matched"};
  object Attempt(string date,string outcome)=>new{AppId=client,TenantFingerprint=tenant,AttemptedAt=date,Outcome=outcome,HttpStatus=(int?)null};
  string Input(object[] rows,object[] attempts)=>JsonSerializer.Serialize(new{SchemaVersion=1,Observations=rows,RegistrationAttempts=attempts});
  try{
   using var store=new EvidenceStore(path);
   var input=Input(new[]{Observation("2026-10-01T00:00:00Z",principal),Observation("2026-10-02T00:00:00Z",principal,"Failed"),Observation("2026-10-01T00:00:00Z",other)},new[]{Attempt("2026-10-01T00:00:00Z","CleanupRequired"),Attempt("2026-10-02T00:00:00Z","CleanupResolved")});
   Check(store.Import(input,"fixture")==3);Check(store.Import(input,"fixture")==0);
   using(var full=JsonDocument.Parse(store.Export())){Check(full.RootElement.GetProperty("Observations").GetArrayLength()==3);Check(full.RootElement.GetProperty("RegistrationAttempts")[1].GetProperty("Outcome").GetString()=="CleanupResolved");}
   using(var current=JsonDocument.Parse(store.Export(latest:true,tenant:tenant,principal:principal,resource:resource))){Check(current.RootElement.GetProperty("Observations").GetArrayLength()==1);Check(current.RootElement.GetProperty("Observations")[0].GetProperty("Outcome").GetString()=="Failed");Check(current.RootElement.GetProperty("RegistrationAttempts")[0].GetProperty("Outcome").GetString()=="CleanupResolved");}
   Check(JsonDocument.Parse(store.Export(latest:true,tenant:other,principal:principal)).RootElement.GetProperty("Observations").GetArrayLength()==0);
   Reject(()=>store.Export(tenant:tenant+"\n"));
   Reject(()=>store.Export(principal:principal));
   Reject(()=>store.Import(Input(new[]{Observation("2026-10-03T00:00:00Z",principal),new{AccessToken="private"}},Array.Empty<object>()),"fixture"));
   Check(JsonDocument.Parse(store.Export()).RootElement.GetProperty("Observations").GetArrayLength()==3);
   Reject(()=>store.Import("{\"SchemaVersion\":1,\"SchemaVersion\":1,\"Observations\":[],\"RegistrationAttempts\":[]}","fixture"));
   using(var raw=new SqliteConnection(new SqliteConnectionStringBuilder{DataSource=path,Pooling=false}.ToString())){raw.Open();using var command=raw.CreateCommand();command.CommandText="UPDATE observations SET client='22222222-2222-2222-2222-222222222222';";command.ExecuteNonQuery();Reject(()=>store.Export());}
  }finally{Directory.Delete(root,true);}
  return count;
 }
}
