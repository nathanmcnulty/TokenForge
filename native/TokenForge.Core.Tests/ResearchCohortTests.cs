using System.Text.Json;
using Microsoft.Data.Sqlite;
using TokenForge.Core;
internal static class ResearchCohortTests
{
 public static int Run(){
  var count=0;void Check(bool condition){if(!condition)throw new Exception("Cohort check failed.");count++;}void Reject(Action action){try{action();}catch{count++;return;}throw new Exception("Expected cohort rejection.");}
  var root=Path.Combine(Path.GetTempPath(),"TokenForge-cohort-test-"+Guid.NewGuid());if(OperatingSystem.IsMacOS()&&root.StartsWith("/var/"))root="/private"+root;
  var path=Path.Combine(root,"scopes.sqlite");var one="11111111-1111-1111-1111-111111111111";var two="22222222-2222-2222-2222-222222222222";var graph="00000003-0000-0000-c000-000000000000";
  var document=new Dictionary<string,object?>{{"Format","TokenForgeResearchCohort"},{"SchemaVersion",1},{"CreatedAt","2026-10-07T00:00:00Z"},{"TenantFingerprint",new string('a',64)},{"PrincipalFingerprint",new string('b',64)},{"CatalogHash",new string('c',64)},{"InventoryHash",new string('d',64)},{"Authority","example.test"},{"Protocols",new[]{"OAuth2V2Pkce","OAuth2V1Implicit"}},{"MaxRedirects",1},{"ExploreAllFlows",true},{"Pairs",new[]{new{ClientId=two,ResourceId=graph},new{ClientId=one,ResourceId=graph}}}};
  try{using var store=new EvidenceStore(path);string Json()=>JsonSerializer.Serialize(document);
   var id=store.Cohort(Json(),1);Check(id==store.Cohort(Json(),1));Check(JsonDocument.Parse(store.Pending(id)).RootElement.GetArrayLength()==2);
   using(var exported=JsonDocument.Parse(store.ExportCohort(id))){Check(exported.RootElement.GetProperty("Cohort").GetProperty("Protocols")[0].GetString()=="OAuth2V2Pkce");Check(exported.RootElement.GetProperty("BatchSize").GetInt32()==1);}
   store.Complete(id,one,"Succeeded");Check(JsonDocument.Parse(store.Pending(id)).RootElement[0].GetProperty("Chunk").GetInt32()==1);
   document["PrincipalFingerprint"]=new string('e',64);var other=store.Cohort(Json(),1);Check(other!=id);Check(JsonDocument.Parse(store.Pending(other)).RootElement.GetArrayLength()==2);
   document["AccessToken"]="private";Reject(()=>store.Cohort(Json(),1));document.Remove("AccessToken");
   document["Authority"]="https://private.test/?credential=private";Reject(()=>store.Cohort(Json(),1));document["Authority"]=".bad";Reject(()=>store.Cohort(Json(),1));document["Authority"]="example.test";
   document["Pairs"]=new[]{new{ClientId=Guid.Empty.ToString(),ResourceId=graph}};Reject(()=>store.Cohort(Json(),1));
   var legacy=store.Plan(new[]{one,two},1);Check(JsonDocument.Parse(store.Pending(legacy)).RootElement.GetArrayLength()==2);Reject(()=>store.ExportCohort(legacy));
   using var raw=new SqliteConnection(new SqliteConnectionStringBuilder{DataSource=path,Pooling=false}.ToString());raw.Open();using var command=raw.CreateCommand();command.CommandText="UPDATE checkpoints SET outcome='private' WHERE plan=$plan;";command.Parameters.AddWithValue("$plan",id);command.ExecuteNonQuery();Reject(()=>store.Pending(id));
   command.CommandText="UPDATE plans SET payload='{}' WHERE id=$plan;";command.ExecuteNonQuery();Reject(()=>store.ExportCohort(id));
  }finally{Directory.Delete(root,true);}return count;
 }
}
