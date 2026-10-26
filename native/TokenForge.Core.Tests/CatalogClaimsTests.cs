using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.Data.Sqlite;
using TokenForge.Core;

static class CatalogClaimsTests
{
 public static void Run(Action<bool> check,Action<Action> reject)
 {
  string root=Path.Combine(Path.GetTempPath(),"TokenForge-catalog-claims-"+Guid.NewGuid());
  if(OperatingSystem.IsMacOS() && root.StartsWith("/var/"))root="/private"+root;
  const string id="11111111-1111-1111-1111-111111111111";
  string Hash(string text)=>Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(text))).ToLowerInvariant();
  string Bytes(string path){using var stream=new FileStream(path,FileMode.Open,FileAccess.Read,FileShare.ReadWrite);return Convert.ToHexString(SHA256.HashData(stream));}
  JsonObject Update(string alternate="Other",bool legacy=false,string kind="Discovery",string date="2026-01-01T00:00:00Z")
  {
   var attrs=new JsonObject{["AppId"]=id,["Name"]=legacy?alternate:"Selected",["PublicClient"]=true};
   if(!legacy){
    string first=DiscoverySourceClaims.Project("Published","https://raw.githubusercontent.com/example/public/main/apps.json","PublishedHint","{\"Name\":\"Selected\"}");
    string other=DiscoverySourceClaims.Project("Other","https://raw.githubusercontent.com/example/other/main/apps.json","PublishedHint",JsonSerializer.Serialize(new{Name=alternate}));
    var claims=JsonNode.Parse(DiscoverySourceClaims.Normalize("["+first+","+other+"]",id))!;
    attrs["SourceClaims"]=claims["SourceClaims"]!.DeepClone();attrs["MetadataConflicts"]=claims["MetadataConflicts"]!.DeepClone();
   }
   var sources=new JsonArray{new JsonObject{["Name"]="Published",["Location"]="https://raw.githubusercontent.com/example/public/main/apps.json",["Evidence"]="PublishedHint"}};
   var hashInput=new JsonObject{["Attributes"]=attrs.DeepClone(),["Sources"]=sources.DeepClone()}.ToJsonString();
   var record=new JsonObject{["Kind"]=kind,["TenantFingerprint"]=kind=="Discovery"?null:new string('a',64),["PrincipalFingerprint"]=null,["ResourceId"]=null,["FirstSeenAt"]=date,["LastSeenAt"]=date,["CurrentVersionFirstSeenAt"]=date,["PresentInLatestRun"]=true,["Attributes"]=attrs,["Sources"]=sources,["ContentSha256"]=Hash(hashInput),["PreviousVersions"]=new JsonArray()};
   var run=new JsonObject{["Id"]=Guid.NewGuid().ToString(),["Kind"]=kind,["ObservedAt"]=date,["RecordedAt"]="2026-01-30T00:00:00Z",["ApplicationRecordCount"]=1,["IgnoredEmptyAppIdCount"]=0,["TenantFingerprint"]=kind=="Discovery"?null:new string('a',64)};
   return new JsonObject{["Format"]="TokenForgeCatalogUpdate",["SchemaVersion"]=legacy?1:2,["Run"]=run,["Rows"]=new JsonArray{new JsonObject{["AppId"]=id,["Record"]=record,["HashInput"]=hashInput}}};
  }
  void LegacyMarker(string path)
  {
   using var connection=new SqliteConnection(new SqliteConnectionStringBuilder{DataSource=path,Pooling=false}.ToString());connection.Open();
   using var command=connection.CreateCommand();command.CommandText="PRAGMA wal_checkpoint(TRUNCATE); PRAGMA journal_mode=DELETE; PRAGMA user_version=1;";command.ExecuteNonQuery();
  }
  try {
   string path=Path.Combine(root,"v2.sqlite");
   using(var store=new ApplicationCatalogStore(path)){
    store.Update(Update().ToJsonString());store.Update(Update("Changed",date:"2026-01-02T00:00:00Z").ToJsonString());
    var exported=store.Export();ApplicationCatalogStore.ValidateDocument(exported);
    var report=JsonNode.Parse(ResearchCoverage.CreateFromValidatedDocuments(exported))!;
    check(report["ApplicationsWithMetadataConflicts"]!.GetValue<int>()==1);
    check(report["Applications"]![0]!["MetadataConflicts"]!.AsArray().Count==1);
    var ledger=JsonNode.Parse(exported)!;check(ledger["SchemaVersion"]!.GetValue<int>()==2);
    var record=ledger["Applications"]![id]!["Records"]!["Discovery///"]!;
    check(record["PreviousVersions"]!.AsArray().Count==1);check(record["Attributes"]!["SourceClaims"]!.AsArray().Count==2);
    var wrongEnvelope=Update();wrongEnvelope["SchemaVersion"]=1;reject(()=>store.Update(wrongEnvelope.ToJsonString()));check(store.Export()==exported);
    var forged=Update();forged["Rows"]![0]!["Record"]!["Attributes"]!["MetadataConflicts"]=new JsonArray();reject(()=>store.Update(forged.ToJsonString()));check(store.Export()==exported);
    record["PreviousVersions"]![0]!["Attributes"]!["SourceClaims"]![0]!["AccessToken"]="synthetic";reject(()=>store.Import(ledger.ToJsonString()));reject(()=>ApplicationCatalogStore.ValidateDocument(ledger.ToJsonString()));check(store.Export()==exported);
    store.Update(Update("2026-01-01T00:00:00+02:00",date:"2026-01-03T00:00:00Z").ToJsonString());
    var literal=DiscoverySourceClaims.ReadCatalog(store.Export());var literalJson=JsonSerializer.Serialize(literal);
    check(literalJson.Contains("2026-01-01T00:00:00\\u002B02:00") || literalJson.Contains("2026-01-01T00:00:00+02:00"));
   }
   string legacyPath=Path.Combine(root,"legacy.sqlite"),legacyExport;
   using(var store=new ApplicationCatalogStore(legacyPath)){
    store.Update(Update(legacy:true).ToJsonString());store.Update(Update("Legacy Changed",legacy:true,date:"2026-01-02T00:00:00Z").ToJsonString());
    store.Update(Update(legacy:true,kind:"Inventory").ToJsonString());legacyExport=store.Export();
   }
   LegacyMarker(legacyPath);string before=Bytes(legacyPath);
   string rollbackPath=Path.Combine(root,"legacy-restored.sqlite");
   if(OperatingSystem.IsLinux()){
    string backupPath=Path.Combine(root,"legacy-backup.sqlite");
    check(SqliteSnapshot.Save(legacyPath,backupPath,"applications").StoreVersion==1);
    check(SqliteSnapshot.Save(backupPath,rollbackPath,"applications").StoreVersion==1);
    check(Bytes(legacyPath)==before);
    using var restored=new ApplicationCatalogStore(rollbackPath,true);
    var expectedRollback=JsonNode.Parse(legacyExport)!;expectedRollback["SchemaVersion"]=1;
    check(JsonNode.DeepEquals(JsonNode.Parse(restored.Export()),expectedRollback));
   }
   using(var readOnly=new ApplicationCatalogStore(legacyPath,true)){
    var read=JsonNode.Parse(readOnly.Export())!;check(read["SchemaVersion"]!.GetValue<int>()==1);
    var expected=JsonNode.Parse(legacyExport)!;expected["SchemaVersion"]=1;check(JsonNode.DeepEquals(read,expected));
   }
   check(Bytes(legacyPath)==before);
   using(var rejected=new ApplicationCatalogStore(legacyPath)){
    reject(()=>rejected.Update("{}"));reject(()=>rejected.Import("{}"));check(Bytes(legacyPath)==before);
    var invalid=Update(legacy:true);invalid["Run"]!["ApplicationRecordCount"]=2;invalid["Rows"]!.AsArray().Add(new JsonObject{["AppId"]=id,["Record"]=new JsonObject(),["HashInput"]="{}"});reject(()=>rejected.Update(invalid.ToJsonString()));check(Bytes(legacyPath)==before);
    var invalidImport=JsonNode.Parse(legacyExport)!;invalidImport["Applications"]![id]!["Records"]!["Discovery///"]!["Attributes"]!["AccessToken"]="synthetic";reject(()=>rejected.Import(invalidImport.ToJsonString()));check(Bytes(legacyPath)==before);
   }
   using(var migrated=new ApplicationCatalogStore(legacyPath)){migrated.Import(legacyExport);check(migrated.Export()==legacyExport);}
   using(var raw=new SqliteConnection(new SqliteConnectionStringBuilder{DataSource=legacyPath,Pooling=false}.ToString())){
    raw.Open();using var command=raw.CreateCommand();command.CommandText="PRAGMA user_version;";check(Convert.ToInt32(command.ExecuteScalar())==2);
   }
   if(OperatingSystem.IsLinux()){
    using var rollback=new ApplicationCatalogStore(rollbackPath,true);
    var expectedRollback=JsonNode.Parse(legacyExport)!;expectedRollback["SchemaVersion"]=1;
    check(JsonNode.DeepEquals(JsonNode.Parse(rollback.Export()),expectedRollback));
   }
   string sharedPath=Path.Combine(root,"shared.sqlite");
   using(var seed=new ApplicationCatalogStore(sharedPath))seed.Update(Update(legacy:true).ToJsonString());
   LegacyMarker(sharedPath);
   using(var firstWriter=new ApplicationCatalogStore(sharedPath))using(var secondWriter=new ApplicationCatalogStore(sharedPath))using(var observer=new ApplicationCatalogStore(sharedPath,true)){
    firstWriter.Update(Update("First migration",date:"2026-01-02T00:00:00Z").ToJsonString());
    check(JsonNode.Parse(observer.Export())!["SchemaVersion"]!.GetValue<int>()==2);
    secondWriter.Update(Update("Other handle",date:"2026-01-03T00:00:00Z").ToJsonString());
    check(JsonNode.Parse(observer.Export())!["Applications"]![id]!["Records"]!["Discovery///"]!["PreviousVersions"]!.AsArray().Count==2);
   }
   string badPath=Path.Combine(root,"bad-history.sqlite");
   using(var store=new ApplicationCatalogStore(badPath)){
    store.Update(Update(legacy:true).ToJsonString());var changed=Update(legacy:true,date:"2026-01-02T00:00:00Z");changed["Rows"]![0]!["Record"]!["Attributes"]!["Name"]="Changed";
    string hashInput=new JsonObject{["Attributes"]=changed["Rows"]![0]!["Record"]!["Attributes"]!.DeepClone(),["Sources"]=changed["Rows"]![0]!["Record"]!["Sources"]!.DeepClone()}.ToJsonString();
    changed["Rows"]![0]!["HashInput"]=hashInput;changed["Rows"]![0]!["Record"]!["ContentSha256"]=Hash(hashInput);store.Update(changed.ToJsonString());
   }
   LegacyMarker(badPath);
   using(var raw=new SqliteConnection(new SqliteConnectionStringBuilder{DataSource=badPath,Pooling=false}.ToString())){
    raw.Open();using var command=raw.CreateCommand();command.CommandText="SELECT payload FROM catalog_versions LIMIT 1;";var previous=JsonNode.Parse((string)command.ExecuteScalar()!)!;
    previous["Attributes"]!["AccessToken"]="synthetic";command.CommandText="UPDATE catalog_versions SET payload=$payload,hash=$hash;";command.Parameters.AddWithValue("$payload",previous.ToJsonString());command.Parameters.AddWithValue("$hash",Hash(previous.ToJsonString()));command.ExecuteNonQuery();
   }
   string invalidBefore=Bytes(badPath);reject(()=>{using var failed=new ApplicationCatalogStore(badPath);failed.Update(Update(legacy:true).ToJsonString());});check(Bytes(badPath)==invalidBefore);
   using(var raw=new SqliteConnection(new SqliteConnectionStringBuilder{DataSource=badPath,Pooling=false}.ToString())){raw.Open();using var command=raw.CreateCommand();command.CommandText="PRAGMA user_version;";check(Convert.ToInt32(command.ExecuteScalar())==1);}
  }finally{if(Directory.Exists(root))Directory.Delete(root,true);}
 }
}
