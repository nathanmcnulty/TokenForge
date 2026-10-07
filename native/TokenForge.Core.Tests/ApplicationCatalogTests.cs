using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.Data.Sqlite;
using TokenForge.Core;

static class ApplicationCatalogTests
{
    public static void Run(Action<bool> check,Action<Action> reject)
    {
        var root=Path.Combine(Path.GetTempPath(),"TokenForge-catalog-test-"+Guid.NewGuid());
        if(OperatingSystem.IsMacOS() && root.StartsWith("/var/"))root="/private"+root;
        var path=Path.Combine(root,"applications.sqlite");var id="11111111-1111-1111-1111-111111111111";var tenant=new string('a',64);
        string Hash(string value)=>Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(value))).ToLowerInvariant();
        JsonObject Update(string name,string date="2026-01-01T00:00:00Z",string kind="Discovery") {
            var attrs=new JsonObject{["AppId"]=id,["Name"]=name,["OwnerTenantId"]="72F988BF-86F1-41AF-91AB-2D7CD011DB47",["PublicClient"]=true,["Foci"]=1,["Grants"]=new JsonArray()};
            if(kind=="Inventory"){attrs.Remove("Grants");attrs["PublishedGrants"]=new JsonArray();attrs["TenantRedirectUris"]="https://example.test/callback";}
            if(kind=="SignIns"){attrs=new JsonObject{["AppId"]=id,["SignInCount"]=1,["CredentialTypeCounts"]=new JsonArray{new JsonObject{["Value"]="Unknown",["Count"]=1}}};}
            var sources=new JsonArray{new JsonObject{["Name"]="Published",["Location"]="https://raw.githubusercontent.com/example/public/main/apps.json",["Evidence"]="PublishedHint"}};
            var hashInput=new JsonObject{["Attributes"]=attrs.DeepClone(),["Sources"]=sources.DeepClone()}.ToJsonString();
            var record=new JsonObject{["Kind"]=kind,["TenantFingerprint"]=kind=="Discovery"?null:tenant,["PrincipalFingerprint"]=null,["ResourceId"]=null,["FirstSeenAt"]=date,["LastSeenAt"]=date,["CurrentVersionFirstSeenAt"]=date,["PresentInLatestRun"]=true,["Attributes"]=attrs,["Sources"]=sources,["ContentSha256"]=Hash(hashInput),["PreviousVersions"]=new JsonArray()};
            var run=new JsonObject{["Id"]=Guid.NewGuid().ToString(),["Kind"]=kind,["ObservedAt"]=date,["RecordedAt"]="2026-01-30T00:00:00Z",["ApplicationRecordCount"]=1,["IgnoredEmptyAppIdCount"]=0,["TenantFingerprint"]=kind=="Discovery"?null:tenant};
            return new JsonObject{["Format"]="TokenForgeCatalogUpdate",["SchemaVersion"]=1,["Run"]=run,["Rows"]=new JsonArray{new JsonObject{["AppId"]=id,["Record"]=record,["HashInput"]=hashInput}}};
        }
        try {
            using(var store=new ApplicationCatalogStore(path)) {
                var initial=Update("Café <a> & \"b\" /");var json=initial.ToJsonString();store.Update(json);var first=store.Export();
                store.Update(json);check(store.Export()==first);
                store.Update(Update("B").ToJsonString());store.Update(Update("Café <a> & \"b\" /").ToJsonString());store.Update(Update("B").ToJsonString());
                var ledger=JsonNode.Parse(store.Export())!;check(ledger["Applications"]![id]!["Records"]!["Discovery///"]!["PreviousVersions"]!.AsArray().Count==3);
                check(store.Import(store.Export())==0);check(JsonNode.Parse(store.Export())!["Applications"]![id]!["Records"]!["Discovery///"]!["PreviousVersions"]!.AsArray().Count==3);
                var empty=Update("Absent","2026-01-05T00:00:00Z");empty["Rows"]=new JsonArray();empty["Run"]!["ApplicationRecordCount"]=0;store.Update(empty.ToJsonString());
                store.Import(first);check(!JsonNode.Parse(store.Export())!["Applications"]![id]!["Records"]!["Discovery///"]!["PresentInLatestRun"]!.GetValue<bool>());
                store.Update(Update("Stale","2026-01-04T00:00:00Z").ToJsonString());
                ledger=JsonNode.Parse(store.Export())!;var record=ledger["Applications"]![id]!["Records"]!["Discovery///"]!;check(!record["PresentInLatestRun"]!.GetValue<bool>());check(record["Attributes"]!["Name"]!.GetValue<string>()=="Stale");
                check(JsonNode.Parse(store.Export(currentOnly:true))!["Runs"]!.AsArray().Count==1);
                check(JsonNode.Parse(store.Export("22222222-2222-2222-2222-222222222222",true))!["Applications"]!.AsObject().Count==0);
                store.Update(Update("Tenant","2026-01-06T00:00:00Z","Inventory").ToJsonString());check(JsonNode.Parse(store.Export())!["Applications"]![id]!["Records"]!.AsObject().Count==2);
                var privateCounts=Update("Count","2026-01-06T00:00:00Z","SignIns");store.Update(privateCounts.ToJsonString());
                var badCount=(JsonObject)privateCounts.DeepClone();badCount["Run"]!["Id"]=Guid.NewGuid().ToString();badCount["Rows"]![0]!["Record"]!["Attributes"]!["CredentialTypeCounts"]![0]!["Value"]="someone@example.test";reject(()=>store.Update(badCount.ToJsonString()));
                var before=store.Export();var conflict=(JsonObject)initial.DeepClone();conflict["Rows"]![0]!["HashInput"]="{}";reject(()=>store.Update(conflict.ToJsonString()));check(store.Export()==before);
                var invalid=Update("Changed","2026-01-07T00:00:00Z");invalid["Run"]!["ApplicationRecordCount"]=2;invalid["Rows"]!.AsArray().Add(new JsonObject{["AppId"]=id,["Record"]=new JsonObject{["AccessToken"]="synthetic"},["HashInput"]="{}"});reject(()=>store.Update(invalid.ToJsonString()));check(store.Export()==before);
                var injected=JsonNode.Parse(before)!;injected["Applications"]![id]!["Records"]!["Discovery///"]!["Attributes"]!["AccessToken"]="synthetic";reject(()=>store.Import(injected.ToJsonString()));check(store.Export()==before);
                var invalidRun=JsonNode.Parse(before)!;invalidRun["Runs"]![0]!["ApplicationRecordCount"]=999;reject(()=>store.Import(invalidRun.ToJsonString()));check(store.Export()==before);
                var wrongHistory=JsonNode.Parse(before)!;wrongHistory["Applications"]![id]!["Records"]!["Discovery///"]!["PreviousVersions"]![0]!["Attributes"]!["AppId"]="22222222-2222-2222-2222-222222222222";reject(()=>store.Import(wrongHistory.ToJsonString()));
                var importedPath=Path.Combine(root,"imported.sqlite");using(var imported=new ApplicationCatalogStore(importedPath)){check(imported.Import(before)>0);check(imported.Import(before)==0);check(imported.Export()==before);}
            }
            using(var a=new ApplicationCatalogStore(Path.Combine(root,"presence-a.sqlite")))using(var b=new ApplicationCatalogStore(Path.Combine(root,"presence-b.sqlite"))){
                a.Update(Update("Recent","2026-01-04T00:00:00Z").ToJsonString());var olderPresent=a.Export();
                b.Update(Update("Older","2026-01-01T00:00:00Z").ToJsonString());var absent=Update("Absent","2026-01-06T00:00:00Z");absent["Rows"]=new JsonArray();absent["Run"]!["ApplicationRecordCount"]=0;b.Update(absent.ToJsonString());
                a.Import(b.Export());var view=JsonNode.Parse(a.Export())!;check(!view["Applications"]![id]!["Records"]!["Discovery///"]!["PresentInLatestRun"]!.GetValue<bool>());check(view["Applications"]![id]!["Records"]!["Discovery///"]!["Attributes"]!["Name"]!.GetValue<string>()=="Recent");
                a.Import(olderPresent);check(!JsonNode.Parse(a.Export())!["Applications"]![id]!["Records"]!["Discovery///"]!["PresentInLatestRun"]!.GetValue<bool>());
                var wrongLink=JsonNode.Parse(a.Export())!;var app=wrongLink["Applications"]![id]!.ToJsonString();var duplicate=wrongLink.ToJsonString().Replace("\"Applications\":{","\"Applications\":{"+JsonSerializer.Serialize(id)+":"+app+",");reject(()=>a.Import(duplicate));
            }
            using(var raw=new SqliteConnection(new SqliteConnectionStringBuilder{DataSource=path,Pooling=false}.ToString())) {
                raw.Open();using var command=raw.CreateCommand();command.CommandText="UPDATE catalog_records SET hash=$hash WHERE origin='Discovery///';";command.Parameters.AddWithValue("$hash",new string('f',64));command.ExecuteNonQuery();
                using(var corrupt=new ApplicationCatalogStore(path,true))reject(()=>corrupt.Export());
                using(var corrupt=new ApplicationCatalogStore(path))reject(()=>corrupt.Update(Update("New","2026-01-08T00:00:00Z").ToJsonString()));
            }
            using(var other=new FlowEvidenceStore(Path.Combine(root,"foreign.sqlite"))){}reject(()=>{using var wrong=new ApplicationCatalogStore(Path.Combine(root,"foreign.sqlite"));});
            if(!OperatingSystem.IsWindows())check(((int)File.GetUnixFileMode(path)&63)==0);
        }finally{if(Directory.Exists(root))Directory.Delete(root,true);}
    }
}
