using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.Data.Sqlite;
using TokenForge.Core;

static class FlowEvidenceTests
{
    public static void Run(Action<bool> check, Action<Action> reject)
    {
        var root = Path.Combine(Path.GetTempPath(), "TokenForge-flow-test-" + Guid.NewGuid());
        if (OperatingSystem.IsMacOS() && root.StartsWith("/var/")) root = "/private" + root;
        var path = Path.Combine(root, "flows.sqlite");
        string Hash(string text) => Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(text))).ToLowerInvariant();
        var date = DateTimeOffset.UtcNow.AddMinutes(-1).ToString("o");
        var tenant = new string('a',64); var principal = new string('b',64); var redirect = new string('c',64);
        var client = "11111111-1111-1111-1111-111111111111"; var resource = "00000003-0000-0000-c000-000000000000";
        var plan = new Dictionary<string,object?> {
            ["TenantFingerprint"]=tenant,["PrincipalFingerprint"]=principal,["ClientId"]=client,["ResourceId"]=resource,["Tenant"]="organizations",["CatalogHash"]=null,["Eligibility"]="Eligible",
            ["ResourceAliases"]=new[]{resource,"https://graph.microsoft.com"},["Cells"]=new[]{new {Protocol="OAuth2V2Pkce",Spa=false,RedirectFingerprint=redirect}},["PlannedAt"]=date };
        var hash = Hash(string.Join("\n", new[]{"FlowPolicy1",tenant,principal,client,resource,"organizations","","Eligible",resource,"https://graph.microsoft.com","OAuth2V2Pkce|0|"+redirect}));
        var row = new Dictionary<string,object?> {
            ["AttemptId"]=Guid.NewGuid().ToString(),["PlanFingerprint"]=hash,["AttemptKey"]=Hash(hash+"|OAuth2V2Pkce|0|"+redirect),["ClientId"]=client,["ResourceId"]=resource,["TenantFingerprint"]=tenant,["PrincipalFingerprint"]=principal,
            ["StartedAt"]=date,["ObservedAt"]=date,["Protocol"]="OAuth2V2Pkce",["Spa"]=false,["RedirectFingerprint"]=redirect,["Outcome"]="Started",["ResponseScopes"]=Array.Empty<string>(),["ScpScopes"]=Array.Empty<string>(),
            ["ClaimsReadable"]=false,["HasScpClaim"]=false,["NamespaceVerification"]="Unverifiable",["RequestVerification"]="Unverifiable",["SignatureValidated"]=false,["ErrorCodes"]=Array.Empty<string>(),["ElapsedSeconds"]=0 };
        string Document(params Dictionary<string,object?>[] attempts) => JsonSerializer.Serialize(new {Format="TokenForgeFlowEvidence",SchemaVersion=1,UpdatedAt=date,Plans=new Dictionary<string,object?>{{hash,plan}},Attempts=attempts});
        try
        {
            using (var store = new FlowEvidenceStore(path))
            {
                check(store.Import(Document(row))==1);
                check(store.Import(Document(row))==0);
                plan["ResourceAliases"] = new[]{"https://graph.microsoft.com",resource};
                check(store.Import(Document(row))==0); // Legacy hashes ignore alias array order.
                check(JsonDocument.Parse(store.Export(planFingerprint: hash)).RootElement.GetProperty("Plans").EnumerateObject().Count()==1);
                check(JsonDocument.Parse(store.Export(planFingerprint: new string('f',64))).RootElement.GetProperty("Plans").EnumerateObject().Count()==0);
                var terminal = new Dictionary<string,object?>(row) { ["Outcome"]="Succeeded",["ClaimsReadable"]=true,["HasScpClaim"]=true,["NamespaceVerification"]="Matched",["RequestVerification"]="Matched",["ScpScopes"]=new[]{"User.Read"},["ResponseScopes"]=new[]{"User.Read"},["ElapsedSeconds"]=1,["ObservedAt"]=DateTimeOffset.UtcNow.AddSeconds(-20).ToString("o") };
                store.SaveAttempt(JsonSerializer.Serialize(terminal));
                check(store.Import(store.Export())==0); // Whitespace/key order must not defeat idempotence.
                var interrupted = new Dictionary<string,object?>(row) { ["AttemptId"]=Guid.NewGuid().ToString(),["StartedAt"]=DateTimeOffset.UtcNow.AddSeconds(-10).ToString("o"),["ObservedAt"]=DateTimeOffset.UtcNow.AddSeconds(-9).ToString("o") };
                store.SaveAttempt(JsonSerializer.Serialize(interrupted));
                using(var latest=JsonDocument.Parse(store.Export(tenant,principal,true)))
                {
                    check(latest.RootElement.GetProperty("Attempts").GetArrayLength()==1);
                    check(latest.RootElement.GetProperty("Attempts")[0].GetProperty("Outcome").GetString()=="Started");
                }
                using(var other=JsonDocument.Parse(store.Export(tenant,new string('d',64),true))) check(other.RootElement.GetProperty("Attempts").GetArrayLength()==0);
                reject(()=>store.Export(tenant));
                var poison = new Dictionary<string,object?>(terminal) { ["AccessToken"]="synthetic-secret" };
                reject(()=>store.Import(Document(poison)));
                poison = new Dictionary<string,object?>(terminal) { ["SignatureValidated"]=true };
                reject(()=>store.SaveAttempt(JsonSerializer.Serialize(poison)));
                poison = new Dictionary<string,object?>(terminal) { ["NamespaceVerification"]="Unverifiable" };
                reject(()=>store.SaveAttempt(JsonSerializer.Serialize(poison)));
                poison = new Dictionary<string,object?>(terminal) { ["PrincipalFingerprint"]=new string('d',64) };
                reject(()=>store.SaveAttempt(JsonSerializer.Serialize(poison)));
                reject(()=>store.Import(Document(terminal,terminal)));
                var before = JsonDocument.Parse(store.Export()).RootElement.GetProperty("Attempts").GetArrayLength();
                var valid = new Dictionary<string,object?>(row) { ["AttemptId"]=Guid.NewGuid().ToString() };
                reject(()=>store.Import(Document(valid,poison)));
                check(JsonDocument.Parse(store.Export()).RootElement.GetProperty("Attempts").GetArrayLength()==before);
                reject(()=>store.SavePlan(new string('f',64),JsonSerializer.Serialize(plan)));
                var modifiedTerminal = new Dictionary<string,object?>(terminal) { ["Outcome"]="Failed" };
                reject(()=>store.SaveAttempt(JsonSerializer.Serialize(modifiedTerminal)));
                check(!store.Export().Contains("synthetic-secret"));
            }
            using(var reopened=new FlowEvidenceStore(path,true)) check(JsonDocument.Parse(reopened.Export()).RootElement.GetProperty("Attempts").GetArrayLength()==2);
            using(var wrong=new EvidenceStore(Path.Combine(root,"other.sqlite"))) { }
            reject(()=>{using var wrong=new FlowEvidenceStore(Path.Combine(root,"other.sqlite"));});
            using(var raw=new SqliteConnection(new SqliteConnectionStringBuilder{DataSource=path,Pooling=false}.ToString()))
            {
                raw.Open();using var command=raw.CreateCommand();command.CommandText="UPDATE flow_plans SET tenant=$tenant WHERE id=$id;";command.Parameters.AddWithValue("$tenant",new string('d',64));command.Parameters.AddWithValue("$id",hash);command.ExecuteNonQuery();
                using(var indexed=new FlowEvidenceStore(path,true)) reject(()=>indexed.Export(new string('d',64),principal));
                using(var indexedWrite=new FlowEvidenceStore(path)) reject(()=>indexedWrite.SaveAttempt(JsonSerializer.Serialize(row)));
                command.Parameters["$tenant"].Value=tenant;command.ExecuteNonQuery();command.Parameters.Clear();
                command.CommandText="UPDATE flow_attempts SET observed=$date;";command.Parameters.AddWithValue("$date",DateTimeOffset.UtcNow.ToString("o"));command.ExecuteNonQuery();
                using(var indexed=new FlowEvidenceStore(path,true)) reject(()=>indexed.Export());
                command.Parameters.Clear();command.CommandText="UPDATE flow_attempts SET payload=$payload;";command.Parameters.AddWithValue("$payload","{\"AccessToken\":\"synthetic-secret\"}");command.ExecuteNonQuery();
            }
            using(var damaged=new FlowEvidenceStore(path,true)) reject(()=>damaged.Export());
            if(!OperatingSystem.IsWindows()) check(((int)File.GetUnixFileMode(path)&63)==0);
        }
        finally { if(Directory.Exists(root)) Directory.Delete(root,true); }
    }
}
