#nullable enable
using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
namespace TokenForge.Core;

// Shared policy and saved-evidence contracts for named administrator tools.
public static partial class AdminWorkflows
{
    private const int MaxBytes=64*1024*1024;
    private const string Graph="00000003-0000-0000-c000-000000000000";
    private static InvalidOperationException Invalid()=>new InvalidOperationException("Administrator workflow input is invalid or unsupported. Details suppressed.");
    private static T Guard<T>(Func<T> run){try{return run();}catch{throw Invalid();}}
    private static JsonObject Obj(JsonNode? n)=>n as JsonObject ?? throw Invalid();
    private static JsonArray Arr(JsonNode? n)=>n as JsonArray ?? throw Invalid();
    private static string Text(JsonNode? n)=>n is JsonValue v && v.TryGetValue<string>(out var s)?s:throw Invalid();
    private static int Int(JsonNode? n)=>n is JsonValue v && v.TryGetValue<int>(out int i)?i:throw Invalid();
    private static bool Bool(JsonNode? n)=>n is JsonValue v && v.TryGetValue<bool>(out bool b)?b:throw Invalid();
    private static void Match(string text,string regex,int max){if(text.Length>max || !Regex.IsMatch(text,regex,RegexOptions.CultureInvariant))throw Invalid();}
    private static void GuidId(JsonNode? n){string s=Text(n);if(!Guid.TryParseExact(s,"D",out var id) || id==Guid.Empty || id.ToString()!=s)throw Invalid();}
    private static void Fingerprint(JsonNode? n)=>Match(Text(n),@"\A[a-f0-9]{64}\z",64);
    private static void Keys(JsonObject o,string fields){var keys=fields.Split(' ');if(o.Count!=keys.Length || o.Any(p=>!keys.Contains(p.Key,StringComparer.Ordinal)))throw Invalid();}
    private static void OptionalKeys(JsonObject o,string allowed,string required){var keys=allowed.Split(' ');if(o.Any(p=>!keys.Contains(p.Key,StringComparer.Ordinal)) || required.Split(' ').Any(k=>!o.ContainsKey(k)))throw Invalid();}
    private static string Canon(JsonNode n){using var d=JsonDocument.Parse(n.ToJsonString());return ApplicationCatalogPolicy.Canonical(d.RootElement);}
    private static JsonObject Parse(string json,int max=MaxBytes){if(json==null || Encoding.UTF8.GetByteCount(json)>max)throw Invalid();using var d=JsonDocument.Parse(json,new JsonDocumentOptions{MaxDepth=64});DiscoverySourceClaims.ValidateUniqueKeys(d.RootElement);return Obj(JsonNode.Parse(d.RootElement.GetRawText()));}
    private static string Choice(JsonNode? n,string values){string s=Text(n);if(!values.Split(' ').Contains(s,StringComparer.Ordinal))throw Invalid();return s;}
    private static JsonArray Strings(JsonNode? n,int max,bool guid=false){var a=Arr(n);if(a.Count is <1 || a.Count>max)throw Invalid();var set=new SortedSet<string>(StringComparer.Ordinal);foreach(var v in a){if(guid)GuidId(v);else{string s=Text(v);Match(s,@"\A[A-Za-z0-9_-][A-Za-z0-9_.-]{0,255}\z",256);if(new[]{"openid","profile","email","offline_access",".default"}.Contains(s,StringComparer.Ordinal))throw Invalid();}if(!set.Add(Text(v)))throw Invalid();}return new JsonArray(set.Select(v=>(JsonNode?)JsonValue.Create(v)).ToArray());}
    private static void Range(JsonNode? n,int min,int max){int i=Int(n);if(i<min || i>max)throw Invalid();}
    private static JsonObject Header(string format)=>new JsonObject{["Format"]=format,["SchemaVersion"]=1};
    private static void Version(JsonObject o,string format){if(Text(o["Format"])!=format || Int(o["SchemaVersion"])!=1)throw Invalid();}
    public static string CreateStrictProfile(string tenant,string principalFingerprint,string bootstrapClient,string[] approvedClients,int maxAdditionalScopes=0,int maxBootstrapAdditionalScopes=0,int maxAgeHours=24,int maxSeconds=180)=>Guard(()=>{
        var p=Header("TokenForgeStrictProfile");p["Tenant"]=tenant;p["ExpectedTenantFingerprint"]=ApplicationCatalogPolicy.Hash(tenant);p["ExpectedPrincipalFingerprint"]=principalFingerprint;p["BootstrapClientId"]=bootstrapClient;p["ApprovedClientIds"]=JsonSerializer.SerializeToNode(approvedClients);p["MaxAdditionalScopes"]=maxAdditionalScopes;p["MaxBootstrapAdditionalScopes"]=maxBootstrapAdditionalScopes;p["MaxAgeHours"]=maxAgeHours;p["MaxSeconds"]=maxSeconds;p["SilentOnly"]=true;return Profile(p).ToJsonString();
    });
    public static string ValidateStrictProfile(string json)=>Guard(()=>Profile(Parse(json,32768)).ToJsonString());
    private static JsonObject Profile(JsonObject p){Keys(p,"Format SchemaVersion Tenant ExpectedTenantFingerprint ExpectedPrincipalFingerprint BootstrapClientId ApprovedClientIds MaxAdditionalScopes MaxBootstrapAdditionalScopes MaxAgeHours MaxSeconds SilentOnly");Version(p,"TokenForgeStrictProfile");GuidId(p["Tenant"]);Fingerprint(p["ExpectedTenantFingerprint"]);Fingerprint(p["ExpectedPrincipalFingerprint"]);if(Text(p["ExpectedTenantFingerprint"])!=ApplicationCatalogPolicy.Hash(Text(p["Tenant"])) || !Bool(p["SilentOnly"]))throw Invalid();GuidId(p["BootstrapClientId"]);p["ApprovedClientIds"]=Strings(p["ApprovedClientIds"],32,true);if(!Arr(p["ApprovedClientIds"]).Select(Text).Contains(Text(p["BootstrapClientId"]),StringComparer.Ordinal))throw Invalid();Range(p["MaxAdditionalScopes"],0,64);Range(p["MaxBootstrapAdditionalScopes"],0,64);Range(p["MaxAgeHours"],1,8760);Range(p["MaxSeconds"],1,900);return p;}
    public static string ValidateRequirements(string json)=>Guard(()=>Requirements(Parse(json,1024*1024)).ToJsonString());
    private static JsonObject Requirements(JsonObject r){Keys(r,"Format SchemaVersion Tools");Version(r,"TokenForgeToolRequirements");var tools=Arr(r["Tools"]);if(tools.Count is <1 or >128)throw Invalid();var ids=new HashSet<string>(StringComparer.Ordinal);
        foreach(var n in tools){var t=Obj(n);Keys(t,"Id ClientIds ResourceId Scopes Protocol CallbackClass Operations Prerequisites SecuritySensitive");string id=Text(t["Id"]);Match(id,@"\A[a-z][a-z0-9-]{0,63}\z",64);if(!ids.Add(id))throw Invalid();t["ClientIds"]=Strings(t["ClientIds"],32,true);GuidId(t["ResourceId"]);t["Scopes"]=Strings(t["Scopes"],64);Choice(t["Protocol"],"OAuth2V2Pkce OAuth2V2Implicit OAuth2V1Implicit");Choice(t["CallbackClass"],"Native Spa Web");Bool(t["SecuritySensitive"]);
            var ops=Arr(t["Operations"]);if(ops.Count>1 || ops.Select(Text).Distinct(StringComparer.Ordinal).Count()!=ops.Count)throw Invalid();foreach(var op in ops){Choice(op,"GraphMeV1");if(Text(t["ResourceId"])!=Graph)throw Invalid();}
            var req=Arr(t["Prerequisites"]);if(req.Count>32)throw Invalid();var requirements=new HashSet<string>(StringComparer.Ordinal);foreach(var v in req){var p=Obj(v);Keys(p,"Kind Name");Choice(p["Kind"],"Role License");Match(Text(p["Name"]),@"\A[A-Za-z0-9][A-Za-z0-9 ._-]{0,79}\z",80);if(!requirements.Add(Canon(p)))throw Invalid();}
        }return r;
    }
}
