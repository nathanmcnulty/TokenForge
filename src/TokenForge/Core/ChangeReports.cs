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

// A transport-free comparison contract. No credentials, stores, or authentication adapters.
public static partial class ChangeReports
{
    public const int MaxBytes=64*1024*1024;
    private const string ContextFields="ContextVersion QueryFingerprint TenantFingerprint ObserverFingerprint PrincipalFingerprint ClientId ResourceId AuthorityFingerprint RequestedScopes Protocol CallbackFingerprint CallbackClass Spa RecipeFingerprint ExecutionPolicyFingerprint OperationFingerprint Method ApiVersion ApprovalFingerprint";
    private const string Types="PermissionDefinition PublicHint ConfiguredGrant IssuedScopes ApiAcceptance";
    private static InvalidOperationException Invalid()=>new InvalidOperationException("Change evidence is invalid or unsupported. No report produced.");
    private static string Str(JsonNode? n)=>n is JsonValue v && v.TryGetValue<string>(out var s)?s:throw Invalid();
    private static string Text(JsonObject o,string key)=>Str(o[key]);
    private static bool Bool(JsonNode? n)=>n is JsonValue v && v.TryGetValue<bool>(out var b)?b:throw Invalid();
    private static int Int(JsonNode? n)=>n is JsonValue v && v.TryGetValue<int>(out var i)?i:throw Invalid();
    private static JsonObject Obj(JsonNode? n)=>n as JsonObject ?? throw Invalid();
    private static JsonArray Arr(JsonNode? n)=>n as JsonArray ?? throw Invalid();
    private static void Keys(JsonObject o,string allowed,string required=""){
        var a=allowed.Split(' ',StringSplitOptions.RemoveEmptyEntries);foreach(var k in o.Select(x=>x.Key))if(!a.Contains(k,StringComparer.Ordinal))throw Invalid();
        foreach(var k in required.Split(' ',StringSplitOptions.RemoveEmptyEntries))if(!o.ContainsKey(k))throw Invalid();
    }
    private static JsonNode? Copy(JsonNode? n)=>n?.DeepClone();
    private static JsonObject Object(params (string,object?)[] fields){var o=new JsonObject();foreach(var f in fields)o[f.Item1]=JsonSerializer.SerializeToNode(f.Item2);return o;}
    private static string Canon(JsonNode? n){using var d=JsonDocument.Parse(n?.ToJsonString() ?? "null");return ApplicationCatalogPolicy.Canonical(d.RootElement);}
    private static string Hash(string s)=>ApplicationCatalogPolicy.Hash(s);
    private static void Match(string s,string pattern,int max=4096){if(s.Length>max || !Regex.IsMatch(s,pattern.Replace("^",@"\A").Replace("$",@"\z"),RegexOptions.CultureInvariant))throw Invalid();}
    private static void Digest(JsonNode? n)=>Match(Str(n),"^[a-f0-9]{64}$",64);
    private static void GuidValue(JsonNode? n){if(!Guid.TryParseExact(Str(n),"D",out var g) || g==Guid.Empty || g.ToString()!=Str(n))throw Invalid();}
    private static DateTimeOffset Date(JsonNode? n){var s=Str(n);if(s.Length>40 || !Regex.IsMatch(s,@"\A\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,7})?(?:Z|[+-]\d\d:\d\d)\z") || !DateTimeOffset.TryParse(s,CultureInfo.InvariantCulture,DateTimeStyles.None,out var d) || d>DateTimeOffset.UtcNow.AddMinutes(5))throw Invalid();return d;}
    private static void Enum(JsonNode? n,string values){if(!values.Split(' ').Contains(Str(n),StringComparer.Ordinal))throw Invalid();}
    private static JsonArray Strings(JsonNode? n,bool hashes=false){var a=Arr(n);if(a.Count>10000)throw Invalid();var set=new SortedSet<string>(StringComparer.Ordinal);foreach(var x in a){var s=Str(x);if(hashes)Digest(x);else Match(s,"^[A-Za-z0-9_.:/-]{1,256}$",256);if(!set.Add(s))throw Invalid();}return new JsonArray(set.Select(x=>(JsonNode?)JsonValue.Create(x)).ToArray());}
    private static JsonObject Parse(string json){if(json==null || Encoding.UTF8.GetByteCount(json)>MaxBytes)throw Invalid();using var d=JsonDocument.Parse(json,new JsonDocumentOptions{MaxDepth=64});DiscoverySourceClaims.ValidateUniqueKeys(d.RootElement);return Obj(JsonNode.Parse(d.RootElement.GetRawText()));}
    private static T Guard<T>(Func<T> run){try{return run();}catch{throw Invalid();}}

    public static string FingerprintJson(string json)=>Guard(()=>Hash(Canon(Parse(json))));
    public static string ValidateSnapshot(string json)=>Guard(()=>Snapshot(Parse(json)).ToJsonString());
    private static JsonObject Snapshot(JsonObject root){
        Keys(root,"Format SchemaVersion Collections","Format SchemaVersion Collections");if(Text(root,"Format")!="TokenForgeChangeSnapshot" || Int(root["SchemaVersion"])!=1)throw Invalid();
        var collections=Arr(root["Collections"]);if(collections.Count>100000)throw Invalid();var seen=new HashSet<string>(StringComparer.Ordinal);
        foreach(var n in collections){var c=Obj(n);Keys(c,"EvidenceType Privacy Status Context Source Records","EvidenceType Privacy Status Context Source Records");Enum(c["EvidenceType"],Types);Enum(c["Privacy"],"Public Private Anonymous");Enum(c["Status"],"Complete Incomplete Denied Failed NotCollected Unknown");
            string type=Text(c,"EvidenceType"),privacy=Text(c,"Privacy");if(type is "ConfiguredGrant" or "ApiAcceptance" && privacy!="Private")throw Invalid();if(type is "PermissionDefinition" or "PublicHint" && privacy=="Anonymous")throw Invalid();
            var ctx=Context(Obj(c["Context"]));c["Context"]=ctx;
            if(privacy!="Private" && new[]{"TenantFingerprint","ObserverFingerprint","PrincipalFingerprint"}.Any(k=>ctx[k]!=null))throw Invalid();
            if(type=="IssuedScopes" && privacy=="Public")throw Invalid();
            var source=Obj(c["Source"]);Keys(source,"Id Location ContentSha256 HashKind SourceObservedAt CollectedAt Commit InputSha256","Id Location ContentSha256 HashKind SourceObservedAt CollectedAt");
            Match(Text(source,"Id"),"^[A-Za-z0-9_.:/-]{1,256}$",256);Digest(source["ContentSha256"]);Enum(source["HashKind"],"NormalizedDocument RawSourceBytes RecordCanonical");
            string loc=Text(source,"Location");if(loc.StartsWith("urn:sha256:",StringComparison.Ordinal))Digest(JsonValue.Create(loc.Substring(11)));else DiscoverySourceClaims.ValidatePublicLocation(loc);
            Date(source["CollectedAt"]);if(source["SourceObservedAt"]!=null)Date(source["SourceObservedAt"]);if(source["Commit"]!=null)Match(Text(source,"Commit"),"^(?:[a-f0-9]{40}|[a-f0-9]{64})$",64);if(source["InputSha256"]!=null)Digest(source["InputSha256"]);
            if(!seen.Add(CollectionKey(c)))throw Invalid();var ids=new HashSet<string>(StringComparer.Ordinal);var records=Arr(c["Records"]);if(records.Count>1000000)throw Invalid();
            foreach(var rn in records){var r=Obj(rn);Keys(r,"RecordId FirstObservedAt ObservedAt Outcome Identity Value","RecordId ObservedAt Outcome Identity Value");Digest(r["RecordId"]);if(!ids.Add(Text(r,"RecordId")))throw Invalid();if(Date(r["ObservedAt"])>Date(source["CollectedAt"]) || r["FirstObservedAt"]!=null && Date(r["FirstObservedAt"])>Date(r["ObservedAt"]))throw Invalid();ValidateRecord(type,r,ctx,privacy);}
        }
        return root;
    }
    private static JsonObject Context(JsonObject c){Keys(c,ContextFields,"ContextVersion");if(Int(c["ContextVersion"])!=1)throw Invalid();
        foreach(var k in ContextFields.Split(' ')){
            if(!c.ContainsKey(k))c[k]=null;if(c[k]==null)continue;
            if(k.EndsWith("Fingerprint",StringComparison.Ordinal))Digest(c[k]);
            else if(k is "ClientId" or "ResourceId")GuidValue(c[k]);
            else if(k=="RequestedScopes")c[k]=Strings(c[k]);
            else if(k=="Spa")Bool(c[k]);
            else if(k=="Protocol")Enum(c[k],"OAuth2V2Pkce OAuth2V2Implicit OAuth2V1Implicit DeviceCode Ropc");
            else if(k=="CallbackClass")Enum(c[k],"Native Spa Web None");
            else if(k=="Method")Enum(c[k],"GET HEAD");
            else if(k=="ApiVersion")Match(Str(c[k]),"^[A-Za-z0-9_.-]{1,64}$",64);
        }return c;
    }
    private static void ValidateRecord(string type,JsonObject r,JsonObject ctx,string privacy){
        var id=Obj(r["Identity"]);var v=Obj(r["Value"]);
        if(type=="PermissionDefinition"){
            Keys(id,"Id PermissionType Origin","Id PermissionType Origin");GuidValue(id["Id"]);Enum(id["PermissionType"],"Delegated Application");Enum(id["Origin"],"PublicPublished Application ServicePrincipal Unknown");if(privacy=="Public" && Text(id,"Origin") is "Application" or "ServicePrincipal" || privacy=="Private" && Text(id,"Origin")=="PublicPublished")throw Invalid();
            Keys(v,"Name Enabled","Name Enabled");Match(Text(v,"Name"),"^[A-Za-z0-9_.:/-]{1,256}$",256);if(v["Enabled"]!=null)Bool(v["Enabled"]);Enum(r["Outcome"],"Observed Unknown");
        }else if(type=="PublicHint"){
            Keys(id,"ClientId","ClientId");GuidValue(id["ClientId"]);Keys(v,"Grants CallbackFingerprints MetadataSha256 Conflicts","Grants CallbackFingerprints MetadataSha256 Conflicts");
            var resources=new HashSet<string>();foreach(var gn in Arr(v["Grants"])){var g=Obj(gn);Keys(g,"ResourceId Scopes","ResourceId Scopes");GuidValue(g["ResourceId"]);if(!resources.Add(Text(g,"ResourceId")))throw Invalid();g["Scopes"]=Strings(g["Scopes"]);}
            v["CallbackFingerprints"]=Strings(v["CallbackFingerprints"],true);Digest(v["MetadataSha256"]);var fields=new HashSet<string>();foreach(var cn in Arr(v["Conflicts"])){var c=Obj(cn);Keys(c,"Field ValueHashes","Field ValueHashes");Enum(c["Field"],"Name OwnerTenantId");if(!fields.Add(Text(c,"Field")))throw Invalid();c["ValueHashes"]=Strings(c["ValueHashes"],true);}Enum(r["Outcome"],"Observed Unknown");
        }else{
            Keys(id,type=="ConfiguredGrant"?"ClientId ResourceId GrantType SubjectFingerprint":"ClientId ResourceId","ClientId ResourceId");foreach(var k in new[]{"ClientId","ResourceId"}){if(id[k]!=null)GuidValue(id[k]);else if(type!="ApiAcceptance")throw Invalid();if(ctx[k]!=null && Canon(ctx[k])!=Canon(id[k]))throw Invalid();}
            if(type=="ConfiguredGrant"){
                Enum(id["GrantType"],"AllPrincipals Principal Unknown");if(id["SubjectFingerprint"]!=null)Digest(id["SubjectFingerprint"]);if(Text(id,"GrantType")=="AllPrincipals" && id["SubjectFingerprint"]!=null)throw Invalid();Keys(v,"Scopes","Scopes");v["Scopes"]=Strings(v["Scopes"]);Enum(r["Outcome"],"Observed Unknown");
            }else if(type=="IssuedScopes"){
                Keys(v,"Scopes NamespaceVerification RequestVerification ClaimsReadable HasScpClaim SignatureValidated","Scopes NamespaceVerification RequestVerification ClaimsReadable HasScpClaim SignatureValidated");v["Scopes"]=Strings(v["Scopes"]);foreach(var k in new[]{"NamespaceVerification","RequestVerification"})if(v[k]!=null)Enum(v[k],"Matched Mismatch Unverifiable");foreach(var k in new[]{"ClaimsReadable","HasScpClaim"})if(v[k]!=null)Bool(v[k]);if(Bool(v["SignatureValidated"]))throw Invalid();
                Enum(r["Outcome"],"Succeeded Failed NoDelegatedScp OpaqueToken NoRedirect Disabled MissingRegistration OwnerMismatch BrokerRequired ContextMismatch Started SessionPaused RequestBlocked TransientFailure Unknown");
                if(Text(r,"Outcome")=="Succeeded" && v["ClaimsReadable"]?.ToJsonString()=="true" && v["HasScpClaim"]?.ToJsonString()=="true" && Arr(v["Scopes"]).Count==0)throw Invalid();
            }else{
                Keys(v,"Status Accepted","Status Accepted");if(v["Status"]!=null){int status=Int(v["Status"]);if(status<100 || status>599 || v["Accepted"]==null || Bool(v["Accepted"])!=(status>=200 && status<=299))throw Invalid();}else if(v["Accepted"]!=null)throw Invalid();Enum(r["Outcome"],"Responded Failed Unknown");
            }
        }
    }
    private static bool Comparable(JsonObject c){var x=Obj(c["Context"]);string t=Text(c,"EvidenceType");if(x["QueryFingerprint"]==null)return false;
        if(t=="PermissionDefinition")return (Text(c,"Privacy")=="Public" || x["TenantFingerprint"]!=null && x["ObserverFingerprint"]!=null) && x["ResourceId"]!=null && Arr(c["Records"]).All(n=>Text(Obj(Obj(n)["Identity"]),"Origin")!="Unknown");
        if(t=="PublicHint")return Text(c,"Privacy")=="Public";
        if(Text(c,"Privacy")!="Private")return false;
        if(t=="ConfiguredGrant")return x["TenantFingerprint"]!=null && x["ObserverFingerprint"]!=null && Arr(c["Records"]).All(n=>{var id=Obj(Obj(n)["Identity"]);return Text(id,"GrantType")=="AllPrincipals" || Text(id,"GrantType")=="Principal" && id["SubjectFingerprint"]!=null;});
        var required="TenantFingerprint PrincipalFingerprint ClientId ResourceId AuthorityFingerprint RequestedScopes Protocol CallbackFingerprint CallbackClass Spa RecipeFingerprint ExecutionPolicyFingerprint".Split(' ');
        if(required.Any(k=>x[k]==null) || Arr(x["RequestedScopes"]).Count==0 && x["Protocol"]?.ToString()!="OAuth2V1Implicit")return false;
        return t!="ApiAcceptance" || "OperationFingerprint Method ApiVersion ApprovalFingerprint".Split(' ').All(k=>x[k]!=null);
    }
    private static string Anchor(JsonObject c)=>Text(c,"EvidenceType")+"/"+Text(c,"Privacy")+"/"+Text(Obj(c["Source"]),"Id")+"/"+(Obj(c["Context"])["ClientId"]?.ToJsonString() ?? "")+"/"+(Obj(c["Context"])["ResourceId"]?.ToJsonString() ?? "");
    private static string CollectionKey(JsonObject c)=>Anchor(c)+"/"+Canon(c["Context"]);
    private static bool Success(string type,JsonObject r){var v=Obj(r["Value"]);return type switch{
        "IssuedScopes"=>Text(r,"Outcome")=="Succeeded" && v["ClaimsReadable"]?.ToJsonString()=="true" && Arr(v["Scopes"]).Count>0 && v["HasScpClaim"]?.ToJsonString()=="true" && v["NamespaceVerification"]?.ToString()=="Matched" && v["RequestVerification"]?.ToString()=="Matched",
        "ApiAcceptance"=>Text(r,"Outcome")=="Responded" && v["Status"]!=null,
        _=>Text(r,"Outcome")=="Observed"};}
    private static Dictionary<string,List<JsonObject>> Histories(JsonObject? c)=>c==null?new Dictionary<string,List<JsonObject>>(StringComparer.Ordinal):Arr(c["Records"]).Select(Obj).GroupBy(r=>Canon(r["Identity"])).ToDictionary(g=>g.Key,g=>g.OrderBy(r=>Date(r["ObservedAt"])).ThenBy(r=>Text(r,"RecordId"),StringComparer.Ordinal).ToList(),StringComparer.Ordinal);
    private static JsonObject? KnownSuccess(string type,List<JsonObject> history)=>history.GroupBy(r=>Date(r["ObservedAt"])).Where(g=>g.Select(r=>Canon(r["Value"])+"/"+Text(r,"Outcome")).Distinct(StringComparer.Ordinal).Count()==1).Select(g=>g.Last()).LastOrDefault(r=>Success(type,r));
    private static JsonNode? FirstDate(JsonObject r)=>r["FirstObservedAt"] ?? r["ObservedAt"];
    private static JsonObject? State(JsonObject? c,List<JsonObject> h){if(c==null)return null;var t=Text(c,"EvidenceType");var latest=h.LastOrDefault();var success=KnownSuccess(t,h);return Object(("Context",c["Context"]),("Privacy",c["Privacy"]),("CollectionStatus",c["Status"]),("Source",c["Source"]),("LatestOutcome",latest?["Outcome"]),("LatestObservedAt",latest?["ObservedAt"]),("LatestValue",latest?["Value"]),("LatestRecordId",latest?["RecordId"]),("LastKnownSuccess",success),("FirstCollectedObservationAt",h.OrderBy(r=>Date(FirstDate(r))).FirstOrDefault() is JsonObject first?FirstDate(first):null));}
    private static string[] Scopes(JsonObject? record)=>record?["Value"] is JsonObject v && v["Scopes"] is JsonArray a?a.Select(Str).ToArray():Array.Empty<string>();

    public static string Compare(string beforeJson,string afterJson,int maxAgeHours=24,DateTimeOffset? asOf=null,bool publicOnly=false)=>Guard(()=>{
        if(maxAgeHours is <1 or >87600)throw Invalid();var now=asOf ?? DateTimeOffset.UtcNow;if(now>DateTimeOffset.UtcNow.AddMinutes(5))throw Invalid();
        var before=Snapshot(Parse(beforeJson));var after=Snapshot(Parse(afterJson));var b=Arr(before["Collections"]).Select(Obj).ToList();var a=Arr(after["Collections"]).Select(Obj).ToList();
        if(publicOnly && b.Concat(a).Any(c=>Text(c,"Privacy")=="Private"))throw Invalid();
        var entries=new List<JsonObject>();var used=new HashSet<JsonObject>();var exact=b.ToDictionary(CollectionKey,StringComparer.Ordinal);var anchors=b.GroupBy(Anchor).ToDictionary(g=>g.Key,g=>g.ToList(),StringComparer.Ordinal);
        foreach(var newer in a.OrderBy(CollectionKey,StringComparer.Ordinal)){
            exact.TryGetValue(CollectionKey(newer),out var older);bool changed=false;
            if(older==null && anchors.TryGetValue(Anchor(newer),out var anchored)){changed=true;if(anchored.Count==1 && !used.Contains(anchored[0]))older=anchored[0];}
            if(older!=null)used.Add(older);CompareCollection(older,newer,changed,now,maxAgeHours,entries);
        }
        foreach(var older in b.Where(c=>!used.Contains(c)).OrderBy(CollectionKey,StringComparer.Ordinal))CompareCollection(older,null,false,now,maxAgeHours,entries);
        return Object(("Format","TokenForgeChangeReport"),("SchemaVersion",1),("AsOf",now.ToString("o")),("MaxAgeHours",maxAgeHours),("DiagnosticOnly",true),("AuthorizationEstablished",false),("RootCauseEstablished",false),("Entries",entries.OrderBy(e=>Text(e,"Key"),StringComparer.Ordinal).ToArray())).ToJsonString();
    });
    private static void CompareCollection(JsonObject? before,JsonObject? after,bool contextChanged,DateTimeOffset now,int hours,List<JsonObject> entries){
        var c=after ?? before!;var type=Text(c,"EvidenceType");var beforeHistories=Histories(before);var afterHistories=Histories(after);
        bool beforeComparable=before!=null && Comparable(before),afterComparable=after!=null && Comparable(after);
        bool futureCollection=new[]{before,after}.Any(collection=>collection!=null && Date(Obj(collection["Source"])["CollectedAt"])>now);
        bool reversedCollection=before!=null && after!=null && Date(Obj(after["Source"])["CollectedAt"])<Date(Obj(before["Source"])["CollectedAt"]);
        var identities=beforeHistories.Keys.Concat(afterHistories.Keys).Distinct(StringComparer.Ordinal).OrderBy(x=>x,StringComparer.Ordinal).ToArray();
        if(identities.Length==0){
            string kind=futureCollection?"Unknown":reversedCollection?"Incomparable":after==null?"LostVisibility":contextChanged?"Incomparable":!afterComparable?"Incomparable":Text(after,"Status")!="Complete" || before!=null && Text(before,"Status")!="Complete"?"Unknown":Date(Obj(after["Source"])["CollectedAt"])<now.AddHours(-hours)?"Stale":before==null?"Baseline":"Unchanged";
            entries.Add(Object(("SchemaVersion",1),("Key",Hash(CollectionKey(c)+"/collection")),("EvidenceType",type),("EventType",kind),("Identity",null),("Before",State(before,new List<JsonObject>())),("After",State(after,new List<JsonObject>())),("BeforeOutcome","NotObserved"),("AfterOutcome","NotObserved"),("LastKnownSuccess",null),("AddedScopes",Array.Empty<string>()),("RemovedScopes",Array.Empty<string>()),("Reasons",new[]{"Collection-level coverage only. An empty or inaccessible collection supplies no entity removal or account authorization."}),("RootCauseEstablished",false),("RegressionConfirmation","NotPerformed")));return;
        }
        foreach(var identity in identities){var bh=beforeHistories.GetValueOrDefault(identity) ?? new List<JsonObject>();var ah=afterHistories.GetValueOrDefault(identity) ?? new List<JsonObject>();var bl=bh.LastOrDefault();var al=ah.LastOrDefault();var bs=KnownSuccess(type,bh);var recentSuccess=KnownSuccess(type,ah);var chosen=after!=null && !contextChanged && recentSuccess!=null && (bs==null || Date(recentSuccess["ObservedAt"])>=Date(bs["ObservedAt"]))?recentSuccess:bs;
            JsonObject? lastSuccess=chosen==null?null:(JsonObject)chosen.DeepClone();if(lastSuccess!=null){var origin=ReferenceEquals(chosen,recentSuccess)?after!:before!;lastSuccess["Context"]=Copy(origin["Context"]);lastSuccess["Source"]=Copy(origin["Source"]);}
            string ev="Unchanged";var reasons=new List<string>();string[] added=Array.Empty<string>(),removed=Array.Empty<string>();
            bool bComplete=before!=null && Text(before,"Status")=="Complete",aComplete=after!=null && Text(after,"Status")=="Complete";
            if(futureCollection){ev="Unknown";reasons.Add("Collection is later than the report AsOf instant.");}
            else if(after==null){ev="LostVisibility";reasons.Add("Collection is absent; absence cannot establish removal.");}
            else if(contextChanged || before!=null && (Date(Obj(after["Source"])["CollectedAt"])<Date(Obj(before["Source"])["CollectedAt"]) || al!=null && bl!=null && Date(al["ObservedAt"])<Date(bl["ObservedAt"]))){ev="Incomparable";reasons.Add("Collection context changed; compare the exact source, account, query and request policy.");}
            else if(al!=null && Date(al["ObservedAt"])>now){ev="Unknown";reasons.Add("Evidence is later than the report AsOf instant.");}
            else if(new[]{bh,ah}.Any(h=>h.Count>1 && h.Where(r=>Date(r["ObservedAt"])==Date(h.Last()["ObservedAt"])).Select(r=>Canon(r["Value"])+"/"+Text(r,"Outcome")).Distinct(StringComparer.Ordinal).Count()>1)){ev="Unknown";reasons.Add("Conflicting latest records share an observation time; their order is unknown.");}
            else if(!afterComparable || before!=null && !beforeComparable){ev="Incomparable";reasons.Add("Required comparison provenance is unknown or anonymous; retained evidence cannot establish a private change.");}
            else if(!aComplete || before!=null && !bComplete){ev=Text(after,"Status") is "Denied" or "NotCollected" or "Incomplete"?"LostVisibility":"Unknown";reasons.Add("Collection completeness or visibility does not support a removal conclusion.");}
            else if((al==null?Date(Obj(after["Source"])["CollectedAt"]):Date(al["ObservedAt"]))<now.AddHours(-hours)){ev="Stale";reasons.Add("Latest after-evidence exceeds the explicit freshness policy.");}
            else if(before==null || bl==null){ev="Baseline";reasons.Add("First collected evidence is a baseline, not the date this permission became available.");if(al!=null && !Success(type,al)){ev="Unknown";reasons.Add("No successful first observation exists.");}else if(before!=null && type is "PermissionDefinition" or "PublicHint" or "ConfiguredGrant")ev=type=="PermissionDefinition"?"DefinitionAdded":type=="PublicHint"?"PublicHintAdded":"ConfiguredGrantAdded";}
            else if(al==null){if(bl!=null && Success(type,bl) && type is "PermissionDefinition" or "PublicHint" or "ConfiguredGrant"){ev=type=="PermissionDefinition"?"DefinitionRemoved":type=="PublicHint"?"PublicHintRemoved":"ConfiguredGrantRemoved";}else{ev="LostVisibility";reasons.Add("Missing issuance/API observations do not establish removal.");}}
            else if(!Success(type,al)){ev="Unknown";reasons.Add("Latest attempt did not produce verified comparable evidence; retained success remains historical.");}
            else{
                var prior=bs;if(prior==null){ev="Baseline";reasons.Add("No prior successful evidence exists for this exact context.");}
                else if(Canon(prior["Value"])!=Canon(al["Value"])){
                    ev=type switch{"PermissionDefinition"=>Obj(prior["Value"])["Name"]?.ToString()!=Obj(al["Value"])["Name"]?.ToString()?"DefinitionRenamed":"DefinitionChanged","PublicHint"=>"PublicHintChanged","ConfiguredGrant"=>"ConfiguredGrantChanged","IssuedScopes"=>"MatchedRequestScopesChanged",_=>"ApiAcceptanceChanged"};
                    if(type is "IssuedScopes" or "ConfiguredGrant"){added=Scopes(al).Except(Scopes(prior),StringComparer.Ordinal).OrderBy(x=>x,StringComparer.Ordinal).ToArray();removed=Scopes(prior).Except(Scopes(al),StringComparer.Ordinal).OrderBy(x=>x,StringComparer.Ordinal).ToArray();}
                }else if(Text(bl,"Outcome")!=Text(al,"Outcome"))ev="AttemptStatusChanged";
            }
            if(lastSuccess!=null && Date(lastSuccess["ObservedAt"])<now.AddHours(-hours))reasons.Add("Last-known success is stale; its observation date has not been refreshed.");
            if(type=="IssuedScopes")reasons.Add("Inspected scopes are diagnostic; no signature, API authorization, permission availability date or root cause is established.");
            if(type=="PublicHint")reasons.Add("Published hints are source claims, not tenant consent or configured grants.");
            if(type=="ConfiguredGrant")reasons.Add("Only the configured delegated edges visible to this tenant observer and query are compared.");
            if(type=="ApiAcceptance")reasons.Add("Only the separately approved saved operation is described; issuance alone does not establish API access.");
            if(reasons.Count==0)reasons.Add("Equivalent visible evidence context; source revision and local observation dates are retained separately.");
            var e=Object(("SchemaVersion",1),("Key",Hash(CollectionKey(c)+"/"+identity)),("EvidenceType",type),("EventType",ev),("Identity",(al ?? bl)!["Identity"]),("Before",State(before,bh)),("After",State(after,ah)),("BeforeOutcome",bl==null?"NotObserved":Text(bl,"Outcome")),("AfterOutcome",al==null?"NotObserved":Text(al,"Outcome")),("LastKnownSuccess",lastSuccess),("FirstCollectedObservationAt",bh.Concat(ah).OrderBy(r=>Date(FirstDate(r))).FirstOrDefault() is JsonObject firstRecord?FirstDate(firstRecord):null),("AddedScopes",added),("RemovedScopes",removed),("Reasons",reasons),("RootCauseEstablished",false),("RegressionConfirmation","NotPerformed"));entries.Add(e);
        }
    }
}
