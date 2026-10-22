#nullable enable
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace TokenForge.Core;

public static partial class ChangeReports
{
    private sealed class CollectionBuilder {
        internal readonly JsonArray Items=new JsonArray();
        private readonly Dictionary<string,JsonObject> index=new Dictionary<string,JsonObject>(StringComparer.Ordinal);
        internal JsonObject GetOrAdd(JsonObject c){c["Context"]=Context(Obj(c["Context"]));string key=CollectionKey(c);if(index.TryGetValue(key,out var existing))return existing;index.Add(key,c);Items.Add(c);return c;}
        internal void Add(JsonObject c){c["Context"]=Context(Obj(c["Context"]));string key=CollectionKey(c);if(!index.TryAdd(key,c))throw Invalid();Items.Add(c);}
    }
    private const string ScopeFields="ClientId ResourceId Outcome TenantFingerprint PrincipalFingerprint ObservedAt Protocol Spa RedirectFingerprint RequestedScopes ResponseScopes ScpScopes ClaimsReadable HasScpClaim NamespaceVerification RequestVerification SignatureValidated ErrorCodes AttemptCount ElapsedSeconds CatalogHash PlanFingerprint ComparisonContext";
    public static string Normalize(string kind,string json)=>Guard(()=>{
        var root=Parse(json);var digest=Hash(Canon(root));var collections=new CollectionBuilder();
        switch(kind){
            case "Snapshot":return Snapshot(root).ToJsonString();
            case "PublicPermissions":PublicPermissions(root,collections,digest);break;
            case "Discovery":Discovery(root,collections,digest);break;
            case "Inventory":Inventory(root,collections,digest);break;
            case "ScopeDatabase":ScopeDatabase(root,collections,digest);break;
            case "FlowEvidence":Flows(root,collections,digest);break;
            case "Anonymous":Anonymous(root,collections,digest);break;
            case "ApiChecks":ApiChecks(root,collections,digest);break;
            case "Maintenance":Maintenance(root,collections,digest);break;
            default:throw Invalid();
        }
        var result=Object(("Format","TokenForgeChangeSnapshot"),("SchemaVersion",1),("Collections",collections.Items));
        return Snapshot(result).ToJsonString();
    });
    public static string CompareSaved(string kind,string before,string after,int maxAgeHours=24,DateTimeOffset? asOf=null,bool publicOnly=false)=>Compare(Normalize(kind,before),Normalize(kind,after),maxAgeHours,asOf,publicOnly);
    private static JsonObject Source(string id,string inputDigest,JsonNode? collected,string? location=null)=>Object(("Id",id),("Location",location ?? "urn:sha256:"+Hash(id)),("ContentSha256",inputDigest),("HashKind","NormalizedDocument"),("SourceObservedAt",null),("CollectedAt",collected));
    private static JsonObject Collection(string type,string privacy,string status,JsonObject context,JsonObject source)=>Object(("EvidenceType",type),("Privacy",privacy),("Status",status),("Context",context),("Source",source),("Records",new JsonArray()));
    private static JsonObject NewRecord(JsonObject raw,JsonNode? date,string outcome,JsonObject identity,JsonObject value)=>Object(("RecordId",Hash(Canon(raw)+"|"+Date(date).ToUniversalTime().ToString("o"))),("ObservedAt",date),("Outcome",outcome),("Identity",identity),("Value",value));
    private static void AddGrouped(CollectionBuilder collections,JsonObject collection,JsonObject record){var target=collections.GetOrAdd(collection);var source=Obj(target["Source"]);var incoming=Obj(collection["Source"]);if(Date(incoming["CollectedAt"])>Date(source["CollectedAt"]))source["CollectedAt"]=Copy(incoming["CollectedAt"]);Arr(target["Records"]).Add(record);}
    private static void Version(JsonObject r){if(Int(r["SchemaVersion"])!=1)throw Invalid();}
    private static void Leaf(string name,JsonNode? n){using var d=JsonDocument.Parse(n?.ToJsonString() ?? "null");ApplicationCatalogPolicy.ValidateLeaf(name,d.RootElement);}
    private static void Attributes(JsonObject app,string kind){var attrs=(JsonObject)app.DeepClone();var sources=attrs["Sources"]?.DeepClone() ?? new JsonArray();attrs.Remove("Sources");var payload=Object(("Attributes",attrs),("Sources",sources),("ContentSha256",Hash(Canon(attrs))));using var d=JsonDocument.Parse(payload.ToJsonString());ApplicationCatalogPolicy.ValidatePayload(d.RootElement,kind,Text(app,"AppId"));}
    private static void ScopeDatabase(JsonObject root,CollectionBuilder output,string digest){Keys(root,"SchemaVersion UpdatedAt Observations RegistrationAttempts","SchemaVersion Observations");Version(root);if(root["UpdatedAt"]!=null)Date(root["UpdatedAt"]);
        // Validate the whole saved history, including records unrelated to any requested comparison.
        foreach(var n in Arr(root["Observations"])){var r=Obj(n);ValidateScopeRow(r);AddScope(output,digest,r,"scope-database",root["UpdatedAt"] ?? r["ObservedAt"]);}
        if(root["RegistrationAttempts"]!=null)foreach(var n in Arr(root["RegistrationAttempts"])){var r=Obj(n);Keys(r,"AppId TenantFingerprint AttemptedAt Outcome HttpStatus","AppId TenantFingerprint AttemptedAt Outcome");GuidValue(r["AppId"]);if(r["TenantFingerprint"]!=null)Digest(r["TenantFingerprint"]);Date(r["AttemptedAt"]);Enum(r["Outcome"],"Created AlreadyPresent Failed OwnerRejected CleanupRequired CleanupResolved NotCreated");if(r["HttpStatus"]!=null && (Int(r["HttpStatus"])<100 || Int(r["HttpStatus"])>599))throw Invalid();}
    }
    private static void ValidateScopeRow(JsonObject r){Keys(r,ScopeFields,"ClientId ResourceId Outcome ObservedAt");GuidValue(r["ClientId"]);GuidValue(r["ResourceId"]);Date(r["ObservedAt"]);
        foreach(var field in r){if(field.Value==null)continue;if(field.Key.EndsWith("Fingerprint",StringComparison.Ordinal) || field.Key=="CatalogHash")Digest(field.Value);else if(field.Key=="ComparisonContext"){ValidateBoundContext(field.Value.ToJsonString(),r.ToJsonString());}else if(field.Key is "RequestedScopes" or "ResponseScopes" or "ScpScopes")Strings(field.Value);else if(field.Key=="ErrorCodes"){foreach(var code in Arr(field.Value))Match(Str(code),"^[0-9]{4,9}$",9);}else if(field.Key is "Spa" or "ClaimsReadable" or "HasScpClaim" or "SignatureValidated"){if(field.Key=="SignatureValidated" && Bool(field.Value))throw Invalid();Bool(field.Value);}else if(field.Key is "AttemptCount" or "ElapsedSeconds")Leaf(field.Key,field.Value);}
        // Use the typed record validator even when legacy comparison context is incomplete.
        var record=ScopeRecord(r);ValidateRecord("IssuedScopes",record,RequestContext(r),"Private");
    }
    private static JsonObject RequestContext(JsonObject r){
        if(r["ComparisonContext"]!=null)return Obj(JsonNode.Parse(ValidateBoundContext(r["ComparisonContext"]!.ToJsonString(),r.ToJsonString())));
        var c=Object(("ContextVersion",1));foreach(var k in new[]{"TenantFingerprint","PrincipalFingerprint","ClientId","ResourceId","Protocol","Spa","RequestedScopes"})if(r.ContainsKey(k))c[k]=Copy(r[k]);if(r["RedirectFingerprint"]!=null)c["CallbackFingerprint"]=Copy(r["RedirectFingerprint"]);return Context(c);
    }
    private static JsonObject ScopeRecord(JsonObject r)=>NewRecord(r,r["ObservedAt"],Text(r,"Outcome"),Object(("ClientId",r["ClientId"]),("ResourceId",r["ResourceId"])),Object(("Scopes",r["ScpScopes"] ?? new JsonArray()),("NamespaceVerification",r["NamespaceVerification"]),("RequestVerification",r["RequestVerification"]),("ClaimsReadable",r["ClaimsReadable"]),("HasScpClaim",r["HasScpClaim"]),("SignatureValidated",false)));
    private static void AddScope(CollectionBuilder output,string inputDigest,JsonObject r,string source,JsonNode? collected)=>AddGrouped(output,Collection("IssuedScopes","Private","Complete",RequestContext(r),Source(source,inputDigest,collected)),ScopeRecord(r));
    public static string ValidateComparisonContext(string json)=>Guard(()=>Context(Parse(json)).ToJsonString());
    public static string ValidateBoundContext(string contextJson,string rowJson)=>Guard(()=>{
        var c=Context(Parse(contextJson));var r=Parse(rowJson);
        foreach(var k in new[]{"TenantFingerprint","PrincipalFingerprint","ClientId","ResourceId","Protocol","Spa","RequestedScopes"})if(r.ContainsKey(k) && Canon(c[k])!=Canon(r[k]))throw Invalid();
        if(r["RedirectFingerprint"]!=null && Canon(r["RedirectFingerprint"])!=Canon(c["CallbackFingerprint"]))throw Invalid();return c.ToJsonString();
    });
    private static void Flows(JsonObject root,CollectionBuilder output,string digest){FlowEvidencePolicy.ValidateDocument(root.ToJsonString());
        foreach(var n in Arr(root["Attempts"])){var r=Obj(n);var p=Obj(Obj(root["Plans"])[Text(r,"PlanFingerprint")]);var c=RequestContext(r);if(r["ComparisonContext"]!=null && c["AuthorityFingerprint"]?.ToString()!=Hash(Text(p,"Tenant")))throw Invalid();
            // Plan hashes remain exact-resume identities; missing historical recipe/budget data remains unknown.
            AddGrouped(output,Collection("IssuedScopes","Private","Complete",c,Source("flow-evidence",digest,root["UpdatedAt"])),ScopeRecord(r));
        }
    }
    private static void Anonymous(JsonObject root,CollectionBuilder output,string digest){Keys(root,"SchemaVersion Observations Disclaimer","SchemaVersion Observations");Version(root);if(root["Disclaimer"]!=null && Str(root["Disclaimer"]).Length>4096)throw Invalid();
        foreach(var n in Arr(root["Observations"])){var r=Obj(n);Keys(r,"ClientId ResourceId ObservedAt Scopes Evidence SignatureValidated","ClientId ResourceId ObservedAt Scopes Evidence SignatureValidated");GuidValue(r["ClientId"]);GuidValue(r["ResourceId"]);Date(r["ObservedAt"]);Enum(r["Evidence"],"AnonymousTenantTokenObservation");if(Bool(r["SignatureValidated"]))throw Invalid();
            var c=Object(("ContextVersion",1),("ClientId",r["ClientId"]),("ResourceId",r["ResourceId"]));var v=Object(("Scopes",Strings(r["Scopes"])),("ClaimsReadable",null),("HasScpClaim",null),("NamespaceVerification",null),("RequestVerification",null),("SignatureValidated",false));
            AddGrouped(output,Collection("IssuedScopes","Anonymous","Unknown",c,Source("anonymous-export",digest,r["ObservedAt"])),NewRecord(r,r["ObservedAt"],"Unknown",Object(("ClientId",r["ClientId"]),("ResourceId",r["ResourceId"])),v));
        }
    }
    private static void PublicPermissions(JsonObject root,CollectionBuilder output,string digest){Keys(root,"Format SchemaVersion Evidence ResourceId RetrievedAt Source Permissions","Format SchemaVersion Evidence ResourceId RetrievedAt Source Permissions");Version(root);if(Text(root,"Format")!="TokenForgePublicPermissions" || Text(root,"Evidence")!="PublicSourceDefinitions" || Text(root,"ResourceId")!="00000003-0000-0000-c000-000000000000")throw Invalid();Date(root["RetrievedAt"]);
        var s=Obj(root["Source"]);Keys(s,"Repository Path Commit RawSha256","Repository Path Commit RawSha256");if(Text(s,"Repository")!="https://github.com/microsoftgraph/microsoft-graph-devx-content" || Text(s,"Path")!="permissions/permissions-descriptions.json")throw Invalid();Match(Text(s,"Commit"),"^[a-f0-9]{40}$",40);Digest(s["RawSha256"]);
        var source=Source("graph-public-definitions",digest,root["RetrievedAt"],"https://raw.githubusercontent.com/microsoftgraph/microsoft-graph-devx-content/"+Text(s,"Commit")+"/"+Text(s,"Path"));source["ContentSha256"]=Copy(s["RawSha256"]);source["HashKind"]="RawSourceBytes";source["Commit"]=Copy(s["Commit"]);source["InputSha256"]=digest;
        var c=Collection("PermissionDefinition","Public","Complete",Object(("ContextVersion",1),("ResourceId",root["ResourceId"]),("QueryFingerprint",Hash("graph-public-definitions/v1/all-kinds"))),source);var p=Obj(root["Permissions"]);Keys(p,"delegatedScopesList applicationScopesList","delegatedScopesList applicationScopesList");
        foreach(var kind in new[]{"delegatedScopesList","applicationScopesList"}){var ids=new HashSet<string>();var names=new HashSet<string>();if(Arr(p[kind]).Count is <1 or >10000)throw Invalid();foreach(var n in Arr(p[kind])){var r=Obj(n);Keys(r,"id value isAdmin isEnabled consentDescription consentDisplayName adminConsentDescription adminConsentDisplayName allowedMemberTypes","id value isAdmin isEnabled consentDescription consentDisplayName");GuidValue(r["id"]);if(!ids.Add(Text(r,"id")) || !names.Add(Text(r,"value")))throw Invalid();Bool(r["isAdmin"]);Bool(r["isEnabled"]);
            if(kind=="delegatedScopesList" && (!r.ContainsKey("adminConsentDescription") || !r.ContainsKey("adminConsentDisplayName") || r.ContainsKey("allowedMemberTypes")) || kind=="applicationScopesList" && r.ContainsKey("adminConsentDescription")!=r.ContainsKey("adminConsentDisplayName"))throw Invalid();
            foreach(var f in r.Where(x=>x.Key.EndsWith("Description",StringComparison.Ordinal) || x.Key.EndsWith("DisplayName",StringComparison.Ordinal)))if(f.Value!=null && Str(f.Value).Length>8192)throw Invalid();if(kind=="applicationScopesList"){var members=Arr(r["allowedMemberTypes"]);if(members.Count is <1 or >2 || members.Select(Str).Distinct(StringComparer.Ordinal).Count()!=members.Count)throw Invalid();foreach(var m in members)Enum(m,"Application User");}
            Arr(c["Records"]).Add(NewRecord(r,root["RetrievedAt"],"Observed",Object(("Id",r["id"]),("PermissionType",kind=="delegatedScopesList"?"Delegated":"Application"),("Origin","PublicPublished")),Object(("Name",r["value"]),("Enabled",r["isEnabled"]))));
        }}output.Add(c);
    }
    private static void Discovery(JsonObject root,CollectionBuilder output,string digest){Keys(root,"SchemaVersion FetchedAt Sources CatalogContentSha256 InvalidSourceRecordCount SourceSnapshots Applications","SchemaVersion FetchedAt Applications");if(Int(root["SchemaVersion"]) is not (1 or 2))throw Invalid();Date(root["FetchedAt"]);if(root["CatalogContentSha256"]!=null)Digest(root["CatalogContentSha256"]);if(root["InvalidSourceRecordCount"]!=null && Int(root["InvalidSourceRecordCount"])<0)throw Invalid();
        if(root["Sources"]!=null)foreach(var s in Arr(root["Sources"]))if(Str(s).Length>4096)throw Invalid();
        if(root["SourceSnapshots"]!=null)foreach(var sn in Arr(root["SourceSnapshots"])){var s=Obj(sn);Keys(s,"Location Sha256 HashKind","Location Sha256 HashKind");if(Text(s,"Location").Length>4096 || Text(s,"HashKind").Length>64)throw Invalid();Digest(s["Sha256"]);}
        var ids=new HashSet<string>();var bySource=new Dictionary<string,JsonObject>(StringComparer.Ordinal);var claimsByClient=new Dictionary<string,List<JsonObject>>(StringComparer.Ordinal);var recordByClient=new Dictionary<string,JsonObject>(StringComparer.Ordinal);
        foreach(var n in Arr(root["Applications"])){var app=Obj(n);Attributes(app,"Discovery");GuidValue(app["AppId"]);if(!ids.Add(Text(app,"AppId")))throw Invalid();
            if(app["SourceClaims"] is not JsonArray claims)continue;
            foreach(var cn in claims){var claim=Obj(cn);string location=Text(claim,"Location"),id="public-hint/"+Hash(Text(claim,"SourceName")+"/"+location+"/"+Text(claim,"Evidence"));
                if(!bySource.TryGetValue(id,out var collection)){var source=Source(id,digest,root["FetchedAt"],location.StartsWith("https://raw.githubusercontent.com/",StringComparison.Ordinal)?location:null);collection=Collection("PublicHint","Public",root["InvalidSourceRecordCount"]!=null && Int(root["InvalidSourceRecordCount"])>0?"Incomplete":"Complete",Object(("ContextVersion",1),("QueryFingerprint",Hash("source-claims/v1/all"))),source);bySource.Add(id,collection);}
                var callbacks=new SortedSet<string>(StringComparer.Ordinal);if(claim["RedirectUris"]!=null)foreach(var u in Arr(claim["RedirectUris"]))callbacks.Add(Hash(Str(u)));if(claim["PreferredRedirectUri"]!=null)callbacks.Add(Hash(Text(claim,"PreferredRedirectUri")));
                var conflicts=new JsonArray();if(app["MetadataConflicts"]!=null)foreach(var cf in Arr(app["MetadataConflicts"])){var conflict=Obj(cf);conflicts.Add(Object(("Field",conflict["Field"]),("ValueHashes",Arr(conflict["Values"]).Select(x=>Hash(Str(x))).OrderBy(x=>x,StringComparer.Ordinal).ToArray())));}
                var value=Object(("Grants",claim["Grants"] ?? new JsonArray()),("CallbackFingerprints",callbacks.ToArray()),("MetadataSha256",Hash(Canon(claim))),("Conflicts",conflicts));string entity=id+"/"+Text(app,"AppId");if(!claimsByClient.TryGetValue(entity,out var claimHistory)){claimHistory=new List<JsonObject>();claimsByClient.Add(entity,claimHistory);}claimHistory.Add((JsonObject)claim.DeepClone());
                string[] claimHashes=claimHistory.Select(x=>Hash(Canon(x))).OrderBy(x=>x,StringComparer.Ordinal).ToArray();value["MetadataSha256"]=Hash(string.Join("\n",claimHashes));
                var grantsByResource=claimHistory.Where(x=>x["Grants"]!=null).SelectMany(x=>Arr(x["Grants"])).Select(Obj).GroupBy(x=>Text(x,"ResourceId")).OrderBy(g=>g.Key,StringComparer.Ordinal).Select(g=>Object(("ResourceId",g.Key),("Scopes",g.SelectMany(x=>Strings(x["Scopes"]).Select(Str)).Distinct(StringComparer.Ordinal).OrderBy(x=>x,StringComparer.Ordinal).ToArray()))).ToArray();value["Grants"]=new JsonArray(grantsByResource.Select(x=>(JsonNode?)x).ToArray());
                foreach(var priorClaim in claimHistory){if(priorClaim["RedirectUris"]!=null)foreach(var u in Arr(priorClaim["RedirectUris"]))callbacks.Add(Hash(Str(u)));if(priorClaim["PreferredRedirectUri"]!=null)callbacks.Add(Hash(Text(priorClaim,"PreferredRedirectUri")));}value["CallbackFingerprints"]=new JsonArray(callbacks.Select(x=>(JsonNode?)JsonValue.Create(x)).ToArray());
                var raw=Object(("ClientId",app["AppId"]),("Claims",claimHashes),("Conflicts",conflicts));var newRecord=NewRecord(raw,root["FetchedAt"],"Observed",Object(("ClientId",app["AppId"])),value);
                if(recordByClient.TryGetValue(entity,out var priorRecord))Arr(collection["Records"]).Remove(priorRecord);Arr(collection["Records"]).Add(newRecord);recordByClient[entity]=newRecord;
            }
        }
        bool missingClaims=Arr(root["Applications"]).Any(n=>Obj(n)["SourceClaims"] is not JsonArray);
        foreach(var c in bySource.Values){if(missingClaims)c["Status"]="Unknown";output.Add(c);}
    }
    private static string Visibility(string status)=>status switch{"Complete"=>"Complete","Forbidden"=>"Denied","Failed"=>"Failed","Skipped" or "NotRun"=>"NotCollected",_=>"Unknown"};
    private static JsonObject CoverageContext(JsonObject root,string query){var c=Object(("ContextVersion",1),("TenantFingerprint",root["TenantFingerprint"]),("ObserverFingerprint",root["PrincipalFingerprint"]));if(root["EvidenceCoverage"] is JsonObject coverage){Keys(coverage,"SchemaVersion InventoryQueryFingerprint GrantQueryFingerprint","SchemaVersion InventoryQueryFingerprint GrantQueryFingerprint");Version(coverage);Digest(coverage["InventoryQueryFingerprint"]);Digest(coverage["GrantQueryFingerprint"]);c["QueryFingerprint"]=Copy(coverage[query]);}return c;}
    private static void Inventory(JsonObject root,CollectionBuilder output,string digest){Keys(root,"SchemaVersion CapturedAt TenantFingerprint PrincipalFingerprint TotalTenantServicePrincipalCount VerifiedMicrosoftServicePrincipalCount GrantEnumeration Applications TenantGrants DiscoveryCatalogHash EvidenceCoverage","SchemaVersion CapturedAt TenantFingerprint PrincipalFingerprint GrantEnumeration Applications TenantGrants");Version(root);Date(root["CapturedAt"]);Digest(root["TenantFingerprint"]);if(root["PrincipalFingerprint"]!=null)Digest(root["PrincipalFingerprint"]);if(root["DiscoveryCatalogHash"]!=null)Digest(root["DiscoveryCatalogHash"]);Enum(root["GrantEnumeration"],"Skipped Complete Forbidden Failed");foreach(var k in new[]{"TotalTenantServicePrincipalCount","VerifiedMicrosoftServicePrincipalCount"})if(root[k]!=null && Int(root[k])<0)throw Invalid();
        var source=Source("tenant-inventory",digest,root["CapturedAt"]);var ctx=CoverageContext(root,"InventoryQueryFingerprint");var ids=new HashSet<string>();
        foreach(var n in Arr(root["Applications"])){var app=Obj(n);Attributes(app,"Inventory");GuidValue(app["AppId"]);if(!ids.Add(Text(app,"AppId")))throw Invalid();
            var dc=(JsonObject)ctx.DeepClone();dc["ResourceId"]=Copy(app["AppId"]);var c=Collection("PermissionDefinition","Private",app["Registration"]?.ToString()=="Present" && app["Ownership"]?.ToString()=="VerifiedMicrosoftOwner" && app["DelegatedScopeDefinitions"] is JsonArray && app["AppRoleDefinitions"] is JsonArray?"Complete":"Unknown",dc,(JsonObject)source.DeepClone());
            foreach(var kind in new[]{"DelegatedScopeDefinitions","AppRoleDefinitions"})if(app[kind]!=null)foreach(var dn in Arr(app[kind])){var d=Obj(dn);string origin=kind=="DelegatedScopeDefinitions"?"ServicePrincipal":d["Origin"]?.ToString() ?? "Unknown";
                Arr(c["Records"]).Add(NewRecord(d,root["CapturedAt"],"Observed",Object(("Id",d["Id"]),("PermissionType",kind=="DelegatedScopeDefinitions"?"Delegated":"Application"),("Origin",origin)),Object(("Name",d["Value"]),("Enabled",d["Enabled"]))));
            }output.Add(c);
        }
        var grants=Collection("ConfiguredGrant","Private",Visibility(Text(root,"GrantEnumeration")),CoverageContext(root,"GrantQueryFingerprint"),source);AddGrants(grants,Arr(root["TenantGrants"]),root["CapturedAt"]);output.Add(grants);
    }
    private static void AddGrants(JsonObject collection,JsonArray grants,JsonNode? observed){
        // Legacy producers save aggregate visible edges, not Graph grant object IDs. Never label app IDs as SP object IDs.
        var edges=new Dictionary<string,(JsonObject id,SortedSet<string> scopes)>(StringComparer.Ordinal);
        foreach(var n in grants){var g=Obj(n);Keys(g,"ClientId ResourceId Scopes PrincipalFingerprint ConsentType AppliesToCurrentPrincipal Evidence","ClientId ResourceId Scopes PrincipalFingerprint ConsentType AppliesToCurrentPrincipal Evidence");GuidValue(g["ClientId"]);GuidValue(g["ResourceId"]);if(g["PrincipalFingerprint"]!=null)Digest(g["PrincipalFingerprint"]);Enum(g["ConsentType"],"Principal AllPrincipals");Bool(g["AppliesToCurrentPrincipal"]);Enum(g["Evidence"],"TenantConfiguredGrant");var id=Object(("ClientId",g["ClientId"]),("ResourceId",g["ResourceId"]),("GrantType",g["ConsentType"]),("SubjectFingerprint",g["PrincipalFingerprint"]));string key=Canon(id);if(!edges.TryGetValue(key,out var edge))edge=(id,new SortedSet<string>(StringComparer.Ordinal));foreach(var scope in Strings(g["Scopes"]))edge.scopes.Add(Str(scope));edges[key]=edge;}
        foreach(var edge in edges.Values){var value=Object(("Scopes",edge.scopes.ToArray()));Arr(collection["Records"]).Add(NewRecord(Object(("Identity",edge.id),("Value",value)),observed,"Observed",edge.id,value));}
    }
    private static void ApiChecks(JsonObject root,CollectionBuilder output,string digest){Keys(root,"Format SchemaVersion CollectedAt Checks","Format SchemaVersion CollectedAt Checks");Version(root);if(Text(root,"Format")!="TokenForgeApiChecks")throw Invalid();Date(root["CollectedAt"]);
        foreach(var n in Arr(root["Checks"])){var r=Obj(n);Keys(r,"ResourceId Status Accepted Evidence CheckedAt ComparisonContext","ResourceId Status Accepted Evidence CheckedAt");GuidValue(r["ResourceId"]);Date(r["CheckedAt"]);Enum(r["Evidence"],"ReadOnlyApiResponse");var c=r["ComparisonContext"]==null?Object(("ContextVersion",1),("ResourceId",r["ResourceId"])):Obj(JsonNode.Parse(ValidateComparisonContext(r["ComparisonContext"]!.ToJsonString())));if(Canon(c["ResourceId"])!=Canon(r["ResourceId"]))throw Invalid();
            var value=Object(("Status",r["Status"]),("Accepted",r["Accepted"]));var record=NewRecord(r,r["CheckedAt"],r["Status"]==null?"Unknown":"Responded",Object(("ClientId",c["ClientId"]),("ResourceId",r["ResourceId"])),value);AddGrouped(output,Collection("ApiAcceptance","Private","Complete",c,Source("api-checks",digest,root["CollectedAt"])),record);
        }
    }
    private static void Maintenance(JsonObject root,CollectionBuilder output,string digest){string context=Text(root,"Context");var parts=context.Split('/');if(parts.Length!=4 || parts[0]!="private-maintenance" || parts[1]!="v1")throw Invalid();MaintenanceSnapshot.ValidateDocument(root.ToJsonString(),parts[2],parts[3]);var last=Obj(root["LastRun"]);var history=Arr(root["GrantHistory"]);
        // Retained grant evidence stays at LastSeenAt. A newer failed run never refreshes it.
        var c=Collection("ConfiguredGrant","Private",Visibility(Text(last,"Grants")),Object(("ContextVersion",1),("TenantFingerprint",parts[2]),("ObserverFingerprint",parts[3])),Source("maintenance-grants",digest,last["FinishedAt"]));
        foreach(var n in history){var h=Obj(n);var one=Collection("ConfiguredGrant","Private","Complete",Obj(c["Context"]).DeepClone() as JsonObject ?? throw Invalid(),Obj(c["Source"]).DeepClone() as JsonObject ?? throw Invalid());AddGrants(one,Arr(h["Grants"]),h["LastSeenAt"]);foreach(var r in Arr(one["Records"])){var saved=(JsonObject)Obj(r).DeepClone();saved["FirstObservedAt"]=Copy(h["FirstSeenAt"]);Arr(c["Records"]).Add(saved);}}output.Add(c);
    }
}
