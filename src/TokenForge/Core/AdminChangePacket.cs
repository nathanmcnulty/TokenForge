#nullable enable
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Text.Json.Nodes;
namespace TokenForge.Core;

public static partial class AdminWorkflows
{
    public static string Check(string profileJson,string requirementsJson,string inventoryJson,string snapshotJson,string toolId,string? prerequisiteJson=null,DateTimeOffset? asOf=null)=>Guard(()=>{
        var explanation=Parse(Explain(profileJson,requirementsJson,inventoryJson,snapshotJson,toolId,prerequisiteJson,asOf));var result=Header("TokenForgeToolHealth");result["ToolId"]=toolId;foreach(string key in new[]{"AsOf","Status","ExitCode","Clients","Prerequisites","InputSha256","CurrentAcquisitionPerformed","AuthorizationEstablished","Disclaimer"})result[key]=explanation[key]?.DeepClone();return result.ToJsonString();
    });
    public static string PreparePacket(string requirementsJson,string beforeJson,string afterJson,string sourceRevision,string packageManifestSha256,int maxEntries=64,int maxAgeHours=24,DateTimeOffset? asOf=null,bool securitySensitive=false)=>Guard(()=>{
        Match(sourceRevision,@"\A(?:[a-f0-9]{40}|[a-f0-9]{64})\z",64);Fingerprint(JsonValue.Create(packageManifestSha256));if(maxEntries is <1 or >128)throw Invalid();var requirements=Requirements(Parse(requirementsJson,1024*1024));string before=ChangeReports.ValidateSnapshot(beforeJson),after=ChangeReports.ValidateSnapshot(afterJson);var report=Parse(ChangeReports.Compare(before,after,maxAgeHours,asOf));
        var result=Header("TokenForgeToolChangePacket");result["Status"]="PreparedForHumanReview";result["ExitCode"]=0;result["AsOf"]=report["AsOf"]!.DeepClone();result["MaxAgeHours"]=maxAgeHours;result["ProducerVersion"]=CredentialRuntime.Version;result["ProducerSourceRevision"]=sourceRevision;result["PackageManifestSha256"]=packageManifestSha256;result["ProducerPinsAreCallerSupplied"]=true;result["RequirementsSha256"]=Hash(requirements);result["BeforeSnapshotSha256"]=Hash(Parse(before));result["AfterSnapshotSha256"]=Hash(Parse(after));result["RootCauseEstablished"]=false;result["RegressionConfirmation"]="NotPerformed";result["AutomaticCommunication"]=false;result["CommunicationAuthorized"]=false;result["SeparateReviewAndExplicitSendingAuthorizationRequired"]=true;result["IntendedAudience"]="MicrosoftOrToolMaintainers";
        var entries=new JsonArray();int affected=0,omitted=0;bool sensitive=securitySensitive;int bytes=0;
        foreach(var n in Arr(report["Entries"])){var change=Obj(n);if(Text(change["EventType"])=="Unchanged")continue;var tools=Arr(requirements["Tools"]).Select(Obj).Where(tool=>Affects(tool,change)).OrderBy(t=>Text(t["Id"]),StringComparer.Ordinal).ToArray();if(tools.Length==0)continue;affected++;sensitive|=tools.Any(tool=>Bool(tool["SecuritySensitive"]));var entry=new JsonObject{["AffectedTools"]=new JsonArray(tools.Select(t=>(JsonNode?)t["Id"]!.DeepClone()).ToArray()),["ImpactConclusion"]="PotentiallyRelevantTypedEvidenceNotProvenToolFailure",["Change"]=change.DeepClone()};int size=Encoding.UTF8.GetByteCount(entry.ToJsonString());if(entries.Count==maxEntries || bytes+size>1024*1024-16384){omitted++;continue;}entries.Add(entry);bytes+=size;}
        result["DisclosureRoute"]=sensitive?"PrivateSecurityDisclosure":"PrivateMaintainerReview";result["SecuritySensitive"]=sensitive;result["AffectedChangeCount"]=affected;result["RetainedEntryCount"]=entries.Count;result["OmittedEntryCount"]=omitted;result["Truncated"]=omitted>0;result["Entries"]=entries;result["Reproduction"]="Use the pinned package/source, matching complete saved snapshots and requirements digests, exact AsOf/freshness policy and request context. No authentication or live reproduction was performed. Review privately before separately authorizing any communication.";string output=result.ToJsonString();if(Encoding.UTF8.GetByteCount(output)>1024*1024)throw Invalid();return output;
    });
    private static bool Affects(JsonObject tool,JsonObject change){
        string resource=Text(tool["ResourceId"]),type=Text(change["EvidenceType"]);var states=new[]{change["Before"] as JsonObject,change["After"] as JsonObject}.Where(s=>s!=null).Select(s=>s!).ToArray();var identity=change["Identity"] as JsonObject;var clients=Values(tool["ClientIds"]);
        // Collection coverage has no entity identity: preserve lost visibility as potential impact.
        if(identity==null)return states.Any(s=>s["Context"] is JsonObject ctx && (ctx["ResourceId"]==null || Text(ctx["ResourceId"])==resource) && (ctx["ClientId"]==null || clients.Contains(Text(ctx["ClientId"]),StringComparer.Ordinal)));
        if(type=="PermissionDefinition")return identity?["PermissionType"]?.ToString()=="Delegated" && states.Any(s=>Obj(s["Context"])["ResourceId"]?.ToString()==resource) && states.Any(s=>s["LatestValue"] is JsonObject value && Values(tool["Scopes"]).Contains(value["Name"]?.ToString(),StringComparer.Ordinal));
        if(type=="PublicHint")return identity?["ClientId"]!=null && clients.Contains(Text(identity["ClientId"]),StringComparer.Ordinal);
        return identity?["ClientId"]!=null && identity?["ResourceId"]?.ToString()==resource && clients.Contains(Text(identity["ClientId"]),StringComparer.Ordinal);
    }
}
