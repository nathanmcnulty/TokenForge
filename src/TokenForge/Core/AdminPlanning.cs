#nullable enable
using System;
using System.Linq;
using System.Text.Json.Nodes;
namespace TokenForge.Core;

public static partial class AdminWorkflows
{
    public static string Plan(string profileJson,string requirementsJson,string inventoryJson,string toolId,string? selectedClient=null,string? selectedCallback=null)=>Guard(()=>{
        var profile=Profile(Parse(profileJson,32768));var requirements=Requirements(Parse(requirementsJson,1024*1024));var inventory=Parse(inventoryJson);ChangeReports.Normalize("Inventory",inventoryJson);var tool=Tool(requirements,toolId);
        return PlanTool(profile,tool,inventory,selectedClient,selectedCallback).ToJsonString();
    });
    private static ScopePlanning.RequestRow? BootstrapRoute(JsonObject profile,JsonObject inventory,DateTimeOffset? now=null){try{return ScopePlanning.BootstrapRequest(inventory.ToJsonString(),Text(profile["Tenant"]),Text(profile["BootstrapClientId"]),Int(profile["MaxAgeHours"]),now);}catch{return null;}}
    private static JsonObject PlanTool(JsonObject profile,JsonObject tool,JsonObject inventory,string? selectedClient,string? selectedCallback){
        if(selectedClient!=null)GuidId(JsonValue.Create(selectedClient));if(selectedCallback!=null)Fingerprint(JsonValue.Create(selectedCallback));
        var plan=Header("TokenForgeStrictPlan");plan["ToolId"]=tool["Id"]!.DeepClone();plan["Status"]="Blocked";plan["ExitCode"]=4;plan["Reason"]="NoSilentRoute";plan["Dispatched"]=false;
        if(!Equal(inventory["TenantFingerprint"],profile["ExpectedTenantFingerprint"]) || !Fresh(inventory["CapturedAt"],DateTimeOffset.UtcNow,Int(profile["MaxAgeHours"]))){plan["Reason"]="InventoryNeedsObservation";plan["Status"]="NeedsObservation";plan["ExitCode"]=3;return plan;}
        if(Text(tool["Protocol"])!="OAuth2V2Pkce"){plan["Reason"]="UnsupportedStrictProtocol";return plan;}
        var apps=Arr(inventory["Applications"]).Select(Obj).ToDictionary(a=>Text(a["AppId"]),StringComparer.Ordinal);if(!apps.TryGetValue(Text(tool["ResourceId"]),out var resource) || !Eligible(resource)){plan["Reason"]="ResourceNotVerifiedEnabled";return plan;}
        var bootstrap=BootstrapRoute(profile,inventory);if(bootstrap==null){plan["Reason"]="NoSilentBootstrapRoute";return plan;}plan["BootstrapClientId"]=bootstrap.ClientId;plan["BootstrapCallbackFingerprint"]=ApplicationCatalogPolicy.Hash(bootstrap.RedirectUri);
        string[] approved=Values(profile["ApprovedClientIds"]);foreach(var id in Values(tool["ClientIds"]).Where(id=>approved.Contains(id,StringComparer.Ordinal) && (selectedClient==null || id==selectedClient)).OrderBy(id=>id,StringComparer.Ordinal)){
            if(!apps.TryGetValue(id,out var app) || !Eligible(app) || app["RedirectUris"] is not JsonArray callbacks)continue;
            foreach(string callback in callbacks.Select(Text).Where(uri=>Callback(uri,Text(tool["CallbackClass"]))).Where(uri=>selectedCallback==null || ApplicationCatalogPolicy.Hash(uri)==selectedCallback).OrderBy(uri=>uri,StringComparer.Ordinal)){
                plan["Status"]="ReadyForExplicitSilentAttempt";plan["ExitCode"]=0;plan["Reason"]="OneApprovedRequestSelectedNoFallback";plan["ClientId"]=id;plan["ResourceId"]=tool["ResourceId"]!.DeepClone();plan["Scopes"]=tool["Scopes"]!.DeepClone();plan["CallbackUri"]=callback;plan["Context"]=ContextFor(profile,tool,id,callback);plan["ProfileSha256"]=Hash(profile);plan["ToolSha256"]=Hash(tool);return plan;
            }
        }return plan;
    }
}
