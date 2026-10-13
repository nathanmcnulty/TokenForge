#nullable enable
using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace TokenForge.Core;

// Complete catalog/flow documents are validated before context or app selection.
// The engine has no transport, credential, file, or database dependencies.
public static class ResearchCoverage
{
    public static string CreateFromValidatedDocuments(string catalogJson, string? flowJson=null,
        string? tenant=null, string? principal=null, string[]? appIds=null,
        int maxAgeHours=24, bool summaryOnly=false, DateTimeOffset? now=null)
    {
        if(string.IsNullOrEmpty(tenant))tenant=null;
        if(string.IsNullOrEmpty(principal))principal=null;
        if(string.IsNullOrEmpty(flowJson))flowJson=null;
        if ((tenant==null)!=(principal==null) || maxAgeHours is <1 or >8760) throw Invalid();
        if (tenant!=null && (!Regex.IsMatch(tenant,"^[a-f0-9]{64}$") || !Regex.IsMatch(principal!,"^[a-f0-9]{64}$"))) throw Invalid();
        var clock=now ?? DateTimeOffset.UtcNow;
        var selected=appIds==null ? null : new HashSet<string>(appIds.Select(x=>Guid.Parse(x).ToString()),StringComparer.Ordinal);
        // The shared policies include historical records, source claims, and plan bindings.
        ApplicationCatalogPolicy.ValidateDocument(catalogJson);
        if(flowJson!=null)FlowEvidencePolicy.ValidateDocument(flowJson);
        using var catalog=Parse(catalogJson);
        using var flows=flowJson==null ? null : Parse(flowJson);
        var plans=new Dictionary<string,(string Hash,JsonElement Plan)>(StringComparer.Ordinal);
        var attempts=new Dictionary<string,JsonElement>(StringComparer.Ordinal);
        DateTimeOffset Instant(JsonElement row,string field) {
            var text=row.GetProperty(field).GetString();
            if(text==null || !Regex.IsMatch(text,@"^\d{4}-\d{2}-\d{2}T[^\r\n]+(Z|[+-]\d{2}:\d{2})$") ||
                !DateTimeOffset.TryParse(text,CultureInfo.InvariantCulture,DateTimeStyles.None,out var value) || value>clock.AddMinutes(5)) throw Invalid();
            return value.ToUniversalTime();
        }
        if(tenant!=null && flows!=null) {
            foreach(var entry in flows.RootElement.GetProperty("Plans").EnumerateObject()) {
                var p=entry.Value;
                if(Text(p,"TenantFingerprint")!=tenant || Text(p,"PrincipalFingerprint")!=principal)continue;
                string pair=Text(p,"ClientId")+"/"+Text(p,"ResourceId");
                if(!plans.TryGetValue(pair,out var old) || Instant(p,"PlannedAt")>Instant(old.Plan,"PlannedAt") ||
                    Instant(p,"PlannedAt")==Instant(old.Plan,"PlannedAt") && StringComparer.Ordinal.Compare(entry.Name,old.Hash)>0)
                    plans[pair]=(entry.Name,p);
            }
            foreach(var row in flows.RootElement.GetProperty("Attempts").EnumerateArray()) {
                if(Text(row,"TenantFingerprint")!=tenant || Text(row,"PrincipalFingerprint")!=principal)continue;
                string slot=Text(row,"AttemptKey");
                // Equal instants use later input order, matching checkpoint append order.
                if(!attempts.TryGetValue(slot,out var old) || Instant(row,"ObservedAt")>=Instant(old,"ObservedAt"))attempts[slot]=row;
            }
        }
        var plansByClient=plans.Values.ToLookup(x=>Text(x.Plan,"ClientId"),StringComparer.Ordinal);
        var attemptsByPlan=attempts.Values.ToLookup(x=>Text(x,"PlanFingerprint"),StringComparer.Ordinal);
        var rows=new List<Dictionary<string,object?>>();
        var allPlans=new List<Dictionary<string,object?>>();
        foreach(var app in catalog.RootElement.GetProperty("Applications").EnumerateObject().OrderBy(x=>x.Name,StringComparer.Ordinal)) {
            if(selected!=null && !selected.Contains(app.Name))continue;
            var records=app.Value.GetProperty("Records").EnumerateObject().OrderBy(x=>x.Name,StringComparer.Ordinal).ToArray();
            JsonElement? Latest(string kind,bool present=true) {
                JsonElement? result=null;
                foreach(var entry in records) {
                    var r=entry.Value;
                    if(Text(r,"Kind")!=kind || present && !r.GetProperty("PresentInLatestRun").GetBoolean())continue;
                    if(kind!="Discovery" && (tenant==null || Text(r,"TenantFingerprint")!=tenant))continue;
                    if(result==null || Instant(r,"LastSeenAt")>=Instant(result.Value,"LastSeenAt"))result=r;
                }
                return result;
            }
            var discovery=Latest("Discovery");var inventory=Latest("Inventory");var registration=Latest("RegistrationAttempts",false);var signin=Latest("SignIns");
            var attrs=inventory?.GetProperty("Attributes") ?? discovery?.GetProperty("Attributes");
            object? Attribute(string field)=>attrs.HasValue && attrs.Value.TryGetProperty(field,out var value) ? value.Clone() : null;
            bool HasItems(string field)=>attrs.HasValue && attrs.Value.TryGetProperty(field,out var value) && value.ValueKind==JsonValueKind.Array && value.GetArrayLength()>0;
            bool client=Attribute("PublicClient") is JsonElement pc && pc.ValueKind!=JsonValueKind.Null || HasItems("Grants") || HasItems("PublishedGrants");
            bool resource=Attribute("IsResourceCandidate") is JsonElement rc && rc.ValueKind==JsonValueKind.True || HasItems("DelegatedScopeDefinitions");
            var hints=new SortedSet<string>(StringComparer.Ordinal);
            if(Attribute("RedirectUris") is JsonElement redirects && redirects.ValueKind==JsonValueKind.Array)
                foreach(var redirect in redirects.EnumerateArray()) {
                    string uri=redirect.GetString()!;
                    // Describe published structure, not execution eligibility or host ownership.
                    if(uri.Length>2048 || uri!=uri.Trim() || uri.Any(char.IsControl) ||
                        !Uri.TryCreate(uri,UriKind.Absolute,out var callback) || callback.UserInfo.Length!=0 ||
                        callback.Query.Length!=0 || callback.Fragment.Length!=0) {
                        hints.Add("OtherCallbackPublished");continue;
                    }
                    if(callback.Scheme.StartsWith("brk-",StringComparison.Ordinal) || callback.Scheme=="ms-appx-web")hints.Add("BrokerCallbackPublished");
                    else if(callback.Scheme=="urn" || (callback.Scheme is "http" or "https") && callback.Host=="localhost" ||
                        callback.Scheme=="https" && callback.AbsolutePath.EndsWith("/oauth2/nativeclient",StringComparison.Ordinal))hints.Add("NativeCallbackPublished");
                    else if(callback.Scheme=="https")hints.Add("BrowserCallbackPublished");
                    else hints.Add("OtherCallbackPublished");
                }
            var coverage=new List<Dictionary<string,object?>>();
            foreach(var entry in plansByClient[app.Name].OrderBy(x=>Text(x.Plan,"ResourceId"),StringComparer.Ordinal)) {
                var p=entry.Plan;var latest=attemptsByPlan[entry.Hash].ToArray();
                var success=latest.Where(x=>Text(x,"Outcome")=="Succeeded").ToArray();int Count(string outcome)=>latest.Count(x=>Text(x,"Outcome")==outcome);
                int cells=p.GetProperty("Cells").GetArrayLength();if(latest.Length>cells)throw Invalid();
                var c=new Dictionary<string,object?> {
                    ["ResourceId"]=Text(p,"ResourceId"),["PlanFingerprint"]=entry.Hash,["Eligibility"]=Text(p,"Eligibility"),
                    ["PlannedSlots"]=cells,["TerminalSlots"]=latest.Length-Count("Started"),["InterruptedSlots"]=Count("Started"),["UntestedSlots"]=cells-latest.Length,
                    ["SuccessfulSlots"]=success.Length,["FailedSlots"]=Count("Failed"),["ContextMismatchSlots"]=Count("ContextMismatch"),
                    ["ObservedProtocols"]=success.Select(x=>Text(x,"Protocol")).Distinct(StringComparer.Ordinal).OrderBy(x=>x,StringComparer.Ordinal).ToArray(),
                    ["SpaRedemptionObserved"]=success.Any(x=>x.GetProperty("Spa").GetBoolean()),
                    ["LatestObservationAt"]=latest.Length==0 ? null : Instant(latest.OrderBy(x=>Instant(x,"ObservedAt")).Last(),"ObservedAt").ToString("o",CultureInfo.InvariantCulture),
                    ["FreshSuccessfulSlots"]=success.Count(x=>Instant(x,"ObservedAt")>=clock.AddHours(-maxAgeHours)),
                    ["Evidence"]="ObservedForSelectedAccountNotUniversalSupport",["ApiAcceptance"]="NotEstablishedByTokenProbe"};
                coverage.Add(c);allPlans.Add(c);
            }
            var conflicts=discovery.HasValue && discovery.Value.GetProperty("Attributes").TryGetProperty("MetadataConflicts",out var mc) ? mc.Clone() : JsonSerializer.SerializeToElement(Array.Empty<object>());
            rows.Add(new Dictionary<string,object?> {
                ["AppId"]=app.Name,["Name"]=Attribute("Name") ?? app.Name,["FirstSeenAt"]=Instant(app.Value,"FirstSeenAt").ToString("o",CultureInfo.InvariantCulture),["LastSeenAt"]=Instant(app.Value,"LastSeenAt").ToString("o",CultureInfo.InvariantCulture),
                ["PublishedInLatestSnapshot"]=discovery.HasValue,["RoleHint"]=client ? (resource ? "ClientAndResource" : "Client") : resource ? "Resource" : "Unknown",
                ["Ownership"]=Attribute("Ownership") ?? "Unknown",["Registration"]=inventory.HasValue ? Attribute("Registration") ?? "Unknown" : "Unknown",
                ["LatestRegistrationOutcome"]=registration?.GetProperty("Attributes").GetProperty("Outcome").Clone(),
                ["RegistrationNeedsInventoryRefresh"]=registration.HasValue && (!inventory.HasValue || Instant(registration.Value,"LastSeenAt")>Instant(inventory.Value,"LastSeenAt")),
                ["PublishedFlowHints"]=hints.ToArray(),["MetadataConflicts"]=conflicts,["SignInSummary"]=signin?.GetProperty("Attributes").Clone(),["FlowCoverage"]=coverage,
                ["Classification"]="DiagnosticEvidenceOnly",["FlowContext"]=tenant==null ? "SelectTenantAndPrincipal" : "SelectedAccount"});
        }
        int Sum(string field)=>allPlans.Sum(x=>(int)x[field]!);
        return JsonSerializer.Serialize(new {
            SchemaVersion=1,ApplicationCount=rows.Count,ApplicationsWithSelectedPlans=rows.Count(x=>((List<Dictionary<string,object?>>)x["FlowCoverage"]!).Count>0),
            ApplicationsWithObservedSuccess=rows.Count(x=>((List<Dictionary<string,object?>>)x["FlowCoverage"]!).Any(c=>(int)c["SuccessfulSlots"]!>0)),
            ApplicationsWithMetadataConflicts=rows.Count(x=>((JsonElement)x["MetadataConflicts"]!).GetArrayLength()>0),
            PlannedSlots=Sum("PlannedSlots"),TerminalSlots=Sum("TerminalSlots"),UntestedSlots=Sum("UntestedSlots"),InterruptedSlots=Sum("InterruptedSlots"),
            Applications=summaryOnly ? new List<Dictionary<string,object?>>() : rows,
            Evidence="CatalogAndSelectedLatestPlanMetadataNoAuthentication",Scope="SelectedAccountPlansOnly",RequiredAuthenticationFlow="NotInferred"});
    }
    private static string Text(JsonElement row,string field)=>row.GetProperty(field).GetString() ?? "";
    private static JsonDocument Parse(string json) {
        if(Encoding.UTF8.GetByteCount(json)>128*1024*1024)throw Invalid();
        return JsonDocument.Parse(json,new JsonDocumentOptions{MaxDepth=100});
    }
    private static InvalidOperationException Invalid()=>new("Invalid research coverage input; details suppressed.");
}
