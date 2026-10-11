using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Security.Cryptography;
using TokenForge.Core.V0240;

namespace TokenForge.Core;

// Metadata-only planning. Neither hints nor observed payload scopes establish consent or API access.
public static class ScopePlanning
{
    private sealed record Observation(string Client, string Resource, string? Tenant, string? Principal,
        DateTimeOffset Date, string Outcome, string? Namespace, string? Request, string[] Scopes,
        string? Redirect, string Protocol, bool? Spa, string[] Requested);
    private sealed record Application(string Id, string? Name, string? Registration, string? Ownership,
        bool? Enabled, string[] Redirects, Dictionary<string,string[]> Published);
    private sealed record Grant(string Client,string Resource,string? Principal,string? Consent,string[] Scopes);
    private sealed record Inventory(DateTimeOffset Captured,string Tenant,string Enumeration,Application[] Apps,Grant[] Grants);
    public sealed record CoverageRow(string ClientId,string ResourceId,bool CoversAll,string[] MissingScopes,
        string[] AdditionalScopes,int AdditionalScopeCount,int ObservedApiScopeCount,string? RedirectFingerprint,
        string ObservedAt,string Protocol,bool? Spa,string Evidence="ObservedScpNotApiAuthorization");
    public sealed record CandidateRow(string ClientId,string? Name,string ResourceId,string? Registration,
        string? Ownership,bool? AccountEnabled,bool InventoryFresh,string InventoryCapturedAt,bool ResourceEligible,
        string GrantEnumeration,string[] PublishedScopes,string[] PublishedMissingScopes,string[] ApplicableConfiguredGrantScopes,
        string ConfiguredGrantStatus,string[]? ConfiguredGrantMissingScopes,string[] FreshObservedScopes,
        string[] ObservedMissingScopes,int? ObservedAdditionalScopeCount,bool ClientEligible,string ObservationStatus,string LatestOutcome,
        string? ObservedAt,string Protocol,string[] RequestedScopes,bool BrowserCallbackAvailable,int CandidateRank,
        string Evidence="PlanningHintsNotGuaranteedSilentExplicitAuthorization");

    public static string Coverage(string databaseJson,string resource,string[] scopes,string tenant,string principal,
        int maxAgeHours=24,DateTimeOffset? now=null)
    {
        try
        {
            ValidateRequest(ref resource,ref scopes,tenant,principal,maxAgeHours);
            var instant=now ?? DateTimeOffset.UtcNow;
            return JsonSerializer.Serialize(CoverageRows(Latest(ParseObservations(databaseJson),resource,tenant,principal),resource,scopes,maxAgeHours,instant));
        }
        catch{throw new InvalidOperationException("Scope planning failed. Details suppressed.");}
    }
    public static string Candidates(string inventoryJson,string databaseJson,string resource,string[] scopes,
        string principal,int maxAgeHours=24,DateTimeOffset? now=null)
    {
        try
        {
            var inventory=ParseInventory(inventoryJson);
            ValidateRequest(ref resource,ref scopes,inventory.Tenant,principal,maxAgeHours);
            var instant=now ?? DateTimeOffset.UtcNow;
            var latest=Latest(ParseObservations(databaseJson),resource,inventory.Tenant,principal);
            return JsonSerializer.Serialize(CandidateRows(inventory,latest,resource,scopes,principal,maxAgeHours,instant));
        }
        catch{throw new InvalidOperationException("Scope planning failed. Details suppressed.");}
    }
    private static CandidateRow[] CandidateRows(Inventory inventory,Dictionary<string,Observation> latest,string resource,string[] scopes,string principal,int maxAgeHours,DateTimeOffset instant)
    {
        var coverage=CoverageRows(latest,resource,scopes,maxAgeHours,instant).ToDictionary(x=>x.ClientId,StringComparer.Ordinal);
        bool fresh=Fresh(inventory.Captured,instant,maxAgeHours);
        bool resourceEligible=inventory.Apps.Any(a=>a.Id==resource && Eligible(a));
        var grantScopes=inventory.Grants.Where(g=>g.Resource==resource && (g.Consent=="AllPrincipals" || g.Consent=="Principal" && g.Principal==principal))
            .GroupBy(g=>g.Client,StringComparer.Ordinal).ToDictionary(g=>g.Key,g=>Canonical(g.SelectMany(x=>x.Scopes)),StringComparer.Ordinal);
        var rows=new List<CandidateRow>();
        foreach(var app in inventory.Apps)
        {
            var published=app.Published.GetValueOrDefault(resource) ?? System.Array.Empty<string>();
            var grants=grantScopes.GetValueOrDefault(app.Id) ?? System.Array.Empty<string>();
            latest.TryGetValue(app.Id,out var observation);coverage.TryGetValue(app.Id,out var observed);
            if(published.Length==0 && grants.Length==0 && observation==null)continue;
            var publishedMissing=Missing(scopes,published);var grantedMissing=Missing(scopes,grants);
            string grantStatus=grants.Length!=0 && grantedMissing.Length==0?"Covered":inventory.Enumeration!="Complete"?"Unknown":grants.Length!=0?"Partial":"NotPresent";
            var observedScopes=observed==null?System.Array.Empty<string>():Canonical(scopes.Except(observed.MissingScopes,StringComparer.Ordinal).Concat(observed.AdditionalScopes));
            string status=observed!=null?(observed.CoversAll?"FreshCoverage":"FreshPartialCoverage"):observation==null?"NotObserved":observation.Date>instant.AddMinutes(5)?"FutureDated":observation.Outcome!="Succeeded"?"LatestAttemptUnsuccessful":observation.Date<instant.AddHours(-maxAgeHours)?"Stale":"Unverified";
            bool eligible=fresh && resourceEligible && Eligible(app);
            int rank=eligible && observed?.CoversAll==true?0:eligible && grants.Length!=0 && grantedMissing.Length==0?1:eligible && published.Length!=0 && publishedMissing.Length==0?2:3;
            rows.Add(new CandidateRow(app.Id,app.Name,resource,app.Registration,app.Ownership,app.Enabled,fresh,inventory.Captured.ToUniversalTime().ToString("o"),resourceEligible,inventory.Enumeration,
                published,publishedMissing,grants,grantStatus,grantStatus=="Unknown"?null:grantedMissing,observedScopes,Missing(scopes,observedScopes),observed?.AdditionalScopeCount,Eligible(app),
                status,observation?.Outcome ?? "NotObserved",observation?.Date.ToUniversalTime().ToString("o"),observation?.Protocol ?? "Unknown",observation?.Requested ?? System.Array.Empty<string>(),app.Redirects.Any(BrowserCallback),rank));
        }
        return rows.OrderBy(r=>r.CandidateRank).ThenBy(r=>r.ObservedAdditionalScopeCount ?? int.MaxValue).ThenBy(r=>r.ClientId,StringComparer.Ordinal).ToArray();
    }
    public sealed record RequestRow(string ClientId,string ResourceId,string ResourceUri,string[] Scopes,string[] OAuthScopes,
        string RedirectUri,string Tenant,bool Spa,string Protocol,string Evidence,string Source,string? ObservedAt,string? ContentSha256=null)
    {
        public TokenForge.Core.V0180.OAuthRequest ToTransport()=>new(){ClientId=ClientId,ResourceId=ResourceId,ResourceUri=ResourceUri,
            Scopes=Scopes.ToArray(),OAuthScopes=OAuthScopes.ToArray(),RedirectUri=RedirectUri,Tenant=Tenant,Spa=Spa,Protocol=Protocol};
    }

    // Warm observed coverage and cold hints have deliberately different redirect eligibility/order.
    // This constructs explicit metadata requests only; execution must verify current issued context.
    public static string BuildRequests(string inventoryJson,string databaseJson,string resource,string[] scopes,string principal,
        string tenant,bool warm,bool browser=false,bool offlineAccess=false,int maxCandidates=8,int maxRedirects=2,
        int maxAgeHours=24,DateTimeOffset? now=null)=>JsonSerializer.Serialize(PlanRequests(inventoryJson,databaseJson,resource,scopes,principal,
            tenant,warm,browser,offlineAccess,maxCandidates,maxRedirects,maxAgeHours,now));

    public static RequestRow BootstrapRequest(string inventoryJson,string tenant,string client,int maxAgeHours=24,DateTimeOffset? now=null)
    {
        try
        {
            const string graph="00000003-0000-0000-c000-000000000000";
            var inventory=ParseInventory(inventoryJson);var instant=now ?? DateTimeOffset.UtcNow;
            if(!Guid.TryParse(client,out var clientId) || clientId==Guid.Empty || maxAgeHours is <1 or >8760 || !Fresh(inventory.Captured,instant,maxAgeHours))throw new InvalidOperationException();
            var application=inventory.Apps.Single(a=>a.Id==clientId.ToString() && Eligible(a));
            inventory.Apps.Single(a=>a.Id==graph && Eligible(a));
            using var parsed=Parse(inventoryJson);
            var resource=Array(parsed.RootElement,"Applications",100000).Single(a=>Id(a,"AppId")==graph);
            if(!Array(resource,"DelegatedScopeDefinitions",4096).Any(d=>Text(d,"Value")=="User.Read" && Boolean(d,"Enabled")==true))throw new InvalidOperationException();
            // Warm bootstrap keeps its published HTTPS nativeclient suffix rule; cold planning is stricter.
            var redirect=application.Redirects.FirstOrDefault(text=>SupportedRedirect(text,true,false) && new Uri(text).Scheme=="https" && new Uri(text).AbsolutePath.EndsWith("/nativeclient",StringComparison.OrdinalIgnoreCase)) ?? throw new InvalidOperationException();
            var request=new RequestRow(clientId.ToString(),graph,graph,new[]{"User.Read"},new[]{graph+"/User.Read"},redirect,tenant,false,"OAuth2V2Pkce",
                "TenantResourceScopeDefinitionNotClientConsent","VerifiedTenantScopeDefinitions",null);
            TokenForge.Core.V0180.OAuthTransport.ValidateRequest(request.ToTransport());return request;
        }
        catch{throw new InvalidOperationException("Observer bootstrap planning failed. Details suppressed.");}
    }
    public static RequestRow[] PlanRequests(string inventoryJson,string databaseJson,string resource,string[] scopes,string principal,
        string tenant,bool warm,bool browser=false,bool offlineAccess=false,int maxCandidates=8,int maxRedirects=2,
        int maxAgeHours=24,DateTimeOffset? now=null)
    {
        try
        {
            var inventory=ParseInventory(inventoryJson);
            ValidateRequest(ref resource,ref scopes,inventory.Tenant,principal,maxAgeHours);
            if(tenant==null || !Regex.IsMatch(tenant,@"\A(organizations|common|consumers|[A-Za-z0-9][A-Za-z0-9.-]{0,252})\z") ||
                maxCandidates is <1 or >100 || maxRedirects is <1 or >8)throw new InvalidOperationException();
            var instant=now ?? DateTimeOffset.UtcNow;
            if(!Fresh(inventory.Captured,instant,maxAgeHours) || !inventory.Apps.Any(a=>a.Id==resource && Eligible(a)))throw new InvalidOperationException();
            var latest=Latest(ParseObservations(databaseJson),resource,inventory.Tenant,principal);
            var apps=inventory.Apps.ToDictionary(a=>a.Id,StringComparer.Ordinal);
            var order=warm?CoverageRows(latest,resource,scopes,maxAgeHours,instant).Where(r=>r.CoversAll).Select(r=>r.ClientId):
                CandidateRows(inventory,latest,resource,scopes,principal,maxAgeHours,instant).Where(r=>r.CandidateRank<=2).Select(r=>r.ClientId);
            var result=new List<RequestRow>();int selected=0;
            foreach(var client in order)
            {
                if(!apps.TryGetValue(client,out var app) || !Eligible(app))continue;
                latest.TryGetValue(client,out var observation);
                IEnumerable<string> redirects=app.Redirects.Where(text=>SupportedRedirect(text,warm,browser));
                if(warm)redirects=redirects.OrderBy(text=>observation?.Redirect==Fingerprint(text)?0:1).ThenBy(text=>text,StringComparer.Ordinal);
                var callbacks=redirects.Take(maxRedirects).ToArray();
                if(callbacks.Length==0)continue;
                if(selected++>=maxCandidates)break;
                foreach(var redirect in callbacks)
                {
                    var oauth=scopes.Select(scope=>resource+"/"+scope).Concat(offlineAccess?new[]{"offline_access"}:System.Array.Empty<string>()).ToArray();
                    TokenForge.Core.V0180.OAuthTransport.ValidateRequest(new TokenForge.Core.V0180.OAuthRequest
                    {
                        ClientId=client,ResourceId=resource,ResourceUri=resource,Scopes=scopes.ToArray(),OAuthScopes=oauth,
                        RedirectUri=redirect,Tenant=tenant,Spa=warm && !browser && observation?.Spa==true && new Uri(redirect).Scheme=="https"
                    });
                    result.Add(new RequestRow(client,resource,resource,scopes.ToArray(),oauth,redirect,tenant,
                        warm && !browser && observation?.Spa==true && new Uri(redirect).Scheme=="https","OAuth2V2Pkce",
                        warm?"MatchedObservedScpNotGuaranteedExplicitAuthorization":"PublishedMetadata",
                        warm?"VerifiedPrivateScopeObservation":"PublishedOrConfiguredHintNotProvenConsent",
                        warm?observation?.Date.ToUniversalTime().ToString("o"):null));
                }
            }
            return result.ToArray();
        }
        catch{throw new InvalidOperationException("Explicit request planning failed. Details suppressed.");}
    }
    private static bool SupportedRedirect(string text,bool warm,bool browser)
    {
        if(text.Length>2048 || !Uri.TryCreate(text,UriKind.Absolute,out var uri) || uri.UserInfo.Length!=0 || uri.Query.Length!=0 || uri.Fragment.Length!=0)return false;
        if(browser)return BrowserCallback(text);
        return warm?(uri.Scheme=="https" || uri.Scheme=="http" && uri.Host=="localhost" || uri.Scheme=="urn"):
            text=="https://login.microsoftonline.com/common/oauth2/nativeclient";
    }
    private static string Fingerprint(string text)=>Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(text))).ToLowerInvariant();
    private static CoverageRow[] CoverageRows(Dictionary<string,Observation> latest,string resource,string[] scopes,int hours,DateTimeOffset now)
    {
        return latest.Values.Where(o=>o.Client!=Guid.Empty.ToString() && o.Namespace=="Matched" && o.Request=="Matched" && o.Outcome=="Succeeded" && Fresh(o.Date,now,hours)).Select(o=>
        {
            var api=o.Scopes.Except(new[]{"openid","profile","email","offline_access"},StringComparer.Ordinal).ToArray();
            var missing=Missing(scopes,api);var additional=Missing(api,scopes);
            return new CoverageRow(o.Client,resource,missing.Length==0,missing,additional,additional.Length,api.Length,o.Redirect,o.Date.ToUniversalTime().ToString("o"),o.Protocol,o.Spa);
        }).OrderBy(r=>r.MissingScopes.Length).ThenBy(r=>r.AdditionalScopeCount).ThenBy(r=>r.ObservedApiScopeCount).ThenBy(r=>r.ClientId,StringComparer.Ordinal).ToArray();
    }
    private static Dictionary<string,Observation> Latest(Observation[] rows,string resource,string tenant,string principal)
    {
        var latest=new Dictionary<string,Observation>(StringComparer.Ordinal);
        foreach(var row in rows.Where(r=>r.Resource==resource && r.Tenant==tenant && r.Principal==principal))
            if(!latest.TryGetValue(row.Client,out var previous) || row.Date>=previous.Date)latest[row.Client]=row;
        // Equal timestamp: last input wins, before success/verification filtering.
        return latest;
    }
    private static Observation[] ParseObservations(string json)
    {
        using var document=Parse(json);var root=document.RootElement;
        if(root.GetProperty("SchemaVersion").GetInt32()!=1 || !root.TryGetProperty("Observations",out var rows) || rows.ValueKind!=JsonValueKind.Array)throw new InvalidOperationException();
        return Array(root,"Observations",100000).Select(o=>new Observation(Id(o,"ClientId"),Id(o,"ResourceId"),Fingerprint(o,"TenantFingerprint"),Fingerprint(o,"PrincipalFingerprint"),
            TimestampPolicy.Parse(Text(o,"ObservedAt")),Text(o,"Outcome")!,Text(o,"NamespaceVerification"),Text(o,"RequestVerification"),Strings(o,"ScpScopes"),
            Fingerprint(o,"RedirectFingerprint"),Text(o,"Protocol") ?? "Unknown",Boolean(o,"Spa"),Strings(o,"RequestedScopes"))).ToArray();
    }
    private static Inventory ParseInventory(string json)
    {
        using var document=Parse(json);var root=document.RootElement;
        if(!root.TryGetProperty("Applications",out var members) || members.ValueKind!=JsonValueKind.Array ||
            root.TryGetProperty("SchemaVersion",out var schema) && schema.GetInt32()!=1)throw new InvalidOperationException();
        var apps=Array(root,"Applications",100000).Select(a=>
        {
            var grants=Array(a,"PublishedGrants",100000).GroupBy(g=>Id(g,"ResourceId"),StringComparer.Ordinal)
                .ToDictionary(g=>g.Key,g=>Canonical(g.SelectMany(x=>Strings(x,"Scopes"))),StringComparer.Ordinal);
            return new Application(Id(a,"AppId",allowEmpty:true),Text(a,"Name"),Text(a,"Registration"),Text(a,"Ownership"),Boolean(a,"AccountEnabled"),Strings(a,"RedirectUris",true,preserveOrder:true),grants);
        }).ToArray();
        if(apps.Select(a=>a.Id).Distinct(StringComparer.Ordinal).Count()!=apps.Length)throw new InvalidOperationException();
        var tenant=Fingerprint(root,"TenantFingerprint") ?? throw new InvalidOperationException();
        var grants=Array(root,"TenantGrants",100000).Select(g=>new Grant(Id(g,"ClientId"),Id(g,"ResourceId"),Fingerprint(g,"PrincipalFingerprint"),Text(g,"ConsentType"),Strings(g,"Scopes"))).ToArray();
        return new Inventory(TimestampPolicy.Parse(Text(root,"CapturedAt")),tenant,Text(root,"GrantEnumeration") ?? "Unknown",apps,grants);
    }
    private static JsonDocument Parse(string json)
    {
        if(json.Length>64*1024*1024 || Encoding.UTF8.GetByteCount(json)>64*1024*1024)throw new InvalidOperationException();
        var document=JsonDocument.Parse(json,new JsonDocumentOptions{MaxDepth=16});
        try{Duplicates(document.RootElement);if(document.RootElement.ValueKind!=JsonValueKind.Object)throw new InvalidOperationException();return document;}catch{document.Dispose();throw;}
    }
    private static void Duplicates(JsonElement element)
    {
        if(element.ValueKind==JsonValueKind.Object)
        {
            var names=new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach(var property in element.EnumerateObject()){if(!names.Add(property.Name))throw new InvalidOperationException();Duplicates(property.Value);}
        }
        else if(element.ValueKind==JsonValueKind.Array)foreach(var item in element.EnumerateArray())Duplicates(item);
    }
    private static JsonElement[] Array(JsonElement value,string field,int maximum)
    {
        if(!value.TryGetProperty(field,out var array) || array.ValueKind==JsonValueKind.Null)return System.Array.Empty<JsonElement>();
        if(array.ValueKind!=JsonValueKind.Array || array.GetArrayLength()>maximum)throw new InvalidOperationException();
        return array.EnumerateArray().ToArray();
    }
    private static string? Text(JsonElement value,string field)
    {
        if(!value.TryGetProperty(field,out var element) || element.ValueKind==JsonValueKind.Null)return null;
        var text=element.GetString();if(text==null || text.Length>4096)throw new InvalidOperationException();return text;
    }
    private static bool? Boolean(JsonElement value,string field)=>!value.TryGetProperty(field,out var e) || e.ValueKind==JsonValueKind.Null?null:e.GetBoolean();
    // Structural catalog/history placeholders are valid metadata, never eligible acquisition IDs.
    private static string Id(JsonElement value,string field,bool allowEmpty=true)=>Guid.TryParse(Text(value,field),out var id) && (allowEmpty || id!=Guid.Empty)?id.ToString():throw new InvalidOperationException();
    private static string? Fingerprint(JsonElement value,string field)
    {
        var text=Text(value,field);if(text!=null && !Regex.IsMatch(text,@"\A[a-f0-9]{64}\z"))throw new InvalidOperationException();return text;
    }
    private static string[] Strings(JsonElement value,string field,bool redirects=false,bool preserveOrder=false)
    {
        var values=Array(value,field,4096).Select(e=>
        {
            string text=e.GetString() ?? throw new InvalidOperationException();
            if(redirects?text.Length>4096:!Regex.IsMatch(text,@"\A[A-Za-z0-9_.:/-]{1,256}\z"))throw new InvalidOperationException();return text;
        });
        return preserveOrder?values.Distinct(StringComparer.Ordinal).ToArray():Canonical(values);
    }
    private static void ValidateRequest(ref string resource,ref string[] scopes,string tenant,string principal,int hours)
    {
        if(!Guid.TryParse(resource,out var id) || id==Guid.Empty || hours<1 || hours>8760 || !Regex.IsMatch(tenant,@"\A[a-f0-9]{64}\z") || !Regex.IsMatch(principal,@"\A[a-f0-9]{64}\z") || scopes==null || scopes.Length is <1 or >64 ||
            scopes.Any(s=>s==null || s.Length>256 || !Regex.IsMatch(s,@"\A[A-Za-z0-9_-][A-Za-z0-9_.-]*\z") || new[]{"openid","profile","email","offline_access"}.Contains(s,StringComparer.Ordinal)))throw new InvalidOperationException();
        resource=id.ToString();scopes=Canonical(scopes);
    }
    private static string[] Canonical(IEnumerable<string> values)=>values.Distinct(StringComparer.Ordinal).OrderBy(x=>x,StringComparer.Ordinal).ToArray();
    private static string[] Missing(IEnumerable<string> requested,IEnumerable<string> actual)=>requested.Except(actual,StringComparer.Ordinal).ToArray();
    private static bool Fresh(DateTimeOffset timestamp,DateTimeOffset now,int hours)=>timestamp>=now.AddHours(-hours) && timestamp<=now.AddMinutes(5);
    private static bool Eligible(Application a)=>a.Id!=Guid.Empty.ToString() && a.Registration=="Present" && a.Ownership=="VerifiedMicrosoftOwner" && a.Enabled==true;
    private static bool BrowserCallback(string text)=>Uri.TryCreate(text,UriKind.Absolute,out var uri) && uri.Scheme=="http" && uri.Host=="localhost" && uri.AbsolutePath=="/" && uri.UserInfo.Length==0 && uri.Query.Length==0 && uri.Fragment.Length==0;
}
