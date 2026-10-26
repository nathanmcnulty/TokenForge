#nullable enable
using System;
using System.Linq;
using System.Text.Json.Nodes;
namespace TokenForge.Core;

public static partial class AdminWorkflows
{
    public static string AcquisitionEvidence(string json)=>Guard(()=>{
        var acquisition=Parse(json,1024*1024);OptionalKeys(acquisition,"Format SchemaVersion ToolId Status ExitCode Reason IssuanceSucceeded CurrentContextConfirmed BootstrapAttempts FinalAttempts ApiProofPerformed ApiCheck SignatureValidated ScopeCountIsNotPrivilegeRanking CredentialDisplay ProfileSha256 ToolSha256 Context BootstrapScopes BootstrapAdditionalScopes BootstrapResponseAdditionalScopeCount FinalScopes FinalAdditionalScopes FinalResponseAdditionalScopeCount ApiComparisonContext ObservedAt","Format SchemaVersion ToolId Status ExitCode Reason IssuanceSucceeded CurrentContextConfirmed BootstrapAttempts FinalAttempts ApiProofPerformed ApiCheck SignatureValidated ScopeCountIsNotPrivilegeRanking CredentialDisplay ProfileSha256 ToolSha256 ObservedAt");Version(acquisition,"TokenForgeStrictAcquisition");Date(acquisition["ObservedAt"]);Fingerprint(acquisition["ProfileSha256"]);Fingerprint(acquisition["ToolSha256"]);if(Bool(acquisition["SignatureValidated"]) || Bool(acquisition["CredentialDisplay"]) || !Bool(acquisition["ScopeCountIsNotPrivilegeRanking"]))throw Invalid();Range(acquisition["BootstrapAttempts"],0,1);Range(acquisition["FinalAttempts"],0,1);bool success=Bool(acquisition["IssuanceSucceeded"]);Bool(acquisition["CurrentContextConfirmed"]);Bool(acquisition["ApiProofPerformed"]);
        Choice(acquisition["Status"],"Blocked NeedsObservation IssuedNeedsApiObservation IssuedWithinStrictPolicy");Range(acquisition["ExitCode"],0,4);Match(Text(acquisition["ToolId"]),@"\A[a-z][a-z0-9-]{0,63}\z",64);Match(Text(acquisition["Reason"]),@"\A[A-Za-z][A-Za-z0-9]{0,127}\z",128);
        ValidateAcquisitionState(acquisition);
        var result=Header("TokenForgeChangeSnapshot");var collections=new JsonArray();result["Collections"]=collections;if(acquisition["Context"]==null){if(Int(acquisition["FinalAttempts"])!=0 || success)throw Invalid();return ChangeReports.ValidateSnapshot(result.ToJsonString());}
        var context=Obj(JsonNode.Parse(ChangeReports.ValidateComparisonContext(acquisition["Context"]!.ToJsonString())));var source=new JsonObject{["Id"]="strict-admin-acquisition",["Location"]="urn:sha256:"+Hash(acquisition),["ContentSha256"]=Hash(acquisition),["HashKind"]="NormalizedDocument",["SourceObservedAt"]=null,["CollectedAt"]=acquisition["ObservedAt"]!.DeepClone()};
        JsonObject Collection(string kind,JsonObject ctx,string status,JsonArray records)=>new JsonObject{["EvidenceType"]=kind,["Privacy"]="Private",["Status"]=status,["Context"]=ctx.DeepClone(),["Source"]=source.DeepClone(),["Records"]=records};
        JsonObject Record(string domain,string outcome,JsonObject value)=>new JsonObject{["RecordId"]=ApplicationCatalogPolicy.Hash(Hash(acquisition)+"/"+domain),["ObservedAt"]=acquisition["ObservedAt"]!.DeepClone(),["Outcome"]=outcome,["Identity"]=new JsonObject{["ClientId"]=context["ClientId"]!.DeepClone(),["ResourceId"]=context["ResourceId"]!.DeepClone()},["Value"]=value};
        var issued=new JsonArray();if(Int(acquisition["FinalAttempts"])!=0){if(success && (!Bool(acquisition["CurrentContextConfirmed"]) || acquisition["FinalScopes"] is not JsonArray))throw Invalid();var scopes=acquisition["FinalScopes"]?.DeepClone() ?? new JsonArray();issued.Add(Record("issued",success?"Succeeded":"Failed",new JsonObject{["Scopes"]=scopes,["NamespaceVerification"]=success?"Matched":"Unverifiable",["RequestVerification"]=success?"Matched":"Unverifiable",["ClaimsReadable"]=success,["HasScpClaim"]=success,["SignatureValidated"]=false}));}
        collections.Add(Collection("IssuedScopes",context,Int(acquisition["FinalAttempts"])==0?"NotCollected":"Complete",issued));
        if(Bool(acquisition["ApiProofPerformed"])){if(!success || acquisition["ApiComparisonContext"] is not JsonObject apiContext || acquisition["ApiCheck"] is not JsonObject api)throw Invalid();Keys(api,"Operation Method ApiVersion Status Accepted Evidence");Choice(api["Operation"],"GraphMeV1");Choice(api["Method"],"GET");Choice(api["ApiVersion"],"v1.0");Choice(api["Evidence"],"SelectedReadOnlyOperationOnly");if(!ExactContext(apiContext,context))throw Invalid();var values=new JsonObject{["Status"]=api["Status"]?.DeepClone(),["Accepted"]=api["Status"]==null?null:api["Accepted"]?.DeepClone()};collections.Add(Collection("ApiAcceptance",apiContext,"Complete",new JsonArray(Record("api",api["Status"]==null?"Unknown":"Responded",values))));}
        return ChangeReports.ValidateSnapshot(result.ToJsonString());
    });
    // Validate the complete receipt before projecting any evidence, including fields not used below.
    private static void ValidateAcquisitionState(JsonObject a)
    {
        int bootstrap=Int(a["BootstrapAttempts"]),final=Int(a["FinalAttempts"]);
        bool confirmed=Bool(a["CurrentContextConfirmed"]),success=Bool(a["IssuanceSucceeded"]),proof=Bool(a["ApiProofPerformed"]);
        string status=Text(a["Status"]);int exit=Int(a["ExitCode"]);
        if(exit!=(status=="IssuedWithinStrictPolicy"?0:status is "NeedsObservation" or "IssuedNeedsApiObservation"?3:4))throw Invalid();
        if(confirmed && bootstrap!=1 || final==1 && !confirmed || success && final!=1 || proof && !success)throw Invalid();
        if(status is "IssuedWithinStrictPolicy" or "IssuedNeedsApiObservation" && !success)throw Invalid();
        foreach(string phase in new[]{"Bootstrap","Final"})
        {
            string scopesKey=phase+"Scopes",additionalKey=phase+"AdditionalScopes",countKey=phase+"ResponseAdditionalScopeCount";
            bool has=a.ContainsKey(scopesKey);
            if(has!=a.ContainsKey(additionalKey) || has!=a.ContainsKey(countKey))throw Invalid();
            if(!has)continue;
            if((phase=="Bootstrap"?bootstrap:final)!=1)throw Invalid();
            foreach(string key in new[]{scopesKey,additionalKey})
            {
                var values=Arr(a[key]);if(values.Count>1024 || values.Select(Text).Distinct(StringComparer.Ordinal).Count()!=values.Count)throw Invalid();
                foreach(var value in values)Match(Text(value),@"\A[A-Za-z0-9_.-]{1,256}\z",256);
            }
            Range(a[countKey],0,int.MaxValue);
        }
        if(confirmed && !a.ContainsKey("BootstrapScopes") || success && !a.ContainsKey("FinalScopes"))throw Invalid();
        if(a["Context"] is not JsonObject ctx)
        {
            if(bootstrap!=0 || final!=0 || confirmed || success || proof || a.ContainsKey("BootstrapScopes") || a.ContainsKey("FinalScopes"))throw Invalid();
        }
        else
        {
            ctx=Parse(ChangeReports.ValidateComparisonContext(ctx.ToJsonString()));
            if(Text(ctx["ExecutionPolicyFingerprint"])!=Text(a["ProfileSha256"]) || Text(ctx["QueryFingerprint"])!=ApplicationCatalogPolicy.Hash("strict-admin-issued/v1") || Text(ctx["Protocol"])!="OAuth2V2Pkce")throw Invalid();
            string resource=Text(ctx["ResourceId"]);var requested=Values(ctx["RequestedScopes"]).Select(scope=>scope.StartsWith(resource+"/",StringComparison.Ordinal)?scope.Substring(resource.Length+1):throw Invalid()).ToArray();
            if(requested.Length is <1 or >64 || requested.Any(scope=>scope is ".default" or "openid" or "profile" or "email" or "offline_access"))throw Invalid();
            foreach(string phase in new[]{"Bootstrap","Final"})if(a.ContainsKey(phase+"Scopes"))
            {
                var expected=phase=="Bootstrap"?new[]{"User.Read"}:requested;
                var actual=Values(a[phase+"Scopes"]);var extras=actual.Except(expected,StringComparer.Ordinal).Except(new[]{"openid","profile","email","offline_access"},StringComparer.Ordinal).OrderBy(v=>v,StringComparer.Ordinal);
                if(!extras.SequenceEqual(Values(a[phase+"AdditionalScopes"]).OrderBy(v=>v,StringComparer.Ordinal)))throw Invalid();
                if((phase=="Bootstrap"?confirmed:success) && !expected.All(scope=>actual.Contains(scope,StringComparer.Ordinal)))throw Invalid();
            }
        }
        if(!proof)
        {
            if(a["ApiCheck"]!=null || a["ApiComparisonContext"]!=null)throw Invalid();
            return;
        }
        var api=Obj(a["ApiCheck"]);Keys(api,"Operation Method ApiVersion Status Accepted Evidence");Choice(api["Operation"],"GraphMeV1");Choice(api["Method"],"GET");Choice(api["ApiVersion"],"v1.0");Choice(api["Evidence"],"SelectedReadOnlyOperationOnly");
        bool accepted=Bool(api["Accepted"]);if(api["Status"]==null){if(accepted)throw Invalid();}else{Range(api["Status"],100,599);if(accepted!=(Int(api["Status"]) is >=200 and <=299))throw Invalid();}
        var apiContext=Parse(ChangeReports.ValidateComparisonContext(Obj(a["ApiComparisonContext"]).ToJsonString()));
        string approval=Hash(new JsonObject{["Version"]=1,["ProfileSha256"]=a["ProfileSha256"]!.DeepClone(),["ToolSha256"]=a["ToolSha256"]!.DeepClone(),["Operation"]="GraphMeV1",["Authorization"]="ExplicitSelectedReadOnlyProof/v1"});
        if(!ExactContext(apiContext,Obj(a["Context"])) || Text(apiContext["ResourceId"])!=Graph || Text(apiContext["OperationFingerprint"])!=ApplicationCatalogPolicy.Hash("GraphMeV1") || Text(apiContext["Method"])!="GET" || Text(apiContext["ApiVersion"])!="v1.0" || Text(apiContext["ApprovalFingerprint"])!=approval)throw Invalid();
    }

}
