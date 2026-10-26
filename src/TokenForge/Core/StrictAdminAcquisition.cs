#nullable enable
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.Json.Serialization;
using System.Threading;
using TokenForge.Core.V0100;
using TokenForge.Core.V0180;
namespace TokenForge.Core;

// Owns a successful credential for in-process tool integrations; JSON is always metadata-only.
public sealed class StrictAdminAcquisitionResult:IDisposable
{
    [JsonIgnore] public ProfileCredentialToken? Credential {get;internal set;}
    private readonly string json;
    internal StrictAdminAcquisitionResult(JsonObject metadata,ProfileCredentialToken? token=null){metadata["ObservedAt"]=DateTimeOffset.UtcNow.ToString("o");json=metadata.ToJsonString();Credential=token;}
    public string ToJson()=>json;
    public void Dispose(){Credential?.Dispose();Credential=null;}
}

public static partial class AdminWorkflows
{
    public static StrictAdminAcquisitionResult Acquire(string profileJson,string requirementsJson,string inventoryJson,string toolId,SecureString? cookie,
        string cookieName="ESTSAUTH",string? selectedClient=null,string? selectedCallback=null,bool performOperationCheck=false,string? prerequisiteJson=null,
        Func<ScopePlanning.RequestRow,ProfileCredentialToken>? execute=null,Func<SecureString,string>? readIdentity=null,
        Func<SecureString,ProfileApiCheck>? checkOperation=null,CancellationToken cancellation=default)
    {
        var profile=Guard(()=>Profile(Parse(profileJson,32768)));var requirements=Guard(()=>Requirements(Parse(requirementsJson,1024*1024)));var tool=Guard(()=>Tool(requirements,toolId));var inventory=Guard(()=>Parse(inventoryJson));Guard(()=>ChangeReports.Normalize("Inventory",inventoryJson));
        var pre=prerequisiteJson==null?EmptyPrerequisites():Guard(()=>Prerequisites(prerequisiteJson));
        var plan=Guard(()=>PlanTool(profile,tool,inventory,selectedClient,selectedCallback));var metadata=Header("TokenForgeStrictAcquisition");metadata["ToolId"]=toolId;metadata["Status"]="Blocked";metadata["ExitCode"]=4;metadata["Reason"]="NoSilentRoute";metadata["IssuanceSucceeded"]=false;metadata["CurrentContextConfirmed"]=false;metadata["BootstrapAttempts"]=0;metadata["FinalAttempts"]=0;metadata["ApiProofPerformed"]=false;metadata["ApiCheck"]=null;metadata["SignatureValidated"]=false;metadata["ScopeCountIsNotPrivilegeRanking"]=true;metadata["CredentialDisplay"]=false;metadata["ProfileSha256"]=Hash(profile);metadata["ToolSha256"]=Hash(tool);
        if(Text(plan["Status"])!="ReadyForExplicitSilentAttempt"){metadata["Status"]=plan["Status"]!.DeepClone();metadata["ExitCode"]=plan["ExitCode"]!.DeepClone();metadata["Reason"]=plan["Reason"]!.DeepClone();return new StrictAdminAcquisitionResult(metadata);}
        metadata["Context"]=plan["Context"]!.DeepClone();
        if(cookieName is not ("ESTSAUTH" or "ESTSAUTHPERSISTENT") || execute!=null && (readIdentity==null || performOperationCheck && checkOperation==null))throw Invalid();
        if(performOperationCheck && Arr(tool["Operations"]).Count!=1)throw Invalid();
        // Reuse the same conservative prerequisite interpretation as the saved-evidence workflow.
        var empty=Header("TokenForgeChangeSnapshot");empty["Collections"]=new JsonArray();var comparison=Obj(JsonNode.Parse(ChangeReports.Compare(empty.ToJsonString(),empty.ToJsonString())));
        var explanation=ExplainTool(profile,tool,inventory,empty,comparison,pre,DateTimeOffset.UtcNow);var prerequisiteStates=Arr(explanation["Prerequisites"]).Select(Obj).ToArray();
        if(prerequisiteStates.Any(p=>Text(p["Status"])!="Satisfied")){metadata["Reason"]="PrerequisiteNotSatisfied";metadata["Status"]=prerequisiteStates.Any(p=>Text(p["Status"])=="Unsatisfied")?"Blocked":"NeedsObservation";metadata["ExitCode"]=Text(metadata["Status"])=="Blocked"?4:3;return new StrictAdminAcquisitionResult(metadata);}
        if(cookie==null || cookie.Length==0){metadata["Reason"]="ExistingSilentSessionRequired";return new StrictAdminAcquisitionResult(metadata);}
        using var deadline=CancellationTokenSource.CreateLinkedTokenSource(cancellation);deadline.CancelAfter(TimeSpan.FromSeconds(Int(profile["MaxSeconds"])));using var owned=cookie.Copy();owned.MakeReadOnly();
        ProfileCredentialToken? final=null;string phase="Bootstrap";
        try{
            deadline.Token.ThrowIfCancellationRequested();
            var bootstrap=ScopePlanning.BootstrapRequest(inventoryJson,Text(profile["Tenant"]),Text(profile["BootstrapClientId"]),Int(profile["MaxAgeHours"]));
            ProfileCredentialToken Execute(ScopePlanning.RequestRow request){deadline.Token.ThrowIfCancellationRequested();if(!Values(profile["ApprovedClientIds"]).Contains(request.ClientId,StringComparer.Ordinal))throw Invalid();if(execute!=null)return execute(request with{Scopes=request.Scopes.ToArray(),OAuthScopes=request.OAuthScopes.ToArray()}) ?? throw Invalid();using var token=OAuthTransport.Cookie(request.ToTransport(),owned,cookieName,deadline.Token);return new ProfileCredentialToken(request.ToTransport(),token.AccessToken,token.RefreshToken,token.ExpiresAt,token.AdditionalScopes.Length);}
            using(var issued=ExecuteBootstrap()){
                ValidateIssued(issued,bootstrap,profile,int.MaxValue);Describe(issued,bootstrap,"Bootstrap");ValidateIssued(issued,bootstrap,profile,Int(profile["MaxBootstrapAdditionalScopes"]));deadline.Token.ThrowIfCancellationRequested();
                string identity=readIdentity==null?ProfileTokenApi.ReadIdentity(issued.AccessToken,deadline.Token):readIdentity(issued.AccessToken);
                if(!Guid.TryParse(identity,out var id) || id==Guid.Empty || !issued.TokenClaims.MatchesPrincipalIdentity(id))throw Invalid();ValidateIssued(issued,bootstrap,profile,Int(profile["MaxBootstrapAdditionalScopes"]));deadline.Token.ThrowIfCancellationRequested();metadata["CurrentContextConfirmed"]=true;
            }
            phase="Final";if(!Fresh(inventory["CapturedAt"],DateTimeOffset.UtcNow,Int(profile["MaxAgeHours"])))throw Invalid();
            var request=new ScopePlanning.RequestRow(Text(plan["ClientId"]),Text(tool["ResourceId"]),Text(tool["ResourceId"]),Values(tool["Scopes"]),Values(Obj(plan["Context"])["RequestedScopes"]),Text(plan["CallbackUri"]),Text(profile["Tenant"]),Text(tool["CallbackClass"])=="Spa","OAuth2V2Pkce","StrictApprovedExplicitRequest","VerifiedTenantInventory",null);
            metadata["FinalAttempts"]=1;final=Execute(request);ValidateIssued(final,request,profile,int.MaxValue);Describe(final,request,"Final");ValidateIssued(final,request,profile,Int(profile["MaxAdditionalScopes"]));deadline.Token.ThrowIfCancellationRequested();metadata["IssuanceSucceeded"]=true;
            if(performOperationCheck){
                phase="Api";metadata["ApiProofPerformed"]=true;
                var proofContext=Obj(plan["Context"]).DeepClone().AsObject();proofContext["OperationFingerprint"]=ApplicationCatalogPolicy.Hash("GraphMeV1");proofContext["Method"]="GET";proofContext["ApiVersion"]="v1.0";proofContext["ApprovalFingerprint"]=Approval(profile,tool,"GraphMeV1");metadata["ApiComparisonContext"]=proofContext;
                metadata["ApiCheck"]=new JsonObject{["Operation"]="GraphMeV1",["Method"]="GET",["ApiVersion"]="v1.0",["Status"]=null,["Accepted"]=false,["Evidence"]="SelectedReadOnlyOperationOnly"};
                var proof=checkOperation==null?ProfileTokenApi.Check(final.AccessToken,Graph,new Uri("https://graph.microsoft.com/v1.0/me?$select=id"),deadline.Token):checkOperation(final.AccessToken);deadline.Token.ThrowIfCancellationRequested();
                if(proof==null || proof.Status is <100 or >599 || proof.Accepted!=(proof.Status is >=200 and <=299))throw Invalid();
                metadata["ApiCheck"]=new JsonObject{["Operation"]="GraphMeV1",["Method"]="GET",["ApiVersion"]="v1.0",["Status"]=proof.Status,["Accepted"]=proof.Accepted,["Evidence"]="SelectedReadOnlyOperationOnly"};
                if(!proof.Accepted){metadata["Reason"]="SelectedApiDeniedOrUnavailable";final.Dispose();final=null;return new StrictAdminAcquisitionResult(metadata);}
                ValidateIssued(final,request,profile,Int(profile["MaxAdditionalScopes"]));
            }
            deadline.Token.ThrowIfCancellationRequested();
            var finalPrerequisites=Arr(ExplainTool(profile,tool,inventory,empty,comparison,pre,DateTimeOffset.UtcNow)["Prerequisites"]).Select(Obj);
            if(!Fresh(inventory["CapturedAt"],DateTimeOffset.UtcNow,Int(profile["MaxAgeHours"])) || finalPrerequisites.Any(p=>Text(p["Status"])!="Satisfied")){metadata["Status"]="NeedsObservation";metadata["ExitCode"]=3;metadata["Reason"]="EvidenceExpiredDuringAttempt";return new StrictAdminAcquisitionResult(metadata);}
            metadata["Status"]=Arr(tool["Operations"]).Count>0 && !performOperationCheck?"IssuedNeedsApiObservation":"IssuedWithinStrictPolicy";metadata["ExitCode"]=Text(metadata["Status"])=="IssuedNeedsApiObservation"?3:0;metadata["Reason"]="OneApprovedSilentRequestNoFallback";metadata["ObservedAt"]=DateTimeOffset.UtcNow.ToString("o");
            var result=new StrictAdminAcquisitionResult(metadata,final);final=null;return result;
            ProfileCredentialToken ExecuteBootstrap(){metadata["BootstrapAttempts"]=1;return Execute(bootstrap);}
            void Describe(ProfileCredentialToken token,ScopePlanning.RequestRow expected,string name){var scopes=token.TokenClaims.Scopes.Where(s=>System.Text.RegularExpressions.Regex.IsMatch(s,@"\A[A-Za-z0-9_.-]{1,256}\z")).Distinct(StringComparer.Ordinal).OrderBy(s=>s,StringComparer.Ordinal).ToArray();metadata[name+"Scopes"]=JsonSerializer.SerializeToNode(scopes);metadata[name+"AdditionalScopes"]=JsonSerializer.SerializeToNode(scopes.Except(expected.Scopes,StringComparer.Ordinal).Except(new[]{"openid","profile","email","offline_access"},StringComparer.Ordinal).ToArray());metadata[name+"ResponseAdditionalScopeCount"]=token.ResponseAdditionalScopeCount;}
        }catch(OperationCanceledException){metadata["Reason"]="DeadlineOrCancelled";return new StrictAdminAcquisitionResult(metadata);}
        catch{metadata["Reason"]=phase+"SilentAttemptOrPolicyFailed";return new StrictAdminAcquisitionResult(metadata);}
        finally{final?.Dispose();}
    }
    private static void ValidateIssued(ProfileCredentialToken token,ScopePlanning.RequestRow row,JsonObject profile,int limit){
        var expected=row.ToTransport();var actual=token.Request;OAuthTransport.ValidateRequest(actual);
        if(actual.Discovery || actual.Protocol!="OAuth2V2Pkce" || actual.ClientId!=expected.ClientId || actual.ResourceId!=expected.ResourceId || actual.ResourceUri!=expected.ResourceUri || actual.Tenant!=expected.Tenant || actual.RedirectUri!=expected.RedirectUri || actual.Spa!=expected.Spa || !actual.Scopes.SequenceEqual(expected.Scopes) || !actual.OAuthScopes.SequenceEqual(expected.OAuthScopes))throw Invalid();
        var claims=token.TokenClaims;TokenPolicy.Validate(claims.TenantFingerprint!,claims.PrincipalFingerprint!,claims.ClientId!,claims.Audience!,Text(profile["ExpectedTenantFingerprint"]),Text(profile["ExpectedPrincipalFingerprint"]),row.ClientId,row.ResourceId,claims.Scopes,row.Scopes,claims.HasDelegatedScopeClaim,claims.ExpiresAt,token.ExpiresAt,limit,token.ResponseAdditionalScopeCount,false,DateTimeOffset.UtcNow);
    }
}
