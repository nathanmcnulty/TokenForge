using System;
using System.Linq;
using System.Security;
using System.Security.Cryptography;
using TokenForge.Core.V0180;
using System.Text;
using System.Text.Json;
using System.Threading;
using TokenForge.Core.V0100;
using TokenForge.Core.V0200;
using TokenForge.Core.V0240;

namespace TokenForge.Core;

// Borrowed cookie; owned result. Optional callbacks are synchronous in-process adapters.
// The caller persists a cold observation before the lifecycle's separate credential commit.
public static class ProfileScopeAcquisition
{
    public static ProfileCredentialToken Acquire(string name,string profileJson,string inventoryJson,string databaseJson,
        string resource,string[] scopes,SecureString cookie,string cookieName="ESTSAUTH",int maxCandidates=8,int maxRedirects=2,
        Func<ScopePlanning.RequestRow,ProfileCredentialToken>? execute=null,Func<SecureString,string>? readIdentity=null,
        Action<string>? checkpoint=null,CancellationToken cancellation=default)
    {
        try
        {
            cancellation.ThrowIfCancellationRequested();
            ProfilePolicy.Validate(profileJson,name);
            if(inventoryJson==null || inventoryJson.Length>64*1024*1024 || Encoding.UTF8.GetByteCount(inventoryJson)>64*1024*1024)throw new InvalidOperationException();
            using var config=JsonDocument.Parse(profileJson);var p=config.RootElement;
            string tenant=p.GetProperty("ExpectedTenantFingerprint").GetString() ?? throw new InvalidOperationException();
            string principal=p.GetProperty("ExpectedPrincipalFingerprint").GetString() ?? throw new InvalidOperationException();
            string authority=p.GetProperty("Tenant").GetString()!;
            int hours=p.GetProperty("MaxAgeHours").GetInt32(),limit=p.GetProperty("MaxAdditionalScopes").GetInt32();
            if(cookie==null || cookie.Length==0 || cookieName is not ("ESTSAUTH" or "ESTSAUTHPERSISTENT"))throw new InvalidOperationException();
            using var ownedCookie=cookie.Copy();ownedCookie.MakeReadOnly();
            using var inventory=JsonDocument.Parse(inventoryJson,new JsonDocumentOptions{MaxDepth=16});
            if(inventory.RootElement.GetProperty("TenantFingerprint").GetString()!=tenant)throw new InvalidOperationException();
            var captured=TimestampPolicy.Parse(inventory.RootElement.GetProperty("CapturedAt").GetString());
            using var covered=JsonDocument.Parse(ScopePlanning.Coverage(databaseJson,resource,scopes,tenant,principal,hours));
            bool warm=covered.RootElement.EnumerateArray().Any(r=>r.GetProperty("CoversAll").GetBoolean());
            var requests=ScopePlanning.PlanRequests(inventoryJson,databaseJson,resource,scopes,principal,authority,warm,false,true,maxCandidates,maxRedirects,hours);
            if(!warm && checkpoint==null)throw new InvalidOperationException();
            ProfileCredentialToken Execute(ScopePlanning.RequestRow row)
            {
                cancellation.ThrowIfCancellationRequested();
                // Adapters receive independent arrays; they cannot change the approved request.
                if(execute!=null)return execute(row with{Scopes=row.Scopes.ToArray(),OAuthScopes=row.OAuthScopes.ToArray()}) ?? throw new InvalidOperationException();
                using var token=OAuthTransport.Cookie(row.ToTransport(),ownedCookie,cookieName,cancellation);
                return new ProfileCredentialToken(row.ToTransport(),token.AccessToken,token.RefreshToken,token.ExpiresAt,token.AdditionalScopes.Length);
            }
            if(warm)
            {
                var bootstrap=ScopePlanning.BootstrapRequest(inventoryJson,authority,p.GetProperty("BootstrapClientId").GetString()!,hours);
                using var issued=Execute(bootstrap);
                Validate(issued,bootstrap,tenant,principal,p.GetProperty("MaxBootstrapAdditionalScopes").GetInt32());
                string identity=readIdentity==null?ProfileTokenApi.ReadIdentity(issued.AccessToken,cancellation):readIdentity(issued.AccessToken);
                if(identity==null || identity.Length>64 || !Guid.TryParse(identity,out var id) || !issued.TokenClaims.MatchesPrincipalIdentity(id))throw new InvalidOperationException();
                cancellation.ThrowIfCancellationRequested();
                Validate(issued,bootstrap,tenant,principal,p.GetProperty("MaxBootstrapAdditionalScopes").GetInt32());
            } // Bootstrap credentials are disposed before any candidate attempt.
            foreach(var request in requests)
            {
                ProfileCredentialToken? result=null;bool returned=false;
                try
                {
                    cancellation.ThrowIfCancellationRequested();
                    Fresh(captured,hours);
                    if(warm)Fresh(TimestampPolicy.Parse(request.ObservedAt),hours);
                    using var issued=Execute(request);
                    cancellation.ThrowIfCancellationRequested();
                    Validate(issued,request,tenant,principal,limit);
                    result=new ProfileCredentialToken(request.ToTransport(),issued.AccessToken,issued.RefreshToken,issued.ExpiresAt,issued.ResponseAdditionalScopeCount,
                        warm?"SilentExplicitScopeAcquisition":"BoundedTargetedSilentExplicitScopeAcquisition");
                    if(!warm)
                    {
                        var claims=result.TokenClaims;
                        var observation=JsonSerializer.Serialize(new{ClientId=request.ClientId,ResourceId=request.ResourceId,Outcome="Succeeded",TenantFingerprint=tenant,
                            PrincipalFingerprint=principal,ObservedAt=DateTimeOffset.UtcNow.ToString("o"),Protocol="OAuth2V2Pkce",Spa=false,
                            RedirectFingerprint=Fingerprint(request.RedirectUri),RequestedScopes=request.Scopes,ScpScopes=claims.Scopes,ClaimsReadable=true,
                            HasScpClaim=true,NamespaceVerification="Matched",RequestVerification="Matched",SignatureValidated=false});
                        try{checkpoint!(observation);}catch{throw new CheckpointFailure();}
                    }
                    cancellation.ThrowIfCancellationRequested();Validate(result,request,tenant,principal,limit);
                    Fresh(captured,hours);if(warm)Fresh(TimestampPolicy.Parse(request.ObservedAt),hours);
                    returned=true;return result;
                }
                catch(CheckpointFailure){throw;}
                catch(OperationCanceledException){throw;}
                catch{cancellation.ThrowIfCancellationRequested();} // Bounded candidates only; no consent/default fallback.
                finally{if(!returned)result?.Dispose();}
            }
            throw new InvalidOperationException();
        }
        catch(OperationCanceledException){throw;}
        catch{throw new InvalidOperationException("Fresh profile scope acquisition failed. Details suppressed.");}
    }
    private sealed class CheckpointFailure:Exception{}
    private static void Validate(ProfileCredentialToken token,ScopePlanning.RequestRow row,string tenant,string principal,int limit)
    {
        var expected=row.ToTransport();var actual=token.Request;
        OAuthTransport.ValidateRequest(actual);
        if(actual.Discovery || actual.Protocol!="OAuth2V2Pkce" || actual.ClientId!=expected.ClientId || actual.ResourceId!=expected.ResourceId ||
            actual.ResourceUri!=expected.ResourceUri || actual.Tenant!=expected.Tenant || actual.RedirectUri!=expected.RedirectUri || actual.Spa!=expected.Spa ||
            !actual.Scopes.SequenceEqual(expected.Scopes) || !actual.OAuthScopes.SequenceEqual(expected.OAuthScopes))throw new InvalidOperationException();
        var claims=token.TokenClaims;
        TokenPolicy.Validate(claims.TenantFingerprint!,claims.PrincipalFingerprint!,claims.ClientId!,claims.Audience!,tenant,principal,row.ClientId,row.ResourceId,
            claims.Scopes,row.Scopes,claims.HasDelegatedScopeClaim,claims.ExpiresAt,token.ExpiresAt,limit,token.ResponseAdditionalScopeCount,false,DateTimeOffset.UtcNow);
    }
    private static void Fresh(DateTimeOffset date,int hours){var now=DateTimeOffset.UtcNow;if(date<now.AddHours(-hours) || date>now.AddMinutes(5))throw new InvalidOperationException();}
    private static string Fingerprint(string value)=>Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(value))).ToLowerInvariant();
}
