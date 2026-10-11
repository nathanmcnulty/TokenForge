using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Security;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;
using System.Threading;
using TokenForge.Core.V0100;
using TokenForge.Core.V0180;
using TokenForge.Core.V0220;
using TokenForge.Core.V0240;
using TokenForge.Core.V0250;

namespace TokenForge.Core;

// Caller owns this result. Credentials are deliberately excluded from JSON projections.
public sealed class ProfileCredentialToken : IDisposable
{
    public OAuthRequest Request { get; }
    [JsonIgnore] public SecureString AccessToken { get; }
    [JsonIgnore] public SecureString? RefreshToken { get; internal set; }
    public DateTimeOffset? ExpiresAt { get; }
    public int ResponseAdditionalScopeCount { get; }
    public TokenClaims TokenClaims => TokenClaims.Read(AccessToken);
    public string Evidence { get; internal set; }
    public ProfileCredentialToken(OAuthRequest request, SecureString access, SecureString? refresh, DateTimeOffset? expiry,
        int responseAdditionalScopeCount=0,string evidence="SilentExplicitScopeAcquisition")
    {
        Request=OAuthTransport.Snapshot(request);
        if(responseAdditionalScopeCount<0 || evidence is not ("SilentExplicitScopeAcquisition" or "BoundedTargetedSilentExplicitScopeAcquisition" or "CachedVerifiedContextNotNewIssuance" or "SameClientRefreshMatchedIssuedContext"))throw new InvalidOperationException();
        ResponseAdditionalScopeCount=responseAdditionalScopeCount;ExpiresAt=expiry;Evidence=evidence;
        AccessToken=access.Copy();
        try{RefreshToken=refresh?.Copy();}catch{AccessToken.Dispose();throw;}
    }
    public void Dispose(){AccessToken.Dispose();RefreshToken?.Dispose();}
}

public sealed class ProfileFreshRequest
{
    public string[] Scopes { get; }
    public string ResourceId { get; }
    [JsonIgnore] public SecureString? Cookie { get; }
    public string CookieName { get; }
    internal ProfileFreshRequest(string[] scopes,string resource,SecureString? cookie,string cookieName)
    {Scopes=scopes.ToArray();ResourceId=resource;Cookie=cookie;CookieName=cookieName;}
}

public static class ProfileTokenLifecycle
{
    // Fresh planning and optional adapter execute synchronously under the profile lock.
    // Vault locking is released for network work and reacquired for ciphertext comparison and commit.
    // The optional delegates are in-process adapters, never a credential export protocol.
    public static ProfileCredentialToken Acquire(string name,string? root,string resource,string[] scopes,SecureString? password=null,
        Func<ProfileFreshRequest,ProfileCredentialToken>? acquireFresh=null,
        Func<OAuthRequest,SecureString,ProfileCredentialToken>? renew=null,CancellationToken cancellation=default,string? expectedProfileJson=null)
    {
        scopes=scopes?.ToArray()!;
        if(!Guid.TryParse(resource,out var resourceId) || resourceId==Guid.Empty || scopes==null || scopes.Length is <1 or >64 ||
            scopes.Any(s=>s==null || s.Length>256 || !Regex.IsMatch(s,@"\A[A-Za-z0-9_-][A-Za-z0-9_.-]*\z") || new[]{"openid","profile","email","offline_access"}.Contains(s,StringComparer.Ordinal)))
            throw new InvalidOperationException("Invalid explicit profile token request.");
        resource=resourceId.ToString();scopes=scopes.Distinct(StringComparer.Ordinal).OrderBy(s=>s,StringComparer.Ordinal).ToArray();
        if(expectedProfileJson!=null)V0200.ProfilePolicy.Validate(expectedProfileJson,name);
        using var expected=expectedProfileJson==null?null:JsonDocument.Parse(expectedProfileJson);
        return ProfileStore.WithVault(name,root,password,null,"Update",false,(transaction,key,configuration)=>
            AcquireLocked(name,root,transaction!,key!,configuration,resource,scopes,acquireFresh,renew,cancellation),
            configuration=>{if(expected!=null && expected.RootElement.GetRawText()!=configuration.GetRawText())throw new InvalidOperationException();if(configuration.GetProperty("Storage").GetString()=="Memory" || configuration.GetProperty("ExpectedTenantFingerprint").ValueKind!=JsonValueKind.String || configuration.GetProperty("ExpectedPrincipalFingerprint").ValueKind!=JsonValueKind.String)throw new InvalidOperationException();});
    }
    private static ProfileCredentialToken AcquireLocked(string name,string? root,VaultFileTransaction transaction,SecureString password,JsonElement profile,
        string resource,string[] scopes,Func<ProfileFreshRequest,ProfileCredentialToken>? acquireFresh,
        Func<OAuthRequest,SecureString,ProfileCredentialToken>? renew,CancellationToken cancellation)
    {
        byte[]? plaintext=null,rewritten=null;ProfileCredentialToken? result=null;SecureString? cookie=null;
        bool returned=false,released=false;
        try
        {
            cancellation.ThrowIfCancellationRequested();
            string tenant=profile.GetProperty("ExpectedTenantFingerprint").GetString() ?? throw new InvalidOperationException();
            string principal=profile.GetProperty("ExpectedPrincipalFingerprint").GetString() ?? throw new InvalidOperationException();
            var envelope=transaction.ReadEnvelope();plaintext=V0190.VaultEnvelope.Decrypt(envelope,password);VaultRecordPolicy.Validate(plaintext);
            using var document=JsonDocument.Parse(plaintext);
            var sessions=document.RootElement.GetProperty("Sessions");
            var saved=sessions.EnumerateObject().Where(s=>s.Name.Equals(name,StringComparison.OrdinalIgnoreCase)).ToArray();
            if(saved.Length!=1)throw new InvalidOperationException();
            var session=saved[0].Value;
            if(Text(session,"TenantFingerprint")!=tenant || Text(session,"PrincipalFingerprint")!=principal || TimestampPolicy.Parse(Text(session,"RetainUntil"))<=DateTimeOffset.UtcNow)throw new InvalidOperationException();
            var selected=session.GetProperty("Tokens").EnumerateObject().Where(t=>Text(t.Value,"ResourceId")==resource && Strings(t.Value,"Scopes").ToHashSet(StringComparer.Ordinal).SetEquals(scopes))
                .OrderByDescending(t=>TimestampPolicy.Parse(Text(t.Value,"AcquiredAt"))).ThenBy(t=>t.Name,StringComparer.Ordinal).ToArray();
            string? replaced=null;
            if(selected.Length!=0)
            {
                var token=selected[0].Value;replaced=selected[0].Name;
                var request=Request(token);
                ValidateRequest(request,profile,resource,scopes);
                using var access=Secret(token,"AccessToken")!;using var refresh=Secret(token,"RefreshToken");
                var expiry=token.GetProperty("ExpiresAt").ValueKind==JsonValueKind.Null ? (DateTimeOffset?)null : TimestampPolicy.Parse(Text(token,"ExpiresAt"));
                using var cached=new ProfileCredentialToken(request,access,refresh,expiry,0,"CachedVerifiedContextNotNewIssuance");
                Validate(cached,profile,resource,scopes,true);
                var claims=cached.TokenClaims;
                if(expiry> DateTimeOffset.UtcNow.AddMinutes(2) && claims.ExpiresAt> DateTimeOffset.UtcNow.AddMinutes(2))
                    result=new ProfileCredentialToken(request,cached.AccessToken,cached.RefreshToken,expiry,0,"CachedVerifiedContextNotNewIssuance");
                else if(refresh!=null)
                {
                    cancellation.ThrowIfCancellationRequested();
                    transaction.Dispose();released=true;
                    if(renew!=null)
                    {
                        using var response=renew(OAuthTransport.Snapshot(request),refresh) ?? throw new InvalidOperationException();
                        result=new ProfileCredentialToken(response.Request,response.AccessToken,response.RefreshToken,response.ExpiresAt,response.ResponseAdditionalScopeCount,response.Evidence);
                    }
                    else
                    {
                        using var renewed=OAuthTransport.Refresh(request,refresh,cancellation);
                        result=new ProfileCredentialToken(request,renewed.AccessToken,renewed.RefreshToken,renewed.ExpiresAt,renewed.AdditionalScopes.Length,"SameClientRefreshMatchedIssuedContext");
                    }
                    if(!SameRequest(result.Request,request))throw new InvalidOperationException();
                    if(result.RefreshToken==null)result.RefreshToken=refresh.Copy();
                    result.Evidence="SameClientRefreshMatchedIssuedContext";
                }
            }
            if(result==null)
            {
                if(acquireFresh==null)throw new InvalidOperationException("Fresh profile acquisition is required.");
                cookie=Secret(session,"Cookie");string cookieName=session.GetProperty("CookieName").GetString() ?? "ESTSAUTH";
                cancellation.ThrowIfCancellationRequested();
                if(!released){transaction.Dispose();released=true;}
                using var response=acquireFresh(new ProfileFreshRequest(scopes,resource,cookie,cookieName)) ?? throw new InvalidOperationException();
                result=new ProfileCredentialToken(response.Request,response.AccessToken,response.RefreshToken,response.ExpiresAt,response.ResponseAdditionalScopeCount,response.Evidence);
                if(result.Evidence is not ("SilentExplicitScopeAcquisition" or "BoundedTargetedSilentExplicitScopeAcquisition"))throw new InvalidOperationException();
            }
            cancellation.ThrowIfCancellationRequested();ValidateRequest(result.Request,profile,resource,scopes);Validate(result,profile,resource,scopes,false);
            // Release the vault lock during network work; direct vault edits can invalidate this result.
            using var update=released?VaultFileTransaction.Begin(Path.Combine(ProfileStore.Root(root,false),name,"session.tfvault"),"Update"):null;
            var active=update ?? transaction;
            // Recheck ciphertext after reacquiring the vault lock, before returning or committing.
            using(var current=JsonDocument.Parse(ProfileStore.Read(name,root)))if(current.RootElement.GetRawText()!=profile.GetRawText())throw new InvalidOperationException();
            if(!active.ReadEnvelope().AsSpan().SequenceEqual(envelope) || TimestampPolicy.Parse(Text(session,"RetainUntil"))<=DateTimeOffset.UtcNow)throw new InvalidOperationException();
            if(result.Evidence!="CachedVerifiedContextNotNewIssuance")
            {
                string id=Id(result.Request);var claims=result.TokenClaims;var now=DateTimeOffset.UtcNow;
                rewritten=VaultInspector.Serialize(writer=>
                {
                    writer.WriteStartObject();writer.WriteNumber("SchemaVersion",1);writer.WriteStartObject("Sessions");
                    foreach(var item in sessions.EnumerateObject())
                    {
                        writer.WritePropertyName(item.Name);
                        if(!item.Name.Equals(name,StringComparison.OrdinalIgnoreCase)){item.Value.WriteTo(writer);continue;}
                        writer.WriteStartObject();
                        foreach(var field in item.Value.EnumerateObject())
                        {
                            writer.WritePropertyName(field.Name);
                            if(field.Name=="Revision"){writer.WriteStringValue(Guid.NewGuid().ToString());continue;}
                            if(field.Name!="Tokens"){field.Value.WriteTo(writer);continue;}
                            writer.WriteStartObject();
                            foreach(var old in field.Value.EnumerateObject())if(old.Name!=replaced && old.Name!=id){writer.WritePropertyName(old.Name);old.Value.WriteTo(writer);}
                            writer.WritePropertyName(id);WriteToken(writer,id,result,claims,now);writer.WriteEndObject();
                        }
                        writer.WriteEndObject();
                    }
                    writer.WriteEndObject();writer.WriteEndObject();
                });
                VaultRecordPolicy.Validate(rewritten);cancellation.ThrowIfCancellationRequested();
                Validate(result,profile,resource,scopes,false);
                if(TimestampPolicy.Parse(Text(session,"RetainUntil"))<=DateTimeOffset.UtcNow)throw new InvalidOperationException();
                using(var current=JsonDocument.Parse(ProfileStore.Read(name,root)))if(current.RootElement.GetRawText()!=profile.GetRawText())throw new InvalidOperationException();
                if(!active.ReadEnvelope().AsSpan().SequenceEqual(envelope))throw new InvalidOperationException();
                var encrypted=V0190.VaultEnvelope.Encrypt(rewritten,password);
                // PBKDF2 encryption can outlast a nearly expired deadline.
                using(var current=JsonDocument.Parse(ProfileStore.Read(name,root)))if(current.RootElement.GetRawText()!=profile.GetRawText())throw new InvalidOperationException();
                if(!active.ReadEnvelope().AsSpan().SequenceEqual(envelope))throw new InvalidOperationException();
                cancellation.ThrowIfCancellationRequested();Validate(result,profile,resource,scopes,false);
                if(TimestampPolicy.Parse(Text(session,"RetainUntil"))<=DateTimeOffset.UtcNow)throw new InvalidOperationException();
                active.Commit(encrypted);
            }
            else
            {
                cancellation.ThrowIfCancellationRequested();Validate(result,profile,resource,scopes,false);
                if(TimestampPolicy.Parse(Text(session,"RetainUntil"))<=DateTimeOffset.UtcNow)throw new InvalidOperationException();
            }
            returned=true;return result;
        }
        catch {throw new InvalidOperationException("Profile token lifecycle failed. Details suppressed.");}
        finally {cookie?.Dispose();if(!returned)result?.Dispose();if(plaintext!=null)CryptographicOperations.ZeroMemory(plaintext);if(rewritten!=null)CryptographicOperations.ZeroMemory(rewritten);}
    }
    private static void Validate(ProfileCredentialToken token,JsonElement profile,string resource,string[] scopes,bool expired)
    {
        var c=token.TokenClaims;
        TokenPolicy.Validate(c.TenantFingerprint!,c.PrincipalFingerprint!,c.ClientId!,c.Audience!,Text(profile,"ExpectedTenantFingerprint"),Text(profile,"ExpectedPrincipalFingerprint"),token.Request.ClientId,resource,
            c.Scopes,scopes,c.HasDelegatedScopeClaim,c.ExpiresAt,token.ExpiresAt,profile.GetProperty("MaxAdditionalScopes").GetInt32(),token.ResponseAdditionalScopeCount,expired,DateTimeOffset.UtcNow);
    }
    private static void ValidateRequest(OAuthRequest request,JsonElement profile,string resource,string[] scopes)
    {
        OAuthTransport.ValidateRequest(request);
        if(request.Discovery || request.Protocol!="OAuth2V2Pkce" || request.Tenant!=Text(profile,"Tenant") || request.ResourceId!=resource || request.ResourceUri!=resource || !request.Scopes.ToHashSet(StringComparer.Ordinal).SetEquals(scopes))throw new InvalidOperationException();
    }
    private static bool SameRequest(OAuthRequest a,OAuthRequest b)=>a.ClientId==b.ClientId && a.ResourceId==b.ResourceId && a.ResourceUri==b.ResourceUri && a.Tenant==b.Tenant && a.RedirectUri==b.RedirectUri && a.Spa==b.Spa && a.Protocol==b.Protocol && a.Discovery==b.Discovery && a.Scopes.SequenceEqual(b.Scopes) && a.OAuthScopes.SequenceEqual(b.OAuthScopes);
    private static OAuthRequest Request(JsonElement token)
    {
        var resource=Text(token,"ResourceId");var scopes=Strings(token,"Scopes");
        return new OAuthRequest{ClientId=Text(token,"ClientId"),ResourceId=resource,ResourceUri=resource,Tenant=Text(token,"Tenant"),RedirectUri=Text(token,"RedirectUri"),Scopes=scopes,
            OAuthScopes=scopes.Select(s=>resource+"/"+s).Concat(token.GetProperty("OfflineAccess").GetBoolean()?new[]{"offline_access"}:Array.Empty<string>()).ToArray(),Spa=token.GetProperty("Spa").GetBoolean(),Protocol=Text(token,"Protocol")};
    }
    private static string Id(OAuthRequest request)=>Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(request.ClientId+"|"+request.ResourceId+"|"+string.Join(" ",request.Scopes.OrderBy(s=>s,StringComparer.Ordinal))+"|"+request.RedirectUri+"|"+request.Spa))).ToLowerInvariant();
    private static void WriteToken(Utf8JsonWriter w,string id,ProfileCredentialToken token,TokenClaims claims,DateTimeOffset now)
    {
        var r=token.Request;w.WriteStartObject();w.WriteString("Id",id);w.WriteString("ClientId",r.ClientId);w.WriteString("ResourceId",r.ResourceId);w.WriteString("Tenant",r.Tenant);w.WriteString("Audience",claims.Audience);
        w.WritePropertyName("Scopes");JsonSerializer.Serialize(w,r.Scopes);w.WritePropertyName("IssuedScopes");JsonSerializer.Serialize(w,claims.Scopes);w.WriteNumber("AdditionalScopeCount",claims.Scopes.Except(r.Scopes,StringComparer.Ordinal).Except(new[]{"openid","profile","email","offline_access"},StringComparer.Ordinal).Count());
        w.WriteString("RedirectUri",r.RedirectUri);w.WriteBoolean("Spa",r.Spa);w.WriteBoolean("OfflineAccess",r.OAuthScopes.Contains("offline_access",StringComparer.Ordinal));w.WriteString("Protocol",r.Protocol);w.WriteString("AcquiredAt",now.ToString("o"));
        w.WriteString("ExpiresAt",(token.ExpiresAt<claims.ExpiresAt?token.ExpiresAt:claims.ExpiresAt)!.Value.ToString("o"));
        w.WriteString("AccessToken",new NetworkCredential("",token.AccessToken).Password);w.WriteString("RefreshToken",token.RefreshToken==null?null:new NetworkCredential("",token.RefreshToken).Password);w.WriteString("ConsentEvidence",token.Evidence);w.WriteEndObject();
    }
    private static string Text(JsonElement v,string field)=>v.GetProperty(field).GetString()!;
    private static string[] Strings(JsonElement v,string field)=>v.GetProperty(field).EnumerateArray().Select(x=>x.GetString()!).ToArray();
    private static SecureString? Secret(JsonElement v,string field)
    {
        if(v.GetProperty(field).ValueKind==JsonValueKind.Null)return null;
        var secret=new SecureString();try{foreach(char c in Text(v,field))secret.AppendChar(c);secret.MakeReadOnly();return secret;}catch{secret.Dispose();throw;}
    }
}
