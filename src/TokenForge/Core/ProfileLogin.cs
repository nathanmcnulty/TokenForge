using System;
using System.IO;
using System.Linq;
using System.Security;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Threading;
using TokenForge.Core.V0100;
using TokenForge.Core.V0110;
using TokenForge.Core.V0180;
using TokenForge.Core.V0190;
using TokenForge.Core.V0200;
using TokenForge.Core.V0220;
using TokenForge.Core.V0230;
using TokenForge.Core.V0240;
using TokenForge.Core.V0250;

namespace TokenForge.Core;

public sealed record ProfileLoginResult(string Profile,string Tenant,string Storage,string SessionState,string RetainUntil,
    string BootstrapClientId,int BootstrapAdditionalScopeCount,string Evidence="ProfileLoginGraphIdentityConfirmed",
    bool CookieSaved=false,bool CredentialOutput=false,bool SignatureValidated=false);

// In-process acquisition adapter; credentials never leave the owned bootstrap result.
// Login resets this session's token cache, just like explicit PowerShell login.
public static class ProfileLogin
{
    public static ProfileLoginResult Login(string name,string? root,string inventoryJson,
        Func<OAuthRequest,ProfileCredentialToken> acquire,SecureString? password=null,
        Func<SecureString,string>? readIdentity=null,CancellationToken cancellation=default)
        => LoginCore(name,root,inventoryJson,acquire,password,readIdentity,cancellation,()=>DateTimeOffset.UtcNow);

    // Internal clock keeps commit-time policy checks deterministic without changing the public login API.
    internal static ProfileLoginResult LoginCore(string name,string? root,string inventoryJson,
        Func<OAuthRequest,ProfileCredentialToken> acquire,SecureString? password,
        Func<SecureString,string>? readIdentity,CancellationToken cancellation,Func<DateTimeOffset> clock)
    {
        SecureString? key=null;byte[]? before=null,plaintext=null,updated=null,envelope=null,configurationBytes=null;
        JsonDocument? previous=null;string? temporary=null;
        try
        {
            cancellation.ThrowIfCancellationRequested();
            if(acquire==null || inventoryJson==null || inventoryJson.Length>64*1024*1024 || Encoding.UTF8.GetByteCount(inventoryJson)>64*1024*1024)throw new InvalidOperationException();
            string initial=ProfileStore.Read(name,root);
            using var document=JsonDocument.Parse(initial);var profile=document.RootElement;
            string storage=profile.GetProperty("Storage").GetString()!;
            if(storage=="Passphrase" && password==null || storage!="Passphrase" && password!=null || storage=="OperatingSystem" && PlatformVaultKey.Backend=="Unsupported")throw new InvalidOperationException();
            var request=ScopePlanning.BootstrapRequest(inventoryJson,profile.GetProperty("Tenant").GetString()!,profile.GetProperty("BootstrapClientId").GetString()!,
                profile.GetProperty("MaxAgeHours").GetInt32(),browser:true).ToTransport();
            using var inventory=JsonDocument.Parse(inventoryJson);string expectedTenant=inventory.RootElement.GetProperty("TenantFingerprint").GetString()!;
            string directory=Path.Combine(ProfileStore.Root(root,false),name);
            string lockPath=PrivateFiles.Resolve(Path.Combine(directory,".operation.lock"),false);
            FileStream held;try{held=PrivateFiles.Open(lockPath,true);}catch(IOException){held=PrivateFiles.Open(lockPath,false);}
            using(held)
            {
                if(ProfileStore.Read(name,root)!=initial)throw new InvalidOperationException();
                string vault=PrivateFiles.Resolve(Path.Combine(directory,"session.tfvault"),false);
                if(storage!="Memory")
                {
                    bool exists=File.Exists(vault);
                    // Lock before touching the OS key. A raced create/delete fails closed.
                    using var read=VaultFileTransaction.Begin(vault,exists?"Read":"Create");
                    if(storage=="Passphrase"){key=password!.Copy();key.MakeReadOnly();}
                    else key=PlatformVaultKey.Open(ProfileKeyIdentity.Compute(directory,profile.GetProperty("KeyId").GetString()!),!exists);
                    if(exists)
                    {
                        before=read.ReadEnvelope();plaintext=VaultEnvelope.Decrypt(before,key);
                        VaultRecordPolicy.Validate(plaintext);previous=JsonDocument.Parse(plaintext);
                    }
                }
                using var token=acquire(OAuthTransport.Snapshot(request)) ?? throw new InvalidOperationException();
                Validate(token,request,profile,expectedTenant,clock());
                string identity=readIdentity==null?ProfileTokenApi.ReadIdentity(token.AccessToken,cancellation):readIdentity(token.AccessToken);
                if(!Guid.TryParse(identity,out var account) || !token.TokenClaims.MatchesPrincipalIdentity(account))throw new InvalidOperationException();
                cancellation.ThrowIfCancellationRequested();Validate(token,request,profile,expectedTenant,clock());
                if(ProfileStore.Read(name,root)!=initial)throw new InvalidOperationException();
                var captured=TimestampPolicy.Parse(inventory.RootElement.GetProperty("CapturedAt").GetString());
                var now=clock();
                if(captured<now.AddHours(-profile.GetProperty("MaxAgeHours").GetInt32()) || captured>now.AddMinutes(5))throw new InvalidOperationException();
                var claims=token.TokenClaims;string tenant=claims.TenantIdentity() ?? throw new InvalidOperationException();
                int extras=claims.Scopes.Count(s=>s!="User.Read" && s is not ("openid" or "profile" or "email" or "offline_access"));
                string retained=now.AddHours(profile.GetProperty("SessionRetentionHours").GetInt32()).ToString("o");
                string created=now.ToString("o");
                if(previous!=null)
                {
                    var old=previous.RootElement.GetProperty("Sessions").EnumerateObject().Where(s=>s.Name.Equals(name,StringComparison.OrdinalIgnoreCase)).ToArray();
                    if(old.Length>1)throw new InvalidOperationException();
                    if(old.Length==1)
                    {
                        if(old[0].Value.GetProperty("TenantFingerprint").GetString()!=claims.TenantFingerprint || old[0].Value.GetProperty("PrincipalFingerprint").GetString()!=claims.PrincipalFingerprint)throw new InvalidOperationException();
                        created=old[0].Value.GetProperty("CreatedAt").GetString()!;
                    }
                }
                var next=JsonNode.Parse(initial)!.AsObject();next["Tenant"]=tenant;next["ExpectedTenantFingerprint"]=claims.TenantFingerprint;
                next["ExpectedPrincipalFingerprint"]=claims.PrincipalFingerprint;next["Revision"]=Guid.NewGuid().ToString();next["UpdatedAt"]=now.ToString("o");
                string configuration=next.ToJsonString(new JsonSerializerOptions{WriteIndented=true});ProfilePolicy.Validate(configuration,name);
                configurationBytes=Encoding.UTF8.GetBytes(configuration);
                temporary=PrivateFiles.Resolve(Path.Combine(directory,".login-"+Guid.NewGuid().ToString("N")+".tmp"),false);
                using(var output=PrivateFiles.Open(temporary,true)){output.Write(configurationBytes);output.Flush(true);}
                if(storage!="Memory")
                {
                    updated=VaultInspector.Serialize(writer=>
                    {
                        writer.WriteStartObject();writer.WriteNumber("SchemaVersion",1);writer.WriteStartObject("Sessions");
                        if(previous!=null)foreach(var item in previous.RootElement.GetProperty("Sessions").EnumerateObject())
                            if(!item.Name.Equals(name,StringComparison.OrdinalIgnoreCase)){writer.WritePropertyName(item.Name);item.Value.WriteTo(writer);}
                        writer.WritePropertyName(name);writer.WriteStartObject();writer.WriteString("TenantFingerprint",claims.TenantFingerprint);writer.WriteString("PrincipalFingerprint",claims.PrincipalFingerprint);
                        writer.WriteString("Revision",Guid.NewGuid().ToString());writer.WriteString("CreatedAt",created);writer.WriteString("LastConfirmedAt",now.ToString("o"));writer.WriteString("RetainUntil",retained);
                        writer.WriteNull("Cookie");writer.WriteString("CookieName","ESTSAUTH");writer.WriteStartObject("Tokens");writer.WriteEndObject();writer.WriteEndObject();writer.WriteEndObject();writer.WriteEndObject();
                    });
                    VaultRecordPolicy.Validate(updated);envelope=VaultEnvelope.Encrypt(updated,key);
                    cancellation.ThrowIfCancellationRequested();
                    using var commit=VaultFileTransaction.Begin(vault,before==null?"Create":"Update");
                    if(before!=null)
                    {
                        byte[] current=commit.ReadEnvelope();
                        try{if(!current.AsSpan().SequenceEqual(before))throw new InvalidOperationException();}
                        finally{CryptographicOperations.ZeroMemory(current);}
                    }
                    if(ProfileStore.Read(name,root)!=initial)throw new InvalidOperationException();
                    Validate(token,request,profile,expectedTenant,clock());
                    if(TimestampPolicy.Parse(retained)<=clock())throw new InvalidOperationException();
                    commit.Commit(envelope);
                }
                else
                {
                    cancellation.ThrowIfCancellationRequested();
                    Validate(token,request,profile,expectedTenant,clock());
                    if(TimestampPolicy.Parse(retained)<=clock())throw new InvalidOperationException();
                    if(ProfileStore.Read(name,root)!=initial)throw new InvalidOperationException();
                }
                // Complete the two local writes without introducing a cancellation gap.
                // A disk failure after the vault commit fails closed; same-account login can recover.
                string profilePath=PrivateFiles.Resolve(Path.Combine(directory,"profile.json"),false);
                File.Move(temporary,profilePath,true);temporary=null;
                return new ProfileLoginResult(name,tenant,storage,storage=="Memory"?"NotPersisted":"Available",retained,request.ClientId,extras);
            }
        }
        catch(OperationCanceledException){throw;}
        catch{throw new InvalidOperationException("Profile login failed. Details suppressed.");}
        finally
        {
            previous?.Dispose();key?.Dispose();
            foreach(var bytes in new[]{before,plaintext,updated,envelope,configurationBytes})if(bytes!=null)CryptographicOperations.ZeroMemory(bytes);
            if(temporary!=null){try{File.Delete(temporary);}catch{}}
        }
    }
    private static void Validate(ProfileCredentialToken token,OAuthRequest request,JsonElement profile,string tenant,DateTimeOffset now)
    {
        var actual=token.Request;OAuthTransport.ValidateRequest(actual);
        if(actual.Discovery || actual.Spa || actual.Protocol!=request.Protocol || actual.ClientId!=request.ClientId || actual.ResourceId!=request.ResourceId ||
            actual.ResourceUri!=request.ResourceUri || actual.Tenant!=request.Tenant || actual.RedirectUri!=request.RedirectUri || !actual.Scopes.SequenceEqual(request.Scopes) || !actual.OAuthScopes.SequenceEqual(request.OAuthScopes))throw new InvalidOperationException();
        var claims=token.TokenClaims;
        if(claims.PrincipalFingerprint==null || claims.TenantIdentity()==null || profile.GetProperty("ExpectedTenantFingerprint").GetString() is string boundTenant && boundTenant!=claims.TenantFingerprint ||
            profile.GetProperty("ExpectedPrincipalFingerprint").GetString() is string boundAccount && boundAccount!=claims.PrincipalFingerprint)throw new InvalidOperationException();
        TokenPolicy.Validate(claims.TenantFingerprint!,claims.PrincipalFingerprint!,claims.ClientId!,claims.Audience!,tenant,claims.PrincipalFingerprint!,request.ClientId,request.ResourceId,
            claims.Scopes,request.Scopes,claims.HasDelegatedScopeClaim,claims.ExpiresAt,token.ExpiresAt,profile.GetProperty("MaxBootstrapAdditionalScopes").GetInt32(),token.ResponseAdditionalScopeCount,false,now);
    }
}
