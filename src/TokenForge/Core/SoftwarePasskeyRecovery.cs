#nullable enable
using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text.Json;
using System.Threading;
using TokenForge.Core.V0100;
using TokenForge.Core.V0180;
using TokenForge.Core.V0220;

namespace TokenForge.Core;

public sealed record SoftwarePasskeyRecoveryResult(bool Usable,bool ReceiptSaved,string Evidence);
public sealed class SoftwarePasskeyRecoveryException : InvalidOperationException
{
    public string Stage {get;}
    public bool ReceiptSaved {get;}
    internal SoftwarePasskeyRecoveryException(string stage,bool saved)
        :base("Software passkey recovery failed during "+stage+". Details suppressed."){Stage=stage;ReceiptSaved=saved;}
}
public static class SoftwarePasskeyRecovery
{
    private const string Client="14d82eec-204b-4c2f-b7e8-296a70dab67e",Graph="00000003-0000-0000-c000-000000000000";
    // Only authentication and Graph GET /me occur remotely. No enrollment request is sent.
    public static SoftwarePasskeyRecoveryResult Recover(string path,string identityJson,CancellationToken cancellation=default,int maximumAdditionalScopes=0)
    {
        string stage="Inputs";bool saved=false;
        using var deadline=CancellationTokenSource.CreateLinkedTokenSource(cancellation);deadline.CancelAfter(TimeSpan.FromMinutes(3));
        try
        {
            if(maximumAdditionalScopes is <0 or >512)throw new InvalidOperationException();
            deadline.Token.ThrowIfCancellationRequested();path=PrivateFiles.Resolve(path,false);
            using var operation=Lock(path);
            if(identityJson.Length>64*1024*1024)throw new InvalidOperationException();
            using var identity=JsonDocument.Parse(identityJson,new JsonDocumentOptions{MaxDepth=32});
            DiscoverySourceClaims.ValidateUniqueKeys(identity.RootElement);
            string tenant=Fingerprint(identity.RootElement,"TenantFingerprint"),principal=Fingerprint(identity.RootElement,"PrincipalFingerprint");
            using var signer=SoftwarePasskey.OpenPendingForRecovery(path);
            stage="Authentication";using var session=signer.Authenticate(deadline.Token);
            stage="IdentityConfirmation";
            using var token=OAuthTransport.Cookie(new OAuthRequest{ClientId=Client,ResourceId=Graph,ResourceUri=Graph,RedirectUri="https://login.microsoftonline.com/common/oauth2/nativeclient",Scopes=new[]{"User.Read"},OAuthScopes=new[]{Graph+"/User.Read"}},session.Cookie,session.CookieName,deadline.Token);
            var claims=token.TokenClaims;
            void ValidateToken()=>TokenPolicy.Validate(claims.TenantFingerprint!,claims.PrincipalFingerprint!,claims.ClientId!,claims.Audience!,tenant,principal,Client,Graph,claims.Scopes,new[]{"User.Read"},claims.HasDelegatedScopeClaim,claims.ExpiresAt,token.ExpiresAt,maximumAdditionalScopes,token.AdditionalScopes.Length,false,DateTimeOffset.UtcNow);
            ValidateToken();
            if(!claims.MatchesPrincipalIdentity(Guid.Parse(ProfileTokenApi.ReadIdentity(token.AccessToken,deadline.Token))))throw new InvalidOperationException();
            ValidateToken();
            stage="ReceiptPublication";
            SoftwarePasskeyReceipt.Publish(path,signer.FileHash,signer.ReceiptCredentialId,deadline.Token,ref saved);
            return new SoftwarePasskeyRecoveryResult(true,true,SoftwarePasskeyReceipt.Proof);
        }
        catch{throw new SoftwarePasskeyRecoveryException(stage,saved);}
    }
    private static FileStream Lock(string path)
    {path=PrivateFiles.Resolve(path+".recovery.lock",false);try{return PrivateFiles.Open(path,true);}catch(IOException){return PrivateFiles.Open(path,false);}}
    private static string Fingerprint(JsonElement root,string name)
    {string value=root.GetProperty(name).GetString() ?? "";if(value.Length!=64 || value.Any(c=>!"0123456789abcdef".Contains(c)))throw new InvalidOperationException();return value;}
}

// Receipts are private local evidence, bound to immutable credential bytes. They
// are not server-signed attestations and cannot protect against their owner editing them.
internal static class SoftwarePasskeyReceipt
{
    internal const string Proof="FreshSoftwarePasskeyAuthenticationAndGraphIdentity";
    internal static void Validate(string path,string hash,string id)
    {
        byte[] bytes=Read(path+".registered.json",4096);
        try
        {
            using var json=JsonDocument.Parse(bytes,new JsonDocumentOptions{MaxDepth=4});var root=json.RootElement;
            DiscoverySourceClaims.ValidateUniqueKeys(root);int version=root.GetProperty("SchemaVersion").GetInt32();
            if(root.GetProperty("CredentialFileSha256").GetString()!=hash || root.GetProperty("CredentialId").GetString()!=id)throw new InvalidOperationException();
            if(version==1)
            {if(root.EnumerateObject().Count()!=4 || root.GetProperty("Registered").ValueKind!=JsonValueKind.True)throw new InvalidOperationException();}
            else if(version==2)
            {if(root.EnumerateObject().Count()!=5 || root.GetProperty("Usable").ValueKind!=JsonValueKind.True || root.GetProperty("Proof").GetString()!=Proof)throw new InvalidOperationException();}
            else throw new InvalidOperationException();
        }
        finally{CryptographicOperations.ZeroMemory(bytes);}
    }
    internal static void Publish(string path,string hash,string id,CancellationToken cancellation,ref bool saved)
    {
        // Keep the exact credential open exclusively until publication completes.
        using var file=PrivateFiles.Open(PrivateFiles.Resolve(path,false),false);
        if(file.Length is <2 or >65536)throw new InvalidOperationException();
        byte[] keyBytes=new byte[checked((int)file.Length)],receipt=Array.Empty<byte>();string? temporary=null;
        try
        {
            file.ReadExactly(keyBytes);
            if(Convert.ToHexString(SHA256.HashData(keyBytes)).ToLowerInvariant()!=hash)throw new InvalidOperationException();
            string target=PrivateFiles.Resolve(path+".registered.json",false);
            receipt=JsonSerializer.SerializeToUtf8Bytes(new{SchemaVersion=2,Usable=true,Proof,CredentialFileSha256=hash,CredentialId=id});
            temporary=PrivateFiles.Resolve(target+"."+Guid.NewGuid().ToString("N")+".tmp",false);
            using(var output=PrivateFiles.Open(temporary,true)){output.Write(receipt);output.Flush(true);}
            cancellation.ThrowIfCancellationRequested();PrivateFiles.Resolve(target,false);PrivateFiles.PublishNew(temporary,target);saved=true;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(keyBytes);CryptographicOperations.ZeroMemory(receipt);
            if(temporary!=null && File.Exists(temporary))File.Delete(temporary);
        }
    }
    private static byte[] Read(string path,int maximum)
    {
        using var file=new FileStream(PrivateFiles.Resolve(path,false),FileMode.Open,FileAccess.Read,FileShare.Read);
        if(file.Length is <2 || file.Length>maximum)throw new InvalidOperationException();
        var bytes=new byte[checked((int)file.Length)];try{file.ReadExactly(bytes);return bytes;}catch{CryptographicOperations.ZeroMemory(bytes);throw;}
    }
}
