#nullable enable
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Security;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Threading;
using TokenForge.Core.V0180;
using TokenForge.Core.V0220;

namespace TokenForge.Core;

// Software authenticator for an explicitly supplied local lab credential. This is not
// a hardware authenticator or an operating-system WebAuthn implementation.
public sealed class SoftwarePasskey : IDisposable
{
    private readonly ECDsa key;
    private readonly string credential, handle, username;
    private SoftwarePasskey(ECDsa key,string credential,string handle,string username)
    {this.key=key;this.credential=credential;this.handle=handle;this.username=username;}
    internal string FileHash {get;private set;} = "";
    internal string ReceiptCredentialId {get;private set;} = "";
    public static SoftwarePasskey Open(string path)=>OpenCore(path,false);
    internal static SoftwarePasskey OpenPendingForRecovery(string path)=>OpenCore(path,true);
    private static SoftwarePasskey OpenCore(string path,bool recovery)
    {
        byte[]? bytes=null;ECDsa? key=null;
        try
        {
            path=PrivateFiles.Resolve(path,false);
            using var stream=new FileStream(path,FileMode.Open,FileAccess.Read,FileShare.Read);
            if(stream.Length is <2 or >65536)throw new InvalidOperationException();
            bytes=new byte[stream.Length];stream.ReadExactly(bytes);
            using var document=JsonDocument.Parse(bytes,new JsonDocumentOptions{MaxDepth=16});Unique(document.RootElement);
            var root=document.RootElement;
            if(root.ValueKind!=JsonValueKind.Object || root.TryGetProperty("keyVault",out _))throw new InvalidOperationException();
            string receiptId=Alias(root,"credentialId","methodId");
            string fileHash=Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();
            bool pending=root.TryGetProperty("enrollmentStatus",out var enrollment);
            if(pending && (enrollment.ValueKind!=JsonValueKind.String || enrollment.GetString()!="PendingRemoteVerification"))throw new InvalidOperationException();
            if(recovery)
            {
                if(!pending || File.Exists(PrivateFiles.Resolve(path+".registered.json",false)))throw new InvalidOperationException();
            }
            else if(pending)SoftwarePasskeyReceipt.Validate(path,fileHash,receiptId);
            string user=Alias(root,"username","userName"),id=receiptId,pem=Alias(root,"privateKey","keyValue");
            string rp=OptionalAlias(root,"relyingParty","rpId") ?? "login.microsoft.com";
            string origin=Optional(root,"url") ?? "https://login.microsoft.com";
            if(rp!="login.microsoft.com" || origin is not ("https://login.microsoft.com" or "https://login.microsoft.com/") || user.Length is <3 or >320 || user.Any(char.IsControl))throw new InvalidOperationException();
            foreach(string counter in new[]{"counter","signCount"})if(root.TryGetProperty(counter,out var count) && (!count.TryGetUInt32(out uint value) || value!=0))throw new InvalidOperationException();
            if(Guid.TryParseExact(id,"D",out var guid))id=Encode(Convert.FromHexString(guid.ToString("N")));
            id=Normalize(id,1024);string userHandle=Normalize(Alias(root,"userHandle",null),64);
            key=ECDsa.Create();
            if(pem.StartsWith("-----BEGIN PRIVATE KEY-----",StringComparison.Ordinal))key.ImportFromPem(pem);
            else
            {
                byte[] der=Convert.FromBase64String(pem.Replace('-','+').Replace('_','/').PadRight((pem.Length+3)/4*4,'='));
                try{key.ImportPkcs8PrivateKey(der,out int read);if(read!=der.Length)throw new InvalidOperationException();}finally{CryptographicOperations.ZeroMemory(der);}
            }
            if(key.KeySize!=256 || key.ExportParameters(false).Curve.Oid.Value!="1.2.840.10045.3.1.7")throw new InvalidOperationException();
            var result=new SoftwarePasskey(key,id,userHandle,user){FileHash=fileHash,ReceiptCredentialId=receiptId};key=null;return result;
        }
        catch{throw new InvalidOperationException("Unsupported or inaccessible software passkey. Details suppressed.");}
        finally{key?.Dispose();if(bytes!=null)CryptographicOperations.ZeroMemory(bytes);}
    }
    public string CreateAssertion(string serverChallenge)
    {
        if(serverChallenge.Length is <1 or >4096 || serverChallenge.Any(c=>c<33 || c>126))throw new InvalidOperationException("Invalid software passkey challenge.");
        byte[] auth=new byte[37],client=Array.Empty<byte>(),signed=Array.Empty<byte>(),signature=Array.Empty<byte>();
        try
        {
            SHA256.HashData(Encoding.ASCII.GetBytes("login.microsoft.com")).CopyTo(auth,0);auth[32]=5;
            client=JsonSerializer.SerializeToUtf8Bytes(new{challenge=Encode(Encoding.ASCII.GetBytes(serverChallenge)),crossOrigin=false,origin="https://login.microsoft.com",type="webauthn.get"});
            signed=new byte[69];auth.CopyTo(signed,0);SHA256.HashData(client).CopyTo(signed,37);
            signature=key.SignData(signed,HashAlgorithmName.SHA256,DSASignatureFormat.Rfc3279DerSequence);
            return JsonSerializer.Serialize(new{id=credential,clientDataJSON=Encode(client),authenticatorData=Encode(auth),signature=Encode(signature),userHandle=handle});
        }
        finally{foreach(byte[] b in new[]{auth,client,signed,signature})CryptographicOperations.ZeroMemory(b);}
    }
    public SoftwarePasskeySession Authenticate(CancellationToken cancellation=default)
    {
        using var handler=new HttpClientHandler{AllowAutoRedirect=false,CookieContainer=new CookieContainer()};
        using var client=new HttpClient(handler){Timeout=Timeout.InfiniteTimeSpan};
        client.DefaultRequestHeaders.UserAgent.ParseAdd("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36 Edg/142.0.0.0");
        using var deadline=CancellationTokenSource.CreateLinkedTokenSource(cancellation);deadline.CancelAfter(TimeSpan.FromSeconds(120));
        string stage="Challenge";
        try
        {
            string auth="https://login.microsoftonline.com/organizations/oauth2/v2.0/authorize?response_type=code&redirect_uri=msauth.com.msauth.unsignedapp%3A%2F%2Fauth&scope=https%3A%2F%2Fgraph.microsoft.com%2F.default&client_id=04b07795-8ddb-461a-bbee-02f9e1bf7b46&sso_reload=true&login_hint="+Uri.EscapeDataString(username);
            using var first=Config(Send(client,new Uri(auth),null,deadline.Token));var initial=first.RootElement;
            var credentialType=initial.GetProperty("oGetCredTypeResult");var credentials=credentialType.GetProperty("Credentials");
            if(credentials.GetProperty("HasFido").ValueKind!=JsonValueKind.True)throw new InvalidOperationException();
            string assertion=CreateAssertion(Text(initial,"sFidoChallenge"));
            var allow=credentials.GetProperty("FidoParams").GetProperty("AllowList");
            if(allow.ValueKind!=JsonValueKind.Array || allow.GetArrayLength()>256)throw new InvalidOperationException();
            string allowed=string.Join(",",allow.EnumerateArray().Select(v=>v.GetString() ?? throw new InvalidOperationException()));
            var pre=new Dictionary<string,string>{["allowedIdentities"]="2",["canary"]=Text(initial,"sFT"),["ServerChallenge"]=Text(initial,"sFT"),["postBackUrl"]=Text(initial,"urlPost"),["postBackUrlAad"]=Text(initial,"urlPostAad"),["postBackUrlMsa"]=Text(initial,"urlPostMsa"),["cancelUrl"]=Text(initial,"urlRefresh"),["resumeUrl"]=Text(initial,"urlResume"),["correlationId"]=Text(initial,"correlationId"),["credentialsJson"]=allowed,["ctx"]=Text(initial,"sCtx"),["username"]=username,["loginCanary"]=Text(initial,"canary")};
            stage="Preverification";
            using var verified=Config(Send(client,new Uri("https://login.microsoft.com/common/fido/get?uiflavor=Web"),pre,deadline.Token));var info=verified.RootElement;
            var post=new Dictionary<string,string>{["type"]="23",["ps"]="23",["assertion"]=assertion,["lmcCanary"]=Text(info,"sCrossDomainCanary"),["hpgrequestid"]=Text(info,"sessionId"),["ctx"]=Text(info,"sCtx"),["canary"]=Text(info,"canary"),["flowToken"]=Text(info,"sFT")};
            stage="Assertion";
            Send(client,new Uri("https://login.microsoftonline.com/common/login"),post,deadline.Token);
            post["flowToken"]=Text(credentialType,"FlowToken");
            stage="Finalization";
            var final=Send(client,new Uri("https://login.microsoftonline.com/common/login?sso_reload=true"),post,deadline.Token);
            var cookie=CompleteSession(client,handler.CookieContainer,final,deadline.Token,ref stage);
            deadline.Token.ThrowIfCancellationRequested();return new SoftwarePasskeySession(cookie.Name,cookie.Value);
        }
        catch(OperationCanceledException) when(cancellation.IsCancellationRequested){throw;}
        catch{throw new InvalidOperationException("Software passkey authentication failed during "+stage+" or requires interaction. Details suppressed.");}
    }
    // Kept separate so routing is tested without contacting the identity service.
    private static Cookie CompleteSession(HttpClient client,CookieContainer jar,OAuthHttpResponse final,CancellationToken cancellation,ref string stage)
    {
        // Only these known account/KMSI speedbumps are supported. Consent and
        // unknown policy pages remain interaction failures; no external callback is requested.
        var visited=new HashSet<string>(StringComparer.Ordinal);
        Cookie? cookie=null;
        for(int step=0;step<6 && (cookie=Cookie(jar))==null;step++)
        {
            cancellation.ThrowIfCancellationRequested();stage="Interaction";using var interrupt=Config(final);var page=interrupt.RootElement;
            string pageId=Text(page,"pgid");if(!visited.Add(pageId))throw new InvalidOperationException();
            if(pageId=="KmsiInterrupt")
            {
                stage="KmsiInterrupt";
                final=Send(client,new Uri("https://login.microsoftonline.com/kmsi"),new Dictionary<string,string>{["LoginOptions"]="1",["type"]="28",["ctx"]=Text(page,"sCtx"),["hpgrequestid"]=Text(page,"correlationId"),["flowToken"]=Text(page,"sFT"),["canary"]=Text(page,"canary"),["i19"]="4130"},cancellation);
            }
            else if(pageId=="CmsiInterrupt")
            {
                stage="CmsiInterrupt";
                final=Send(client,new Uri("https://login.microsoftonline.com/appverify"),new Dictionary<string,string>{["ContinueAuth"]="true",["i19"]="4130",["canary"]=Text(page,"canary"),["iscsrfspeedbump"]="false",["flowToken"]=Text(page,"sFT"),["hpgrequestid"]=Text(page,"correlationId"),["ctx"]=Text(page,"sCtx")},cancellation);
            }
            else if(pageId=="ConvergedSignIn")
            {
                stage="ConvergedSignIn";string sessionId;
                if(page.TryGetProperty("arrSessions",out var sessions) && sessions.ValueKind!=JsonValueKind.Array)throw new InvalidOperationException();
                if(sessions.ValueKind==JsonValueKind.Array && sessions.GetArrayLength()>0)
                {
                    if(sessions.GetArrayLength()!=1)throw new InvalidOperationException();sessionId=Text(sessions[0],"id");
                }
                else sessionId=Text(page,"sessionId");
                string url=Text(page,"urlLogin");var target=new Uri(url+(url.Contains('?')?"&":"?")+"sessionid="+Uri.EscapeDataString(sessionId));
                final=FollowIdentityGet(client,target,cancellation);
            }
            else{stage="UnsupportedInteraction";throw new InvalidOperationException();}
        }
        cookie=Cookie(jar);
        if(cookie==null)throw new InvalidOperationException();
        cancellation.ThrowIfCancellationRequested();return cookie;
    }
    private static OAuthHttpResponse Send(HttpClient client,Uri uri,Dictionary<string,string>? form,CancellationToken cancellation)
    {
        if(uri.Scheme!="https" || !uri.IsDefaultPort || uri.UserInfo.Length!=0 || uri.Fragment.Length!=0 || uri.Host is not ("login.microsoftonline.com" or "login.microsoft.com"))throw new InvalidOperationException();
        // OAuthTransport's single-host identity gate intentionally excludes the FIDO origin.
        using var timeout=CancellationTokenSource.CreateLinkedTokenSource(cancellation);timeout.CancelAfter(TimeSpan.FromSeconds(30));
        using var request=new HttpRequestMessage(form==null?HttpMethod.Get:HttpMethod.Post,uri);
        if(form!=null)request.Content=new FormUrlEncodedContent(form);
        using var response=client.SendAsync(request,HttpCompletionOption.ResponseHeadersRead,timeout.Token).GetAwaiter().GetResult();
        if((int)response.StatusCode is <200 or >=400 || response.Content.Headers.ContentLength>1048576)throw new InvalidOperationException();
        using var stream=response.Content.ReadAsStreamAsync(timeout.Token).GetAwaiter().GetResult();byte[] bytes=new byte[1048577];
        try
        {
            int used=0,count;while((count=stream.ReadAsync(bytes.AsMemory(used),timeout.Token).AsTask().GetAwaiter().GetResult())!=0){used+=count;if(used>1048576)throw new InvalidOperationException();}
            string? location=response.Headers.Location?.OriginalString;if(location?.Length>65536)throw new InvalidOperationException();
            return new OAuthHttpResponse((int)response.StatusCode,location,Encoding.UTF8.GetString(bytes,0,used));
        }
        finally{CryptographicOperations.ZeroMemory(bytes);}
    }
    private static OAuthHttpResponse FollowIdentityGet(HttpClient client,Uri uri,CancellationToken cancellation)
    {
        for(int step=0;step<8;step++)
        {
            cancellation.ThrowIfCancellationRequested();
            if(uri.Scheme!="https" || uri.Host!="login.microsoftonline.com" || !uri.IsDefaultPort || uri.UserInfo.Length!=0 || uri.Fragment.Length!=0)throw new InvalidOperationException();
            var response=Send(client,uri,null,cancellation);
            if(response.Status is not (301 or 302 or 303 or 307 or 308) || response.Location==null)return response;
            var next=new Uri(uri,response.Location);
            // The OAuth callback is terminal metadata, never a request destination.
            if(next.Scheme!="https" || next.Host!="login.microsoftonline.com" || !next.IsDefaultPort || next.UserInfo.Length!=0 || next.Fragment.Length!=0)return response;
            uri=next;
        }
        throw new InvalidOperationException();
    }
    private static JsonDocument Config(OAuthHttpResponse response)
    {
        var match=Regex.Match(response.Content,@"\$Config\s*=\s*(\{)",RegexOptions.CultureInvariant,TimeSpan.FromSeconds(1));
        if(!match.Success)throw new InvalidOperationException();
        byte[] bytes=Encoding.UTF8.GetBytes(response.Content.Substring(match.Groups[1].Index));
        try{var reader=new Utf8JsonReader(bytes,new JsonReaderOptions{MaxDepth=32});var result=JsonDocument.ParseValue(ref reader);try{Unique(result.RootElement);return result;}catch{result.Dispose();throw;}}
        finally{CryptographicOperations.ZeroMemory(bytes);}
    }
    private static Cookie? Cookie(CookieContainer jar)=>jar.GetCookies(new Uri("https://login.microsoftonline.com/" )).Cast<Cookie>().Where(c=>c.Name is "ESTSAUTH" or "ESTSAUTHPERSISTENT" && c.Secure && !c.Expired && c.Value.Length is >0 and <=65536).OrderByDescending(c=>c.Value.Length).FirstOrDefault();
    private static string Text(JsonElement root,string name)=>Optional(root,name) ?? throw new InvalidOperationException();
    private static string? Optional(JsonElement root,string name){if(!root.TryGetProperty(name,out var v))return null;if(v.ValueKind!=JsonValueKind.String || v.GetString()!.Length>65536)throw new InvalidOperationException();return v.GetString();}
    private static string Alias(JsonElement root,string name,string? other)=>OptionalAlias(root,name,other) ?? throw new InvalidOperationException();
    private static string? OptionalAlias(JsonElement root,string name,string? other){string? first=Optional(root,name),second=other==null?null:Optional(root,other);if(first!=null && second!=null && first!=second)throw new InvalidOperationException();return first ?? second;}
    private static string Normalize(string value,int limit){string clean=value.TrimEnd('=').Replace('+','-').Replace('/','_');if(!Regex.IsMatch(clean,@"\A[A-Za-z0-9_-]+\z") || clean.Length>limit*2)throw new InvalidOperationException();byte[] bytes=Convert.FromBase64String(clean.Replace('-','+').Replace('_','/').PadRight((clean.Length+3)/4*4,'='));try{if(bytes.Length is <1 || bytes.Length>limit || Encode(bytes)!=clean)throw new InvalidOperationException();return clean;}finally{CryptographicOperations.ZeroMemory(bytes);}}
    private static string Encode(byte[] bytes)=>Convert.ToBase64String(bytes).TrimEnd('=').Replace('+','-').Replace('/','_');
    private static void Unique(JsonElement value){if(value.ValueKind==JsonValueKind.Object){var names=new HashSet<string>(StringComparer.Ordinal);foreach(var p in value.EnumerateObject()){if(!names.Add(p.Name))throw new InvalidOperationException();Unique(p.Value);}}else if(value.ValueKind==JsonValueKind.Array)foreach(var item in value.EnumerateArray())Unique(item);}
    public void Dispose()=>key.Dispose();
}
public sealed class SoftwarePasskeySession : IDisposable
{
    public string CookieName {get;}
    [System.Text.Json.Serialization.JsonIgnore] public SecureString Cookie {get;}
    internal SoftwarePasskeySession(string name,string value){CookieName=name;Cookie=new SecureString();foreach(char c in value)Cookie.AppendChar(c);Cookie.MakeReadOnly();}
    public void Dispose()=>Cookie.Dispose();
}
