#nullable enable
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Threading;
using TokenForge.Core.V0180;
using TokenForge.Core.V0220;

namespace TokenForge.Core;

public sealed record SoftwarePasskeyEnrollmentResult(bool Registered,bool RecoveryFileSaved,string Authenticator="LabSoftwareNotHardware",bool CredentialsReturned=false);
public sealed class SoftwarePasskeyEnrollmentException : Exception
{
    public string Stage {get;}
    public bool RecoveryFileSaved {get;}
    internal SoftwarePasskeyEnrollmentException(string stage,bool saved):base("Software passkey enrollment failed during "+stage+". Details suppressed. "+(saved?"Preserve the recovery file and check Security info before retrying.":"No recovery key was published.")){Stage=stage;RecoveryFileSaved=saved;}
}

// Explicit, same-account lab enrollment. No browser automation, remote targeting,
// policy changes, automatic retry, or claim that software attestation proves hardware.
public static class SoftwarePasskeyEnrollment
{
    private const string SelfClient="19db86c3-b2b9-44cc-b339-36da233a3be2", Graph="00000003-0000-0000-c000-000000000000", Bootstrap="14d82eec-204b-4c2f-b7e8-296a70dab67e";
    public static SoftwarePasskeyEnrollmentResult Enroll(string sourcePath,string identityJson,string outputPath,string displayName="Test",CancellationToken cancellation=default)
    {
        string stage="Inputs";bool saved=false;
        using var deadline=CancellationTokenSource.CreateLinkedTokenSource(cancellation);deadline.CancelAfter(TimeSpan.FromMinutes(5));
        try
        {
            if(displayName.Length is <1 or >64 || displayName.Any(char.IsControl) || identityJson.Length>64*1024*1024)throw new InvalidOperationException();
            string output=PrivateFiles.Resolve(outputPath,true);
            if(File.Exists(output) || File.Exists(output+".registered.json") || Path.GetFullPath(sourcePath)==output)throw new InvalidOperationException();
            using var operation=EnrollmentLock(output);
            if(File.Exists(output))throw new InvalidOperationException();
            using var identity=Json(identityJson);string tenantFingerprint=Fingerprint(identity.RootElement,"TenantFingerprint"),principalFingerprint=Fingerprint(identity.RootElement,"PrincipalFingerprint");
            using var signer=SoftwarePasskey.Open(sourcePath);
            stage="Authentication";using var session=signer.Authenticate(deadline.Token);
            stage="IdentityConfirmation";
            using var graph=OAuthTransport.Cookie(new OAuthRequest{ClientId=Bootstrap,ResourceId=Graph,ResourceUri=Graph,RedirectUri="https://login.microsoftonline.com/common/oauth2/nativeclient",Scopes=new[]{"User.Read"},OAuthScopes=new[]{Graph+"/User.Read"}},session.Cookie,session.CookieName,deadline.Token);
            var claims=graph.TokenClaims;
            if(claims.TenantFingerprint!=tenantFingerprint || claims.PrincipalFingerprint!=principalFingerprint || claims.ClientId!=Bootstrap || claims.Audience is not (Graph or "https://graph.microsoft.com" or "https://graph.microsoft.com/") || !claims.MatchesPrincipalIdentity(Guid.Parse(ProfileTokenApi.ReadIdentity(graph.AccessToken,deadline.Token))))throw new InvalidOperationException();
            string tenant=claims.TenantIdentity() ?? throw new InvalidOperationException();
            stage="SelfToken";
            using var self=OAuthTransport.Cookie(new OAuthRequest{ClientId=SelfClient,ResourceId=SelfClient,ResourceUri=SelfClient,RedirectUri="https://mysignins.microsoft.com",Discovery=true,Spa=true,OAuthScopes=new[]{SelfClient+"/.default","offline_access"}},session.Cookie,session.CookieName,deadline.Token);
            ValidateSelf(self,tenantFingerprint,principalFingerprint);
            using var handler=new HttpClientHandler{AllowAutoRedirect=false,CookieContainer=new CookieContainer(),MaxResponseHeadersLength=32};
            handler.CookieContainer.Add(new Cookie(session.CookieName,new NetworkCredential("",session.Cookie).Password,"/","login.microsoftonline.com"){Secure=true,HttpOnly=true});
            using var http=new HttpClient(handler){Timeout=Timeout.InfiniteTimeSpan};
            return Complete(http,signer.Username,self,tenant,tenantFingerprint,principalFingerprint,output,displayName,deadline.Token,ref stage,ref saved);
        }
        catch{throw new SoftwarePasskeyEnrollmentException(stage,saved);}
    }
    private static FileStream EnrollmentLock(string output)
    {string path=PrivateFiles.Resolve(output+".enrollment.lock",false);try{return PrivateFiles.Open(path,true);}catch(IOException){return PrivateFiles.Open(path,false);}}
    private static SoftwarePasskeyEnrollmentResult Complete(HttpClient http,string username,OAuthResult original,string tenant,string expectedTenant,string expectedPrincipal,string output,string name,CancellationToken cancellation,ref string stage,ref bool saved)
    {
        string clientSession=Guid.NewGuid().ToString();OAuthResult? renewed=null;
        try
        {
            OAuthResult current=original;
            stage="SessionAuthorization";
            using var initial=Authorize(http,current,clientSession,null,cancellation);var session=initial.RootElement;
            string context=AuthorizedContext(session);
            if(session.TryGetProperty("requireNgcMfaForSecurityInfo",out var require) && require.ValueKind==JsonValueKind.True)
            {
                stage="MfaClaimsRefresh";
                if(current.RefreshToken==null)throw new InvalidOperationException();
                using var request=new HttpRequestMessage(HttpMethod.Post,new Uri("https://login.microsoftonline.com/"+tenant+"/oauth2/v2.0/token"));
                request.Headers.Add("Origin","https://mysignins.microsoft.com");
                request.Content=new FormUrlEncodedContent(new Dictionary<string,string>{["client_id"]=SelfClient,["scope"]=SelfClient+"/.default openid",["grant_type"]="refresh_token",["refresh_token"]=new NetworkCredential("",current.RefreshToken).Password,["claims"]="{\"id_token\":{\"amr\":{\"essential\":true,\"values\":[\"ngcmfa\"]}},\"access_token\":{\"amr\":{\"essential\":true,\"values\":[\"ngcmfa\"]}}}"});
                renewed=ParseSelf(Send(http,request,"IdentityToken",tenant,cancellation));
                ValidateSelf(renewed,expectedTenant,expectedPrincipal);current=renewed;
                using var updated=Authorize(http,current,clientSession,null,cancellation);
                context=AuthorizedContext(updated.RootElement);
                if(updated.RootElement.TryGetProperty("requireNgcMfaForSecurityInfo",out var still) && still.ValueKind==JsonValueKind.True)throw new InvalidOperationException();
            }
            ValidateSelf(current,expectedTenant,expectedPrincipal);
            stage="Challenge";
            using var begin=ApiRequest("authenticationmethods/new",current,context,clientSession,"{\"Type\":18}");
            using var outer=Json(Send(http,begin,"New",tenant,cancellation));NoError(outer.RootElement);
            using var details=Json(Text(outer.RootElement,"Data"));var data=details.RootElement;var challenge=data.GetProperty("requestData");
            string canary=Text(challenge,"canary"),serverChallenge=Text(challenge,"serverChallenge"),handle=Text(challenge,"userId");
            if(serverChallenge.Length>16384 || serverChallenge.Any(c=>c<33 || c>126))throw new InvalidOperationException();
            handle=Base64(handle,64);
            string serverHandle=Text(challenge,"userId");
            string correlation=Guid.NewGuid().ToString();
            var provision=Target(Text(data,"provisionUrl"),"Provision",tenant);
            var postback=Target(Text(challenge,"postBackUrl"),"Postback",tenant);
            provision=WithQuery(provision,correlation);postback=WithQuery(postback,correlation);
            using var material=new Material(serverChallenge,username,handle);
            stage="RecoveryPublication";
            material.Save(output,ref saved);
            // From this point, preserve the recovery key regardless of remote outcome.
            stage="Provisioning";cancellation.ThrowIfCancellationRequested();
            var fields=new Dictionary<string,string>{["correlationId"]=correlation,["canary"]=canary,["ExcludeNextGenCredentialsJSON"]=Optional(challenge,"ExcludeNextGenCredentialsJSON") ?? "[]",["memberName"]=username,["postBackUrl"]=postback.AbsoluteUri,["serverChallenge"]=serverChallenge,["userDisplayName"]=name,["userIconUrl"]="",["userId"]=serverHandle};
            using(var provisionRequest=new HttpRequestMessage(HttpMethod.Post,provision)){provisionRequest.Content=new FormUrlEncodedContent(fields);Send(http,provisionRequest,"Provision",tenant,cancellation);}fields.Clear();
            stage="AttestationSubmission";cancellation.ThrowIfCancellationRequested();
            string postInfo="";
            using(var post=new HttpRequestMessage(HttpMethod.Post,postback))
            {
                post.Headers.Add("Origin","https://login.microsoft.com");post.Headers.Referrer=new Uri("https://login.microsoft.com/");
                post.Content=new FormUrlEncodedContent(new Dictionary<string,string>{["canary"]=canary,["authenticator"]="cross-platform",["transports"]="usb",["aaguid"]=Guid.Empty.ToString(),["credentialDeviceType"]="singleDevice",["credentialBackedUp"]="false",["attestationParseError"]="",["error_code"]="",["suberror_code"]="",["clientDataJson"]=material.ClientData,["attestationObject"]=material.Attestation,["credentialId"]=material.Id,["clientExtensionResults"]=material.Extensions,["i19"]=""});
                string html=Send(http,post,"Postback",tenant,cancellation);
                stage="FinalizationContext";
                var finalized=Finalization(html,material.Id,material.ClientData,material.Attestation);
                canary=finalized.Canary;postInfo=finalized.PostInfo;
            }
            stage="MethodsContext";
            using(var methods=ApiRequest("authenticationmethods/availablemethods",current,context,clientSession,"",get:true))Send(http,methods,"Methods",tenant,cancellation);
            stage="SessionReauthorization";
            using var reauthorized=Authorize(http,current,clientSession,context,cancellation);context=AuthorizedContext(reauthorized.RootElement);
            ValidateSelf(current,expectedTenant,expectedPrincipal);
            stage="VerificationTransport";cancellation.ThrowIfCancellationRequested();
            string verification=JsonSerializer.Serialize(new{Name=name,Canary=canary,AttestationObject=material.Attestation,ClientDataJson=material.ClientData,CredentialId=material.Id,ClientExtensionResults=material.Extensions,PostInfo=postInfo,AAGuid=Guid.Empty.ToString(),CredentialDeviceType="singleDevice"});
            using var verify=ApiRequest("authenticationmethods/verify",null,context,clientSession,JsonSerializer.Serialize(new{Type=18,VerificationData=verification}));
            VerifyResponse(Send(http,verify,"Verify",tenant,cancellation),material.Id,name,ref stage);
            stage="RecoveryConfirmation";material.Confirm(output);
            return new SoftwarePasskeyEnrollmentResult(true,true);
        }
        finally{renewed?.Dispose();}
    }
    // Fixed local stages distinguish failures without projecting remote content.
    private static void VerifyResponse(string body,string credential,string name,ref string stage)
    {
        stage="VerificationResponse";using var result=Json(body);
        stage="VerificationServiceStatus";NoError(result.RootElement);
        stage="VerificationState";
        if(!result.RootElement.TryGetProperty("VerificationState",out var state) || state.GetInt32()!=2)throw new InvalidOperationException();
        stage="VerifiedCredentialMatch";
        // A terminal response must identify the exact new credential; success alone is insufficient.
        var devices=result.RootElement.GetProperty("DataUpdates").GetProperty("FidoDevices");
        if(!VerifiedDevice(devices,credential,name))throw new InvalidOperationException();
    }
    private sealed record FinalizationData(string Canary,string PostInfo);
    private static FinalizationData Finalization(string html,string credential,string clientData,string attestation)
    {
        var values=new Dictionary<string,string>(StringComparer.Ordinal);
        foreach(Match tag in Regex.Matches(html,@"<div\b[^>]{0,131072}>",RegexOptions.IgnoreCase|RegexOptions.CultureInvariant,TimeSpan.FromSeconds(1)))
        {
            var attributes=new Dictionary<string,string>(StringComparer.OrdinalIgnoreCase);
            foreach(Match attribute in Regex.Matches(tag.Value,@"\s(id|data-content)\s*=\s*([""'])(.*?)\2",RegexOptions.Singleline|RegexOptions.IgnoreCase|RegexOptions.CultureInvariant,TimeSpan.FromSeconds(1)))
                if(!attributes.TryAdd(attribute.Groups[1].Value,WebUtility.HtmlDecode(attribute.Groups[3].Value)))throw new InvalidOperationException();
            if(attributes.TryGetValue("id",out var id) && id is "context" or "redirectUrl")
            {if(!attributes.TryGetValue("data-content",out var value) || value.Length>65536 || !values.TryAdd(id,value))throw new InvalidOperationException();}
        }
        if(!values.ContainsKey("context") || !values.ContainsKey("redirectUrl"))throw new InvalidOperationException();
        using var context=Json(values["context"]);var root=context.RootElement;
        string canary=Optional(root,"Canary",true) ?? "",postInfo=Optional(root,"PostInfo",true) ?? "";
        foreach(var field in new[]{("CredentialId",credential),("ClientDataJson",clientData),("AttestationObject",attestation)})
            if(root.TryGetProperty(field.Item1,out _) && !MatchesWireValue(Text(root,field.Item1),field.Item2))throw new InvalidOperationException();
        string redirectText=values["redirectUrl"];
        if(!Uri.TryCreate(redirectText,UriKind.Absolute,out var redirect) || redirect.Scheme!="https" || !redirect.IsDefaultPort || redirect.UserInfo.Length!=0 || redirect.Host!="mysignins.microsoft.com" || redirect.AbsolutePath!="/security-info")throw new InvalidOperationException();
        var query=System.Web.HttpUtility.ParseQueryString(redirect.Query);
        foreach(string? name in query.AllKeys)
            if(name is not ("cid" or "mysignins-region") || query.GetValues(name)?.Length!=1 || (name=="cid"?!Guid.TryParseExact(query[name],"D",out _):!Regex.IsMatch(query[name]!,@"\A[a-z0-9]{1,32}\z")))throw new InvalidOperationException();
        var fragments=new Dictionary<string,string>(StringComparer.Ordinal);
        int fragmentStart=redirectText.IndexOf('#');if(fragmentStart<0)throw new InvalidOperationException();
        foreach(string part in redirectText.Substring(fragmentStart+1).Split('&',StringSplitOptions.RemoveEmptyEntries))
        {
            string[] pair=part.Split('=',2);
            if(pair.Length!=2)throw new InvalidOperationException();
            string name=DecodeFragment(pair[0]),value=DecodeFragment(pair[1]);
            if(name is not ("fidoProvisionSuccess" or "postinfo") || value.Length is <1 or >65536 || value.Any(char.IsControl) || !fragments.TryAdd(name,value))throw new InvalidOperationException();
        }
        // Validated callback values are the final server state, as in the SPA.
        // The fragment is protocol data only: never navigate it or forward it.
        if(!fragments.TryGetValue("fidoProvisionSuccess",out var refreshed))throw new InvalidOperationException();
        canary=refreshed;if(fragments.TryGetValue("postinfo",out var info))postInfo=info;
        return new FinalizationData(canary,postInfo);
    }
    private static string DecodeFragment(string value)
    {
        var utf8=new UTF8Encoding(false,true);byte[] output=new byte[utf8.GetMaxByteCount(value.Length)];int used=0;
        try
        {
            for(int i=0;i<value.Length;)
            {
                if(value[i]=='%')
                {
                    if(i+2>=value.Length || !byte.TryParse(value.AsSpan(i+1,2),System.Globalization.NumberStyles.AllowHexSpecifier,System.Globalization.CultureInfo.InvariantCulture,out byte encoded))throw new InvalidOperationException();
                    output[used++]=encoded;i+=3;
                }
                else
                {
                    int end=value.IndexOf('%',i);if(end<0)end=value.Length;
                    used+=utf8.GetBytes(value.AsSpan(i,end-i),output.AsSpan(used));i=end;
                }
            }
            return utf8.GetString(output,0,used);
        }
        finally{CryptographicOperations.ZeroMemory(output);}
    }
    private static bool VerifiedDevice(JsonElement devices,string credential,string name)
    {
        if(devices.ValueKind==JsonValueKind.Array && devices.GetArrayLength()>256)throw new InvalidOperationException();
        var rows=devices.ValueKind==JsonValueKind.Array?devices.EnumerateArray().ToArray():new[]{devices};
        int matched=0;bool named=false;
        foreach(var row in rows)
        {
            string? id=Optional(row,"CredentialId");if(id==null || !MatchesWireValue(id,credential))continue;
            matched++;named=Text(row,"DisplayName")==name;
        }
        return matched==1 && named;
    }
    private static bool MatchesWireValue(string value,string expected)
    {
        // My Sign-ins DTOs may use ASP.NET URL-token encoding: unpadded
        // Base64URL followed by the number of removed padding characters.
        int padding=(4-expected.Length%4)%4;
        return value==expected || value==expected+padding.ToString(System.Globalization.CultureInfo.InvariantCulture);
    }
    private static JsonDocument Authorize(HttpClient http,OAuthResult token,string clientSession,string? context,CancellationToken cancellation)
    {using var request=ApiRequest("session/authorize",token,context,clientSession,"{}");return Json(Send(http,request,"Session","",cancellation));}
    private static string AuthorizedContext(JsonElement value)
    {if(!value.TryGetProperty("isAuthorized",out var allowed) || allowed.ValueKind!=JsonValueKind.True)throw new InvalidOperationException();return Text(value,"sessionCtxV2");}
    private static HttpRequestMessage ApiRequest(string path,OAuthResult? token,string? context,string clientSession,string body,bool get=false)
    {
        var request=new HttpRequestMessage(get?HttpMethod.Get:HttpMethod.Post,"https://mysignins.microsoft.com/api/"+path);
        if(token!=null)request.Headers.Authorization=new AuthenticationHeaderValue("Bearer",new NetworkCredential("",token.AccessToken).Password);
        if(context!=null)request.Headers.Add("SessionCtxV2",context);
        request.Headers.Add("Origin","https://mysignins.microsoft.com");request.Headers.Referrer=new Uri("https://mysignins.microsoft.com/security-info");request.Headers.Add("AjaxRequest","true");request.Headers.Add("x-ms-mysignins-region","westus2");request.Headers.Add("x-ms-client-session-id",clientSession);
        if(!get)request.Content=new StringContent(body,Encoding.UTF8,"application/json");return request;
    }
    private static Uri Target(string value,string role,string tenant)
    {
        if(!Uri.TryCreate(value,UriKind.Absolute,out var uri) || uri.Scheme!="https" || !uri.IsDefaultPort || uri.UserInfo.Length!=0 || uri.Fragment.Length!=0 || value.Length>4096)throw new InvalidOperationException();
        bool valid=role switch{
            "IdentityToken"=>uri.Host=="login.microsoftonline.com" && uri.AbsolutePath=="/"+tenant+"/oauth2/v2.0/token",
            "Provision"=>uri.Host=="login.microsoft.com" && uri.AbsolutePath=="/"+tenant+"/fido/create",
            "Postback"=>uri.Host=="mysignins.microsoft.com" && uri.AbsolutePath=="/api/post/newfido",
            "Session"=>uri.Host=="mysignins.microsoft.com" && uri.AbsolutePath=="/api/session/authorize",
            "New"=>uri.Host=="mysignins.microsoft.com" && uri.AbsolutePath=="/api/authenticationmethods/new",
            "Methods"=>uri.Host=="mysignins.microsoft.com" && uri.AbsolutePath=="/api/authenticationmethods/availablemethods",
            "Verify"=>uri.Host=="mysignins.microsoft.com" && uri.AbsolutePath=="/api/authenticationmethods/verify",_=>false};
        if(!valid)throw new InvalidOperationException();
        var query=System.Web.HttpUtility.ParseQueryString(uri.Query);
        foreach(string? key in query.AllKeys)
        {
            if(role is not ("Provision" or "Postback") || key is not ("cid" or "mysignins-region") || query.GetValues(key)?.Length!=1)throw new InvalidOperationException();
            string v=query[key]!;if(key=="cid" ? !Guid.TryParseExact(v,"D",out _) : !Regex.IsMatch(v,@"\A[a-z0-9]{1,32}\z"))throw new InvalidOperationException();
        }
        return uri;
    }
    private static Uri WithQuery(Uri uri,string correlation)
    {var b=new UriBuilder(uri);var q=System.Web.HttpUtility.ParseQueryString(uri.Query);q["cid"]=correlation;if(uri.Host=="mysignins.microsoft.com" && q["mysignins-region"]==null)q["mysignins-region"]="westus2";b.Query=q.ToString();return b.Uri;}
    private static string Send(HttpClient http,HttpRequestMessage request,string role,string tenant,CancellationToken cancellation)
    {
        Target(request.RequestUri!.AbsoluteUri,role,tenant);
        if(role is "Provision" or "Postback" or "IdentityToken" && (request.Headers.Authorization!=null || request.Headers.Contains("SessionCtxV2")))throw new InvalidOperationException();
        if(role=="Verify" && request.Headers.Authorization!=null)throw new InvalidOperationException();
        using var deadline=CancellationTokenSource.CreateLinkedTokenSource(cancellation);deadline.CancelAfter(TimeSpan.FromSeconds(30));deadline.Token.ThrowIfCancellationRequested();
        using var response=http.SendAsync(request,HttpCompletionOption.ResponseHeadersRead,deadline.Token).GetAwaiter().GetResult();
        // Redirects are never followed, including a redirect between two allowed hosts.
        if(response.StatusCode!=HttpStatusCode.OK || response.Headers.Location!=null || response.Content.Headers.ContentLength>1048576)throw new InvalidOperationException();
        using var stream=response.Content.ReadAsStreamAsync(deadline.Token).GetAwaiter().GetResult();byte[] bytes=new byte[1048577];
        try{int used=0,count;while((count=stream.ReadAsync(bytes.AsMemory(used),deadline.Token).AsTask().GetAwaiter().GetResult())!=0){used+=count;if(used>1048576)throw new InvalidOperationException();}return Encoding.UTF8.GetString(bytes,0,used);}
        finally{CryptographicOperations.ZeroMemory(bytes);}
    }
    private static OAuthResult ParseSelf(string body)
    {
        using var json=Json(body);var root=json.RootElement;if(Text(root,"token_type")!="Bearer")throw new InvalidOperationException();
        var result=new OAuthResult{ClientId=SelfClient,ResourceId=SelfClient};
        try{result.AccessToken.Dispose();result.AccessToken=Secure(Text(root,"access_token"));result.TokenClaims=TokenClaims.Read(result.AccessToken);string? refresh=Optional(root,"refresh_token");if(refresh!=null)result.RefreshToken=Secure(refresh);return result;}catch{result.Dispose();throw;}
    }
    private static void ValidateSelf(OAuthResult token,string tenant,string principal)
    {var claims=token.TokenClaims;if(!claims.Readable || claims.TenantFingerprint!=tenant || claims.PrincipalFingerprint!=principal || claims.ClientId!=SelfClient || claims.Audience!=SelfClient || claims.ExpiresAt==null || claims.ExpiresAt<DateTimeOffset.UtcNow.AddMinutes(1))throw new InvalidOperationException();}
    private static SecureString Secure(string value){var secret=new SecureString();foreach(char c in value)secret.AppendChar(c);secret.MakeReadOnly();return secret;}
    private static string Fingerprint(JsonElement root,string name){string value=Text(root,name);if(!Regex.IsMatch(value,@"\A[a-f0-9]{64}\z"))throw new InvalidOperationException();return value;}
    private static string Text(JsonElement root,string name)=>Optional(root,name) ?? throw new InvalidOperationException();
    private static string? Optional(JsonElement root,string name,bool allowEmpty=false){if(!root.TryGetProperty(name,out var value))return null;if(value.ValueKind!=JsonValueKind.String || (value.GetString()!.Length>65536 || !allowEmpty && value.GetString()!.Length==0))throw new InvalidOperationException();return value.GetString();}
    private static JsonDocument Json(string text){var result=JsonDocument.Parse(text,new JsonDocumentOptions{MaxDepth=32});try{Unique(result.RootElement);return result;}catch{result.Dispose();throw;}}
    private static void Unique(JsonElement root){if(root.ValueKind==JsonValueKind.Object){var seen=new HashSet<string>(StringComparer.Ordinal);foreach(var field in root.EnumerateObject()){if(!seen.Add(field.Name))throw new InvalidOperationException();Unique(field.Value);}}else if(root.ValueKind==JsonValueKind.Array)foreach(var value in root.EnumerateArray())Unique(value);}
    private static void NoError(JsonElement value){if(value.TryGetProperty("ErrorCode",out var error) && error.GetInt32()!=0)throw new InvalidOperationException();}
    private static string Encode(byte[] bytes)=>Convert.ToBase64String(bytes).TrimEnd('=').Replace('+','-').Replace('/','_');
    private static string Base64(string text,int limit){string value=text.TrimEnd('=').Replace('+','-').Replace('/','_');byte[] bytes=Convert.FromBase64String(value.Replace('-','+').Replace('_','/').PadRight((value.Length+3)/4*4,'='));try{if(bytes.Length is <1 || bytes.Length>limit || Encode(bytes)!=value)throw new InvalidOperationException();return value;}finally{CryptographicOperations.ZeroMemory(bytes);}}

    private sealed class Material : IDisposable
    {
        private readonly ECDsa key=ECDsa.Create(ECCurve.NamedCurves.nistP256);
        private readonly string username,handle;
        private byte[]? savedBytes;
        internal string Id {get;} internal string ClientData {get;} internal string Attestation {get;} internal string Extensions {get;}="eyJobWFjQ3JlYXRlU2VjcmV0IjpmYWxzZX0";
        internal Material(string challenge,string username,string handle)
        {
            this.username=username;this.handle=handle;
            try
            {
            byte[] id=RandomNumberGenerator.GetBytes(32);Id=Encode(id);
            var point=key.ExportParameters(false);
            byte[] cose=Cbor(new Dictionary<object,object>{{1,2},{3,-7},{-1,1},{-2,point.Q.X!},{-3,point.Q.Y!}});
            byte[] auth=SHA256.HashData(Encoding.ASCII.GetBytes("login.microsoft.com")).Concat(new byte[]{0x45,0,0,0,0}).Concat(new byte[16]).Concat(new byte[]{0,32}).Concat(id).Concat(cose).ToArray();
            byte[] client=JsonSerializer.SerializeToUtf8Bytes(new{type="webauthn.create",challenge=Encode(Encoding.ASCII.GetBytes(challenge)),origin="https://login.microsoft.com",crossOrigin=false});ClientData=Encode(client);
            using var batch=ECDsa.Create(ECCurve.NamedCurves.nistP256);
            var subject=new X500DistinguishedNameBuilder();subject.AddCountryOrRegion("US");subject.AddOrganizationName("TokenForge");subject.AddOrganizationalUnitName("Authenticator Attestation");subject.AddCommonName("TokenForge Lab Software");
            var certificate=new CertificateRequest(subject.Build(),batch,HashAlgorithmName.SHA256);
            certificate.CertificateExtensions.Add(new X509BasicConstraintsExtension(false,false,0,true));
            using var cert=certificate.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1),DateTimeOffset.UtcNow.AddYears(1));
            byte[] signed=auth.Concat(SHA256.HashData(client)).ToArray();byte[] signature=batch.SignData(signed,HashAlgorithmName.SHA256,DSASignatureFormat.Rfc3279DerSequence);
            try{Attestation=Encode(Cbor(new Dictionary<object,object>{{"fmt","packed"},{"attStmt",new Dictionary<object,object>{{"alg",-7},{"sig",signature},{"x5c",new object[]{cert.RawData}}}},{"authData",auth}}));}
            finally{foreach(byte[] bytes in new[]{id,cose,auth,client,signed,signature})CryptographicOperations.ZeroMemory(bytes);}
            }catch{key.Dispose();throw;}
        }
        internal void Save(string path,ref bool published)
        {
            byte[] der=key.ExportPkcs8PrivateKey();
            try{savedBytes=JsonSerializer.SerializeToUtf8Bytes(new{username,credentialId=Id,privateKey=Convert.ToBase64String(der),userHandle=handle,counter=0,relyingParty="login.microsoft.com",url="https://login.microsoft.com",enrollmentStatus="PendingRemoteVerification",authenticator="LabSoftwareNotHardware"});Publish(path,savedBytes,ref published);}
            finally{CryptographicOperations.ZeroMemory(der);}
        }
        internal void Confirm(string path)
        {
            using var file=PrivateFiles.Open(PrivateFiles.Resolve(path,false),false);
            if(file.Length>65536 || savedBytes==null)throw new InvalidOperationException();
            byte[] bytes=new byte[checked((int)file.Length)];
            try
            {
                file.ReadExactly(bytes);if(!bytes.AsSpan().SequenceEqual(savedBytes))throw new InvalidOperationException();
                // Key material stays immutable. A separate no-overwrite receipt binds
                // server confirmation to these exact recovery bytes and credential ID.
                byte[] receipt=JsonSerializer.SerializeToUtf8Bytes(new{SchemaVersion=1,Registered=true,CredentialFileSha256=Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant(),CredentialId=Id});
                bool published=false;
                try{Publish(PrivateFiles.Resolve(path+".registered.json",false),receipt,ref published);}finally{CryptographicOperations.ZeroMemory(receipt);}
            }
            finally{CryptographicOperations.ZeroMemory(bytes);}
        }
        private static void Publish(string path,byte[] bytes,ref bool published,Action<string>? cleanup=null)
        {
            string temporary=PrivateFiles.Resolve(path+"."+Guid.NewGuid().ToString("N")+".tmp",false);
            try
            {
                using(var stream=PrivateFiles.Open(temporary,true)){stream.Write(bytes);stream.Flush(true);}
                PrivateFiles.Resolve(path,false);PrivateFiles.PublishNew(temporary,path);
                published=true; // A subsequent cleanup failure must still report the recovery file.
            }
            finally{if(cleanup!=null)cleanup(temporary);else if(File.Exists(temporary))File.Delete(temporary);}
        }
        public void Dispose(){key.Dispose();if(savedBytes!=null)CryptographicOperations.ZeroMemory(savedBytes);}
    }
    // Small bounded CBOR encoder for the exact ES256 packed-attestation structures above.
    private static byte[] Cbor(object value)
    {
        using var output=new MemoryStream();
        void Head(int major,int count){if(count<24)output.WriteByte((byte)(major*32+count));else if(count<=255){output.WriteByte((byte)(major*32+24));output.WriteByte((byte)count);}else if(count<=65535){output.WriteByte((byte)(major*32+25));output.WriteByte((byte)(count>>8));output.WriteByte((byte)count);}else throw new InvalidOperationException();}
        void Write(object item)
        {
            switch(item)
            {
                case int number:Head(number<0?1:0,number<0?-1-number:number);break;
                case byte[] bytes:Head(2,bytes.Length);output.Write(bytes);break;
                case string text:byte[] encoded=Encoding.UTF8.GetBytes(text);Head(3,encoded.Length);output.Write(encoded);break;
                case object[] array:Head(4,array.Length);foreach(var entry in array)Write(entry);break;
                case Dictionary<object,object> map:Head(5,map.Count);foreach(var entry in map){Write(entry.Key);Write(entry.Value);}break;
                default:throw new InvalidOperationException();
            }
        }
        Write(value);return output.ToArray();
    }
}
