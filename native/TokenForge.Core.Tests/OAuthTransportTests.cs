using System.Net;
using System.Net.Http;
using System.Security;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using TokenForge.Core.V0180;

static class OAuthTransportTests
{
    static OAuthRequest Plan() => new() { ClientId="11111111-1111-1111-1111-111111111111",ResourceId="00000003-0000-0000-c000-000000000000",ResourceUri="https://graph.microsoft.com",RedirectUri="https://example.test/callback",Scopes=["User.Read"],OAuthScopes=["https://graph.microsoft.com/User.Read","offline_access"] };
    static SecureString Secret(string value="synthetic-secret") { var s=new SecureString();foreach(char c in value)s.AppendChar(c);s.MakeReadOnly();return s; }
    static string Jwt(string scopes="User.Read") => "e30."+Convert.ToBase64String(Encoding.UTF8.GetBytes(JsonSerializer.Serialize(new {tid="tenant",oid="principal",azp=Plan().ClientId,aud="https://graph.microsoft.com",scp=scopes,exp=DateTimeOffset.UtcNow.AddHours(1).ToUnixTimeSeconds()}))).TrimEnd('=').Replace('+','-').Replace('/','_')+".synthetic";
    static OAuthHttpResponse Token(string scopes="User.Read") => new(200,null,JsonSerializer.Serialize(new {access_token=Jwt(scopes),refresh_token="synthetic-refresh",token_type="Bearer",scope=scopes,expires_in=3600}));
    public static void Run(Action<bool> check, Action<Action> reject)
    {
        using var secret=Secret();string? challenge=null;int calls=0;
        Func<HttpClient,Uri,Dictionary<string,string>?,string?,OAuthHttpResponse> transport=(client,uri,form,origin)=>{
            calls++;check(uri.Host=="login.microsoftonline.com");
            if(form==null){var q=System.Web.HttpUtility.ParseQueryString(uri.Query);challenge=q["code_challenge"];check(q["prompt"]=="none" && q["response_type"]=="code");return new(302,"https://example.test/callback?code=synthetic-code&state="+q["state"],"");}
            check(form["grant_type"]=="authorization_code");check(challenge==Convert.ToBase64String(SHA256.HashData(Encoding.ASCII.GetBytes(form["code_verifier"]))).TrimEnd('=').Replace('+','-').Replace('/','_'));return Token();
        };
        using(var result=OAuthTransport.AcquireForAdapter(Plan(),"Cookie",secret,null,null,"ESTSAUTH",transport)){
            check(calls==2 && result.TokenClaims.Readable && result.TokenClaims.HasDelegatedScopeClaim && !result.TokenClaims.SignatureValidated);
            check(result.TokenClaims.Scopes.SequenceEqual(["User.Read"]) && result.RefreshToken!=null && result.AdditionalScopes.Length==0);
            string serialized=JsonSerializer.Serialize(result);check(!serialized.Contains("synthetic-refresh") && !serialized.Contains("AccessToken"));
        }
        using(var result=OAuthTransport.AcquireForAdapter(Plan(),"Refresh",secret,null,null,"ESTSAUTH",(c,u,f,o)=>{check(u.AbsolutePath.EndsWith("/token") && f!["grant_type"]=="refresh_token" && f["refresh_token"]=="synthetic-secret");return Token();}))check(result.ScopeEvidence=="TokenResponse");
        foreach(string protocol in new[]{"OAuth2V2Implicit","OAuth2V1Implicit"}){
            var plan=Plan();plan.Discovery=true;plan.ResourceUri=plan.ResourceId;plan.Scopes=[];plan.OAuthScopes=[plan.ResourceId+"/.default"];plan.Protocol=protocol;
            using(var result=OAuthTransport.AcquireForAdapter(plan,"Cookie",secret,null,null,"ESTSAUTH",(c,u,f,o)=>{
                check(f==null);var q=System.Web.HttpUtility.ParseQueryString(u.Query);check(q["code_challenge"]==null && q["response_mode"]=="fragment");
                check(protocol=="OAuth2V1Implicit" ? q["resource"]==plan.ResourceId && q["scope"]==null : q["scope"]==plan.ResourceId+"/.default");
                return new(302,"https://example.test/callback#access_token="+Jwt()+"&token_type=Bearer&expires_in=3600&state="+q["state"],"");
            }))check(result.Protocol==protocol && result.ScopeEvidence=="Unverified");
            reject(()=>OAuthTransport.Refresh(plan,secret));
        }
        foreach(string suffix in new[]{"?code=private-code&state=wrong","?code=private-code","?code=x&code=y&state={state}","?code=x&state={state}&state={state}","?code=x&state={state}#private-fragment"}){
            reject(()=>OAuthTransport.AcquireForAdapter(Plan(),"Cookie",secret,null,null,"ESTSAUTH",(c,u,f,o)=>new(302,"https://example.test/callback"+suffix.Replace("{state}",System.Web.HttpUtility.ParseQueryString(u.Query)["state"]),"")));
        }
        calls=0;reject(()=>OAuthTransport.AcquireForAdapter(Plan(),"Cookie",secret,null,null,"ESTSAUTH",(c,u,f,o)=>{calls++;return new(302,"https://login.microsoftonline.com.evil.test/private-code","");}));check(calls==1);
        calls=0;reject(()=>OAuthTransport.AcquireForAdapter(Plan(),"Cookie",secret,null,null,"ESTSAUTH",(c,u,f,o)=>{calls++;return new(302,"/loop","");}));check(calls==10);
        foreach(string body in new[]{"[]","{bad","{\"access_token\":\"private\",\"access_token\":\"other\",\"token_type\":\"Bearer\"}","{\"access_token\":\"private\",\"token_type\":\"Unknown\"}"})reject(()=>OAuthTransport.AcquireForAdapter(Plan(),"Refresh",secret,null,null,"ESTSAUTH",(c,u,f,o)=>new(200,null,body)));
        reject(()=>OAuthTransport.AcquireForAdapter(Plan(),"Refresh",secret,null,null,"ESTSAUTH",(c,u,f,o)=>Token("Mail.Read")));
        try{OAuthTransport.AcquireForAdapter(Plan(),"Refresh",secret,null,null,"ESTSAUTH",(c,u,f,o)=>new(429,null,"private-body AADSTS50076"));throw new Exception("Expected rejection");}catch(InvalidOperationException e){check(e.Message.Contains("HTTP 429") && e.Message.Contains("AADSTS50076") && !e.Message.Contains("private-body"));}
        foreach(int status in new[]{429,503}) {
            try { OAuthTransport.AcquireForAdapter(Plan(),"Cookie",secret,null,null,"ESTSAUTH",(c,u,f,o)=>new(status,null,"private-session")); throw new Exception("Expected rejection"); }
            catch(InvalidOperationException e) { check(e.Message.Contains("HTTP "+status) && !e.Message.Contains("private-session")); }
        }
        try { OAuthTransport.AcquireForAdapter(Plan(),"Cookie",secret,null,null,"ESTSAUTH",(c,u,f,o)=>throw new Exception("private-adapter-cookie")); throw new Exception("Expected rejection"); }
        catch(InvalidOperationException e) { check(!e.Message.Contains("private-adapter-cookie") && e.InnerException==null); }
        using(var dotted=Secret(new string('.',43)))using(var r=OAuthTransport.AcquireForAdapter(Plan(),"Code",secret,dotted,Plan().RedirectUri,"ESTSAUTH",(c,u,f,o)=>Token()))check(r.TokenType=="Bearer");
        var invalid=Plan();invalid.OAuthScopes=["https://evil.test/.default"];reject(()=>OAuthTransport.Refresh(invalid,secret));
        var spa=Plan();spa.Spa=true;using(var r=OAuthTransport.AcquireForAdapter(spa,"Refresh",secret,null,null,"ESTSAUTH",(c,u,f,o)=>{check(o=="https://example.test");return Token();}))check(r.TokenClaims.ClientId==spa.ClientId);
        using var verifier=Secret(new string('a',43));using(var r=OAuthTransport.AcquireForAdapter(Plan(),"Code",secret,verifier,Plan().RedirectUri,"ESTSAUTH",(c,u,f,o)=>{check(f!["code_verifier"]==new string('a',43));return Token();}))check(r.TokenType=="Bearer");
        reject(()=>OAuthTransport.AcquireForAdapter(Plan(),"Code",secret,verifier,"https://evil.test/callback","ESTSAUTH",(c,u,f,o)=>Token()));
        using(var client=new HttpClient(new FakeHandler((r,t)=>Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK){Content=new StringContent(new string('x',OAuthTransport.MaximumResponseBytes+1))}))))reject(()=>OAuthTransport.Send(client,new Uri("https://login.microsoftonline.com/token"),null,null));
        using(var client=new HttpClient(new FakeHandler((r,t)=>Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK){Content=new UnknownLengthContent()}))))reject(()=>OAuthTransport.Send(client,new Uri("https://login.microsoftonline.com/token"),null,null));
        using(var client=new HttpClient(new FakeHandler(async(r,t)=>{await Task.Delay(60000,t);return new HttpResponseMessage(HttpStatusCode.OK);})))using(var cancel=new CancellationTokenSource(20))reject(()=>OAuthTransport.Send(client,new Uri("https://login.microsoftonline.com/token"),null,null,cancel.Token));
        using(var client=new HttpClient(new FakeHandler((r,t)=>throw new Exception("private-url-and-cookie")))){
            try{OAuthTransport.Send(client,new Uri("https://login.microsoftonline.com/token"),null,null);throw new Exception("Expected failure");}catch(InvalidOperationException e){check(!e.Message.Contains("private-url") && e.InnerException==null);}
            reject(()=>OAuthTransport.Send(client,new Uri("http://login.microsoftonline.com/token"),null,null));
        }
        using var opaque=Secret("opaque");check(!TokenClaims.Read(opaque).Readable);
        using var jwt=Secret(Jwt());check(TokenClaims.Read(jwt).ExpiresAt>DateTimeOffset.UtcNow);
    }
    sealed class UnknownLengthContent : HttpContent
    {
        protected override bool TryComputeLength(out long length) { length=0; return false; }
        protected override async Task SerializeToStreamAsync(Stream stream, TransportContext? context) { await stream.WriteAsync(new byte[OAuthTransport.MaximumResponseBytes+1]); }
        protected override Task<Stream> CreateContentReadStreamAsync() => Task.FromResult<Stream>(new MemoryStream(new byte[OAuthTransport.MaximumResponseBytes+1]));
    }
    sealed class FakeHandler(Func<HttpRequestMessage,CancellationToken,Task<HttpResponseMessage>> respond):HttpMessageHandler
    {protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request,CancellationToken cancellationToken)=>respond(request,cancellationToken);}
}
