using System.Net;
using System.Net.Http;
using System.Reflection;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using TokenForge.Core;
using TokenForge.Core.V0180;
using TokenForge.Core.V0220;

static class PasskeyEnrollmentChecks
{
    const string Tenant="11111111-1111-1111-1111-111111111111",Principal="22222222-2222-2222-2222-222222222222",Self="19db86c3-b2b9-44cc-b339-36da233a3be2";
    static object Call(string method,params object[] args)=>typeof(SoftwarePasskeyEnrollment).GetMethod(method,BindingFlags.NonPublic|BindingFlags.Static)!.Invoke(null,args)!;
    static string Encode(byte[] bytes)=>Convert.ToBase64String(bytes).TrimEnd('=').Replace('+','-').Replace('/','_');
    static string Hash(string text)=>Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(text))).ToLowerInvariant();
    static string Token(string principal=Principal)=>"eyJhbGciOiJub25lIn0."+Encode(JsonSerializer.SerializeToUtf8Bytes(new{tid=Tenant,oid=principal,appid=Self,aud=Self,exp=DateTimeOffset.UtcNow.AddHours(1).ToUnixTimeSeconds()}))+".c3ludGhldGlj";
    static OAuthResult SelfToken(string principal=Principal)=>(OAuthResult)Call("ParseSelf",JsonSerializer.Serialize(new{access_token=Token(principal),refresh_token="synthetic-refresh",token_type="Bearer"}));
    public static void Run(Action<bool> check,Action<Action> reject)
    {
        string root=Path.Combine(Path.GetTempPath(),"TokenForge-enrollment-check-"+Guid.NewGuid().ToString("N"));if(OperatingSystem.IsMacOS() && root.StartsWith("/var/"))root="/private"+root;
        PrivateFiles.Resolve(Path.Combine(root,".owned"),true);
        try
        {
            foreach(string url in new[]{"http://mysignins.microsoft.com/api/post/newfido","https://mysignins.microsoft.com:444/api/post/newfido","https://evil.test/api/post/newfido","https://mysignins.microsoft.com/api/other","https://mysignins.microsoft.com/api/post/newfido#secret","https://mysignins.microsoft.com/api/post/newfido?next=evil","https://mysignins.microsoft.com/api/post/newfido?cid=11111111-1111-1111-1111-111111111111&cid=22222222-2222-2222-2222-222222222222","https://mysignins.microsoft.com/api/post/newfido?mysignins-region=secret%0d%0a"})reject(()=>Call("Target",url,"Postback",Tenant));
            reject(()=>Call("Target","https://login.microsoft.com/22222222-2222-2222-2222-222222222222/fido/create","Provision",Tenant));
            check(((Uri)Call("Target","https://login.microsoft.com/"+Tenant+"/fido/create","Provision",Tenant)).Host=="login.microsoft.com");
            using(var good=SelfToken())Call("ValidateSelf",good,Hash(Tenant),Hash(Tenant+"/"+Principal));
            using(var wrong=SelfToken("33333333-3333-3333-3333-333333333333"))reject(()=>Call("ValidateSelf",wrong,Hash(Tenant),Hash(Tenant+"/"+Principal)));
            reject(()=>Call("Json","{\"nested\":{\"private\":1,\"private\":2}}"));
            string FinalPage(string context,string redirect)=>"<div id=\"context\" data-content=\""+WebUtility.HtmlEncode(context)+"\"></div><div id=\"redirectUrl\" data-content=\""+WebUtility.HtmlEncode(redirect)+"\"></div>";
            string ctx="{\"Canary\":\"context\",\"PostInfo\":\"context-info\"}";
            string finalizationUrl="https://mysignins.microsoft.com/security-info#fidoProvisionSuccess=final&postinfo=final-info";
            using(var device=JsonDocument.Parse("[{\"CredentialId\":\"Ag2\",\"DisplayName\":\"Other\"},{\"CredentialId\":\"AQ2\",\"DisplayName\":\"Test\"}]"))check((bool)Call("VerifiedDevice",device.RootElement,"AQ","Test"));
            using(var device=JsonDocument.Parse("[{\"CredentialId\":\"AQ2\",\"DisplayName\":\"Test\"},{\"CredentialId\":\"AQ\",\"DisplayName\":\"Test\"}]"))check(!(bool)Call("VerifiedDevice",device.RootElement,"AQ","Test"));
            using(var device=JsonDocument.Parse("{\"CredentialId\":\"AQ2\",\"DisplayName\":\"Other\"}"))check(!(bool)Call("VerifiedDevice",device.RootElement,"AQ","Test"));
            check((bool)Call("MatchesWireValue","AQ2","AQ"));check(!(bool)Call("MatchesWireValue","AQ0","AQ"));
            object finalized=Call("Finalization",FinalPage("{\"Canary\":\"context\",\"CredentialId\":\"AQ2\",\"ClientDataJson\":\"Aw2\",\"AttestationObject\":\"Ag2\"}",finalizationUrl),"AQ","Aw","Ag");
            check(finalized.GetType().GetProperty("Canary")!.GetValue(finalized)!.ToString()=="final" && finalized.GetType().GetProperty("PostInfo")!.GetValue(finalized)!.ToString()=="final-info");
            foreach(string invalidEncoding in new[]{"%GG","%FF","%C0%AF","%E2%82"})reject(()=>Call("Finalization",FinalPage(ctx,"https://mysignins.microsoft.com/security-info#fidoProvisionSuccess="+invalidEncoding),"AQ","synthetic","synthetic"));
            check((string)Call("DecodeFragment","%2520+")=="%20+");
            check((string)Call("DecodeFragment",string.Concat(Enumerable.Repeat("é%F0%9F%94%91+%25",4096)))==string.Concat(Enumerable.Repeat("é🔑+%",4096)));
            foreach(string invalid in new[]{"https://evil.test/security-info#fidoProvisionSuccess=secret","https://mysignins.microsoft.com/api/other#fidoProvisionSuccess=secret","https://mysignins.microsoft.com/security-info#fidoProvisionSuccess=a&fidoProvisionSuccess=b","https://mysignins.microsoft.com/security-info#fidoProvisionSuccess=%Q0","https://mysignins.microsoft.com/security-info#error=secret","https://mysignins.microsoft.com/security-info#fidoProvisionSuccess=a&next=evil"})reject(()=>Call("Finalization",FinalPage(ctx,invalid),"AQ","synthetic","synthetic"));
            reject(()=>Call("Finalization",FinalPage("{\"Canary\":\"a\",\"Canary\":\"b\"}",finalizationUrl),"AQ","synthetic","synthetic"));
            reject(()=>Call("Finalization",FinalPage("{\"Canary\":\"a\",\"CredentialId\":\"wrong\"}",finalizationUrl),"AQ","synthetic","synthetic"));
            reject(()=>Call("Finalization",FinalPage(ctx,finalizationUrl)+FinalPage(ctx,finalizationUrl),"AQ","synthetic","synthetic"));
            var verifyResponse=typeof(SoftwarePasskeyEnrollment).GetMethod("VerifyResponse",BindingFlags.NonPublic|BindingFlags.Static)!.CreateDelegate<Verification>();
            foreach(var failure in new[]{("{private malformed","VerificationResponse"),("{\"ErrorCode\":4,\"private\":\"secret\"}","VerificationServiceStatus"),("{\"ErrorCode\":0,\"VerificationState\":3}","VerificationState"),("{\"ErrorCode\":0,\"VerificationState\":2}","VerifiedCredentialMatch"),("{\"ErrorCode\":0,\"VerificationState\":2,\"DataUpdates\":{\"FidoDevices\":{\"CredentialId\":\"wrong\",\"DisplayName\":\"Test\"}}}","VerifiedCredentialMatch")})
            {
                string failureStage="VerificationTransport";reject(()=>verifyResponse(failure.Item1,"AQ","Test",ref failureStage));check(failureStage==failure.Item2);
            }
            string successStage="VerificationTransport";verifyResponse("{\"ErrorCode\":0,\"VerificationState\":2,\"DataUpdates\":{\"FidoDevices\":{\"CredentialId\":\"AQ2\",\"DisplayName\":\"Test\"}}}","AQ","Test",ref successStage);check(successStage=="VerifiedCredentialMatch");
            foreach(string scenario in new[]{"Success","RefreshIdentityChanged","ProvisionTimeout","PostbackMalformed","VerifyAmbiguous","Cancellation","UnsafeProvision","UnsafePostback","VerifyMismatch","ChangedRecovery","ReceiptAlreadyExists","OversizedChallenge"})
            {
                string serverChallenge=scenario=="Success"?new string('x',5198):scenario=="OversizedChallenge"?new string('x',16385):"synthetic-challenge";
                string output=Path.Combine(root,scenario+".passkey");int mutations=0,verifies=0,sessions=0;
                using var cancellation=new CancellationTokenSource();
                using var http=new HttpClient(new Handler(async (request,ct)=>
                {
                    string path=request.RequestUri!.AbsolutePath;
                    if(path=="/api/session/authorize")
                    {sessions++;return Response(JsonSerializer.Serialize(new{isAuthorized=true,sessionCtxV2="synthetic-context",requireNgcMfaForSecurityInfo=sessions==1}));}
                    if(path.EndsWith("/token"))
                    {check(request.Headers.Authorization==null && !request.Headers.Contains("SessionCtxV2"));return Response(JsonSerializer.Serialize(new{access_token=Token(scenario=="RefreshIdentityChanged"?"33333333-3333-3333-3333-333333333333":Principal),token_type="Bearer"}));}
                    if(path=="/api/authenticationmethods/new")
                    {return Response(JsonSerializer.Serialize(new{ErrorCode=0,Data=JsonSerializer.Serialize(new{provisionUrl=scenario=="UnsafeProvision"?"https://evil.test/fido/create":"https://login.microsoft.com/"+Tenant+"/fido/create",requestData=new{canary="synthetic",serverChallenge,userId="AQ",postBackUrl=scenario=="UnsafePostback"?"https://mysignins.microsoft.com/api/other":"https://mysignins.microsoft.com/api/post/newfido"}})}));}
                    if(path=="/api/authenticationmethods/availablemethods"){check(request.Method==HttpMethod.Get && request.Headers.Authorization!=null && request.Headers.Contains("SessionCtxV2"));return Response("{}");}
                    mutations++;
                    check(File.Exists(output));
                    using(var recovery=JsonDocument.Parse(File.ReadAllBytes(output)))check(recovery.RootElement.GetProperty("enrollmentStatus").GetString()=="PendingRemoteVerification");
                    reject(()=>SoftwarePasskey.Open(output).Dispose());
                    if(path.EndsWith("/fido/create"))
                    {
                        check(request.Headers.Authorization==null && !request.Headers.Contains("SessionCtxV2"));
                        if(scenario=="ProvisionTimeout")throw new TimeoutException("synthetic secret request body");
                        if(scenario=="Cancellation")cancellation.Cancel();
                        return Response("synthetic provision");
                    }
                    if(path=="/api/post/newfido")
                    {check(request.Headers.Authorization==null && !request.Headers.Contains("SessionCtxV2"));if(scenario=="PostbackMalformed")return Response("synthetic",HttpStatusCode.Found);return Response("<div id=\"context\" data-content=\""+WebUtility.HtmlEncode(JsonSerializer.Serialize(new{Canary="context-canary",PostInfo="context-info"}))+"\"></div><div id=\"redirectUrl\" data-content=\"https://mysignins.microsoft.com/security-info#fidoProvisionSuccess=final-canary&amp;postinfo=final-info\"></div>");}
                    if(path=="/api/authenticationmethods/verify")
                    {
                        verifies++;check(request.Headers.Authorization==null && request.Headers.Contains("SessionCtxV2"));
                        if(scenario=="VerifyAmbiguous")return Response("private ambiguous body",HttpStatusCode.ServiceUnavailable);
                        using var body=JsonDocument.Parse(await request.Content!.ReadAsStringAsync(ct));using var data=JsonDocument.Parse(body.RootElement.GetProperty("VerificationData").GetString()!);check(data.RootElement.GetProperty("Canary").GetString()=="final-canary" && data.RootElement.GetProperty("PostInfo").GetString()=="final-info");
                        if(scenario=="Success")
                        {
                            using var verifyBody=JsonDocument.Parse(await request.Content!.ReadAsStringAsync(ct));using var verifyData=JsonDocument.Parse(verifyBody.RootElement.GetProperty("VerificationData").GetString()!);
                            var att=(Dictionary<object,object>)DecodeCbor(Decode(verifyData.RootElement.GetProperty("AttestationObject").GetString()!));var auth=(byte[])att["authData"];var statement=(Dictionary<object,object>)att["attStmt"];
                            check((string)att["fmt"]=="packed" && (int)statement["alg"]==-7 && auth[32]==0x45 && auth.AsSpan(33,20).ToArray().All(b=>b==0));
                            check(auth.AsSpan(0,32).SequenceEqual(SHA256.HashData(Encoding.ASCII.GetBytes("login.microsoft.com"))));
                            check(auth[53]==0 && auth[54]==32 && Encode(auth.AsSpan(55,32).ToArray())==verifyData.RootElement.GetProperty("CredentialId").GetString());
                            var cose=(Dictionary<object,object>)DecodeCbor(auth.AsSpan(87).ToArray());check((int)cose[1]==2 && (int)cose[3]==-7 && (int)cose[-1]==1);
                            using var keyJson=JsonDocument.Parse(File.ReadAllBytes(output));using var credential=ECDsa.Create();byte[] privateDer=Convert.FromBase64String(keyJson.RootElement.GetProperty("privateKey").GetString()!);
                            try{credential.ImportPkcs8PrivateKey(privateDer,out int used);check(used==privateDer.Length);var point=credential.ExportParameters(false);check(point.Q.X!.SequenceEqual((byte[])cose[-2]) && point.Q.Y!.SequenceEqual((byte[])cose[-3]));}finally{CryptographicOperations.ZeroMemory(privateDer);}
                            byte[] client=Decode(verifyData.RootElement.GetProperty("ClientDataJson").GetString()!);using var cd=JsonDocument.Parse(client);check(cd.RootElement.GetProperty("origin").GetString()=="https://login.microsoft.com" && cd.RootElement.GetProperty("type").GetString()=="webauthn.create" && cd.RootElement.GetProperty("challenge").GetString()==Encode(Encoding.ASCII.GetBytes(serverChallenge)));
                            using var certificate=X509CertificateLoader.LoadCertificate((byte[])((object[])statement["x5c"])[0]);using var batch=certificate.GetECDsaPublicKey()!;check(batch.VerifyData(auth.Concat(SHA256.HashData(client)).ToArray(),(byte[])statement["sig"],HashAlgorithmName.SHA256,DSASignatureFormat.Rfc3279DerSequence));
                        }
                        if(scenario=="ChangedRecovery")File.WriteAllText(output,"synthetic external replacement");
                        if(scenario=="ReceiptAlreadyExists")File.WriteAllText(output+".registered.json","synthetic external receipt");
                        return Response(JsonSerializer.Serialize(new{VerificationState=2,DataUpdates=new{FidoDevices=new{CredentialId=scenario=="VerifyMismatch"?"Ag":data.RootElement.GetProperty("CredentialId").GetString()+"1",DisplayName="Test"}}}));
                    }
                    throw new InvalidOperationException("Unexpected route");
                }));
                using var self=SelfToken();object[] values={http,"synthetic@example.test",self,Tenant,Hash(Tenant),Hash(Tenant+"/"+Principal),output,"Test",cancellation.Token,"Test",false};
                if(scenario=="Success")
                {
                    var result=(SoftwarePasskeyEnrollmentResult)Call("Complete",values);check(result.Registered && result.RecoveryFileSaved && !result.CredentialsReturned);
                    using var signer=SoftwarePasskey.Open(output);check(!string.IsNullOrEmpty(signer.CreateAssertion("synthetic-login")));check(verifies==1 && mutations==3);
                    byte[] before=File.ReadAllBytes(output);reject(()=>SoftwarePasskeyEnrollment.Enroll("does-not-exist",JsonSerializer.Serialize(new{TenantFingerprint=Hash(Tenant),PrincipalFingerprint=Hash(Tenant+"/"+Principal)}),output));check(before.SequenceEqual(File.ReadAllBytes(output)));
                }
                else
                {
                    reject(()=>Call("Complete",values));
                    bool published=scenario is not ("RefreshIdentityChanged" or "UnsafeProvision" or "UnsafePostback" or "OversizedChallenge");check(File.Exists(output)==published);
                    if(scenario=="ChangedRecovery")check(File.ReadAllText(output)=="synthetic external replacement");
                    if(scenario=="ReceiptAlreadyExists")check(File.ReadAllText(output+".registered.json")=="synthetic external receipt");
                    if(published && scenario!="ChangedRecovery"){using var data=JsonDocument.Parse(File.ReadAllBytes(output));check(data.RootElement.GetProperty("enrollmentStatus").GetString()=="PendingRemoteVerification");reject(()=>SoftwarePasskey.Open(output).Dispose());}
                    if(scenario=="Cancellation")check(mutations==1);
                    if(scenario=="RefreshIdentityChanged")check(mutations==0 && sessions==1);
                    check(verifies<=1);
                }
                check(!Directory.EnumerateFiles(root,"*.tmp").Any());
            }
            var material=typeof(SoftwarePasskeyEnrollment).GetNestedType("Material",BindingFlags.NonPublic)!;
            var publish=material.GetMethod("Publish",BindingFlags.NonPublic|BindingFlags.Static)!.CreateDelegate<Publication>();
            string cleanupTarget=Path.Combine(root,"cleanup-boundary.json");bool saved=false;
            try{publish(cleanupTarget,Encoding.UTF8.GetBytes("synthetic recovery"),ref saved,_=>throw new IOException("synthetic cleanup failure"));throw new InvalidOperationException();}catch(IOException){}
            check(saved && File.ReadAllText(cleanupTarget)=="synthetic recovery");
            var sanitized=new SoftwarePasskeyEnrollmentResult(true,true);check(!JsonSerializer.Serialize(sanitized).Contains("privateKey"));
        }
        finally{Directory.Delete(root,true);}
    }
    static byte[] Decode(string value)=>Convert.FromBase64String(value.Replace('-','+').Replace('_','/').PadRight((value.Length+3)/4*4,'='));
    static object DecodeCbor(byte[] bytes)
    {
        int position=0;
        object Read()
        {
            int first=bytes[position++],major=first>>5,count=first&31;
            if(count==24)count=bytes[position++];else if(count==25){count=bytes[position++]*256+bytes[position++];}else if(count>25)throw new InvalidOperationException();
            if(major==0)return count;if(major==1)return -1-count;
            if(major is 2 or 3){byte[] value=bytes.AsSpan(position,count).ToArray();position+=count;return major==2?value:Encoding.UTF8.GetString(value);}
            if(major==4){object[] array=new object[count];for(int i=0;i<count;i++)array[i]=Read();return array;}
            if(major==5){var map=new Dictionary<object,object>();for(int i=0;i<count;i++)map.Add(Read(),Read());return map;}
            throw new InvalidOperationException();
        }
        object result=Read();if(position!=bytes.Length)throw new InvalidOperationException();return result;
    }
    delegate void Verification(string body,string credential,string name,ref string stage);
    delegate void Publication(string path,byte[] bytes,ref bool published,Action<string>? cleanup);
    static HttpResponseMessage Response(string content,HttpStatusCode status=HttpStatusCode.OK)=>new(status){Content=new StringContent(content)};
    sealed class Handler(Func<HttpRequestMessage,CancellationToken,Task<HttpResponseMessage>> send):HttpMessageHandler
    {protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request,CancellationToken cancellation)=>send(request,cancellation);}
}
