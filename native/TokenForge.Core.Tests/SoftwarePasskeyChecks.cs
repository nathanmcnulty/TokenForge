using System.Net;
using System.Net.Http;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using TokenForge.Core;
using TokenForge.Core.V0220;

static class SoftwarePasskeyChecks
{
 public static void Run(Action<bool> check,Action<Action> reject)
 {
  string root=Path.Combine(Path.GetTempPath(),"TokenForge-passkey-check-"+Guid.NewGuid().ToString("N"));
  if(OperatingSystem.IsMacOS() && root.StartsWith("/var/"))root="/private"+root;
  string path=PrivateFiles.Resolve(Path.Combine(root,"key.json"),true);
  using var key=ECDsa.Create(ECCurve.NamedCurves.nistP256);
  var data=new Dictionary<string,object>{["username"]="synthetic@example.test",["credentialId"]="00000000-0000-0000-0000-000000000001",["privateKey"]=key.ExportPkcs8PrivateKeyPem(),["userHandle"]="AQ",["counter"]=0};
  void Write(string text){using var file=PrivateFiles.Open(path,!File.Exists(path));file.SetLength(0);file.Write(Encoding.UTF8.GetBytes(text));}
  byte[] Decode(string value)=>Convert.FromBase64String(value.Replace('-','+').Replace('_','/').PadRight((value.Length+3)/4*4,'='));
  try
  {
   Write(JsonSerializer.Serialize(data));using(var signer=SoftwarePasskey.Open(path))
   {
    string assertion=signer.CreateAssertion("synthetic-challenge");using var doc=JsonDocument.Parse(assertion);var v=doc.RootElement;
    byte[] auth=Decode(v.GetProperty("authenticatorData").GetString()!),client=Decode(v.GetProperty("clientDataJSON").GetString()!),signature=Decode(v.GetProperty("signature").GetString()!);
    check(auth.Length==37 && auth[32]==5 && auth.Skip(33).All(b=>b==0));check(auth.AsSpan(0,32).SequenceEqual(SHA256.HashData(Encoding.ASCII.GetBytes("login.microsoft.com"))));
    using var cd=JsonDocument.Parse(client);check(cd.RootElement.GetProperty("challenge").GetString()==Convert.ToBase64String(Encoding.ASCII.GetBytes("synthetic-challenge")).TrimEnd('='));
    check(cd.RootElement.GetProperty("origin").GetString()=="https://login.microsoft.com" && cd.RootElement.GetProperty("type").GetString()=="webauthn.get" && !cd.RootElement.GetProperty("crossOrigin").GetBoolean());
    byte[] signed=auth.Concat(SHA256.HashData(client)).ToArray();check(key.VerifyData(signed,signature,HashAlgorithmName.SHA256,DSASignatureFormat.Rfc3279DerSequence));signed[0]^=1;check(!key.VerifyData(signed,signature,HashAlgorithmName.SHA256,DSASignatureFormat.Rfc3279DerSequence));
    check(v.GetProperty("id").GetString()=="AAAAAAAAAAAAAAAAAAAAAQ" && v.GetProperty("userHandle").GetString()=="AQ");
    check(!assertion.Contains("PRIVATE KEY") && JsonSerializer.Serialize(signer)=="{}");
    reject(()=>signer.CreateAssertion(""));reject(()=>signer.CreateAssertion("secret\n"));reject(()=>signer.CreateAssertion(new string('a',4097)));
   }
   foreach(var entry in new[]{("relyingParty",(object)"evil.test"),("url",(object)"https://login.microsoft.com@evil.test"),("counter",(object)1),("userHandle",(object)"AR"),("userName",(object)"other@example.test"),("keyVault",(object)new {vaultName="private"})})
   {var copy=new Dictionary<string,object>(data);copy[entry.Item1]=entry.Item2;Write(JsonSerializer.Serialize(copy));reject(()=>SoftwarePasskey.Open(path).Dispose());}
   Write(JsonSerializer.Serialize(data).Replace("{","{\"username\":\"duplicate@example.test\",",StringComparison.Ordinal));reject(()=>SoftwarePasskey.Open(path).Dispose());
   using var wrong=ECDsa.Create(ECCurve.NamedCurves.nistP384);var invalid=new Dictionary<string,object>(data);invalid["privateKey"]=wrong.ExportPkcs8PrivateKeyPem();Write(JsonSerializer.Serialize(invalid));reject(()=>SoftwarePasskey.Open(path).Dispose());
   // Pending credentials cannot be used through normal acquisition until a byte-bound receipt exists.
   var pending=new Dictionary<string,object>(data){["enrollmentStatus"]="PendingRemoteVerification"};
   Write(JsonSerializer.Serialize(pending));byte[] pendingBytes=File.ReadAllBytes(path);
   string hash=Convert.ToHexString(SHA256.HashData(pendingBytes)).ToLowerInvariant();
   string receiptPath=path+".registered.json",rawId=(string)data["credentialId"];
   var receiptType=typeof(SoftwarePasskey).Assembly.GetType("TokenForge.Core.SoftwarePasskeyReceipt")!;
   var publish=receiptType.GetMethod("Publish",BindingFlags.Static|BindingFlags.NonPublic)!;
   bool Publish(string expectedHash,CancellationToken cancellation)
   {object[] args={path,expectedHash,rawId,cancellation,false};publish.Invoke(null,args);return (bool)args[4];}
   reject(()=>SoftwarePasskey.Open(path).Dispose());
   using(var cancelled=new CancellationTokenSource())
   {
    cancelled.Cancel();reject(()=>SoftwarePasskeyRecovery.Recover(path,"{}",cancelled.Token));
    reject(()=>Publish(hash,cancelled.Token));check(!File.Exists(receiptPath));
    check(!Directory.EnumerateFiles(root,"*.tmp").Any());
   }
   foreach(string input in new[]{"{}","{\"TenantFingerprint\":\"bad\",\"PrincipalFingerprint\":\"bad\"}","{\"TenantFingerprint\":\"a\",\"TenantFingerprint\":\"b\"}"})
   {reject(()=>SoftwarePasskeyRecovery.Recover(path,input));check(!File.Exists(receiptPath));}
   Write(JsonSerializer.Serialize(pending)+" ");reject(()=>Publish(hash,CancellationToken.None));check(!File.Exists(receiptPath));
   Write(JsonSerializer.Serialize(pending));check(Publish(hash,CancellationToken.None));
   check(File.ReadAllBytes(path).SequenceEqual(pendingBytes));
   using(var confirmed=SoftwarePasskey.Open(path))check(confirmed.CreateAssertion("synthetic").Length>0);
   byte[] validReceipt=File.ReadAllBytes(receiptPath);
   reject(()=>Publish(hash,CancellationToken.None));check(File.ReadAllBytes(receiptPath).SequenceEqual(validReceipt));
   check(!Directory.EnumerateFiles(root,"*.tmp").Any());
   reject(()=>SoftwarePasskeyRecovery.Recover(path,JsonSerializer.Serialize(new{TenantFingerprint=new string('a',64),PrincipalFingerprint=new string('b',64)})));
   foreach(string field in new[]{"SchemaVersion","Usable","Proof","CredentialFileSha256","CredentialId"})
   {
    var record=JsonSerializer.Deserialize<Dictionary<string,object>>(validReceipt)!;
    record[field]=field=="SchemaVersion"?3:field=="Usable"?false:"wrong";
    using(var file=PrivateFiles.Open(receiptPath,false)){file.SetLength(0);file.Write(JsonSerializer.SerializeToUtf8Bytes(record));}
    reject(()=>SoftwarePasskey.Open(path).Dispose());
   }
   using(var file=PrivateFiles.Open(receiptPath,false)){file.SetLength(0);file.Write(Encoding.UTF8.GetBytes(Encoding.UTF8.GetString(validReceipt).Replace("{","{\"Usable\":true,")));}
   reject(()=>SoftwarePasskey.Open(path).Dispose());
   using(var file=PrivateFiles.Open(receiptPath,false)){file.SetLength(0);file.Write(JsonSerializer.SerializeToUtf8Bytes(new{SchemaVersion=1,Registered=true,CredentialFileSha256=hash,CredentialId=rawId}));}
   using(var legacy=SoftwarePasskey.Open(path))check(legacy.CreateAssertion("synthetic").Length>0);
   Write(JsonSerializer.Serialize(pending)+" ");reject(()=>SoftwarePasskey.Open(path).Dispose());
   File.Delete(receiptPath);
   Write(JsonSerializer.Serialize(data));if(!OperatingSystem.IsWindows()){File.SetUnixFileMode(path,UnixFileMode.UserRead|UnixFileMode.UserWrite|UnixFileMode.GroupRead);reject(()=>SoftwarePasskey.Open(path).Dispose());File.SetUnixFileMode(path,UnixFileMode.UserRead|UnixFileMode.UserWrite);string link=Path.Combine(root,"link");File.CreateSymbolicLink(link,path);reject(()=>SoftwarePasskey.Open(link).Dispose());}
  }
  finally{Directory.Delete(root,true);}
  static object Invoke(string method,params object[] args)=>typeof(SoftwarePasskey).GetMethod(method,BindingFlags.NonPublic|BindingFlags.Static)!.Invoke(null,args)!;
  using(var config=(JsonDocument)Invoke("Config",new TokenForge.Core.V0180.OAuthHttpResponse(200,null,"before $Config={\"sFidoChallenge\":\"synthetic\"};after")))check(config.RootElement.GetProperty("sFidoChallenge").GetString()=="synthetic");
  foreach(string body in new[]{"no config","$Config={broken}","$Config={\"nested\":{\"x\":1,\"x\":2}}"})reject(()=>Invoke("Config",new TokenForge.Core.V0180.OAuthHttpResponse(200,null,body)));
  int calls=0;
  using(var client=new HttpClient(new Handler((r,c)=>{calls++;return Task.FromResult(new HttpResponseMessage(HttpStatusCode.Found){Headers={Location=new Uri("https://evil.test/private")},Content=new StringContent("synthetic")});})))
  {
   var response=(TokenForge.Core.V0180.OAuthHttpResponse)Invoke("Send",client,new Uri("https://login.microsoft.com/common/fido/get"),null!,CancellationToken.None);check(response.Status==302 && response.Location=="https://evil.test/private" && calls==1);
   var followed=(TokenForge.Core.V0180.OAuthHttpResponse)Invoke("FollowIdentityGet",client,new Uri("https://login.microsoftonline.com/common/login"),CancellationToken.None);check(followed.Status==302 && calls==2);
   foreach(string url in new[]{"http://login.microsoft.com/","https://login.microsoft.com:444/","https://login.microsoft.com@evil.test/","https://evil.test/","https://login.microsoft.com/#private"})reject(()=>Invoke("Send",client,new Uri(url),null!,CancellationToken.None));check(calls==2);
  }
  foreach(int length in new[]{1048576,1048577})using(var client=new HttpClient(new Handler((r,c)=>Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK){Content=new ChunkContent(length)}))))
  {
   if(length==1048576){var response=(TokenForge.Core.V0180.OAuthHttpResponse)Invoke("Send",client,new Uri("https://login.microsoftonline.com/common/login"),null!,CancellationToken.None);check(response.Content.Length==length);}
   else reject(()=>Invoke("Send",client,new Uri("https://login.microsoftonline.com/common/login"),null!,CancellationToken.None));
  }
  using(var cancel=new CancellationTokenSource())using(var client=new HttpClient(new Handler(async(r,c)=>{await Task.Delay(10000,c);return new HttpResponseMessage(HttpStatusCode.OK);})))
  {cancel.CancelAfter(20);reject(()=>Invoke("Send",client,new Uri("https://login.microsoftonline.com/common/login"),null!,cancel.Token));}
  string Page(string kind)=>"$Config="+JsonSerializer.Serialize(new{pgid=kind,canary="synthetic",sFT="synthetic",correlationId="synthetic",sCtx="synthetic"})+";";
  var stateJar=new CookieContainer();int steps=0;
  using(var client=new HttpClient(new Handler((r,c)=>{
   steps++;check(r.Method==HttpMethod.Post && r.RequestUri!.Host=="login.microsoftonline.com");
   if(steps==1){check(r.RequestUri!.AbsolutePath=="/appverify");return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK){Content=new StringContent(Page("KmsiInterrupt"))});}
   check(r.RequestUri!.AbsolutePath=="/kmsi");stateJar.Add(new Cookie("ESTSAUTH","synthetic","/","login.microsoftonline.com"){Secure=true});return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK){Content=new StringContent("done")});
  })))
  {check(((Cookie)Invoke("CompleteSession",client,stateJar,new TokenForge.Core.V0180.OAuthHttpResponse(200,null,Page("CmsiInterrupt")),CancellationToken.None,"Interaction")).Name=="ESTSAUTH" && steps==2);}
  steps=0;stateJar=new CookieContainer();
  using(var client=new HttpClient(new Handler((r,c)=>{steps++;return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK){Content=new StringContent(Page("CmsiInterrupt"))});})))
  {reject(()=>Invoke("CompleteSession",client,stateJar,new TokenForge.Core.V0180.OAuthHttpResponse(200,null,Page("CmsiInterrupt")),CancellationToken.None,"Interaction"));check(steps==1);}
  string multiple="$Config="+JsonSerializer.Serialize(new{pgid="ConvergedSignIn",arrSessions=new[]{new{id="first"},new{id="second"}},urlLogin="https://login.microsoftonline.com/common/oauth2/authorize"})+";";
  using(var client=new HttpClient(new Handler((r,c)=>throw new Exception("Must not select an ambiguous session."))))reject(()=>Invoke("CompleteSession",client,new CookieContainer(),new TokenForge.Core.V0180.OAuthHttpResponse(200,null,multiple),CancellationToken.None,"Interaction"));
  string single="$Config="+JsonSerializer.Serialize(new{pgid="ConvergedSignIn",arrSessions=new[]{new{id="synthetic-session"}},urlLogin="https://login.microsoftonline.com/common/oauth2/authorize"})+";";
  steps=0;stateJar=new CookieContainer();
  using(var client=new HttpClient(new Handler((r,c)=>{
   steps++;check(r.Method==HttpMethod.Get);
   if(steps==1){check(r.RequestUri!.Query=="?sessionid=synthetic-session");return Task.FromResult(new HttpResponseMessage(HttpStatusCode.Found){Headers={Location=new Uri("/common/finish",UriKind.Relative)},Content=new StringContent("")});}
   check(r.RequestUri!.AbsolutePath=="/common/finish");stateJar.Add(new Cookie("ESTSAUTH","synthetic","/","login.microsoftonline.com"){Secure=true});return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK){Content=new StringContent("done")});
  })))check(((Cookie)Invoke("CompleteSession",client,stateJar,new TokenForge.Core.V0180.OAuthHttpResponse(200,null,single),CancellationToken.None,"Interaction")).Name=="ESTSAUTH" && steps==2);
  foreach(bool empty in new[]{false,true})
  {
   var fields=new Dictionary<string,object>{["pgid"]="ConvergedSignIn",["sessionId"]="fallback-session",["urlLogin"]="https://login.microsoftonline.com/common/oauth2/authorize"};
   if(empty)fields["arrSessions"]=Array.Empty<object>();
   stateJar=new CookieContainer();steps=0;
   using(var client=new HttpClient(new Handler((r,c)=>{steps++;check(r.RequestUri!.Query=="?sessionid=fallback-session");stateJar.Add(new Cookie("ESTSAUTH","synthetic","/","login.microsoftonline.com"){Secure=true});return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK){Content=new StringContent("done")});})))
   check(((Cookie)Invoke("CompleteSession",client,stateJar,new TokenForge.Core.V0180.OAuthHttpResponse(200,null,"$Config="+JsonSerializer.Serialize(fields)+";"),CancellationToken.None,"Interaction")).Name=="ESTSAUTH" && steps==1);
  }
  string malformed="$Config="+JsonSerializer.Serialize(new{pgid="ConvergedSignIn",arrSessions="invalid",sessionId="must-not-fallback",urlLogin="https://login.microsoftonline.com/common/oauth2/authorize"})+";";
  using(var client=new HttpClient(new Handler((r,c)=>throw new Exception("Must reject malformed session metadata."))))reject(()=>Invoke("CompleteSession",client,new CookieContainer(),new TokenForge.Core.V0180.OAuthHttpResponse(200,null,malformed),CancellationToken.None,"Interaction"));
  steps=0;
  using(var client=new HttpClient(new Handler((r,c)=>{steps++;return Task.FromResult(new HttpResponseMessage(HttpStatusCode.Found){Headers={Location=new Uri("/loop",UriKind.Relative)},Content=new StringContent("")});})))
  {reject(()=>Invoke("FollowIdentityGet",client,new Uri("https://login.microsoftonline.com/loop"),CancellationToken.None));check(steps==8);}
  steps=0;using(var cancel=new CancellationTokenSource())using(var client=new HttpClient(new Handler((r,c)=>{steps++;cancel.Cancel();return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK){Content=new StringContent(Page("KmsiInterrupt"))});})))
  {reject(()=>Invoke("CompleteSession",client,new CookieContainer(),new TokenForge.Core.V0180.OAuthHttpResponse(200,null,Page("CmsiInterrupt")),cancel.Token,"Interaction"));check(steps==1);}
  using(var client=new HttpClient(new Handler((r,c)=>throw new Exception("Must not automate consent."))))reject(()=>Invoke("CompleteSession",client,new CookieContainer(),new TokenForge.Core.V0180.OAuthHttpResponse(200,null,Page("Consent")),CancellationToken.None,"Interaction"));
  var jar=new CookieContainer();jar.Add(new Cookie("ESTSAUTHLIGHT","private","/","login.microsoftonline.com"){Secure=true});check(Invoke("Cookie",jar)==null);
  jar.Add(new Cookie("ESTSAUTH","insecure","/","login.microsoftonline.com"));check(Invoke("Cookie",jar)==null);
  jar.Add(new Cookie("ESTSAUTH","synthetic","/","login.microsoftonline.com"){Secure=true,HttpOnly=true});check(((Cookie)Invoke("Cookie",jar)).Name=="ESTSAUTH");
  jar.Add(new Cookie("ESTSAUTHPERSISTENT","synthetic-longer","/","login.microsoftonline.com"){Secure=true,HttpOnly=true});check(((Cookie)Invoke("Cookie",jar)).Name=="ESTSAUTHPERSISTENT");
 }
 sealed class Handler(Func<HttpRequestMessage,CancellationToken,Task<HttpResponseMessage>> send):HttpMessageHandler
 {protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request,CancellationToken cancellation)=>send(request,cancellation);}
 sealed class ChunkContent(int length):HttpContent
 {
  protected override bool TryComputeLength(out long result){result=0;return false;}
  protected override Task SerializeToStreamAsync(Stream stream,TransportContext? context)=>throw new NotSupportedException();
  protected override Task<Stream> CreateContentReadStreamAsync()=>Task.FromResult<Stream>(new ChunkStream(length));
 }
 sealed class ChunkStream(int remaining):Stream
 {
  public override bool CanRead=>true;public override bool CanSeek=>false;public override bool CanWrite=>false;public override long Length=>throw new NotSupportedException();public override long Position{get=>throw new NotSupportedException();set=>throw new NotSupportedException();}
  public override int Read(byte[] buffer,int offset,int count){int n=Math.Min(Math.Min(count,4093),remaining);Array.Fill(buffer,(byte)'x',offset,n);remaining-=n;return n;}
  public override ValueTask<int> ReadAsync(Memory<byte> buffer,CancellationToken cancellation=default){cancellation.ThrowIfCancellationRequested();int n=Math.Min(Math.Min(buffer.Length,4093),remaining);buffer.Span[..n].Fill((byte)'x');remaining-=n;return ValueTask.FromResult(n);}
  public override void Flush()=>throw new NotSupportedException();public override long Seek(long offset,SeekOrigin origin)=>throw new NotSupportedException();public override void SetLength(long value)=>throw new NotSupportedException();public override void Write(byte[] buffer,int offset,int count)=>throw new NotSupportedException();
 }
}
