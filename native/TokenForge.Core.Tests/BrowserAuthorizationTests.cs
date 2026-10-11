using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using TokenForge.Core;
using TokenForge.Core.V0180;

static class BrowserAuthorizationTests
{
    static OAuthRequest Plan() => new() {ClientId="11111111-1111-1111-1111-111111111111",ResourceId="00000003-0000-0000-c000-000000000000",ResourceUri="https://graph.microsoft.com",RedirectUri="http://localhost",Scopes=["User.Read"],OAuthScopes=["https://graph.microsoft.com/User.Read"]};
    static string Send(int port,string target,string? headers=null)
    {
        using var client=new TcpClient();client.Connect(IPAddress.Loopback,port);client.ReceiveTimeout=3000;client.SendTimeout=3000;
        using var stream=client.GetStream();Thread.Sleep(100);byte[] message=Encoding.ASCII.GetBytes("GET /?"+target+" HTTP/1.1\r\n"+(headers??"Host: localhost:"+port)+"\r\n\r\n");stream.Write(message,0,message.Length/2);Thread.Sleep(50);stream.Write(message,message.Length/2,message.Length-message.Length/2);
        using var reader=new StreamReader(stream,Encoding.ASCII);return reader.ReadToEnd();
    }
    public static void Run(Action<bool> check,Action<Action> reject)
    {
        var readBody=typeof(ProfileTokenApi).GetMethod("ReadIdentityBody",System.Reflection.BindingFlags.NonPublic|System.Reflection.BindingFlags.Static)!;
        using(var listener=new TcpListener(IPAddress.Loopback,0)){
            listener.Start();int p=((IPEndPoint)listener.LocalEndpoint).Port;
            var writer=Task.Run(()=>{using var client=new TcpClient();client.Connect(IPAddress.Loopback,p);using var stream=client.GetStream();Thread.Sleep(100);stream.Write(Encoding.UTF8.GetBytes("{\"id\":\"11111111-1111-1111-1111-"));Thread.Sleep(100);stream.Write(Encoding.UTF8.GetBytes("111111111111\"}"));client.Client.Shutdown(SocketShutdown.Send);});
            using var accepted=listener.AcceptTcpClient();using var input=accepted.GetStream();
            check((string)readBody.Invoke(null,[input,CancellationToken.None])! == "11111111-1111-1111-1111-111111111111");writer.GetAwaiter().GetResult();
        }
        foreach(string body in new[]{"{\"id\":\"11111111-1111-1111-1111-111111111111\",\"ID\":\"11111111-1111-1111-1111-111111111111\"}","{\"id\":",new string('x',65537)}){
            using var input=new MemoryStream(Encoding.UTF8.GetBytes(body));reject(()=>readBody.Invoke(null,[input,CancellationToken.None]));
        }
        int launches=0;
        foreach(string redirect in new[]{"https://localhost","http://127.0.0.1","http://localhost/path","http://localhost/?query=1"}){
            var plan=Plan();plan.RedirectUri=redirect;reject(()=>OAuthBrowserAuthorization.Authorize(plan,_=>launches++,timeoutSeconds:1));
        }
        foreach(string hint in new[]{new string('a',321),"secret\n"})reject(()=>OAuthBrowserAuthorization.Authorize(Plan(),_=>launches++,hint,1));
        var invalid=Plan();invalid.Tenant="organizations\n";reject(()=>OAuthTransport.ValidateRequest(invalid));
        invalid=Plan();invalid.Scopes=["User.Read\n"];invalid.OAuthScopes=["https://graph.microsoft.com/User.Read\n"];reject(()=>OAuthTransport.ValidateRequest(invalid));check(launches==0);
        try{OAuthBrowserAuthorization.Authorize(Plan(),_=>throw new Exception("synthetic-secret-url"),timeoutSeconds:1);throw new Exception("Expected launch failure");}
        catch(InvalidOperationException e){check(e.Message=="Browser authorization failed. Details suppressed." && e.InnerException==null);}
        Task? sender=null;int port=0;string? challenge=null;
        using(var result=OAuthBrowserAuthorization.Authorize(Plan(),uri=>{
            var query=System.Web.HttpUtility.ParseQueryString(uri.Query);port=new Uri(query["redirect_uri"]!).Port;challenge=query["code_challenge"];
            check(uri.Host=="login.microsoftonline.com" && uri.AbsolutePath=="/organizations/oauth2/v2.0/authorize");
            check(query["prompt"]=="none" && query["login_hint"]=="observer+hint@example.test" && query["code_challenge_method"]=="S256");
            string state=query["state"]!;
            sender=Task.Run(()=>{
                foreach(string target in new[]{"code=x&state=wrong","code=x&code=y&state="+state,"code=x&%63ode=y&state="+state,"Code=x&state="+state,"code=%GG&state="+state,"code=%C0%AF&state="+state,"code=x%00&state="+state,"code=x&state="+state+"&error=no"})check(Send(port,target).StartsWith("HTTP/1.1 400"));
                foreach(string header in new[]{"Host : localhost:"+port,"Host: localhost:"+port+"\r\nBad Name: x","Host: localhost:"+port+"\r\nHost: localhost:"+port,"Host: localhost:"+port+"\r\nTransfer-Encoding: chunked","Host: localhost:"+port+"\r\nContent-Length: 1"})check(Send(port,"code=x&state="+state,header).StartsWith("HTTP/1.1 400"));
                string reply=Send(port,"code=synthetic-code&state="+state);check(reply.StartsWith("HTTP/1.1 200") && reply.Contains("Cache-Control: no-store") && !reply.Contains(state) && !reply.Contains("synthetic-code"));
            });
        },"observer+hint@example.test",10)){
            sender!.GetAwaiter().GetResult();string verifier=new NetworkCredential("",result.Verifier).Password;
            check(result.Code.IsReadOnly() && result.Verifier.IsReadOnly() && new NetworkCredential("",result.Code).Password=="synthetic-code");
            check(challenge==Convert.ToBase64String(SHA256.HashData(Encoding.ASCII.GetBytes(verifier))).TrimEnd('=').Replace('+','-').Replace('/','_'));
            string json=JsonSerializer.Serialize(result);check(!json.Contains("Code") && !json.Contains("Verifier") && !json.Contains("observer"));
        }
        using(var closed=new TcpClient())reject(()=>closed.Connect(IPAddress.Loopback,port));
        foreach(bool slow in new[]{false,true}){
            using var cancel=new CancellationTokenSource();Task? slowSender=null;int canceledPort=0;
            try{
                OAuthBrowserAuthorization.Authorize(Plan(),uri=>{
                    canceledPort=new Uri(System.Web.HttpUtility.ParseQueryString(uri.Query)["redirect_uri"]!).Port;
                    if(slow)slowSender=Task.Run(()=>{using var client=new TcpClient();client.Connect(IPAddress.Loopback,canceledPort);client.GetStream().Write(Encoding.ASCII.GetBytes("GET /?code=private"));cancel.CancelAfter(50);Thread.Sleep(150);});
                    else cancel.CancelAfter(50);
                },timeoutSeconds:5,cancellation:cancel.Token);throw new Exception("Expected cancellation");
            }catch(OperationCanceledException){check(cancel.IsCancellationRequested);}
            slowSender?.GetAwaiter().GetResult();using var closed=new TcpClient();reject(()=>closed.Connect(IPAddress.Loopback,canceledPort));
        }
        foreach(string error in new[]{"consent_required","access_denied"}){
            Task? decline=null;
            try{
                OAuthBrowserAuthorization.Authorize(Plan(),uri=>{var q=System.Web.HttpUtility.ParseQueryString(uri.Query);int p=new Uri(q["redirect_uri"]!).Port;decline=Task.Run(()=>Send(p,"error="+error+"&state="+q["state"]+"&error_description=synthetic-secret%20AADSTS53003"));},timeoutSeconds:5);throw new Exception("Expected decline");
            }catch(InvalidOperationException e){check(!e.Message.Contains("synthetic-secret") && e.Message.Contains("AADSTS53003") && (error!="consent_required" || e.Message.Contains("no interactive fallback")));}
            decline!.GetAwaiter().GetResult();
        }
    }
}
