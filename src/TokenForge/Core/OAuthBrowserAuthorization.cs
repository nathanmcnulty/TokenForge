using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Security;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;
using System.Threading;
using TokenForge.Core.V0180;

namespace TokenForge.Core;

// Caller owns both secure credentials. Callback URLs and account hints are never result metadata.
public sealed class BrowserAuthorization : IDisposable
{
    [JsonIgnore] public SecureString Code { get; }
    [JsonIgnore] public SecureString Verifier { get; }
    public string RedirectUri { get; }
    internal BrowserAuthorization(string code,string verifier,string redirect)
    {
        Code=Secret(code);
        try{Verifier=Secret(verifier);RedirectUri=redirect;}catch{Code.Dispose();throw;}
    }
    private static SecureString Secret(string text){var value=new SecureString();try{foreach(char c in text)value.AppendChar(c);value.MakeReadOnly();return value;}catch{value.Dispose();throw;}}
    public void Dispose(){Code.Dispose();Verifier.Dispose();}
}
public static class OAuthBrowserAuthorization
{
    public static BrowserAuthorization Authorize(OAuthRequest source,Action<Uri> openBrowser,string? loginHint=null,int timeoutSeconds=300,
        bool noConsent=true,CancellationToken cancellation=default)
    {
        OAuthRequest request=OAuthTransport.Snapshot(source);
        var published=new Uri(request.RedirectUri);
        if(request.Discovery || request.Protocol!="OAuth2V2Pkce" || request.Spa || published.Scheme!="http" || published.Host!="localhost" || published.AbsolutePath!="/" || published.Query.Length!=0 || published.Fragment.Length!=0 || published.UserInfo.Length!=0)
            throw new InvalidOperationException("Browser authentication requires a published http://localhost root redirect for a public native client.");
        if(openBrowser==null || timeoutSeconds is <1 or >900 || !Regex.IsMatch(request.Tenant,@"\A(organizations|common|consumers|[A-Za-z0-9][A-Za-z0-9.-]{0,252})\z") ||
            loginHint!=null && (loginHint.Length>320 || loginHint.Any(char.IsControl)))throw new InvalidOperationException("Browser authorization options are invalid.");
        var listener=new TcpListener(IPAddress.Loopback,0);byte[]? random=null,challengeBytes=null;
        try
        {
            cancellation.ThrowIfCancellationRequested();
            using var deadline=CancellationTokenSource.CreateLinkedTokenSource(cancellation);deadline.CancelAfter(TimeSpan.FromSeconds(timeoutSeconds));
            random=RandomNumberGenerator.GetBytes(32);
            string verifier=Convert.ToBase64String(random).TrimEnd('=').Replace('+','-').Replace('/','_');
            CryptographicOperations.ZeroMemory(random);random=RandomNumberGenerator.GetBytes(32);
            string state=Convert.ToHexString(random);challengeBytes=Encoding.ASCII.GetBytes(verifier);
            string challenge=Convert.ToBase64String(SHA256.HashData(challengeBytes)).TrimEnd('=').Replace('+','-').Replace('/','_');
            listener.Start();int port=((IPEndPoint)listener.LocalEndpoint).Port;string redirect="http://localhost:"+port+"/";
            var query=new Dictionary<string,string>{{"client_id",request.ClientId},{"redirect_uri",redirect},{"scope",string.Join(" ",request.OAuthScopes)},
                {"response_type","code"},{"response_mode","query"},{"prompt",noConsent?"none":"select_account"},{"code_challenge",challenge},{"code_challenge_method","S256"},{"state",state}};
            if(!string.IsNullOrEmpty(loginHint))query.Add("login_hint",loginHint);
            string encoded=string.Join("&",query.Select(p=>Uri.EscapeDataString(p.Key)+"="+Uri.EscapeDataString(p.Value)));
            openBrowser(new Uri("https://login.microsoftonline.com/"+Uri.EscapeDataString(request.Tenant)+"/oauth2/v2.0/authorize?"+encoded));
            while(true)
            {
                deadline.Token.ThrowIfCancellationRequested();
                using var client=listener.AcceptTcpClientAsync(deadline.Token).AsTask().GetAwaiter().GetResult();
                using var connection=CancellationTokenSource.CreateLinkedTokenSource(deadline.Token);connection.CancelAfter(TimeSpan.FromSeconds(2));
                var header=new byte[8192];var buffer=new byte[256];
                try
                {
                    using var stream=client.GetStream();int length=0;bool ended=false,ascii=true;
                    while(length<header.Length && !ended && ascii)
                    {
                        int count=stream.ReadAsync(buffer.AsMemory(0,Math.Min(buffer.Length,header.Length-length)),connection.Token).AsTask().GetAwaiter().GetResult();if(count==0)break;
                        for(int i=0;i<count;i++)
                        {
                            byte value=buffer[i];header[length++]=value;if(value>127 || value==0){ascii=false;break;}
                            if(length>=4 && header[length-4]==13 && header[length-3]==10 && header[length-2]==13 && header[length-1]==10){ended=true;break;}
                        }
                    }
                    Dictionary<string,string>? values=ascii && ended?Parse(Encoding.ASCII.GetString(header,0,length),port,state):null;
                    bool valid=values!=null;
                    string body=valid?"Sign-in callback received. You can close this tab.":"Invalid sign-in callback.";
                    byte[] reply=Encoding.ASCII.GetBytes("HTTP/1.1 "+(valid?"200 OK":"400 Bad Request")+"\r\nContent-Type: text/plain\r\nCache-Control: no-store\r\nReferrer-Policy: no-referrer\r\nConnection: close\r\nContent-Length: "+body.Length+"\r\n\r\n"+body);
                    stream.WriteAsync(reply.AsMemory(),connection.Token).AsTask().GetAwaiter().GetResult();stream.FlushAsync(connection.Token).GetAwaiter().GetResult();
                    if(!valid)continue;
                    deadline.Token.ThrowIfCancellationRequested();
                    if(values!.TryGetValue("error",out var error))
                    {
                        string reason=noConsent && error is "consent_required" or "interaction_required" or "login_required" or "account_selection_required"?
                            "Silent browser authorization requires an existing session and authorization; no interactive fallback performed.":"Browser authorization was declined. Identity response details suppressed.";
                        var codes=Regex.Matches(values.GetValueOrDefault("error_description") ?? "",@"\bAADSTS[0-9]{4,9}\b").Cast<Match>().Select(m=>m.Value).Distinct(StringComparer.Ordinal).OrderBy(x=>x,StringComparer.Ordinal).Take(5).ToArray();
                        if(codes.Contains("AADSTS50011",StringComparer.Ordinal))reason="Identity request failed ("+string.Join(", ",codes)+"). Entra rejected the redirect URI; published metadata may differ from the current app registration. Response details suppressed.";
                        else if(codes.Length>0)reason+=" Identity error codes: "+string.Join(", ",codes)+".";
                        throw new BrowserDeclined(reason);
                    }
                    return new BrowserAuthorization(values["code"],verifier,redirect);
                }
                catch(OperationCanceledException){if(deadline.IsCancellationRequested)throw;}
                catch(System.IO.IOException){deadline.Token.ThrowIfCancellationRequested();}
                catch(SocketException){deadline.Token.ThrowIfCancellationRequested();}
                finally{CryptographicOperations.ZeroMemory(header);CryptographicOperations.ZeroMemory(buffer);}
            }
        }
        catch(BrowserDeclined error){throw new InvalidOperationException(error.Message);}
        catch(OperationCanceledException){if(cancellation.IsCancellationRequested)throw;throw new InvalidOperationException("Browser authorization timed out. No token returned.");}
        catch{throw new InvalidOperationException("Browser authorization failed. Details suppressed.");}
        finally{listener.Stop();if(random!=null)CryptographicOperations.ZeroMemory(random);if(challengeBytes!=null)CryptographicOperations.ZeroMemory(challengeBytes);}
    }
    private sealed class BrowserDeclined:Exception{internal BrowserDeclined(string message):base(message){}}
    private static Dictionary<string,string>? Parse(string header,int port,string state)
    {
        try
        {
            string[] lines=header.Split(new[]{"\r\n"},StringSplitOptions.None);
            var request=Regex.Match(lines[0],@"\AGET (/\?[^ #]+) HTTP/1\.[01]\z");if(!request.Success)return null;
            int hosts=0;
            foreach(string line in lines.Skip(1))
            {
                if(line.Length==0)continue;int colon=line.IndexOf(':');if(colon<=0 || line.Any(c=>char.IsControl(c) && c!='\t') || line[0]==' ' || line[0]=='\t')return null;
                string key=line.Substring(0,colon),value=line.Substring(colon+1).Trim();
                if(!Regex.IsMatch(key,@"\A[!#$%&'*+.^_`|~0-9A-Za-z-]+\z"))return null;
                if(key.Equals("Host",StringComparison.OrdinalIgnoreCase)){if(++hosts!=1 || !value.Equals("localhost:"+port,StringComparison.OrdinalIgnoreCase))return null;}
                if(key.Equals("Transfer-Encoding",StringComparison.OrdinalIgnoreCase) || key.Equals("Content-Length",StringComparison.OrdinalIgnoreCase) && value!="0")return null;
            }
            if(hosts!=1)return null;
            var values=new Dictionary<string,string>(StringComparer.OrdinalIgnoreCase);
            foreach(string pair in request.Groups[1].Value.Substring(2).Split('&'))
            {
                int equals=pair.IndexOf('=');if(equals<1)return null;
                string key=Decode(pair.Substring(0,equals)),value=Decode(pair.Substring(equals+1));
                if(key.Any(char.IsControl) || value.Any(char.IsControl) || !values.TryAdd(key,value))return null;
                if(key.Equals("state",StringComparison.OrdinalIgnoreCase) && key!="state" || key.Equals("code",StringComparison.OrdinalIgnoreCase) && key!="code" || key.Equals("error",StringComparison.OrdinalIgnoreCase) && key!="error")return null;
            }
            if(!values.TryGetValue("state",out var returned) || returned!=state)return null;
            bool code=values.TryGetValue("code",out var codeValue),error=values.TryGetValue("error",out var errorValue);
            if(code==error || code && string.IsNullOrWhiteSpace(codeValue) || error && string.IsNullOrWhiteSpace(errorValue))return null;
            return values;
        }
        catch{return null;}
    }
    private static string Decode(string text)
    {
        byte[] bytes=new byte[text.Length];int length=0;
        try
        {
            for(int i=0;i<text.Length;i++)
            {
                if(text[i]=='%'){if(i+2>=text.Length || !byte.TryParse(text.Substring(i+1,2),System.Globalization.NumberStyles.HexNumber,System.Globalization.CultureInfo.InvariantCulture,out var value))throw new FormatException();bytes[length++]=value;i+=2;}
                else{if(text[i]>127)throw new FormatException();bytes[length++]=(byte)(text[i]=='+'?' ':text[i]);}
            }
            return new UTF8Encoding(false,true).GetString(bytes,0,length);
        }
        finally{CryptographicOperations.ZeroMemory(bytes);}
    }
}
