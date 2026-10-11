using System;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security;
using System.Security.Cryptography;
using System.Text.Json;
using System.Threading;

namespace TokenForge.Core;

public sealed record ProfileApiCheck(int? Status,bool Accepted,string Evidence="ResourceGetStatusNotAuthorizationForOtherEndpoints");
public static class ProfileTokenApi
{
    public static string ReadIdentity(SecureString token,CancellationToken cancellation=default)
    {
        byte[]? bytes=null;MemoryStream? output=null;
        try
        {
            using var deadline=CancellationTokenSource.CreateLinkedTokenSource(cancellation);deadline.CancelAfter(TimeSpan.FromSeconds(30));
            using var client=Client();using var request=Request(token,new Uri("https://graph.microsoft.com/v1.0/me?$select=id"));
            using var response=client.Send(request,HttpCompletionOption.ResponseHeadersRead,deadline.Token);
            if(response.StatusCode!=HttpStatusCode.OK || response.Content.Headers.ContentLength>65536)throw new InvalidOperationException();
            using var stream=response.Content.ReadAsStream(deadline.Token);output=new MemoryStream();bytes=new byte[4096];
            int count;while((count=stream.ReadAsync(bytes.AsMemory(),deadline.Token).GetAwaiter().GetResult())!=0)
            {if(output.Length+count>65536)throw new InvalidOperationException();output.Write(bytes,0,count);}
            using var json=JsonDocument.Parse(output.GetBuffer().AsMemory(0,checked((int)output.Length)),new JsonDocumentOptions{MaxDepth=8});
            var fields=json.RootElement.EnumerateObject().WhereIdentityFields();
            if(fields.Length!=1 || fields[0].Value.ValueKind!=JsonValueKind.String || !Guid.TryParse(fields[0].Value.GetString(),out var identity) || identity==Guid.Empty)throw new InvalidOperationException();
            return identity.ToString();
        }
        catch(OperationCanceledException){throw;}
        catch{throw new InvalidOperationException("Graph identity confirmation failed. Details suppressed.");}
        finally{if(bytes!=null)CryptographicOperations.ZeroMemory(bytes);if(output!=null){CryptographicOperations.ZeroMemory(output.GetBuffer());output.Dispose();}}
    }
    public static ProfileApiCheck Check(SecureString token,string resource,Uri uri,CancellationToken cancellation=default)
    {
        string host=resource switch{"00000003-0000-0000-c000-000000000000"=>"graph.microsoft.com","797f4846-ba00-4fd7-ba43-dac1f8f63013"=>"management.azure.com",_=>throw new InvalidOperationException()};
        if(!uri.IsAbsoluteUri || uri.Scheme!="https" || uri.Host!=host || uri.Port!=443 || uri.UserInfo.Length!=0 || uri.Fragment.Length!=0)throw new InvalidOperationException("API URI is outside the resource boundary.");
        try{
            using var deadline=CancellationTokenSource.CreateLinkedTokenSource(cancellation);deadline.CancelAfter(TimeSpan.FromSeconds(30));
            using var client=Client();using var request=Request(token,uri);using var response=client.Send(request,HttpCompletionOption.ResponseHeadersRead,deadline.Token);
            return new ProfileApiCheck((int)response.StatusCode,response.IsSuccessStatusCode);
        }catch(OperationCanceledException){throw;}catch{return new ProfileApiCheck(null,false,"TransportFailureDetailsSuppressed");}
    }
    private static HttpClient Client()=>new(new HttpClientHandler{AllowAutoRedirect=false,UseCookies=false,MaxResponseHeadersLength=32}){Timeout=TimeSpan.FromSeconds(30)};
    private static HttpRequestMessage Request(SecureString token,Uri uri)
    {
        var request=new HttpRequestMessage(HttpMethod.Get,uri);
        try{request.Headers.Authorization=new AuthenticationHeaderValue("Bearer",new NetworkCredential("",token).Password);return request;}catch{request.Dispose();throw;}
    }
    // Require exactly one case-sensitive id; reject ambiguous case variants too.
    private static JsonProperty[] WhereIdentityFields(this JsonElement.ObjectEnumerator fields)
    {var values=new System.Collections.Generic.List<JsonProperty>();foreach(var field in fields)if(field.Name.Equals("id",StringComparison.OrdinalIgnoreCase))values.Add(field);return values.Count==1 && values[0].Name=="id"?values.ToArray():Array.Empty<JsonProperty>();}
}
