using System.Security;
using System.Diagnostics;
using System.Security.Cryptography;
using TokenForge.Core;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;
using TokenForge.Core.V0100;
using TokenForge.Core.V0180;

// Advanced acquisition validation. Credentials enter through an unechoed prompt or explicit stdin.
// Tokens remain in this process and are disposed after the policy-checked metadata projection.
internal static class NativeTokenCommand
{
    internal sealed class Plan
    {
        public int SchemaVersion { get; set; }
        public OAuthRequest Request { get; set; } = new();
        public string ExpectedTenantFingerprint { get; set; } = "";
        public string ExpectedPrincipalFingerprint { get; set; } = "";
        public int MaximumAdditionalScopes { get; set; }
    }
    public static int Run(string[] args)
    {
        var stage = "InvalidPlan";
        try {
        if(args.Length<6 || args[2]!="--plan" || args[4]!="--credential" || args[5] is not ("cookie" or "refresh" or "browser" or "passkey"))throw new InvalidOperationException();
        bool browser=args[5]=="browser",passkey=args[5]=="passkey",stdin=false,interactive=false;string? hint=null,keyPath=null;int timeout=300;
        if(browser){
            var seen=new HashSet<string>(StringComparer.Ordinal);
            for(int i=6;i<args.Length;i++){
                string option=args[i];if(!seen.Add(option))throw new InvalidOperationException();
                if(option=="--interactive"){interactive=true;continue;}
                if(option is not ("--login-hint" or "--timeout-seconds") || ++i>=args.Length)throw new InvalidOperationException();
                if(option=="--login-hint"){hint=args[i];if(hint.Length>320 || hint.Any(char.IsControl))throw new InvalidOperationException();}
                else if(!int.TryParse(args[i],System.Globalization.NumberStyles.None,System.Globalization.CultureInfo.InvariantCulture,out timeout) || timeout is <30 or >900)throw new InvalidOperationException();
            }
        }else if(passkey){
            if(args.Length!=8 || args[6]!="--passkey-file" || args[7].Length is <1 or >4096 || args[7].StartsWith('-'))throw new InvalidOperationException();
            keyPath=args[7];
        }else{
            if(args.Length>7 || args.Length==7 && args[6]!="--stdin")throw new InvalidOperationException();
            stdin=args.Length==7;if(!stdin && Console.IsInputRedirected)throw new InvalidOperationException();
        }
        var plan=ReadPlan(args[3]);
        if(browser){var callback=new Uri(plan.Request.RedirectUri);if(plan.Request.Spa || callback.Scheme!="http" || callback.Host!="localhost" || callback.AbsolutePath!="/" || callback.Query.Length!=0 || callback.Fragment.Length!=0 || callback.UserInfo.Length!=0)throw new InvalidOperationException();}
        using var cancellation = new CancellationTokenSource();
        ConsoleCancelEventHandler cancel = (_, e) => { e.Cancel = true; cancellation.Cancel(); };
        stage = "CredentialInputFailed";
        using var secret = browser || passkey ? null : ReadCredential(stdin);
        Console.CancelKeyPress += cancel;
        try
        {
            cancellation.Token.ThrowIfCancellationRequested();
            stage = "TokenAcquisitionFailed";
            using var result = passkey ? AcquirePasskey(plan.Request,keyPath!,cancellation.Token) : browser ? AcquireBrowser(plan.Request,hint,timeout,!interactive,cancellation.Token) :
                args[5] == "cookie" ? OAuthTransport.Cookie(plan.Request, secret!, cancellation: cancellation.Token) : OAuthTransport.Refresh(plan.Request, secret!, cancellation.Token);
            var claims = result.TokenClaims;
            stage = "TokenPolicyRejected";
            TokenPolicy.Validate(claims.TenantFingerprint!, claims.PrincipalFingerprint!, claims.ClientId!, claims.Audience!, plan.ExpectedTenantFingerprint, plan.ExpectedPrincipalFingerprint, plan.Request.ClientId, plan.Request.ResourceId, claims.Scopes, plan.Request.Scopes, claims.HasDelegatedScopeClaim, claims.ExpiresAt, result.ExpiresAt, plan.MaximumAdditionalScopes, result.AdditionalScopes.Length, false, DateTimeOffset.UtcNow);
            Console.WriteLine(JsonSerializer.Serialize(new {
                SchemaVersion = 1, Succeeded = true, Transport = "NativeOAuth", CredentialOperation = args[5],
                result.ClientId, result.ResourceId, result.RequestedScopes, result.GrantedScopes, result.AdditionalScopes,
                result.ScopeEvidence, result.ExpiresAt, result.Protocol, claims.Audience,
                SignatureValidated = false, ApiAuthorization = "NotEstablished", CredentialsPersisted = false,
                TokensReturned = false
            }));
            return 0;
        }
        finally { Console.CancelKeyPress -= cancel; }
        } catch (Exception error) { throw new NativeTokenException(stage, error.Message); }
    }
    internal static OAuthResult AcquirePasskey(OAuthRequest request,string path,CancellationToken cancellation)
    {
        using var signer=SoftwarePasskey.Open(path);
        using var session=signer.Authenticate(cancellation);
        return OAuthTransport.Cookie(request,session.Cookie,session.CookieName,cancellation);
    }
    internal static OAuthResult AcquireBrowser(OAuthRequest request,string? hint,int timeout,bool silent,CancellationToken cancellation)
    {
        using var authorization=OAuthBrowserAuthorization.Authorize(request,uri=>OpenBrowser(uri,cancellation),hint,timeout,silent,cancellation);
        cancellation.ThrowIfCancellationRequested();
        return OAuthTransport.RedeemCode(request,authorization.Code,authorization.Verifier,authorization.RedirectUri,cancellation);
    }
    private static void OpenBrowser(Uri uri,CancellationToken cancellation)
    {
        try{
            cancellation.ThrowIfCancellationRequested();
            if(OperatingSystem.IsWindows()){
                using var launched=Process.Start(new ProcessStartInfo(uri.AbsoluteUri){UseShellExecute=true});
                return;
            }
            var info=new ProcessStartInfo(OperatingSystem.IsMacOS()?"/usr/bin/open":"/usr/bin/xdg-open"){
                UseShellExecute=false,RedirectStandardOutput=true,RedirectStandardError=true,CreateNoWindow=true};
            info.ArgumentList.Add(uri.AbsoluteUri);
            using var process=Process.Start(info)??throw new InvalidOperationException();
            using var deadline=CancellationTokenSource.CreateLinkedTokenSource(cancellation);deadline.CancelAfter(TimeSpan.FromSeconds(10));
            async Task Drain(Stream stream){var bytes=new byte[1024];try{while(await stream.ReadAsync(bytes.AsMemory(),deadline.Token)!=0){}}finally{CryptographicOperations.ZeroMemory(bytes);}}
            Task output=Drain(process.StandardOutput.BaseStream),errors=Drain(process.StandardError.BaseStream);
            try{process.WaitForExitAsync(deadline.Token).GetAwaiter().GetResult();if(process.ExitCode!=0)throw new InvalidOperationException();}
            finally{
                deadline.Cancel();
                if(!process.HasExited){try{process.Kill();}catch{}}
                try{Task.WhenAll(output,errors).GetAwaiter().GetResult();}catch(OperationCanceledException){}
            }
        }catch(OperationCanceledException){if(cancellation.IsCancellationRequested)throw;throw new InvalidOperationException("Browser launcher timed out. Details suppressed.");}
        catch{throw new InvalidOperationException("Unable to open the system browser. Details suppressed.");}
    }
    private static Plan ReadPlan(string path)
    {
        var file = new FileInfo(TokenForge.Core.PrivatePath.ValidateExisting(path));
        if (file.Length > 65536) throw new InvalidOperationException();
        using var stream = new FileStream(file.FullName, FileMode.Open, FileAccess.Read, FileShare.Read);
        using var buffer = new MemoryStream(); var bytes = new byte[4096]; int count;
        while ((count = stream.Read(bytes, 0, bytes.Length)) != 0) { if (buffer.Length + count > 65536) throw new InvalidOperationException(); buffer.Write(bytes, 0, count); }
        using var doc = JsonDocument.Parse(buffer.ToArray(), new JsonDocumentOptions { MaxDepth = 8 });
        UniqueKeys(doc.RootElement);
        var plan = doc.RootElement.Deserialize<Plan>(new JsonSerializerOptions { UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow }) ?? throw new InvalidOperationException();
        if (plan.SchemaVersion != 1 || !Regex.IsMatch(plan.ExpectedTenantFingerprint, "\\A[a-f0-9]{64}\\z") || !Regex.IsMatch(plan.ExpectedPrincipalFingerprint, "\\A[a-f0-9]{64}\\z") || plan.MaximumAdditionalScopes < 0 || plan.MaximumAdditionalScopes > 4096 || plan.Request == null || plan.Request.Discovery || plan.Request.Protocol != "OAuth2V2Pkce") throw new InvalidOperationException();
        OAuthTransport.ValidateRequest(plan.Request);
        return plan;
    }
    private static void UniqueKeys(JsonElement element)
    {
        if (element.ValueKind == JsonValueKind.Object) {
            var keys = new HashSet<string>(StringComparer.Ordinal);
            foreach (var field in element.EnumerateObject()) { if (!keys.Add(field.Name)) throw new InvalidOperationException(); UniqueKeys(field.Value); }
        } else if (element.ValueKind == JsonValueKind.Array) foreach (var item in element.EnumerateArray()) UniqueKeys(item);
    }
    internal static SecureString ReadCredential(bool stdin, int minimum = 1, int maximum = 65536, string prompt = "Credential (hidden): ")
    {
        var result = new SecureString();
        try {
            if (stdin) {
                bool ended = false; int value;
                while ((value = Console.In.Read()) >= 0) {
                    if (value is '\r' or '\n') { ended = true; continue; }
                    if (ended || char.IsControl((char)value) || result.Length >= maximum) throw new InvalidOperationException();
                    result.AppendChar((char)value);
                }
            } else {
                Console.Error.Write(prompt);
                while (true) {
                    var key = Console.ReadKey(true);
                    if (key.Key == ConsoleKey.Enter) { Console.Error.WriteLine(); break; }
                    if (key.Key == ConsoleKey.Backspace) { if (result.Length > 0) result.RemoveAt(result.Length - 1); continue; }
                    if (char.IsControl(key.KeyChar) || result.Length >= maximum) throw new InvalidOperationException();
                    result.AppendChar(key.KeyChar);
                }
            }
            if (result.Length < minimum) throw new InvalidOperationException();
            result.MakeReadOnly(); return result;
        } catch { result.Dispose(); throw; }
    }
}
