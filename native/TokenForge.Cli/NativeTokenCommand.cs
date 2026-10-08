using System.Security;
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
        if (args.Length is not (6 or 7) || args[2] != "--plan" || args[4] != "--credential" || args[5] is not ("cookie" or "refresh") || args.Length == 7 && args[6] != "--stdin") throw new InvalidOperationException();
        var plan = ReadPlan(args[3]);
        bool stdin = args.Length == 7;
        if (!stdin && Console.IsInputRedirected) throw new InvalidOperationException();
        using var cancellation = new CancellationTokenSource();
        ConsoleCancelEventHandler cancel = (_, e) => { e.Cancel = true; cancellation.Cancel(); };
        stage = "CredentialInputFailed";
        using var secret = ReadCredential(stdin);
        Console.CancelKeyPress += cancel;
        try
        {
            cancellation.Token.ThrowIfCancellationRequested();
            stage = "TokenAcquisitionFailed";
            using var result = args[5] == "cookie" ? OAuthTransport.Cookie(plan.Request, secret, cancellation: cancellation.Token) : OAuthTransport.Refresh(plan.Request, secret, cancellation.Token);
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
    private static SecureString ReadCredential(bool stdin)
    {
        var result = new SecureString();
        try {
            if (stdin) {
                bool ended = false; int value;
                while ((value = Console.In.Read()) >= 0) {
                    if (value is '\r' or '\n') { ended = true; continue; }
                    if (ended || char.IsControl((char)value) || result.Length >= 65536) throw new InvalidOperationException();
                    result.AppendChar((char)value);
                }
            } else {
                Console.Error.Write("Credential (hidden): ");
                while (true) {
                    var key = Console.ReadKey(true);
                    if (key.Key == ConsoleKey.Enter) { Console.Error.WriteLine(); break; }
                    if (key.Key == ConsoleKey.Backspace) { if (result.Length > 0) result.RemoveAt(result.Length - 1); continue; }
                    if (char.IsControl(key.KeyChar) || result.Length >= 65536) throw new InvalidOperationException();
                    result.AppendChar(key.KeyChar);
                }
            }
            if (result.Length == 0) throw new InvalidOperationException();
            result.MakeReadOnly(); return result;
        } catch { result.Dispose(); throw; }
    }
}

internal sealed class NativeTokenException : Exception
{
    public string Code { get; }
    public string Reason { get; }
    public string[] IdentityErrorCodes { get; }
    public int? HttpStatus { get; }
    public NativeTokenException(string code, string diagnostic)
    {
        Code = code;
        Reason = diagnostic.StartsWith("Silent authorization", StringComparison.Ordinal) ? "SilentAuthorizationDeclined" : diagnostic.StartsWith("Identity transport", StringComparison.Ordinal) ? "TransportFailed" : diagnostic.StartsWith("Token request failed", StringComparison.Ordinal) ? "TokenEndpointRejected" : "ValidationFailed";
        IdentityErrorCodes = Regex.Matches(diagnostic, @"\bAADSTS([0-9]{4,9})\b").Select(m => m.Groups[1].Value).Distinct().Take(5).ToArray();
        var status = Regex.Match(diagnostic, @"\bHTTP ([1-5][0-9]{2})\b");
        HttpStatus = status.Success ? int.Parse(status.Groups[1].Value) : null;
    }
}
