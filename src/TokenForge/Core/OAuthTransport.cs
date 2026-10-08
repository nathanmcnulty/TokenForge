#nullable enable
using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Security;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;
using System.Threading;

namespace TokenForge.Core.V0180
{
    public sealed class OAuthRequest
    {
        public string ClientId { get; set; } = "";
        public string ResourceId { get; set; } = "";
        public string ResourceUri { get; set; } = "";
        public string Tenant { get; set; } = "organizations";
        public string RedirectUri { get; set; } = "";
        public string[] Scopes { get; set; } = Array.Empty<string>();
        public string[] OAuthScopes { get; set; } = Array.Empty<string>();
        public bool Spa { get; set; }
        public bool Discovery { get; set; }
        public string Protocol { get; set; } = "OAuth2V2Pkce";
    }
    public sealed class OAuthHttpResponse
    {
        public int Status { get; }
        public string? Location { get; }
        public string Content { get; }
        public OAuthHttpResponse(int status, string? location, string content)
        { Status = status; Location = location; Content = content ?? ""; }
    }
    public sealed class TokenClaims
    {
        public bool Readable { get; internal set; }
        public string[] Scopes { get; internal set; } = Array.Empty<string>();
        public bool HasDelegatedScopeClaim { get; internal set; }
        public string? Audience { get; internal set; }
        public string? ClientId { get; internal set; }
        public string? TenantFingerprint { get; internal set; }
        public string? PrincipalFingerprint { get; internal set; }
        public DateTimeOffset? ExpiresAt { get; internal set; }
        public bool SignatureValidated => false;
        public string Evidence => Readable ? "JwtPayloadUnverified" : "OpaqueToken";
        public static TokenClaims Read(SecureString token)
        {
            var result = new TokenClaims(); byte[]? bytes = null;
            try
            {
                string text = new NetworkCredential("", token).Password;
                if (text.Length > 262144) return result;
                var parts = text.Split('.'); if (parts.Length != 3) return result;
                string encoded = parts[1].Replace('-', '+').Replace('_', '/');
                encoded = encoded.PadRight((encoded.Length + 3) / 4 * 4, '=');
                bytes = Convert.FromBase64String(encoded);
                using var document = JsonDocument.Parse(bytes);
                var root = document.RootElement; if (root.ValueKind != JsonValueKind.Object) return result;
                // Ambiguous duplicate claims never establish readable context.
                if (root.EnumerateObject().Select(p => p.Name).Distinct(StringComparer.Ordinal).Count() != root.EnumerateObject().Count()) return result;
                result.Readable = true;
                result.HasDelegatedScopeClaim = root.TryGetProperty("scp", out _);
                string? scope = Text(root, "scp");
                result.Scopes = Regex.Split(scope ?? "", @"\s+").Where(s => Regex.IsMatch(s, @"^[A-Za-z0-9_.-]+$")).Distinct(StringComparer.Ordinal).OrderBy(s => s, StringComparer.Ordinal).ToArray();
                result.Audience = Text(root, "aud");
                result.ClientId = Text(root, "azp") ?? Text(root, "appid");
                string? tenant = Text(root, "tid"), principal = Text(root, "oid");
                if (!string.IsNullOrEmpty(tenant)) result.TenantFingerprint = Fingerprint(tenant);
                if (!string.IsNullOrEmpty(tenant) && !string.IsNullOrEmpty(principal)) result.PrincipalFingerprint = Fingerprint(tenant + "/" + principal);
                if (root.TryGetProperty("exp", out var expiry) && expiry.ValueKind == JsonValueKind.Number && expiry.TryGetInt64(out long seconds))
                    try { result.ExpiresAt = DateTimeOffset.FromUnixTimeSeconds(seconds); } catch (ArgumentOutOfRangeException) { }
            }
            catch (Exception e) when (e is FormatException || e is JsonException || e is ArgumentException) { return new TokenClaims(); }
            finally { if (bytes != null) CryptographicOperations.ZeroMemory(bytes); }
            return result;
        }
        internal static string? Text(JsonElement root, string name) => root.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() : null;
        private static string Fingerprint(string value)
        { byte[] bytes = Encoding.UTF8.GetBytes(value); try { return Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant(); } finally { CryptographicOperations.ZeroMemory(bytes); } }
    }
    public sealed class OAuthResult : IDisposable
    {
        public string ClientId { get; internal set; } = "";
        public string ResourceId { get; internal set; } = "";
        public string[] RequestedScopes { get; internal set; } = Array.Empty<string>();
        public string[] GrantedScopes { get; internal set; } = Array.Empty<string>();
        public string[] AdditionalScopes { get; internal set; } = Array.Empty<string>();
        public string ScopeEvidence { get; internal set; } = "Unverified";
        public DateTimeOffset? ExpiresAt { get; internal set; }
        public string TokenType { get; internal set; } = "Bearer";
        public TokenClaims TokenClaims { get; internal set; } = new TokenClaims();
        public bool Discovery { get; internal set; }
        public string Protocol { get; internal set; } = "";
        [JsonIgnore] public SecureString AccessToken { get; internal set; } = new SecureString();
        [JsonIgnore] public SecureString? RefreshToken { get; internal set; }
        public void Dispose() { AccessToken.Dispose(); RefreshToken?.Dispose(); }
    }
    public static class OAuthTransport
    {
        public const int MaximumResponseBytes = 2 * 1024 * 1024;
        private static readonly string[] Oidc = { "openid", "profile", "email", "offline_access" };
        public static OAuthResult Cookie(OAuthRequest request, SecureString cookie, string name = "ESTSAUTH", CancellationToken cancellation = default)
            => Acquire(request, "Cookie", cookie, null, null, name, null, cancellation);
        public static OAuthResult Refresh(OAuthRequest request, SecureString refresh, CancellationToken cancellation = default)
            => Acquire(request, "Refresh", refresh, null, null, "ESTSAUTH", null, cancellation);
        public static OAuthResult RedeemCode(OAuthRequest request, SecureString code, SecureString verifier, string redirect, CancellationToken cancellation = default)
            => Acquire(request, "Code", code, verifier, redirect, "ESTSAUTH", null, cancellation);
        // A per-call synchronous adapter/test seam. Native production callers use the methods above.
        public static OAuthResult AcquireForAdapter(OAuthRequest request, string mode, SecureString credential, SecureString? verifier, string? redirect, string cookieName,
            Func<HttpClient, Uri, Dictionary<string, string>?, string?, OAuthHttpResponse> adapter)
            => Acquire(request, mode, credential, verifier, redirect, cookieName, adapter, default);
        public static void ValidateRequest(OAuthRequest request) => Snapshot(request);
        private static OAuthRequest Snapshot(OAuthRequest p)
        {
            if (p == null) throw new InvalidOperationException("Invalid request client or tenant.");
            // Validate only the owned snapshot; a caller may mutate its original concurrently.
            p = new OAuthRequest { ClientId = p.ClientId, ResourceId = p.ResourceId, ResourceUri = p.ResourceUri, Tenant = p.Tenant, RedirectUri = p.RedirectUri, Scopes = (p.Scopes ?? Array.Empty<string>()).ToArray(), OAuthScopes = (p.OAuthScopes ?? Array.Empty<string>()).ToArray(), Spa = p.Spa, Discovery = p.Discovery, Protocol = p.Protocol };
            if (p == null || !Guid.TryParse(p.ClientId, out var client) || client == Guid.Empty || !Guid.TryParse(p.ResourceId, out var resource) || resource == Guid.Empty ||
                !Regex.IsMatch(p.Tenant ?? "", @"^(organizations|common|consumers|[a-zA-Z0-9][a-zA-Z0-9.-]{0,252})$")) throw new InvalidOperationException("Invalid request client or tenant.");
            Uri uri = Redirect(p.RedirectUri);
            if (p.Spa && uri.Scheme != "https") throw new InvalidOperationException("SPA requests require HTTPS.");
            string[] scopes = (p.Scopes ?? Array.Empty<string>()).ToArray(), oauth = (p.OAuthScopes ?? Array.Empty<string>()).ToArray();
            if (scopes.Length > 1024 || oauth.Length > 1025 || string.IsNullOrEmpty(p.ResourceUri) || p.ResourceUri.Length > 2048) throw new InvalidOperationException("Invalid request scopes.");
            if (!p.Discovery && (scopes.Length == 0 || scopes.Any(s => s == null || s.Length > 256 || !Regex.IsMatch(s, @"^[A-Za-z0-9_-][A-Za-z0-9_.-]*$") || Oidc.Contains(s, StringComparer.Ordinal)))) throw new InvalidOperationException("Invalid request scope names.");
            if (p.Discovery && (scopes.Length != 0 || p.ResourceUri != p.ResourceId)) throw new InvalidOperationException("Discovery requests must use one resource application ID and no asserted API scopes.");
            var expected = p.Discovery ? new[] { p.ResourceId + "/.default" } : scopes.Select(s => p.ResourceUri.TrimEnd('/') + "/" + s).ToArray();
            if (oauth.Length == 0 || oauth.Any(s => s == null || (s != "offline_access" && !expected.Contains(s, StringComparer.Ordinal))) || expected.Any(s => !oauth.Contains(s, StringComparer.Ordinal))) throw new InvalidOperationException("Request OAuth scopes do not match the plan.");
            if (!new[] { "OAuth2V2Pkce", "OAuth2V2Implicit", "OAuth2V1Implicit" }.Contains(p.Protocol, StringComparer.Ordinal) || (p.Protocol != "OAuth2V2Pkce" && !p.Discovery)) throw new InvalidOperationException("Implicit protocols are available only for explicit discovery plans.");
            return new OAuthRequest { ClientId = p.ClientId, ResourceId = p.ResourceId, ResourceUri = p.ResourceUri, Tenant = p.Tenant!, RedirectUri = p.RedirectUri, Scopes = scopes, OAuthScopes = oauth, Spa = p.Spa, Discovery = p.Discovery, Protocol = p.Protocol };
        }
        private static Uri Redirect(string value)
        {
            if (value == null || value.Length > 2048 || !Uri.TryCreate(value, UriKind.Absolute, out var uri) || uri.UserInfo.Length != 0 || uri.Query.Length != 0 || uri.Fragment.Length != 0) throw new InvalidOperationException("Invalid request redirect URI.");
            return uri;
        }
        private static void Identity(Uri uri)
        {
            if (!uri.IsAbsoluteUri || uri.AbsoluteUri.Length > 262144 || uri.Scheme != "https" || uri.Host != "login.microsoftonline.com" || uri.Port != 443 || uri.UserInfo.Length != 0 || uri.Fragment.Length != 0)
                throw new InvalidOperationException("Authorization redirected outside the supported identity host. Browser interaction may be required.");
        }
        public static OAuthHttpResponse Send(HttpClient client, Uri uri, Dictionary<string, string>? form, string? origin, CancellationToken cancellation = default)
        {
            Identity(uri);
            using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellation); deadline.CancelAfter(TimeSpan.FromSeconds(30));
            using var request = new HttpRequestMessage(form == null ? HttpMethod.Get : HttpMethod.Post, uri);
            if (form != null) request.Content = new FormUrlEncodedContent(form);
            if (origin != null) request.Headers.Add("Origin", origin);
            try
            {
                using var response = client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, deadline.Token).GetAwaiter().GetResult();
                if (response.Content.Headers.ContentLength > MaximumResponseBytes) throw new InvalidOperationException("Identity response exceeded the supported size.");
                using var stream = response.Content.ReadAsStreamAsync(deadline.Token).GetAwaiter().GetResult();
                using var buffer = new MemoryStream(); byte[] bytes = new byte[8192];
                try
                {
                    int count;
                    while ((count = stream.ReadAsync(bytes.AsMemory(), deadline.Token).AsTask().GetAwaiter().GetResult()) != 0)
                    { if (buffer.Length + count > MaximumResponseBytes) throw new InvalidOperationException("Identity response exceeded the supported size."); buffer.Write(bytes, 0, count); }
                    string content = Encoding.UTF8.GetString(buffer.GetBuffer(), 0, (int)buffer.Length);
                    string? location = response.Headers.Location?.OriginalString;
                    if (location?.Length > 262144) throw new InvalidOperationException("Identity redirect exceeded the supported size.");
                    return new OAuthHttpResponse((int)response.StatusCode, location, content);
                }
                finally { CryptographicOperations.ZeroMemory(bytes); if (buffer.TryGetBuffer(out var memory)) CryptographicOperations.ZeroMemory(memory.AsSpan()); }
            }
            catch (InvalidOperationException e) when (e.Message == "Identity response exceeded the supported size." || e.Message == "Identity redirect exceeded the supported size.") { throw; }
            catch { throw new InvalidOperationException("Identity transport failed or timed out. Request and response details suppressed."); }
        }
        private static OAuthResult Acquire(OAuthRequest source, string mode, SecureString credential, SecureString? browserVerifier, string? browserRedirect, string cookieName,
            Func<HttpClient, Uri, Dictionary<string, string>?, string?, OAuthHttpResponse>? adapter, CancellationToken cancellation)
        {
            OAuthRequest p = Snapshot(source); Uri redirect = Redirect(p.RedirectUri);
            bool implicitFlow = p.Protocol != "OAuth2V2Pkce";
            if (mode != "Cookie" && mode != "Refresh" && mode != "Code") throw new InvalidOperationException("Invalid credential operation.");
            if (implicitFlow && mode != "Cookie") throw new InvalidOperationException("Implicit discovery does not redeem refresh tokens; use a PKCE request plan.");
            if (credential == null || credential.Length == 0 || credential.Length > 262144) throw new InvalidOperationException("Credential is empty or exceeds the supported size.");
            string authority = "https://login.microsoftonline.com/" + p.Tenant + (p.Protocol == "OAuth2V1Implicit" ? "/oauth2" : "/oauth2/v2.0");
            using var handler = new HttpClientHandler { AllowAutoRedirect = false, CookieContainer = new CookieContainer() };
            using var client = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(30) };
            var form = new Dictionary<string, string> { ["client_id"] = p.ClientId, ["scope"] = string.Join(" ", p.OAuthScopes) };
            Dictionary<string, string>? tokens = null;
            OAuthHttpResponse Exchange(Uri uri, Dictionary<string, string>? fields = null, string? origin = null)
            {
                cancellation.ThrowIfCancellationRequested(); Identity(uri);
                // The seam receives only validated identity requests. It cannot alter callback/state rules.
                OAuthHttpResponse response;
                try { response = adapter == null ? Send(client, uri, fields, origin, cancellation) : adapter(client, uri, fields, origin); }
                catch { throw new InvalidOperationException("Identity transport failed or timed out. Request and response details suppressed."); }
                if (response == null || Encoding.UTF8.GetByteCount(response.Content) > MaximumResponseBytes || response.Location?.Length > 262144) throw new InvalidOperationException("Identity response exceeded the supported size.");
                return response;
            }
            try
            {
                if (mode == "Refresh") { form["grant_type"] = "refresh_token"; form["refresh_token"] = new NetworkCredential("", credential).Password; }
                else if (mode == "Code")
                {
                    Uri runtime = Redirect(browserRedirect ?? "");
                    if (runtime.GetLeftPart(UriPartial.Path) != redirect.GetLeftPart(UriPartial.Path) && !(runtime.Scheme == "http" && redirect.Scheme == "http" && runtime.IsLoopback && redirect.IsLoopback && runtime.Host == redirect.Host && runtime.Port > 0 && runtime.AbsolutePath == redirect.AbsolutePath)) throw new InvalidOperationException("Browser redirect does not match the request.");
                    string verifier = browserVerifier == null ? "" : new NetworkCredential("", browserVerifier).Password;
                    if (!Regex.IsMatch(verifier, @"^[A-Za-z0-9._~-]{43,128}$")) throw new InvalidOperationException("Invalid authorization verifier.");
                    form["grant_type"] = "authorization_code"; form["code"] = new NetworkCredential("", credential).Password; form["code_verifier"] = verifier; form["redirect_uri"] = runtime.OriginalString;
                }
                else
                {
                    if (cookieName != "ESTSAUTH" && cookieName != "ESTSAUTHPERSISTENT") throw new InvalidOperationException("Invalid cookie name.");
                    try { handler.CookieContainer.Add(new Cookie(cookieName, new NetworkCredential("", credential).Password, "/", "login.microsoftonline.com") { Secure = true, HttpOnly = true }); }
                    catch { throw new InvalidOperationException("Invalid cookie value. Supply only the cookie value as SecureString."); }
                    byte[] random = RandomNumberGenerator.GetBytes(32);
                    string verifier = Convert.ToBase64String(random).TrimEnd('=').Replace('+', '-').Replace('/', '_'); CryptographicOperations.ZeroMemory(random);
                    string challenge = Convert.ToBase64String(SHA256.HashData(Encoding.ASCII.GetBytes(verifier))).TrimEnd('=').Replace('+', '-').Replace('/', '_');
                    string state = Convert.ToHexString(RandomNumberGenerator.GetBytes(32));
                    var query = new Dictionary<string, string> { ["client_id"] = p.ClientId, ["redirect_uri"] = p.RedirectUri, ["scope"] = form["scope"], ["response_type"] = "code", ["response_mode"] = "query", ["prompt"] = "none", ["code_challenge"] = challenge, ["code_challenge_method"] = "S256", ["state"] = state };
                    if (implicitFlow)
                    { query["response_type"] = "token"; query["response_mode"] = "fragment"; query.Remove("code_challenge"); query.Remove("code_challenge_method"); query["scope"] = p.ResourceId + "/.default"; if (p.Protocol == "OAuth2V1Implicit") { query.Remove("scope"); query["resource"] = p.ResourceId; } }
                    Uri url = new Uri(authority + "/authorize?" + string.Join("&", query.Select(k => Uri.EscapeDataString(k.Key) + "=" + Uri.EscapeDataString(k.Value))));
                    string? code = null;
                    for (int step = 0; step < 10; step++)
                    {
                        var response = Exchange(url);
                        if (!new[] { 301, 302, 303, 307, 308 }.Contains(response.Status) || string.IsNullOrEmpty(response.Location)) throw new InvalidOperationException(Failure(response.Content, "Silent authorization did not return a redirect (HTTP " + response.Status.ToString(CultureInfo.InvariantCulture) + "). Sign-in, consent, MFA, a policy interrupt, or an unsupported HTML flow may require browser interaction."));
                        if (!Uri.TryCreate(url, response.Location, out var next)) throw new InvalidOperationException("Authorization returned an invalid redirect.");
                        if (next.GetLeftPart(UriPartial.Path) == redirect.GetLeftPart(UriPartial.Path))
                        {
                            var values = System.Web.HttpUtility.ParseQueryString(implicitFlow ? next.Fragment.TrimStart('#') : next.Query);
                            if (values.GetValues("state")?.Length != 1 || values["state"] != state) throw new InvalidOperationException("Authorization state mismatch.");
                            if (values["error"] != null) throw new InvalidOperationException(Failure(values["error_description"] ?? "", "Silent authorization was declined. Interactive sign-in, consent, or tenant policy may be required."));
                            if (implicitFlow)
                            {
                                if (values.GetValues("access_token")?.Length != 1 || string.IsNullOrWhiteSpace(values["access_token"]) || next.Query.Length != 0) throw new InvalidOperationException("Implicit authorization callback is missing a valid token.");
                                tokens = new Dictionary<string, string>(); foreach (string key in new[] { "access_token", "token_type", "expires_in", "scope" }) if (values[key] != null) tokens[key] = values[key]!;
                            }
                            else
                            { if (values.GetValues("code")?.Length != 1 || string.IsNullOrWhiteSpace(values["code"]) || next.Fragment.Length != 0) throw new InvalidOperationException("Authorization callback is missing a valid code."); code = values["code"]; }
                            break;
                        }
                        Identity(next); url = next;
                    }
                    if (code == null && tokens == null) throw new InvalidOperationException("Authorization exceeded the redirect limit.");
                    if (!implicitFlow) { form["grant_type"] = "authorization_code"; form["code"] = code!; form["code_verifier"] = verifier; form["redirect_uri"] = p.RedirectUri; }
                }
                if (tokens == null)
                {
                    var response = Exchange(new Uri(authority + "/token"), form, p.Spa ? redirect.GetLeftPart(UriPartial.Authority) : null);
                    if (response.Status != 200) throw new InvalidOperationException(Failure(response.Content, "Token request failed (HTTP " + response.Status + "). Identity response details suppressed; verify session, client flow, consent, and tenant policy."));
                    try
                    {
                        using var document = JsonDocument.Parse(response.Content); var root = document.RootElement;
                        if (root.ValueKind != JsonValueKind.Object || root.EnumerateObject().Select(k => k.Name).Distinct(StringComparer.Ordinal).Count() != root.EnumerateObject().Count()) throw new JsonException();
                        tokens = new Dictionary<string, string>();
                        foreach (string key in new[] { "access_token", "refresh_token", "token_type", "scope", "expires_in" }) if (root.TryGetProperty(key, out var value))
                        { if (value.ValueKind == JsonValueKind.String) tokens[key] = value.GetString()!; else if (key == "expires_in" && value.ValueKind == JsonValueKind.Number) tokens[key] = value.GetRawText(); }
                    }
                    catch (JsonException) { throw new InvalidOperationException("Token endpoint returned invalid JSON."); }
                }
                if (!tokens.TryGetValue("access_token", out var access) || string.IsNullOrEmpty(access) || access.Length > 65536 || !tokens.TryGetValue("token_type", out var type) || !string.Equals(type, "Bearer", StringComparison.OrdinalIgnoreCase)) throw new InvalidOperationException("Token endpoint returned no usable bearer token.");
                string[] granted = tokens.TryGetValue("scope", out var scope) ? scope.Split(' ', StringSplitOptions.RemoveEmptyEntries) : Array.Empty<string>();
                var expected = p.Scopes.Select(s => p.ResourceUri.TrimEnd('/') + "/" + s).ToArray();
                if (granted.Length > 0 && p.Scopes.Any(s => !granted.Contains(s, StringComparer.Ordinal) && !granted.Contains(p.ResourceUri.TrimEnd('/') + "/" + s, StringComparer.Ordinal))) throw new InvalidOperationException("Token response is missing one or more requested API scopes. No token returned.");
                var result = new OAuthResult { ClientId = p.ClientId, ResourceId = p.ResourceId, RequestedScopes = p.Scopes, GrantedScopes = granted, AdditionalScopes = granted.Where(s => !Oidc.Contains(s, StringComparer.Ordinal) && !p.Scopes.Contains(s, StringComparer.Ordinal) && !expected.Contains(s, StringComparer.Ordinal)).ToArray(), ScopeEvidence = granted.Length > 0 ? "TokenResponse" : "Unverified", TokenType = type, Discovery = p.Discovery, Protocol = p.Protocol };
                try
                {
                    result.AccessToken.Dispose(); result.AccessToken = Secure(access);
                    result.TokenClaims = TokenClaims.Read(result.AccessToken);
                    if (result.TokenClaims.HasDelegatedScopeClaim && p.Scopes.Any(s => !result.TokenClaims.Scopes.Contains(s, StringComparer.Ordinal))) throw new InvalidOperationException("Decoded scp is missing one or more requested API scopes. No token returned.");
                    if (tokens.TryGetValue("expires_in", out var expiry) && double.TryParse(expiry, NumberStyles.Float, CultureInfo.InvariantCulture, out double seconds) && double.IsFinite(seconds) && seconds >= 0 && seconds <= 604800) result.ExpiresAt = DateTimeOffset.UtcNow.AddSeconds(seconds);
                    if (tokens.TryGetValue("refresh_token", out var refresh) && refresh.Length > 0) { if (refresh.Length > 65536) throw new InvalidOperationException("Token endpoint returned an oversized refresh credential."); result.RefreshToken = Secure(refresh); }
                    return result;
                }
                catch { result.Dispose(); throw; }
            }
            finally { form.Clear(); tokens?.Clear(); }
        }
        private static SecureString Secure(string value) { var s = new SecureString(); try { foreach (char c in value) s.AppendChar(c); s.MakeReadOnly(); return s; } catch { s.Dispose(); throw; } }
        private static string Failure(string content, string fallback)
        {
            var codes = Regex.Matches(content, @"\bAADSTS([0-9]{4,9})\b").Select(m => m.Groups[1].Value).Distinct(StringComparer.Ordinal).OrderBy(s => s, StringComparer.Ordinal).Take(5).ToArray();
            if (codes.Length == 0) return fallback;
            string suffix = string.Join(", ", codes.Select(s => "AADSTS" + s));
            return codes.Contains("50011") ? "Identity request failed (" + suffix + "). Entra rejected the redirect URI; published metadata may differ from the current app registration. Response details suppressed." : fallback + " Identity error codes: " + suffix + ".";
        }
    }
}
