#nullable enable
using System;
using System.Collections.Generic;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace TokenForge.Core.V0250
{
    // Validate decrypted records before projection or publication. Authentication, expiry,
    // token claims and credential ownership remain the acquisition/retrieval caller's policy.
    public static class VaultRecordPolicy
    {
        public static void Validate(byte[]? plaintext)
        {
            try
            {
                if (plaintext == null || plaintext.Length > 8388608) throw new InvalidOperationException();
                using (JsonDocument document = JsonDocument.Parse(plaintext, new JsonDocumentOptions { MaxDepth = 8 }))
                {
                    JsonElement root = document.RootElement;
                    Fields(root, new[] { "SchemaVersion", "Sessions" });
                    if (Integer(root, "SchemaVersion") != 1) throw new InvalidOperationException();
                    JsonElement sessions = root.GetProperty("Sessions");
                    UniqueObject(sessions);
                    foreach (JsonProperty named in sessions.EnumerateObject())
                    {
                        Match(named.Name, "\\A[a-zA-Z][a-zA-Z0-9_-]{0,63}\\z");
                        JsonElement session = named.Value;
                        Fields(session, new[] { "TenantFingerprint", "PrincipalFingerprint", "Revision", "CreatedAt", "LastConfirmedAt", "RetainUntil", "Cookie", "CookieName", "Tokens" });
                        foreach (string field in new[] { "TenantFingerprint", "PrincipalFingerprint" }) Match(Text(session, field, 64), "\\A[a-f0-9]{64}\\z");
                        GuidValue(session, "Revision");
                        foreach (string field in new[] { "CreatedAt", "LastConfirmedAt", "RetainUntil" }) Date(session, field, false);
                        NullableText(session, "Cookie", 1048576);
                        string? cookieName = NullableText(session, "CookieName", 32);
                        if (cookieName != null && cookieName != "ESTSAUTH" && cookieName != "ESTSAUTHPERSISTENT" || session.GetProperty("Cookie").ValueKind != JsonValueKind.Null && cookieName == null) throw new InvalidOperationException();
                        JsonElement tokens = session.GetProperty("Tokens");
                        UniqueObject(tokens);
                        foreach (JsonProperty entry in tokens.EnumerateObject()) Token(entry.Name, entry.Value);
                    }
                }
            }
            catch { throw new InvalidOperationException("Vault credential records are invalid. Details suppressed."); }
        }
        private static void Token(string id, JsonElement token)
        {
            Match(id, "\\A[a-f0-9]{64}\\z");
            Fields(token, new[] { "Id", "ClientId", "ResourceId", "Tenant", "Audience", "Scopes", "IssuedScopes", "AdditionalScopeCount", "RedirectUri", "Spa", "OfflineAccess", "Protocol", "AcquiredAt", "ExpiresAt", "AccessToken", "RefreshToken", "ConsentEvidence" });
            if (Text(token, "Id", 64) != id) throw new InvalidOperationException();
            GuidValue(token, "ClientId"); GuidValue(token, "ResourceId");
            foreach (string field in new[] { "Tenant", "Audience", "RedirectUri", "Protocol" }) Text(token, field, 4096);
            ScopeArray(token, "Scopes"); ScopeArray(token, "IssuedScopes");
            if (Integer(token, "AdditionalScopeCount") < 0) throw new InvalidOperationException();
            foreach (string field in new[] { "Spa", "OfflineAccess" })
            {
                JsonValueKind kind = token.GetProperty(field).ValueKind;
                if (kind != JsonValueKind.True && kind != JsonValueKind.False) throw new InvalidOperationException();
            }
            Date(token, "AcquiredAt", false); Date(token, "ExpiresAt", true);
            Text(token, "AccessToken", 1048576); NullableText(token, "RefreshToken", 1048576);
            NullableText(token, "ConsentEvidence", 65536);
        }
        private static void UniqueObject(JsonElement value)
        {
            if (value.ValueKind != JsonValueKind.Object) throw new InvalidOperationException();
            var keys = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (JsonProperty property in value.EnumerateObject()) if (!keys.Add(property.Name)) throw new InvalidOperationException();
        }
        private static void Fields(JsonElement value, string[] required)
        {
            UniqueObject(value);
            var remaining = new HashSet<string>(required, StringComparer.Ordinal);
            foreach (JsonProperty property in value.EnumerateObject()) if (!remaining.Remove(property.Name)) throw new InvalidOperationException();
            if (remaining.Count != 0) throw new InvalidOperationException();
        }
        private static string Text(JsonElement parent, string field, int maximum)
        {
            JsonElement value = parent.GetProperty(field);
            if (value.ValueKind != JsonValueKind.String) throw new InvalidOperationException();
            string text = value.GetString()!;
            if (text.Length == 0 || text.Length > maximum || text.IndexOf('\0') >= 0) throw new InvalidOperationException();
            return text;
        }
        private static string? NullableText(JsonElement parent, string field, int maximum)
        {
            return parent.GetProperty(field).ValueKind == JsonValueKind.Null ? null : Text(parent, field, maximum);
        }
        private static int Integer(JsonElement parent, string field)
        {
            JsonElement value = parent.GetProperty(field);
            if (value.ValueKind != JsonValueKind.Number || !value.TryGetInt32(out int number)) throw new InvalidOperationException();
            return number;
        }
        private static void Date(JsonElement parent, string field, bool nullable)
        {
            if (nullable && parent.GetProperty(field).ValueKind == JsonValueKind.Null) return;
            // Legacy strings retain the existing current-culture semantics; no DateTime projection occurs here.
            if (!DateTimeOffset.TryParse(Text(parent, field, 128), out _)) throw new InvalidOperationException();
        }
        private static void GuidValue(JsonElement parent, string field)
        {
            if (!Guid.TryParse(Text(parent, field, 64), out Guid id) || id == Guid.Empty) throw new InvalidOperationException();
        }
        private static void Match(string text, string pattern)
        {
            if (!Regex.IsMatch(text, pattern, RegexOptions.CultureInvariant)) throw new InvalidOperationException();
        }
        private static void ScopeArray(JsonElement parent, string field)
        {
            JsonElement value = parent.GetProperty(field);
            if (value.ValueKind != JsonValueKind.Array) throw new InvalidOperationException();
            foreach (JsonElement scope in value.EnumerateArray())
            {
                if (scope.ValueKind != JsonValueKind.String) throw new InvalidOperationException();
                string text = scope.GetString()!;
                if (text.Length == 0 || text.Length > 4096 || text.IndexOf('\0') >= 0) throw new InvalidOperationException();
                foreach (char character in text) if (char.IsWhiteSpace(character)) throw new InvalidOperationException();
            }
        }
    }
}
