#nullable enable
using System;
using System.Collections.Generic;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace TokenForge.Core.V0200
{
    // Configuration validation only. Path trust, locking, credential storage and login are caller-owned.
    public static class ProfilePolicy
    {
        public static void Validate(string json, string expectedName)
        {
            try
            {
                if (json == null || Encoding.UTF8.GetByteCount(json) > 32768 || expectedName == null ||
                    !Regex.IsMatch(expectedName, "\\A[a-z][a-z0-9_-]{0,63}\\z", RegexOptions.CultureInvariant)) throw new InvalidOperationException();
                using (JsonDocument document = JsonDocument.Parse(json, new JsonDocumentOptions { MaxDepth = 4 }))
                {
                    JsonElement root = document.RootElement;
                    if (root.ValueKind != JsonValueKind.Object) throw new InvalidOperationException();
                    var keys = new HashSet<string>(StringComparer.Ordinal);
                    foreach (JsonProperty property in root.EnumerateObject()) if (!keys.Add(property.Name)) throw new InvalidOperationException();
                    int version = Integer(root, "SchemaVersion", 1, 2);
                    string[] required = { "Format", "SchemaVersion", "Name", "Tenant", "StatePath", "Storage", "BootstrapClientId",
                        "MaxAdditionalScopes", "MaxBootstrapAdditionalScopes", "MaxAgeHours", "SessionRetentionHours", "PasskeyPath",
                        "XdrModulePath", "ExpectedTenantFingerprint", "ExpectedPrincipalFingerprint", "Revision", "CreatedAt", "UpdatedAt" };
                    foreach (string key in required) if (!keys.Remove(key)) throw new InvalidOperationException();
                    if (version == 2 && !keys.Remove("KeyId") || keys.Count != 0) throw new InvalidOperationException();
                    if (Text(root, "Format") != "TokenForgeProfile" || Text(root, "Name") != expectedName) throw new InvalidOperationException();
                    string tenant = Text(root, "Tenant");
                    if (!Regex.IsMatch(tenant, "\\A[a-zA-Z0-9][a-zA-Z0-9.-]{0,252}\\z", RegexOptions.CultureInvariant) ||
                        string.Equals(tenant, "common", StringComparison.OrdinalIgnoreCase) ||
                        string.Equals(tenant, "organizations", StringComparison.OrdinalIgnoreCase) ||
                        string.Equals(tenant, "consumers", StringComparison.OrdinalIgnoreCase)) throw new InvalidOperationException();
                    string storage = Text(root, "Storage");
                    if (storage != "Memory" && storage != "Passphrase" && storage != "OperatingSystem" ||
                        (storage == "OperatingSystem") != (version == 2)) throw new InvalidOperationException();
                    if (version == 2)
                    {
                        string key = Text(root, "KeyId");
                        if (!Regex.IsMatch(key, "\\A[a-f0-9]{32}\\z", RegexOptions.CultureInvariant) || key == new string('0', 32)) throw new InvalidOperationException();
                    }
                    foreach (string field in new[] { "StatePath", "PasskeyPath", "XdrModulePath" })
                        if (Text(root, field).Length > 4096) throw new InvalidOperationException();
                    foreach (string field in new[] { "BootstrapClientId", "Revision" })
                        if (!Guid.TryParse(Text(root, field), out Guid id) || id == Guid.Empty) throw new InvalidOperationException();
                    foreach (string field in new[] { "ExpectedTenantFingerprint", "ExpectedPrincipalFingerprint" })
                    {
                        JsonElement value = root.GetProperty(field);
                        if (value.ValueKind != JsonValueKind.Null && !Regex.IsMatch(Text(root, field), "\\A[a-f0-9]{64}\\z", RegexOptions.CultureInvariant)) throw new InvalidOperationException();
                    }
                    Integer(root, "MaxAdditionalScopes", 0, 8760); Integer(root, "MaxBootstrapAdditionalScopes", 0, 8760);
                    Integer(root, "MaxAgeHours", 1, 8760); Integer(root, "SessionRetentionHours", 1, 168);
                    foreach (string field in new[] { "CreatedAt", "UpdatedAt" })
                        if (!DateTimeOffset.TryParse(Text(root, field), out _)) throw new InvalidOperationException();
                    if ((Text(root, "PasskeyPath").Length != 0) != (Text(root, "XdrModulePath").Length != 0)) throw new InvalidOperationException();
                }
            }
            catch { throw new InvalidOperationException("Profile configuration is invalid. Details suppressed."); }
        }
        private static string Text(JsonElement root, string name)
        {
            JsonElement value = root.GetProperty(name);
            if (value.ValueKind != JsonValueKind.String) throw new InvalidOperationException();
            return value.GetString()!;
        }
        private static int Integer(JsonElement root, string name, int minimum, int maximum)
        {
            JsonElement value = root.GetProperty(name);
            if (value.ValueKind != JsonValueKind.Number || !value.TryGetInt32(out int number) || number < minimum || number > maximum) throw new InvalidOperationException();
            return number;
        }
    }
}
