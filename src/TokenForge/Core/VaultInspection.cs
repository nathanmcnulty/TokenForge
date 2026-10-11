using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Buffers;
using System.Security;
using System.Security.Cryptography;
using System.Text.Json;
using TokenForge.Core.V0190;
using TokenForge.Core.V0220;
using TokenForge.Core.V0250;

namespace TokenForge.Core;

// The result contains only newly allocated metadata; no credential-bearing JSON elements escape.
public sealed record VaultInspection(int SchemaVersion, string GeneratedAt, string Protection, VaultSessionMetadata[] Sessions, string Evidence);
public sealed record VaultSessionMetadata(string Name, string TenantFingerprint, string PrincipalFingerprint, string? CookieName, bool HasCookie,
    string CreatedAt, string LastConfirmedAt, string RetainUntil, bool RetentionExpired, VaultTokenMetadata[] Tokens);
public sealed record VaultTokenMetadata(string Id, string ClientId, string ResourceId, string Audience, string[] RequestedScopes, string[] IssuedScopes,
    int AdditionalScopeCount, string AcquiredAt, string? ExpiresAt, bool HasRefreshToken, string ExpiryStatus, string Protocol, string? ConsentEvidence, bool SignatureValidated);

internal static class VaultInspector
{
    internal static VaultInspection Inspect(VaultFileTransaction transaction, SecureString password, string sessionName, string? tenant, string? principal, DateTimeOffset now)
    {
        byte[]? plaintext = null;
        try
        {
            plaintext = VaultEnvelope.Decrypt(transaction.ReadEnvelope(), password);
            VaultRecordPolicy.Validate(plaintext);
            using var document = JsonDocument.Parse(plaintext);
            var sessions = new List<VaultSessionMetadata>();
            foreach (var item in document.RootElement.GetProperty("Sessions").EnumerateObject())
            {
                if (!string.Equals(item.Name, sessionName, StringComparison.OrdinalIgnoreCase)) continue;
                var session = item.Value;
                if (tenant == null || principal == null || Text(session,"TenantFingerprint") != tenant || Text(session,"PrincipalFingerprint") != principal) throw new InvalidOperationException();
                var tokens = new List<VaultTokenMetadata>();
                foreach (var saved in session.GetProperty("Tokens").EnumerateObject())
                {
                    var token = saved.Value;
                    string? expiry = NullableText(token,"ExpiresAt");
                    tokens.Add(new VaultTokenMetadata(Text(token,"Id"), Text(token,"ClientId"), Text(token,"ResourceId"), Text(token,"Audience"),
                        Strings(token,"Scopes"), Strings(token,"IssuedScopes"), token.GetProperty("AdditionalScopeCount").GetInt32(), Text(token,"AcquiredAt"), expiry,
                        token.GetProperty("RefreshToken").ValueKind != JsonValueKind.Null, expiry == null ? "Unknown" : DateTimeOffset.Parse(expiry) <= now.AddMinutes(2) ? "ExpiredOrNearExpiry" : "WithinReportedLifetime",
                        Text(token,"Protocol"), NullableText(token,"ConsentEvidence"), false));
                }
                string retention = Text(session,"RetainUntil");
                sessions.Add(new VaultSessionMetadata(item.Name, Text(session,"TenantFingerprint"), Text(session,"PrincipalFingerprint"), NullableText(session,"CookieName"),
                    session.GetProperty("Cookie").ValueKind != JsonValueKind.Null, Text(session,"CreatedAt"), Text(session,"LastConfirmedAt"), retention, DateTimeOffset.Parse(retention) <= now,
                    tokens.OrderBy(t=>t.ClientId,StringComparer.Ordinal).ThenBy(t=>t.ResourceId,StringComparer.Ordinal).ThenBy(t=>t.Id,StringComparer.Ordinal).ToArray()));
            }
            return new VaultInspection(1,now.ToString("o"),"Passphrase-AES-256-GCM",sessions.ToArray(),"StoredMetadataNotNewIssuanceOrApiAuthorization");
        }
        catch { throw new InvalidOperationException("Vault inspection failed. Details suppressed."); }
        finally { if (plaintext != null) CryptographicOperations.ZeroMemory(plaintext); }
    }
    // Explicit local cleanup preserves unrelated sessions without projecting their credentials.
    internal static void RemoveSession(VaultFileTransaction transaction, SecureString password, string sessionName)
    {
        byte[]? plaintext = null, rewritten = null;
        try
        {
            plaintext = VaultEnvelope.Decrypt(transaction.ReadEnvelope(),password);
            VaultRecordPolicy.Validate(plaintext);
            using var document = JsonDocument.Parse(plaintext);
            var sessions = document.RootElement.GetProperty("Sessions");
            if (!sessions.EnumerateObject().Any(s=>string.Equals(s.Name,sessionName,StringComparison.OrdinalIgnoreCase))) return;
            rewritten = Serialize(writer =>
            {
                writer.WriteStartObject();writer.WriteNumber("SchemaVersion",1);writer.WriteStartObject("Sessions");
                foreach(var session in sessions.EnumerateObject())
                {
                    if(string.Equals(session.Name,sessionName,StringComparison.OrdinalIgnoreCase))continue;
                    writer.WritePropertyName(session.Name);session.Value.WriteTo(writer);
                }
                writer.WriteEndObject();writer.WriteEndObject();
            });
            VaultRecordPolicy.Validate(rewritten);
            transaction.Commit(VaultEnvelope.Encrypt(rewritten,password));
        }
        catch { throw new InvalidOperationException("Vault session removal failed. Details suppressed."); }
        finally
        {
            if (plaintext != null) CryptographicOperations.ZeroMemory(plaintext);
            if (rewritten != null) CryptographicOperations.ZeroMemory(rewritten);
        }
    }
    internal static byte[] Serialize(Action<Utf8JsonWriter> write)
    {
        byte[] buffer = new byte[VaultEnvelope.MaximumPlaintextBytes];
        try
        {
            var output = new BoundedCredentialWriter(buffer);
            using(var writer = new Utf8JsonWriter(output)){write(writer);writer.Flush();}
            return buffer.AsSpan(0,output.WrittenCount).ToArray();
        }
        finally { CryptographicOperations.ZeroMemory(buffer); }
    }
    // Stream writers allocate a growing internal buffer. This writer owns no extra array.
    private sealed class BoundedCredentialWriter(byte[] bytes) : IBufferWriter<byte>
    {
        public int WrittenCount { get; private set; }
        public void Advance(int count)
        {
            if(count < 0 || count > bytes.Length-WrittenCount) throw new InvalidOperationException();
            WrittenCount += count;
        }
        public Memory<byte> GetMemory(int sizeHint=0)
        {
            if(sizeHint < 0 || Math.Max(sizeHint,1) > bytes.Length-WrittenCount) throw new InvalidOperationException();
            return bytes.AsMemory(WrittenCount);
        }
        public Span<byte> GetSpan(int sizeHint=0) => GetMemory(sizeHint).Span;
    }
    private static string Text(JsonElement value,string field)=>value.GetProperty(field).GetString()!;
    private static string? NullableText(JsonElement value,string field)=>value.GetProperty(field).ValueKind == JsonValueKind.Null ? null : Text(value,field);
    private static string[] Strings(JsonElement value,string field)=>value.GetProperty(field).EnumerateArray().Select(v=>v.GetString()!).ToArray();
}
