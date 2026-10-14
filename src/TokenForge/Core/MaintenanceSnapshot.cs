#nullable enable
using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading;
using TokenForge.Core.V0220;

namespace TokenForge.Core;

public sealed class MaintenanceSnapshotResult
{
    public int SchemaVersion => 1;
    public bool Authenticated { get; internal set; }
    public bool Restored { get; internal set; }
    public bool FreshAuthenticationPerformed => false;
    public int ApplicationCount { get; internal set; }
    public int CatalogRunCount { get; internal set; }
    public int GrantSnapshotCount { get; internal set; }
    public string Evidence => "HistoricalMaintenanceMetadata";
}

public sealed class MaintenanceSnapshotCleanupException : InvalidOperationException
{
    public bool Restored { get; }
    internal MaintenanceSnapshotCleanupException(bool restored)
        : base("Maintenance snapshot temporary plaintext cleanup failed; details suppressed.") { Restored = restored; }
}

// The CLI and plaintext report adapter share this complete-envelope policy.
// Authentication here means AES-GCM/context authentication, never current API authorization.
public static class MaintenanceSnapshot
{
    private const int MaximumPlaintextBytes = 128 * 1024 * 1024;
    private static readonly UTF8Encoding Utf8 = new(false, true);

    public static MaintenanceSnapshotResult Inspect(string snapshotPath, string keyPath, string tenant, string principal, CancellationToken cancellation = default)
        => Open(snapshotPath, keyPath, tenant, principal, null, cancellation);

    public static MaintenanceSnapshotResult Restore(string snapshotPath, string keyPath, string tenant, string principal, string outputPath, CancellationToken cancellation = default)
    {
        if (string.IsNullOrEmpty(outputPath)) throw Invalid();
        return Open(snapshotPath, keyPath, tenant, principal, outputPath, cancellation);
    }

    private static MaintenanceSnapshotResult Open(string snapshotPath, string keyPath, string tenant, string principal, string? outputPath, CancellationToken cancellation)
    {
        byte[]? blob = null, encodedKey = null, key = null, plaintext = null;
        string? temporary = null;
        bool published = false;
        try
        {
            string context = Context(tenant, principal);
            cancellation.ThrowIfCancellationRequested();
            // Recheck private paths after bounded reads; no output storage is created before validation.
            blob = ReadPrivate(snapshotPath, MaximumPlaintextBytes + 29);
            if (blob.Length <= 29 || blob[0] != 1) throw Invalid();
            encodedKey = ReadPrivate(keyPath, 46);
            string text = Utf8.GetString(encodedKey).TrimEnd('\r', '\n');
            if (text.Length != 44) throw Invalid();
            key = Convert.FromBase64String(text);
            if (key.Length != 32 || Convert.ToBase64String(key) != text) throw Invalid();
            plaintext = new byte[blob.Length - 29];
            using (var aes = new AesGcm(key, 16))
                aes.Decrypt(blob.AsSpan(1, 12), blob.AsSpan(29), blob.AsSpan(13, 16), plaintext, Utf8.GetBytes(context));
            cancellation.ThrowIfCancellationRequested();
            var result = ValidateDocument(Utf8.GetString(plaintext), tenant, principal);
            result.Authenticated = true;
            cancellation.ThrowIfCancellationRequested();
            if (outputPath != null)
            {
                string target = PrivateFiles.Resolve(outputPath, true);
                if (File.Exists(target)) throw Invalid();
                temporary = PrivateFiles.Resolve(Path.Combine(Path.GetDirectoryName(target)!, ".restore-" + Guid.NewGuid().ToString("N") + ".tmp"), false);
                using (var file = PrivateFiles.Open(temporary, true)) { file.Write(plaintext); file.Flush(true); }
                cancellation.ThrowIfCancellationRequested();
                PrivateFiles.Resolve(target, false);
                PrivateFiles.PublishNew(temporary, target);
                published = true;
                result.Restored = true;
            }
            return result;
        }
        catch (OperationCanceledException) { throw; }
        catch { throw Invalid(); }
        finally
        {
            foreach (var buffer in new[] { blob, encodedKey, key, plaintext })
                if (buffer != null) CryptographicOperations.ZeroMemory(buffer);
            if (temporary != null) CleanupTemporary(temporary, published, File.Delete);
        }
    }

    public static string ReadCatalog(string maintenancePath, string tenant, string principal)
    {
        byte[]? plaintext = null;
        try
        {
            plaintext = ReadPrivate(maintenancePath, MaximumPlaintextBytes);
            string json = Utf8.GetString(plaintext);
            ValidateDocument(json, tenant, principal);
            using var document = ApplicationCatalogPolicy.Parse(json);
            return document.RootElement.GetProperty("Metadata").GetRawText();
        }
        catch { throw Invalid(); }
        finally { if (plaintext != null) CryptographicOperations.ZeroMemory(plaintext); }
    }

    public static MaintenanceSnapshotResult ValidateDocument(string json, string tenant, string principal)
    {
        try
        {
            string context = Context(tenant, principal);
            using var document = ApplicationCatalogPolicy.Parse(json);
            var root = document.RootElement;
            DiscoverySourceClaims.ValidateUniqueKeys(root);
            ApplicationCatalogPolicy.Keys(root, "SchemaVersion Context Metadata GrantHistory LastRun");
            if (root.GetProperty("SchemaVersion").GetInt32() != 1 || ApplicationCatalogPolicy.Text(root, "Context") != context) throw Invalid();
            var catalog = root.GetProperty("Metadata");
            ApplicationCatalogPolicy.ValidateDocument(catalog.GetRawText());
            foreach (var app in catalog.GetProperty("Applications").EnumerateObject())
                foreach (var record in app.Value.GetProperty("Records").EnumerateObject())
                {
                    var recordTenant = ApplicationCatalogPolicy.NullableText(record.Value, "TenantFingerprint");
                    var observer = ApplicationCatalogPolicy.NullableText(record.Value, "PrincipalFingerprint");
                    if (recordTenant != null && recordTenant != tenant || observer != null && observer != principal) throw Invalid();
                }
            foreach (var origin in catalog.GetProperty("Origins").EnumerateObject())
            {
                var parts = origin.Name.Split('/');
                if (parts[1].Length != 0 && parts[1] != tenant || parts[2].Length != 0 && parts[2] != principal) throw Invalid();
            }
            foreach (var run in catalog.GetProperty("Runs").EnumerateArray())
            {
                var observedTenant = ApplicationCatalogPolicy.NullableText(run, "TenantFingerprint");
                if (observedTenant != null && observedTenant != tenant) throw Invalid();
            }
            var history = root.GetProperty("GrantHistory");
            if (history.ValueKind != JsonValueKind.Array || history.GetArrayLength() > 10000) throw Invalid();
            foreach (var snapshot in history.EnumerateArray())
            {
                ApplicationCatalogPolicy.Keys(snapshot, "FirstSeenAt LastSeenAt Grants");
                OrderedDates(snapshot, "FirstSeenAt", "LastSeenAt");
                var grants = snapshot.GetProperty("Grants");
                if (grants.ValueKind != JsonValueKind.Array || grants.GetArrayLength() > 100000) throw Invalid();
                foreach (var grant in grants.EnumerateArray())
                {
                    ApplicationCatalogPolicy.Keys(grant, "ClientId ResourceId Scopes PrincipalFingerprint ConsentType AppliesToCurrentPrincipal Evidence");
                    foreach (var field in new[] { "ClientId", "ResourceId" }) ApplicationCatalogPolicy.GuidValue(ApplicationCatalogPolicy.Text(grant, field));
                    ApplicationCatalogPolicy.ValidateLeaf("Scopes", grant.GetProperty("Scopes"));
                    if (grant.GetProperty("Scopes").ValueKind != JsonValueKind.Array) throw Invalid();
                    // This identifies the grant beneficiary, which may differ from the observer.
                    var beneficiary = ApplicationCatalogPolicy.NullableText(grant, "PrincipalFingerprint");
                    if (beneficiary != null) ApplicationCatalogPolicy.HashValue(beneficiary);
                    if (ApplicationCatalogPolicy.Text(grant, "ConsentType") is not ("AllPrincipals" or "Principal") ||
                        grant.GetProperty("AppliesToCurrentPrincipal").ValueKind is not (JsonValueKind.True or JsonValueKind.False) ||
                        ApplicationCatalogPolicy.Text(grant, "Evidence") != "TenantConfiguredGrant") throw Invalid();
                }
            }
            var last = root.GetProperty("LastRun");
            ApplicationCatalogPolicy.AllowedKeys(last, "StartedAt FinishedAt Discovery Inventory Grants SignIns SignInFailureReason SignInSince SignInUntil SignInMaxPages Registration Status");
            // Early schema-1 snapshots did not persist a failure category. Its absence is unknown.
            foreach (var field in "StartedAt FinishedAt Discovery Inventory Grants SignIns SignInSince SignInUntil SignInMaxPages Registration Status".Split(' '))
                if (!last.TryGetProperty(field, out _)) throw Invalid();
            string? failureReason = last.TryGetProperty("SignInFailureReason", out _) ? ApplicationCatalogPolicy.NullableText(last, "SignInFailureReason") : null;
            OrderedDates(last, "StartedAt", "FinishedAt");
            OrderedDates(last, "SignInSince", "SignInUntil");
            foreach (var field in new[] { "Discovery", "Inventory" })
                if (ApplicationCatalogPolicy.Text(last, field) is not ("NotRun" or "Complete" or "Failed")) throw Invalid();
            if (ApplicationCatalogPolicy.Text(last, "Grants") is not ("NotRun" or "Skipped" or "Complete" or "Forbidden" or "Failed") ||
                ApplicationCatalogPolicy.Text(last, "SignIns") is not ("NotRun" or "Skipped" or "SkippedInventoryUnavailable" or "Complete" or "Forbidden" or "Failed") ||
                failureReason is not (null or "Forbidden" or "EnumerationBounded" or "TransientTransport" or "OtherFailure") ||
                !last.GetProperty("SignInMaxPages").TryGetInt32(out int pages) || pages is < 1 or > 1000 ||
                ApplicationCatalogPolicy.Text(last, "Registration") != "NotRun" ||
                ApplicationCatalogPolicy.Text(last, "Status") is not ("Complete" or "Partial" or "Failed")) throw Invalid();
            return new MaintenanceSnapshotResult
            {
                ApplicationCount = catalog.GetProperty("Applications").EnumerateObject().Count(),
                CatalogRunCount = catalog.GetProperty("Runs").GetArrayLength(),
                GrantSnapshotCount = history.GetArrayLength()
            };
        }
        catch { throw Invalid(); }
    }

    private static void OrderedDates(JsonElement value, string first, string last)
    {
        if (StringComparer.Ordinal.Compare(ApplicationCatalogPolicy.Date(value, first), ApplicationCatalogPolicy.Date(value, last)) > 0) throw Invalid();
    }
    private static string Context(string tenant, string principal)
    {
        ApplicationCatalogPolicy.HashValue(tenant); ApplicationCatalogPolicy.HashValue(principal);
        return "private-maintenance/v1/" + tenant + "/" + principal;
    }
    private static byte[] ReadPrivate(string path, int maximum)
    {
        path = PrivateFiles.Resolve(path, false);
        byte[]? bytes = null;
        try
        {
            using var file = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
            if (file.Length < 1 || file.Length > maximum) throw Invalid();
            bytes = new byte[(int)file.Length]; file.ReadExactly(bytes);
            if (file.ReadByte() != -1) throw Invalid();
            PrivateFiles.Resolve(path, false);
            return bytes;
        }
        catch { if (bytes != null) CryptographicOperations.ZeroMemory(bytes); throw; }
    }
    private static InvalidOperationException Invalid() => new("Maintenance snapshot operation failed; details suppressed. Existing files are never overwritten.");

    private static void CleanupTemporary(string path, bool published, Action<string> delete)
    {
        try { delete(path); }
        catch { throw new MaintenanceSnapshotCleanupException(published); }
    }
}
