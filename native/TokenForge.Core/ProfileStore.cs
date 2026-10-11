using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.RegularExpressions;
using TokenForge.Core.V0110;
using TokenForge.Core.V0200;
using TokenForge.Core.V0210;

namespace TokenForge.Core;

// Configuration files only. Creating/reading profiles never accesses keys, credentials, or network services.
public static class ProfileStore
{
    private static readonly JsonSerializerOptions JsonOptions = new() { WriteIndented = true, Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping };
    private static void Name(string name)
    {
        if (name == null || !Regex.IsMatch(name, @"\A[a-z][a-z0-9_-]{0,63}\z", RegexOptions.CultureInvariant)) throw new InvalidOperationException();
    }
    private static string Root(string? root, bool create)
    {
        if (string.IsNullOrEmpty(root))
        {
            string local = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
            if (string.IsNullOrEmpty(local)) throw new InvalidOperationException();
            root = Path.Combine(local, "TokenForge", "profiles");
        }
        return Path.GetDirectoryName(PrivateFiles.Resolve(Path.Combine(root, ".profiles"), create))!;
    }
    public static string Read(string name, string? root = null)
    {
        try
        {
            Name(name);
            string path = PrivateFiles.Resolve(Path.Combine(Root(root, false), name, "profile.json"), false);
            using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
            if (stream.Length > 32768) throw new InvalidOperationException();
            byte[] bytes = new byte[(int)stream.Length]; stream.ReadExactly(bytes);
            // Preserve BOM-marked legacy text encodings without allowing a growing file to exceed the cap.
            using var reader = new StreamReader(new MemoryStream(bytes), new UTF8Encoding(false, true), true);
            string json = reader.ReadToEnd(); ProfilePolicy.Validate(json, name); return json;
        }
        catch { throw new InvalidOperationException("Profile cannot be read. Details suppressed."); }
    }
    public static string Create(string name, string tenant, string? root = null, string? statePath = null,
        string storage = "Passphrase", string bootstrapClient = "038ddad9-5bbe-4f64-b0cd-12434d1e633b",
        int maximumAdditionalScopes = 0, int maximumBootstrapAdditionalScopes = 0, int maximumAgeHours = 24,
        int retentionHours = 8, string passkeyPath = "", string xdrModulePath = "")
    {
        try
        {
            Name(name);
            if (!Guid.TryParse(bootstrapClient, out Guid client) || client == Guid.Empty) throw new InvalidOperationException();
            string now = DateTimeOffset.UtcNow.ToString("o");
            var profile = new Dictionary<string, object?> {
                ["Format"]="TokenForgeProfile",["SchemaVersion"]=1,["Name"]=name,["Tenant"]=tenant,["StatePath"]=statePath ?? "",
                ["Storage"]=storage,["BootstrapClientId"]=client.ToString(),["MaxAdditionalScopes"]=maximumAdditionalScopes,
                ["MaxBootstrapAdditionalScopes"]=maximumBootstrapAdditionalScopes,["MaxAgeHours"]=maximumAgeHours,["SessionRetentionHours"]=retentionHours,
                ["PasskeyPath"]=passkeyPath,["XdrModulePath"]=xdrModulePath,["ExpectedTenantFingerprint"]=null,["ExpectedPrincipalFingerprint"]=null,
                ["Revision"]=Guid.NewGuid().ToString(),["CreatedAt"]=now,["UpdatedAt"]=now
            };
            if (storage == "OperatingSystem")
            {
                if (PlatformVaultKey.Backend == "Unsupported") throw new InvalidOperationException();
                profile["SchemaVersion"]=2; profile["KeyId"]=Guid.NewGuid().ToString("N");
            }
            ProfilePolicy.Validate(JsonSerializer.Serialize(profile, JsonOptions), name);
            string path = PrivateFiles.Resolve(Path.Combine(Root(root, true), name, "profile.json"), true);
            string directory = Path.GetDirectoryName(path)!;
            string lockPath = PrivateFiles.Resolve(Path.Combine(directory, ".operation.lock"), false);
            FileStream operation;
            try { operation = PrivateFiles.Open(lockPath, true); }
            catch (IOException) { operation = PrivateFiles.Open(lockPath, false); }
            using (operation)
            {
                if (File.Exists(path)) throw new InvalidOperationException();
                string evidence = string.IsNullOrEmpty(statePath) ? Path.Combine(directory, "state") : statePath;
                profile["StatePath"] = Path.GetDirectoryName(PrivateFiles.Resolve(Path.Combine(evidence, ".state"), true));
                string json = JsonSerializer.Serialize(profile, JsonOptions); ProfilePolicy.Validate(json, name);
                string temporary = Path.Combine(directory, Guid.NewGuid().ToString("N") + ".tmp");
                try
                {
                    using (var output = PrivateFiles.Open(PrivateFiles.Resolve(temporary, false), true))
                    {
                        output.Write(Encoding.UTF8.GetBytes(json)); output.Flush(true);
                    }
                    // Revalidate the destination and refuse overwrite, including uncooperative creators.
                    PrivateFiles.Resolve(path, false); File.Move(temporary, path, false); return json;
                }
                finally { if (File.Exists(temporary)) File.Delete(temporary); }
            }
        }
        catch { throw new InvalidOperationException("Profile creation failed. Details suppressed."); }
    }
}
