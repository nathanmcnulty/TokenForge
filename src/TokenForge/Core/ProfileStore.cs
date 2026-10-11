using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Security;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.RegularExpressions;
using TokenForge.Core.V0110;
using TokenForge.Core.V0200;
using TokenForge.Core.V0220;
using TokenForge.Core.V0230;

namespace TokenForge.Core;

// Configuration operations, read-only vault inspection, and explicit OS-key forgetting use no network services.
public static class ProfileStore
{
    public sealed record KeyRemoval(string Profile, bool VaultRemoved, bool KeyRemoved, string NextStep, string Evidence);

    public static KeyRemoval ForgetKey(string name, string? root = null)
    {
        try
        {
            string initial = Read(name, root);
            using var initialProfile = JsonDocument.Parse(initial);
            if (initialProfile.RootElement.GetProperty("Storage").GetString() != "OperatingSystem" || PlatformVaultKey.Backend == "Unsupported") throw new InvalidOperationException();
            string directory = Path.Combine(Root(root, false), name);
            string operationPath = PrivateFiles.Resolve(Path.Combine(directory, ".operation.lock"), false);
            FileStream operation;
            try { operation = PrivateFiles.Open(operationPath, true); }
            catch (IOException) { operation = PrivateFiles.Open(operationPath, false); }
            using (operation)
            {
                // A login/configuration change between the initial read and lock must be retried.
                if (Read(name, root) != initial) throw new InvalidOperationException();
                string vaultLockPath = PrivateFiles.Resolve(Path.Combine(directory, "session.tfvault.lock"), false);
                FileStream vaultLock;
                try { vaultLock = PrivateFiles.Open(vaultLockPath, true); }
                catch (IOException) { vaultLock = PrivateFiles.Open(vaultLockPath, false); }
                using (vaultLock)
                {
                    string handle = ProfileKeyIdentity.Compute(directory, initialProfile.RootElement.GetProperty("KeyId").GetString()!);
                    string vault = PrivateFiles.Resolve(Path.Combine(directory, "session.tfvault"), false);
                    File.Delete(vault); // Missing ciphertext is already removed; never open or decrypt it.
                    bool removed = true;
                    try { PlatformVaultKey.Delete(handle); } catch { removed = false; }
                    return new KeyRemoval(name, true, removed, removed ? "Log in explicitly to create a new local session." : "Vault removed; retry this operation to delete the remaining OS key.", "LocalDeletionNotServerRevocation");
                }
            }
        }
        catch { throw new InvalidOperationException("Profile key removal failed. Details suppressed."); }
    }
    public sealed record LogoutResult(string Profile, bool Removed, string Evidence);
    public static VaultInspection InspectVault(string name, string? root = null, SecureString? password = null) =>
        WithVault(name,root,password,null,"Read",false,(transaction,key,configuration)=>VaultInspector.Inspect(transaction!,key!,name,configuration.GetProperty("ExpectedTenantFingerprint").GetString(),configuration.GetProperty("ExpectedPrincipalFingerprint").GetString(),DateTimeOffset.UtcNow));
    public static LogoutResult Logout(string name, string? root = null, SecureString? password = null, Func<SecureString>? passwordProvider = null) =>
        WithVault(name,root,password,passwordProvider,"Update",true,(transaction,key,configuration)=>
        {
            if (transaction != null) VaultInspector.RemoveSession(transaction,key!,name);
            return new LogoutResult(name,true,"LocalLogoutNotServerRevocation");
        });
    internal static T WithVault<T>(string name, string? root, SecureString? password, Func<SecureString>? passwordProvider,
        string mode, bool allowMissing, Func<VaultFileTransaction?,SecureString?,JsonElement,T> operation, Action<JsonElement>? validateConfiguration=null)
    {
        SecureString? ownedPassword = null;
        try
        {
            string initial = Read(name, root);
            using var profile = JsonDocument.Parse(initial);
            var configuration = profile.RootElement;
            string storage = configuration.GetProperty("Storage").GetString()!;
            if (password != null && passwordProvider != null || storage != "Passphrase" && passwordProvider != null || storage == "OperatingSystem" && password != null) throw new InvalidOperationException();
            string directory = Path.Combine(Root(root, false), name);
            string operationPath = PrivateFiles.Resolve(Path.Combine(directory,".operation.lock"),false);
            FileStream held;
            try { held = PrivateFiles.Open(operationPath,true); }
            catch (IOException) { held = PrivateFiles.Open(operationPath,false); }
            using (held)
            {
                if (Read(name,root) != initial) throw new InvalidOperationException();
                validateConfiguration?.Invoke(configuration);
                if (storage == "Memory")
                {
                    if (!allowMissing) throw new InvalidOperationException();
                    return operation(null,null,configuration);
                }
                string vault = PrivateFiles.Resolve(Path.Combine(directory,"session.tfvault"),false);
                if (!File.Exists(vault))
                {
                    if (!allowMissing) throw new InvalidOperationException();
                    return operation(null,null,configuration);
                }
                if (storage == "OperatingSystem" && PlatformVaultKey.Backend == "Unsupported") throw new InvalidOperationException();
                using var transaction = VaultFileTransaction.Begin(vault,mode);
                if (storage == "OperatingSystem") ownedPassword = PlatformVaultKey.Open(ProfileKeyIdentity.Compute(directory,configuration.GetProperty("KeyId").GetString()!),false);
                else if (password == null && passwordProvider != null) ownedPassword = passwordProvider();
                if (ownedPassword == null && password == null) throw new InvalidOperationException();
                return operation(transaction,ownedPassword ?? password,configuration);
            }
        }
        catch { throw new InvalidOperationException("Profile vault operation failed. Details suppressed."); }
        finally { ownedPassword?.Dispose(); }
    }
    private static readonly JsonSerializerOptions JsonOptions = new() { WriteIndented = true, Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping };
    private static void Name(string name)
    {
        if (name == null || !Regex.IsMatch(name, @"\A[a-z][a-z0-9_-]{0,63}\z", RegexOptions.CultureInvariant)) throw new InvalidOperationException();
    }
    internal static string Root(string? root, bool create)
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
                    PrivateFiles.Resolve(path, false); PrivateFiles.PublishNew(temporary, path); return json;
                }
                finally { if (File.Exists(temporary)) File.Delete(temporary); }
            }
        }
        catch { throw new InvalidOperationException("Profile creation failed. Details suppressed."); }
    }
}
