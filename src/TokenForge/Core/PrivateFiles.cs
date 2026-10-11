#nullable enable
using System;
using System.IO;
using System.Runtime.Versioning;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;

namespace TokenForge.Core.V0220
{
    // Shared profile/vault policy. Unlike the SQLite path policy, trusted SYSTEM/Admin ACL entries are allowed.
    public static class PrivateFiles
    {
        public static string Resolve(string path, bool createDirectory)
        {
            if (path.StartsWith(@"\\", StringComparison.Ordinal)) throw new InvalidOperationException("Vaults require a local filesystem path.");
            string full = Path.GetFullPath(path);
            if (full.StartsWith(@"\\", StringComparison.Ordinal)) throw new InvalidOperationException("Vaults require a local filesystem path.");
            string parent = Path.GetDirectoryName(full) ?? throw new InvalidOperationException("A local file path is required.");
            for (string? part = full; !string.IsNullOrEmpty(part); part = Path.GetDirectoryName(part))
            {
                FileAttributes? attributes = Attributes(part);
                if (attributes.HasValue && (attributes.Value & FileAttributes.ReparsePoint) != 0)
                    throw new InvalidOperationException("Vault paths must not contain links or reparse points.");
            }
            if (!Directory.Exists(parent))
            {
                if (!createDirectory) throw new InvalidOperationException("Vault directory does not exist.");
                if (OperatingSystem.IsWindows()) CreatePrivateDirectory(parent);
                else Directory.CreateDirectory(parent, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
            }
            foreach (string part in new[] { parent, full })
            {
                FileAttributes? attributes = Attributes(part);
                if (!attributes.HasValue) continue;
                if (part == full && (attributes.Value & FileAttributes.Directory) != 0) throw new InvalidOperationException("Vault path must be a regular file.");
                if (!OperatingSystem.IsWindows())
                {
                    if (((int)File.GetUnixFileMode(part) & 63) != 0) throw new InvalidOperationException("Vault files and their directory must exclude group and other access.");
                }
                else CheckWindows(part, (attributes.Value & FileAttributes.Directory) != 0);
            }
            return full;
        }
        public static FileStream Open(string path, bool create)
        {
            if (create && OperatingSystem.IsWindows())
            {
                var security = new FileSecurity(); var sid = WindowsIdentity.GetCurrent().User!;
                security.SetOwner(sid); security.SetAccessRuleProtection(true, false);
                security.AddAccessRule(new FileSystemAccessRule(sid, FileSystemRights.FullControl, AccessControlType.Allow));
                return FileSystemAclExtensions.Create(new FileInfo(path), FileMode.CreateNew, FileSystemRights.FullControl, FileShare.None, 4096, FileOptions.None, security);
            }
            var options = new FileStreamOptions { Mode = create ? FileMode.CreateNew : FileMode.Open, Access = FileAccess.ReadWrite, Share = FileShare.None };
            if (create && !OperatingSystem.IsWindows()) options.UnixCreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite;
            return new FileStream(path, options);
        }
        // Caller owns a complete private temporary file and removes it in finally.
        // Unix rename can overwrite a destination created after File.Move's check.
        internal static void PublishNew(string source, string target)
        {
            if (OperatingSystem.IsWindows()) { File.Move(source, target, false); return; }
            int result = OperatingSystem.IsLinux() ? LinuxLink(source, target) :
                OperatingSystem.IsMacOS() ? MacLink(source, target) : throw new PlatformNotSupportedException();
            if (result != 0) throw new IOException("Private file publication failed.");
        }
        [DllImport("libc", EntryPoint="link", SetLastError=true)]
        private static extern int LinuxLink([MarshalAs(UnmanagedType.LPUTF8Str)] string source, [MarshalAs(UnmanagedType.LPUTF8Str)] string target);
        [DllImport("libSystem.B.dylib", EntryPoint="link", SetLastError=true)]
        private static extern int MacLink([MarshalAs(UnmanagedType.LPUTF8Str)] string source, [MarshalAs(UnmanagedType.LPUTF8Str)] string target);
        private static FileAttributes? Attributes(string path)
        {
            try { return File.GetAttributes(path); }
            catch (FileNotFoundException) { return null; }
            catch (DirectoryNotFoundException) { return null; }
        }
        [SupportedOSPlatform("windows")]
        private static void CreatePrivateDirectory(string path)
        {
            var security = new DirectorySecurity(); var sid = WindowsIdentity.GetCurrent().User!;
            security.SetOwner(sid); security.SetAccessRuleProtection(true, false);
            security.AddAccessRule(new FileSystemAccessRule(sid, FileSystemRights.FullControl, InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit, PropagationFlags.None, AccessControlType.Allow));
            FileSystemAclExtensions.Create(new DirectoryInfo(path), security);
        }
        [SupportedOSPlatform("windows")]
        private static void CheckWindows(string path, bool directory)
        {
            string sid = WindowsIdentity.GetCurrent().User!.Value;
            FileSystemSecurity security = directory ? new DirectoryInfo(path).GetAccessControl() : new FileInfo(path).GetAccessControl();
            bool Trusted(string value) => value == sid || value == "S-1-5-18" || value == "S-1-5-32-544";
            IdentityReference? owner = security.GetOwner(typeof(SecurityIdentifier));
            if (owner == null || !Trusted(owner.Value)) throw new InvalidOperationException("Vault path is owned by another identity.");
            foreach (FileSystemAccessRule rule in security.GetAccessRules(true, true, typeof(SecurityIdentifier)))
                if (rule.AccessControlType == AccessControlType.Allow && !Trusted(rule.IdentityReference.Value)) throw new InvalidOperationException("Vault ACL permits another identity.");
        }
    }

    // Owns one exclusive vault-file transaction. It handles ciphertext only; callers own encryption and record validation.
    public sealed class VaultFileTransaction : IDisposable
    {
        private readonly string path, mode;
        private FileStream? operation;
        private bool read, committed;
        private const int MaximumEnvelopeBytes = 16777216;
        private VaultFileTransaction(string path, string mode, FileStream operation)
        { this.path = path; this.mode = mode; this.operation = operation; }

        public static VaultFileTransaction Begin(string path, string mode)
        {
            FileStream? operation = null;
            try
            {
                if (mode != "Read" && mode != "Create" && mode != "Update") throw new InvalidOperationException();
                string full = PrivateFiles.Resolve(path, mode == "Create");
                string lockPath = PrivateFiles.Resolve(full + ".lock", false);
                try { operation = PrivateFiles.Open(lockPath, true); }
                catch (IOException) { operation = PrivateFiles.Open(lockPath, false); }
                // Resolve again after acquiring the cooperative lock.
                PrivateFiles.Resolve(full, false);
                if (File.Exists(full) == (mode == "Create")) throw new InvalidOperationException();
                var transaction = new VaultFileTransaction(full, mode, operation);
                operation = null; return transaction;
            }
            catch { throw Failure(); }
            finally { try { operation?.Dispose(); } catch { } }
        }
        public byte[] ReadEnvelope()
        {
            try
            {
                if (operation == null || mode == "Create" || committed) throw new InvalidOperationException();
                using var input = PrivateFiles.Open(PrivateFiles.Resolve(path, false), false);
                if (input.Length < 100 || input.Length > MaximumEnvelopeBytes) throw new InvalidOperationException();
                byte[] bytes = new byte[(int)input.Length]; input.ReadExactly(bytes);
                read = true; return bytes;
            }
            catch { throw Failure(); }
        }
        public void Commit(byte[] envelope)
        {
            string? temporary = null;
            try
            {
                if (operation == null || committed || mode == "Read" || (mode == "Update" && !read) ||
                    envelope == null || envelope.Length < 100 || envelope.Length > MaximumEnvelopeBytes) throw new InvalidOperationException();
                temporary = Path.Combine(Path.GetDirectoryName(path)!, Guid.NewGuid().ToString("N") + ".tmp");
                using (var output = PrivateFiles.Open(PrivateFiles.Resolve(temporary, false), true))
                { output.Write(envelope); output.Flush(true); }
                PrivateFiles.Resolve(path, false);
                if (mode == "Update") { File.Move(temporary, path, true); temporary = null; }
                else PrivateFiles.PublishNew(temporary, path);
                committed = true;
            }
            catch { throw Failure(); }
            finally { if (temporary != null) { try { File.Delete(temporary); } catch { } } }
        }
        public void Dispose()
        {
            FileStream? held = operation; operation = null;
            try { held?.Dispose(); } catch { throw Failure(); }
        }
        private static InvalidOperationException Failure() => new InvalidOperationException("Vault file transaction failed. Details suppressed.");
    }
}
