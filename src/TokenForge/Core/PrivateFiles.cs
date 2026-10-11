#nullable enable
using System;
using System.IO;
using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Principal;

namespace TokenForge.Core.V0210
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
}
