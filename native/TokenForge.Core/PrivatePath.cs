using System.Security.AccessControl;
using System.Security.Principal;

namespace TokenForge.Core;
public static class PrivatePath
{
    public static string Prepare(string path)
    {
        path = Path.GetFullPath(path);
        if (OperatingSystem.IsWindows() && path.StartsWith(@"\\", StringComparison.Ordinal)) throw new InvalidOperationException("Use a local storage path.");
        var directory = Path.GetDirectoryName(path) ?? throw new InvalidOperationException("A local file path is required.");
        for (var current = new DirectoryInfo(directory); current != null; current = current.Parent)
            if (current.Exists && (current.Attributes & FileAttributes.ReparsePoint) != 0)
                throw new InvalidOperationException("Linked storage paths are not supported.");
        foreach(var candidate in new[] { path, path+"-wal", path+"-shm", path+"-journal" })
        if (File.Exists(candidate) && (File.GetAttributes(candidate) & FileAttributes.ReparsePoint) != 0)
            throw new InvalidOperationException("Linked storage files are not supported.");
        if (OperatingSystem.IsWindows())
        {
            var sid = WindowsIdentity.GetCurrent().User ?? throw new InvalidOperationException("User identity unavailable.");
            if (!Directory.Exists(directory))
            {
                Directory.CreateDirectory(directory);
                var acl = new DirectorySecurity();
                acl.SetOwner(sid); acl.SetAccessRuleProtection(true, false);
                acl.AddAccessRule(new FileSystemAccessRule(sid, FileSystemRights.FullControl,
                    InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit, PropagationFlags.None, AccessControlType.Allow));
                new DirectoryInfo(directory).SetAccessControl(acl);
            }
            CheckWindows(new DirectoryInfo(directory).GetAccessControl(), sid);
            if (File.Exists(path)) CheckWindows(new FileInfo(path).GetAccessControl(), sid);
        }
        else
        {
            Directory.CreateDirectory(directory, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
            if (((int)File.GetUnixFileMode(directory) & 63) != 0 ||
                (File.Exists(path) && ((int)File.GetUnixFileMode(path) & 63) != 0))
                throw new InvalidOperationException("Storage permissions must exclude group and other access.");
        }
        if (!File.Exists(path))
        {
            var options = new FileStreamOptions { Mode = FileMode.CreateNew, Access = FileAccess.Write, Share = FileShare.None };
            if (!OperatingSystem.IsWindows()) options.UnixCreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite;
            using var file = new FileStream(path, options);
            if(OperatingSystem.IsWindows())
            {
                var sid=WindowsIdentity.GetCurrent().User!;var acl=new FileSecurity();
                acl.SetOwner(sid);acl.SetAccessRuleProtection(true,false);
                acl.AddAccessRule(new FileSystemAccessRule(sid,FileSystemRights.FullControl,AccessControlType.Allow));
                new FileInfo(path).SetAccessControl(acl);
            }
        }
        return path;
    }
    [System.Runtime.Versioning.SupportedOSPlatform("windows")]
    private static void CheckWindows(FileSystemSecurity acl, SecurityIdentifier sid)
    {
        if (!acl.AreAccessRulesProtected || !sid.Equals(acl.GetOwner(typeof(SecurityIdentifier))))
            throw new InvalidOperationException("Storage must have a protected user-owned ACL.");
        foreach (FileSystemAccessRule rule in acl.GetAccessRules(true, true, typeof(SecurityIdentifier)))
            if (rule.AccessControlType == AccessControlType.Allow && !sid.Equals(rule.IdentityReference))
                throw new InvalidOperationException("Storage ACL permits another principal.");
    }
}
