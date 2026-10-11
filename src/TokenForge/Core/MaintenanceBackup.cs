#nullable enable
using System;
using System.IO;
using System.Security.Cryptography;
using System.Runtime.InteropServices;
using TokenForge.Core.V0220;

namespace TokenForge.Core;

// Copies ciphertext only. Content identity does not authenticate the envelope.
public sealed class MaintenanceBackupResult
{
    public bool Saved { get; internal set; }
    public bool AlreadyExists => !Saved;
    public string Sha256 { get; internal set; } = "";
    public int Bytes { get; internal set; }
    public string BackupPath { get; internal set; } = "";
    public bool Authenticated => false;
}
public static class MaintenanceBackup
{
    private const int MaximumBytes = 134217757;
    public static MaintenanceBackupResult Save(string snapshotPath, string backupDirectory)
    {
        byte[]? blob = null;
        string? temporary = null;
        try
        {
            string source = PrivateFiles.Resolve(snapshotPath, false);
            using (var input = new FileStream(source, FileMode.Open, FileAccess.Read, FileShare.Read))
            {
                if (input.Length <= 29 || input.Length > MaximumBytes) throw new InvalidOperationException();
                blob = new byte[(int)input.Length];
                input.ReadExactly(blob);
                if (input.ReadByte() != -1 || blob[0] != 1) throw new InvalidOperationException();
            }
            string hash = Convert.ToHexString(SHA256.HashData(blob)).ToLowerInvariant();
            string target = PrivateFiles.Resolve(Path.Combine(backupDirectory, hash + ".sealed"), true);
            bool saved = false;
            if (!File.Exists(target))
            {
                temporary = PrivateFiles.Resolve(Path.Combine(Path.GetDirectoryName(target)!, ".backup-" + Guid.NewGuid().ToString("N") + ".tmp"), false);
                using (var output = PrivateFiles.Open(temporary, true)) { output.Write(blob); output.Flush(true); }
                PrivateFiles.Resolve(target, false);
                try { if (PublishNoOverwrite(temporary, target)) temporary = null; saved = true; }
                catch (IOException) when (File.Exists(target)) { /* An independent identical copy may have won publication. */ }
            }
            if (!saved)
            {
                using var stored = new FileStream(PrivateFiles.Resolve(target, false), FileMode.Open, FileAccess.Read, FileShare.Read);
                if (stored.Length != blob.Length) throw new InvalidOperationException();
                using var digest = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
                byte[] buffer = new byte[8192];
                try
                {
                    int remaining = blob.Length;
                    while (remaining > 0) { int read = stored.Read(buffer, 0, Math.Min(buffer.Length, remaining)); if (read == 0) throw new InvalidOperationException(); digest.AppendData(buffer, 0, read); remaining -= read; }
                    if (stored.ReadByte() != -1 || Convert.ToHexString(digest.GetHashAndReset()).ToLowerInvariant() != hash) throw new InvalidOperationException();
                }
                finally { CryptographicOperations.ZeroMemory(buffer); }
            }
            return new MaintenanceBackupResult { Saved = saved, Sha256 = hash, Bytes = blob.Length, BackupPath = target };
        }
        catch { throw new InvalidOperationException("Encrypted maintenance backup failed; details suppressed. Existing backups are never overwritten."); }
        finally
        {
            if (temporary != null) { try { File.Delete(temporary); } catch { } }
            if (blob != null) CryptographicOperations.ZeroMemory(blob);
        }
    }
    // A Unix File.Move(false) can race between its destination check and rename.
    // Hard-link publication atomically fails if ANY destination entry already exists.
    // The caller retains its temporary link for finally cleanup on Unix.
    private static bool PublishNoOverwrite(string source, string target)
    {
        if (OperatingSystem.IsWindows()) { File.Move(source, target, false); return true; }
        int result = OperatingSystem.IsLinux() ? LinuxLink(source, target) :
            OperatingSystem.IsMacOS() ? MacLink(source, target) : throw new PlatformNotSupportedException();
        if (result != 0) throw new IOException("Immutable backup publication failed.");
        return false;
    }
    [DllImport("libc", EntryPoint="link", SetLastError=true)]
    private static extern int LinuxLink([MarshalAs(UnmanagedType.LPUTF8Str)] string source, [MarshalAs(UnmanagedType.LPUTF8Str)] string target);
    [DllImport("libSystem.B.dylib", EntryPoint="link", SetLastError=true)]
    private static extern int MacLink([MarshalAs(UnmanagedType.LPUTF8Str)] string source, [MarshalAs(UnmanagedType.LPUTF8Str)] string target);

}
