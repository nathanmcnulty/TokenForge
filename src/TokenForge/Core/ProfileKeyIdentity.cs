#nullable enable
using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace TokenForge.Core.V0230
{
    // Moving a profile does not migrate its OS key. Both entry points bind the handle to its directory and key ID.
    public static class ProfileKeyIdentity
    {
        public static string Compute(string directory, string keyId)
        {
            try
            {
                if (string.IsNullOrEmpty(directory) || !Guid.TryParseExact(keyId, "N", out Guid key) ||
                    key == Guid.Empty || key.ToString("N") != keyId) throw new InvalidOperationException();
                string full = Path.GetFullPath(directory);
                if (OperatingSystem.IsWindows()) full = full.ToLowerInvariant();
                return Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(full + "|" + keyId))).ToLowerInvariant();
            }
            catch { throw new InvalidOperationException("Profile key identity is invalid. Details suppressed."); }
        }
    }
}
