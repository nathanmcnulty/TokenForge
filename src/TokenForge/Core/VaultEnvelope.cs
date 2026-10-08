#nullable enable
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Security;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace TokenForge.Core.V0190
{
    // Cryptographic envelope only. Callers own plaintext buffers and validate record schemas and paths.
    public static class VaultEnvelope
    {
        public const int MaximumPlaintextBytes = 8388608;
        public const int MaximumEnvelopeBytes = 16777216;
        private const int Iterations = 600000;
        private static readonly byte[] Aad = Encoding.UTF8.GetBytes("TokenForgeVault|1|PBKDF2-SHA256|600000|AES-256-GCM");

        public static byte[] Encrypt(byte[]? plaintext, SecureString? password)
        {
            byte[]? key = null, passwordBytes = null;
            try
            {
                if (plaintext == null || plaintext.Length > MaximumPlaintextBytes) throw new InvalidOperationException();
                passwordBytes = PasswordBytes(password);
                byte[] salt = RandomNumberGenerator.GetBytes(32), nonce = RandomNumberGenerator.GetBytes(12);
                key = Rfc2898DeriveBytes.Pbkdf2(passwordBytes, salt, Iterations, HashAlgorithmName.SHA256, 32);
                byte[] cipher = new byte[plaintext.Length], tag = new byte[16];
                using (var aes = new AesGcm(key, 16)) aes.Encrypt(nonce, plaintext, cipher, tag, Aad);
                return JsonSerializer.SerializeToUtf8Bytes(new Dictionary<string, object> {
                    {"Format", "TokenForgeVault"}, {"Version", 1}, {"Kdf", "PBKDF2-SHA256"}, {"Iterations", Iterations},
                    {"Salt", Convert.ToBase64String(salt)}, {"Nonce", Convert.ToBase64String(nonce)},
                    {"Tag", Convert.ToBase64String(tag)}, {"Ciphertext", Convert.ToBase64String(cipher)}
                });
            }
            catch { throw new InvalidOperationException("Vault envelope operation failed. Details suppressed."); }
            finally { Clear(key); Clear(passwordBytes); }
        }

        public static byte[] Decrypt(byte[]? envelope, SecureString? password)
        {
            byte[]? key = null, passwordBytes = null, plaintext = null;
            try
            {
                if (envelope == null || envelope.Length < 100 || envelope.Length > MaximumEnvelopeBytes) throw new InvalidOperationException();
                using (var parsed = JsonDocument.Parse(envelope, new JsonDocumentOptions { MaxDepth = 8 }))
                {
                    var root = parsed.RootElement;
                    if (root.ValueKind != JsonValueKind.Object) throw new InvalidOperationException();
                    var allowed = new HashSet<string>(new[] { "Format", "Version", "Kdf", "Iterations", "Salt", "Nonce", "Tag", "Ciphertext" }, StringComparer.Ordinal);
                    foreach (var property in root.EnumerateObject())
                        if (!allowed.Remove(property.Name)) throw new InvalidOperationException();
                    if (allowed.Count != 0 || root.GetProperty("Format").GetString() != "TokenForgeVault" ||
                        root.GetProperty("Version").GetInt32() != 1 || root.GetProperty("Kdf").GetString() != "PBKDF2-SHA256" ||
                        root.GetProperty("Iterations").GetInt32() != Iterations) throw new InvalidOperationException();
                    byte[] salt = Decode(root, "Salt", 32), nonce = Decode(root, "Nonce", 12), tag = Decode(root, "Tag", 16);
                    byte[] cipher = Decode(root, "Ciphertext", MaximumPlaintextBytes, false);
                    passwordBytes = PasswordBytes(password);
                    key = Rfc2898DeriveBytes.Pbkdf2(passwordBytes, salt, Iterations, HashAlgorithmName.SHA256, 32);
                    plaintext = new byte[cipher.Length];
                    using (var aes = new AesGcm(key, 16)) aes.Decrypt(nonce, cipher, tag, plaintext, Aad);
                    byte[] result = plaintext; plaintext = null;
                    return result;
                }
            }
            catch { throw new InvalidOperationException("Vault envelope operation failed. Details suppressed."); }
            finally { Clear(key); Clear(passwordBytes); Clear(plaintext); }
        }

        private static byte[] Decode(JsonElement root, string name, int limit, bool exact = true)
        {
            string? encoded = root.GetProperty(name).GetString();
            // Bound allocation before decoding, even for malformed or whitespace-heavy base64.
            if (encoded == null || encoded.Length > ((limit + 2L) / 3L) * 4L) throw new InvalidOperationException();
            byte[] value = Convert.FromBase64String(encoded);
            if (value.Length > limit || (exact && value.Length != limit)) throw new InvalidOperationException();
            return value;
        }

        private static byte[] PasswordBytes(SecureString? password)
        {
            if (password == null) throw new InvalidOperationException();
            IntPtr pointer = IntPtr.Zero; char[]? chars = null;
            using (var owned = password.Copy())
            {
                try
                {
                    if (owned.Length < 12 || owned.Length > 1024) throw new InvalidOperationException();
                    pointer = Marshal.SecureStringToBSTR(owned);
                    chars = new char[owned.Length]; Marshal.Copy(pointer, chars, 0, chars.Length);
                    return Encoding.UTF8.GetBytes(chars);
                }
                finally
                {
                    if (chars != null) Array.Clear(chars, 0, chars.Length);
                    if (pointer != IntPtr.Zero) Marshal.ZeroFreeBSTR(pointer);
                }
            }
        }
        private static void Clear(byte[]? value) { if (value != null) CryptographicOperations.ZeroMemory(value); }
    }
}
