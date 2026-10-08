using System.Security;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using TokenForge.Core.V0190;

internal static class VaultEnvelopeChecks
{
    // Independent pre-extraction format implementation for compatibility checks, not production storage.
    private const string AssociatedData = "TokenForgeVault|1|PBKDF2-SHA256|600000|AES-256-GCM";
    private static SecureString Secret(string value)
    {
        var result = new SecureString(); foreach (char c in value) result.AppendChar(c); result.MakeReadOnly(); return result;
    }
    private static byte[] LegacyEncrypt(byte[] plain, string password, string aad = AssociatedData)
    {
        byte[] salt = RandomNumberGenerator.GetBytes(32), nonce = RandomNumberGenerator.GetBytes(12), tag = new byte[16], cipher = new byte[plain.Length];
        byte[] key = Rfc2898DeriveBytes.Pbkdf2(Encoding.UTF8.GetBytes(password), salt, 600000, HashAlgorithmName.SHA256, 32);
        try
        {
            using var aes = new AesGcm(key, 16); aes.Encrypt(nonce, plain, cipher, tag, Encoding.UTF8.GetBytes(aad));
            return JsonSerializer.SerializeToUtf8Bytes(new { Format="TokenForgeVault",Version=1,Kdf="PBKDF2-SHA256",Iterations=600000,Salt=Convert.ToBase64String(salt),Nonce=Convert.ToBase64String(nonce),Tag=Convert.ToBase64String(tag),Ciphertext=Convert.ToBase64String(cipher) });
        }
        finally { CryptographicOperations.ZeroMemory(key); }
    }
    private static byte[] LegacyDecrypt(byte[] encoded, string password)
    {
        using var json = JsonDocument.Parse(encoded); var r=json.RootElement;
        byte[] key=Rfc2898DeriveBytes.Pbkdf2(Encoding.UTF8.GetBytes(password),Convert.FromBase64String(r.GetProperty("Salt").GetString()!),600000,HashAlgorithmName.SHA256,32);
        byte[] cipher=Convert.FromBase64String(r.GetProperty("Ciphertext").GetString()!), plain=new byte[cipher.Length];
        try
        {
            using var aes=new AesGcm(key,16);aes.Decrypt(Convert.FromBase64String(r.GetProperty("Nonce").GetString()!),cipher,Convert.FromBase64String(r.GetProperty("Tag").GetString()!),plain,Encoding.UTF8.GetBytes(AssociatedData));return plain;
        }
        finally { CryptographicOperations.ZeroMemory(key); }
    }
    public static void Run(Action<bool> check, Action<Action> reject)
    {
        byte[] plain=Encoding.UTF8.GetBytes("{\"SchemaVersion\":1,\"Sessions\":{}}");
        foreach (string text in new[] { "synthetic-passphrase", "synthetic-é-🙂-passphrase", "synthetic-\uD800-passphrase", "synthetic-\0-suffix-passphrase" })
        {
            using var password=Secret(text);
            byte[] old=LegacyEncrypt(plain,text), current=VaultEnvelope.Encrypt(plain,password);
            byte[] decoded=VaultEnvelope.Decrypt(old,password), independent=LegacyDecrypt(current,text);
            check(decoded.SequenceEqual(plain));check(independent.SequenceEqual(plain));check(!old.SequenceEqual(current));
            CryptographicOperations.ZeroMemory(decoded);CryptographicOperations.ZeroMemory(independent);
        }
        using var valid=Secret("synthetic-passphrase");using var wrong=Secret("synthetic-wrong-passphrase");
        byte[] fixture=VaultEnvelope.Encrypt(plain,valid);
        reject(()=>VaultEnvelope.Decrypt(fixture,wrong));reject(()=>VaultEnvelope.Decrypt(LegacyEncrypt(plain,"synthetic-passphrase","wrong-associated-data"),valid));
        foreach (string field in new[]{"Salt","Nonce","Tag","Ciphertext"})
        {
            var properties=JsonSerializer.Deserialize<Dictionary<string,JsonElement>>(fixture)!;
            byte[] bytes=Convert.FromBase64String(properties[field].GetString()!);bytes[0]^=1;
            properties[field]=JsonSerializer.SerializeToElement(Convert.ToBase64String(bytes));
            reject(()=>VaultEnvelope.Decrypt(JsonSerializer.SerializeToUtf8Bytes(properties),valid));
        }
        string json=Encoding.UTF8.GetString(fixture);
        reject(()=>VaultEnvelope.Decrypt(Encoding.UTF8.GetBytes(json.Replace("{","{\"Version\":1,",StringComparison.Ordinal)),valid));
        foreach(var alteration in new[]{json.Replace("\"Version\":1","\"Version\":\"1\""),json.Replace("\"Iterations\":600000","\"Iterations\":1"),json.Replace("\"Format\":","\"Unknown\":0,\"Format\":"),json.Replace("\"Salt\":","\"Salt\":null,\"RemovedSalt\":"),json.Replace("\"Salt\":","\"Salt\":0,\"RemovedSalt\":")})
            reject(()=>VaultEnvelope.Decrypt(Encoding.UTF8.GetBytes(alteration),valid));
        foreach(string field in new[]{"Salt","Nonce","Tag","Ciphertext"})
        {
            foreach(var badValue in new[]{JsonSerializer.SerializeToElement((string?)null),JsonSerializer.SerializeToElement(1),JsonSerializer.SerializeToElement("invalid-base64!"),JsonSerializer.SerializeToElement(new string(' ',128))})
            {
                var properties=JsonSerializer.Deserialize<Dictionary<string,JsonElement>>(fixture)!;properties[field]=badValue;
                reject(()=>VaultEnvelope.Decrypt(JsonSerializer.SerializeToUtf8Bytes(properties),valid));
            }
            if(field!="Ciphertext")
            {
                var properties=JsonSerializer.Deserialize<Dictionary<string,JsonElement>>(fixture)!;properties[field]=JsonSerializer.SerializeToElement(Convert.ToBase64String(new byte[1]));
                reject(()=>VaultEnvelope.Decrypt(JsonSerializer.SerializeToUtf8Bytes(properties),valid));
            }
        }
        reject(()=>VaultEnvelope.Decrypt(new byte[VaultEnvelope.MaximumEnvelopeBytes+1],valid));
        reject(()=>VaultEnvelope.Encrypt(new byte[VaultEnvelope.MaximumPlaintextBytes+1],valid));
        using var shortPassword=Secret("short");using var longPassword=Secret(new string('x',1025));
        reject(()=>VaultEnvelope.Encrypt(plain,shortPassword));reject(()=>VaultEnvelope.Encrypt(plain,longPassword));
        using var minimum=Secret(new string('x',12));using var maximum=Secret(new string('x',1024));
        foreach(var password in new[]{minimum,maximum})check(VaultEnvelope.Decrypt(VaultEnvelope.Encrypt(plain,password),password).SequenceEqual(plain));
        byte[] limit=new byte[VaultEnvelope.MaximumPlaintextBytes];byte[] full=VaultEnvelope.Encrypt(limit,valid);byte[] restored=VaultEnvelope.Decrypt(full,valid);check(restored.Length==limit.Length);CryptographicOperations.ZeroMemory(restored);
        try{VaultEnvelope.Decrypt(fixture,wrong);throw new Exception("Expected failure");}catch(InvalidOperationException error){check(error.InnerException==null && error.Message=="Vault envelope operation failed. Details suppressed.");}
    }
}
