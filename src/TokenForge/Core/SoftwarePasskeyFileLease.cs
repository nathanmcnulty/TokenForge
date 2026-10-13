#nullable enable
using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using TokenForge.Core.V0220;

namespace TokenForge.Core;

// The external authentication provider reads the file itself. Hold a read lease
// and verify its immutable inputs before allowing its returned cookie to escape.
public sealed class SoftwarePasskeyFileLease : IDisposable
{
    private readonly string path;
    private readonly FileStream stream;
    private readonly byte[] hash;
    private readonly bool pending;
    private bool disposed;
    private SoftwarePasskeyFileLease(string path,FileStream stream,byte[] hash,bool pending)
    {this.path=path;this.stream=stream;this.hash=hash;this.pending=pending;}
    public static SoftwarePasskeyFileLease Open(string path)
    {
        FileStream? stream=null;byte[]? bytes=null,hash=null;
        try
        {
            path=PrivateFiles.Resolve(path,false);
            stream=new FileStream(path,FileMode.Open,FileAccess.Read,FileShare.Read);
            bytes=Read(stream);
            // Validate UTF-8 without creating a second managed plaintext string.
            _=new UTF8Encoding(false,true).GetCharCount(bytes);
            ReadOnlyMemory<byte> payload=bytes;
            if(bytes.Length>=3 && bytes[0]==0xef && bytes[1]==0xbb && bytes[2]==0xbf)payload=payload.Slice(3);
            using var json=JsonDocument.Parse(payload,new JsonDocumentOptions{MaxDepth=16});
            var root=json.RootElement;if(root.ValueKind!=JsonValueKind.Object)throw new InvalidOperationException();
            DiscoverySourceClaims.ValidateUniqueKeys(root);hash=SHA256.HashData(bytes);
            bool pending=root.TryGetProperty("enrollmentStatus",out _);
            if(pending)ValidatePending(path,hash);
            var result=new SoftwarePasskeyFileLease(path,stream,hash,pending);stream=null;hash=null;return result;
        }
        catch{throw new InvalidOperationException("Unsupported or inaccessible software passkey. Details suppressed.");}
        finally{stream?.Dispose();if(bytes!=null)CryptographicOperations.ZeroMemory(bytes);if(hash!=null)CryptographicOperations.ZeroMemory(hash);}
    }
    public void ConfirmUnchanged()
    {
        byte[]? bytes=null;
        try
        {
            if(disposed)throw new InvalidOperationException();
            using var current=new FileStream(PrivateFiles.Resolve(path,false),FileMode.Open,FileAccess.Read,FileShare.Read);
            bytes=Read(current);byte[] digest=SHA256.HashData(bytes);
            try{if(!CryptographicOperations.FixedTimeEquals(hash,digest))throw new InvalidOperationException();}
            finally{CryptographicOperations.ZeroMemory(digest);}
            if(pending)ValidatePending(path,hash);
        }
        catch{throw new InvalidOperationException("Software passkey changed or its evidence is unavailable. Details suppressed.");}
        finally{if(bytes!=null)CryptographicOperations.ZeroMemory(bytes);}
    }
    private static void ValidatePending(string path,byte[] hash)
    {
        // Normal opening performs status, receipt, key-format and byte-binding
        // checks. This adapter cannot open an unconfirmed pending key.
        using var signer=SoftwarePasskey.Open(path);
        if(signer.FileHash!=Convert.ToHexString(hash).ToLowerInvariant())throw new InvalidOperationException();
    }
    private static byte[] Read(FileStream file)
    {
        if(file.Length is <2 or >65536)throw new InvalidOperationException();
        byte[] bytes=new byte[checked((int)file.Length)];try{file.ReadExactly(bytes);return bytes;}catch{CryptographicOperations.ZeroMemory(bytes);throw;}
    }
    public void Dispose(){if(disposed)return;disposed=true;try{stream.Dispose();}finally{CryptographicOperations.ZeroMemory(hash);}}
}
