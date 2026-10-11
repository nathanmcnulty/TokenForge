using System.Security;
using System.Security.Cryptography;
using System.Text;
using TokenForge.Core.V0190;
using TokenForge.Core.V0220;

internal static class VaultFileChecks
{
    public static void Run(Action<bool> check, Action<Action> reject)
    {
        string root = Path.Combine(Path.GetTempPath(),"tokenforge-vault-files-"+Guid.NewGuid().ToString("N"));
        if(OperatingSystem.IsMacOS() && root.StartsWith("/var/")) root="/private"+root;
        string path=Path.Combine(root,"session.tfvault");
        using var password=new SecureString();
        foreach(char character in "synthetic-unlock-passphrase") password.AppendChar(character);
        password.MakeReadOnly();
        byte[] plain=Encoding.UTF8.GetBytes("{\"SchemaVersion\":1,\"Sessions\":{}}");
        byte[] encoded=VaultEnvelope.Encrypt(plain,password);
        try
        {
            reject(()=>VaultFileTransaction.Begin(path,"synthetic-private-invalid"));check(!Directory.Exists(root));
            reject(()=>VaultFileTransaction.Begin(path,"Read"));check(!Directory.Exists(root));
            reject(()=>VaultFileTransaction.Begin(path,"Update"));check(!Directory.Exists(root));
            using(var aborted=VaultFileTransaction.Begin(path,"Create")) {check(!File.Exists(path));reject(()=>aborted.ReadEnvelope());}
            check(!File.Exists(path));
            using(var create=VaultFileTransaction.Begin(path,"Create"))
            {
                reject(()=>VaultFileTransaction.Begin(path,"Create"));
                reject(()=>create.Commit(new byte[99]));check(!File.Exists(path));
                create.Commit(encoded);check(File.Exists(path));
                reject(()=>create.Commit(encoded));reject(()=>create.ReadEnvelope());
            }
            byte[] original=File.ReadAllBytes(path);
            reject(()=>VaultFileTransaction.Begin(path,"Create"));check(File.ReadAllBytes(path).SequenceEqual(original));
            using(var read=VaultFileTransaction.Begin(path,"Read"))
            {
                reject(()=>read.Commit(encoded));
                byte[] decrypted=VaultEnvelope.Decrypt(read.ReadEnvelope(),password);
                try{check(decrypted.SequenceEqual(plain));}finally{CryptographicOperations.ZeroMemory(decrypted);}
                reject(()=>VaultFileTransaction.Begin(path,"Update"));
            }
            using(var update=VaultFileTransaction.Begin(path,"Update"))
            {
                reject(()=>update.Commit(encoded));check(File.ReadAllBytes(path).SequenceEqual(original));
                check(update.ReadEnvelope().SequenceEqual(original));
                update.Commit(VaultEnvelope.Encrypt(plain,password));
            }
            check(!File.ReadAllBytes(path).SequenceEqual(original));
            var disposed=VaultFileTransaction.Begin(path,"Read");disposed.Dispose();disposed.Dispose();
            reject(()=>disposed.ReadEnvelope());reject(()=>disposed.Commit(encoded));
            using(var reopened=VaultFileTransaction.Begin(path,"Read")) check(reopened.ReadEnvelope().Length>=100);
            // An uncooperative creator cannot be overwritten by a pending Create transaction.
            string conflict=Path.Combine(root,"conflict.tfvault");
            using(var create=VaultFileTransaction.Begin(conflict,"Create"))
            {
                using(var other=PrivateFiles.Open(conflict,true)) other.Write(encoded);
                reject(()=>create.Commit(encoded));check(File.ReadAllBytes(conflict).SequenceEqual(encoded));
            }
            check(Directory.GetFiles(root,"*.tmp").Length==0);
            File.WriteAllBytes(path,new byte[99]);
            using(var shortFile=VaultFileTransaction.Begin(path,"Read")) reject(()=>shortFile.ReadEnvelope());
            using(var oversized=new FileStream(path,FileMode.Open,FileAccess.Write)) oversized.SetLength(16777217);
            using(var largeFile=VaultFileTransaction.Begin(path,"Read")) reject(()=>largeFile.ReadEnvelope());
            try{VaultFileTransaction.Begin(path,"synthetic-private-invalid");throw new Exception("Expected refusal.");}
            catch(InvalidOperationException error){check(error.InnerException==null);check(error.Message=="Vault file transaction failed. Details suppressed.");}
            if(!OperatingSystem.IsWindows())
            {
                check(((int)File.GetUnixFileMode(path)&63)==0);
                check(((int)File.GetUnixFileMode(path+".lock")&63)==0);
                string link=Path.Combine(root,"linked.tfvault");File.CreateSymbolicLink(link,path);
                reject(()=>VaultFileTransaction.Begin(link,"Read"));
            }
        }
        finally {CryptographicOperations.ZeroMemory(plain);if(Directory.Exists(root)) Directory.Delete(root,true);}
    }
}
