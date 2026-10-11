using System.Text;
using System.Text.Json;
using System.Security.AccessControl;
using System.Security.Principal;
using TokenForge.Core;
using TokenForge.Core.V0210;

internal static class ProfileStoreChecks
{
    public static void Run(Action<bool> check, Action<Action> reject)
    {
        string root = Path.Combine(Path.GetTempPath(), "tokenforge-profile-" + Guid.NewGuid().ToString("N"));
        if (OperatingSystem.IsMacOS() && root.StartsWith("/var/")) root = "/private" + root;
        try
        {
            string missing = Path.Combine(root,"missing");
            reject(()=>ProfileStore.Read("lab",missing)); check(!Directory.Exists(root));
            reject(()=>ProfileStore.Create("../lab","example.onmicrosoft.com",root));
            reject(()=>ProfileStore.Create("lab","common",root));
            reject(()=>ProfileStore.Create("lab","example.onmicrosoft.com",root,storage:"unknown"));
            reject(()=>ProfileStore.Create("lab","example.onmicrosoft.com",root,maximumAgeHours:0));
            reject(()=>ProfileStore.Create("lab","example.onmicrosoft.com",root,passkeyPath:"/private/key"));
            check(!Directory.Exists(root));
            string json = ProfileStore.Create("lab","example.onmicrosoft.com",root);
            string path = Path.Combine(root,"lab","profile.json");
            using(var profile = JsonDocument.Parse(json))
            {
                check(profile.RootElement.GetProperty("Storage").GetString()=="Passphrase");
                check(profile.RootElement.GetProperty("StatePath").GetString()==Path.Combine(root,"lab","state"));
                check(profile.RootElement.GetProperty("ExpectedPrincipalFingerprint").ValueKind==JsonValueKind.Null);
            }
            check(ProfileStore.Read("lab",root)==json);
            reject(()=>ProfileStore.Create("lab","example.onmicrosoft.com",root));
            check(File.ReadAllText(path)==json);
            string lockedPath = PrivateFiles.Resolve(Path.Combine(root,"locked",".operation.lock"),true);
            using(var held = PrivateFiles.Open(lockedPath,true))
                reject(()=>ProfileStore.Create("locked","example.onmicrosoft.com",root));
            check(!File.Exists(Path.Combine(root,"locked","profile.json")));
            check(Directory.GetFiles(root,"*.tmp",SearchOption.AllDirectories).Length==0);
            if(!OperatingSystem.IsWindows())
            {
                check(((int)File.GetUnixFileMode(path)&63)==0);
                check(((int)File.GetUnixFileMode(Path.GetDirectoryName(path)!)&63)==0);
                File.SetUnixFileMode(path,UnixFileMode.UserRead);
                check(ProfileStore.Read("lab",root)==json);
                File.SetUnixFileMode(path,UnixFileMode.UserRead|UnixFileMode.UserWrite|UnixFileMode.GroupRead);
                reject(()=>ProfileStore.Read("lab",root));
                File.SetUnixFileMode(path,UnixFileMode.UserRead|UnixFileMode.UserWrite);
                string directory = Path.GetDirectoryName(path)!;
                File.SetUnixFileMode(directory,(UnixFileMode)493);
                reject(()=>ProfileStore.Read("lab",root));
                File.SetUnixFileMode(directory,(UnixFileMode)448);
                string link = Path.Combine(root,"leaf-link");
                File.CreateSymbolicLink(link,path); reject(()=>PrivateFiles.Resolve(link,false)); File.Delete(link);
                File.CreateSymbolicLink(link,Path.Combine(root,"absent")); reject(()=>PrivateFiles.Resolve(link,false)); File.Delete(link);
                Directory.CreateSymbolicLink(link,directory);
                reject(()=>PrivateFiles.Resolve(Path.Combine(link,"profile.json"),false)); Directory.Delete(link);
            }
            else
            {
                var file = new FileInfo(path);
                var acl = file.GetAccessControl();
                check(acl.AreAccessRulesProtected);
                foreach(string trusted in new[]{"S-1-5-18","S-1-5-32-544"})
                    acl.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(trusted),FileSystemRights.Read,AccessControlType.Allow));
                file.SetAccessControl(acl);
                check(ProfileStore.Read("lab",root)==json);
                var outsider = new FileSystemAccessRule(new SecurityIdentifier("S-1-1-0"),FileSystemRights.Read,AccessControlType.Allow);
                acl.AddAccessRule(outsider); file.SetAccessControl(acl);
                reject(()=>ProfileStore.Read("lab",root));
                acl.RemoveAccessRuleSpecific(outsider); file.SetAccessControl(acl);
            }
            foreach(Encoding encoding in new Encoding[]{new UTF8Encoding(true),Encoding.Unicode})
            {
                File.WriteAllBytes(path,encoding.GetPreamble().Concat(encoding.GetBytes(json)).ToArray());
                check(ProfileStore.Read("lab",root)==json);
            }
            File.WriteAllText(path,new string(' ',32769)); reject(()=>ProfileStore.Read("lab",root));
            File.WriteAllText(path,json.Insert(1,"\"Na\\u006de\":\"lab\",")); reject(()=>ProfileStore.Read("lab",root));
            try{ProfileStore.Read("lab",root);throw new Exception("Expected refusal.");}
            catch(InvalidOperationException error){check(error.InnerException==null);check(error.Message=="Profile cannot be read. Details suppressed.");}
            string osRoot=Path.Combine(root,"os");
            if(OperatingSystem.IsMacOS()) {reject(()=>ProfileStore.Create("lab","example.onmicrosoft.com",osRoot,storage:"OperatingSystem"));check(!Directory.Exists(osRoot));}
            else
            {
                using var os=JsonDocument.Parse(ProfileStore.Create("lab","example.onmicrosoft.com",osRoot,storage:"OperatingSystem"));
                check(os.RootElement.GetProperty("SchemaVersion").GetInt32()==2);
                check(os.RootElement.GetProperty("KeyId").GetString()!.Length==32);
                check(Directory.GetFiles(Path.Combine(osRoot,"lab")).Length==2); // Configuration and operation lock only.
            }
        }
        finally {if(Directory.Exists(root)) Directory.Delete(root,true);}
    }
}
