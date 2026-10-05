#nullable disable
using System;
using System.Runtime.InteropServices;
using System.Security;
using System.Security.Cryptography;
using System.Threading;

namespace TokenForge.Core.V0110
{
    // OS stores protect a random vault password. They do not isolate other processes of this user.
    public static class PlatformVaultKey
    {
        public static string Backend { get { return OperatingSystem.IsWindows() ? "WindowsCredentialManager" : OperatingSystem.IsLinux() ? "LinuxSecretService" : "Unsupported"; } }
        public static SecureString Open(string handle, bool create)
        {
            ValidateHandle(handle);
            string value = null;
            try
            {
                value = Read(handle);
                if (value == null)
                {
                    if (!create) throw new InvalidOperationException();
                    byte[] bytes = RandomNumberGenerator.GetBytes(32);
                    try { value = Convert.ToBase64String(bytes); } finally { CryptographicOperations.ZeroMemory(bytes); }
                    Write(handle, value);
                    // Detect store failures or an unexpected replacement before encrypting anything.
                    if (Read(handle) != value) throw new InvalidOperationException();
                }
                ValidateValue(value);
                var secret = new SecureString();
                foreach (char c in value) secret.AppendChar(c);
                secret.MakeReadOnly();
                return secret;
            }
            catch { throw new InvalidOperationException("Operating-system vault key unavailable. Unlock the OS store or use an explicitly created Passphrase profile. Existing keys are never replaced to recover a vault."); }
            finally { value = null; }
        }
        public static void Delete(string handle)
        {
            ValidateHandle(handle);
            try
            {
                if (OperatingSystem.IsWindows()) { if (!CredDelete("TokenForge/v1/" + handle, 1, 0) && Marshal.GetLastWin32Error() != 1168) throw new InvalidOperationException(); }
                else if (OperatingSystem.IsLinux()) Linux(handle, null, 2);
                else throw new PlatformNotSupportedException();
            }
            catch { throw new InvalidOperationException("Operating-system vault key deletion failed. Details suppressed."); }
        }
        private static void ValidateHandle(string handle)
        {
            if (handle == null || handle.Length != 64) throw new ArgumentException("Invalid vault key handle.");
            foreach (char c in handle) if (!(c >= '0' && c <= '9') && !(c >= 'a' && c <= 'f')) throw new ArgumentException("Invalid vault key handle.");
        }
        private static void ValidateValue(string value)
        {
            if (value == null || value.Length != 44) throw new InvalidOperationException();
            byte[] bytes = Convert.FromBase64String(value);
            try { if (bytes.Length != 32 || Convert.ToBase64String(bytes) != value) throw new InvalidOperationException(); }
            finally { CryptographicOperations.ZeroMemory(bytes); }
        }
        private static string Read(string handle)
        {
            if (OperatingSystem.IsLinux()) return Linux(handle, null, 0);
            if (!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException();
            IntPtr pointer;
            if (!CredRead("TokenForge/v1/" + handle, 1, 0, out pointer))
            {
                if (Marshal.GetLastWin32Error() == 1168) return null;
                throw new InvalidOperationException();
            }
            Credential credential = default(Credential);
            try
            {
                credential = Marshal.PtrToStructure<Credential>(pointer);
                if (credential.Size != 44 || credential.Blob == IntPtr.Zero) throw new InvalidOperationException();
                byte[] bytes = new byte[44];
                try { Marshal.Copy(credential.Blob, bytes, 0, 44); return System.Text.Encoding.ASCII.GetString(bytes); }
                finally { CryptographicOperations.ZeroMemory(bytes); }
            }
            finally { if (credential.Blob != IntPtr.Zero && credential.Size == 44) for (int i=0;i<44;i++) Marshal.WriteByte(credential.Blob,i,0); CredFree(pointer); }
        }
        private static void Write(string handle, string value)
        {
            if (OperatingSystem.IsLinux()) { Linux(handle, value, 1); return; }
            if (!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException();
            IntPtr blob = Marshal.StringToCoTaskMemUTF8(value);
            try
            {
                var credential = new Credential { Type=1, Target="TokenForge/v1/"+handle, Size=44, Blob=blob, Persist=2, User="TokenForge" };
                if (!CredWrite(ref credential, 0)) throw new InvalidOperationException();
            }
            finally { for(int i=0;i<45;i++) Marshal.WriteByte(blob,i,0); Marshal.FreeCoTaskMem(blob); }
        }
        // libsecret calls can prompt to unlock. Cancellation is cooperative; no plaintext fallback.
        private static string Linux(string handle, string value, int operation)
        {
            IntPtr table=IntPtr.Zero, cancel=IntPtr.Zero, error=IntPtr.Zero, result=IntPtr.Zero;
            IntPtr[] strings=new IntPtr[6]; IntPtr password=IntPtr.Zero;
            Timer timer=null;
            try
            {
                table=g_hash_table_new(g_str_hash_ptr, g_str_equal_ptr);
                if(table==IntPtr.Zero) throw new InvalidOperationException();
                strings[0]=Marshal.StringToCoTaskMemUTF8("application"); strings[1]=Marshal.StringToCoTaskMemUTF8("org.tokenforge.vault.v1");
                strings[2]=Marshal.StringToCoTaskMemUTF8("key"); strings[3]=Marshal.StringToCoTaskMemUTF8(handle);
                strings[4]=Marshal.StringToCoTaskMemUTF8("version"); strings[5]=Marshal.StringToCoTaskMemUTF8("1");
                for(int i=0;i<6;i+=2) g_hash_table_insert(table, strings[i], strings[i+1]);
                cancel=g_cancellable_new();
                if(table==IntPtr.Zero || cancel==IntPtr.Zero) throw new InvalidOperationException();
                timer=new Timer(_=>g_cancellable_cancel(cancel),null,TimeSpan.FromSeconds(30),Timeout.InfiniteTimeSpan);
                if(operation==0)
                {
                    int matches=LinuxMatchCount(table,cancel);
                    if(matches==0) return null;
                    if(matches!=1) throw new InvalidOperationException();
                    result=secret_password_lookupv_sync(IntPtr.Zero,table,cancel,out error);
                    if(error!=IntPtr.Zero) throw new InvalidOperationException();
                    if(result==IntPtr.Zero) throw new InvalidOperationException();
                    int length=0; while(length<=44 && Marshal.ReadByte(result,length)!=0) length++;
                    if(length!=44) throw new InvalidOperationException();
                    return Marshal.PtrToStringUTF8(result,44);
                }
                if(operation==1)
                {
                    password=Marshal.StringToCoTaskMemUTF8(value);
                    if(!secret_password_storev_sync(IntPtr.Zero,table,"default","TokenForge vault key",password,cancel,out error) || error!=IntPtr.Zero) throw new InvalidOperationException();
                }
                else
                {
                    secret_password_clearv_sync(IntPtr.Zero,table,cancel,out error);
                    if(error!=IntPtr.Zero || LinuxMatchCount(table,cancel)!=0) throw new InvalidOperationException();
                }
                return null;
            }
            finally
            {
                if(timer!=null) { using(var done=new ManualResetEvent(false)) { if(timer.Dispose(done)) done.WaitOne(); } }
                if(result!=IntPtr.Zero) secret_password_free(result);
                if(password!=IntPtr.Zero) { for(int i=0;i<45;i++) Marshal.WriteByte(password,i,0); Marshal.FreeCoTaskMem(password); }
                if(error!=IntPtr.Zero) g_error_free(error);
                if(cancel!=IntPtr.Zero) g_object_unref(cancel);
                if(table!=IntPtr.Zero) g_hash_table_unref(table);
                foreach(var text in strings) if(text!=IntPtr.Zero) Marshal.FreeCoTaskMem(text);
            }
        }
        private static int LinuxMatchCount(IntPtr table, IntPtr cancel)
        {
            IntPtr error=IntPtr.Zero, list=IntPtr.Zero;
            try
            {
                // SEARCH_ALL=2 includes locked items; neither unlock nor secret loading is requested.
                list=secret_service_search_sync(IntPtr.Zero,IntPtr.Zero,table,2,cancel,out error);
                if(error!=IntPtr.Zero) throw new InvalidOperationException();
                int count=0;
                for(var node=list;node!=IntPtr.Zero;node=Marshal.ReadIntPtr(node,IntPtr.Size)) count++;
                return count;
            }
            finally
            {
                for(var node=list;node!=IntPtr.Zero;node=Marshal.ReadIntPtr(node,IntPtr.Size)) g_object_unref(Marshal.ReadIntPtr(node));
                if(list!=IntPtr.Zero) g_list_free(list);
                if(error!=IntPtr.Zero) g_error_free(error);
            }
        }
        private const string Secret="libsecret-1.so.0", Glib="libglib-2.0.so.0", Gio="libgio-2.0.so.0", GObject="libgobject-2.0.so.0";
        // Delegates remain rooted for the lifetime of native hash tables.
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)] private delegate uint Hash(IntPtr key);
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)] private delegate int Equal(IntPtr left,IntPtr right);
        private static readonly Hash hash=g_str_hash; private static readonly Equal equal=g_str_equal;
        private static readonly IntPtr g_str_hash_ptr=Marshal.GetFunctionPointerForDelegate(hash), g_str_equal_ptr=Marshal.GetFunctionPointerForDelegate(equal);
        [DllImport(Glib)] private static extern uint g_str_hash(IntPtr key);
        [DllImport(Glib)] private static extern int g_str_equal(IntPtr left,IntPtr right);
        [DllImport(Glib)] private static extern IntPtr g_hash_table_new(IntPtr hash,IntPtr equal);
        [DllImport(Glib)] private static extern void g_hash_table_insert(IntPtr table,IntPtr key,IntPtr value);
        [DllImport(Glib)] private static extern void g_hash_table_unref(IntPtr table);
        [DllImport(Glib)] private static extern void g_list_free(IntPtr list);
        [DllImport(Secret)] private static extern IntPtr secret_service_search_sync(IntPtr service,IntPtr schema,IntPtr attrs,int flags,IntPtr cancel,out IntPtr error);
        [DllImport(Glib)] private static extern void g_error_free(IntPtr error);
        [DllImport(Gio)] private static extern IntPtr g_cancellable_new();
        [DllImport(Gio)] private static extern void g_cancellable_cancel(IntPtr cancel);
        [DllImport(GObject)] private static extern void g_object_unref(IntPtr obj);
        [DllImport(Secret)] private static extern IntPtr secret_password_lookupv_sync(IntPtr schema,IntPtr attrs,IntPtr cancel,out IntPtr error);
        [DllImport(Secret)] [return:MarshalAs(UnmanagedType.Bool)] private static extern bool secret_password_storev_sync(IntPtr schema,IntPtr attrs,[MarshalAs(UnmanagedType.LPUTF8Str)] string collection,[MarshalAs(UnmanagedType.LPUTF8Str)] string label,IntPtr password,IntPtr cancel,out IntPtr error);
        [DllImport(Secret)] [return:MarshalAs(UnmanagedType.Bool)] private static extern bool secret_password_clearv_sync(IntPtr schema,IntPtr attrs,IntPtr cancel,out IntPtr error);
        [DllImport(Secret)] private static extern void secret_password_free(IntPtr password);
        [StructLayout(LayoutKind.Sequential,CharSet=CharSet.Unicode)] private struct Credential
        {
            public uint Flags,Type; public string Target,Comment; public System.Runtime.InteropServices.ComTypes.FILETIME Written;
            public uint Size; public IntPtr Blob; public uint Persist,AttributeCount; public IntPtr Attributes; public string Alias,User;
        }
        [DllImport("advapi32.dll",EntryPoint="CredReadW",CharSet=CharSet.Unicode,SetLastError=true)] [return:MarshalAs(UnmanagedType.Bool)] private static extern bool CredRead(string target,uint type,uint flags,out IntPtr credential);
        [DllImport("advapi32.dll",EntryPoint="CredWriteW",CharSet=CharSet.Unicode,SetLastError=true)] [return:MarshalAs(UnmanagedType.Bool)] private static extern bool CredWrite(ref Credential credential,uint flags);
        [DllImport("advapi32.dll",EntryPoint="CredDeleteW",CharSet=CharSet.Unicode,SetLastError=true)] [return:MarshalAs(UnmanagedType.Bool)] private static extern bool CredDelete(string target,uint type,uint flags);
        [DllImport("advapi32.dll")] private static extern void CredFree(IntPtr credential);
    }
}
