#nullable enable
using System;
using System.IO;
using System.Text;
namespace TokenForge.Core;

// Explicit local JSON ingress only. Never discovers profiles or opens credential stores.
public static class ChangeReportFiles
{
    public static string Read(string path)
    {
        try{
            path=V0220.PrivateFiles.Resolve(path,false);
            using var file=new FileStream(path,FileMode.Open,FileAccess.Read,FileShare.Read);
            if(file.Length>ChangeReports.MaxBytes)throw new InvalidOperationException();
            var bytes=new byte[checked((int)file.Length)];file.ReadExactly(bytes);if(file.ReadByte()!=-1)throw new InvalidOperationException();
            int offset=bytes.Length>=3 && bytes[0]==0xef && bytes[1]==0xbb && bytes[2]==0xbf?3:0;
            return new UTF8Encoding(false,true).GetString(bytes,offset,bytes.Length-offset);
        }catch{throw new InvalidOperationException("Change evidence file is invalid or unavailable. No report produced.");}
    }
}
