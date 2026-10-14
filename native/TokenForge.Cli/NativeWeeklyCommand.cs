using System.Text;
using System.Text.Json;
using TokenForge.Core;

internal static class NativeWeeklyCommand
{
    internal static int Run(string[] args)
    {
        string? statePath=null;bool json=false;
        var seen=new HashSet<string>(StringComparer.Ordinal);
        for(int i=2;i<args.Length;i++) {
            string option=args[i];if(!seen.Add(option))throw new InvalidOperationException();
            if(option=="--json"){json=true;continue;}
            if(option!="--state-path" || ++i==args.Length || args[i].StartsWith('-') || args[i].Length is <1 or >4096)throw new InvalidOperationException();
            statePath=args[i];
        }
        if(statePath==null)throw new InvalidOperationException();
        string root=Path.GetFullPath(statePath);
        RejectLinks(root);
        if(!Directory.Exists(root))throw new InvalidOperationException();
        DateTimeOffset now=DateTimeOffset.UtcNow;
        var reports=new List<JsonElement>();
        foreach(string mode in new[]{"Shallow","Deep"}) {
            string path=Path.Combine(root,"weekly-"+mode.ToLowerInvariant()+".json");
            // Reject dangling links as well as links to regular files.
            if(new FileInfo(path).LinkTarget!=null)throw new InvalidOperationException();
            if(!File.Exists(path))continue;
            RejectLinks(path);
            using var file=new FileStream(path,FileMode.Open,FileAccess.Read,FileShare.Read);
            if(file.Length is <1 or >134217728)throw new InvalidOperationException();
            byte[] bytes=new byte[checked((int)file.Length)];file.ReadExactly(bytes);
            if(file.ReadByte()!=-1)throw new InvalidOperationException();
            int offset=bytes.Length>=3 && bytes[0]==0xef && bytes[1]==0xbb && bytes[2]==0xbf ? 3 : 0;
            string text=new UTF8Encoding(false,true).GetString(bytes,offset,bytes.Length-offset);
            using var report=JsonDocument.Parse(WeeklyResearchReport.Create(text,mode,now));
            reports.Add(report.RootElement.Clone());
        }
        if(reports.Count==0)throw new InvalidOperationException();
        string week=$"{System.Globalization.ISOWeek.GetYear(now.UtcDateTime):D4}-W{System.Globalization.ISOWeek.GetWeekOfYear(now.UtcDateTime):D2}";
        if(json)Console.WriteLine(JsonSerializer.Serialize(new{SchemaVersion=1,CurrentWeek=week,Reports=reports,Evidence="OfflineFrozenRecipesNotUniversalSupportOrApiAuthorization",CredentialOutput=false}));
        else {
            foreach(var r in reports) {
                string Value(string name)=>r.GetProperty(name).ToString();
                Console.WriteLine($"{Value("Mode")} [{Value("Week")}]: {Value("AssessedApplications")}/{Value("SelectedApplications")} applications assessed; {Value("AssessedPairs")}/{Value("SelectedPairs")} resource pairs assessed; {Value("SuccessfulApplications")} apps / {Value("SuccessfulPairs")} pairs succeeded.");
                Console.WriteLine($"Remaining: {Value("RemainingApplications")} applications / {Value("RemainingPairs")} pairs; pending batches {Value("PendingBatches")}, exhausted {Value("ExhaustedBatches")}. {Value("NextAction")}");
            }
            Console.WriteLine("Assessment includes structural exclusions. Successful token observations do not establish universal support or API authorization.");
        }
        return 0;
    }
    private static void RejectLinks(string path)
    {
        for(string? part=path;!string.IsNullOrEmpty(part);part=Path.GetDirectoryName(part))
            if((File.GetAttributes(part)&FileAttributes.ReparsePoint)!=0)throw new InvalidOperationException();
    }
}
