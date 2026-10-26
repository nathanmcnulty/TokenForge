using System.Globalization;
using TokenForge.Core;

internal static class NativeChangesCommand
{
    internal static int Run(string[] args)
    {
        var options=new Dictionary<string,string>(StringComparer.Ordinal);var seen=new HashSet<string>(StringComparer.Ordinal);bool publicOnly=false;
        bool snapshot=args[1]=="snapshot";
        var allowed=snapshot?new[]{"--input-path","--kind"}:new[]{"--before-path","--after-path","--kind","--max-age-hours","--as-of"};
        for(int i=2;i<args.Length;i++){
            string flag=args[i];if(!seen.Add(flag))throw new InvalidOperationException();if(flag=="--json")continue;
            if(!snapshot && flag=="--public-only"){publicOnly=true;continue;}
            if(!allowed.Contains(flag,StringComparer.Ordinal) || ++i>=args.Length || args[i].StartsWith("--",StringComparison.Ordinal) || args[i].Length is <1 or >4096)throw new InvalidOperationException();options[flag]=args[i];
        }
        string kind=options.GetValueOrDefault("--kind") ?? "Snapshot";
        if(!new[]{"Snapshot","PublicPermissions","Discovery","Inventory","ScopeDatabase","FlowEvidence","Anonymous","ApiChecks","Maintenance"}.Contains(kind,StringComparer.Ordinal))throw new InvalidOperationException();
        // Validate every option before reading files. No profile or authentication fallback.
        if(snapshot){if(!options.ContainsKey("--input-path"))throw new InvalidOperationException();Console.WriteLine(ChangeReports.Normalize(kind,ChangeReportFiles.Read(options["--input-path"])));return 0;}
        int hours=24;if(options.TryGetValue("--max-age-hours",out var h) && (!int.TryParse(h,NumberStyles.None,CultureInfo.InvariantCulture,out hours) || hours is <1 or >87600))throw new InvalidOperationException();
        DateTimeOffset? asOf=null;if(options.TryGetValue("--as-of",out var date)){
            if(!System.Text.RegularExpressions.Regex.IsMatch(date,@"\A\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,7})?(?:Z|[+-]\d\d:\d\d)\z") || !DateTimeOffset.TryParse(date,CultureInfo.InvariantCulture,DateTimeStyles.None,out var instant))throw new InvalidOperationException();asOf=instant;
        }
        if(!options.ContainsKey("--before-path") || !options.ContainsKey("--after-path"))throw new InvalidOperationException();
        string before=ChangeReportFiles.Read(options["--before-path"]),after=ChangeReportFiles.Read(options["--after-path"]);
        Console.WriteLine(ChangeReports.CompareSaved(kind,before,after,hours,asOf,publicOnly));return 0;
    }
}
