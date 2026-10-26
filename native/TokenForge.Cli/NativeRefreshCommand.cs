using System.Globalization;
using System.Text.Json;
using TokenForge.Core;

internal static class NativeRefreshCommand
{
    internal static int Run(string[] args)
    {
        if(args.Length<2 || args[1] is not ("plan" or "validate" or "capture" or "status" or "project"))throw new InvalidOperationException();
        string command=args[1];var values=new Dictionary<string,string>(StringComparer.Ordinal);var seen=new HashSet<string>(StringComparer.Ordinal);
        string[] allowed=command=="plan"?new[]{"--input-path","--as-of"}:command=="validate"?new[]{"--plan-path"}:command=="capture"?new[]{"--plan-path","--snapshot-path","--history-path"}:command=="status"?new[]{"--plan-path","--state-path"}:new[]{"--plan-path","--state-path","--history-path"};
        for(int i=2;i<args.Length;i++){string key=args[i];if(!seen.Add(key))throw new InvalidOperationException();if(key=="--json")continue;if(!allowed.Contains(key,StringComparer.Ordinal) || ++i>=args.Length || args[i].Length is <1 or >4096 || args[i].StartsWith("--",StringComparison.Ordinal))throw new InvalidOperationException();values.Add(key,args[i]);}
        string Read(string key)=>ChangeReportFiles.Read(values.GetValueOrDefault(key) ?? throw new InvalidOperationException());
        string? history=values.ContainsKey("--history-path")?Read("--history-path"):null;
        string output;
        if(command=="plan"){
            DateTimeOffset? at=null;if(values.TryGetValue("--as-of",out var text)){if(!System.Text.RegularExpressions.Regex.IsMatch(text,@"\A\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,7})?(?:Z|[+-]\d\d:\d\d)\z") || !DateTimeOffset.TryParse(text,CultureInfo.InvariantCulture,DateTimeStyles.None,out var date))throw new InvalidOperationException();at=date;}
            output=AdminWorkflows.PlanRefresh(Read("--input-path"),at);
        }else if(command=="validate")output=AdminWorkflows.ValidateRefresh(Read("--plan-path"));
        else if(command=="capture")output=AdminWorkflows.CaptureRefreshEvidence(Read("--plan-path"),Read("--snapshot-path"),history);
        else{
            string path=values.GetValueOrDefault("--state-path") ?? throw new InvalidOperationException();if(!File.Exists(path))throw new InvalidOperationException();
            using var run=AdminWorkflows.OpenRefreshRun(Read("--plan-path"),path);output=command=="status"?run.Status():run.ProjectHistory(history);
        }
        Console.WriteLine(output);using var result=JsonDocument.Parse(output);
        return result.RootElement.TryGetProperty("ExitCode",out var exit)?exit.GetInt32():command=="status" && result.RootElement.GetProperty("PendingCount").GetInt32()>0?3:0;
    }
}
