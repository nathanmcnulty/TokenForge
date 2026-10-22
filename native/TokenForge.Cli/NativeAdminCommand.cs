using System.Globalization;
using System.Text.Json;
using TokenForge.Core;

internal static class NativeAdminCommand
{
    internal static int Run(string[] args)
    {
        if(args.Length<2 || args[1] is not ("explain" or "check" or "acquire" or "packet" or "evidence"))throw new InvalidOperationException();string command=args[1];
        var values=new Dictionary<string,string>(StringComparer.Ordinal);var flags=new HashSet<string>(StringComparer.Ordinal);
        var allowed=command=="evidence"?new[]{"--acquisition-path"}:command=="packet"?new[]{"--requirements-path","--before-path","--after-path","--source-revision","--package-sha256","--max-entries","--max-age-hours","--as-of"}:command=="acquire"?new[]{"--profile-path","--requirements-path","--inventory-path","--tool","--prerequisites-path","--client","--callback-fingerprint","--cookie-name"}:new[]{"--profile-path","--requirements-path","--inventory-path","--snapshot-path","--tool","--prerequisites-path","--as-of"};
        for(int i=2;i<args.Length;i++){
            string flag=args[i];if(!flags.Add(flag))throw new InvalidOperationException();if(flag=="--json" || command=="packet" && flag=="--security-sensitive" || command=="acquire" && flag is "--cookie-stdin" or "--operation-check")continue;
            if(!allowed.Contains(flag,StringComparer.Ordinal) || ++i>=args.Length || args[i].StartsWith("--",StringComparison.Ordinal) || args[i].Length is <1 or >4096)throw new InvalidOperationException();values[flag]=args[i];
        }
        string Required(string flag)=>values.GetValueOrDefault(flag) ?? throw new InvalidOperationException();
        string Read(string flag)=>ChangeReportFiles.Read(Required(flag));
        int Number(string flag,int fallback,int max)=>values.TryGetValue(flag,out var value)?int.TryParse(value,NumberStyles.None,CultureInfo.InvariantCulture,out int n) && n>=1 && n<=max?n:throw new InvalidOperationException():fallback;
        DateTimeOffset? asOf=null;if(values.TryGetValue("--as-of",out var date)){
            if(!System.Text.RegularExpressions.Regex.IsMatch(date,@"\A\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,7})?(?:Z|[+-]\d\d:\d\d)\z") || !DateTimeOffset.TryParse(date,CultureInfo.InvariantCulture,DateTimeStyles.None,out var instant))throw new InvalidOperationException();asOf=instant;
        }
        string output;
        if(command=="evidence"){output=AdminWorkflows.AcquisitionEvidence(Read("--acquisition-path"));Console.WriteLine(output);return 0;}
        if(command=="packet"){
            int entries=Number("--max-entries",64,128),hours=Number("--max-age-hours",24,87600);string revision=Required("--source-revision"),sha=Required("--package-sha256");
            output=AdminWorkflows.PreparePacket(Read("--requirements-path"),Read("--before-path"),Read("--after-path"),revision,sha,entries,hours,asOf,flags.Contains("--security-sensitive"));
        }else{
            string tool=Required("--tool"),profile=Read("--profile-path"),requirements=Read("--requirements-path"),inventory=Read("--inventory-path"),prerequisites=values.ContainsKey("--prerequisites-path")?Read("--prerequisites-path"):null!;
            if(command=="acquire"){
                // All metadata and the concrete route validate before optional stdin credential access.
                string? client=values.GetValueOrDefault("--client"),callback=values.GetValueOrDefault("--callback-fingerprint");AdminWorkflows.Plan(profile,requirements,inventory,tool,client,callback);
                string cookieName=values.GetValueOrDefault("--cookie-name") ?? "ESTSAUTH";if(cookieName is not ("ESTSAUTH" or "ESTSAUTHPERSISTENT"))throw new InvalidOperationException();
                using(var preflight=AdminWorkflows.Acquire(profile,requirements,inventory,tool,null,cookieName,client,callback,flags.Contains("--operation-check"),prerequisites)){
                    using var state=JsonDocument.Parse(preflight.ToJson());
                    if(!flags.Contains("--cookie-stdin") || state.RootElement.GetProperty("Reason").GetString()!="ExistingSilentSessionRequired"){Console.WriteLine(preflight.ToJson());return state.RootElement.GetProperty("ExitCode").GetInt32();}
                }
                using var cookie=flags.Contains("--cookie-stdin")?NativeTokenCommand.ReadCredential(true,1,16384,"Existing session cookie (hidden): "):null;
                using var cancel=new CancellationTokenSource();ConsoleCancelEventHandler handler=(_,e)=>{e.Cancel=true;cancel.Cancel();};Console.CancelKeyPress+=handler;
                try{using var result=AdminWorkflows.Acquire(profile,requirements,inventory,tool,cookie,cookieName,client,callback,flags.Contains("--operation-check"),prerequisites,cancellation:cancel.Token);output=result.ToJson();}finally{Console.CancelKeyPress-=handler;}
            }else{
                string snapshot=Read("--snapshot-path");output=command=="explain"?AdminWorkflows.Explain(profile,requirements,inventory,snapshot,tool,prerequisites,asOf):AdminWorkflows.Check(profile,requirements,inventory,snapshot,tool,prerequisites,asOf);
            }
        }
        using var document=JsonDocument.Parse(output);int exit=document.RootElement.GetProperty("ExitCode").GetInt32();Console.WriteLine(output);return exit;
    }
}
