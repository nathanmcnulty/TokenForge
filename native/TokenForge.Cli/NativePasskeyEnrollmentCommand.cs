using System.Text.Json;
using TokenForge.Core;

internal static class NativePasskeyEnrollmentCommand
{
    internal static int Run(string[] args)
    {
        var seen=new HashSet<string>(StringComparer.Ordinal);var options=new Dictionary<string,string>(StringComparer.Ordinal);
        for(int i=2;i<args.Length;i++)
        {
            string option=args[i];if(!seen.Add(option))throw new InvalidOperationException();
            if(option=="--json")continue;
            if(option is not ("--passkey-file" or "--identity-file" or "--output-path" or "--name" or "--max-extra-scopes") || ++i==args.Length || args[i].StartsWith('-') || args[i].Length is <1 or >4096)throw new InvalidOperationException();
            options[option]=args[i];
        }
        if(!options.ContainsKey("--passkey-file") || !options.ContainsKey("--identity-file") || !options.ContainsKey("--output-path"))throw new InvalidOperationException();
        int maximum=0;
        if(options.TryGetValue("--max-extra-scopes",out var allowance) && (!int.TryParse(allowance,System.Globalization.NumberStyles.None,System.Globalization.CultureInfo.InvariantCulture,out maximum) || maximum is <0 or >512))throw new InvalidOperationException();
        using var cancellation=new CancellationTokenSource();ConsoleCancelEventHandler cancel=(_,e)=>{e.Cancel=true;cancellation.Cancel();};Console.CancelKeyPress+=cancel;
        try
        {
            var result=SoftwarePasskeyEnrollment.Enroll(options["--passkey-file"],NativeScopeCommand.ReadJson(options["--identity-file"]),options["--output-path"],options.GetValueOrDefault("--name") ?? "Test",cancellation.Token,maximum);
            Console.WriteLine(JsonSerializer.Serialize(new{SchemaVersion=1,Result=result}));return 0;
        }
        finally{Console.CancelKeyPress-=cancel;}
    }
}
