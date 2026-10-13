using System.Text.Json;
using TokenForge.Core;

internal static class NativePasskeyCommand
{
    internal static int Run(string[] args)
    {
        var options=new Dictionary<string,string>(StringComparer.Ordinal);var seen=new HashSet<string>(StringComparer.Ordinal);
        for(int i=2;i<args.Length;i++)
        {
            string option=args[i];if(!seen.Add(option))throw new InvalidOperationException();
            if(option=="--json")continue;
            if(option is not ("--passkey-file" or "--identity-file" or "--max-extra-scopes") || ++i==args.Length || args[i].StartsWith('-') || args[i].Length is <1 or >4096)throw new InvalidOperationException();
            options.Add(option,args[i]);
        }
        if(!options.TryGetValue("--passkey-file",out var key) || !options.TryGetValue("--identity-file",out var identity))throw new InvalidOperationException();
        int maximum=0;
        if(options.TryGetValue("--max-extra-scopes",out var allowance) && (!int.TryParse(allowance,System.Globalization.NumberStyles.None,System.Globalization.CultureInfo.InvariantCulture,out maximum) || maximum is <0 or >512))throw new InvalidOperationException();
        using var cancellation=new CancellationTokenSource();
        ConsoleCancelEventHandler handler=(_,e)=>{e.Cancel=true;cancellation.Cancel();};Console.CancelKeyPress+=handler;
        try
        {
            var result=SoftwarePasskeyRecovery.Recover(key,NativeScopeCommand.ReadJson(identity),cancellation.Token,maximum);
            Console.WriteLine(seen.Contains("--json")?JsonSerializer.Serialize(result):"Passkey usability confirmed; a private local receipt was saved.");return 0;
        }
        catch(SoftwarePasskeyRecoveryException error)
        {Console.Error.WriteLine(JsonSerializer.Serialize(new{Error="PasskeyRecoveryFailed",error.Stage,error.ReceiptSaved,DetailsSuppressed=true}));return 1;}
        finally{Console.CancelKeyPress-=handler;}
    }
}
