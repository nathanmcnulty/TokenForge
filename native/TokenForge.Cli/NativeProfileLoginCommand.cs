using System.Security;
using System.Text.Json;
using TokenForge.Core;

internal static class NativeProfileLoginCommand
{
 internal static int Run(string[] args)
 {
  var seen=new HashSet<string>(StringComparer.Ordinal);var options=new Dictionary<string,string>(StringComparer.Ordinal);
  var flags=new HashSet<string>(new[]{"--browser","--interactive","--json","--stdin","--prompt-passphrase"},StringComparer.Ordinal);
  for(int i=1;i<args.Length;i++)
  {
   string option=args[i];if(!seen.Add(option))throw new InvalidOperationException();
   if(flags.Contains(option))continue;
   if(option is not ("--profile" or "--root" or "--login-hint" or "--timeout-seconds" or "--passkey-file") || ++i==args.Length || args[i].StartsWith('-') || args[i].Length is <1 or >4096)throw new InvalidOperationException();
   options[option]=args[i];
  }
  bool passkey=options.ContainsKey("--passkey-file");
  if(seen.Contains("--browser")==passkey || passkey && (seen.Contains("--interactive") || options.ContainsKey("--login-hint") || options.ContainsKey("--timeout-seconds")) || seen.Contains("--stdin") && seen.Contains("--prompt-passphrase"))throw new InvalidOperationException();
  if(options.TryGetValue("--login-hint",out var hint) && (hint.Length>320 || hint.Any(char.IsControl)))throw new InvalidOperationException();
  int timeout=300;if(options.TryGetValue("--timeout-seconds",out var value) && (!int.TryParse(value,out timeout) || timeout is <30 or >900))throw new InvalidOperationException();
  string name=options.GetValueOrDefault("--profile") ?? "default";string? root=options.GetValueOrDefault("--root");
  using var profile=JsonDocument.Parse(ProfileStore.Read(name,root));var configuration=profile.RootElement;
  string storage=configuration.GetProperty("Storage").GetString()!;
  bool stdin=seen.Contains("--stdin"),prompt=seen.Contains("--prompt-passphrase");
  if(storage=="Passphrase" && !stdin && !prompt || storage!="Passphrase" && (stdin || prompt))throw new InvalidOperationException();
  string inventory=NativeScopeCommand.ReadJson(Path.Combine(configuration.GetProperty("StatePath").GetString()!,"inventory.json"));
  using SecureString? password=storage=="Passphrase"?NativeTokenCommand.ReadCredential(stdin,12,1024,"Vault passphrase (hidden): "):null;
  using var cancellation=new CancellationTokenSource();ConsoleCancelEventHandler cancel=(_,e)=>{e.Cancel=true;cancellation.Cancel();};Console.CancelKeyPress+=cancel;
  try
  {
   var result=passkey?ProfileLogin.LoginSoftwarePasskey(name,root,inventory,options["--passkey-file"],password,cancellation.Token):ProfileLogin.Login(name,root,inventory,request=>
   {
    using var acquired=NativeTokenCommand.AcquireBrowser(request,options.GetValueOrDefault("--login-hint"),timeout,!seen.Contains("--interactive"),cancellation.Token);
    return new ProfileCredentialToken(request,acquired.AccessToken,acquired.RefreshToken,acquired.ExpiresAt,acquired.AdditionalScopes.Length);
   },password,cancellation:cancellation.Token);
   Console.WriteLine(JsonSerializer.Serialize(new{SchemaVersion=1,Result=result}));return 0;
  }
  finally{Console.CancelKeyPress-=cancel;}
 }
}
