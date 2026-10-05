using System.Diagnostics;
using System.Text.Json;
using TokenForge.Core;

try
{
    if(args.Length==1 && args[0]=="--version"){Console.WriteLine(JsonSerializer.Serialize(new{Name="TokenForge",Version="0.11.0",AuthenticationDependency="PowerShell 7.4+"}));return 0;}
    if (args.Length == 0 || args[0] is "help" or "--help")
    {
        Console.WriteLine("TokenForge: profile create/show/forget-key, login, status, doctor, logout, scopes explain, token get, graph permissions; evidence import/export/plan/pending/checkpoint. See README.md beside this executable for examples. Authentication currently requires PowerShell 7.4+.");
        return 0;
    }
    if (args[0] == "evidence")
    {
        if (args.Length < 4 || args[2] != "--database") throw new InvalidOperationException();
        var valid=args[1] switch {
            "import" => args.Length==6 && args[4]=="--input",
            "export" => args.Length==4 || (args.Length==5 && args[4]=="--public"),
            "plan" => args.Length==8 && args[4]=="--input" && args[6]=="--batch-size",
            "pending" => args.Length==6 && args[4]=="--plan",
            "checkpoint" => args.Length==10 && args[4]=="--plan" && args[6]=="--client" && args[8]=="--outcome",
            _ => false };
        if(!valid) throw new InvalidOperationException();
        using var store = new EvidenceStore(args[3],args[1] is "export" or "pending");
        object result;
        switch (args[1])
        {
            case "import":
                if (args.Length != 6 || args[4] != "--input") throw new InvalidOperationException();
                var input = Path.GetFullPath(args[5]);
                if (new FileInfo(input).Length > 64 * 1024 * 1024) throw new InvalidOperationException();
                result = new { SchemaVersion = 1, Imported = store.Import(File.ReadAllText(input), input) }; break;
            case "export":
                if (args.Length != 4 && !(args.Length == 5 && args[4] == "--public")) throw new InvalidOperationException();
                Console.WriteLine(store.Export(args.Length == 5)); return 0;
            case "plan":
                if (args.Length != 8 || args[4] != "--input" || args[6] != "--batch-size" || new FileInfo(args[5]).Length > 8 * 1024 * 1024) throw new InvalidOperationException();
                result = new { SchemaVersion = 1, PlanId = store.Plan(JsonSerializer.Deserialize<string[]>(File.ReadAllText(args[5]))!, int.Parse(args[7])) }; break;
            case "pending":
                if (args.Length != 6 || args[4] != "--plan") throw new InvalidOperationException();
                Console.WriteLine(store.Pending(args[5])); return 0;
            case "checkpoint":
                if (args.Length != 10 || args[4] != "--plan" || args[6] != "--client" || args[8] != "--outcome") throw new InvalidOperationException();
                store.Complete(args[5], args[7], args[9]); result = new { SchemaVersion = 1, Saved = true }; break;
            default: throw new InvalidOperationException();
        }
        Console.WriteLine(JsonSerializer.Serialize(result)); return 0;
    }
    var commands = new HashSet<string> { "profile", "login", "logout", "status", "doctor", "token", "scopes", "graph" };
    var operations = new HashSet<string> { "create", "forget-key", "show", "get", "explain", "permissions" };
    if (!commands.Contains(args[0])) throw new InvalidOperationException();
    var script = Path.Combine(AppContext.BaseDirectory, "scripts", "tokenforge.ps1");
    if (!File.Exists(script)) throw new InvalidOperationException();
    var start = new ProcessStartInfo("pwsh") { UseShellExecute = false };
    foreach (var value in new[] { "-NoLogo", "-NoProfile", "-File", script, "-Command", args[0] }) start.ArgumentList.Add(value);
    var index = 1;
    if (index < args.Length && !args[index].StartsWith("--", StringComparison.Ordinal))
    {
        if (!operations.Contains(args[index])) throw new InvalidOperationException();
        start.ArgumentList.Add("-Operation"); start.ArgumentList.Add(args[index++]);
    }
    var options = new Dictionary<string, string> { ["--login-hint"]="LoginHint", ["--profile"]="Profile", ["--root"]="Root", ["--tenant"]="Tenant", ["--state-path"]="StatePath", ["--storage"]="Storage", ["--resource"]="Resource", ["--scope"]="Scope", ["--passkey-path"]="PasskeyPath", ["--xdr-module-path"]="XdrModulePath", ["--bootstrap-client"]="BootstrapClientId", ["--max-extra-scopes"]="MaxAdditionalScopes", ["--max-bootstrap-extra-scopes"]="MaxBootstrapAdditionalScopes", ["--api-uri"]="ApiUri", ["--graph-command"]="GraphCommand" };
    var flags = new Dictionary<string, string> { ["--json"]="Json", ["--browser"]="Browser", ["--interactive"]="Interactive", ["--prompt-passphrase"]="PromptPassphrase" };
    var seen = new HashSet<string>();
    while (index < args.Length)
    {
        var option = args[index++]; if (!seen.Add(option)) throw new InvalidOperationException();
        if (flags.TryGetValue(option, out var flag)) { start.ArgumentList.Add("-"+flag); continue; }
        if (!options.TryGetValue(option, out var parameter) || index == args.Length) throw new InvalidOperationException();
        var value = args[index++]; if (value.StartsWith('-') || value.Length > 4096) throw new InvalidOperationException();
        start.ArgumentList.Add("-"+parameter); start.ArgumentList.Add(value);
    }
    if (args[0] == "profile" && args.Length > 1 && args[1] == "create" && !seen.Contains("--storage")) { start.ArgumentList.Add("-Storage"); start.ArgumentList.Add("Passphrase"); }
    using var process = Process.Start(start) ?? throw new InvalidOperationException();
    await process.WaitForExitAsync(); return process.ExitCode;
}
catch
{
    Console.Error.WriteLine("{\"SchemaVersion\":1,\"Succeeded\":false,\"Code\":\"OperationFailed\",\"Message\":\"Operation failed; details suppressed. Check the command, private paths, and installed runtime.\"}");
    return 1;
}
