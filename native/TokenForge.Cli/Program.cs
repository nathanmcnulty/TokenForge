using System.Diagnostics;
using System.Text.Json;
using TokenForge.Core;

try
{
    if(args.Length==1 && args[0]=="--version"){Console.WriteLine(JsonSerializer.Serialize(new{Name="TokenForge",Version="0.17.0",AuthenticationDependency="PowerShell 7.4+"}));return 0;}
    if (args.Length == 0 || args[0] is "help" or "--help")
    {
        Console.WriteLine("TokenForge: profile create/show/forget-key, login, status, doctor, logout, scopes explain, token get, graph permissions; research report/weekly/export-flows/backup; evidence import/update/export/plan/cohort/cohort-export/pending/checkpoint; flows import/export/plan/attempt; catalog import/update/export. See README.md beside this executable for examples. Authentication currently requires PowerShell 7.4+.");
        return 0;
    }
    if (args[0] == "catalog")
    {
        if(args.Length<4 || args[2]!="--database")throw new InvalidOperationException();
        var catalogOperation=args[1];
        if(catalogOperation=="export") {
            string? catalogApp=null;var current=false;var catalogOptions=new HashSet<string>(StringComparer.Ordinal);
            for(var catalogIndex=4;catalogIndex<args.Length;catalogIndex++){
                var option=args[catalogIndex];if(!catalogOptions.Add(option))throw new InvalidOperationException();
                if(option=="--current"){current=true;continue;}
                if(option!="--app" || catalogIndex+1>=args.Length)throw new InvalidOperationException();catalogApp=args[++catalogIndex];
            }
            using var store=new ApplicationCatalogStore(args[3],true);Console.WriteLine(store.Export(catalogApp,current));return 0;
        }
        if(catalogOperation is not ("import" or "update") || args.Length!=6 || args[4]!="--input")throw new InvalidOperationException();
        var inputFile=new FileInfo(Path.GetFullPath(args[5]));if(inputFile.Length>128*1024*1024 || (inputFile.Attributes&FileAttributes.ReparsePoint)!=0)throw new InvalidOperationException();
        var inputJson=File.ReadAllText(inputFile.FullName);using(var store=new ApplicationCatalogStore(args[3])){
            if(catalogOperation=="import")Console.WriteLine(JsonSerializer.Serialize(new{SchemaVersion=1,ImportedRuns=store.Import(inputJson)}));
            else Console.WriteLine(JsonSerializer.Serialize(store.Update(inputJson)));
        }
        return 0;
    }
    if (args[0] == "flows")
    {
        if (args.Length < 4 || args[2] != "--database") throw new InvalidOperationException();
        var operation = args[1];
        if (operation == "export")
        {
            string? tenant = null; string? principal = null; string? plan = null; var latest = false;
            var flowOptionsSeen = new HashSet<string>(StringComparer.Ordinal);
            for (var flowIndex = 4; flowIndex < args.Length; flowIndex++)
            {
                var option = args[flowIndex];
                if (!flowOptionsSeen.Add(option)) throw new InvalidOperationException();
                if (option == "--latest") { latest = true; continue; }
                if (flowIndex + 1 >= args.Length) throw new InvalidOperationException();
                var value = args[++flowIndex];
                switch (option) {
                    case "--tenant": tenant = value; break;
                    case "--principal": principal = value; break;
                    case "--plan": plan = value; break;
                    default: throw new InvalidOperationException();
                }
            }
            using var store = new FlowEvidenceStore(args[3], true);
            Console.WriteLine(store.Export(tenant, principal, latest, plan)); return 0;
        }
        if (operation is not ("import" or "plan" or "attempt") || args.Length != (operation == "plan" ? 8 : 6) || args[4] != "--input" || operation == "plan" && args[6] != "--fingerprint") throw new InvalidOperationException();
        var file = new FileInfo(Path.GetFullPath(args[5]));
        if (file.Length > 128 * 1024 * 1024 || (file.Attributes & FileAttributes.ReparsePoint) != 0) throw new InvalidOperationException();
        var json = File.ReadAllText(file.FullName);
        using (var store = new FlowEvidenceStore(args[3]))
        {
            if (operation == "import") Console.WriteLine(JsonSerializer.Serialize(new { SchemaVersion = 1, Imported = store.Import(json) }));
            else { if (operation == "plan") store.SavePlan(args[7], json); else store.SaveAttempt(json); Console.WriteLine("{\"SchemaVersion\":1,\"Saved\":true}"); }
        }
        return 0;
    }
    if (args[0] == "evidence")
    {
        if (args.Length < 4 || args[2] != "--database") throw new InvalidOperationException();
        var valid=args[1] switch {
            "import" => (args.Length==6 || args.Length==8 && args[6]=="--source") && args[4]=="--input",
            "update" => args.Length==6 && args[4]=="--input",
            "export" => true,
            "plan" => args.Length==8 && args[4]=="--input" && args[6]=="--batch-size",
            "cohort" => args.Length==8 && args[4]=="--input" && args[6]=="--batch-size",
            "cohort-export" => args.Length==6 && args[4]=="--plan",
            "pending" => args.Length==6 && args[4]=="--plan",
            "checkpoint" => args.Length==10 && args[4]=="--plan" && args[6]=="--client" && args[8]=="--outcome",
            _ => false };
        if(!valid) throw new InvalidOperationException();
        using var store = new EvidenceStore(args[3],args[1] is "export" or "pending" or "cohort-export");
        object result;
        switch (args[1])
        {
            case "import":
            case "update":
                if (args[4] != "--input") throw new InvalidOperationException();
                var input = Path.GetFullPath(args[5]);
                if (new FileInfo(input).Length > 64 * 1024 * 1024) throw new InvalidOperationException();
                result = new { SchemaVersion = 1, Imported = store.Import(File.ReadAllText(input), args[1]=="update"?"PrimaryCheckpoint":args.Length==8?args[7]:input) }; break;
            case "export":
                var publicOnly=false;var latest=false;string? tenant=null,principal=null,resource=null,flowPlan=null,scopeClient=null;var evidenceFlags=new HashSet<string>();
                for(var i=4;i<args.Length;i++){
                    if(!evidenceFlags.Add(args[i]))throw new InvalidOperationException();
                    switch(args[i]){
                        case "--public":publicOnly=true;break;
                        case "--latest":latest=true;break;
                        case "--tenant":if(++i>=args.Length)throw new InvalidOperationException();tenant=args[i];break;
                        case "--principal":if(++i>=args.Length)throw new InvalidOperationException();principal=args[i];break;
                        case "--flow-plan":if(++i>=args.Length)throw new InvalidOperationException();flowPlan=args[i];break;
                        case "--client":if(++i>=args.Length)throw new InvalidOperationException();scopeClient=args[i];break;
                        case "--resource":if(++i>=args.Length)throw new InvalidOperationException();resource=args[i];break;
                        default:throw new InvalidOperationException();
                    }
                }
                Console.WriteLine(store.Export(publicOnly,latest,tenant,principal,resource,flowPlan,scopeClient)); return 0;
            case "plan":
                if (args.Length != 8 || args[4] != "--input" || args[6] != "--batch-size" || new FileInfo(args[5]).Length > 8 * 1024 * 1024) throw new InvalidOperationException();
                result = new { SchemaVersion = 1, PlanId = store.Plan(JsonSerializer.Deserialize<string[]>(File.ReadAllText(args[5]))!, int.Parse(args[7])) }; break;
            case "cohort":
                if(new FileInfo(args[5]).Length>8*1024*1024)throw new InvalidOperationException();
                result=new{SchemaVersion=1,PlanId=store.Cohort(File.ReadAllText(args[5]),int.Parse(args[7]))};break;
            case "cohort-export":
                Console.WriteLine(store.ExportCohort(args[5]));return 0;
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
    var commands = new HashSet<string> { "profile", "login", "logout", "status", "doctor", "token", "scopes", "graph", "research" };
    var operations = new HashSet<string> { "create", "forget-key", "show", "get", "explain", "permissions", "report", "export-flows", "backup", "weekly" };
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
    var options = new Dictionary<string, string> { ["--snapshot-path"]="SnapshotPath", ["--backup-directory"]="BackupDirectory", ["--tenant-fingerprint"]="TenantFingerprint", ["--principal-fingerprint"]="PrincipalFingerprint", ["--flow-path"]="FlowPath", ["--metadata-path"]="MetadataPath", ["--export-path"]="ExportPath", ["--login-hint"]="LoginHint", ["--profile"]="Profile", ["--root"]="Root", ["--tenant"]="Tenant", ["--state-path"]="StatePath", ["--storage"]="Storage", ["--resource"]="Resource", ["--scope"]="Scope", ["--passkey-path"]="PasskeyPath", ["--xdr-module-path"]="XdrModulePath", ["--bootstrap-client"]="BootstrapClientId", ["--max-extra-scopes"]="MaxAdditionalScopes", ["--max-bootstrap-extra-scopes"]="MaxBootstrapAdditionalScopes", ["--api-uri"]="ApiUri", ["--graph-command"]="GraphCommand" };
    var flags = new Dictionary<string, string> { ["--summary-only"]="SummaryOnly", ["--json"]="Json", ["--browser"]="Browser", ["--interactive"]="Interactive", ["--prompt-passphrase"]="PromptPassphrase" };
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
