using System.Globalization;
using System.Text.Json;
using TokenForge.Core;

internal static class NativeResearchCommand
{
    internal static int Run(string[] args)
    {
        var seen=new HashSet<string>(StringComparer.Ordinal);var options=new Dictionary<string,string>(StringComparer.Ordinal);
        for(int i=2;i<args.Length;i++) {
            string option=args[i];if(!seen.Add(option))throw new InvalidOperationException();
            if(option is "--json" or "--summary-only")continue;
            if(option is not ("--metadata-path" or "--flow-path" or "--state-path" or "--profile" or "--root" or "--tenant-fingerprint" or "--principal-fingerprint" or "--app" or "--max-age-hours") ||
                ++i==args.Length || args[i].StartsWith('-') || args[i].Length is <1 or >4096)throw new InvalidOperationException();
            options[option]=args[i];
        }
        string? state=options.GetValueOrDefault("--state-path"),tenant=options.GetValueOrDefault("--tenant-fingerprint"),principal=options.GetValueOrDefault("--principal-fingerprint");
        if((tenant==null)!=(principal==null))throw new InvalidOperationException();
        if(state==null && !options.ContainsKey("--metadata-path")) {
            using var profile=JsonDocument.Parse(ProfileStore.Read(options.GetValueOrDefault("--profile") ?? "default",options.GetValueOrDefault("--root")));
            state=profile.RootElement.GetProperty("StatePath").GetString();
            if(tenant==null) {
                tenant=profile.RootElement.GetProperty("ExpectedTenantFingerprint").GetString();
                principal=profile.RootElement.GetProperty("ExpectedPrincipalFingerprint").GetString();
            }
        }
        string Choose(string name)=>Path.Combine(state!,File.Exists(Path.Combine(state!,name+".sqlite")) ? name+".sqlite" : name+".json");
        string metadata=options.GetValueOrDefault("--metadata-path") ?? Choose("applications");
        string catalogJson;
        if(metadata.EndsWith(".sqlite",StringComparison.OrdinalIgnoreCase)) {
            using var store=new ApplicationCatalogStore(metadata,true);catalogJson=store.Export();
        } else catalogJson=NativeScopeCommand.ReadJson(metadata,128*1024*1024);
        string? flow=options.GetValueOrDefault("--flow-path") ?? (state==null ? null : Choose("flows"));
        string? flowJson=null;
        // An explicit flow input is validated even when its account is unselected.
        // Missing optional state flows are an empty coverage set, never a new file.
        if(flow!=null && (options.ContainsKey("--flow-path") || File.Exists(flow))) {
            if(flow.EndsWith(".sqlite",StringComparison.OrdinalIgnoreCase)) {
                using var store=new FlowEvidenceStore(flow,true);flowJson=store.Export();
            } else flowJson=NativeScopeCommand.ReadJson(flow,128*1024*1024);
        }
        int age=options.TryGetValue("--max-age-hours",out var text) ? int.Parse(text,NumberStyles.None,CultureInfo.InvariantCulture) : 24;
        string[]? apps=options.TryGetValue("--app",out var app) ? new[]{app} : null;
        string report=ResearchCoverage.CreateFromValidatedDocuments(catalogJson,flowJson,tenant,principal,apps,age,seen.Contains("--summary-only"));
        if(seen.Contains("--json"))Console.WriteLine(report);
        else {
            using var json=JsonDocument.Parse(report);var r=json.RootElement;
            Console.WriteLine($"Applications: {r.GetProperty("ApplicationCount")}; metadata conflicts: {r.GetProperty("ApplicationsWithMetadataConflicts")}");
            Console.WriteLine($"Selected plans: {r.GetProperty("ApplicationsWithSelectedPlans")}; applications with observed success: {r.GetProperty("ApplicationsWithObservedSuccess")}");
            Console.WriteLine($"Flow slots — planned: {r.GetProperty("PlannedSlots")}; terminal: {r.GetProperty("TerminalSlots")}; untested: {r.GetProperty("UntestedSlots")}; interrupted: {r.GetProperty("InterruptedSlots")}");
            Console.WriteLine(tenant==null ? "Select both --tenant-fingerprint and --principal-fingerprint for account-specific coverage." : "Coverage describes the selected account's latest plans.");
            Console.WriteLine("Diagnostic evidence; required authentication flows and API authorization are not inferred. Use --json for application details.");
        }
        return 0;
    }
}
