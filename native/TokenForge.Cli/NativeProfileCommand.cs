using System.Globalization;
using TokenForge.Core;

internal static class NativeProfileCommand
{
    internal static int Run(string[] args)
    {
        string operation = args[1];
        var values = new Dictionary<string, string>(StringComparer.Ordinal);
        var allowed = new HashSet<string>(StringComparer.Ordinal) { "--profile", "--root" };
        if (operation == "create") allowed.UnionWith(new[] { "--tenant", "--state-path", "--storage", "--bootstrap-client", "--max-extra-scopes", "--max-bootstrap-extra-scopes", "--max-age-hours", "--session-retention-hours", "--passkey-path", "--xdr-module-path" });
        var seen = new HashSet<string>(StringComparer.Ordinal);
        for (int i = 2; i < args.Length; i++)
        {
            string option = args[i]; if (!seen.Add(option)) throw new InvalidOperationException();
            if (option == "--json") continue;
            if (!allowed.Contains(option) || ++i == args.Length || args[i].StartsWith('-') || args[i].Length > 4096) throw new InvalidOperationException();
            values[option] = args[i];
        }
        string Required(string option) => values.TryGetValue(option, out string? value) && value.Length != 0 ? value : throw new InvalidOperationException();
        string? Optional(string option) => values.GetValueOrDefault(option);
        int Number(string option, int fallback) => values.TryGetValue(option, out string? value) ? int.Parse(value, NumberStyles.None, CultureInfo.InvariantCulture) : fallback;
        string name = values.ContainsKey("--profile") ? Required("--profile") : "default";
        string json = operation == "show" ? ProfileStore.Read(name, Optional("--root")) : ProfileStore.Create(name, Required("--tenant"), Optional("--root"), Optional("--state-path"),
            Optional("--storage") ?? "Passphrase", Optional("--bootstrap-client") ?? "038ddad9-5bbe-4f64-b0cd-12434d1e633b", Number("--max-extra-scopes",0), Number("--max-bootstrap-extra-scopes",0),
            Number("--max-age-hours",24), Number("--session-retention-hours",8), Optional("--passkey-path") ?? "", Optional("--xdr-module-path") ?? "");
        Console.WriteLine(json); return 0;
    }
}
