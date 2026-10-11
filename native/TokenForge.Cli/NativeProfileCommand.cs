using System.Globalization;
using System.Security;
using System.Text.Json;
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
            if (option == "--json" || (operation is "inspect-vault" or "logout") && option == "--stdin" || operation == "logout" && option == "--prompt-passphrase") continue;
            if (!allowed.Contains(option) || ++i == args.Length || args[i].StartsWith('-') || args[i].Length > 4096) throw new InvalidOperationException();
            values[option] = args[i];
        }
        string Required(string option) => values.TryGetValue(option, out string? value) && value.Length != 0 ? value : throw new InvalidOperationException();
        string? Optional(string option) => values.GetValueOrDefault(option);
        int Number(string option, int fallback) => values.TryGetValue(option, out string? value) ? int.Parse(value, NumberStyles.None, CultureInfo.InvariantCulture) : fallback;
        string name = values.ContainsKey("--profile") ? Required("--profile") : "default";
        if (operation == "logout")
        {
            using var configuration = JsonDocument.Parse(ProfileStore.Read(name,Optional("--root")));
            string storage = configuration.RootElement.GetProperty("Storage").GetString()!;
            bool stdin = seen.Contains("--stdin"), prompt = seen.Contains("--prompt-passphrase");
            if ((stdin || prompt) && storage != "Passphrase" || stdin && prompt) throw new InvalidOperationException();
            Func<SecureString>? unlock = storage == "Passphrase" ? () =>
            {
                if (!stdin && Console.IsInputRedirected) throw new InvalidOperationException();
                return NativeTokenCommand.ReadCredential(stdin,12,1024,"Vault passphrase (hidden): ");
            } : null;
            Console.WriteLine(JsonSerializer.Serialize(ProfileStore.Logout(name,Optional("--root"),passwordProvider:unlock)));
            return 0;
        }
        if (operation == "inspect-vault")
        {
            using var configuration = JsonDocument.Parse(ProfileStore.Read(name,Optional("--root")));
            string storage = configuration.RootElement.GetProperty("Storage").GetString()!;
            bool stdin = seen.Contains("--stdin");
            if (storage == "Memory" || stdin && storage != "Passphrase") throw new InvalidOperationException();
            if (storage == "Passphrase")
            {
                if (!stdin && Console.IsInputRedirected) throw new InvalidOperationException();
                using var password = NativeTokenCommand.ReadCredential(stdin,12,1024,"Vault passphrase (hidden): ");
                Console.WriteLine(JsonSerializer.Serialize(ProfileStore.InspectVault(name,Optional("--root"),password)));
            }
            else Console.WriteLine(JsonSerializer.Serialize(ProfileStore.InspectVault(name,Optional("--root"))));
            return 0;
        }
        if (operation == "forget-key")
        {
            var removed = ProfileStore.ForgetKey(name, Optional("--root"));
            Console.WriteLine(JsonSerializer.Serialize(removed)); return removed.KeyRemoved ? 0 : 1;
        }
        string json = operation == "show" ? ProfileStore.Read(name, Optional("--root")) : ProfileStore.Create(name, Required("--tenant"), Optional("--root"), Optional("--state-path"),
            Optional("--storage") ?? "Passphrase", Optional("--bootstrap-client") ?? "038ddad9-5bbe-4f64-b0cd-12434d1e633b", Number("--max-extra-scopes",0), Number("--max-bootstrap-extra-scopes",0),
            Number("--max-age-hours",24), Number("--session-retention-hours",8), Optional("--passkey-path") ?? "", Optional("--xdr-module-path") ?? "");
        Console.WriteLine(json); return 0;
    }
}
