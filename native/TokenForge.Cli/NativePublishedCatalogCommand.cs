using System.Text.Json;
using TokenForge.Core;

internal static class NativePublishedCatalogCommand
{
    public static int Run(string[] args)
    {
        bool detail = args[1] == "get";
        string? snapshot = null, revision = null, name = null;
        Guid? id = null, resource = null;
        CatalogTenancyEvidence? tenancy = null;
        bool includeNonVerified = false;
        var scopes = new List<string>();
        var seen = new HashSet<string>(StringComparer.Ordinal);
        for (int i = 2; i < args.Length; i++)
        {
            string option = args[i];
            if (!seen.Add(option) && option != "--scope")
                throw new InvalidOperationException();
            if (option == "--include-non-verified")
            {
                includeNonVerified = true;
                continue;
            }
            if (option == "--json")
                continue;
            if (++i >= args.Length || string.IsNullOrWhiteSpace(args[i]) ||
                args[i].StartsWith("--", StringComparison.Ordinal) || args[i].Length > 4096)
                throw new InvalidOperationException();
            string value = args[i];
            switch (option)
            {
                case "--snapshot": snapshot = value; break;
                case "--revision": revision = value; break;
                case "--id": id = Guid.ParseExact(value, "D"); break;
                case "--name" when !detail: name = value; break;
                case "--resource" when !detail: resource = Guid.ParseExact(value, "D"); break;
                case "--scope" when !detail: scopes.Add(value); break;
                case "--tenancy-evidence" when !detail:
                    tenancy = value switch
                    {
                        "owner-outside-target-tenant" => CatalogTenancyEvidence.OwnerOutsideTargetTenant,
                        "unknown" => CatalogTenancyEvidence.Unknown,
                        _ => throw new InvalidOperationException()
                    };
                    break;
                default: throw new InvalidOperationException();
            }
        }
        if (snapshot == null || revision == null || (detail && !id.HasValue))
            throw new InvalidOperationException();

        using var verified = Read(snapshot, "applications.json");
        using var nonVerified = Read(snapshot, "applications.non-verified.json");
        using var evidence = Read(snapshot, "applications.verified-evidence.json");
        var catalog = new PublishedCatalog(revision, verified.RootElement, nonVerified.RootElement, evidence.RootElement);
        var result = detail
            ? catalog.GetApplication(id!.Value, includeNonVerified)
            : catalog.Search(new PublishedCatalogQuery(id, name, resource, scopes, tenancy, includeNonVerified));
        Console.WriteLine(JsonSerializer.Serialize(result));
        return 0;
    }

    private static JsonDocument Read(string directory, string file)
    {
        using var stream = File.OpenRead(Path.Combine(directory, file));
        if (stream.Length > 128 * 1024 * 1024)
            throw new InvalidDataException("Published catalog file exceeds the size limit.");
        return JsonDocument.Parse(stream);
    }
}
