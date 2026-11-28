using System.Text.Json;

namespace TokenForge.Core;

public enum CatalogTenancyEvidence { OwnerOutsideTargetTenant, Unknown }

public sealed record PublishedCatalogQuery(Guid? AppId = null, string? Name = null,
    Guid? ResourceId = null, IReadOnlyList<string>? Scopes = null,
    CatalogTenancyEvidence? TenancyEvidence = null, bool IncludeNonVerified = false);

public sealed record PublishedCatalogResult(int SchemaVersion, string CatalogRevision,
    int Count, IReadOnlyList<PublishedCatalogMatch> Applications);

public sealed record PublishedCatalogMatch(Guid AppId, string Partition,
    JsonElement? VerificationEvidence, string? Disposition, string? Reason,
    IReadOnlyList<PublishedCatalogMetadata> MatchingEvidence, IReadOnlyList<string> UnknownFields);

public sealed record PublishedCatalogMetadata(string Record, string? ObservedAtUtc,
    JsonElement? MetadataConflicts, IReadOnlyList<PublishedCatalogClaim> Claims);

public sealed record PublishedCatalogClaim(string? Source, IReadOnlyDictionary<string, JsonElement> Claim,
    IReadOnlyList<JsonElement> MatchingGrants);

public sealed class PublishedCatalog
{
    private readonly string revision;
    private readonly SortedDictionary<string, Entry> entries = new(StringComparer.Ordinal);

    private sealed record Entry(Guid Id, bool Verified, JsonElement Records,
        JsonElement? Evidence, string? Disposition, string? Reason);

    // Revision is the identity of the caller-supplied snapshot.
    public PublishedCatalog(string revision, JsonElement verified, JsonElement nonVerified,
        JsonElement verifiedEvidence)
    {
        if (revision.Length != 40 || !revision.All(Uri.IsHexDigit))
            throw new ArgumentException("Expected a full catalog revision.", nameof(revision));
        this.revision = revision.ToLowerInvariant();

        var evidence = Applications(verifiedEvidence, "TokenForgeVerifiedApplicationEvidence", 1)
            .EnumerateObject().ToDictionary(row => Guid.ParseExact(row.Name, "D"), row => row.Value);
        foreach (var row in Applications(verified, "TokenForgeApplicationMetadata", 2).EnumerateObject())
        {
            var id = Guid.ParseExact(row.Name, "D");
            if (!evidence.Remove(id, out var observation) || observation.ValueKind != JsonValueKind.Object ||
                string.IsNullOrWhiteSpace(Text(observation, "EvidenceSource")) ||
                string.IsNullOrWhiteSpace(Text(observation, "ObservedAtUtc")))
                throw new InvalidDataException("Verified application has no observation.");
            Add(id, true, row.Value, observation, null, null);
        }
        if (evidence.Count != 0)
            throw new InvalidDataException("Verified evidence does not match the verified partition.");

        foreach (var row in Applications(nonVerified, "TokenForgeNonVerifiedApplications", 1).EnumerateObject())
        {
            var id = Guid.ParseExact(row.Name, "D");
            Add(id, false, row.Value.GetProperty("CatalogRecord"), Field(row.Value, "Evidence"),
                Text(row.Value, "Disposition"), Text(row.Value, "Reason"));
        }
    }

    private void Add(Guid id, bool verified, JsonElement application, JsonElement? evidence,
        string? disposition, string? reason)
    {
        if (Guid.ParseExact(application.GetProperty("AppId").GetString()!, "D") != id)
            throw new InvalidDataException("Catalog AppId mismatch.");
        entries.Add(id.ToString("D"), new Entry(id, verified, application.GetProperty("Records").Clone(),
            evidence?.Clone(), disposition, reason));
    }

    public PublishedCatalogResult GetApplication(Guid id, bool includeNonVerified = false) =>
        Search(new PublishedCatalogQuery(AppId: id, IncludeNonVerified: includeNonVerified));

    public PublishedCatalogResult Search(PublishedCatalogQuery query)
    {
        var scopes = query.Scopes ?? Array.Empty<string>();
        bool grantFilter = query.ResourceId.HasValue || scopes.Count > 0;
        bool metadataFilter = query.Name != null || grantFilter;
        var matches = new List<PublishedCatalogMatch>();
        IEnumerable<Entry> candidates = entries.Values;
        if (query.AppId is Guid id)
            candidates = entries.TryGetValue(id.ToString("D"), out var entry) ? new[] { entry } : Array.Empty<Entry>();

        foreach (var candidate in candidates)
        {
            if (!candidate.Verified && !query.IncludeNonVerified)
                continue;
            bool outside = candidate.Evidence is JsonElement observation &&
                Field(observation, "OwnerOutsideTargetTenant")?.ValueKind == JsonValueKind.True;
            var tenancy = outside ? CatalogTenancyEvidence.OwnerOutsideTargetTenant : CatalogTenancyEvidence.Unknown;
            if (query.TenancyEvidence.HasValue && query.TenancyEvidence.Value != tenancy)
                continue;

            var metadata = new List<PublishedCatalogMetadata>();
            foreach (var record in candidate.Records.EnumerateObject().OrderBy(row => row.Name, StringComparer.Ordinal))
            {
                var attributes = record.Value.GetProperty("Attributes");
                var claims = new List<PublishedCatalogClaim>();
                foreach (var claim in ArrayField(attributes, "SourceClaims"))
                {
                    if (query.Name != null && Text(claim, "Name")?.Contains(query.Name, StringComparison.OrdinalIgnoreCase) != true)
                        continue;

                    var grants = ArrayField(claim, "Grants")
                        .Where(grant => MatchesGrant(grant, query.ResourceId, scopes)).ToArray();
                    if (grantFilter && grants.Length == 0)
                        continue;
                    var fields = claim.EnumerateObject().Where(field => field.Name != "Grants")
                        .ToDictionary(field => field.Name, field => field.Value, StringComparer.Ordinal);
                    claims.Add(new PublishedCatalogClaim(Text(claim, "SourceName"), fields, grants));
                }
                if (claims.Count > 0 || !metadataFilter)
                    metadata.Add(new PublishedCatalogMetadata(record.Name, Text(record.Value, "LastSeenAt"),
                        Field(attributes, "MetadataConflicts"), claims));
            }

            if (metadataFilter && metadata.Count == 0)
                continue;

            // The published schema has no configured sign-in audience field.
            var unknown = new List<string> { "SignInAudience" };
            if (!outside)
                unknown.Add("OwnerOutsideTargetTenant");
            matches.Add(new PublishedCatalogMatch(candidate.Id, candidate.Verified ? "Verified" : "NonVerified",
                candidate.Evidence, candidate.Disposition, candidate.Reason, metadata, unknown));
        }
        return new PublishedCatalogResult(1, revision, matches.Count, matches);
    }

    private static bool MatchesGrant(JsonElement grant, Guid? resource, IReadOnlyList<string> scopes)
    {
        if (!Guid.TryParseExact(Text(grant, "ResourceId"), "D", out var grantResource) ||
            (resource.HasValue && resource.Value != grantResource))
            return false;
        var observed = ArrayField(grant, "Scopes").Select(scope => scope.GetString());
        return scopes.All(scope => observed.Contains(scope, StringComparer.Ordinal));
    }

    private static JsonElement Applications(JsonElement root, string format, int version)
    {
        if (Text(root, "Format") != format || root.GetProperty("SchemaVersion").GetInt32() != version)
            throw new InvalidDataException("Unsupported published catalog format.");
        return root.GetProperty("Applications");
    }

    private static JsonElement? Field(JsonElement row, string name) =>
        row.TryGetProperty(name, out var value) && value.ValueKind != JsonValueKind.Null ? value : null;

    private static string? Text(JsonElement row, string name) => Field(row, name)?.GetString();

    private static IEnumerable<JsonElement> ArrayField(JsonElement row, string name) =>
        Field(row, name) is JsonElement value ? value.EnumerateArray() : Array.Empty<JsonElement>();
}
