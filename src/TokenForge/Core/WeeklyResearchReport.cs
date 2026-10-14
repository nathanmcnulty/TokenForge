#nullable enable
using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace TokenForge.Core;

// Offline frozen recipes describe observations for one account, not API authorization.
public static class WeeklyResearchReport
{
    private const string Graph = "00000003-0000-0000-c000-000000000000";
    private const string Legacy = "797f4846-ba00-4fd7-ba43-dac1f8f63013";
    private static readonly UTF8Encoding Utf8 = new(false, true);

    public static string Create(string stateJson, string expectedMode, DateTimeOffset now)
    {
        try { return CreateCore(stateJson, expectedMode, now.ToUniversalTime()); }
        catch { throw new InvalidOperationException("Invalid frozen weekly research data. Details suppressed."); }
    }

    private static string CreateCore(string json, string expectedMode, DateTimeOffset now)
    {
        if (json is null || Utf8.GetByteCount(json) > 128 * 1024 * 1024 || expectedMode is not ("Shallow" or "Deep")) throw Invalid();
        using var document = JsonDocument.Parse(json, new JsonDocumentOptions { MaxDepth = 100 });
        var state = document.RootElement;
        DiscoverySourceClaims.ValidateUniqueKeys(state);
        bool hasHistory = state.TryGetProperty("DeepSelectionHistory", out var history);
        Keys(state, hasHistory ? new[] { "SchemaVersion", "PlanId", "Recipe", "Batches", "DeepSelectionHistory" } : new[] { "SchemaVersion", "PlanId", "Recipe", "Batches" });
        int version = Integer(state.GetProperty("SchemaVersion"), 1, 2);
        var recipe = state.GetProperty("Recipe");
        var recipeKeys = new List<string> { "SchemaVersion", "Week", "CreatedAt", "Mode", "ChunkSize", "MaxRedirects", "AppIds", "Discovery" };
        if (version == 2) recipeKeys.Add("ResourceIds");
        Keys(recipe, recipeKeys);
        if (Integer(recipe.GetProperty("SchemaVersion"), 1, 2) != version) throw Invalid();
        string mode = Text(recipe.GetProperty("Mode"), 16);
        if (mode != expectedMode || version == 2 && mode != "Deep") throw Invalid();
        string week = Text(recipe.GetProperty("Week"), 8);
        Week(week);
        string currentWeek = WeekOf(now);
        var created = Date(recipe.GetProperty("CreatedAt"), now);
        if (string.CompareOrdinal(week, currentWeek) > 0) throw Invalid();
        int chunk = Integer(recipe.GetProperty("ChunkSize"), 1, 200);
        if (Integer(recipe.GetProperty("MaxRedirects"), 2, 4) != (mode == "Deep" ? 4 : 2)) throw Invalid();
        string plan = Text(state.GetProperty("PlanId"), 64);
        if (!Regex.IsMatch(plan, "^[a-f0-9]{64}$") || plan != WeeklyRecipeHash.Compute(recipe.GetRawText())) throw Invalid();
        var resources = version == 2 ? Strings(recipe.GetProperty("ResourceIds"), 2, 36) : new[] { Graph };
        if (resources.Length < 1 || resources.Any(x => x != Graph && x != Legacy) || !resources.SequenceEqual(resources.Distinct(StringComparer.Ordinal).OrderBy(x => x, StringComparer.Ordinal))) throw Invalid();
        var discovery = recipe.GetProperty("Discovery");
        var published = ValidateDiscovery(discovery, now);
        var ids = Strings(recipe.GetProperty("AppIds"), 100000, 128);
        var publishedIds = new HashSet<string>(published.Keys, StringComparer.OrdinalIgnoreCase);
        if (ids.Length == 0 || ids.Any(x => !publishedIds.Contains(x)) || ids.Distinct(StringComparer.OrdinalIgnoreCase).Count() != ids.Length || !ids.SequenceEqual(ids.OrderBy(x => x, StringComparer.OrdinalIgnoreCase)) || mode == "Shallow" && ids.Length != published.Count) throw Invalid();
        int? historyCount = null, never = null;
        if (hasHistory)
        {
            if (mode != "Deep" || history.ValueKind != JsonValueKind.Object) throw Invalid();
            var selections = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            foreach (var selection in history.EnumerateObject())
            {
                string selectedWeek = Text(selection.Value, 8);
                Week(selectedWeek);
                if (!published.ContainsKey(selection.Name) || string.CompareOrdinal(selectedWeek, week) > 0) throw Invalid();
                selections.Add(selection.Name, selectedWeek);
            }
            if (selections.Count > published.Count || ids.Any(id => !selections.TryGetValue(id, out var selectedWeek) || selectedWeek != week)) throw Invalid();
            historyCount = selections.Count;
            never = published.Count(x => x.Value && !selections.ContainsKey(x.Key));
        }
        var batches = state.GetProperty("Batches");
        if (batches.ValueKind != JsonValueKind.Array || batches.GetArrayLength() != (ids.Length + chunk - 1) / chunk) throw Invalid();
        int index = 0, completed = 0, pending = 0, exhausted = 0, assessed = 0, success = 0, assessedPairs = 0, successfulPairs = 0;
        var durations = new List<double>();
        string? oldestText = null, latestText = null;
        DateTimeOffset? oldest = null, latest = null;
        foreach (var batch in batches.EnumerateArray())
        {
            var batchKeys = new List<string> { "Index", "Status", "Attempts", "Assessed", "Successful", "DurationSeconds", "ObservedAt" };
            if (version == 2) batchKeys.AddRange(new[] { "AssessedPairs", "SuccessfulPairs" });
            Keys(batch, batchKeys);
            if (Integer(batch.GetProperty("Index"), 0, 100000) != index) throw Invalid();
            int count = Math.Min(chunk, ids.Length - index * chunk);
            index++;
            string status = Text(batch.GetProperty("Status"), 16);
            if (status is not ("Pending" or "Failed" or "Complete")) throw Invalid();
            int attempts = Integer(batch.GetProperty("Attempts"), 0, int.MaxValue);
            int batchAssessed = Integer(batch.GetProperty("Assessed"), 0, count);
            int batchSuccess = Integer(batch.GetProperty("Successful"), 0, batchAssessed);
            double duration = Number(batch.GetProperty("DurationSeconds"));
            if (duration > 3600 || status == "Complete" && attempts == 0) throw Invalid();
            int pairs = version == 2 ? Integer(batch.GetProperty("AssessedPairs"), 0, count * resources.Length) : batchAssessed;
            int successes = version == 2 ? Integer(batch.GetProperty("SuccessfulPairs"), 0, pairs) : batchSuccess;
            if (pairs != batchAssessed * resources.Length || successes < batchSuccess || successes > batchSuccess * resources.Length) throw Invalid();
            var observed = batch.GetProperty("ObservedAt");
            DateTimeOffset? observation = observed.ValueKind == JsonValueKind.Null ? null : Date(observed, now);
            if (observation < created || status == "Complete" && (observation is null || batchAssessed != count)) throw Invalid();
            if (status == "Complete")
            {
                completed++; assessed += batchAssessed; success += batchSuccess; assessedPairs += pairs; successfulPairs += successes; durations.Add(duration);
                if (oldest is null || observation < oldest) { oldest = observation; oldestText = observed.GetString(); }
                if (latest is null || observation > latest) { latest = observation; latestText = observed.GetString(); }
            }
            else { pending++; if (attempts >= 3) exhausted++; }
        }
        if (pending > 0 && created > now) throw Invalid();
        durations.Sort();
        double? median = durations.Count == 0 ? null : durations[(durations.Count - 1) / 2];
        double? p95 = durations.Count == 0 ? null : durations[(int)Math.Ceiling(durations.Count * .95) - 1];
        bool current = week == currentWeek;
        var report = new Dictionary<string, object?>
        {
            ["SchemaVersion"] = 3, ["ResourceIds"] = resources, ["SelectedPairs"] = ids.Length * resources.Length,
            ["AssessedPairs"] = assessedPairs, ["SuccessfulPairs"] = successfulPairs, ["SourceCatalogApplications"] = published.Count,
            ["SelectedApplications"] = ids.Length, ["PublishedCallbackCandidates"] = published.Count(x => x.Value),
            ["DeepSelectionHistoryApplications"] = historyCount, ["NeverDeepSelectedCallbackCandidates"] = never,
            ["Week"] = week, ["Mode"] = mode, ["GeneratedAt"] = now.ToString("o", CultureInfo.InvariantCulture),
            ["PublishedApplications"] = ids.Length, ["AssessedApplications"] = assessed, ["SuccessfulApplications"] = success,
            ["TotalBatches"] = index, ["CompletedBatches"] = completed, ["PendingBatches"] = pending,
            ["ExhaustedBatches"] = exhausted, ["Complete"] = pending == 0, ["OldestCompletedAssessmentAt"] = oldestText,
            ["LatestCompletedAssessmentAt"] = latestText, ["OldestPendingHours"] = pending == 0 ? 0 : Math.Round((now - created).TotalHours, 2),
            ["MedianBatchSeconds"] = median, ["P95BatchSeconds"] = p95, ["EstimatedRemainingRunnerSeconds"] = median * pending,
            ["Evidence"] = "AssessedForOneAccountNotUniversalSupport", ["SuccessfulScopeFreshness"] = "InspectAnonymousObservationDates",
            ["PlanId"] = plan, ["CurrentWeek"] = current, ["RemainingApplications"] = ids.Length - assessed,
            ["RemainingPairs"] = ids.Length * resources.Length - assessedPairs,
            ["NextAction"] = !current ? "Refresh the checkout and inspect the next weekly cycle." : exhausted > 0 ? "Review exhausted batches; use the workflow retry_exhausted option after resolving failures." : pending == 0 ? "This selected set is complete; inspect observation dates and the next weekly cycle." : "Pending batches require an explicitly approved manual run; inspect failed worker status if progress stalls."
        };
        return JsonSerializer.Serialize(report);
    }

    private static Dictionary<string, bool> ValidateDiscovery(JsonElement discovery, DateTimeOffset now)
    {
        Keys(discovery, new[] { "SchemaVersion", "FetchedAt", "Sources", "CatalogContentSha256", "InvalidSourceRecordCount", "SourceSnapshots", "Applications" });
        int version = Integer(discovery.GetProperty("SchemaVersion"), 1, 2);
        Date(discovery.GetProperty("FetchedAt"), now);
        if (!Regex.IsMatch(Text(discovery.GetProperty("CatalogContentSha256"), 64), "^[a-f0-9]{64}$")) throw Invalid();
        Integer(discovery.GetProperty("InvalidSourceRecordCount"), 0, int.MaxValue);
        Strings(discovery.GetProperty("Sources"), 100000, 2048);
        var snapshots = discovery.GetProperty("SourceSnapshots");
        if (snapshots.ValueKind != JsonValueKind.Array || snapshots.GetArrayLength() > 100000) throw Invalid();
        foreach (var snapshot in snapshots.EnumerateArray())
        {
            Keys(snapshot, new[] { "Location", "Sha256", "HashKind" });
            // Snapshot labels may be local-source sentinels (LocalMicrosoftApps /
            // LocalResources). They are descriptive strings, never fetch targets.
            Text(snapshot.GetProperty("Location"), 2048);
            if (!Regex.IsMatch(Text(snapshot.GetProperty("Sha256"), 64), "^[a-f0-9]{64}$")) throw Invalid();
            Text(snapshot.GetProperty("HashKind"), 2048);
        }
        var apps = discovery.GetProperty("Applications");
        if (apps.ValueKind != JsonValueKind.Array || apps.GetArrayLength() > 100000) throw Invalid();
        var published = new Dictionary<string, bool>(StringComparer.Ordinal);
        var unique = new HashSet<Guid>();
        foreach (var app in apps.EnumerateArray())
        {
            var fields = new List<string> { "AppId", "Name", "OwnerTenantId", "Ownership", "Sources", "PublicClient", "Foci", "RedirectUris", "PreferredRedirectUri", "Grants", "IsResourceCandidate", "IdentifierUris" };
            if (version == 2) fields.AddRange(new[] { "SourceClaims", "MetadataConflicts" });
            Keys(app, fields);
            string id = Text(app.GetProperty("AppId"), 128);
            if (!Guid.TryParse(id, out var guid) || guid == Guid.Empty || !unique.Add(guid)) throw Invalid();
            Text(app.GetProperty("Name"), 2048);
            string ownership = Text(app.GetProperty("Ownership"), 64);
            if (ownership is not ("Unverified" or "PublishedMicrosoftOwner")) throw Invalid();
            var owner = app.GetProperty("OwnerTenantId");
            if (owner.ValueKind != JsonValueKind.Null && !Guid.TryParse(Text(owner, 128), out _)) throw Invalid();
            foreach (string name in new[] { "PublicClient", "Foci" }) if (app.GetProperty(name).ValueKind is not (JsonValueKind.Null or JsonValueKind.True or JsonValueKind.False)) throw Invalid();
            if (app.GetProperty("IsResourceCandidate").ValueKind is not (JsonValueKind.True or JsonValueKind.False)) throw Invalid();
            var redirects = Strings(app.GetProperty("RedirectUris"), 100000, 2048);
            Strings(app.GetProperty("IdentifierUris"), 100000, 2048);
            Text(app.GetProperty("PreferredRedirectUri"), 128 * 1024 * 1024);
            var sources = app.GetProperty("Sources");
            if (sources.ValueKind != JsonValueKind.Array) throw Invalid();
            foreach (var source in sources.EnumerateArray())
            {
                Keys(source, new[] { "Name", "Location", "Evidence" });
                Text(source.GetProperty("Name"), 2048); Text(source.GetProperty("Evidence"), 2048);
                DiscoverySourceClaims.ValidatePublicLocation(Text(source.GetProperty("Location"), 2048));
            }
            var grants = app.GetProperty("Grants");
            if (grants.ValueKind != JsonValueKind.Array) throw Invalid();
            foreach (var grant in grants.EnumerateArray())
            {
                Keys(grant, new[] { "ResourceId", "Scopes" });
                if (!Guid.TryParse(Text(grant.GetProperty("ResourceId"), 128), out _)) throw Invalid();
                if (Strings(grant.GetProperty("Scopes"), 100000, 256).Any(x => !Regex.IsMatch(x, "^[A-Za-z0-9_.-]{1,256}$"))) throw Invalid();
            }
            if (version == 2)
            {
                DiscoverySourceClaims.Validate(app.GetProperty("SourceClaims").GetRawText(), app.GetProperty("MetadataConflicts").GetRawText(), id);
                foreach (var claim in app.GetProperty("SourceClaims").EnumerateArray()) DiscoverySourceClaims.ValidatePublicLocation(Text(claim.GetProperty("Location"), 4096));
            }
            published.Add(id, redirects.Length > 0);
        }
        return published;
    }

    private static void Keys(JsonElement value, IEnumerable<string> fields)
    {
        if (value.ValueKind != JsonValueKind.Object) throw Invalid();
        var required = new HashSet<string>(fields, StringComparer.Ordinal);
        foreach (var property in value.EnumerateObject()) if (!required.Remove(property.Name)) throw Invalid();
        if (required.Count != 0) throw Invalid();
    }
    private static string Text(JsonElement value, int maximum)
    { if (value.ValueKind != JsonValueKind.String || value.GetString()!.Length > maximum) throw Invalid(); return value.GetString()!; }
    private static string[] Strings(JsonElement value, int maximumCount, int maximumLength)
    { if (value.ValueKind != JsonValueKind.Array || value.GetArrayLength() > maximumCount) throw Invalid(); return value.EnumerateArray().Select(x => Text(x, maximumLength)).ToArray(); }
    private static int Integer(JsonElement value, int minimum, int maximum)
    { if (!value.TryGetInt32(out int number) || number < minimum || number > maximum) throw Invalid(); return number; }
    private static double Number(JsonElement value)
    { if (!value.TryGetDouble(out double number) || !double.IsFinite(number) || number < 0) throw Invalid(); return number; }
    private static DateTimeOffset Date(JsonElement value, DateTimeOffset now)
    {
        string text = Text(value, 128);
        // Frozen producer dates always carry an explicit offset. Never interpret a
        // date-only or zoneless string using the machine's current time zone.
        if (!Regex.IsMatch(text, @"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,7})?(?:Z|[+-][0-9]{2}:[0-9]{2})$") ||
            !DateTimeOffset.TryParse(text, CultureInfo.InvariantCulture, DateTimeStyles.None, out var date) || date > now.AddMinutes(5)) throw Invalid();
        return date;
    }
    private static void Week(string text)
    {
        if (!Regex.IsMatch(text, "^[0-9]{4}-W[0-9]{2}$")) throw Invalid();
        int year = int.Parse(text.Substring(0, 4), CultureInfo.InvariantCulture), week = int.Parse(text.Substring(6), CultureInfo.InvariantCulture);
        if (year < 1 || week < 1 || week > ISOWeek.GetWeeksInYear(year)) throw Invalid();
    }
    private static string WeekOf(DateTimeOffset now) => string.Format(CultureInfo.InvariantCulture, "{0:D4}-W{1:D2}", ISOWeek.GetYear(now.UtcDateTime), ISOWeek.GetWeekOfYear(now.UtcDateTime));
    private static InvalidOperationException Invalid() => new("Invalid frozen weekly research data. Details suppressed.");
}
