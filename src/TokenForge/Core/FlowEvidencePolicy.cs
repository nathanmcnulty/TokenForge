#nullable enable
using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
namespace TokenForge.Core;

// Shared validation of complete flow history, independent of SQLite or credentials.
public static class FlowEvidencePolicy
{
    private const int MaxDocumentBytes=128*1024*1024;
    public static void ValidateDocument(string json)
    {
        using var doc = Parse(json); var root = doc.RootElement;
        DiscoverySourceClaims.ValidateUniqueKeys(root);
        Keys(root, "Format SchemaVersion UpdatedAt Plans Attempts");
        if (Text(root, "Format") != "TokenForgeFlowEvidence" || root.GetProperty("SchemaVersion").GetInt32() != 1) throw Invalid();
        Date(root, "UpdatedAt");
        var plans = root.GetProperty("Plans"); var attempts = root.GetProperty("Attempts");
        if (plans.ValueKind != JsonValueKind.Object || attempts.ValueKind != JsonValueKind.Array) throw Invalid();
        var hashes = new HashSet<string>(StringComparer.Ordinal);
        foreach (var plan in plans.EnumerateObject()) {
            if (!hashes.Add(plan.Name)) throw Invalid(); ValidatePlan(plan.Name, plan.Value);
        }
        var ids = new HashSet<string>(StringComparer.Ordinal);
        foreach (var row in attempts.EnumerateArray()) {
            var hash = Text(row, "PlanFingerprint");
            if (!ids.Add(Text(row, "AttemptId")) || !hashes.Contains(hash)) throw Invalid();
            ValidateAttempt(row, hash, plans.GetProperty(hash));
        }
    }

    public static void ValidatePlan(string hash, JsonElement plan)
    {
        HashValue(hash);
        var cohort=plan.TryGetProperty("CohortFingerprint",out var cohortValue);
        Keys(plan, "TenantFingerprint PrincipalFingerprint ClientId ResourceId Tenant CatalogHash Eligibility ResourceAliases Cells PlannedAt"+(cohort?" CohortFingerprint":""));
        if(cohort) HashValue(cohortValue.GetString()!);
        foreach (var field in new[] { "TenantFingerprint", "PrincipalFingerprint" }) HashValue(Text(plan, field));
        foreach (var field in new[] { "ClientId", "ResourceId" }) GuidValue(Text(plan, field));
        Date(plan, "PlannedAt");
        if (plan.GetProperty("CatalogHash").ValueKind != JsonValueKind.Null) HashValue(Text(plan, "CatalogHash"));
        if (!Regex.IsMatch(Text(plan, "Tenant"), "^(organizations|common|consumers|[a-zA-Z0-9][a-zA-Z0-9.-]{0,252})$")) throw Invalid();
        Choice(plan, "Eligibility", "Eligible MissingRegistration OwnerMismatch Disabled NoRedirect BrokerRedirectHint InvalidRedirectHints");
        var aliases = Strings(plan, "ResourceAliases", "^[A-Za-z0-9_.:/-]{1,256}$");
        var cells = plan.GetProperty("Cells"); if (cells.ValueKind != JsonValueKind.Array || cells.GetArrayLength() > 4000) throw Invalid();
        var slots = new HashSet<string>();
        foreach (var cell in cells.EnumerateArray())
        {
            Keys(cell, "Protocol Spa RedirectFingerprint");
            Choice(cell, "Protocol", "OAuth2V2Pkce OAuth2V2Implicit OAuth2V1Implicit");
            HashValue(Text(cell, "RedirectFingerprint"));
            if (cell.GetProperty("Spa").GetBoolean() && Text(cell, "Protocol") != "OAuth2V2Pkce") throw Invalid();
            if (!slots.Add(Cell(cell))) throw Invalid();
        }
        // Match legacy PowerShell Sort-Object -Unique for the ASCII alias vocabulary.
        var parts = new List<string> { "FlowPolicy1" };
        foreach (var field in new[] { "TenantFingerprint", "PrincipalFingerprint", "ClientId", "ResourceId", "Tenant", "CatalogHash", "Eligibility" })
            parts.Add(plan.GetProperty(field).ValueKind == JsonValueKind.Null ? "" : Text(plan, field));
        if(cohort) parts.Add("Cohort|"+cohortValue.GetString());
        parts.AddRange(aliases.Distinct(StringComparer.CurrentCultureIgnoreCase).OrderBy(x => x, StringComparer.CurrentCultureIgnoreCase)); parts.AddRange(cells.EnumerateArray().Select(Cell));
        if (Hash(string.Join("\n", parts)) != hash) throw Invalid();
    }
    public static void ValidateAttempt(JsonElement row, string hash, JsonElement plan)
    {
        Keys(row, "AttemptId PlanFingerprint AttemptKey ClientId ResourceId TenantFingerprint PrincipalFingerprint StartedAt ObservedAt Protocol Spa RedirectFingerprint Outcome ResponseScopes ScpScopes ClaimsReadable HasScpClaim NamespaceVerification RequestVerification SignatureValidated ErrorCodes ElapsedSeconds");
        GuidValue(Text(row, "AttemptId"));
        foreach (var field in new[] { "AttemptKey", "PlanFingerprint", "TenantFingerprint", "PrincipalFingerprint", "RedirectFingerprint" }) HashValue(Text(row, field));
        if (Text(row, "PlanFingerprint") != hash) throw Invalid();
        foreach (var field in new[] { "TenantFingerprint", "PrincipalFingerprint", "ClientId", "ResourceId" }) if (Text(row, field) != Text(plan, field)) throw Invalid();
        if (!plan.GetProperty("Cells").EnumerateArray().Any(x => Cell(x) == Cell(row)) || Text(row, "AttemptKey") != Hash(hash + "|" + Cell(row))) throw Invalid();
        var start = Date(row, "StartedAt"); var observed = Date(row, "ObservedAt"); if (StringComparer.Ordinal.Compare(start, observed) > 0) throw Invalid();
        Choice(row, "Outcome", "Started Failed Succeeded OpaqueToken NoDelegatedScp ContextMismatch");
        foreach (var field in new[] { "NamespaceVerification", "RequestVerification" }) Choice(row, field, "Matched Mismatch Unverifiable");
        foreach (var field in new[] { "Spa", "ClaimsReadable", "HasScpClaim" }) row.GetProperty(field).GetBoolean();
        if (row.GetProperty("SignatureValidated").GetBoolean()) throw Invalid();
        var duration = row.GetProperty("ElapsedSeconds").GetDouble(); if (!double.IsFinite(duration) || duration < 0 || duration > 86400) throw Invalid();
        Strings(row, "ResponseScopes", "^[A-Za-z0-9_.:/-]{1,256}$");
        var scopes = Strings(row, "ScpScopes", "^[A-Za-z0-9_.:/-]{1,256}$");
        if (Strings(row, "ErrorCodes", "^[0-9]{4,9}$").Length > 16) throw Invalid();
        if (Text(row, "Outcome") == "Succeeded" && (!row.GetProperty("ClaimsReadable").GetBoolean() || !row.GetProperty("HasScpClaim").GetBoolean() || scopes.Length == 0 || Text(row, "NamespaceVerification") != "Matched" || Text(row, "RequestVerification") != "Matched")) throw Invalid();
    }
    public static string Canonical(JsonElement value)
    {
        object? Normalize(JsonElement element, string? field = null)
        {
            if (element.ValueKind == JsonValueKind.Object)
                return element.EnumerateObject().OrderBy(x => x.Name, StringComparer.Ordinal).ToDictionary(x => x.Name, x => Normalize(x.Value, x.Name));
            if (element.ValueKind == JsonValueKind.Array) return element.EnumerateArray().Select(x => Normalize(x)).ToArray();
            if (element.ValueKind == JsonValueKind.String && field is "PlannedAt" or "StartedAt" or "ObservedAt")
                return DateTimeOffset.Parse(element.GetString()!, CultureInfo.InvariantCulture).ToUniversalTime().ToString("o");
            return element.ValueKind switch {
                JsonValueKind.String => element.GetString(), JsonValueKind.Number => element.GetDouble(),
                JsonValueKind.True => true, JsonValueKind.False => false, JsonValueKind.Null => null, _ => throw Invalid() };
        }
        return JsonSerializer.Serialize(Normalize(value));
    }
    public static string Cell(JsonElement cell) => Text(cell, "Protocol") + "|" + (cell.GetProperty("Spa").GetBoolean() ? "1" : "0") + "|" + Text(cell, "RedirectFingerprint");
    public static string Text(JsonElement value, string field) => value.GetProperty(field).GetString() ?? throw Invalid();
    public static void Keys(JsonElement value, string fields)
    {
        if (value.ValueKind != JsonValueKind.Object) throw Invalid();
        var expected = fields.Split(' ').ToHashSet(StringComparer.Ordinal); var seen = new HashSet<string>(StringComparer.Ordinal);
        foreach (var field in value.EnumerateObject()) if (!expected.Contains(field.Name) || !seen.Add(field.Name)) throw Invalid();
        if (seen.Count != expected.Count) throw Invalid();
    }
    public static string[] Strings(JsonElement value, string field, string pattern)
    {
        var array = value.GetProperty(field); if (array.ValueKind != JsonValueKind.Array || array.GetArrayLength() > 4096) throw Invalid();
        return array.EnumerateArray().Select(x => { var text = x.GetString() ?? throw Invalid(); if (!Regex.IsMatch(text, pattern.TrimEnd('$') + "\\z")) throw Invalid(); return text; }).ToArray();
    }
    public static void HashValue(string value) { if (!Regex.IsMatch(value, "^[a-f0-9]{64}\\z")) throw Invalid(); }
    public static void GuidValue(string value) { if (!Guid.TryParse(value, out var id) || id == Guid.Empty || id.ToString() != value) throw Invalid(); }
    public static string Date(JsonElement value, string field)
    {
        var text = Text(value, field);
        if (text.Length > 64 || text.Contains('\r') || text.Contains('\n') || !Regex.IsMatch(text, @"^\d{4}-\d{2}-\d{2}T[^\r\n]+(Z|[+-]\d{2}:\d{2})$") || !DateTimeOffset.TryParse(text, CultureInfo.InvariantCulture, DateTimeStyles.None, out var date) || date > DateTimeOffset.UtcNow.AddMinutes(5)) throw Invalid();
        return date.ToUniversalTime().ToString("o");
    }
    public static void Choice(JsonElement value, string field, string choices) { if (!choices.Split(' ').Contains(Text(value, field), StringComparer.Ordinal)) throw Invalid(); }
    public static JsonDocument Parse(string json) { if (Encoding.UTF8.GetByteCount(json) > MaxDocumentBytes) throw Invalid(); return JsonDocument.Parse(json, new JsonDocumentOptions { MaxDepth = 12 }); }
    public static string Hash(string text) => Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(text))).ToLowerInvariant();
    public static InvalidOperationException Invalid() => new("Invalid flow evidence; details suppressed.");
}
