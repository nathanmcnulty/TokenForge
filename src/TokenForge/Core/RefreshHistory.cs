#nullable enable
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json.Nodes;
namespace TokenForge.Core;

public static partial class AdminWorkflows
{
    private sealed record RefreshObservation(JsonObject Collection, JsonObject Record);
    private static string RefreshReferenceKey(string snapshot, string type, string source, string record, string context) => Hash(new JsonObject { ["Snapshot"] = snapshot, ["Type"] = type, ["Source"] = source, ["Record"] = record, ["Context"] = context });
    private static Dictionary<string, RefreshObservation> RefreshEvidenceIndex(JsonObject snapshot)
    {
        var rows = new Dictionary<string, RefreshObservation>(StringComparer.Ordinal); AddRefreshSnapshot(rows, snapshot); return rows;
    }
    private static void AddRefreshSnapshot(Dictionary<string, RefreshObservation> rows, JsonObject snapshot)
    {
        string digest = Hash(snapshot); foreach (var collection in Arr(snapshot["Collections"]).Select(Obj)) foreach (var record in Arr(collection["Records"]).Select(Obj))
        {
            string key = RefreshReferenceKey(digest, Text(collection["EvidenceType"]), Text(Obj(collection["Source"])["Id"]), Text(record["RecordId"]), Hash(Obj(collection["Context"])));
            if (rows.TryGetValue(key, out var existing)) { if (!Equal(existing.Record, record) || !Equal(existing.Collection, collection)) throw Invalid(); } else rows.Add(key, new RefreshObservation(collection, record));
        }
    }
    private static JsonObject EmptyRefreshHistory() => new JsonObject { ["Format"] = "TokenForgeRefreshHistory", ["SchemaVersion"] = 1, ["Snapshots"] = new JsonArray(), ["Entries"] = new JsonArray() };
    public static string CreateRefreshHistory() => EmptyRefreshHistory().ToJsonString();
    private static JsonObject ValidateRefreshHistory(JsonObject history, Dictionary<string, RefreshObservation> evidence)
    {
        Keys(history, "Format SchemaVersion Snapshots Entries"); Version(history, "TokenForgeRefreshHistory"); var snapshots = Arr(history["Snapshots"]); if (snapshots.Count > 10000) throw Invalid(); var hashes = new HashSet<string>(); foreach (var n in snapshots) { var saved = Obj(n); Keys(saved, "Sha256 Snapshot"); Fingerprint(saved["Sha256"]); var snapshot = Parse(ChangeReports.ValidateSnapshot(Obj(saved["Snapshot"]).ToJsonString())); if (Hash(snapshot) != Text(saved["Sha256"]) || !hashes.Add(Text(saved["Sha256"]))) throw Invalid(); AddRefreshSnapshot(evidence, snapshot); }
        var entries = Arr(history["Entries"]); if (entries.Count > 100000) throw Invalid(); var seen = new HashSet<string>(); foreach (var n in entries)
        {
            var entry = Obj(n); Keys(entry, "FamilyId RequestId CompatibilityKey CompatibilityDescriptor ExactIdentity SnapshotSha256 ObservationReferences CoverageReferences"); var descriptor = ValidateRefreshDescriptor(Obj(entry["CompatibilityDescriptor"])); foreach (string key in new[] { "FamilyId", "RequestId", "CompatibilityKey", "SnapshotSha256" }) Fingerprint(entry[key]); if (Text(entry["CompatibilityKey"]) != Hash(descriptor) || Text(entry["FamilyId"]) != RefreshFamily(descriptor) || Text(entry["RequestId"]) != RefreshRequest(descriptor) || !hashes.Contains(Text(entry["SnapshotSha256"]))) throw Invalid();
            var identity = Obj(entry["ExactIdentity"]); Keys(identity, "SourceRevision PackageManifestSha256 SchemaSha256 CollectorSemanticsSha256 CatalogHash CohortHash LegacyInventoryHash InventorySha256 ComparisonContextSha256"); foreach (var field in identity) { if (field.Key == "SourceRevision") Match(Text(field.Value), @"\A[a-f0-9]{40}\z", 40); else Fingerprint(field.Value); }
            if (!Equal(identity["CollectorSemanticsSha256"], descriptor["CollectorSemanticsSha256"]) || Text(identity["ComparisonContextSha256"]) != Hash(RefreshContext(descriptor))) throw Invalid();
            var references = Arr(entry["ObservationReferences"]); if (references.Count > 10000 || !seen.Add(Text(entry["RequestId"]) + "/" + Text(entry["CompatibilityKey"]) + "/" + Text(entry["SnapshotSha256"]))) throw Invalid(); var refKeys = new HashSet<string>(); foreach (var rn in references)
            {
                var reference = Obj(rn); Keys(reference, "EvidenceType SourceId RecordId ContextSha256 ObservedAt"); Choice(reference["EvidenceType"], "IssuedScopes ApiAcceptance"); Match(Text(reference["SourceId"]), @"\A[A-Za-z0-9_.:/-]{1,256}\z", 256); Fingerprint(reference["RecordId"]); Fingerprint(reference["ContextSha256"]); Date(reference["ObservedAt"]);
                string key = RefreshReferenceKey(Text(entry["SnapshotSha256"]), Text(reference["EvidenceType"]), Text(reference["SourceId"]), Text(reference["RecordId"]), Text(reference["ContextSha256"])); if (!refKeys.Add(key) || !evidence.TryGetValue(key, out var observed) || Text(observed.Record["ObservedAt"]) != Text(reference["ObservedAt"]) || Text(observed.Collection["Privacy"]) != "Private") throw Invalid(); var actual = Obj(observed.Collection["Context"]); if (Text(reference["EvidenceType"]) == "IssuedScopes" ? !ExactContext(actual, RefreshContext(descriptor)) : !OperationContext(actual, RefreshContext(descriptor), Obj(descriptor["Profile"]), Obj(descriptor["Tool"]), "GraphMeV1")) throw Invalid();
            }
            var coverage = Arr(entry["CoverageReferences"]); if (coverage.Count > 10000 || references.Count + coverage.Count == 0) throw Invalid();
            var savedSnapshot = Obj(snapshots.Select(Obj).Single(x => Equal(x["Sha256"], entry["SnapshotSha256"]))["Snapshot"]); var coverageSeen = new HashSet<string>();
            foreach (var node in coverage)
            {
                var reference = Obj(node); Keys(reference, "EvidenceType SourceId ContextSha256 CollectedAt Status"); Choice(reference["EvidenceType"], "IssuedScopes ApiAcceptance"); Fingerprint(reference["ContextSha256"]); Date(reference["CollectedAt"]); Match(Text(reference["SourceId"]), @"\A[A-Za-z0-9_.:/-]{1,256}\z", 256); Choice(reference["Status"], "Unknown Denied Incomplete Failed NotCollected"); if (!coverageSeen.Add(Hash(reference))) throw Invalid();
                var collections = Arr(savedSnapshot["Collections"]).Select(Obj).Where(c => Text(c["Privacy"]) == "Private" && Equal(c["EvidenceType"], reference["EvidenceType"]) && Text(Obj(c["Source"])["Id"]) == Text(reference["SourceId"]) && Hash(Obj(c["Context"])) == Text(reference["ContextSha256"]) && Equal(Obj(c["Source"])["CollectedAt"], reference["CollectedAt"]) && Equal(c["Status"], reference["Status"])).ToArray();
                if (collections.Length != 1) throw Invalid(); var actual = Obj(collections[0]["Context"]); if (Text(reference["EvidenceType"]) == "IssuedScopes" ? !ExactContext(actual, RefreshContext(descriptor)) : !OperationContext(actual, RefreshContext(descriptor), Obj(descriptor["Profile"]), Obj(descriptor["Tool"]), "GraphMeV1")) throw Invalid();
            }
        }
        return history;
    }
    private static RefreshObservation? LatestRefreshObservation(IEnumerable<RefreshObservation> input) { var rows = input.OrderBy(o => Date(o.Record["ObservedAt"])).ToArray(); if (rows.Length == 0) return null; var latest = rows.Last(); var tied = rows.Where(o => Date(o.Record["ObservedAt"]) == Date(latest.Record["ObservedAt"])); return tied.Select(o => Hash(new JsonObject { ["RecordOutcome"] = o.Record["Outcome"]!.DeepClone(), ["Value"] = o.Record["Value"]!.DeepClone(), ["Status"] = o.Collection["Status"]!.DeepClone(), ["Context"] = o.Collection["Context"]!.DeepClone() })).Distinct(StringComparer.Ordinal).Count() > 1 ? null : latest; }
    private static RefreshObservation[] RefreshEntryObservations(JsonObject entry, Dictionary<string, RefreshObservation> evidence, DateTimeOffset now) => Arr(entry["ObservationReferences"]).Select(Obj).Select(reference => evidence[RefreshReferenceKey(Text(entry["SnapshotSha256"]), Text(reference["EvidenceType"]), Text(reference["SourceId"]), Text(reference["RecordId"]), Text(reference["ContextSha256"]))]).Where(o => Date(o.Record["ObservedAt"]) <= now).ToArray();
    private static JsonObject? RefreshHistoryState(JsonObject entry, Dictionary<string, RefreshObservation> evidence, DateTimeOffset now, int hours) => EvaluateRefreshState(entry, RefreshEntryObservations(entry, evidence, now), Arr(entry["CoverageReferences"]).Select(Obj).Where(c => Date(c["CollectedAt"]) <= now).ToArray(), now, hours);
    private static JsonObject? CombinedRefreshState(JsonObject[] entries, Dictionary<string, RefreshObservation> evidence, DateTimeOffset now, int hours)
    {
        var observations = entries.SelectMany(e => RefreshEntryObservations(e, evidence, now)).ToArray(); var coverage = entries.SelectMany(e => Arr(e["CoverageReferences"]).Select(Obj)).Where(c => Date(c["CollectedAt"]) <= now).ToArray();
        var issued = LatestRefreshObservation(observations.Where(o => Text(o.Collection["EvidenceType"]) == "IssuedScopes"));
        var primary = issued == null ? entries.OrderBy(e => Text(e["SnapshotSha256"]), StringComparer.Ordinal).First() : entries.OrderBy(e => Text(e["SnapshotSha256"]), StringComparer.Ordinal).First(e => RefreshEntryObservations(e, evidence, now).Any(o => Equal(o.Collection, issued.Collection) && Equal(o.Record, issued.Record)));
        var result = EvaluateRefreshState(primary, observations, coverage, now, hours); if (result == null) return null; result["Origins"] = new JsonArray(entries.OrderBy(e => Text(e["SnapshotSha256"]), StringComparer.Ordinal).Select(e => (JsonNode?)new JsonObject { ["SnapshotSha256"] = e["SnapshotSha256"]!.DeepClone(), ["ExactIdentity"] = e["ExactIdentity"]!.DeepClone(), ["ObservationReferences"] = e["ObservationReferences"]!.DeepClone(), ["CoverageReferences"] = e["CoverageReferences"]!.DeepClone() }).ToArray()); return result;
    }
    private static JsonObject? EvaluateRefreshState(JsonObject entry, RefreshObservation[] observations, JsonObject[] coverage, DateTimeOffset now, int hours)
    {
        if (observations.Length + coverage.Length == 0) return null; var issued = LatestRefreshObservation(observations.Where(o => Text(o.Collection["EvidenceType"]) == "IssuedScopes")); var api = LatestRefreshObservation(observations.Where(o => Text(o.Collection["EvidenceType"]) == "ApiAcceptance"));
        var descriptor = Obj(entry["CompatibilityDescriptor"]); var tool = Obj(descriptor["Tool"]); var profile = Obj(descriptor["Profile"]); string outcome = "Unknown"; bool fresh = false;
        if (issued != null)
        {
            var value = Obj(issued.Record["Value"]); var scopes = Values(value["Scopes"]); string observed = Text(issued.Record["Outcome"]); bool successful = Text(issued.Collection["Status"]) == "Complete" && observed == "Succeeded" && value["ClaimsReadable"]?.ToJsonString() == "true" && value["HasScpClaim"]?.ToJsonString() == "true" && value["NamespaceVerification"]?.ToString() == "Matched" && value["RequestVerification"]?.ToString() == "Matched" && Values(tool["Scopes"]).All(scope => scopes.Contains(scope, StringComparer.Ordinal)) && scopes.Except(Values(tool["Scopes"]), StringComparer.Ordinal).Except(new[] { "openid", "profile", "email", "offline_access" }, StringComparer.Ordinal).Count() <= Int(profile["MaxAdditionalScopes"]);
            outcome = successful ? "Succeeded" : Text(issued.Collection["Status"]) == "Complete" && observed is "RequestBlocked" or "Disabled" or "MissingRegistration" or "OwnerMismatch" or "BrokerRequired" ? "StableFailure" : observed == "TransientFailure" ? "TransientFailure" : "Unknown";
            fresh = Fresh(issued.Record["ObservedAt"], now, hours); if (Arr(tool["Operations"]).Count > 0) { if (api == null || Text(api.Collection["Status"]) != "Complete" || Text(api.Record["Outcome"]) != "Responded" || Obj(api.Record["Value"])["Accepted"]?.ToJsonString() != "true") { if (successful) outcome = "Unknown"; } fresh &= api != null && Fresh(api.Record["ObservedAt"], now, hours); }
        }
        var dates = observations.Select(o => Date(o.Record["ObservedAt"])).Concat(coverage.Select(c => Date(c["CollectedAt"]))).ToArray(); var observedAt = issued == null ? (dates.Length == 0 ? DateTimeOffset.MaxValue : dates.Max()) : Date(issued.Record["ObservedAt"]);
        var issuedDate = observations.Where(o => Text(o.Collection["EvidenceType"]) == "IssuedScopes").Select(o => Date(o.Record["ObservedAt"])).DefaultIfEmpty(DateTimeOffset.MinValue).Max();
        var apiDate = observations.Where(o => Text(o.Collection["EvidenceType"]) == "ApiAcceptance").Select(o => Date(o.Record["ObservedAt"])).DefaultIfEmpty(DateTimeOffset.MinValue).Max();
        var blockingCoverage = coverage.Where(c => Text(c["EvidenceType"]) == "IssuedScopes" ? Date(c["CollectedAt"]) >= issuedDate : Arr(tool["Operations"]).Count > 0 && Date(c["CollectedAt"]) >= apiDate).ToArray();
        if (blockingCoverage.Length > 0) { if (outcome == "Succeeded") outcome = "Unknown"; fresh = false; if (outcome != "StableFailure") observedAt = blockingCoverage.Max(c => Date(c["CollectedAt"])); }
        return new JsonObject { ["Outcome"] = outcome, ["ObservedAt"] = observedAt.ToString("o"), ["IssuedDigest"] = issued == null ? null : Hash(new JsonObject { ["Outcome"] = issued.Record["Outcome"]!.DeepClone(), ["Value"] = issued.Record["Value"]!.DeepClone(), ["Status"] = issued.Collection["Status"]!.DeepClone() }), ["ApiDigest"] = api == null ? null : Hash(new JsonObject { ["Outcome"] = api.Record["Outcome"]!.DeepClone(), ["Value"] = api.Record["Value"]!.DeepClone(), ["Status"] = api.Collection["Status"]!.DeepClone() }), ["Fresh"] = fresh, ["SnapshotSha256"] = entry["SnapshotSha256"]!.DeepClone(), ["ObservationReferences"] = entry["ObservationReferences"]!.DeepClone(), ["CoverageReferences"] = entry["CoverageReferences"]!.DeepClone() };
    }
    // Replay the complete frozen input rather than trusting self-reported counts, policy or reused evidence.
    // Digests establish local consistency, not authenticity or permission to acquire credentials.
    private static JsonObject ValidateRefreshPlan(JsonObject plan)
    {
        Keys(plan, "Format SchemaVersion AsOf FrozenInput Policy InputSha256 Pins Candidates Excluded SelectedCount ReusedCount HasIssuancePlan FreshnessMisses AuthorizationEstablished ExitCode PlanId Metrics");
        Version(plan, "TokenForgeRefreshPlan"); Fingerprint(plan["PlanId"]);
        var rebuilt = Parse(PlanRefresh(Obj(plan["FrozenInput"]).ToJsonString(), Date(plan["AsOf"])));
        var actual = (JsonObject)plan.DeepClone(); actual.Remove("Metrics"); rebuilt.Remove("Metrics");
        if (!Equal(actual, rebuilt)) throw Invalid();
        var metrics = Obj(plan["Metrics"]); Keys(metrics, "ValidationMilliseconds PlanningMilliseconds InputBytes ProcessStarts ExternalRequests DatabaseIoOperations CurrentProcessPeakWorkingSetBytes");
        foreach (var pair in metrics) if (pair.Value == null || !pair.Value.AsValue().TryGetValue<long>(out var value) || value < 0) throw Invalid();
        return plan;
    }
    public static string ValidateRefresh(string planJson) => Guard(() => ValidateRefreshPlan(Parse(planJson)).ToJsonString());
    public static string CaptureRefreshEvidence(string planJson, string snapshotJson, string? historyJson = null) => Guard(() =>
    {
        var plan = ValidateRefreshPlan(Parse(planJson)); var snapshot = Parse(ChangeReports.ValidateSnapshot(snapshotJson)); var evidence = RefreshEvidenceIndex(snapshot); var history = ValidateRefreshHistory(historyJson == null ? EmptyRefreshHistory() : Parse(historyJson), evidence); string digest = Hash(snapshot); bool added = false;
        foreach (var candidate in Arr(plan["Candidates"]).Select(Obj).Where(c => Bool(c["Selected"])))
        {
            var descriptor = Obj(candidate["CompatibilityDescriptor"]); var context = RefreshContext(descriptor); var matches = evidence.Values.Where(o => Text(o.Collection["Privacy"]) == "Private" && Date(o.Record["ObservedAt"]) >= Date(plan["AsOf"]) && (Text(o.Collection["EvidenceType"]) == "IssuedScopes" ? ExactContext(Obj(o.Collection["Context"]), context) : Text(o.Collection["EvidenceType"]) == "ApiAcceptance" && OperationContext(Obj(o.Collection["Context"]), context, Obj(descriptor["Profile"]), Obj(descriptor["Tool"]), "GraphMeV1"))).ToArray();
            // Reference only the supplied snapshot, never silently relabel a retained old observation.
            matches = matches.Where(o => Arr(snapshot["Collections"]).Select(Obj).Contains(o.Collection)).ToArray();
            var coverage = new JsonArray(Arr(snapshot["Collections"]).Select(Obj).Where(c => Text(c["Privacy"]) == "Private" && Text(c["Status"]) != "Complete" && Date(Obj(c["Source"])["CollectedAt"]) >= Date(plan["AsOf"]) && (Text(c["EvidenceType"]) == "IssuedScopes" ? ExactContext(Obj(c["Context"]), context) : Text(c["EvidenceType"]) == "ApiAcceptance" && OperationContext(Obj(c["Context"]), context, Obj(descriptor["Profile"]), Obj(descriptor["Tool"]), "GraphMeV1"))).Select(c => (JsonNode?)new JsonObject { ["EvidenceType"] = c["EvidenceType"]!.DeepClone(), ["SourceId"] = Obj(c["Source"])["Id"]!.DeepClone(), ["ContextSha256"] = Hash(Obj(c["Context"])), ["CollectedAt"] = Obj(c["Source"])["CollectedAt"]!.DeepClone(), ["Status"] = c["Status"]!.DeepClone() }).ToArray());
            if (matches.Length + coverage.Count == 0) continue;
            if (Arr(history["Entries"]).Select(Obj).Any(e => Equal(e["RequestId"], candidate["RequestId"]) && Equal(e["CompatibilityKey"], candidate["CompatibilityKey"]) && Text(e["SnapshotSha256"]) == digest)) continue;
            var refs = new JsonArray(matches.Select(o => (JsonNode?)new JsonObject { ["EvidenceType"] = o.Collection["EvidenceType"]!.DeepClone(), ["SourceId"] = Obj(o.Collection["Source"])["Id"]!.DeepClone(), ["RecordId"] = o.Record["RecordId"]!.DeepClone(), ["ContextSha256"] = Hash(Obj(o.Collection["Context"])), ["ObservedAt"] = o.Record["ObservedAt"]!.DeepClone() }).ToArray()); var entry = new JsonObject { ["FamilyId"] = candidate["FamilyId"]!.DeepClone(), ["RequestId"] = candidate["RequestId"]!.DeepClone(), ["CompatibilityKey"] = candidate["CompatibilityKey"]!.DeepClone(), ["CompatibilityDescriptor"] = descriptor.DeepClone(), ["ExactIdentity"] = candidate["ExactIdentity"]!.DeepClone(), ["SnapshotSha256"] = digest, ["ObservationReferences"] = refs, ["CoverageReferences"] = coverage }; Arr(history["Entries"]).Add(entry); added = true;
        }
        if (added && !Arr(history["Snapshots"]).Select(Obj).Any(s => Text(s["Sha256"]) == digest)) Arr(history["Snapshots"]).Add(new JsonObject { ["Sha256"] = digest, ["Snapshot"] = snapshot.DeepClone() }); ValidateRefreshHistory(history, evidence); return history.ToJsonString();
    });
}
