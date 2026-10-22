#nullable enable
using System;
using System.IO;
using System.Linq;
using System.Security;
using System.Threading;
using TokenForge.Core.V0180;
using System.Text;
using System.Text.Json.Nodes;
using System.Collections.Generic;
using TokenForge.Core.V0220;
namespace TokenForge.Core;

public static partial class AdminWorkflows
{
    public static RefreshRun OpenRefreshRun(string planJson, string path) => new RefreshRun(ValidateRefreshPlan(Parse(planJson)), path);

    private static string RefreshAccountFingerprint(JsonObject plan) { var profile = Obj(Obj(plan["FrozenInput"])["Profile"]); return Hash(new JsonObject { ["Tenant"] = profile["ExpectedTenantFingerprint"]!.DeepClone(), ["Principal"] = profile["ExpectedPrincipalFingerprint"]!.DeepClone() }); }
    private static FileStream LockRefreshAccount(string directory) => PrivateFiles.Open(PrivateFiles.Resolve(Path.Combine(directory, ".refresh-account.lock"), true), !File.Exists(Path.Combine(directory, ".refresh-account.lock")));
    private static bool CheckRefreshAccount(JsonObject plan, string directory)
    {
        string marker = PrivateFiles.Resolve(Path.Combine(directory, "refresh-store.json"), false), canonical = PrivateFiles.Resolve(Path.Combine(directory, "refresh-run.json"), false);
        if (File.Exists(marker)) { var value = Parse(File.ReadAllText(marker, new UTF8Encoding(false, true)), 4096); Keys(value, "Format SchemaVersion AccountFingerprint"); Version(value, "TokenForgeRefreshStore"); if (Text(value["AccountFingerprint"]) != RefreshAccountFingerprint(plan) || !File.Exists(canonical)) throw Invalid(); return true; }
        if (Directory.GetFiles(directory, "refresh-run-*.json").Length > 0) throw Invalid(); return false;
    }
    private static void WriteRefreshPrivate(string path, JsonObject value, bool immutable = false)
    {
        path = PrivateFiles.Resolve(path, false); if (immutable && File.Exists(path)) { if (!Equal(Parse(File.ReadAllText(path, new UTF8Encoding(false, true))), value)) throw Invalid(); return; }
        string temporary = path + "." + Guid.NewGuid().ToString("N") + ".tmp"; try { using (var output = PrivateFiles.Open(temporary, true)) { output.Write(Encoding.UTF8.GetBytes(value.ToJsonString())); output.Flush(true); } if (immutable) PrivateFiles.PublishNew(temporary, path); else File.Move(temporary, path, true); } finally { if (File.Exists(temporary)) File.Delete(temporary); }
    }
    public static string AdvanceRefreshRun(string planJson, string accountStateDirectory) => Guard(() =>
    {
        var next = ValidateRefreshPlan(Parse(planJson)); using var accountGate = LockRefreshAccount(accountStateDirectory); if (!CheckRefreshAccount(next, accountStateDirectory)) throw Invalid();
        string path = PrivateFiles.Resolve(Path.Combine(accountStateDirectory, "refresh-run.json"), false); var saved = Parse(File.ReadAllText(path, new UTF8Encoding(false, true))); var oldPlan = ValidateRefreshPlan(Obj(saved["Plan"]));
        using var old = new RefreshRun(oldPlan, path); saved = Parse(File.ReadAllText(path, new UTF8Encoding(false, true))); if(Equal(oldPlan["PlanId"],next["PlanId"]) || Date(next["AsOf"])<Arr(saved["Terminals"]).Select(Obj).Select(t=>Date(t["SavedAt"])).DefaultIfEmpty(Date(oldPlan["AsOf"])).Max())throw Invalid(); var status = Parse(old.Status()); if (!old.CanAdvance() || Int(status["InFlightUnknownCount"]) != 0 || RefreshAccountFingerprint(oldPlan) != RefreshAccountFingerprint(next)) throw Invalid();
        var retained = Parse(old.ProjectHistory(Obj(Obj(oldPlan["FrozenInput"])["History"]).ToJsonString())); var incoming = Obj(Obj(next["FrozenInput"])["History"]);
        foreach (string section in new[] { "Snapshots", "Entries" }) foreach (var item in Arr(retained[section])) if (!Arr(incoming[section]).Any(n => Equal(n, item))) throw Invalid();
        // Archive first, replace the canonical primary atomically. Interruption leaves the old primary valid.
        WriteRefreshPrivate(Path.Combine(accountStateDirectory, "refresh-run-" + Text(oldPlan["PlanId"]) + ".json"), saved, true);
        WriteRefreshPrivate(path, new JsonObject { ["Format"] = "TokenForgeRefreshRun", ["SchemaVersion"] = 1, ["Plan"] = next.DeepClone(), ["StartedAt"] = DateTimeOffset.UtcNow.ToString("o"), ["Events"] = new JsonArray(), ["Terminals"] = new JsonArray(), ["ExactlyOnceGuaranteed"] = false });
        return next["PlanId"]!.ToJsonString();
    });

    // No sign-in or fallback. Every actual acquisition still passes Goal 3 token and namespace checks.
    public static string AcquireRefresh(string planJson, string accountStateDirectory, string requestId, SecureString? cookie, string cookieName = "ESTSAUTH", CancellationToken cancellation = default, Func<System.Net.Http.HttpClient, Uri, Dictionary<string, string>?, string?, OAuthHttpResponse>? transport = null, Func<SecureString, string>? identityAdapter = null, Func<SecureString, ProfileApiCheck>? proofAdapter = null)
    {
        var plan = ValidateRefreshPlan(Parse(planJson)); var candidate = Arr(plan["Candidates"]).Select(Obj).SingleOrDefault(c => Text(c["RequestId"]) == requestId && Bool(c["Selected"])) ?? throw Invalid();
        if (Date(plan["AsOf"]) > DateTimeOffset.UtcNow) throw Invalid(); var input = Obj(plan["FrozenInput"]); var descriptor = Obj(candidate["CompatibilityDescriptor"]); var profile = Obj(descriptor["Profile"]); var tool = Obj(descriptor["Tool"]);
        // Metadata-only preflight never reads or renews a credential and never creates a journal.
        if (cookie == null || cookie.Length == 0) { using var empty = Acquire(profile.ToJsonString(), Obj(input["Requirements"]).ToJsonString(), Obj(input["Inventory"]).ToJsonString(), Text(tool["Id"]), null, selectedClient: Text(Obj(descriptor["Client"])["AppId"]), selectedCallback: ApplicationCatalogPolicy.Hash(Text(descriptor["CallbackUri"]))); return empty.ToJson(); }
        using var accountGate = LockRefreshAccount(accountStateDirectory); bool initialized = CheckRefreshAccount(plan, accountStateDirectory);
        using var run = OpenRefreshRun(planJson, Path.Combine(accountStateDirectory, "refresh-run.json")); if (!initialized) WriteRefreshPrivate(Path.Combine(accountStateDirectory, "refresh-store.json"), new JsonObject { ["Format"] = "TokenForgeRefreshStore", ["SchemaVersion"] = 1, ["AccountFingerprint"] = RefreshAccountFingerprint(plan) }, true);
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellation); deadline.CancelAfter(run.Remaining); int phase = 0;
        ProfileCredentialToken Execute(ScopePlanning.RequestRow request)
        {
            bool bootstrap = ++phase == 1; int issuance = run.Reserve(requestId, bootstrap ? "BootstrapIssuance" : "FinalIssuance");
            try
            {
                using var token = OAuthTransport.AcquireForAdapter(request.ToTransport(), "Cookie", cookie, null, null, cookieName, (client, uri, form, origin) =>
                {
                    int sequence = run.Reserve(requestId, bootstrap ? "BootstrapHttp" : "OtherHttp");
                    try { var response = (transport == null ? OAuthTransport.Send(client, uri, form, origin, deadline.Token) : transport(client, uri, form, origin)); run.Complete(sequence, response.Status); return response; } catch { run.Complete(sequence, outcomeKnown: false); throw; }
                }, deadline.Token);
                run.Complete(issuance); return new ProfileCredentialToken(request.ToTransport(), token.AccessToken, token.RefreshToken, token.ExpiresAt, token.AdditionalScopes.Length);
            }
            catch { run.CompleteFailedIssuance(issuance); throw; }
        }
        string Identity(SecureString token) { int sequence = run.Reserve(requestId, "IdentityGet"); try { string identity = identityAdapter == null ? ProfileTokenApi.ReadIdentity(token, deadline.Token) : identityAdapter(token); run.Complete(sequence, 200); return identity; } catch { run.Complete(sequence, outcomeKnown: false); throw; } }
        ProfileApiCheck Proof(SecureString token) { int sequence = run.Reserve(requestId, "ApiGet"); try { var proof = proofAdapter == null ? ProfileTokenApi.Check(token, Graph, new Uri("https://graph.microsoft.com/v1.0/me?$select=id"), deadline.Token) : proofAdapter(token); run.Complete(sequence, proof.Status); return proof; } catch { run.Complete(sequence, outcomeKnown: false); throw; } }
        using var acquisition = Acquire(profile.ToJsonString(), Obj(input["Requirements"]).ToJsonString(), Obj(input["Inventory"]).ToJsonString(), Text(tool["Id"]), cookie, cookieName, Text(Obj(descriptor["Client"])["AppId"]), ApplicationCatalogPolicy.Hash(Text(descriptor["CallbackUri"])), Arr(tool["Operations"]).Count > 0, execute: Execute, readIdentity: Identity, checkOperation: Proof, cancellation: deadline.Token);
        var status = Parse(run.Status()); if (Int(status["InFlightUnknownCount"]) == 0) run.SaveEvidence(requestId, AcquisitionEvidence(acquisition.ToJson()));
        return new JsonObject { ["Format"] = "TokenForgeRefreshAttempt", ["SchemaVersion"] = 1, ["Acquisition"] = Parse(acquisition.ToJson()), ["Run"] = Parse(run.Status()) }.ToJsonString();
    }

    // Serial primary journal. All externally visible work reserves an intent before dispatch.
    // The caller retains credentials in memory. The journal accepts only typed saved evidence.
    public sealed class RefreshRun : IDisposable
    {
        private readonly string path;
        private readonly FileStream gate;
        private readonly JsonObject plan;
        private readonly JsonObject state;
        private readonly HashSet<string> interrupted = new(StringComparer.Ordinal);
        private bool disposed;
        private static readonly string[] kinds = { "BootstrapIssuance", "FinalIssuance", "BootstrapHttp", "IdentityGet", "ApiGet", "InventoryGet", "InventoryPageGet", "SourceGet", "OtherHttp" };
        private static bool Issuance(string kind) => kind is "BootstrapIssuance" or "FinalIssuance";
        private static bool Recoverable(string kind) => kind is "InventoryGet" or "InventoryPageGet" or "SourceGet" or "ApiGet" or "IdentityGet";
        private JsonArray Events => Arr(state["Events"]);
        private JsonArray Terminals => Arr(state["Terminals"]);
        private bool Unresolved(JsonObject e) => (Text(e["Outcome"]) is "Intent" or "TransportUnknown") && !Events.Select(Obj).Any(r => Bool(r["Recovery"]) && r["RetryOf"] != null && Int(r["RetryOf"]) == Int(e["Sequence"]) && Text(r["Outcome"]) == "Responded");
        internal RefreshRun(JsonObject frozenPlan, string target)
        {
            plan = frozenPlan; path = PrivateFiles.Resolve(target, true);
            string lockPath = PrivateFiles.Resolve(path + ".lock", false);
            gate = PrivateFiles.Open(lockPath, !File.Exists(lockPath));
            try
            {
                if (File.Exists(path))
                {
                    var file = new FileInfo(path); if (file.Length is < 1 or > 134217728) throw Invalid();
                    state = Parse(File.ReadAllText(path, new UTF8Encoding(false, true)));
                    Validate();
                    foreach (var id in Events.Select(Obj).Select(e => Text(e["RequestId"])).Distinct(StringComparer.Ordinal).Where(id => !Terminals.Select(Obj).Any(t => Text(t["RequestId"]) == id))) interrupted.Add(id);
                }
                else
                {
                    state = new JsonObject { ["Format"] = "TokenForgeRefreshRun", ["SchemaVersion"] = 1, ["Plan"] = plan.DeepClone(), ["StartedAt"] = DateTimeOffset.UtcNow.ToString("o"), ["Events"] = new JsonArray(), ["Terminals"] = new JsonArray(), ["ExactlyOnceGuaranteed"] = false };
                    Save();
                }
            }
            catch { gate.Dispose(); throw; }
        }
        private void Validate()
        {
            Keys(state, "Format SchemaVersion Plan StartedAt Events Terminals ExactlyOnceGuaranteed"); Version(state, "TokenForgeRefreshRun");
            if (Bool(state["ExactlyOnceGuaranteed"]) || !Equal(state["Plan"], plan) || Date(state["StartedAt"]) > DateTimeOffset.UtcNow.AddMinutes(5)) throw Invalid();
            if (Events.Count > 1000000 || Terminals.Count > 4096) throw Invalid();
            var seen = new HashSet<int>(); int retries = 0, recoveries = 0;
            foreach (var node in Events)
            {
                var e = Obj(node); Keys(e, "Sequence RequestId Kind StartedAt Outcome HttpStatus RetryOf Recovery");
                int sequence = Int(e["Sequence"]); if (sequence != seen.Count + 1 || !seen.Add(sequence)) throw Invalid();
                Candidate(Text(e["RequestId"])); string kind = Text(e["Kind"]); if (!kinds.Contains(kind, StringComparer.Ordinal)) throw Invalid();
                if (Date(e["StartedAt"]) < Date(state["StartedAt"]) || Date(e["StartedAt"]) > DateTimeOffset.UtcNow.AddMinutes(5)) throw Invalid();
                Choice(e["Outcome"], "Intent Responded TransportUnknown"); bool recovery = Bool(e["Recovery"]);
                if (e["HttpStatus"] != null) { Range(e["HttpStatus"], 100, 599); if (Text(e["Outcome"]) != "Responded") throw Invalid(); }
                else if (Text(e["Outcome"]) == "Responded" && !Issuance(kind)) throw Invalid();
                if (e["RetryOf"] != null)
                {
                    int prior = Int(e["RetryOf"]); if (prior < 1 || prior >= sequence || !Recoverable(kind)) throw Invalid(); var old = Obj(Events[prior - 1]); if (!Equal(old["Kind"], e["Kind"]) || !Equal(old["RequestId"], e["RequestId"])) throw Invalid();
                    if (recovery) { if (Text(old["Outcome"]) == "Responded" || ++recoveries > 1) throw Invalid(); }
                    else { if (Text(old["Outcome"]) != "Responded" || old["HttpStatus"] == null || Int(old["HttpStatus"]) is not (429 or 502 or 503 or 504)) throw Invalid(); retries++; }
                }
                else if (recovery) throw Invalid();
            }
            if (retries > Int(Obj(plan["Policy"])["MaxTransientRetries"])) throw Invalid();
            var ids = new HashSet<string>(); foreach (var node in Terminals) { var terminal = Obj(node); Keys(terminal, "RequestId Snapshot SavedAt"); Candidate(Text(terminal["RequestId"])); if (!ids.Add(Text(terminal["RequestId"])) || Date(terminal["SavedAt"]) < Date(state["StartedAt"]) || Date(terminal["SavedAt"]) > DateTimeOffset.UtcNow.AddMinutes(5)) throw Invalid(); ValidateTerminal(Text(terminal["RequestId"]), Obj(terminal["Snapshot"])); if (Events.Select(Obj).Any(e => Text(e["RequestId"]) == Text(terminal["RequestId"]) && (Unresolved(e) || Date(e["StartedAt"]) > Date(terminal["SavedAt"])))) throw Invalid(); }
            CheckCounts();
        }
        private JsonObject Candidate(string id) => Arr(plan["Candidates"]).Select(Obj).SingleOrDefault(c => Text(c["RequestId"]) == id && Bool(c["Selected"])) ?? throw Invalid();
        private void CheckCounts()
        {
            var p = Obj(plan["Policy"]); var events = Events.Select(Obj).ToArray();
            void Limit(string key, int count) { if (count > Int(p[key])) throw Invalid(); }
            Limit("MaxIssuanceAttempts", events.Count(e => Issuance(Text(e["Kind"]))));
            Limit("MaxTotalRequests", events.Count(e => !Issuance(Text(e["Kind"]))));
            Limit("MaxBootstrapRequests", events.Count(e => Text(e["Kind"]) == "BootstrapHttp"));
            Limit("MaxInventoryRequests", events.Count(e => Text(e["Kind"]) is "InventoryGet" or "InventoryPageGet"));
            Limit("MaxInventoryPages", events.Count(e => Text(e["Kind"]) == "InventoryPageGet"));
            Limit("MaxSourceRequests", events.Count(e => Text(e["Kind"]) == "SourceGet"));
        }
        public void CheckDeadline() { if (disposed) throw new ObjectDisposedException(nameof(RefreshRun)); if (DateTimeOffset.UtcNow - Date(state["StartedAt"]) >= TimeSpan.FromSeconds(Int(Obj(plan["Policy"])["MaxSeconds"]))) throw new InvalidOperationException("Refresh deadline reached; saved evidence retained."); }
        public TimeSpan Remaining { get { CheckDeadline(); return TimeSpan.FromSeconds(Int(Obj(plan["Policy"])["MaxSeconds"])) - (DateTimeOffset.UtcNow - Date(state["StartedAt"])); } }
        public int Reserve(string requestId, string kind, int retryOf = 0, bool recoverUnknown = false)
        {
            CheckDeadline(); Candidate(requestId);
            if (Issuance(kind) && Events.Select(Obj).Any(e => Text(e["RequestId"]) == requestId && Text(e["Kind"]) == kind)) throw Invalid();
            if (!kinds.Contains(kind, StringComparer.Ordinal) || Terminals.Select(Obj).Any(t => Text(t["RequestId"]) == requestId)) throw Invalid();
            // Restart never silently replays an incomplete acquisition. A single GET may be explicitly recovered.
            if (interrupted.Contains(requestId) && !recoverUnknown) throw new InvalidOperationException("Interrupted refresh requires explicit review; remote consumption is unknown.");
            if (Events.Select(Obj).Any(e => Unresolved(e) && !Issuance(Text(e["Kind"])) && (retryOf != Int(e["Sequence"]) || !recoverUnknown))) throw Invalid();
            if (retryOf > 0 && Events.Select(Obj).Any(e => e["RetryOf"] != null && Int(e["RetryOf"]) == retryOf)) throw Invalid();
            int sequence = Events.Count + 1; Events.Add(new JsonObject { ["Sequence"] = sequence, ["RequestId"] = requestId, ["Kind"] = kind, ["StartedAt"] = DateTimeOffset.UtcNow.ToString("o"), ["Outcome"] = "Intent", ["HttpStatus"] = null, ["RetryOf"] = retryOf == 0 ? null : retryOf, ["Recovery"] = recoverUnknown });
            try { Validate(); Save(); } catch { Events.RemoveAt(Events.Count - 1); throw; }
            return sequence;
        }
        internal void CompleteFailedIssuance(int sequence) { var later = Events.Select(Obj).Where(e => Int(e["Sequence"]) > sequence).ToArray(); Complete(sequence, outcomeKnown: later.All(e => Text(e["Outcome"]) == "Responded")); }
        public void Complete(int sequence, int? httpStatus = null, bool outcomeKnown = true)
        {
            if (disposed || sequence < 1 || sequence > Events.Count) throw Invalid(); var e = Obj(Events[sequence - 1]); if (Text(e["Outcome"]) != "Intent") throw Invalid();
            var before = e.DeepClone(); e["Outcome"] = outcomeKnown ? "Responded" : "TransportUnknown"; e["HttpStatus"] = httpStatus;
            try { Validate(); Save(); if (Bool(e["Recovery"]) && outcomeKnown && !Events.Select(Obj).Any(old => Text(old["RequestId"]) == Text(e["RequestId"]) && Unresolved(old))) interrupted.Remove(Text(e["RequestId"])); } catch { Events[sequence - 1] = before; throw; }
        }
        private void ValidateTerminal(string id, JsonObject snapshot)
        {
            ChangeReports.ValidateSnapshot(snapshot.ToJsonString()); var row = Candidate(id); var descriptor = Obj(row["CompatibilityDescriptor"]); var context = RefreshContext(descriptor);
            foreach (var collection in Arr(snapshot["Collections"]).Select(Obj))
            {
                if (Text(collection["Privacy"]) != "Private" || (Text(collection["EvidenceType"]) == "IssuedScopes" ? !ExactContext(Obj(collection["Context"]), context) : Text(collection["EvidenceType"]) != "ApiAcceptance" || !OperationContext(Obj(collection["Context"]), context, Obj(descriptor["Profile"]), Obj(descriptor["Tool"]), "GraphMeV1"))) throw Invalid();
                foreach (var record in Arr(collection["Records"]).Select(Obj))
                {
                    if (Date(record["ObservedAt"]) < Date(state["StartedAt"]) || Date(record["ObservedAt"]) > DateTimeOffset.UtcNow.AddMinutes(5)) throw Invalid();
                    bool Has(string kind, Func<JsonObject, bool>? extra = null) => Events.Select(Obj).Any(e => Text(e["RequestId"]) == id && Text(e["Kind"]) == kind && Text(e["Outcome"]) == "Responded" && Date(e["StartedAt"]) <= Date(record["ObservedAt"]) && (extra == null || extra(e)));
                    if (Text(collection["EvidenceType"]) == "IssuedScopes" && (!Has("FinalIssuance") || !Has("BootstrapIssuance") || !Has("IdentityGet", e => e["HttpStatus"] != null && Int(e["HttpStatus"]) == 200))) throw Invalid();
                    if (Text(collection["EvidenceType"]) == "ApiAcceptance" && !Has("ApiGet", e => Equal(e["HttpStatus"], Obj(record["Value"])["Status"]))) throw Invalid();
                }
            }
        }
        public void SaveEvidence(string requestId, string snapshotJson)
        {
            if (disposed) throw Invalid(); var snapshot = Parse(ChangeReports.ValidateSnapshot(snapshotJson)); ValidateTerminal(requestId, snapshot);
            if (interrupted.Contains(requestId) || Events.Select(Obj).Any(e => Text(e["RequestId"]) == requestId && Unresolved(e))) throw Invalid();
            if (Terminals.Select(Obj).Any(t => Text(t["RequestId"]) == requestId)) throw Invalid();
            Terminals.Add(new JsonObject { ["RequestId"] = requestId, ["Snapshot"] = snapshot, ["SavedAt"] = DateTimeOffset.UtcNow.ToString("o") }); try { Validate(); Save(); } catch { Terminals.RemoveAt(Terminals.Count - 1); throw; }
        }
        internal bool CanAdvance() => Events.Select(Obj).All(e => Terminals.Select(Obj).Any(t => Equal(t["RequestId"], e["RequestId"])));
        public string ProjectHistory(string? historyJson = null)
        {
            if (disposed) throw Invalid(); string history = historyJson ?? CreateRefreshHistory();
            foreach (var terminal in Terminals.Select(Obj)) history = CaptureRefreshEvidence(plan.ToJsonString(), Obj(terminal["Snapshot"]).ToJsonString(), history);
            return history;
        }
        public string Status()
        {
            if (disposed) throw Invalid(); var events = Events.Select(Obj).ToArray(); var result = Header("TokenForgeRefreshRunStatus"); result["PlanId"] = plan["PlanId"]!.DeepClone(); result["SelectedCount"] = plan["SelectedCount"]!.DeepClone(); result["CompletedCount"] = Terminals.Count; result["PendingCount"] = Int(plan["SelectedCount"]) - Terminals.Count; result["InFlightUnknownCount"] = events.Count(Unresolved); result["InterruptedCount"] = interrupted.Count; result["IssuanceAttempts"] = events.Count(e => Issuance(Text(e["Kind"]))); result["TotalRequests"] = events.Count(e => !Issuance(Text(e["Kind"]))); result["BootstrapRequests"] = events.Count(e => Text(e["Kind"]) == "BootstrapHttp"); result["InventoryRequests"] = events.Count(e => Text(e["Kind"]) is "InventoryGet" or "InventoryPageGet"); result["InventoryPages"] = events.Count(e => Text(e["Kind"]) == "InventoryPageGet"); result["SourceRequests"] = events.Count(e => Text(e["Kind"]) == "SourceGet"); result["OtherRequests"] = events.Count(e => Text(e["Kind"]) is "OtherHttp" or "ApiGet" or "IdentityGet"); result["TransientRetries"] = events.Count(e => e["RetryOf"] != null && !Bool(e["Recovery"])); result["RecoveryRetries"] = events.Count(e => Bool(e["Recovery"])); result["Requests"] = new JsonArray(Arr(plan["Candidates"]).Select(Obj).Where(c => Bool(c["Selected"])).Select(c => (JsonNode?)new JsonObject { ["RequestId"] = c["RequestId"]!.DeepClone(), ["Status"] = Terminals.Select(Obj).Any(t => Equal(t["RequestId"], c["RequestId"])) ? "Complete" : events.Any(e => Equal(e["RequestId"], c["RequestId"]) && Unresolved(e)) ? "InFlightUnknown" : interrupted.Contains(Text(c["RequestId"])) ? "Interrupted" : "Pending" }).ToArray()); result["DeadlineReached"] = DateTimeOffset.UtcNow - Date(state["StartedAt"]) >= TimeSpan.FromSeconds(Int(Obj(plan["Policy"])["MaxSeconds"])); result["ExactlyOnceGuaranteed"] = false; return result.ToJsonString();
        }
        private void Save()
        {
            PrivateFiles.Resolve(path, false); string temporary = path + "." + Guid.NewGuid().ToString("N") + ".tmp";
            try { using (var output = PrivateFiles.Open(temporary, true)) { output.Write(Encoding.UTF8.GetBytes(state.ToJsonString())); output.Flush(true); } File.Move(temporary, path, true); } finally { if (File.Exists(temporary)) File.Delete(temporary); }
        }
        public void Dispose() { if (disposed) return; disposed = true; gate.Dispose(); }
    }
}
