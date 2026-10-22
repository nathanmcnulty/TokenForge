using static TokenForge.Core.FlowEvidencePolicy;
using Microsoft.Data.Sqlite;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace TokenForge.Core;

// Flow evidence is private diagnostic metadata, never a credential or authorization store.
public sealed class FlowEvidenceStore : IDisposable
{
    private readonly SqliteConnection connection;
    private const int ApplicationId = 0x54464746;
    private const int MaxDocumentBytes = 128 * 1024 * 1024;
    public FlowEvidenceStore(string path, bool readOnly = false)
    {
        if (readOnly && !File.Exists(path)) throw new InvalidOperationException("Flow store does not exist.");
        var empty = !File.Exists(path) || new FileInfo(path).Length == 0;
        path = PrivatePath.Prepare(path);
        connection = new SqliteConnection(new SqliteConnectionStringBuilder {
            DataSource = path, Pooling = false, DefaultTimeout = 5,
            Mode = readOnly ? SqliteOpenMode.ReadOnly : SqliteOpenMode.ReadWrite }.ToString());
        try
        {
            connection.Open();
            using var command = connection.CreateCommand();
            command.CommandText = "PRAGMA application_id;";
            var app = Convert.ToInt32(command.ExecuteScalar());
            command.CommandText = "PRAGMA user_version;";
            var version = Convert.ToInt32(command.ExecuteScalar());
            if (!empty && (app != ApplicationId || version != 1)) throw new InvalidOperationException("Unknown flow store format.");
            if (empty && readOnly) throw new InvalidOperationException("Flow store is not initialized.");
            command.CommandText = "PRAGMA trusted_schema=OFF; PRAGMA foreign_keys=ON;";
            command.ExecuteNonQuery();
            if (!empty) return;
            using var transaction = connection.BeginTransaction();
            command.Transaction = transaction;
            command.CommandText = """
                CREATE TABLE flow_plans(id TEXT PRIMARY KEY,tenant TEXT NOT NULL,principal TEXT NOT NULL,client TEXT NOT NULL,resource TEXT NOT NULL,planned TEXT NOT NULL,payload TEXT NOT NULL);
                CREATE INDEX flow_context ON flow_plans(tenant,principal,client,resource,planned);
                CREATE TABLE flow_attempts(sequence INTEGER PRIMARY KEY AUTOINCREMENT,id TEXT NOT NULL UNIQUE,slot TEXT NOT NULL,plan TEXT NOT NULL REFERENCES flow_plans(id),observed TEXT NOT NULL,outcome TEXT NOT NULL,payload TEXT NOT NULL);
                CREATE INDEX flow_latest ON flow_attempts(plan,slot,observed DESC,sequence DESC);
                PRAGMA application_id=1413891910;
                PRAGMA user_version=1;
                """;
            command.ExecuteNonQuery(); transaction.Commit();
            command.Transaction = null;
            command.CommandText = "PRAGMA journal_mode=WAL;"; command.ExecuteNonQuery();
        }
        catch { connection.Dispose(); throw; }
    }

    // Validate a complete input before a read-only consumer selects its context.
    // No connection, file, import, or normalization is involved.
    public static void ValidateDocument(string json)=>FlowEvidencePolicy.ValidateDocument(json);

    public int Import(string json)
    {
        using var doc = Parse(json);
        var root = doc.RootElement;
        Keys(root, "Format SchemaVersion UpdatedAt Plans Attempts");
        if (Text(root, "Format") != "TokenForgeFlowEvidence" || root.GetProperty("SchemaVersion").GetInt32() != 1) throw Invalid();
        Date(root, "UpdatedAt");
        var plans = root.GetProperty("Plans");
        if (plans.ValueKind != JsonValueKind.Object || root.GetProperty("Attempts").ValueKind != JsonValueKind.Array) throw Invalid();
        using var transaction = connection.BeginTransaction();
        var seen = new HashSet<string>(StringComparer.Ordinal);
        foreach (var plan in plans.EnumerateObject())
        {
            if (!seen.Add(plan.Name)) throw Invalid();
            WritePlan(plan.Name, plan.Value, transaction);
        }
        var ids = new HashSet<string>(StringComparer.Ordinal); var count = 0;
        foreach (var row in root.GetProperty("Attempts").EnumerateArray())
        {
            if (!ids.Add(Text(row, "AttemptId"))) throw Invalid();
            // Import must not bind an attempt to a plan absent from the imported document.
            if (!seen.Contains(Text(row, "PlanFingerprint"))) throw Invalid();
            count += WriteAttempt(row, transaction);
        }
        transaction.Commit(); return count;
    }

    public void SavePlan(string fingerprint, string json)
    {
        using var doc = Parse(json);
        using var transaction = connection.BeginTransaction();
        WritePlan(fingerprint, doc.RootElement, transaction); transaction.Commit();
    }
    public void SaveAttempt(string json)
    {
        using var doc = Parse(json);
        using var transaction = connection.BeginTransaction();
        WriteAttempt(doc.RootElement, transaction); transaction.Commit();
    }
    private void WritePlan(string fingerprint, JsonElement plan, SqliteTransaction transaction)
    {
        ValidatePlan(fingerprint, plan);
        using var command = connection.CreateCommand(); command.Transaction = transaction;
        command.CommandText = """
            INSERT INTO flow_plans VALUES($id,$tenant,$principal,$client,$resource,$planned,$payload)
            ON CONFLICT(id) DO UPDATE SET planned=excluded.planned,payload=excluded.payload WHERE excluded.planned>=flow_plans.planned;
            """;
        Add(command, "$id", fingerprint);
        foreach (var field in new[] { "TenantFingerprint", "PrincipalFingerprint", "ClientId", "ResourceId" })
            Add(command, field switch { "TenantFingerprint" => "$tenant", "PrincipalFingerprint" => "$principal", "ClientId" => "$client", _ => "$resource" }, Text(plan, field));
        Add(command, "$planned", Date(plan, "PlannedAt")); Add(command, "$payload", Canonical(plan)); command.ExecuteNonQuery();
    }
    private int WriteAttempt(JsonElement row, SqliteTransaction transaction)
    {
        var hash = Text(row, "PlanFingerprint");
        using var planDoc = ReadPlan(hash, transaction);
        ValidateAttempt(row, hash, planDoc.RootElement);
        using var command = connection.CreateCommand(); command.Transaction = transaction;
        command.CommandText = "SELECT payload FROM flow_attempts WHERE id=$id;";
        Add(command, "$id", Text(row, "AttemptId"));
        var existing = command.ExecuteScalar() as string;
        if (existing != null)
        {
            using var old = Parse(existing); ValidateAttempt(old.RootElement, hash, planDoc.RootElement);
            bool oldContext=old.RootElement.TryGetProperty("ComparisonContext",out var beforeContext),newContext=row.TryGetProperty("ComparisonContext",out var afterContext);
            if(oldContext!=newContext || oldContext && Canonical(beforeContext)!=Canonical(afterContext))throw Invalid();
            foreach (var field in new[] { "AttemptId", "PlanFingerprint", "AttemptKey", "Protocol", "RedirectFingerprint", "TenantFingerprint", "PrincipalFingerprint", "ClientId", "ResourceId" })
                if (Text(old.RootElement, field) != Text(row, field)) throw Invalid();
            if (Date(old.RootElement, "StartedAt") != Date(row, "StartedAt") || StringComparer.Ordinal.Compare(Date(old.RootElement, "ObservedAt"), Date(row, "ObservedAt")) > 0) throw Invalid();
            if (old.RootElement.GetProperty("Spa").GetBoolean() != row.GetProperty("Spa").GetBoolean()) throw Invalid();
            if (Date(old.RootElement, "ObservedAt") == Date(row, "ObservedAt") && Canonical(old.RootElement) == Canonical(row)) return 0;
            if (Text(old.RootElement, "Outcome") != "Started" || Text(row, "Outcome") == "Started") throw Invalid();
        }
        command.CommandText = """
            INSERT INTO flow_attempts(id,slot,plan,observed,outcome,payload) VALUES($id,$slot,$plan,$observed,$outcome,$payload)
            ON CONFLICT(id) DO UPDATE SET observed=excluded.observed,outcome=excluded.outcome,payload=excluded.payload;
            """;
        Add(command, "$slot", Text(row, "AttemptKey")); Add(command, "$plan", hash); Add(command, "$observed", Date(row, "ObservedAt"));
        Add(command, "$outcome", Text(row, "Outcome")); Add(command, "$payload", Canonical(row)); command.ExecuteNonQuery(); return 1;
    }
    private JsonDocument ReadPlan(string hash, SqliteTransaction transaction)
    {
        HashValue(hash);
        using var command = connection.CreateCommand(); command.Transaction = transaction;
        command.CommandText = "SELECT payload,tenant,principal,client,resource,planned FROM flow_plans WHERE id=$id;"; Add(command, "$id", hash);
        using var reader = command.ExecuteReader();
        if (!reader.Read()) throw Invalid();
        var doc = Parse(reader.GetString(0));
        try {
            var plan = doc.RootElement; ValidatePlan(hash, plan);
            var fields = new[] { "TenantFingerprint", "PrincipalFingerprint", "ClientId", "ResourceId" };
            for (var i = 0; i < fields.Length; i++) if (reader.GetString(i + 1) != Text(plan, fields[i])) throw Invalid();
            if (reader.GetString(5) != Date(plan, "PlannedAt")) throw Invalid();
            return doc;
        } catch { doc.Dispose(); throw; }
    }
    public string Export(string? tenant = null, string? principal = null, bool latestOnly = false, string? planFingerprint = null)
    {
        if ((tenant == null) != (principal == null)) throw Invalid();
        if (tenant != null) { HashValue(tenant); HashValue(principal!); }
        if (planFingerprint != null) HashValue(planFingerprint);
        using var transaction = connection.BeginTransaction();
        long bytes = 0;
        void Bound(string payload) { bytes += Encoding.UTF8.GetByteCount(payload); if (bytes > MaxDocumentBytes) throw new InvalidOperationException("Select a smaller flow export context."); }
        var plans = new SortedDictionary<string, JsonElement>(StringComparer.Ordinal);
        using (var command = connection.CreateCommand())
        {
            command.Transaction = transaction;
            command.CommandText = "SELECT id,payload,tenant,principal,client,resource,planned FROM flow_plans WHERE ($tenant IS NULL OR tenant=$tenant AND principal=$principal) AND ($plan IS NULL OR id=$plan) ORDER BY id;";
            Add(command, "$tenant", tenant); Add(command, "$principal", principal); Add(command, "$plan", planFingerprint);
            using var reader = command.ExecuteReader();
            while (reader.Read()) {
                var payload = reader.GetString(1); Bound(payload); using var doc = Parse(payload); var plan = doc.RootElement;
                ValidatePlan(reader.GetString(0), plan);
                var fields = new[] { "TenantFingerprint", "PrincipalFingerprint", "ClientId", "ResourceId" };
                for (var i = 0; i < fields.Length; i++) if (reader.GetString(i + 2) != Text(plan, fields[i])) throw Invalid();
                if (reader.GetString(6) != Date(plan, "PlannedAt")) throw Invalid();
                if (tenant != null && (Text(plan, "TenantFingerprint") != tenant || Text(plan, "PrincipalFingerprint") != principal)) throw Invalid();
                plans.Add(reader.GetString(0), plan.Clone());
            }
        }
        var attempts = new List<JsonElement>();
        using (var command = connection.CreateCommand())
        {
            command.Transaction = transaction;
            command.CommandText = latestOnly ? """
                WITH selected AS (
                SELECT a.*,ROW_NUMBER() OVER(PARTITION BY slot ORDER BY observed DESC,sequence DESC) AS rank
                FROM flow_attempts a JOIN flow_plans p ON a.plan=p.id WHERE ($tenant IS NULL OR p.tenant=$tenant AND p.principal=$principal) AND ($plan IS NULL OR p.id=$plan))
                SELECT plan,payload,slot,observed,outcome,id FROM selected WHERE ($latest=0 OR rank=1) ORDER BY observed,sequence;
                """ : """
                SELECT a.plan,a.payload,a.slot,a.observed,a.outcome,a.id FROM flow_attempts a JOIN flow_plans p ON a.plan=p.id
                WHERE ($tenant IS NULL OR p.tenant=$tenant AND p.principal=$principal) AND ($plan IS NULL OR p.id=$plan) ORDER BY a.observed,a.sequence;
                """;
            Add(command, "$tenant", tenant); Add(command, "$principal", principal); Add(command, "$latest", latestOnly ? 1 : 0); Add(command, "$plan", planFingerprint);
            using var reader = command.ExecuteReader();
            while (reader.Read()) {
                var payload = reader.GetString(1); Bound(payload); using var doc = Parse(payload); var row = doc.RootElement;
                ValidateAttempt(row, reader.GetString(0), plans[reader.GetString(0)]);
                if (reader.GetString(2) != Text(row, "AttemptKey") || reader.GetString(3) != Date(row, "ObservedAt") || reader.GetString(4) != Text(row, "Outcome") || reader.GetString(5) != Text(row, "AttemptId")) throw Invalid();
                attempts.Add(row.Clone());
            }
        }
        transaction.Commit();
        var json = JsonSerializer.Serialize(new { Format = "TokenForgeFlowEvidence", SchemaVersion = 1, UpdatedAt = DateTimeOffset.UtcNow.ToString("o"), Plans = plans, Attempts = attempts });
        if (Encoding.UTF8.GetByteCount(json) > MaxDocumentBytes) throw new InvalidOperationException("Select a smaller flow export context.");
        return json;
    }

    private static void Add(SqliteCommand command, string key, object? value) => command.Parameters.AddWithValue(key, value ?? DBNull.Value);
    public void Dispose() => connection.Dispose();
}
