using Microsoft.Data.Sqlite;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using TokenForge.Core.V0220;

namespace TokenForge.Core;

// One-store online backup, not a coordinated checkpoint of several databases/journals.
public static class SqliteSnapshot
{
    private const long MaxBytes = 512L * 1024 * 1024;
    public sealed record Result(int SchemaVersion, string Domain, int ApplicationId, int StoreVersion,
        long Bytes, string Sha256, string CreatedAt, bool FreshAuthenticationPerformed = false,
        bool CrossStoreAtomic = false);

    public static Result Save(string sourcePath, string outputPath, string domain, CancellationToken cancellation = default)
    {
        if (!OperatingSystem.IsLinux()) throw new PlatformNotSupportedException("SQLite snapshots are currently validated for Linux only.");
        if (domain is not ("scopes" or "flows" or "applications")) throw new InvalidOperationException();
        sourcePath = PrivatePath.ValidateExisting(sourcePath);
        foreach (string suffix in new[] { "-wal", "-shm", "-journal" })
        {
            string companion = sourcePath + suffix;
            if (new FileInfo(companion).LinkTarget is not null || Directory.Exists(companion)) throw new InvalidOperationException();
            if (File.Exists(companion)) PrivatePath.ValidateExisting(companion);
        }
        outputPath = PrivateFiles.Resolve(outputPath, true);
        if (sourcePath == outputPath) throw new InvalidOperationException();
        RefuseDestination(outputPath);
        if (new FileInfo(sourcePath).Length is < 1 or > MaxBytes) throw new InvalidOperationException();
        string temporary = outputPath + "." + Guid.NewGuid().ToString("N") + ".tmp";
        bool published = false, cleanupFailed = false;
        try
        {
            cancellation.ThrowIfCancellationRequested();
            using (var file = PrivateFiles.Open(temporary, true)) { }
            int app, version;
            using (var source = Open(sourcePath, true))
            using (var transaction = source.BeginTransaction(deferred: true))
            {
                (app, version) = Validate(source, domain, transaction);
                using var destination = Open(temporary, false);
                // SQLite's backup API includes committed WAL pages. A pinned read snapshot
                // prevents a later source writer from changing this copy mid-validation.
                source.BackupDatabase(destination);
                Execute(destination, "PRAGMA journal_mode=DELETE;");
                Validate(destination, domain);
            }
            cancellation.ThrowIfCancellationRequested();
            if (new FileInfo(temporary).Length > MaxBytes) throw new InvalidOperationException();
            // Validate typed histories using existing read-only consumers before publication.
            // Auxiliary plan/checkpoint tables are copied in full by SQLite, not reconstructed
            // from the portable scope export.
            switch (domain)
            {
                case "scopes":
                    using (var store = new EvidenceStore(temporary, readOnly: true))
                    using (var copy = Open(temporary, true))
                    {
                        _ = store.Export();
                        using var command = copy.CreateCommand();
                        command.CommandText = "SELECT count(*),coalesce(sum(length(payload)),0) FROM plans;";
                        using (var reader = command.ExecuteReader())
                        { reader.Read(); if (reader.GetInt64(0) > 10000 || reader.GetInt64(1) > 64L * 1024 * 1024) throw new InvalidOperationException(); }
                        command.CommandText = "SELECT id FROM plans;";
                        var ids = new List<string>(); using (var reader = command.ExecuteReader()) while (reader.Read()) ids.Add(reader.GetString(0));
                        foreach (var id in ids) { cancellation.ThrowIfCancellationRequested(); _ = store.Pending(id); }
                        command.CommandText = "SELECT 1 FROM checkpoints c LEFT JOIN plans p ON p.id=c.plan WHERE p.id IS NULL UNION ALL SELECT 1 FROM sources s LEFT JOIN observations o ON o.id=s.observation_id WHERE o.id IS NULL LIMIT 1;";
                        if (command.ExecuteScalar() is not null) throw new InvalidOperationException();
                    }
                    break;
                case "flows": using (var store = new FlowEvidenceStore(temporary, readOnly: true)) { _ = store.Export(); } break;
                case "applications": using (var store = new ApplicationCatalogStore(temporary, readOnly: true)) { _ = store.Export(); } break;
            }
            using (var file = new FileStream(temporary, FileMode.Open, FileAccess.ReadWrite, FileShare.None)) file.Flush(true);
            string hash; using (var input = File.OpenRead(temporary)) hash = Convert.ToHexString(SHA256.HashData(input)).ToLowerInvariant();
            var result = new Result(1, domain, app, version, new FileInfo(temporary).Length, hash, DateTimeOffset.UtcNow.ToString("o"));
            cancellation.ThrowIfCancellationRequested();
            PrivateFiles.Resolve(outputPath, false);
            RefuseDestination(outputPath);
            if (Link(temporary, outputPath) != 0) throw new IOException("Create-new snapshot publication failed.");
            published = true;
            return result;
        }
        finally
        {
            foreach (string suffix in new[] { "", "-wal", "-shm", "-journal" })
                try { if (File.Exists(temporary + suffix)) File.Delete(temporary + suffix); } catch { cleanupFailed = true; }
            if (cleanupFailed) throw new SqliteSnapshotCleanupException(published);
        }
    }

    private static void RefuseDestination(string path)
    {
        foreach (string suffix in new[] { "", "-wal", "-shm", "-journal" })
        {
            string item = path + suffix;
            if (File.Exists(item) || Directory.Exists(item) || new FileInfo(item).LinkTarget is not null) throw new InvalidOperationException();
        }
    }
    private static SqliteConnection Open(string path, bool readOnly)
    {
        var connection = new SqliteConnection(new SqliteConnectionStringBuilder
        { DataSource = path, Pooling = false, DefaultTimeout = 5, Mode = readOnly ? SqliteOpenMode.ReadOnly : SqliteOpenMode.ReadWrite }.ToString());
        try { connection.Open(); Execute(connection, "PRAGMA trusted_schema=OFF;"); return connection; }
        catch { connection.Dispose(); throw; }
    }
    private static void Execute(SqliteConnection connection, string sql)
    { using var command = connection.CreateCommand(); command.CommandText = sql; command.ExecuteNonQuery(); }
    private static (int, int) Validate(SqliteConnection connection, string domain, SqliteTransaction? transaction = null)
    {
        using var command = connection.CreateCommand(); command.Transaction = transaction;
        int Value(string sql) { command.CommandText = sql; return Convert.ToInt32(command.ExecuteScalar()); }
        int app = Value("PRAGMA application_id;"), version = Value("PRAGMA user_version;");
        int expected = domain switch { "scopes" => 0x54464745, "flows" => 0x54464746, _ => 0x54464741 };
        if (app != expected || (domain == "applications" ? version is not (1 or 2) : version != 1)) throw new InvalidOperationException();
        long pages = Value("PRAGMA page_count;"), pageSize = Value("PRAGMA page_size;");
        if (pages <= 0 || pages * pageSize > MaxBytes) throw new InvalidOperationException();
        command.CommandText = "PRAGMA integrity_check;";
        using (var reader = command.ExecuteReader()) if (!reader.Read() || reader.GetString(0) != "ok" || reader.Read()) throw new InvalidOperationException();
        command.CommandText = "PRAGMA foreign_key_check;";
        using (var reader = command.ExecuteReader()) if (reader.Read()) throw new InvalidOperationException();
        // Unknown executable schema objects are never promoted into a restored operational store.
        string[] tables = domain switch
        {
            "scopes" => new[] { "observations", "sources", "registration_attempts", "plans", "checkpoints" },
            "flows" => new[] { "flow_plans", "flow_attempts" },
            _ => new[] { "catalog_info", "catalog_apps", "catalog_runs", "catalog_origins", "catalog_records", "catalog_versions" }
        };
        command.CommandText = "SELECT type,name FROM sqlite_schema WHERE substr(name,1,7) <> 'sqlite_';";
        var found = new HashSet<string>(StringComparer.Ordinal);
        using (var reader = command.ExecuteReader())
            while (reader.Read())
            {
                string type = reader.GetString(0), name = reader.GetString(1);
                if (type == "table") { if (!tables.Contains(name, StringComparer.Ordinal) || !found.Add(name)) throw new InvalidOperationException(); }
                else if (type != "index" || !(domain switch {
                    "scopes" => new[] { "coverage" }, "flows" => new[] { "flow_context", "flow_latest" },
                    _ => new[] { "catalog_origin", "catalog_history", "catalog_version_payload" }
                }).Contains(name, StringComparer.Ordinal)) throw new InvalidOperationException();
            }
        if (!found.SetEquals(tables)) throw new InvalidOperationException();
        var columns = new Dictionary<string, string>(StringComparer.Ordinal) {
            ["observations"]="id,tenant,principal,client,resource,observed,payload", ["sources"]="observation_id,source,imported",
            ["registration_attempts"]="id,payload", ["plans"]="id,batch_size,payload", ["checkpoints"]="plan,client,outcome,completed",
            ["flow_plans"]="id,tenant,principal,client,resource,planned,payload", ["flow_attempts"]="sequence,id,slot,plan,observed,outcome,payload",
            ["catalog_info"]="id,created,updated", ["catalog_apps"]="id,first,last", ["catalog_runs"]="sequence,id,kind,observed,payload,request",
            ["catalog_origins"]="id,kind,observed,run,payload", ["catalog_records"]="app,origin,first,last,present,hash,payload,digest",
            ["catalog_versions"]="sequence,app,origin,id,first,last,payload,hash"
        };
        foreach (string table in tables)
        {
            command.CommandText = "PRAGMA table_xinfo(" + table + ");";
            var names = new List<string>(); using var reader = command.ExecuteReader();
            while (reader.Read()) { if (reader.GetInt32(6) != 0) throw new InvalidOperationException(); names.Add(reader.GetString(1)); }
            if (string.Join(",", names) != columns[table]) throw new InvalidOperationException();
        }
        if (domain == "scopes")
        {
            command.CommandText = "SELECT source,imported FROM sources;"; long total = 0;
            using var reader = command.ExecuteReader();
            while (reader.Read())
            {
                string label = reader.GetString(0), imported = reader.GetString(1);
                if (label.Length > 4096 || (total += label.Length + imported.Length) > 64L * 1024 * 1024) throw new InvalidOperationException();
                CanonicalDate(imported);
            }
        }
        if (domain == "applications")
        {
            command.CommandText = "SELECT id,created,updated FROM catalog_info;";
            using var reader = command.ExecuteReader(); int count = 0;
            while (reader.Read())
            {
                if (++count > 1 || reader.GetInt64(0) != 1 || CanonicalDate(reader.GetString(1)) > CanonicalDate(reader.GetString(2))) throw new InvalidOperationException();
            }
        }
        // Check relationships explicitly: foreign_key_check alone trusts the input DDL.
        command.CommandText = domain switch {
            "flows" => "SELECT 1 FROM flow_attempts a LEFT JOIN flow_plans p ON a.plan=p.id WHERE p.id IS NULL LIMIT 1;",
            "applications" => "SELECT 1 FROM catalog_origins o LEFT JOIN catalog_runs r ON o.run=r.id WHERE r.id IS NULL UNION ALL SELECT 1 FROM catalog_records c LEFT JOIN catalog_apps a ON c.app=a.id LEFT JOIN catalog_origins o ON c.origin=o.id WHERE a.id IS NULL OR o.id IS NULL UNION ALL SELECT 1 FROM catalog_versions v LEFT JOIN catalog_records c ON v.app=c.app AND v.origin=c.origin WHERE c.app IS NULL LIMIT 1;",
            _ => "SELECT 1 FROM checkpoints c LEFT JOIN plans p ON c.plan=p.id WHERE p.id IS NULL UNION ALL SELECT 1 FROM sources s LEFT JOIN observations o ON s.observation_id=o.id WHERE o.id IS NULL LIMIT 1;"
        };
        if (command.ExecuteScalar() is not null) throw new InvalidOperationException();
        return (app, version);
    }
    private static DateTimeOffset CanonicalDate(string value)
    {
        if (value.Length > 64 || !DateTimeOffset.TryParse(value, System.Globalization.CultureInfo.InvariantCulture,
            System.Globalization.DateTimeStyles.None, out var date) || value != date.ToUniversalTime().ToString("o")) throw new InvalidOperationException();
        return date;
    }
    [DllImport("libc", EntryPoint = "link", SetLastError = true)]
    private static extern int Link(string source, string target);
}
public sealed class SqliteSnapshotCleanupException(bool snapshotCreated) : IOException("SQLite snapshot cleanup failed.")
{ public bool SnapshotCreated { get; } = snapshotCreated; }
