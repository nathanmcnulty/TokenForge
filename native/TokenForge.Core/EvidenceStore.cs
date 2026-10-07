using Microsoft.Data.Sqlite;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
namespace TokenForge.Core;

public sealed class EvidenceStore : IDisposable
{
    private readonly SqliteConnection connection;
    private static readonly HashSet<string> Fields = new("ClientId ResourceId Outcome TenantFingerprint PrincipalFingerprint ObservedAt Protocol Spa RedirectFingerprint RequestedScopes ResponseScopes ScpScopes ClaimsReadable HasScpClaim NamespaceVerification RequestVerification SignatureValidated ErrorCodes AttemptCount ElapsedSeconds CatalogHash".Split(' '), StringComparer.Ordinal);
    public EvidenceStore(string path, bool readOnly = false)
    {
        if(readOnly && !File.Exists(path)) throw new InvalidOperationException("Evidence database does not exist.");
        var wasEmpty=!File.Exists(path) || new FileInfo(path).Length==0;
        path = PrivatePath.Prepare(path);
        connection = new SqliteConnection(new SqliteConnectionStringBuilder { DataSource = path, Pooling = false, DefaultTimeout = 5, Mode = readOnly ? SqliteOpenMode.ReadOnly : SqliteOpenMode.ReadWrite }.ToString());
        connection.Open();
        using var command = connection.CreateCommand();
        try
        {
            command.CommandText="PRAGMA application_id;";var applicationId=Convert.ToInt32(command.ExecuteScalar());
            command.CommandText="PRAGMA user_version;";var version=Convert.ToInt32(command.ExecuteScalar());
            if(!wasEmpty && (applicationId!=0x54464745 || version!=1)) throw new InvalidOperationException("Unknown evidence database format.");
            if(readOnly && wasEmpty) throw new InvalidOperationException("Evidence database is not initialized.");
            command.CommandText="PRAGMA trusted_schema=OFF;";command.ExecuteNonQuery();
            if(!wasEmpty) return;
        }
        catch{connection.Dispose();throw;}
        command.CommandText = """
            PRAGMA journal_mode=WAL;
            CREATE TABLE IF NOT EXISTS observations(id TEXT PRIMARY KEY,tenant TEXT,principal TEXT,client TEXT NOT NULL,resource TEXT NOT NULL,observed TEXT NOT NULL,payload TEXT NOT NULL);
            CREATE INDEX IF NOT EXISTS coverage ON observations(tenant,principal,resource,client,observed);
            CREATE TABLE IF NOT EXISTS sources(observation_id TEXT NOT NULL,source TEXT NOT NULL,imported TEXT NOT NULL,PRIMARY KEY(observation_id,source));
            CREATE TABLE IF NOT EXISTS registration_attempts(id TEXT PRIMARY KEY,payload TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS plans(id TEXT PRIMARY KEY,batch_size INTEGER NOT NULL,payload TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS checkpoints(plan TEXT NOT NULL,client TEXT NOT NULL,outcome TEXT NOT NULL,completed TEXT NOT NULL,PRIMARY KEY(plan,client));
            PRAGMA application_id=1413891909;
            PRAGMA user_version=1;
            """;
        command.ExecuteNonQuery();
    }
    public int Import(string json, string source)
    {
        if (json.Length > 64 * 1024 * 1024 || source.Length > 4096) throw new InvalidOperationException("Evidence input exceeds bounds.");
        using var document = JsonDocument.Parse(json, new JsonDocumentOptions { MaxDepth = 8 });
        var root = document.RootElement;
        if (root.GetProperty("SchemaVersion").GetInt32() != 1 || root.GetProperty("Observations").ValueKind != JsonValueKind.Array)
            throw new InvalidOperationException("Unsupported scope database.");
        if(root.EnumerateObject().Select(x=>x.Name).Distinct(StringComparer.Ordinal).Count()!=root.EnumerateObject().Count()) throw new InvalidOperationException("Duplicate scope database fields.");
        if(root.EnumerateObject().Any(x=>x.Name is not ("SchemaVersion" or "UpdatedAt" or "Observations" or "RegistrationAttempts"))) throw new InvalidOperationException("Unknown scope database fields.");
        using var transaction = connection.BeginTransaction();
        var count = 0;
        foreach (var row in root.GetProperty("Observations").EnumerateArray())
        {
            var clean = CleanObservation(row);
            var payload = JsonSerializer.Serialize(clean);
            var id = Hash(payload);
            using var command = connection.CreateCommand(); command.Transaction = transaction;
            command.CommandText = "INSERT OR IGNORE INTO observations VALUES($id,$tenant,$principal,$client,$resource,$observed,$payload);";
            Add(command, "$id", id); Add(command, "$tenant", clean["TenantFingerprint"]); Add(command, "$principal", clean["PrincipalFingerprint"]);
            Add(command, "$client", clean["ClientId"]); Add(command, "$resource", clean["ResourceId"]); Add(command, "$observed", clean["ObservedAt"]); Add(command, "$payload", payload);
            count += command.ExecuteNonQuery();
            command.Parameters.Clear();
            command.CommandText = "INSERT INTO sources VALUES($id,$source,$date) ON CONFLICT(observation_id,source) DO UPDATE SET imported=excluded.imported;";
            Add(command, "$id", id); Add(command, "$source", source); Add(command, "$date", DateTimeOffset.UtcNow.ToString("o")); command.ExecuteNonQuery();
        }
        if (root.TryGetProperty("RegistrationAttempts", out var attempts))
        {
            foreach (var row in attempts.EnumerateArray())
            {
                var clean=CleanRegistration(row);
                var payload = JsonSerializer.Serialize(clean);
                using var command = connection.CreateCommand(); command.Transaction = transaction; command.CommandText = "INSERT OR IGNORE INTO registration_attempts VALUES($id,$payload);";
                Add(command, "$id", Hash(payload)); Add(command, "$payload", payload); command.ExecuteNonQuery();
            }
        }
        transaction.Commit(); return count;
    }
    private static SortedDictionary<string, object?> CleanObservation(JsonElement row)
    {
        var clean = new SortedDictionary<string, object?>(StringComparer.Ordinal);
        foreach (var property in row.EnumerateObject())
        {
            var name = property.Name; var value = property.Value;
            if (!Fields.Contains(name) || clean.ContainsKey(name)) throw new InvalidOperationException("Unknown or duplicate observation fields.");
            clean[name] = name switch
            {
                "ClientId" or "ResourceId" => GuidValue(value),
                "TenantFingerprint" or "PrincipalFingerprint" or "RedirectFingerprint" or "CatalogHash" => Fingerprint(value),
                "ObservedAt" => Date(value),
                "Outcome" => Choice(value, "Succeeded NoDelegatedScp OpaqueToken Failed NoRedirect Disabled MissingRegistration OwnerMismatch BrokerRequired ContextMismatch"),
                "Protocol" => Choice(value, "OAuth2V2Pkce OAuth2V2Implicit OAuth2V1Implicit"),
                "NamespaceVerification" or "RequestVerification" => Choice(value, "Matched Mismatch Unverifiable"),
                "RequestedScopes" or "ResponseScopes" or "ScpScopes" => Strings(value, "^[A-Za-z0-9_.:/-]{1,256}$"),
                "ErrorCodes" => Strings(value, "^[0-9]{4,9}$"),
                "Spa" or "ClaimsReadable" or "HasScpClaim" => value.GetBoolean(),
                "SignatureValidated" => false,
                "AttemptCount" => Number(value, 100000),
                "ElapsedSeconds" => Number(value, 604800),
                _ => throw new InvalidOperationException("Invalid evidence field.")
            };
        }
        foreach (var required in new[] { "ClientId", "ResourceId", "Outcome", "TenantFingerprint", "PrincipalFingerprint", "ObservedAt" })
            if (!clean.ContainsKey(required)) throw new InvalidOperationException("Missing observation field.");
        clean["SignatureValidated"] = false;
        return clean;
    }
    public string Export(bool publicOnly = false, bool latest = false, string? tenant = null, string? principal = null, string? resource = null)
    {
        if(tenant!=null && !Regex.IsMatch(tenant,"\\A[a-f0-9]{64}\\z") || principal!=null && !Regex.IsMatch(principal,"\\A[a-f0-9]{64}\\z")) throw new InvalidOperationException("Invalid evidence namespace.");
        if(principal!=null && tenant==null) throw new InvalidOperationException("Principal selection requires a tenant.");
        if(resource!=null) resource=Guid.Parse(resource).ToString();
        using var transaction = connection.BeginTransaction();
        var rows = new List<JsonElement>();
        long bytes=0;
        void Bound(string payload){bytes+=Encoding.UTF8.GetByteCount(payload);if(bytes>64*1024*1024)throw new InvalidOperationException("Evidence export exceeds bounds.");}
        using (var command = connection.CreateCommand())
        {
            command.Transaction = transaction;
            var filter=" WHERE ($tenant IS NULL OR tenant=$tenant) AND ($principal IS NULL OR principal=$principal) AND ($resource IS NULL OR resource=$resource)";
            command.CommandText=latest ? "SELECT id,tenant,principal,client,resource,observed,payload FROM (SELECT *,ROW_NUMBER() OVER(PARTITION BY tenant,principal,client,resource ORDER BY observed DESC,rowid DESC) AS rank FROM observations"+filter+") WHERE rank=1 ORDER BY observed,id;" : "SELECT id,tenant,principal,client,resource,observed,payload FROM observations"+filter+" ORDER BY observed,rowid;";
            Add(command,"$tenant",tenant);Add(command,"$principal",principal);Add(command,"$resource",resource);
            using var reader = command.ExecuteReader();
            while (reader.Read())
            {
                var payload=reader.GetString(6);Bound(payload);
                using var document = JsonDocument.Parse(payload);
                var clean = CleanObservation(document.RootElement);
                if(Hash(JsonSerializer.Serialize(clean))!=reader.GetString(0) || (string?)clean["TenantFingerprint"]!=(reader.IsDBNull(1)?null:reader.GetString(1)) || (string?)clean["PrincipalFingerprint"]!=(reader.IsDBNull(2)?null:reader.GetString(2)) || (string?)clean["ClientId"]!=reader.GetString(3) || (string?)clean["ResourceId"]!=reader.GetString(4) || (string?)clean["ObservedAt"]!=reader.GetString(5)) throw new InvalidOperationException("Invalid stored scope evidence.");
                if (publicOnly) { clean.Remove("TenantFingerprint"); clean.Remove("PrincipalFingerprint"); }
                rows.Add(JsonSerializer.SerializeToElement(clean));
            }
        }
        var attempts = new List<JsonElement>();
        if (!publicOnly)
        {
            using var command = connection.CreateCommand(); command.Transaction = transaction; command.CommandText=latest ? "WITH ranked AS (SELECT *,json_extract(payload,'$.TenantFingerprint') AS tenant,json_extract(payload,'$.AppId') AS app,ROW_NUMBER() OVER(PARTITION BY json_extract(payload,'$.TenantFingerprint'),json_extract(payload,'$.AppId') ORDER BY json_extract(payload,'$.AttemptedAt') DESC,rowid DESC) AS rank FROM registration_attempts WHERE ($tenant IS NULL OR json_extract(payload,'$.TenantFingerprint')=$tenant)), cleanup AS (SELECT *,ROW_NUMBER() OVER(PARTITION BY json_extract(payload,'$.TenantFingerprint'),json_extract(payload,'$.AppId') ORDER BY json_extract(payload,'$.AttemptedAt') DESC,rowid DESC) AS rank FROM registration_attempts WHERE ($tenant IS NULL OR json_extract(payload,'$.TenantFingerprint')=$tenant) AND json_extract(payload,'$.Outcome') IN ('CleanupRequired','CleanupResolved')) SELECT CASE WHEN json_extract(c.payload,'$.Outcome')='CleanupRequired' THEN c.id ELSE r.id END,CASE WHEN json_extract(c.payload,'$.Outcome')='CleanupRequired' THEN c.payload ELSE r.payload END FROM ranked r LEFT JOIN cleanup c ON c.rank=1 AND json_extract(c.payload,'$.TenantFingerprint')=r.tenant AND json_extract(c.payload,'$.AppId')=r.app WHERE r.rank=1 ORDER BY json_extract(r.payload,'$.AttemptedAt'),r.id;" : "SELECT id,payload FROM registration_attempts WHERE ($tenant IS NULL OR json_extract(payload,'$.TenantFingerprint')=$tenant) ORDER BY json_extract(payload,'$.AttemptedAt'),rowid;";
            Add(command,"$tenant",tenant);
            using var reader = command.ExecuteReader(); while (reader.Read()){var payload=reader.GetString(1);Bound(payload);using var document=JsonDocument.Parse(payload);var clean=CleanRegistration(document.RootElement);if(Hash(JsonSerializer.Serialize(clean))!=reader.GetString(0))throw new InvalidOperationException("Invalid stored registration evidence.");attempts.Add(JsonSerializer.SerializeToElement(clean));}
        }
        transaction.Commit();
        var result=JsonSerializer.Serialize(new { SchemaVersion = 1, UpdatedAt = DateTimeOffset.UtcNow.ToString("o"), Observations = rows, RegistrationAttempts = attempts });
        if(Encoding.UTF8.GetByteCount(result)>64*1024*1024)throw new InvalidOperationException("Evidence export exceeds bounds.");
        return result;
    }
    public string Plan(IEnumerable<string> clients, int batchSize)
    {
        if (batchSize < 1 || batchSize > 1000) throw new InvalidOperationException("Invalid chunk size.");
        var members = clients.Select(x => Guid.Parse(x).ToString()).Distinct(StringComparer.Ordinal).Order(StringComparer.Ordinal).ToArray();
        if (members.Length > 100000) throw new InvalidOperationException("Plan too large.");
        if(members.Any(x=>Guid.Parse(x)==Guid.Empty)) throw new InvalidOperationException("Empty client ID.");
        var payload = JsonSerializer.Serialize(members); var id = Hash(batchSize + "|" + payload);
        using var command = connection.CreateCommand(); command.CommandText = "INSERT OR IGNORE INTO plans VALUES($id,$size,$payload);";
        Add(command, "$id", id); Add(command, "$size", batchSize); Add(command, "$payload", payload); command.ExecuteNonQuery(); return id;
    }
    public string Pending(string plan)
    {
        var (members, size) = ReadPlan(plan); var completed = new HashSet<string>();
        using var command = connection.CreateCommand(); command.CommandText = "SELECT client FROM checkpoints WHERE plan=$plan;"; Add(command, "$plan", plan);
        using var reader = command.ExecuteReader(); while (reader.Read()) completed.Add(reader.GetString(0));
        return JsonSerializer.Serialize(members.Select((client, index) => new { ClientId = client, Chunk = index / size, Completed = completed.Contains(client) }).Where(x=>!x.Completed));
    }
    public void Complete(string plan, string client, string outcome)
    {
        client = Guid.Parse(client).ToString(); var (members, _) = ReadPlan(plan);
        if (!members.Contains(client, StringComparer.Ordinal) || outcome is not ("Succeeded" or "Failed" or "NoRedirect" or "Disabled" or "MissingRegistration" or "OwnerMismatch" or "BrokerRequired" or "ContextMismatch" or "OpaqueToken" or "NoDelegatedScp")) throw new InvalidOperationException("Invalid checkpoint.");
        using var command = connection.CreateCommand(); command.CommandText = "INSERT INTO checkpoints VALUES($plan,$client,$outcome,$date) ON CONFLICT(plan,client) DO UPDATE SET outcome=excluded.outcome,completed=excluded.completed;";
        Add(command, "$plan", plan); Add(command, "$client", client); Add(command, "$outcome", outcome); Add(command, "$date", DateTimeOffset.UtcNow.ToString("o")); command.ExecuteNonQuery();
    }
    private (string[], int) ReadPlan(string id)
    {
        using var command = connection.CreateCommand(); command.CommandText = "SELECT payload,batch_size FROM plans WHERE id=$id;"; Add(command, "$id", id);
        using var reader = command.ExecuteReader(); if (!reader.Read()) throw new InvalidOperationException("Unknown plan.");
        var payload=reader.GetString(0);var size=reader.GetInt32(1);
        if(payload.Length>8*1024*1024 || size<1 || size>1000) throw new InvalidOperationException("Invalid stored plan.");
        var members=JsonSerializer.Deserialize<string[]>(payload)!;
        if(members.Length>100000 || members.Any(x=>!Guid.TryParse(x,out var value) || value==Guid.Empty || value.ToString()!=x) || !members.SequenceEqual(members.Distinct(StringComparer.Ordinal).Order(StringComparer.Ordinal)) || Hash(size+"|"+JsonSerializer.Serialize(members))!=id) throw new InvalidOperationException("Invalid stored plan.");
        return (members,size);
    }
    private static SortedDictionary<string,object?> CleanRegistration(JsonElement row)
    {
        var allowed=new HashSet<string>(new[]{"AppId","TenantFingerprint","AttemptedAt","Outcome","HttpStatus"});
        var seen=new HashSet<string>();
        foreach(var field in row.EnumerateObject()) if(!allowed.Contains(field.Name) || !seen.Add(field.Name)) throw new InvalidOperationException("Invalid registration fields.");
        var clean=new SortedDictionary<string,object?> { ["AppId"]=GuidValue(row.GetProperty("AppId")),["TenantFingerprint"]=Fingerprint(row.GetProperty("TenantFingerprint")),["AttemptedAt"]=Date(row.GetProperty("AttemptedAt")),["Outcome"]=Choice(row.GetProperty("Outcome"),"Created AlreadyPresent Failed OwnerRejected CleanupRequired CleanupResolved") };
        clean["HttpStatus"]=null;
        if(row.TryGetProperty("HttpStatus",out var status) && status.ValueKind!=JsonValueKind.Null){var code=status.GetInt32();if(code<100 || code>599) throw new InvalidOperationException("Invalid status.");clean["HttpStatus"]=code;}
        return clean;
    }
    private static string GuidValue(JsonElement value){var id=Guid.Parse(value.GetString()!);return id.ToString();}
    private static object? Fingerprint(JsonElement value) { if (value.ValueKind == JsonValueKind.Null) return null; var text = value.GetString(); if (text == null || !Regex.IsMatch(text, "\\A[a-f0-9]{64}\\z")) throw new InvalidOperationException("Invalid fingerprint."); return text; }
    private static string Date(JsonElement value){var text=value.GetString();if(text==null || text.Length>64 || !Regex.IsMatch(text,@"^\d{4}-\d{2}-\d{2}T[^\r\n]+(Z|[+-]\d{2}:\d{2})$")) throw new InvalidOperationException("Invalid evidence date.");return DateTimeOffset.Parse(text,System.Globalization.CultureInfo.InvariantCulture).ToUniversalTime().ToString("o");}
    private static string Choice(JsonElement value, string choices) { var text = value.GetString(); if (text == null || !choices.Split(' ').Contains(text, StringComparer.Ordinal)) throw new InvalidOperationException("Invalid evidence enum."); return text; }
    private static string[] Strings(JsonElement value, string pattern) { if (value.GetArrayLength() > 4096) throw new InvalidOperationException("Too many scope values."); var values = value.EnumerateArray().Select(x => x.ValueKind == JsonValueKind.Number ? x.GetRawText() : x.GetString()!).ToArray(); if (values.Any(x => x == null || !Regex.IsMatch(x, pattern.Replace("^", "\\A").Replace("$", "\\z")))) throw new InvalidOperationException("Invalid evidence values."); return values.Distinct(StringComparer.Ordinal).Order(StringComparer.Ordinal).ToArray(); }
    private static double Number(JsonElement value, double max) { var number = value.GetDouble(); if (!double.IsFinite(number) || number < 0 || number > max) throw new InvalidOperationException("Invalid evidence count."); return number; }
    private static string Hash(string text) => Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(text))).ToLowerInvariant();
    private static void Add(SqliteCommand command, string key, object? value) => command.Parameters.AddWithValue(key, value ?? DBNull.Value);
    public void Dispose() => connection.Dispose();
}
