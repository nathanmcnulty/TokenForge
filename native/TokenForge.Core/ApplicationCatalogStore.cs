using static TokenForge.Core.ApplicationCatalogPolicy;
using Microsoft.Data.Sqlite;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;

namespace TokenForge.Core;

// Diagnostic application metadata. Credentials and authorization decisions belong elsewhere.
public sealed class ApplicationCatalogStore : IDisposable
{
    private const int MaxBytes = 128 * 1024 * 1024;
    private readonly SqliteConnection connection;
    public ApplicationCatalogStore(string path, bool readOnly = false)
    {
        if(readOnly && !File.Exists(path)) throw Invalid();
        var empty=!File.Exists(path) || new FileInfo(path).Length==0;
        path=PrivatePath.Prepare(path);
        connection=new SqliteConnection(new SqliteConnectionStringBuilder {DataSource=path,Pooling=false,DefaultTimeout=5,Mode=readOnly?SqliteOpenMode.ReadOnly:SqliteOpenMode.ReadWrite}.ToString());
        try {
            connection.Open();using var command=connection.CreateCommand();
            command.CommandText="PRAGMA application_id;";var app=Convert.ToInt32(command.ExecuteScalar());
            command.CommandText="PRAGMA user_version;";var version=Convert.ToInt32(command.ExecuteScalar());
            if(!empty && (app!=0x54464741 || version is not (1 or 2)) || empty && readOnly) throw Invalid();
            command.CommandText="PRAGMA trusted_schema=OFF; PRAGMA foreign_keys=ON;";command.ExecuteNonQuery();
            if(!empty)return;
            using var transaction=connection.BeginTransaction();command.Transaction=transaction;
            command.CommandText="""
                CREATE TABLE catalog_info(id INTEGER PRIMARY KEY CHECK(id=1),created TEXT NOT NULL,updated TEXT NOT NULL);
                CREATE TABLE catalog_apps(id TEXT PRIMARY KEY,first TEXT NOT NULL,last TEXT NOT NULL);
                CREATE TABLE catalog_runs(sequence INTEGER PRIMARY KEY AUTOINCREMENT,id TEXT NOT NULL UNIQUE,kind TEXT NOT NULL,observed TEXT NOT NULL,payload TEXT NOT NULL,request TEXT);
                CREATE TABLE catalog_origins(id TEXT PRIMARY KEY,kind TEXT NOT NULL,observed TEXT NOT NULL,run TEXT NOT NULL REFERENCES catalog_runs(id),payload TEXT NOT NULL);
                CREATE TABLE catalog_records(app TEXT NOT NULL REFERENCES catalog_apps(id),origin TEXT NOT NULL,first TEXT NOT NULL,last TEXT NOT NULL,present INTEGER NOT NULL,hash TEXT NOT NULL,payload TEXT NOT NULL,digest TEXT NOT NULL,PRIMARY KEY(app,origin),FOREIGN KEY(origin) REFERENCES catalog_origins(id) DEFERRABLE INITIALLY DEFERRED);
                CREATE INDEX catalog_origin ON catalog_records(origin,app);
                CREATE TABLE catalog_versions(sequence INTEGER PRIMARY KEY AUTOINCREMENT,app TEXT NOT NULL,origin TEXT NOT NULL,id TEXT NOT NULL,first TEXT NOT NULL,last TEXT NOT NULL,payload TEXT NOT NULL,hash TEXT NOT NULL,UNIQUE(app,origin,id),FOREIGN KEY(app,origin) REFERENCES catalog_records(app,origin));
                CREATE INDEX catalog_history ON catalog_versions(app,origin,first,last,sequence);
                CREATE INDEX catalog_version_payload ON catalog_versions(app,origin,hash);
                PRAGMA application_id=1413891905; PRAGMA user_version=2;
                """;
            command.ExecuteNonQuery();transaction.Commit();command.Transaction=null;
            command.CommandText="PRAGMA journal_mode=WAL;";command.ExecuteNonQuery();
        }catch{connection.Dispose();throw;}
    }
    public object Update(string json)
    {
        using var document=Parse(json);var root=document.RootElement;
        Keys(root,"Format SchemaVersion Run Rows");
        var version=root.GetProperty("SchemaVersion").GetInt32();
        if(Text(root,"Format")!="TokenForgeCatalogUpdate" || version is not (1 or 2)) throw Invalid();
        var run=root.GetProperty("Run");ValidateRun(run);var kind=Text(run,"Kind");var observed=Date(run,"ObservedAt");var now=Date(run,"RecordedAt");var runId=Text(run,"Id");
        var rows=root.GetProperty("Rows");if(rows.ValueKind!=JsonValueKind.Array || rows.GetArrayLength()!=run.GetProperty("ApplicationRecordCount").GetInt32()) throw Invalid();
        using var tx=connection.BeginTransaction(deferred:false);EnsureWritableFormat(tx);
        if(!WriteRun(run,tx,Hash(Canonical(root)))){tx.Commit();return Statistics(kind);}
        Execute("CREATE TEMP TABLE seen_apps(app TEXT NOT NULL,origin TEXT NOT NULL,PRIMARY KEY(app,origin));",tx);
        var origins=new HashSet<string>(StringComparer.Ordinal);
        foreach(var row in rows.EnumerateArray()) {
            Keys(row,"AppId Record HashInput");var id=Text(row,"AppId");GuidValue(id);var record=row.GetProperty("Record");ValidateClaimsVersion(record,id,version);var origin=ValidateRecord(record,id);
            if(Text(record,"Kind")!=kind || record.GetProperty("PreviousVersions").GetArrayLength()!=0 || Date(record,"FirstSeenAt")!=Date(record,"LastSeenAt") || Date(record,"CurrentVersionFirstSeenAt")!=Date(record,"LastSeenAt")) throw Invalid();
            var hashInput=Text(row,"HashInput",MaxBytes);using var hashDoc=Parse(hashInput);Keys(hashDoc.RootElement,"Attributes Sources");
            if(Hash(hashInput)!=Text(record,"ContentSha256") || Canonical(hashDoc.RootElement.GetProperty("Attributes"))!=Canonical(record.GetProperty("Attributes")) || Canonical(hashDoc.RootElement.GetProperty("Sources"))!=Canonical(record.GetProperty("Sources"))) throw Invalid();
            var tenant=NullableText(record,"TenantFingerprint");if(kind is "Inventory" or "SignIns" && tenant!=NullableText(run,"TenantFingerprint")) throw Invalid();
            var current=OriginObserved(origin,tx);var present=current==null || StringComparer.Ordinal.Compare(observed,current)>=0;
            MergeRecord(id,origin,record,present,tx,true);origins.Add(origin);
            Execute("INSERT OR IGNORE INTO seen_apps VALUES($app,$origin);",tx,("$app",id),("$origin",origin));
        }
        if(kind is "Discovery" or "Inventory" or "SignIns") {
            var origin=Origin(kind,NullableText(run,"TenantFingerprint"),null,null,null);origins.Add(origin);
            var previous=OriginObserved(origin,tx);
            if(previous==null || StringComparer.Ordinal.Compare(observed,previous)>=0) {
                using var command=Command("SELECT app FROM catalog_records r WHERE origin=$origin AND NOT EXISTS(SELECT 1 FROM seen_apps s WHERE s.app=r.app AND s.origin=r.origin);",tx,("$origin",origin));
                using var reader=command.ExecuteReader();var missing=new List<string>();while(reader.Read())missing.Add(reader.GetString(0));reader.Close();
                foreach(var id in missing){var old=ReadRecord(id,origin,tx)!;old["PresentInLatestRun"]=false;WriteRecord(id,origin,old,tx);}
            }
        }
        foreach(var origin in origins)WriteOrigin(origin,kind,observed,runId,tx);
        UpdateInfo(now,now,tx);Execute("DROP TABLE seen_apps;",tx);tx.Commit();return Statistics(kind);
    }
    // Pure validation retains the import contract, including history and origin
    // relationships, for consumers that must never create or migrate a store.
    public static void ValidateDocument(string json)=>ApplicationCatalogPolicy.ValidateDocument(json);

    public int Import(string json)
    {
        using var document=Parse(json);var root=document.RootElement;
        Keys(root,"Format SchemaVersion CreatedAt UpdatedAt Applications Origins Runs");
        var envelopeVersion=root.GetProperty("SchemaVersion").GetInt32();
        if(Text(root,"Format")!="TokenForgeApplicationMetadata" || envelopeVersion is not (1 or 2)) throw Invalid();
        var created=Date(root,"CreatedAt");var updated=Date(root,"UpdatedAt");if(StringComparer.Ordinal.Compare(created,updated)>0)throw Invalid();
        var applications=root.GetProperty("Applications");var origins=root.GetProperty("Origins");var runs=root.GetProperty("Runs");
        if(applications.ValueKind!=JsonValueKind.Object || origins.ValueKind!=JsonValueKind.Object || runs.ValueKind!=JsonValueKind.Array)throw Invalid();
        using var tx=connection.BeginTransaction(deferred:false);EnsureWritableFormat(tx);var count=0;var runIds=new Dictionary<string,JsonElement>(StringComparer.Ordinal);
        UniqueKeys(applications);UniqueKeys(origins);
        foreach(var run in runs.EnumerateArray()){ValidateRun(run);if(!runIds.TryAdd(Text(run,"Id"),run))throw Invalid();if(WriteRun(run,tx))count++;}
        foreach(var app in applications.EnumerateObject()) {
            GuidValue(app.Name);Keys(app.Value,"AppId FirstSeenAt LastSeenAt Records");if(Text(app.Value,"AppId")!=app.Name)throw Invalid();
            var first=Date(app.Value,"FirstSeenAt");var last=Date(app.Value,"LastSeenAt");if(StringComparer.Ordinal.Compare(first,last)>0)throw Invalid();
            WriteApp(app.Name,first,last,tx);var records=app.Value.GetProperty("Records");if(records.ValueKind!=JsonValueKind.Object)throw Invalid();UniqueKeys(records);
            foreach(var entry in records.EnumerateObject()) {
                ValidateClaimsVersion(entry.Value,app.Name,envelopeVersion);
                if(ValidateRecord(entry.Value,app.Name)!=entry.Name)throw Invalid();
                if(!origins.TryGetProperty(entry.Name,out _))throw Invalid();
                var importedObserved=Date(origins.GetProperty(entry.Name),"LastObservedAt");var currentObserved=OriginObserved(entry.Name,tx);
                var stale=currentObserved!=null && StringComparer.Ordinal.Compare(importedObserved,currentObserved)<0;
                MergeRecord(app.Name,entry.Name,entry.Value,stale?null:entry.Value.GetProperty("PresentInLatestRun").GetBoolean(),tx);
                var occurrences=new Dictionary<string,int>(StringComparer.Ordinal);
                foreach(var version in entry.Value.GetProperty("PreviousVersions").EnumerateArray()){
                    var payloadHash=Hash(Canonical(version));occurrences.TryGetValue(payloadHash,out var occurrence);occurrences[payloadHash]=++occurrence;
                    WriteVersion(app.Name,entry.Name,version,tx,occurrence);
                }
            }
        }
        foreach(var origin in origins.EnumerateObject()) {
            Keys(origin.Value,"Kind LastObservedAt LastRunId");var kind=Text(origin.Value,"Kind");var runId=Text(origin.Value,"LastRunId");var observed=Date(origin.Value,"LastObservedAt");
            if(!runIds.TryGetValue(runId,out var referenced) || Text(referenced,"Kind")!=kind || Date(referenced,"ObservedAt")!=observed || !OriginShape(origin.Name,kind))throw Invalid();
            if(kind is "Inventory" or "SignIns" && NullableText(referenced,"TenantFingerprint")!=origin.Name.Split('/')[1])throw Invalid();
            WriteOrigin(origin.Name,kind,observed,runId,tx);
        }
        UpdateInfo(created,updated,tx);tx.Commit();return count;
    }
    public string Export(string? appId=null,bool currentOnly=false)
    {
        if(appId!=null)GuidValue(appId);
        using var tx=connection.BeginTransaction();var catalogVersion=ReadFormatVersion(tx);long bytes=0;
        void Bound(string text){bytes+=Encoding.UTF8.GetByteCount(text);if(bytes>MaxBytes)throw new InvalidOperationException("Select a smaller catalog export.");}
        var apps=new JsonObject();
        using(var command=Command("SELECT id,first,last FROM catalog_apps WHERE ($app IS NULL OR id=$app) ORDER BY id;",tx,("$app",appId))) {
            using var reader=command.ExecuteReader();while(reader.Read()){
                var id=reader.GetString(0);GuidValue(id);var first=DateText(reader.GetString(1));var last=DateText(reader.GetString(2));
                if(first!=reader.GetString(1) || last!=reader.GetString(2) || StringComparer.Ordinal.Compare(first,last)>0)throw Invalid();
                var app=new JsonObject { ["AppId"]=id,["FirstSeenAt"]=first,["LastSeenAt"]=last,["Records"]=new JsonObject()};Bound(app.ToJsonString());apps[id]=app;
            }
        }
        using(var command=Command("SELECT app,origin,payload,first,last,present,hash,digest FROM catalog_records WHERE ($app IS NULL OR app=$app) ORDER BY app,origin;",tx,("$app",appId))) {
            using var reader=command.ExecuteReader();while(reader.Read()){
                var payload=reader.GetString(2);Bound(payload);using var shape=Parse(payload);ValidateClaimsVersion(shape.RootElement,reader.GetString(0),catalogVersion);var record=ParseRecord(payload,reader.GetString(0),reader.GetString(1));CheckIndex(record,reader,3);
                record["PreviousVersions"]=new JsonArray();((JsonObject)apps[reader.GetString(0)]!["Records"]!)[reader.GetString(1)]=record;
            }
        }
        if(!currentOnly)using(var command=Command("SELECT app,origin,payload,id,first,last,hash FROM catalog_versions WHERE ($app IS NULL OR app=$app) ORDER BY app,origin,first,last,sequence;",tx,("$app",appId))) {
            using var reader=command.ExecuteReader();while(reader.Read()){
                var payload=reader.GetString(2);Bound(payload);using var doc=Parse(payload);var version=doc.RootElement;var record=apps[reader.GetString(0)]!["Records"]![reader.GetString(1)]!;
                using var current=Parse(record.ToJsonString());ValidateVersion(version,record["Kind"]!.GetValue<string>(),reader.GetString(0),current.RootElement);
                DiscoverySourceClaims.ValidateCatalogAttributes(version.GetProperty("Attributes"),reader.GetString(0),record["Kind"]!.GetValue<string>(),catalogVersion);
                HashValue(reader.GetString(3));if(Hash(Canonical(version))!=reader.GetString(6) || Date(version,"FirstSeenAt")!=reader.GetString(4) || Date(version,"LastSeenAt")!=reader.GetString(5))throw Invalid();
                ((JsonArray)record["PreviousVersions"]!).Add(JsonNode.Parse(Canonical(version)));
            }
        }
        var origins=new JsonObject();var runs=new JsonArray();
        using(var command=Command("SELECT id,payload,kind,observed,run FROM catalog_origins WHERE ($app IS NULL OR id IN(SELECT origin FROM catalog_records WHERE app=$app)) ORDER BY id;",tx,("$app",appId))){
            using var reader=command.ExecuteReader();while(reader.Read()){
                var payload=reader.GetString(1);Bound(payload);using var doc=Parse(payload);var value=doc.RootElement;Keys(value,"Kind LastObservedAt LastRunId");
                if(!OriginShape(reader.GetString(0),Text(value,"Kind")) || Text(value,"Kind")!=reader.GetString(2) || Date(value,"LastObservedAt")!=reader.GetString(3) || Text(value,"LastRunId")!=reader.GetString(4))throw Invalid();
                _=OriginObserved(reader.GetString(0),tx);
                origins[reader.GetString(0)]=JsonNode.Parse(Canonical(value));
            }
        }
        using(var command=Command("SELECT id,payload,kind,observed FROM catalog_runs WHERE ($current=0 AND $app IS NULL) OR id IN(SELECT run FROM catalog_origins WHERE $app IS NULL OR id IN(SELECT origin FROM catalog_records WHERE app=$app)) ORDER BY sequence;",tx,("$app",appId),("$current",currentOnly?1:0))){
            using var reader=command.ExecuteReader();while(reader.Read()){
                var payload=reader.GetString(1);Bound(payload);using var doc=Parse(payload);ValidateRun(doc.RootElement);
                if(Text(doc.RootElement,"Id")!=reader.GetString(0) || Text(doc.RootElement,"Kind")!=reader.GetString(2) || Date(doc.RootElement,"ObservedAt")!=reader.GetString(3))throw Invalid();
                runs.Add(JsonNode.Parse(Canonical(doc.RootElement)));
            }
        }
        using var info=Command("SELECT created,updated FROM catalog_info WHERE id=1;",tx);using var infoReader=info.ExecuteReader();
        var now=DateTimeOffset.UtcNow.ToString("o");var created=now;var updated=now;if(infoReader.Read()){created=DateText(infoReader.GetString(0));updated=DateText(infoReader.GetString(1));}infoReader.Close();
        var result=new JsonObject { ["Format"]="TokenForgeApplicationMetadata",["SchemaVersion"]=catalogVersion,["CreatedAt"]=created,["UpdatedAt"]=updated,["Applications"]=apps,["Origins"]=origins,["Runs"]=runs}.ToJsonString();
        if(Encoding.UTF8.GetByteCount(result)>MaxBytes)throw new InvalidOperationException("Select a smaller catalog export.");tx.Commit();return result;
    }
    private void MergeRecord(string app,string origin,JsonElement incoming,bool? present,SqliteTransaction tx,bool newEvent=false)
    {
        var first=Date(incoming,"FirstSeenAt");var last=Date(incoming,"LastSeenAt");WriteApp(app,first,last,tx);
        var old=ReadRecord(app,origin,tx);var next=(JsonObject)JsonNode.Parse(Canonical(incoming))!;next["PreviousVersions"]=new JsonArray();
        if(old==null){next["PresentInLatestRun"]=present??false;WriteRecord(app,origin,next,tx);return;}
        var oldFirst=old["FirstSeenAt"]!.GetValue<string>();var oldLast=old["LastSeenAt"]!.GetValue<string>();
        var oldPresent=old["PresentInLatestRun"]!.GetValue<bool>();var importedPresent=present??oldPresent;
        if(!newEvent)old["PresentInLatestRun"]=importedPresent;
        if(StringComparer.Ordinal.Compare(last,oldLast)>=0){
            if(Text(incoming,"ContentSha256")!=old["ContentSha256"]!.GetValue<string>()){
                var previous=new JsonObject { ["FirstSeenAt"]=old["CurrentVersionFirstSeenAt"]!.DeepClone(),["LastSeenAt"]=old["LastSeenAt"]!.DeepClone(),["Attributes"]=old["Attributes"]!.DeepClone(),["Sources"]=old["Sources"]!.DeepClone(),["ContentSha256"]=old["ContentSha256"]!.DeepClone()};
                using var version=Parse(previous.ToJsonString());WriteVersion(app,origin,version.RootElement,tx,newEvent?0:1);
            }else{
                var oldVersion=old["CurrentVersionFirstSeenAt"]!.GetValue<string>();var newVersion=next["CurrentVersionFirstSeenAt"]!.GetValue<string>();next["CurrentVersionFirstSeenAt"]=StringComparer.Ordinal.Compare(oldVersion,newVersion)<0?oldVersion:newVersion;
            }
            next["FirstSeenAt"]=StringComparer.Ordinal.Compare(oldFirst,first)<0?oldFirst:first;
            next["PresentInLatestRun"]=newEvent?(present==true?true:oldPresent):importedPresent;
            WriteRecord(app,origin,next,tx);
        }else{
            var earlier=StringComparer.Ordinal.Compare(first,oldFirst)<0;if(earlier)old["FirstSeenAt"]=first;
            if(earlier || !newEvent && oldPresent!=importedPresent)WriteRecord(app,origin,old,tx);
        }
    }
    private void EnsureWritableFormat(SqliteTransaction tx)
    {
        if(ReadFormatVersion(tx)!=1)return;
        ValidateLegacyStorage(tx);Execute("PRAGMA user_version=2;",tx);
    }
    private int ReadFormatVersion(SqliteTransaction tx)
    {
        using var command=Command("PRAGMA application_id;",tx);if(Convert.ToInt32(command.ExecuteScalar())!=0x54464741)throw Invalid();
        command.CommandText="PRAGMA user_version;";int version=Convert.ToInt32(command.ExecuteScalar());if(version is not (1 or 2))throw Invalid();return version;
    }
    // Validate every domain and historical row under the same writer transaction as
    // the format marker. Do not assemble an export or impose its whole-document limit.
    private void ValidateLegacyStorage(SqliteTransaction tx)
    {
        using(var command=Command("PRAGMA foreign_key_check;",tx))using(var reader=command.ExecuteReader())if(reader.Read())throw Invalid();
        using(var command=Command("SELECT id,first,last FROM catalog_apps;",tx))using(var reader=command.ExecuteReader())while(reader.Read()){
            GuidValue(reader.GetString(0));var first=DateText(reader.GetString(1));var last=DateText(reader.GetString(2));
            if(first!=reader.GetString(1) || last!=reader.GetString(2) || StringComparer.Ordinal.Compare(first,last)>0)throw Invalid();
        }
        using(var command=Command("SELECT app,origin,payload,first,last,present,hash,digest FROM catalog_records;",tx))using(var reader=command.ExecuteReader())while(reader.Read()){
            string app=reader.GetString(0),payload=reader.GetString(2);using var shape=Parse(payload);ValidateClaimsVersion(shape.RootElement,app,1);
            var record=ParseRecord(payload,app,reader.GetString(1));CheckIndex(record,reader,3);
        }
        using(var command=Command("SELECT v.app,v.payload,v.id,v.first,v.last,v.hash,r.payload FROM catalog_versions v JOIN catalog_records r ON r.app=v.app AND r.origin=v.origin;",tx))using(var reader=command.ExecuteReader())while(reader.Read()){
            using var document=Parse(reader.GetString(1));using var current=Parse(reader.GetString(6));var version=document.RootElement;string app=reader.GetString(0),kind=Text(current.RootElement,"Kind");
            DiscoverySourceClaims.ValidateCatalogAttributes(version.GetProperty("Attributes"),app,kind,1);ValidateVersion(version,kind,app,current.RootElement);
            HashValue(reader.GetString(2));if(Hash(Canonical(version))!=reader.GetString(5) || Date(version,"FirstSeenAt")!=reader.GetString(3) || Date(version,"LastSeenAt")!=reader.GetString(4))throw Invalid();
        }
        using(var command=Command("SELECT id FROM catalog_origins;",tx))using(var reader=command.ExecuteReader())while(reader.Read())if(OriginObserved(reader.GetString(0),tx)==null)throw Invalid();
        using(var command=Command("SELECT id,payload,kind,observed,request FROM catalog_runs;",tx))using(var reader=command.ExecuteReader())while(reader.Read()){
            using var document=Parse(reader.GetString(1));var run=document.RootElement;ValidateRun(run);
            if(Text(run,"Id")!=reader.GetString(0) || Text(run,"Kind")!=reader.GetString(2) || Date(run,"ObservedAt")!=reader.GetString(3))throw Invalid();
            if(!reader.IsDBNull(4))HashValue(reader.GetString(4));
        }
        using(var command=Command("SELECT id,created,updated FROM catalog_info;",tx))using(var reader=command.ExecuteReader())while(reader.Read()){
            var created=DateText(reader.GetString(1));var updated=DateText(reader.GetString(2));
            if(reader.GetInt32(0)!=1 || created!=reader.GetString(1) || updated!=reader.GetString(2) || StringComparer.Ordinal.Compare(created,updated)>0)throw Invalid();
        }
    }
    private void WriteApp(string app,string first,string last,SqliteTransaction tx)=>Execute("INSERT INTO catalog_apps VALUES($app,$first,$last) ON CONFLICT(id) DO UPDATE SET first=MIN(first,excluded.first),last=MAX(last,excluded.last);",tx,("$app",app),("$first",first),("$last",last));
    private void WriteRecord(string app,string origin,JsonObject record,SqliteTransaction tx)
    {
        using var doc=Parse(record.ToJsonString());ValidateRecord(doc.RootElement,app);
        Execute("INSERT INTO catalog_records VALUES($app,$origin,$first,$last,$present,$hash,$payload,$digest) ON CONFLICT(app,origin) DO UPDATE SET first=excluded.first,last=excluded.last,present=excluded.present,hash=excluded.hash,payload=excluded.payload,digest=excluded.digest;",tx,("$app",app),("$origin",origin),("$first",Date(doc.RootElement,"FirstSeenAt")),("$last",Date(doc.RootElement,"LastSeenAt")),("$present",record["PresentInLatestRun"]!.GetValue<bool>()?1:0),("$hash",Text(doc.RootElement,"ContentSha256")),("$payload",Canonical(doc.RootElement)),("$digest",Hash(Canonical(doc.RootElement))));
    }
    private JsonObject? ReadRecord(string app,string origin,SqliteTransaction tx)
    {
        using var command=Command("SELECT payload,first,last,present,hash,digest FROM catalog_records WHERE app=$app AND origin=$origin;",tx,("$app",app),("$origin",origin));using var reader=command.ExecuteReader();
        if(!reader.Read())return null;var record=ParseRecord(reader.GetString(0),app,origin);CheckIndex(record,reader,1);return record;
    }
    private static JsonObject ParseRecord(string payload,string app,string origin){using var doc=Parse(payload);if(ValidateRecord(doc.RootElement,app)!=origin || doc.RootElement.GetProperty("PreviousVersions").GetArrayLength()!=0)throw Invalid();return (JsonObject)JsonNode.Parse(Canonical(doc.RootElement))!;}
    private static void CheckIndex(JsonObject record,SqliteDataReader reader,int index){if(record["FirstSeenAt"]!.GetValue<string>()!=reader.GetString(index) || record["LastSeenAt"]!.GetValue<string>()!=reader.GetString(index+1) || record["PresentInLatestRun"]!.GetValue<bool>()!=(reader.GetInt32(index+2)==1) || reader.GetInt32(index+2) is not (0 or 1) || record["ContentSha256"]!.GetValue<string>()!=reader.GetString(index+3) || Hash(Canonical(JsonSerializer.SerializeToElement(record)))!=reader.GetString(index+4))throw Invalid();}
    private void WriteVersion(string app,string origin,JsonElement version,SqliteTransaction tx,int requiredOccurrence)
    {
        var payload=Canonical(version);var hash=Hash(payload);
        if(requiredOccurrence>0){using var count=Command("SELECT COUNT(*) FROM catalog_versions WHERE app=$app AND origin=$origin AND hash=$hash;",tx,("$app",app),("$origin",origin),("$hash",hash));if(Convert.ToInt64(count.ExecuteScalar())>=requiredOccurrence)return;}
        Execute("INSERT INTO catalog_versions(app,origin,id,first,last,payload,hash) VALUES($app,$origin,$id,$first,$last,$payload,$hash);",tx,("$app",app),("$origin",origin),("$id",Hash(Guid.NewGuid().ToString())),("$first",Date(version,"FirstSeenAt")),("$last",Date(version,"LastSeenAt")),("$payload",payload),("$hash",hash));
    }
    private bool WriteRun(JsonElement run,SqliteTransaction tx,string? request=null)
    {
        var id=Text(run,"Id");var payload=Canonical(run);using var existing=Command("SELECT payload,request,kind,observed FROM catalog_runs WHERE id=$id;",tx,("$id",id));using var reader=existing.ExecuteReader();
        if(reader.Read()){
            using var doc=Parse(reader.GetString(0));ValidateRun(doc.RootElement);
            if(Text(doc.RootElement,"Id")!=id || Text(doc.RootElement,"Kind")!=reader.GetString(2) || Date(doc.RootElement,"ObservedAt")!=reader.GetString(3) || reader.GetString(0)!=payload || request!=null && (reader.IsDBNull(1) || reader.GetString(1)!=request))throw Invalid();
            return false;
        }
        reader.Close();Execute("INSERT INTO catalog_runs(id,kind,observed,payload,request) VALUES($id,$kind,$observed,$payload,$request);",tx,("$id",id),("$kind",Text(run,"Kind")),("$observed",Date(run,"ObservedAt")),("$payload",payload),("$request",request));return true;
    }
    private string? OriginObserved(string origin,SqliteTransaction tx)
    {
        using var command=Command("SELECT o.payload,o.kind,o.observed,o.run,r.payload FROM catalog_origins o JOIN catalog_runs r ON o.run=r.id WHERE o.id=$id;",tx,("$id",origin));using var reader=command.ExecuteReader();
        if(!reader.Read())return null;
        using var doc=Parse(reader.GetString(0));var value=doc.RootElement;Keys(value,"Kind LastObservedAt LastRunId");using var run=Parse(reader.GetString(4));ValidateRun(run.RootElement);
        if(!OriginShape(origin,Text(value,"Kind")) || Text(value,"Kind")!=reader.GetString(1) || Date(value,"LastObservedAt")!=reader.GetString(2) || Text(value,"LastRunId")!=reader.GetString(3) || Text(run.RootElement,"Id")!=reader.GetString(3) || Text(run.RootElement,"Kind")!=Text(value,"Kind") || Date(run.RootElement,"ObservedAt")!=Date(value,"LastObservedAt"))throw Invalid();
        if(Text(value,"Kind") is "Inventory" or "SignIns" && NullableText(run.RootElement,"TenantFingerprint")!=origin.Split('/')[1])throw Invalid();
        return reader.GetString(2);
    }
    private void WriteOrigin(string origin,string kind,string observed,string run,SqliteTransaction tx)
    {
        _=OriginObserved(origin,tx);
        var payload=JsonSerializer.Serialize(new{Kind=kind,LastObservedAt=observed,LastRunId=run});
        Execute("INSERT INTO catalog_origins VALUES($id,$kind,$observed,$run,$payload) ON CONFLICT(id) DO UPDATE SET observed=excluded.observed,run=excluded.run,payload=excluded.payload WHERE excluded.observed>=catalog_origins.observed;",tx,("$id",origin),("$kind",kind),("$observed",observed),("$run",run),("$payload",payload));
    }
    private void UpdateInfo(string created,string updated,SqliteTransaction tx)=>Execute("INSERT INTO catalog_info VALUES(1,$created,$updated) ON CONFLICT(id) DO UPDATE SET created=MIN(created,excluded.created),updated=MAX(updated,excluded.updated);",tx,("$created",created),("$updated",updated));
    private object Statistics(string kind){using var command=connection.CreateCommand();command.CommandText="SELECT (SELECT COUNT(*) FROM catalog_apps),(SELECT COUNT(*) FROM catalog_runs);";using var reader=command.ExecuteReader();reader.Read();return new{Updated=true,ApplicationCount=reader.GetInt64(0),RunCount=reader.GetInt64(1),Kind=kind};}
    private SqliteCommand Command(string sql,SqliteTransaction tx,params (string,object?)[] args){var command=connection.CreateCommand();command.Transaction=tx;command.CommandText=sql;foreach(var (key,value) in args)command.Parameters.AddWithValue(key,value??DBNull.Value);return command;}
    private void Execute(string sql,SqliteTransaction tx,params (string,object?)[] args){using var command=Command(sql,tx,args);command.ExecuteNonQuery();}

    public void Dispose()=>connection.Dispose();
}
