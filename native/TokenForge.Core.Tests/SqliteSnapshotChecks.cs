using Microsoft.Data.Sqlite;
using System.Security.Cryptography;
using System.Text.Json;
using TokenForge.Core;
using TokenForge.Core.V0220;

internal static class SqliteSnapshotChecks
{
    public static void Run(Action<bool> check, Action<Action> reject)
    {
        if (!OperatingSystem.IsLinux()) return;
        string root = Path.Combine(Path.GetTempPath(), "TokenForge-snapshot-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        void Sql(string path, string sql) { using var db = new SqliteConnection("Data Source=" + path + ";Pooling=False"); db.Open(); using var cmd = db.CreateCommand(); cmd.CommandText = sql; cmd.ExecuteNonQuery(); }
        try
        {
            string source = Path.Combine(root, "scopes.sqlite"), snapshot = Path.Combine(root, "snapshot.sqlite");
            using var store = new EvidenceStore(source);
            string plan = store.Plan(new[] { "11111111-1111-1111-1111-111111111111" }, 1);
            // Keep a WAL connection open, so a byte-copy of just the main file loses committed data.
            using var writer = new SqliteConnection("Data Source=" + source + ";Pooling=False"); writer.Open();
            using (var command = writer.CreateCommand()) { command.CommandText = "PRAGMA journal_mode=WAL; PRAGMA wal_autocheckpoint=0;"; command.ExecuteNonQuery(); }
            store.Complete(plan, "11111111-1111-1111-1111-111111111111", "Failed");
            check(File.Exists(source + "-wal") && new FileInfo(source + "-wal").Length > 0);
            string original; using (var db = new EvidenceStore(source, readOnly:true)) original = db.Pending(plan);
            var result = SqliteSnapshot.Save(source, snapshot, "scopes");
            check(result.Domain == "scopes" && result.StoreVersion == 1 && !result.CrossStoreAtomic && !result.FreshAuthenticationPerformed);
            check(result.Sha256 == Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(snapshot))).ToLowerInvariant());
            check(((int)File.GetUnixFileMode(snapshot) & 511) == 384);
            using (var restored = new EvidenceStore(snapshot, readOnly:true)) check(restored.Pending(plan) == original && JsonDocument.Parse(original).RootElement.GetArrayLength() == 0);
            string restoredPath = Path.Combine(root, "restored.sqlite"); SqliteSnapshot.Save(snapshot, restoredPath, "scopes");
            using (var restored = new EvidenceStore(restoredPath, readOnly:true)) check(restored.Pending(plan) == original);
            byte[] saved = File.ReadAllBytes(snapshot); reject(() => SqliteSnapshot.Save(source, snapshot, "scopes")); check(saved.SequenceEqual(File.ReadAllBytes(snapshot)));
            reject(() => SqliteSnapshot.Save(source, source, "scopes"));
            reject(() => SqliteSnapshot.Save(source, Path.Combine(root,"wrong.sqlite"), "flows"));
            using var cancel = new CancellationTokenSource(); cancel.Cancel(); reject(() => SqliteSnapshot.Save(source, Path.Combine(root,"cancel.sqlite"), "scopes", cancel.Token));
            check(!File.Exists(Path.Combine(root,"cancel.sqlite")));
            foreach (string suffix in new[]{"-wal","-shm","-journal"})
            {
                string target=Path.Combine(root,"sidecar.sqlite"); File.WriteAllText(target+suffix,"synthetic-stale");
                reject(()=>SqliteSnapshot.Save(source,target,"scopes")); check(!File.Exists(target)); File.Delete(target+suffix);
                File.CreateSymbolicLink(target+suffix,Path.Combine(root,"missing-target"));
                reject(()=>SqliteSnapshot.Save(source,target,"scopes")); check(!File.Exists(target)); File.Delete(target+suffix);
            }
            string cleanSource=Path.Combine(root,"source-links.sqlite"); using(var clean=new EvidenceStore(cleanSource)){}
            foreach(string suffix in new[]{"-wal","-shm","-journal"}){
                File.CreateSymbolicLink(cleanSource+suffix,Path.Combine(root,"missing-source-companion"));
                reject(()=>SqliteSnapshot.Save(cleanSource,Path.Combine(root,"source-link-copy.sqlite"),"scopes"));File.Delete(cleanSource+suffix);
            }
            string link = Path.Combine(root,"link.sqlite"); File.CreateSymbolicLink(link,snapshot); reject(() => SqliteSnapshot.Save(link,Path.Combine(root,"badlink.sqlite"),"scopes"));
            File.SetUnixFileMode(snapshot, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.GroupRead);
            reject(() => SqliteSnapshot.Save(snapshot,Path.Combine(root,"broad.sqlite"),"scopes")); File.SetUnixFileMode(snapshot,UnixFileMode.UserRead|UnixFileMode.UserWrite);
            string corrupt = PrivateFiles.Resolve(Path.Combine(root,"corrupt.sqlite"),true); using(var f=PrivateFiles.Open(corrupt,true)){f.Write(new byte[]{1,2,3});}
            reject(() => SqliteSnapshot.Save(corrupt,Path.Combine(root,"bad.sqlite"),"scopes"));
            string flow = Path.Combine(root,"flows.sqlite"); using(var f=new FlowEvidenceStore(flow)){}
            var flowResult=SqliteSnapshot.Save(flow,Path.Combine(root,"flows-copy.sqlite"),"flows"); check(flowResult.ApplicationId==0x54464746);
            Sql(flow,"DROP TABLE flow_attempts; CREATE TABLE flow_attempts(sequence INTEGER PRIMARY KEY AUTOINCREMENT,id TEXT NOT NULL UNIQUE,slot TEXT NOT NULL,plan TEXT NOT NULL,observed TEXT NOT NULL,outcome TEXT NOT NULL,payload TEXT NOT NULL); INSERT INTO flow_attempts(id,slot,plan,observed,outcome,payload) VALUES('id','slot','missing','2026-01-01T00:00:00Z','Failed','{}');");
            reject(()=>SqliteSnapshot.Save(flow,Path.Combine(root,"orphan.sqlite"),"flows"));
            string app=Path.Combine(root,"applications.sqlite"); using(var a=new ApplicationCatalogStore(app)){}
            Sql(app,"PRAGMA user_version=1;");
            var appResult=SqliteSnapshot.Save(app,Path.Combine(root,"apps-copy.sqlite"),"applications"); check(appResult.StoreVersion==1);
            using(var db=new SqliteConnection("Data Source="+app+";Pooling=False")){db.Open();using var cmd=db.CreateCommand();cmd.CommandText="PRAGMA user_version";check(Convert.ToInt32(cmd.ExecuteScalar())==1);}
            foreach (string objectSql in new[] {
                "CREATE TRIGGER sqlitex_bad AFTER INSERT ON catalog_apps BEGIN DELETE FROM catalog_apps; END;",
                "CREATE VIEW sqlitex_bad AS SELECT * FROM catalog_apps;", "CREATE TABLE sqlitex_bad(secret TEXT);" })
            {
                Sql(app,objectSql); reject(()=>SqliteSnapshot.Save(app,Path.Combine(root,"prefix.sqlite"),"applications"));
                Sql(app,"DROP " + (objectSql.Contains("TRIGGER") ? "TRIGGER" : objectSql.Contains("VIEW") ? "VIEW" : "TABLE") + " sqlitex_bad;");
            }
            Sql(app,"DROP TABLE catalog_info; CREATE TABLE catalog_info(id INTEGER PRIMARY KEY,created TEXT NOT NULL,updated TEXT NOT NULL); INSERT INTO catalog_info VALUES(2,'2026-01-01T00:00:00.0000000+00:00','2026-01-01T00:00:00.0000000+00:00');");
            reject(()=>SqliteSnapshot.Save(app,Path.Combine(root,"aux.sqlite"),"applications"));Sql(app,"DELETE FROM catalog_info;");
            Sql(app,"CREATE TRIGGER bad AFTER INSERT ON catalog_apps BEGIN DELETE FROM catalog_apps; END;");
            reject(()=>SqliteSnapshot.Save(app,Path.Combine(root,"trigger.sqlite"),"applications"));
            Sql(app,"DROP TRIGGER bad; ALTER TABLE catalog_apps ADD COLUMN extra TEXT;");
            reject(()=>SqliteSnapshot.Save(app,Path.Combine(root,"extra.sqlite"),"applications"));
            string observation=JsonSerializer.Serialize(new{SchemaVersion=1,Observations=new[]{new{ClientId="11111111-1111-1111-1111-111111111111",ResourceId="00000003-0000-0000-c000-000000000000",Outcome="Failed",TenantFingerprint=new string('a',64),PrincipalFingerprint=new string('b',64),ObservedAt=DateTimeOffset.UtcNow.ToString("o")}},RegistrationAttempts=Array.Empty<object>()});
            store.Import(observation,"synthetic-source");
            Sql(source,"UPDATE sources SET source='"+new string('x',4097)+"';");reject(()=>SqliteSnapshot.Save(source,Path.Combine(root,"source-fields.sqlite"),"scopes"));
            Sql(source,"UPDATE sources SET source='synthetic',imported='bad-date';");reject(()=>SqliteSnapshot.Save(source,Path.Combine(root,"source-time.sqlite"),"scopes"));
            Sql(source,"DELETE FROM sources;");
            Sql(source,"UPDATE plans SET payload='[]';"); reject(()=>SqliteSnapshot.Save(source,Path.Combine(root,"plan-corrupt.sqlite"),"scopes"));
            check(!File.Exists(Path.Combine(root,"plan-corrupt.sqlite")) && !Directory.EnumerateFiles(root,"*.tmp*").Any());
        }
        finally { Directory.Delete(root,true); }
    }
}
