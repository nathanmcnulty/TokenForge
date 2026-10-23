using System.Text.Json;
using TokenForge.Core;

internal static class NativeStorageCommand
{
    internal static int Run(string[] args)
    {
        if (args.Length < 2 || args[1] != "snapshot") throw new InvalidOperationException();
        var options = new Dictionary<string, string>(StringComparer.Ordinal); var seen = new HashSet<string>(StringComparer.Ordinal);
        for (int i = 2; i < args.Length; i++)
        {
            string key = args[i]; if (!seen.Add(key)) throw new InvalidOperationException();
            if (key == "--json") continue;
            if (key is not ("--database" or "--output-path" or "--domain") || ++i >= args.Length || args[i].Length is < 1 or > 4096 || args[i].StartsWith("--", StringComparison.Ordinal)) throw new InvalidOperationException();
            options.Add(key, args[i]);
        }
        foreach (string key in new[] { "--database", "--output-path", "--domain" }) if (!options.ContainsKey(key)) throw new InvalidOperationException();
        using var stop = new CancellationTokenSource();
        ConsoleCancelEventHandler handler = (_, e) => { e.Cancel = true; stop.Cancel(); }; Console.CancelKeyPress += handler;
        try { Console.WriteLine(JsonSerializer.Serialize(SqliteSnapshot.Save(options["--database"], options["--output-path"], options["--domain"], stop.Token))); return 0; }
        catch (SqliteSnapshotCleanupException error) { Console.Error.WriteLine(JsonSerializer.Serialize(new { Code = "OperationFailed", error.SnapshotCreated, CleanupFailed = true })); return 1; }
        finally { Console.CancelKeyPress -= handler; }
    }
}
