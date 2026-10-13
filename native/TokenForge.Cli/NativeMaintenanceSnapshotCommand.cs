using System.Text.Json;
using TokenForge.Core;

internal static class NativeMaintenanceSnapshotCommand
{
    internal static int Run(string[] args)
    {
        var options = new Dictionary<string,string>(StringComparer.Ordinal);
        var seen = new HashSet<string>(StringComparer.Ordinal);
        for (int i = 2; i < args.Length; i++)
        {
            string option = args[i];
            if (!seen.Add(option)) throw new InvalidOperationException();
            if (option == "--json") continue;
            if (option is not ("--snapshot-path" or "--key-file" or "--tenant-fingerprint" or "--principal-fingerprint" or "--output-path") ||
                ++i == args.Length || args[i].StartsWith('-') || args[i].Length is < 1 or > 4096) throw new InvalidOperationException();
            options[option] = args[i];
        }
        foreach (string name in new[] { "--snapshot-path", "--key-file", "--tenant-fingerprint", "--principal-fingerprint" })
            if (!options.ContainsKey(name)) throw new InvalidOperationException();
        bool restore = args[1] == "restore-backup";
        if (restore != options.ContainsKey("--output-path")) throw new InvalidOperationException();
        using var cancelled = new CancellationTokenSource();
        ConsoleCancelEventHandler handler = (_, e) => { e.Cancel = true; cancelled.Cancel(); };
        Console.CancelKeyPress += handler;
        try
        {
            var result = restore
                ? MaintenanceSnapshot.Restore(options["--snapshot-path"], options["--key-file"], options["--tenant-fingerprint"], options["--principal-fingerprint"], options["--output-path"], cancelled.Token)
                : MaintenanceSnapshot.Inspect(options["--snapshot-path"], options["--key-file"], options["--tenant-fingerprint"], options["--principal-fingerprint"], cancelled.Token);
            Console.WriteLine(JsonSerializer.Serialize(result));
            return 0;
        }
        catch (MaintenanceSnapshotCleanupException failure)
        {
            Console.Error.WriteLine(JsonSerializer.Serialize(new { Code = "OperationFailed", Restored = failure.Restored, CleanupFailed = true }));
            return 1;
        }
        finally { Console.CancelKeyPress -= handler; }
    }
}
