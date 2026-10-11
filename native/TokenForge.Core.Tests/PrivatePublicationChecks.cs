using System.Reflection;
using TokenForge.Core.V0220;

internal static class PrivatePublicationChecks
{
    public static void Run(Action<bool> check, Action<Action> reject)
    {
        // Exercise the shared internal primitive without adding a public test hook.
        var publish = typeof(PrivateFiles).GetMethod("PublishNew", BindingFlags.Static | BindingFlags.NonPublic)!
            .CreateDelegate<Action<string,string>>();
        string root = Path.Combine(Path.GetTempPath(), "TokenForge-publication-" + Guid.NewGuid());
        if (OperatingSystem.IsMacOS() && root.StartsWith("/var/")) root = "/private" + root;
        string Write(string name, byte value)
        {
            string path = PrivateFiles.Resolve(Path.Combine(root, name), true);
            using var file = PrivateFiles.Open(path, true); file.Write(new byte[]{value}); file.Flush(true);
            return path;
        }
        try
        {
            string source = Write("source", 1), target = Write("existing", 2);
            reject(() => publish(source, target));
            check(File.ReadAllBytes(target).SequenceEqual(new byte[]{2}));
            check(File.ReadAllBytes(source).SequenceEqual(new byte[]{1}));
            string directory = Path.Combine(root, "directory"); Directory.CreateDirectory(directory);
            reject(() => publish(source, directory)); check(Directory.Exists(directory));
            if (!OperatingSystem.IsWindows())
            {
                string link = Path.Combine(root, "link"); File.CreateSymbolicLink(link, target);
                reject(() => publish(source, link));
                check(File.ReadAllBytes(target).SequenceEqual(new byte[]{2}));
            }
            for (int round = 0; round < 10; round++)
            {
                string raceTarget = Path.Combine(root, "winner-" + round);
                var sources = Enumerable.Range(0, 8).Select(i => Write($"candidate-{round}-{i}", (byte)i)).ToArray();
                var won = new bool[8]; using var barrier = new Barrier(8);
                var tasks = Enumerable.Range(0, 8).Select(i => Task.Factory.StartNew(() =>
                {
                    if (!barrier.SignalAndWait(TimeSpan.FromSeconds(10))) throw new Exception("Publication fixture barrier timed out.");
                    try { publish(sources[i], raceTarget); won[i] = true; }
                    catch (IOException) { }
                }, CancellationToken.None, TaskCreationOptions.LongRunning, TaskScheduler.Default)).ToArray();
                if (!Task.WaitAll(tasks, 30000)) throw new Exception("Publication fixture timed out.");
                check(won.Count(v => v) == 1);
                int winner = Array.FindIndex(won, v => v);
                check(File.ReadAllBytes(raceTarget).SequenceEqual(new byte[]{(byte)winner}));
                check(PrivateFiles.Resolve(raceTarget, false) == raceTarget);
                foreach (string temporary in sources) File.Delete(temporary);
            }
            // Existing vault transactions must also preserve an uncooperative creator.
            string vault = Path.Combine(root, "vault");
            using var transaction = VaultFileTransaction.Begin(vault, "Create");
            Write("vault", 7);
            reject(() => transaction.Commit(new byte[128]));
            check(File.ReadAllBytes(vault).SequenceEqual(new byte[]{7}));
            check(Directory.GetFiles(root, "*.tmp").Length == 0);
        }
        finally { Directory.Delete(root, true); }
    }
}
