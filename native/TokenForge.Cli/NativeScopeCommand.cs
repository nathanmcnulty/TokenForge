using System.Text;
using System.Text.Json;
using TokenForge.Core;
using TokenForge.Core.V0220;

internal static class NativeScopeCommand
{
    internal static int Run(string[] args)
    {
        var options=new Dictionary<string,string>(StringComparer.Ordinal);
        var seen=new HashSet<string>(StringComparer.Ordinal);
        var allowed=new HashSet<string>(new[]{"--profile","--root","--resource","--scope"},StringComparer.Ordinal);
        for(int i=2;i<args.Length;i++)
        {
            string option=args[i];if(!seen.Add(option))throw new InvalidOperationException();
            if(option=="--json")continue;
            if(!allowed.Contains(option) || ++i==args.Length || args[i].StartsWith('-') || args[i].Length is <1 or >4096)throw new InvalidOperationException();
            options[option]=args[i];
        }
        if(!options.TryGetValue("--scope",out var scope))throw new InvalidOperationException();
        string resource=options.GetValueOrDefault("--resource") ?? "graph";
        resource=resource switch{"graph"=>"00000003-0000-0000-c000-000000000000","arm"=>"797f4846-ba00-4fd7-ba43-dac1f8f63013",_=>throw new InvalidOperationException()};
        using var configuration=JsonDocument.Parse(ProfileStore.Read(options.GetValueOrDefault("--profile") ?? "default",options.GetValueOrDefault("--root")));
        var profile=configuration.RootElement;
        string principal=profile.GetProperty("ExpectedPrincipalFingerprint").GetString() ?? throw new InvalidOperationException();
        string tenant=profile.GetProperty("ExpectedTenantFingerprint").GetString() ?? throw new InvalidOperationException();
        string state=profile.GetProperty("StatePath").GetString()!;
        string inventoryJson=ReadJson(Path.Combine(state,"inventory.json"));
        using(var inventory=JsonDocument.Parse(inventoryJson))if(inventory.RootElement.GetProperty("TenantFingerprint").GetString()!=tenant)throw new InvalidOperationException();
        string sqlite=Path.Combine(state,"scopes.sqlite"),json=Path.Combine(state,"scopes.json");
        string databaseJson;
        if(File.Exists(sqlite))
        {
            using var store=new EvidenceStore(sqlite,readOnly:true);
            databaseJson=store.Export(latest:false,tenant:tenant,principal:principal,resource:resource);
        }
        else databaseJson=ReadJson(json);
        Console.WriteLine(ScopePlanning.Candidates(inventoryJson,databaseJson,resource,scope.Split(','),principal,profile.GetProperty("MaxAgeHours").GetInt32()));
        return 0;
    }
    internal static string ReadJson(string path)
    {
        path=PrivateFiles.Resolve(path,false);
        using var file=new FileStream(path,FileMode.Open,FileAccess.Read,FileShare.Read);
        if(file.Length>64*1024*1024)throw new InvalidOperationException();
        var bytes=new byte[checked((int)file.Length)];file.ReadExactly(bytes);
        if(file.ReadByte()!=-1)throw new InvalidOperationException();
        int skip=bytes.Length>=3 && bytes[0]==0xef && bytes[1]==0xbb && bytes[2]==0xbf?3:0;
        return new UTF8Encoding(false,true).GetString(bytes,skip,bytes.Length-skip);
    }
}
