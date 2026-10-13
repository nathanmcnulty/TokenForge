using System.Security;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using TokenForge.Core;
using TokenForge.Core.V0220;

internal static class NativeProfileTokenCommand
{
 internal static bool TryRun(string[] args,out int exit)
 {
  exit=0;
  var options=new Dictionary<string,string>(StringComparer.Ordinal);var seen=new HashSet<string>(StringComparer.Ordinal);
  var allowed=new HashSet<string>(new[]{"--profile","--root","--resource","--resource-id","--scope","--api-uri","--max-candidates","--max-redirects","--login-hint","--timeout-seconds","--passkey-file"},StringComparer.Ordinal);
  bool stdin=false,prompt=false,browser=false;
  for(int i=2;i<args.Length;i++)
  {
   string option=args[i];if(!seen.Add(option))throw new InvalidOperationException();
   if(option=="--json")continue;if(option=="--browser"){browser=true;continue;}if(option=="--prompt-passphrase"){prompt=true;continue;}if(option=="--stdin"){stdin=true;continue;}
   if(!allowed.Contains(option) || ++i==args.Length || args[i].StartsWith('-') || args[i].Length is <1 or >4096)throw new InvalidOperationException();options[option]=args[i];
  }
  if(stdin && prompt || options.TryGetValue("--login-hint",out var hint) && (hint.Length>320 || hint.Any(char.IsControl)))throw new InvalidOperationException();
  int timeout=300;if(options.TryGetValue("--timeout-seconds",out var timeoutText) && (!int.TryParse(timeoutText,out timeout) || timeout is <30 or >900))throw new InvalidOperationException();
  if(!options.TryGetValue("--scope",out var scope))throw new InvalidOperationException();
  var scopes=scope.Split(',');
  if(scopes.Length is <1 or >256 || scopes.Any(s=>s is "openid" or "profile" or "email" or "offline_access" or ".default" || !Regex.IsMatch(s,@"\A[A-Za-z0-9_.-]{1,256}\z")))throw new InvalidOperationException();
  string resource;
  if(options.TryGetValue("--resource-id",out var explicitResource))
  {if(options.ContainsKey("--resource") || !Guid.TryParse(explicitResource,out var id) || id==Guid.Empty)throw new InvalidOperationException();resource=id.ToString();}
  else resource=(options.GetValueOrDefault("--resource") ?? "graph") switch{"graph"=>"00000003-0000-0000-c000-000000000000","arm"=>"797f4846-ba00-4fd7-ba43-dac1f8f63013",_=>throw new InvalidOperationException()};
  int Bound(string option,int fallback,int maximum)=>options.TryGetValue(option,out var value)?int.TryParse(value,out var n) && n>=1 && n<=maximum?n:throw new InvalidOperationException():fallback;
  int maxCandidates=Bound("--max-candidates",8,100),maxRedirects=Bound("--max-redirects",2,8);
  Uri? api=null;
  if(options.TryGetValue("--api-uri",out var apiText))
  {
   string host=resource switch{"00000003-0000-0000-c000-000000000000"=>"graph.microsoft.com","797f4846-ba00-4fd7-ba43-dac1f8f63013"=>"management.azure.com",_=>throw new InvalidOperationException()};
   if(!Uri.TryCreate(apiText,UriKind.Absolute,out api) || api.Scheme!="https" || api.Host!=host || api.Port!=443 || api.UserInfo.Length!=0 || api.Fragment.Length!=0)throw new InvalidOperationException("API URI is outside the resource boundary.");
  }
  string name=options.GetValueOrDefault("--profile") ?? "default",root=options.GetValueOrDefault("--root")!;
  string configJson=ProfileStore.Read(name,root);using var configuration=JsonDocument.Parse(configJson);var p=configuration.RootElement;
  string storage=p.GetProperty("Storage").GetString()!;
  bool memoryPasskey=options.ContainsKey("--passkey-file");
  if(memoryPasskey && (storage!="Memory" || stdin || prompt || browser || options.ContainsKey("--login-hint") || options.ContainsKey("--timeout-seconds")))throw new InvalidOperationException();
  if(storage=="Memory"){if(stdin || prompt)throw new InvalidOperationException();if(!memoryPasskey)return false;}
  if(storage=="Passphrase" && !stdin && !prompt)return false;
  if(storage=="OperatingSystem" && (stdin || prompt))throw new InvalidOperationException();
  using SecureString? password=storage=="Passphrase"?NativeTokenCommand.ReadCredential(stdin,12,1024,"Vault passphrase (hidden): "):null;
  using var cancellation=new CancellationTokenSource();ConsoleCancelEventHandler cancel=(_,e)=>{e.Cancel=true;cancellation.Cancel();};
  Console.CancelKeyPress+=cancel;
  try
  {
   ProfileCredentialToken Fresh(ProfileFreshRequest input)
   {
    bool useBrowser=browser || input.Cookie==null || options.ContainsKey("--login-hint") || options.ContainsKey("--timeout-seconds");
    string state=p.GetProperty("StatePath").GetString()!,inventory=NativeScopeCommand.ReadJson(Path.Combine(state,"inventory.json"));
    string sqlite=Path.Combine(state,"scopes.sqlite"),json=Path.Combine(state,"scopes.json"),database;
    bool useSqlite=File.Exists(sqlite),existed=useSqlite || File.Exists(json);
    if(useSqlite){using var store=new EvidenceStore(sqlite,true);database=store.Export(latest:false,tenant:p.GetProperty("ExpectedTenantFingerprint").GetString(),principal:p.GetProperty("ExpectedPrincipalFingerprint").GetString(),resource:resource);}
    else {PrivateFiles.Resolve(json,false);database=existed?NativeScopeCommand.ReadJson(json):"{\"SchemaVersion\":1,\"Observations\":[],\"RegistrationAttempts\":[]}";}
    if(memoryPasskey)
    {
     // Validate account-bound metadata and the bounded plan before touching the private key.
     using var inventoryDocument=JsonDocument.Parse(inventory);
     string tenant=p.GetProperty("ExpectedTenantFingerprint").GetString() ?? throw new InvalidOperationException();
     string principal=p.GetProperty("ExpectedPrincipalFingerprint").GetString() ?? throw new InvalidOperationException();
     if(inventoryDocument.RootElement.GetProperty("TenantFingerprint").GetString()!=tenant)throw new InvalidOperationException();
     string authority=p.GetProperty("Tenant").GetString()!;int hours=p.GetProperty("MaxAgeHours").GetInt32();
     _=ScopePlanning.BootstrapRequest(inventory,authority,p.GetProperty("BootstrapClientId").GetString()!,hours);
     using var coverage=JsonDocument.Parse(ScopePlanning.Coverage(database,resource,input.Scopes,tenant,principal,hours));
     bool warm=coverage.RootElement.EnumerateArray().Any(row=>row.GetProperty("CoversAll").GetBoolean());
     if(ScopePlanning.PlanRequests(inventory,database,resource,input.Scopes,principal,authority,warm,false,true,maxCandidates,maxRedirects,hours).Length==0)throw new InvalidOperationException();
     using var signer=SoftwarePasskey.Open(options["--passkey-file"]);using var session=signer.Authenticate(cancellation.Token);
     return ProfileScopeAcquisition.Acquire(name,configJson,inventory,database,resource,input.Scopes,session.Cookie,session.CookieName,maxCandidates,maxRedirects,
         checkpoint:observation=>Checkpoint(state,useSqlite?sqlite:json,useSqlite,existed,observation,cancellation.Token),cancellation:cancellation.Token,confirmIdentity:true);
    }
    return ProfileScopeAcquisition.Acquire(name,configJson,inventory,database,resource,input.Scopes,useBrowser?null:input.Cookie,input.CookieName,maxCandidates,maxRedirects,
        execute:useBrowser?row=>{using var issued=NativeTokenCommand.AcquireBrowser(row.ToTransport(),options.GetValueOrDefault("--login-hint"),timeout,true,cancellation.Token);return new ProfileCredentialToken(row.ToTransport(),issued.AccessToken,issued.RefreshToken,issued.ExpiresAt,issued.AdditionalScopes.Length);}:null,
        checkpoint:observation=>Checkpoint(state,useSqlite?sqlite:json,useSqlite,existed,observation,cancellation.Token),cancellation:cancellation.Token,browser:useBrowser);
   }
   using var result=memoryPasskey?ProfileTokenLifecycle.AcquireMemory(name,root,resource,scopes,Fresh,cancellation.Token,configJson):
       ProfileTokenLifecycle.Acquire(name,root,resource,scopes,password,Fresh,cancellation:cancellation.Token,expectedProfileJson:configJson);
   var apiCheck=api==null?null:ProfileTokenApi.Check(result.AccessToken,resource,api,cancellation.Token);
   Console.WriteLine(JsonSerializer.Serialize(new{SchemaVersion=1,Profile=name,ClientId=result.Request.ClientId,ResourceId=result.Request.ResourceId,
       RequestedScopes=result.Request.Scopes,IssuedScopes=result.TokenClaims.Scopes,result.ExpiresAt,result.Evidence,ApiCheck=apiCheck,CredentialOutput=false}));return true;
  }
  finally{Console.CancelKeyPress-=cancel;}
 }
 private static void Checkpoint(string state,string path,bool sqlite,bool existed,string observation,CancellationToken cancellation)
 {
  cancellation.ThrowIfCancellationRequested();
  string lockPath=PrivateFiles.Resolve(Path.Combine(state,".writer.lock"),false);FileStream? writer=null;
  try
  {
   if(!File.Exists(lockPath)){try{writer=PrivateFiles.Open(lockPath,true);}catch(IOException){}}
   writer ??=PrivateFiles.Open(PrivateFiles.Resolve(lockPath,false),false);
   cancellation.ThrowIfCancellationRequested();
   if(sqlite)
   {using var row=JsonDocument.Parse(observation);using var store=new EvidenceStore(path,requireExisting:true);store.Import(JsonSerializer.Serialize(new{SchemaVersion=1,Observations=new[]{row.RootElement},RegistrationAttempts=Array.Empty<object>()}),"NativeProfileExplicitAcquisition");return;}
   if(existed && !File.Exists(path))throw new InvalidOperationException();
   string latest=File.Exists(path)?NativeScopeCommand.ReadJson(path):"{\"SchemaVersion\":1,\"Observations\":[],\"RegistrationAttempts\":[]}";
   string merged=EvidenceStore.AppendPortableObservation(latest,observation);
   string temporary=PrivateFiles.Resolve(Path.Combine(state,".scope-"+Guid.NewGuid().ToString("N")+".tmp"),false);
   try
   {
    using(var file=PrivateFiles.Open(temporary,true)){var bytes=Encoding.UTF8.GetBytes(merged);try{file.Write(bytes);file.Flush(true);}finally{Array.Clear(bytes);}}
    cancellation.ThrowIfCancellationRequested();PrivateFiles.Resolve(path,false);PrivateFiles.Resolve(temporary,false);File.Move(temporary,path,true);
   }
   finally{if(File.Exists(temporary))File.Delete(temporary);}
  }
  finally{writer?.Dispose();}
 }
}
