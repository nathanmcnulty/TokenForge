using System.Text.Json.Nodes;
using TokenForge.Core;

static class ScopePlanningChecks
{
 public static void Run(Action<bool> check,Action<Action> reject)
 {
  const string resource="00000003-0000-0000-c000-000000000000",client="11111111-1111-1111-1111-111111111111",other="22222222-2222-2222-2222-222222222222";
  string tenant=new('a',64),principal=new('b',64);var now=new DateTimeOffset(2026,10,11,12,0,0,TimeSpan.Zero);
  JsonObject App(string id)=>new(){["AppId"]=id,["Name"]="Synthetic",["Registration"]="Present",["Ownership"]="VerifiedMicrosoftOwner",["AccountEnabled"]=true,["RedirectUris"]=new JsonArray("http://localhost/","http://localhost/?private=synthetic"),["PublishedGrants"]=new JsonArray(new JsonObject{["ResourceId"]=resource,["Scopes"]=new JsonArray("User.Read")})};
  JsonObject Observation()=>new(){["ClientId"]=client,["ResourceId"]=resource,["TenantFingerprint"]=tenant,["PrincipalFingerprint"]=principal,["ObservedAt"]=now.AddMinutes(-1).ToString("o"),["Outcome"]="Succeeded",["NamespaceVerification"]="Matched",["RequestVerification"]="Matched",["ScpScopes"]=new JsonArray("User.Read","Mail.Read","openid"),["RequestedScopes"]=new JsonArray(".default"),["Protocol"]="OAuth2V2Pkce"};
  JsonObject Inventory()=>new(){["TenantFingerprint"]=tenant,["CapturedAt"]=now.ToString("o"),["GrantEnumeration"]="Complete",["Applications"]=new JsonArray(App(other),App(client),App(resource)),["TenantGrants"]=new JsonArray()};
  JsonObject Database()=>new(){["SchemaVersion"]=1,["Observations"]=new JsonArray(Observation())};
  JsonArray Coverage(JsonObject db)=>JsonNode.Parse(ScopePlanning.Coverage(db.ToJsonString(),resource,new[]{"User.Read"},tenant,principal,24,now))!.AsArray();
  JsonArray Candidates(JsonObject inventory,JsonObject db)=>JsonNode.Parse(ScopePlanning.Candidates(inventory.ToJsonString(),db.ToJsonString(),resource,new[]{"User.Read"},principal,24,now))!.AsArray();
  var inventory=Inventory();var db=Database();var row=Coverage(db)[0]!;
  var utcPlan=Candidates(inventory,db).ToJsonString();inventory["CapturedAt"]="2026-10-11T04:00:00-08:00";
  check(Candidates(inventory,db).ToJsonString()==utcPlan);
  check(row["CoversAll"]!.GetValue<bool>() && row["AdditionalScopeCount"]!.GetValue<int>()==1);
  check(row["ObservedApiScopeCount"]!.GetValue<int>()==2 && row["AdditionalScopes"]!.AsArray()[0]!.GetValue<string>()=="Mail.Read");
  row=Candidates(inventory,db)[0]!;check(row["ClientId"]!.GetValue<string>()==client && row["CandidateRank"]!.GetValue<int>()==0);
  check(row["BrowserCallbackAvailable"]!.GetValue<bool>() && row["RequestedScopes"]!.AsArray()[0]!.GetValue<string>()==".default");
  var failure=Observation();failure["Outcome"]="Failed";db["Observations"]!.AsArray().Add(failure);
  check(Coverage(db).Count==0);check(Candidates(inventory,db).Single(x=>x!["ClientId"]!.GetValue<string>()==client)!["ObservationStatus"]!.GetValue<string>()=="LatestAttemptUnsuccessful");
  db=Database();db["Observations"]![0]!["ObservedAt"]="2026-10-11T03:59:00-08:00";check(Coverage(db).Count==1);
  failure=Observation();failure["ObservedAt"]="2026-10-11T20:00:00+08:00";failure["Outcome"]="Failed";db["Observations"]!.AsArray().Add(failure);check(Coverage(db).Count==0);
  foreach(string field in new[]{"TenantFingerprint","PrincipalFingerprint"}){db=Database();db["Observations"]![0]![field]=new string('c',64);check(Coverage(db).Count==0);}
  foreach(string field in new[]{"NamespaceVerification","RequestVerification"}){db=Database();db["Observations"]![0]![field]="Unverifiable";check(Coverage(db).Count==0);}
  foreach(var date in new[]{now.AddHours(-25),now.AddMinutes(6)}){db=Database();db["Observations"]![0]!["ObservedAt"]=date.ToString("o");check(Coverage(db).Count==0);}
  db=Database();db["Observations"]![0]!["ScpScopes"]=new JsonArray("user.read");check(!Coverage(db)[0]!["CoversAll"]!.GetValue<bool>());
  inventory=Inventory();db=Database();inventory["TenantGrants"]!.AsArray().Add(new JsonObject{["ClientId"]=other,["ResourceId"]=resource,["ConsentType"]="Principal",["PrincipalFingerprint"]=principal,["Scopes"]=new JsonArray("User.Read")});
  var rows=Candidates(inventory,db);check(rows[0]!["CandidateRank"]!.GetValue<int>()==0 && rows[1]!["CandidateRank"]!.GetValue<int>()==1);
  inventory["TenantGrants"]![0]!["PrincipalFingerprint"]=new string('c',64);inventory["TenantGrants"]![0]!["AppliesToCurrentPrincipal"]=true;
  check(Candidates(inventory,db).Single(x=>x!["ClientId"]!.GetValue<string>()==other)!["CandidateRank"]!.GetValue<int>()==2);
  inventory["TenantGrants"]![0]!["ConsentType"]="AllPrincipals";check(Candidates(inventory,db).Single(x=>x!["ClientId"]!.GetValue<string>()==other)!["CandidateRank"]!.GetValue<int>()==1);
  foreach(string enumeration in new[]{"Forbidden","Failed","Skipped","Unknown"}){inventory=Inventory();inventory["GrantEnumeration"]=enumeration;db=Database();db["Observations"]=new JsonArray();row=Candidates(inventory,db)[0]!;check(row["ConfiguredGrantStatus"]!.GetValue<string>()=="Unknown" && row["ConfiguredGrantMissingScopes"]==null);}
  inventory=Inventory();db=Database();inventory["Applications"]![2]!["AccountEnabled"]=false;check(Candidates(inventory,db).All(x=>x!["CandidateRank"]!.GetValue<int>()==3));
  inventory=Inventory();inventory["CapturedAt"]=now.AddDays(-2).ToString("o");check(Candidates(inventory,db).All(x=>x!["CandidateRank"]!.GetValue<int>()==3));
  inventory=Inventory();inventory["Applications"]!.AsArray().Add(App(client.ToUpperInvariant()));reject(()=>Candidates(inventory,db));
  inventory=Inventory();inventory.Remove("Applications");reject(()=>Candidates(inventory,db));
  inventory=Inventory();inventory["SchemaVersion"]=99;reject(()=>Candidates(inventory,db));
  inventory=Inventory();inventory["Applications"]!.AsArray().Add(App(Guid.Empty.ToString()));
  row=Candidates(inventory,db).Single(x=>x!["ClientId"]!.GetValue<string>()==Guid.Empty.ToString())!;
  check(row["CandidateRank"]!.GetValue<int>()==3 && !row["ClientEligible"]!.GetValue<bool>());
  db=Database();db["Observations"]![0]!["ClientId"]=Guid.Empty.ToString();db["Observations"]![0]!["Outcome"]="MissingRegistration";check(Coverage(db).Count==0);
  db["Observations"]![0]!["Outcome"]="Succeeded";check(Coverage(db).Count==0);
  reject(()=>ScopePlanning.Coverage(db.ToJsonString(),Guid.Empty.ToString(),new[]{"User.Read"},tenant,principal));
  reject(()=>ScopePlanning.Coverage("{\"SchemaVersion\":1,\"Observations\":[],\"observations\":[]}",resource,new[]{"User.Read"},tenant,principal));
  reject(()=>ScopePlanning.Coverage("{\"SchemaVersion\":1}",resource,new[]{"User.Read"},tenant,principal));
  reject(()=>ScopePlanning.Coverage(Database().ToJsonString(),resource,new[]{".default"},tenant,principal));
  reject(()=>ScopePlanning.Coverage(Database().ToJsonString(),resource,new[]{"offline_access"},tenant,principal));
  reject(()=>ScopePlanning.Coverage(Database().ToJsonString(),resource,new[]{"User.Read\n"},tenant,principal));
  inventory=Inventory();db=Database();inventory["Applications"]![0]!["Cookie"]="synthetic-private-secret";db["Observations"]![0]!["AccessToken"]="synthetic-private-secret";
  string output=Candidates(inventory,db).ToJsonString();check(!output.Contains("synthetic-private-secret") && !output.Contains("Fingerprint"));
  JsonArray Requests(JsonObject inv,JsonObject database,bool warm=true,bool browser=false,int clients=1,int redirects=2,bool offline=true)=>
   JsonNode.Parse(ScopePlanning.BuildRequests(inv.ToJsonString(),database.ToJsonString(),resource,new[]{"User.Read"},principal,"example.test",warm,browser,offline,clients,redirects,24,now))!.AsArray();
  const string native="https://login.microsoftonline.com/common/oauth2/nativeclient",callback="https://example.test/callback";
  inventory=Inventory();db=Database();inventory["Applications"]![1]!["RedirectUris"]=new JsonArray("urn:ietf:wg:oauth:2.0:oob",native,callback,"http://localhost/path","http://localhost:8080/","http://localhost:9090/","https://evil.test/?private=secret","https://user@evil.test/");
  db["Observations"]![0]!["RedirectFingerprint"]=Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(callback))).ToLowerInvariant();
  db["Observations"]![0]!["Spa"]=true;db["Observations"]![0]!["Protocol"]="OAuth2V1Implicit";
  var requests=Requests(inventory,db);row=requests[0]!;
  check(row["RedirectUri"]!.GetValue<string>()==callback && row["Spa"]!.GetValue<bool>());
  check(row["Protocol"]!.GetValue<string>()=="OAuth2V2Pkce" && row["ResourceUri"]!.GetValue<string>()==resource);
  check(row["OAuthScopes"]!.AsArray().Select(x=>x!.GetValue<string>()).SequenceEqual(new[]{resource+"/User.Read","offline_access"}));
  check(requests.Count==2 && row["Source"]!.GetValue<string>()=="VerifiedPrivateScopeObservation");
  requests=Requests(inventory,db,redirects:8);check(requests.Count==6 && requests.Any(x=>x!["RedirectUri"]!.GetValue<string>().StartsWith("urn:")));
  check(requests.Where(x=>!x!["RedirectUri"]!.GetValue<string>().StartsWith("https:")).All(x=>!x!["Spa"]!.GetValue<bool>()));
  requests=Requests(inventory,db,browser:true,redirects:8);check(requests.Count==2 && requests.All(x=>!x!["Spa"]!.GetValue<bool>()));
  requests=Requests(inventory,db,warm:false,redirects:8);check(requests.Count==1 && requests[0]!["RedirectUri"]!.GetValue<string>()==native && !requests[0]!["Spa"]!.GetValue<bool>());
  check(requests[0]!["ObservedAt"]==null && requests[0]!["Source"]!.GetValue<string>()=="PublishedOrConfiguredHintNotProvenConsent");
  requests=Requests(inventory,db,warm:false,browser:true,redirects:1);check(requests.Count==1 && requests[0]!["RedirectUri"]!.GetValue<string>()=="http://localhost:8080/");
  requests=Requests(inventory,db,offline:false);check(!requests[0]!["OAuthScopes"]!.AsArray().Any(x=>x!.GetValue<string>()=="offline_access"));
  inventory["Applications"]![1]!["RedirectUris"]=new JsonArray("https://login.microsoftonline.com:443/common/oauth2/nativeclient","https://login.microsoftonline.com/common/oauth2/nativeclient/");
  check(Requests(inventory,db,warm:false).Count==0);
  inventory=Inventory();db=Database();var better=Observation();better["ClientId"]=other;better["ScpScopes"]=new JsonArray("User.Read");db["Observations"]!.AsArray().Add(better);
  inventory["Applications"]![0]!["RedirectUris"]=new JsonArray("https://evil.test/?query=not-eligible");
  check(Requests(inventory,db)[0]!["ClientId"]!.GetValue<string>()==client);
  inventory["Applications"]![0]!["RedirectUris"]=new JsonArray(native);inventory["Applications"]![1]!["RedirectUris"]=new JsonArray(native);
  check(Requests(inventory,db)[0]!["ClientId"]!.GetValue<string>()==other); // Coverage extras, not client ID, determine warm order.
  requests=Requests(inventory,db,clients:2);check(requests.Count==2 && requests.Select(x=>x!["ClientId"]!.GetValue<string>()).Distinct().Count()==2);
  inventory["Applications"]![0]!["AccountEnabled"]=false;check(Requests(inventory,db)[0]!["ClientId"]!.GetValue<string>()==client);
  var newer=Observation();newer["Outcome"]="Failed";db["Observations"]!.AsArray().Add(newer);check(Requests(inventory,db).Count==0);
  inventory=Inventory();db=Database();inventory["CapturedAt"]=now.AddDays(-2).ToString("o");reject(()=>Requests(inventory,db));
  inventory=Inventory();inventory["Applications"]![2]!["AccountEnabled"]=false;reject(()=>Requests(inventory,db));
  inventory=Inventory();reject(()=>ScopePlanning.BuildRequests(inventory.ToJsonString(),db.ToJsonString(),resource,new[]{"User.Read"},principal,"example.test\n",true,now:now));
  reject(()=>Requests(inventory,db,clients:0));reject(()=>Requests(inventory,db,redirects:9));
  db["Observations"]![0]!["ScpScopes"]=new JsonArray("User.Read","user.read");
  requests=JsonNode.Parse(ScopePlanning.BuildRequests(inventory.ToJsonString(),db.ToJsonString(),resource,new[]{"user.read","User.Read","User.Read"},principal,"example.test",true,now:now))!.AsArray();
  check(requests[0]!["Scopes"]!.AsArray().Select(x=>x!.GetValue<string>()).SequenceEqual(new[]{"User.Read","user.read"}));

 }
}
