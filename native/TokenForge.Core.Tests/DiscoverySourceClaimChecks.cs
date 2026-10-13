using System.Text.Json;
using System.Text.Json.Nodes;
using TokenForge.Core;

static class DiscoverySourceClaimChecks
{
 public static void Run(Action<bool> check,Action<Action> reject)
 {
  const string app="11111111-1111-1111-1111-111111111111",owner="22222222-2222-2222-2222-222222222222",other="33333333-3333-3333-3333-333333333333";
  string Project(string value)=>DiscoverySourceClaims.Project("Published","https://raw.githubusercontent.com/example/apps/main/apps.json","PublishedHint",value);
  string one=Project($$"""{"Name":"Alpha","OwnerTenantId":"{{owner}}","AccessToken":"private-token","ObservedAt":"private-date","Grants":[{"ResourceId":"{{app}}","Scopes":["user.read","User.Read","User.Read"],"RefreshToken":"private-refresh"}]}""");
  check(!one.Contains("private-") && !one.Contains("AccessToken") && !one.Contains("RefreshToken"));
  using var clean=JsonDocument.Parse(one);check(clean.RootElement.GetProperty("Grants")[0].GetProperty("Scopes").GetArrayLength()==2);
  string two=Project($$"""{"Name":"Beta","OwnerTenantId":"{{other}}"}""");
  string first=DiscoverySourceClaims.Normalize("["+one+","+two+","+one+"]",app),reordered=DiscoverySourceClaims.Normalize("["+two+","+one+"]",app);check(first==reordered);
  check(DiscoverySourceClaims.Normalize("["+one+","+two.Replace("Beta","Gamma")+"]",app)!=first);
  check(Project("{\"Name\":\"Alpha\",\"ObservedAt\":\"first-date\"}")==Project("{\"Name\":\"Alpha\",\"ObservedAt\":\"later-date\"}"));
  using var combined=JsonDocument.Parse(first);check(combined.RootElement.GetProperty("SourceClaims").GetArrayLength()==2);check(combined.RootElement.GetProperty("MetadataConflicts").GetArrayLength()==2);
  DiscoverySourceClaims.Validate(combined.RootElement.GetProperty("SourceClaims").GetRawText(),combined.RootElement.GetProperty("MetadataConflicts").GetRawText(),app);
  reject(()=>DiscoverySourceClaims.Validate(combined.RootElement.GetProperty("SourceClaims").GetRawText(),"[]",app));
  reject(()=>DiscoverySourceClaims.Validate("["+one+","+two+","+one+"]",combined.RootElement.GetProperty("MetadataConflicts").GetRawText(),app));
  string placeholder=Project($$"""{"Name":"{{app}}"}"""),missing=Project("{}");
  using var nonconflict=JsonDocument.Parse(DiscoverySourceClaims.Normalize("["+one+","+placeholder+","+missing+"]",app));check(nonconflict.RootElement.GetProperty("MetadataConflicts").GetArrayLength()==0);
  string guidCase=Project($$"""{"OwnerTenantId":"{ABCDEFAB-CDEF-ABCD-EFAB-CDEFABCDEFAB}"}""");check(guidCase.Contains("abcdefab-cdef-abcd-efab-cdefabcdefab"));
  foreach(string location in new[]{"https://user:password@example.test/source","https://example.test/source?access_token=private","https://example.test/source#private","local?private"})reject(()=>DiscoverySourceClaims.Project("Published",location,"PublishedHint","{}"));
  foreach(string invalid in new[]{"{\"Name\":\"x\",\"Name\":\"y\"}","{\"Name\":{\"AccessToken\":\"private\"}}","{\"PublicClient\":\"true\"}","{\"OwnerTenantId\":\"not-guid\"}","{\"RedirectUris\":[{\"AccessToken\":\"private\"}]}","{\"Foci\":{\"Cookie\":\"private\"}}","{\"Grants\":[{\"ResourceId\":\""+app+"\",\"Scopes\":[\"invalid scope\"]}]}"})reject(()=>Project(invalid));
  var injected=JsonNode.Parse(one)!.AsObject();injected["RefreshToken"]="private";reject(()=>DiscoverySourceClaims.Normalize(new JsonArray(injected).ToJsonString(),app));
  injected=JsonNode.Parse(one)!.AsObject();injected["Grants"]![0]!["AccessToken"]="private";reject(()=>DiscoverySourceClaims.Normalize(new JsonArray(injected).ToJsonString(),app));
  reject(()=>DiscoverySourceClaims.Normalize("["+string.Join(',',Enumerable.Repeat(one,257))+"]",app));
  reject(()=>Project(JsonSerializer.Serialize(new{Name=new string('x',4097)})));
  reject(()=>Project(JsonSerializer.Serialize(new{RedirectUris=Enumerable.Repeat("https://example.test/",1001).ToArray()})));
  reject(()=>DiscoverySourceClaims.Normalize("[]",Guid.Empty.ToString()));
  using(var name=JsonDocument.Parse(Project(JsonSerializer.Serialize(new{Name="Published \u00e2\u0080\u0093 Name"}))))check(name.RootElement.GetProperty("Name").GetString()=="Published \u00e2\u0080\u0093 Name");
  string encodedName=DiscoverySourceClaims.Normalize("["+Project(JsonSerializer.Serialize(new{Name="Published \u00e2\u0080\u0093 Name"}))+","+two+"]",app);
  using(var normalizedName=JsonDocument.Parse(encodedName))check(DiscoverySourceClaims.Normalize(normalizedName.RootElement.GetProperty("SourceClaims").GetRawText(),app)==encodedName);
  reject(()=>Project(JsonSerializer.Serialize(new{Name="bad\u001b[31m"})));
  string grant=JsonSerializer.Serialize(new{ResourceId=app,Scopes=new[]{"User.Read"}});
  string splitGrants=JsonSerializer.Serialize(new{Grants=new[]{new{ResourceId=app,Scopes=Enumerable.Range(0,600).Select(i=>"Scope."+i).ToArray()},new{ResourceId=app,Scopes=Enumerable.Range(600,600).Select(i=>"Scope."+i).ToArray()}}});
  reject(()=>Project(splitGrants));
  reject(()=>DiscoverySourceClaims.Normalize("[{\"SourceName\":\"Published\",\"Location\":\"Local\",\"Evidence\":\"PublishedHint\",\"Grants\":"+JsonNode.Parse(splitGrants)!["Grants"]!.ToJsonString()+"}]",app));
  string expandingUris="["+string.Join(',',Enumerable.Range(0,220).Select(i=>"\"https://example.test/"+new string('\u00e9',3500)+i+"\""))+"]";
  reject(()=>Project("{\"IdentifierUris\":"+expandingUris+"}"));
  reject(()=>DiscoverySourceClaims.Normalize("[{\"SourceName\":\"Published\",\"Location\":\"Local\",\"Evidence\":\"PublishedHint\",\"IdentifierUris\":"+expandingUris+"}]",app));
  check(Project("{\"Grants\":["+string.Join(',',Enumerable.Repeat(grant,1596))+"]}").Length>0);
  reject(()=>Project("{\"Grants\":["+string.Join(',',Enumerable.Repeat(grant,10001))+"]}"));
  reject(()=>DiscoverySourceClaims.Project("\ud800","LocalSource","PublishedHint","{}"));
  reject(()=>Project("{\"RedirectUris\":[\"https://user:password@example.test/callback\"]}"));
  reject(()=>Project("{\"PreferredRedirectUri\":\"https://user:password@example.test/callback\"}"));
  reject(()=>Project("{\"IdentifierUris\":[\"https://user:password@example.test/api\"]}"));
 }
}
