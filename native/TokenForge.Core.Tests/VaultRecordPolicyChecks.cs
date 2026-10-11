using System.Text;
using System.Text.Json.Nodes;
using System.Globalization;
using TokenForge.Core.V0250;

static class VaultRecordPolicyChecks
{
 public static void Run(Action<bool> check, Action<Action> reject)
 {
  var id=new string('c',64);
  JsonObject Fixture() => new() {
   ["SchemaVersion"]=1,["Sessions"]=new JsonObject {
    ["test"]=new JsonObject {
     ["TenantFingerprint"]=new string('a',64),["PrincipalFingerprint"]=new string('b',64),["Revision"]="11111111-1111-1111-1111-111111111111",
     ["CreatedAt"]="2026-10-11T01:00:00Z",["LastConfirmedAt"]="2026-10-11T09:00:00+08:00",["RetainUntil"]="2026-10-11T10:00:00Z",
     ["Cookie"]="synthetic-cookie",["CookieName"]="ESTSAUTH",["Tokens"]=new JsonObject {
      [id]=new JsonObject {
       ["Id"]=id,["ClientId"]="11111111-1111-1111-1111-111111111111",["ResourceId"]="00000003-0000-0000-c000-000000000000",
       ["Tenant"]="example.test",["Audience"]="https://graph.microsoft.com",["Scopes"]=new JsonArray("User.Read"),["IssuedScopes"]=new JsonArray("User.Read","openid"),
       ["AdditionalScopeCount"]=0,["RedirectUri"]="http://localhost/",["Spa"]=false,["OfflineAccess"]=true,["Protocol"]="OAuth2V2Pkce",
       ["AcquiredAt"]="2026-10-11T01:00:00Z",["ExpiresAt"]="2026-10-11T02:00:00Z",["AccessToken"]="synthetic-access",["RefreshToken"]="synthetic-refresh",["ConsentEvidence"]="SyntheticOnly"
      }
     }
    }
   }
  };
  void Validate(JsonObject value)=>VaultRecordPolicy.Validate(Encoding.UTF8.GetBytes(value.ToJsonString()));
  JsonObject Session(JsonObject value)=>(JsonObject)value["Sessions"]!["test"]!;
  JsonObject Token(JsonObject value)=>(JsonObject)Session(value)["Tokens"]![id]!;
  Validate(Fixture());check(true);
  var mixed=Fixture();var session=Session(mixed).DeepClone();((JsonObject)mixed["Sessions"]!).Clear();mixed["Sessions"]!["Test"]=session;Validate(mixed);check(true);
  VaultRecordPolicy.Validate(Encoding.UTF8.GetBytes("{\"SchemaVersion\":1,\"Sessions\":{}}"));check(true);
  var optional=Fixture();Session(optional)["Cookie"]=null;Session(optional)["CookieName"]=null;Token(optional)["ExpiresAt"]=null;Token(optional)["RefreshToken"]=null;Token(optional)["ConsentEvidence"]=null;Validate(optional);check(true);
  var prior=CultureInfo.CurrentCulture;
  try{CultureInfo.CurrentCulture=CultureInfo.GetCultureInfo("fr-FR");var legacy=Fixture();Session(legacy)["CreatedAt"]="17/10/2026 12:34:56";Validate(legacy);check(true);}finally{CultureInfo.CurrentCulture=prior;}
  foreach(var field in new[]{"Cookie","CookieName","Revision","Tokens","RetainUntil"}){var d=Fixture();Session(d).Remove(field);reject(()=>Validate(d));}
  foreach(var field in new[]{"Id","AccessToken","Scopes","RefreshToken","ExpiresAt"}){var d=Fixture();Token(d).Remove(field);reject(()=>Validate(d));}
  foreach(var change in new Action<JsonObject>[] {
   d=>d["Extra"]="synthetic-secret",d=>d["SchemaVersion"]=2,d=>d["Sessions"]=new JsonArray(),
   d=>Session(d)["Extra"]="synthetic-secret",d=>Session(d)["CookieName"]="OtherCookie",d=>Session(d)["CookieName"]=null,
   d=>Session(d)["TenantFingerprint"]="wrong",d=>Session(d)["Revision"]="00000000-0000-0000-0000-000000000000",d=>Session(d)["RetainUntil"]="synthetic-secret",
   d=>Token(d)["Id"]=new string('d',64),d=>Token(d)["ClientId"]="invalid",d=>Token(d)["ResourceId"]="00000000-0000-0000-0000-000000000000",
   d=>Token(d)["Spa"]="false",d=>Token(d)["AdditionalScopeCount"]=-1,d=>Token(d)["Scopes"]="User.Read",d=>Token(d)["IssuedScopes"]=new JsonArray(new JsonObject{["secret"]="synthetic-secret"}),
   d=>Token(d)["Scopes"]=new JsonArray("User.Read Mail.Read"),d=>Token(d)["AccessToken"]="",d=>Token(d)["AccessToken"]="synthetic\0secret",d=>Token(d)["CookieJar"]=new JsonObject()
  }) {var d=Fixture();change(d);reject(()=>Validate(d));}
  foreach(var json in new[]{
   "{\"SchemaVersion\":1,\"SchemaVersion\":1,\"Sessions\":{}}",
   "{\"SchemaVersion\":1,\"schemaVersion\":1,\"Sessions\":{}}",
   Fixture().ToJsonString().Replace("\"CookieName\":", "\"cookiename\":\"ESTSAUTH\",\"CookieName\":"),
   Fixture().ToJsonString().Replace("\"AccessToken\":", "\"AccessToken\":\"synthetic-secret\",\"AccessToken\":"),
   Fixture().ToJsonString().Replace("\"test\":", "\"Test\":{},\"test\":"),
   Fixture().ToJsonString().Replace("\"test\":", "\"../test\":"),
   Fixture().ToJsonString().Replace("\""+id+"\":", "\"wrong-id\":")
  }) reject(()=>VaultRecordPolicy.Validate(Encoding.UTF8.GetBytes(json)));
  reject(()=>VaultRecordPolicy.Validate(null));reject(()=>VaultRecordPolicy.Validate(new byte[8388609]));reject(()=>VaultRecordPolicy.Validate(new byte[]{0xff,0xfe}));
  var huge=Fixture();Token(huge)["AccessToken"]=new string('s',1048577);reject(()=>Validate(huge));
  try{VaultRecordPolicy.Validate(Encoding.UTF8.GetBytes("synthetic-secret"));throw new Exception("Expected rejection.");}
  catch(InvalidOperationException e){check(e.InnerException==null && !e.ToString().Contains("synthetic-secret"));}
 }
}
