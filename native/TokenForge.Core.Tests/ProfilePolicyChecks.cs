using System.Text.Json;
using TokenForge.Core.V0200;

internal static class ProfilePolicyChecks
{
    public static void Run(Action<bool> check, Action<Action> reject)
    {
        var profile = new Dictionary<string, object?> {
            ["Format"]="TokenForgeProfile",["SchemaVersion"]=1,["Name"]="lab",["Tenant"]="example.onmicrosoft.com",
            ["StatePath"]="/private/evidence",["Storage"]="Passphrase",["BootstrapClientId"]="038ddad9-5bbe-4f64-b0cd-12434d1e633b",
            ["MaxAdditionalScopes"]=0,["MaxBootstrapAdditionalScopes"]=0,["MaxAgeHours"]=24,["SessionRetentionHours"]=8,
            ["PasskeyPath"]="",["XdrModulePath"]="",["ExpectedTenantFingerprint"]=null,["ExpectedPrincipalFingerprint"]=null,
            ["Revision"]="11111111-1111-1111-1111-111111111111",["CreatedAt"]="2026-10-07T12:00:00Z",["UpdatedAt"]="2026-10-07T12:00:00+00:00"
        };
        string Json() => JsonSerializer.Serialize(profile);
        void Valid(){ProfilePolicy.Validate(Json(),"lab");check(true);}
        void Invalid(string key, object? value)
        {
            object? old=profile[key];profile[key]=value;
            reject(()=>ProfilePolicy.Validate(Json(),"lab"));profile[key]=old;
        }
        Valid();profile["Storage"]="Memory";Valid();profile["Storage"]="Passphrase";
        profile["SchemaVersion"]=2;profile["Storage"]="OperatingSystem";profile["KeyId"]="0123456789abcdef0123456789abcdef";Valid();
        foreach(object? key in new object?[]{null,"",new string('0',32),new string('A',32),new string('f',33)}) Invalid("KeyId",key);
        Invalid("Storage","Memory");profile.Remove("KeyId");profile["SchemaVersion"]=1;profile["Storage"]="Passphrase";
        Invalid("Storage","OperatingSystem");Invalid("Storage","passphrase");
        foreach(string field in profile.Keys.ToArray())
        {
            object? old=profile[field];profile.Remove(field);reject(()=>ProfilePolicy.Validate(Json(),"lab"));profile[field]=old;
        }
        profile["Unknown"]="synthetic-secret";reject(()=>ProfilePolicy.Validate(Json(),"lab"));profile.Remove("Unknown");
        foreach(object? value in new object?[]{null,true,"1",0,3,1.5}) Invalid("SchemaVersion",value);
        foreach(string field in new[]{"MaxAdditionalScopes","MaxBootstrapAdditionalScopes","MaxAgeHours","SessionRetentionHours"})
            foreach(object? value in new object?[]{null,true,"1",-1,8761,1.5}) Invalid(field,value);
        Invalid("MaxAgeHours",0);Invalid("SessionRetentionHours",0);Invalid("SessionRetentionHours",169);
        foreach(string tenant in new[]{"common","ORGANIZATIONS","consumers","","../tenant","tenant\n"}) Invalid("Tenant",tenant);
        foreach(string field in new[]{"BootstrapClientId","Revision"}) foreach(object? value in new object?[]{null,1,Guid.Empty.ToString(),"invalid"}) Invalid(field,value);
        foreach(string field in new[]{"StatePath","PasskeyPath","XdrModulePath"}){Invalid(field,null);Invalid(field,new string('x',4097));}
        profile["PasskeyPath"]="/private/passkey";reject(()=>ProfilePolicy.Validate(Json(),"lab"));profile["XdrModulePath"]="/private/module";Valid();
        profile["PasskeyPath"]="";profile["XdrModulePath"]="";
        foreach(string field in new[]{"ExpectedTenantFingerprint","ExpectedPrincipalFingerprint"})
        {
            foreach(object? value in new object?[]{"",new string('A',64),new string('a',63),1}) Invalid(field,value);
            profile[field]=new string('a',64);Valid();profile[field]=null;
        }
        foreach(string field in new[]{"CreatedAt","UpdatedAt"}){Invalid(field,"invalid");Invalid(field,1);Invalid(field,null);}
        string json=Json();
        reject(()=>ProfilePolicy.Validate(json,"other"));reject(()=>ProfilePolicy.Validate(json,"../lab"));
        reject(()=>ProfilePolicy.Validate(json.Insert(1,"\"Name\":\"other\","),"lab"));
        reject(()=>ProfilePolicy.Validate(json.Insert(1,"\"Na\\u006de\":\"lab\","),"lab"));
        reject(()=>ProfilePolicy.Validate(json.Insert(1,"\"name\":\"lab\","),"lab"));
        reject(()=>ProfilePolicy.Validate(json.Replace("\"Name\":","\"name\":"),"lab"));
        reject(()=>ProfilePolicy.Validate(new string(' ',32769)+json,"lab"));
        reject(()=>ProfilePolicy.Validate("[]","lab"));
        try{ProfilePolicy.Validate("{\"AccessToken\":\"synthetic-secret\"}","lab");throw new Exception("Expected rejection.");}
        catch(InvalidOperationException error){check(error.Message=="Profile configuration is invalid. Details suppressed.");check(error.InnerException==null);}
    }
}
