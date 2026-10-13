#nullable enable
using System;
using System.Collections.Generic;
using System.Collections;
using System.Collections.Specialized;
using System.Linq;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;

namespace TokenForge.Core;

// Descriptive published claims; never tenant ownership or a consent decision.
public static class DiscoverySourceClaims
{
    private const int MaxInput=4*1024*1024;
    private static readonly UTF8Encoding Utf8=new UTF8Encoding(false,true);
    private static readonly string[] Fields={"Name","OwnerTenantId","PublicClient","Foci","RedirectUris","PreferredRedirectUri","Grants","IsResourceCandidate","IdentifierUris"};
    public static string Project(string sourceName,string location,string evidence,string attributesJson)
    {
        using var input=Parse(attributesJson);
        if(input.RootElement.ValueKind!=JsonValueKind.Object)throw Invalid();
        var result=Header(sourceName,location,evidence);
        foreach(string field in Fields)
            if(input.RootElement.TryGetProperty(field,out var value) && value.ValueKind!=JsonValueKind.Null && !(value.ValueKind==JsonValueKind.String && value.GetString()==""))
                result[field]=Attribute(field,value,false);
        return Serialize(result);
    }
    public static string Normalize(string claimsJson,string appId)
    {
        if(!Guid.TryParse(appId,out var id) || id==Guid.Empty)throw Invalid();
        using var input=Parse(claimsJson);
        if(input.RootElement.ValueKind!=JsonValueKind.Array || input.RootElement.GetArrayLength()>256)throw Invalid();
        var claims=new SortedDictionary<string,JsonObject>(StringComparer.Ordinal);
        foreach(var claim in input.RootElement.EnumerateArray())
        {
            Keys(claim,new[]{"SourceName","Location","Evidence"}.Concat(Fields));
            var normalized=Header(Text(claim,"SourceName"),Text(claim,"Location"),Text(claim,"Evidence"));
            foreach(string field in Fields)
                if(claim.TryGetProperty(field,out var value) && value.ValueKind!=JsonValueKind.Null && !(value.ValueKind==JsonValueKind.String && value.GetString()==""))
                    normalized[field]=Attribute(field,value,true);
            // An ID placeholder is not a competing display-name claim.
            if(normalized["Name"] is JsonValue name && Guid.TryParse(name.GetValue<string>(),out var nameId) && nameId==id)normalized.Remove("Name");
            string key=normalized.ToJsonString();claims.TryAdd(key,normalized);
        }
        var conflicts=new JsonArray();
        foreach(string field in new[]{"Name","OwnerTenantId"})
        {
            var values=new SortedSet<string>(StringComparer.Ordinal);
            foreach(var claim in claims.Values)if(claim[field] is JsonValue value)values.Add(value.GetValue<string>());
            if(values.Count>1)conflicts.Add(new JsonObject{["Field"]=field,["Values"]=new JsonArray(values.Select(x=>(JsonNode?)JsonValue.Create(x)).ToArray())});
        }
        return Serialize(new JsonObject{["SourceClaims"]=new JsonArray(claims.Values.Select(x=>(JsonNode)x).ToArray()),["MetadataConflicts"]=conflicts});
    }
    public static void Validate(string claimsJson,string conflictsJson,string appId)
    {
        using var expected=Parse(Normalize(claimsJson,appId));using var actual=Parse(conflictsJson);
        if(!JsonNode.DeepEquals(JsonNode.Parse(expected.RootElement.GetProperty("SourceClaims").GetRawText()),JsonNode.Parse(claimsJson)) || !JsonNode.DeepEquals(JsonNode.Parse(expected.RootElement.GetProperty("MetadataConflicts").GetRawText()),JsonNode.Parse(actual.RootElement.GetRawText())))throw Invalid();
    }
    public static void ValidatePublicLocation(string location)
    {
        String(location,4096);
        if(!Uri.TryCreate(location,UriKind.Absolute,out var uri) || uri.Scheme!=Uri.UriSchemeHttps || !string.Equals(uri.Host,"raw.githubusercontent.com",StringComparison.OrdinalIgnoreCase) || uri.UserInfo.Length!=0 || uri.Query.Length!=0 || uri.Fragment.Length!=0)throw Invalid();
    }
    public static IDictionary NormalizeMetadata(string claimsJson,string appId)
    {
        using var document=Parse(Normalize(claimsJson,appId));
        return (IDictionary)ReadValue(document.RootElement)!;
    }
    // Used by both catalog readers so date-looking names remain strings on PowerShell 7.4.
    public static IDictionary ReadCatalog(string json)
    {
        if(Utf8.GetByteCount(json)>128*1024*1024)throw Invalid();
        using var document=JsonDocument.Parse(json,new JsonDocumentOptions{MaxDepth=100});
        Unique(document.RootElement);var root=document.RootElement;
        if(root.GetProperty("Format").GetString()!="TokenForgeApplicationMetadata" || !root.GetProperty("SchemaVersion").TryGetInt32(out int version) || version is not (1 or 2))throw Invalid();
        foreach(var app in root.GetProperty("Applications").EnumerateObject())
            foreach(var record in app.Value.GetProperty("Records").EnumerateObject())
            {
                string kind=record.Value.GetProperty("Kind").GetString()!;
                ValidateCatalogAttributes(record.Value.GetProperty("Attributes"),app.Name,kind,version);
                foreach(var previous in record.Value.GetProperty("PreviousVersions").EnumerateArray())ValidateCatalogAttributes(previous.GetProperty("Attributes"),app.Name,kind,version);
            }
        return (IDictionary)ReadValue(root)!;
    }
    public static object? ReadMetadataJson(string json)
    {
        if(Utf8.GetByteCount(json)>128*1024*1024)throw Invalid();
        using var document=JsonDocument.Parse(json,new JsonDocumentOptions{MaxDepth=100});Unique(document.RootElement);return ReadValue(document.RootElement);
    }
    public static void ValidateCatalogAttributes(JsonElement attributes,string appId,string kind,int version)
    {
        bool claims=attributes.TryGetProperty("SourceClaims",out var sourceClaims),conflicts=attributes.TryGetProperty("MetadataConflicts",out var metadataConflicts);
        if(claims!=conflicts || claims && (kind!="Discovery" || version!=2))throw Invalid();
        if(claims)Validate(sourceClaims.GetRawText(),metadataConflicts.GetRawText(),appId);
    }
    private static object? ReadValue(JsonElement value)
    {
        switch(value.ValueKind)
        {
            case JsonValueKind.Object:
                var fields=new OrderedDictionary(StringComparer.Ordinal);
                foreach(var field in value.EnumerateObject())fields.Add(field.Name,ReadValue(field.Value));return fields;
            case JsonValueKind.Array:return value.EnumerateArray().Select(ReadValue).ToArray();
            case JsonValueKind.String:return value.GetString();
            case JsonValueKind.Number:return value.TryGetInt64(out var integer)?(object)integer:value.GetDouble();
            case JsonValueKind.True:return true;
            case JsonValueKind.False:return false;
            case JsonValueKind.Null:return null;
            default:throw Invalid();
        }
    }
    private static JsonObject Header(string source,string location,string evidence)
    {
        String(source,4096);String(location,4096);String(evidence,4096);
        if(location.IndexOfAny(new[]{'?','#'})>=0)throw Invalid();
        if(Uri.TryCreate(location,UriKind.Absolute,out var uri) && (uri.UserInfo.Length!=0 || uri.Query.Length!=0 || uri.Fragment.Length!=0))throw Invalid();
        return new JsonObject{["SourceName"]=source,["Location"]=location,["Evidence"]=evidence};
    }
    private static JsonNode Attribute(string name,JsonElement value,bool strict)
    {
        if(name is "PublicClient" or "IsResourceCandidate")
        {if(value.ValueKind is not (JsonValueKind.True or JsonValueKind.False))throw Invalid();return JsonValue.Create(value.GetBoolean())!;}
        if(name=="OwnerTenantId")
        {if(value.ValueKind!=JsonValueKind.String || !Guid.TryParse(value.GetString(),out var id) || id==Guid.Empty)throw Invalid();return JsonValue.Create(id.ToString())!;}
        if(name=="Foci" && value.ValueKind is JsonValueKind.Number or JsonValueKind.True or JsonValueKind.False)
        {if(value.ValueKind==JsonValueKind.Number && (!value.TryGetInt64(out var integer) || integer<0))throw Invalid();return JsonNode.Parse(value.GetRawText())!;}
        if(name is "RedirectUris" or "IdentifierUris"){var values=Strings(value,4096,false);foreach(var item in values)UriValue(item!.GetValue<string>());return values;}
        if(name=="Grants")
        {
            if(value.ValueKind!=JsonValueKind.Array || value.GetArrayLength()>10000)throw Invalid();
            var grants=new SortedDictionary<string,SortedSet<string>>(StringComparer.Ordinal);
            foreach(var grant in value.EnumerateArray())
            {
                if(strict)Keys(grant,new[]{"ResourceId","Scopes"});
                string resource=Text(grant,"ResourceId");if(!Guid.TryParse(resource,out var id) || id==Guid.Empty)throw Invalid();resource=id.ToString();
                var scopes=Strings(grant.GetProperty("Scopes"),256,true);
                if(!grants.TryGetValue(resource,out var names)){names=new SortedSet<string>(StringComparer.Ordinal);grants.Add(resource,names);}
                foreach(var scope in scopes)names.Add(scope!.GetValue<string>());
                if(names.Count>1000)throw Invalid();
            }
            return new JsonArray(grants.Select(x=>(JsonNode)new JsonObject{["ResourceId"]=x.Key,["Scopes"]=new JsonArray(x.Value.Select(v=>(JsonNode?)JsonValue.Create(v)).ToArray())}).ToArray());
        }
        if(value.ValueKind!=JsonValueKind.String)throw Invalid();string text=value.GetString()!;String(text,4096,name=="Name");if(name=="PreferredRedirectUri")UriValue(text);return JsonValue.Create(text)!;
    }
    private static void UriValue(string value){if(Uri.TryCreate(value,UriKind.Absolute,out var uri) && uri.UserInfo.Length!=0)throw Invalid();}
    private static JsonArray Strings(JsonElement value,int maximum,bool scope)
    {
        if(value.ValueKind!=JsonValueKind.Array || value.GetArrayLength()>1000)throw Invalid();var names=new SortedSet<string>(StringComparer.Ordinal);
        foreach(var entry in value.EnumerateArray())
        {
            if(entry.ValueKind!=JsonValueKind.String)throw Invalid();string text=entry.GetString()!;String(text,maximum);
            if(scope && !Regex.IsMatch(text,@"\A[A-Za-z0-9_.:/-]{1,256}\z",RegexOptions.CultureInvariant))throw Invalid();names.Add(text);
        }
        return new JsonArray(names.Select(x=>(JsonNode?)JsonValue.Create(x)).ToArray());
    }
    private static string Text(JsonElement root,string name)
    {if(!root.TryGetProperty(name,out var value) || value.ValueKind!=JsonValueKind.String)throw Invalid();string text=value.GetString()!;String(text,4096);return text;}
    private static void String(string value,int maximum,bool displayName=false){if(value.Length is <1 || value.Length>maximum || value.Any(c=>c<32 || c==127 || !displayName && char.IsControl(c)))throw Invalid();try{Utf8.GetByteCount(value);}catch(EncoderFallbackException){throw Invalid();}}
    private static void Keys(JsonElement value,IEnumerable<string> keys)
    {if(value.ValueKind!=JsonValueKind.Object)throw Invalid();var allowed=new HashSet<string>(keys,StringComparer.Ordinal);foreach(var field in value.EnumerateObject())if(!allowed.Contains(field.Name))throw Invalid();}
    private static JsonDocument Parse(string json)
    {if(json.Length>MaxInput)throw Invalid();var document=JsonDocument.Parse(json,new JsonDocumentOptions{MaxDepth=32});try{Unique(document.RootElement);return document;}catch{document.Dispose();throw Invalid();}}
    private static void Unique(JsonElement value)
    {if(value.ValueKind==JsonValueKind.Object){var names=new HashSet<string>(StringComparer.Ordinal);foreach(var field in value.EnumerateObject()){if(!names.Add(field.Name))throw Invalid();Unique(field.Value);}}else if(value.ValueKind==JsonValueKind.Array)foreach(var child in value.EnumerateArray())Unique(child);}
    private static InvalidOperationException Invalid()=>new InvalidOperationException("Discovery source claims are invalid.");
    private static string Serialize(JsonNode value){string json=value.ToJsonString();if(json.Length>MaxInput)throw Invalid();return json;}
}
