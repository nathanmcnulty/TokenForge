#nullable enable
using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
namespace TokenForge.Core;

// Shared, transport-free catalog policy. Storage and reporting use these same rules.
public static class ApplicationCatalogPolicy
{
    private const int MaxBytes=128*1024*1024;
    private static readonly string[] Kinds = "Discovery Inventory SignIns ScopeObservations RegistrationAttempts FlowAttempts".Split(' ');
    private static readonly HashSet<string> Dates = new("CreatedAt UpdatedAt FirstSeenAt LastSeenAt CurrentVersionFirstSeenAt LastObservedAt ObservedAt RecordedAt Since Until".Split(' '), StringComparer.Ordinal);
    private static readonly Dictionary<string,string> Attributes = new() {
        ["Discovery"]="AppId Name OwnerTenantId Ownership PublicClient Foci RedirectUris PreferredRedirectUri Grants IsResourceCandidate IdentifierUris SourceClaims MetadataConflicts",
        ["Inventory"]="AppId Name PublishedName ServicePrincipalType PreferredSingleSignOnMode LoginUrl LogoutUrl Homepage Registration Ownership OwnerTenantId AccountEnabled AssignmentRequired SignInAudience PublicClient Foci RedirectUris TenantRedirectUris PreferredRedirectUri PublishedGrants DelegatedScopeDefinitions AppRoleDefinitions IdentifierUris IsResourceCandidate",
        ["SignIns"]="AppId SignInCount KnownInInventory RegisteredMicrosoft Evidence ProtocolCounts ClientTypeCounts EventTypeCounts ResourceCounts OutcomeCounts AuthenticationMethodCounts CredentialTypeCounts IncomingTokenTypeCounts",
        ["RegistrationAttempts"]="AppId Outcome HttpStatus",
        ["ScopeObservations"]="ClientId ResourceId Outcome Protocol Spa RequestedScopes ResponseScopes ScpScopes ClaimsReadable HasScpClaim SignatureValidated NamespaceVerification RequestVerification ErrorCodes AttemptCount ElapsedSeconds RedirectFingerprint CatalogHash PlanFingerprint",
        ["FlowAttempts"]="AttemptKey PlanFingerprint Protocol Spa RedirectFingerprint Outcome ResponseScopes ScpScopes ClaimsReadable HasScpClaim NamespaceVerification RequestVerification SignatureValidated ErrorCodes ElapsedSeconds"
    };
    public static bool IsKind(string kind)=>Kinds.Contains(kind);
    public static void ValidateDocument(string json)
    {
        using var document=Parse(json);var root=document.RootElement;
        DiscoverySourceClaims.ValidateUniqueKeys(root);
        Keys(root,"Format SchemaVersion CreatedAt UpdatedAt Applications Origins Runs");
        int version=root.GetProperty("SchemaVersion").GetInt32();
        if(Text(root,"Format")!="TokenForgeApplicationMetadata" || version is not (1 or 2))throw Invalid();
        if(StringComparer.Ordinal.Compare(Date(root,"CreatedAt"),Date(root,"UpdatedAt"))>0)throw Invalid();
        var apps=root.GetProperty("Applications");var origins=root.GetProperty("Origins");var runs=root.GetProperty("Runs");
        if(apps.ValueKind!=JsonValueKind.Object || origins.ValueKind!=JsonValueKind.Object || runs.ValueKind!=JsonValueKind.Array)throw Invalid();
        UniqueKeys(apps);UniqueKeys(origins);var runIds=new Dictionary<string,JsonElement>(StringComparer.Ordinal);
        foreach(var run in runs.EnumerateArray()){
            ValidateRun(run);if(!runIds.TryAdd(Text(run,"Id"),run))throw Invalid();
        }
        foreach(var app in apps.EnumerateObject()){
            GuidValue(app.Name);Keys(app.Value,"AppId FirstSeenAt LastSeenAt Records");
            if(Text(app.Value,"AppId")!=app.Name || StringComparer.Ordinal.Compare(Date(app.Value,"FirstSeenAt"),Date(app.Value,"LastSeenAt"))>0)throw Invalid();
            var records=app.Value.GetProperty("Records");if(records.ValueKind!=JsonValueKind.Object)throw Invalid();UniqueKeys(records);
            foreach(var record in records.EnumerateObject()){
                ValidateClaimsVersion(record.Value,app.Name,version);
                if(ValidateRecord(record.Value,app.Name)!=record.Name || !origins.TryGetProperty(record.Name,out _))throw Invalid();
            }
        }
        foreach(var origin in origins.EnumerateObject()){
            Keys(origin.Value,"Kind LastObservedAt LastRunId");string kind=Text(origin.Value,"Kind"),id=Text(origin.Value,"LastRunId");
            if(!runIds.TryGetValue(id,out var run) || Text(run,"Kind")!=kind || Date(run,"ObservedAt")!=Date(origin.Value,"LastObservedAt") || !OriginShape(origin.Name,kind))throw Invalid();
            if(kind is "Inventory" or "SignIns" && NullableText(run,"TenantFingerprint")!=origin.Name.Split('/')[1])throw Invalid();
        }
    }

    public static void ValidateClaimsVersion(JsonElement record,string app,int version)
    {
        string kind=Text(record,"Kind");DiscoverySourceClaims.ValidateCatalogAttributes(record.GetProperty("Attributes"),app,kind,version);
        foreach(var previous in record.GetProperty("PreviousVersions").EnumerateArray())DiscoverySourceClaims.ValidateCatalogAttributes(previous.GetProperty("Attributes"),app,kind,version);
    }
    public static string ValidateRecord(JsonElement record,string app)
    {
        Keys(record,"Kind TenantFingerprint PrincipalFingerprint ResourceId FirstSeenAt LastSeenAt PresentInLatestRun CurrentVersionFirstSeenAt Attributes Sources ContentSha256 PreviousVersions");
        var kind=Text(record,"Kind");if(!Kinds.Contains(kind))throw Invalid();
        var origin=Origin(kind,NullableText(record,"TenantFingerprint"),NullableText(record,"PrincipalFingerprint"),NullableText(record,"ResourceId"),kind=="FlowAttempts"?Text(record.GetProperty("Attributes"),"AttemptKey"):null);
        ValidatePayload(record,kind,app);ValidateContext(record.GetProperty("Attributes"),kind,record);var first=Date(record,"FirstSeenAt");var last=Date(record,"LastSeenAt");var current=Date(record,"CurrentVersionFirstSeenAt");
        if(StringComparer.Ordinal.Compare(first,current)>0 || StringComparer.Ordinal.Compare(current,last)>0 || record.GetProperty("PresentInLatestRun").ValueKind is not (JsonValueKind.True or JsonValueKind.False))throw Invalid();
        var versions=record.GetProperty("PreviousVersions");if(versions.ValueKind!=JsonValueKind.Array)throw Invalid();foreach(var version in versions.EnumerateArray())ValidateVersion(version,kind,app,record);
        return origin;
    }
    public static void ValidateVersion(JsonElement version,string kind,string app,JsonElement record){Keys(version,"FirstSeenAt LastSeenAt Attributes Sources ContentSha256");ValidatePayload(version,kind,app);ValidateContext(version.GetProperty("Attributes"),kind,record);if(StringComparer.Ordinal.Compare(Date(version,"FirstSeenAt"),Date(version,"LastSeenAt"))>0)throw Invalid();}
    public static void ValidateContext(JsonElement attributes,string kind,JsonElement record)
    {
        if(kind=="ScopeObservations" && attributes.TryGetProperty("ResourceId",out var resource) && resource.ValueKind!=JsonValueKind.Null && Guid.Parse(resource.GetString()!).ToString()!=NullableText(record,"ResourceId"))throw Invalid();
        if(kind=="FlowAttempts")foreach(var field in new[]{"AttemptKey","PlanFingerprint","Protocol","Spa","RedirectFingerprint"}){
            var current=record.GetProperty("Attributes");if(attributes.TryGetProperty(field,out var value) && (!current.TryGetProperty(field,out var expected) || Canonical(value)!=Canonical(expected)))throw Invalid();
        }
    }
    private static readonly Dictionary<string,string[]> SummaryValues=new() {
        ["ProtocolCounts"]="none oAuth2 ropc wsFederation saml20 deviceCode unknownFutureValue authenticationTransfer nativeAuth implicitAccessTokenAndGetResponseMode implicitIdTokenAndGetResponseMode implicitAccessTokenAndPostResponseMode implicitIdTokenAndPostResponseMode authorizationCodeWithoutPkce authorizationCodeWithPkce clientCredentials refreshTokenGrant encryptedAuthorizeResponse directUserGrant kerberos prtGrant seamlessSso prtBrokerBased prtNonBrokerBased onBehalfOf samlOnBehalfOf Unknown".Split(' '),
        ["ClientTypeCounts"]=new[]{"Browser","Mobile Apps and Desktop clients","Modern clients","Exchange ActiveSync","Other clients","IMAP","MAPI","SMTP","POP","Authenticated SMTP","Exchange Web Services","Unknown"},
        ["EventTypeCounts"]="interactiveUser nonInteractiveUser servicePrincipal managedIdentity".Split(' '),
        ["AuthenticationMethodCounts"]=new[]{"SMS","Authenticator App","App Verification code","Password","FIDO","PTA","PHS","Unknown"},
        ["CredentialTypeCounts"]="none clientSecret clientAssertion federatedIdentityCredential managedIdentity certificate unknownFutureValue Unknown".Split(' '),
        ["IncomingTokenTypeCounts"]="none primaryRefreshToken saml11 saml20 unknownFutureValue remoteDesktopToken refreshToken Unknown".Split(' '),
        ["OutcomeCounts"]="Succeeded Failed Unknown".Split(' ')
    };
    public static void ValidatePayload(JsonElement payload,string kind,string? app)
    {
        HashValue(Text(payload,"ContentSha256"));var attributes=payload.GetProperty("Attributes");AllowedKeys(attributes,Attributes[kind]);
        DiscoverySourceClaims.ValidateCatalogAttributes(attributes,app!,kind,2);
        foreach(var field in attributes.EnumerateObject()) {
            if(field.Name is "SourceClaims" or "MetadataConflicts")continue;
            var value=field.Value;if(value.ValueKind==JsonValueKind.Null)continue;
            if(field.Name is "Grants" or "PublishedGrants" or "DelegatedScopeDefinitions" or "AppRoleDefinitions" || field.Name.EndsWith("Counts",StringComparison.Ordinal)){
                if(value.ValueKind!=JsonValueKind.Array)throw Invalid();foreach(var item in value.EnumerateArray()){
                    var columns=field.Name switch {"Grants" or "PublishedGrants"=>"ResourceId Scopes","DelegatedScopeDefinitions"=>"Id Value Enabled ConsentType AdminConsentDisplayName AdminConsentDescription UserConsentDisplayName UserConsentDescription","AppRoleDefinitions"=>"Id Value DisplayName Description AllowedMemberTypes Enabled Origin",_=>"Value Count"};
                    AllowedKeys(item,columns);
                    if(field.Name=="AppRoleDefinitions" && item.TryGetProperty("Origin",out var origin) &&
                        (origin.ValueKind!=JsonValueKind.String || origin.GetString() is not ("Application" or "ServicePrincipal" or "Unknown")))throw Invalid();
                    foreach(var leaf in item.EnumerateObject())ValidateLeaf(leaf.Name,leaf.Value);
                }
            }else ValidateLeaf(field.Name,value);
        }
        foreach(var field in new[]{"AppId","ClientId"})if(attributes.TryGetProperty(field,out var id) && id.ValueKind!=JsonValueKind.Null && app!=null && Guid.Parse(id.GetString()!).ToString()!=app)throw Invalid();
        if(kind=="SignIns"){
            if(!attributes.TryGetProperty("SignInCount",out var total) || !total.TryGetInt64(out var count) || count<0)throw Invalid();
            foreach(var field in attributes.EnumerateObject().Where(x=>x.Name.EndsWith("Counts",StringComparison.Ordinal))){
                var seen=new HashSet<string>(StringComparer.Ordinal);
                foreach(var item in field.Value.EnumerateArray()){
                    Keys(item,"Value Count");var value=Text(item,"Value");if(!seen.Add(value) || !item.GetProperty("Count").TryGetInt64(out var number) || number<0 || number>count)throw Invalid();
                    if(field.Name=="ResourceCounts")GuidValue(value);else if(!SummaryValues[field.Name].Contains(value))throw Invalid();
                }
            }
        }
        var sources=payload.GetProperty("Sources");if(sources.ValueKind!=JsonValueKind.Array)throw Invalid();foreach(var source in sources.EnumerateArray()){Keys(source,"Name Location Evidence");foreach(var field in source.EnumerateObject())if(field.Value.ValueKind!=JsonValueKind.Null)Text(source,field.Name);}
    }
    public static void ValidateLeaf(string name,JsonElement value)
    {
        if(value.ValueKind==JsonValueKind.Null)return;
        // Older inventory producers unrolled singleton tenant callback arrays. Preserve their hashes and shape on import.
        if(name=="TenantRedirectUris" && value.ValueKind==JsonValueKind.String){if(value.GetString()!.Length>32768)throw Invalid();return;}
        if(name is "Scopes" or "RedirectUris" or "TenantRedirectUris" or "IdentifierUris" or "AllowedMemberTypes" or "RequestedScopes" or "ResponseScopes" or "ScpScopes" or "ErrorCodes"){
            if(value.ValueKind!=JsonValueKind.Array || value.GetArrayLength()>100000)throw Invalid();foreach(var item in value.EnumerateArray()){
                if(item.ValueKind!=JsonValueKind.String || item.GetString()!.Length>32768)throw Invalid();var arrayText=item.GetString()!;
                if(name=="ErrorCodes" && !Regex.IsMatch(arrayText,"\\A[0-9]{4,9}\\z",RegexOptions.CultureInvariant))throw Invalid();
                if(name is "Scopes" or "RequestedScopes" or "ResponseScopes" or "ScpScopes" && !Regex.IsMatch(arrayText,"\\A[A-Za-z0-9_.:/-]{1,256}\\z",RegexOptions.CultureInvariant))throw Invalid();
            }return;
        }
        if(name is "PublicClient" or "IsResourceCandidate" or "AccountEnabled" or "AssignmentRequired" or "KnownInInventory" or "RegisteredMicrosoft" or "Spa" or "ClaimsReadable" or "HasScpClaim" or "Enabled" or "SignatureValidated"){
            if(value.ValueKind is not (JsonValueKind.True or JsonValueKind.False) || name=="SignatureValidated" && value.GetBoolean())throw Invalid();return;
        }
        if(name is "Count" or "SignInCount" or "AttemptCount" or "HttpStatus" or "ElapsedSeconds"){
            if(value.ValueKind!=JsonValueKind.Number || !value.TryGetDouble(out var number) || !double.IsFinite(number) || number<0 || name!="ElapsedSeconds" && !value.TryGetInt64(out _))throw Invalid();return;
        }
        if(name=="Foci" && value.ValueKind is JsonValueKind.Number or JsonValueKind.True or JsonValueKind.False)return;
        if(value.ValueKind!=JsonValueKind.String || value.GetString()!.Length>32768)throw Invalid();
        var text=value.GetString()!;if(name is "AppId" or "ClientId" or "ResourceId" or "OwnerTenantId" or "Id"){if(!Guid.TryParse(text,out var id) || id==Guid.Empty)throw Invalid();}
        if(name is "PlanFingerprint" or "AttemptKey" or "RedirectFingerprint" or "CatalogHash")HashValue(text);
    }
    public static void ValidateRun(JsonElement run)
    {
        AllowedKeys(run,"Id Kind ObservedAt RecordedAt ApplicationRecordCount IgnoredEmptyAppIdCount TenantFingerprint SourceSnapshots Window");
        foreach(var required in "Id Kind ObservedAt RecordedAt ApplicationRecordCount IgnoredEmptyAppIdCount TenantFingerprint".Split(' '))if(!run.TryGetProperty(required,out _))throw Invalid();
        GuidValue(Text(run,"Id"));var kind=Text(run,"Kind");if(!Kinds.Contains(kind))throw Invalid();Date(run,"ObservedAt");Date(run,"RecordedAt");
        foreach(var field in new[]{"ApplicationRecordCount","IgnoredEmptyAppIdCount"})if(!run.GetProperty(field).TryGetInt32(out var count) || count<0)throw Invalid();
        var tenant=NullableText(run,"TenantFingerprint");if(kind is "Inventory" or "SignIns"){if(tenant==null)throw Invalid();HashValue(tenant);}else if(tenant!=null)throw Invalid();
        if(run.TryGetProperty("SourceSnapshots",out var snapshots)){if(kind!="Discovery" || snapshots.ValueKind!=JsonValueKind.Array)throw Invalid();foreach(var source in snapshots.EnumerateArray()){Keys(source,"Location Sha256 HashKind");Text(source,"Location");HashValue(Text(source,"Sha256"));Text(source,"HashKind");}}
        if(run.TryGetProperty("Window",out var window)){if(kind!="SignIns")throw Invalid();Keys(window,"Since Until EventTypes");Date(window,"Since");Date(window,"Until");var events=window.GetProperty("EventTypes");if(events.ValueKind!=JsonValueKind.Array || events.EnumerateArray().Any(x=>x.ValueKind!=JsonValueKind.String || x.GetString() is not ("interactiveUser" or "nonInteractiveUser" or "servicePrincipal" or "managedIdentity")))throw Invalid();}
    }
    public static string Origin(string kind,string? tenant,string? principal,string? resource,string? attempt)
    {
        if(kind=="Discovery"){if(tenant!=null || principal!=null || resource!=null)throw Invalid();}
        else{if(tenant==null)throw Invalid();HashValue(tenant);}
        if(kind is "ScopeObservations" or "FlowAttempts"){if(principal==null || resource==null)throw Invalid();HashValue(principal);GuidValue(resource);}else if(principal!=null || resource!=null)throw Invalid();
        if(attempt!=null)HashValue(attempt);return string.Join("/",kind,tenant??"",principal??"",resource??"")+(attempt==null?"":"/"+attempt);
    }
    public static bool OriginShape(string origin,string kind){try{var p=origin.Split('/');return Kinds.Contains(kind) && p.Length==(kind=="FlowAttempts"?5:4) && p[0]==kind && Origin(kind,p[1]==""?null:p[1],p[2]==""?null:p[2],p[3]==""?null:p[3],p.Length==5?p[4]:null)==origin;}catch{return false;}}
    public static JsonDocument Parse(string json){if(Encoding.UTF8.GetByteCount(json)>MaxBytes)throw Invalid();return JsonDocument.Parse(json,new JsonDocumentOptions{MaxDepth=32});}
    public static void UniqueKeys(JsonElement value){if(value.ValueKind!=JsonValueKind.Object)throw Invalid();var seen=new HashSet<string>(StringComparer.Ordinal);foreach(var field in value.EnumerateObject())if(!seen.Add(field.Name))throw Invalid();}
    public static void AllowedKeys(JsonElement value,string allowed){if(value.ValueKind!=JsonValueKind.Object)throw Invalid();var names=allowed.Split(' ');var seen=new HashSet<string>(StringComparer.Ordinal);foreach(var field in value.EnumerateObject())if(!names.Contains(field.Name) || !seen.Add(field.Name))throw Invalid();}
    public static void Keys(JsonElement value,string expected){AllowedKeys(value,expected);if(value.EnumerateObject().Count()!=expected.Split(' ').Length)throw Invalid();}
    public static string Text(JsonElement value,string name,int limit=32768){var field=value.GetProperty(name);if(field.ValueKind!=JsonValueKind.String || field.GetString()!.Length>limit)throw Invalid();return field.GetString()!;}
    public static string? NullableText(JsonElement value,string name)=>value.GetProperty(name).ValueKind==JsonValueKind.Null?null:Text(value,name);
    public static string Date(JsonElement value,string name)=>DateText(Text(value,name));
    public static string DateText(string value){if(value.Contains('\n') || value.Contains('\r') || !DateTimeOffset.TryParse(value,CultureInfo.InvariantCulture,DateTimeStyles.None,out var date) || date>DateTimeOffset.UtcNow.AddMinutes(5))throw Invalid();return date.ToUniversalTime().ToString("o",CultureInfo.InvariantCulture);}
    public static void GuidValue(string value){if(!Guid.TryParseExact(value,"D",out var id) || id==Guid.Empty || id.ToString()!=value)throw Invalid();}
    public static void HashValue(string value){if(!Regex.IsMatch(value,"\\A[a-f0-9]{64}\\z",RegexOptions.CultureInvariant))throw Invalid();}
    public static string Hash(string value)=>Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(value))).ToLowerInvariant();
    public static string Canonical(JsonElement value)
    {
        object? Clean(JsonElement item,string? key=null)=>item.ValueKind switch {
            JsonValueKind.Object=>item.EnumerateObject().OrderBy(p=>p.Name,StringComparer.Ordinal).ToDictionary(p=>p.Name,p=>Clean(p.Value,p.Name),StringComparer.Ordinal),
            JsonValueKind.Array=>item.EnumerateArray().Select(x=>Clean(x)).ToArray(),JsonValueKind.String=>Dates.Contains(key??"")?DateText(item.GetString()!):item.GetString(),
            JsonValueKind.Number=>item.TryGetInt64(out var integer)?(object)integer:item.GetDouble(),JsonValueKind.True=>true,JsonValueKind.False=>false,JsonValueKind.Null=>null,_=>throw Invalid()};
        return JsonSerializer.Serialize(Clean(value));
    }
    public static InvalidOperationException Invalid()=>new("Invalid application catalog metadata.");
}
