using System.Text.Json;
using System.Text.Json.Serialization;
using TokenForge.Core;

internal static class NativeCatalogMcpServer
{
    private const int DefaultPageSize = 25;
    private const int MaxPageSize = 100;
    private const string ProtocolVersion = "2025-11-25";

    private static readonly JsonSerializerOptions ToolArguments = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
        AllowDuplicateProperties = false
    };

    private static readonly JsonElement ToolList = JsonSerializer.Deserialize<JsonElement>("""
        {"tools":[
          {
            "name":"search_applications",
            "description":"Search the local published catalog in ascending AppId order. Reuse the filters with the returned NextOffset for the next page.",
            "annotations":{"readOnlyHint":true,"openWorldHint":false},
            "inputSchema":{
              "type":"object","additionalProperties":false,
              "properties":{
                "appId":{"type":"string","format":"uuid"},
                "name":{"type":"string","pattern":"\\S","maxLength":4096,"description":"Case-insensitive application name substring."},
                "resourceId":{"type":"string","format":"uuid"},
                "scopes":{"type":"array","items":{"type":"string","pattern":"\\S","maxLength":4096},"description":"Every scope must match the same resource grant row. Scope names are case-sensitive."},
                "tenancyEvidence":{"enum":["owner-outside-target-tenant","owner-not-outside-target-tenant","unknown"]},
                "includeNonVerified":{"type":"boolean","default":false},
                "pageSize":{"type":"integer","minimum":1,"maximum":100,"default":25},
                "offset":{"type":"integer","minimum":0,"maximum":2147483647,"default":0}
              }
            }
          },
          {
            "name":"get_application",
            "description":"Look up an exact AppId. Returns zero or one application, with verified results by default.",
            "annotations":{"readOnlyHint":true,"openWorldHint":false},
            "inputSchema":{
              "type":"object","additionalProperties":false,"required":["appId"],
              "properties":{
                "appId":{"type":"string","format":"uuid"},
                "includeNonVerified":{"type":"boolean","default":false}
              }
            }
          }
        ]}
        """);

    private sealed record SearchArguments(string? AppId, string? Name, string? ResourceId,
        string[]? Scopes, string? TenancyEvidence, bool IncludeNonVerified = false,
        int PageSize = DefaultPageSize, int Offset = 0);

    private sealed record GetArguments(string AppId, bool IncludeNonVerified = false);

    public static int Run(PublishedCatalog catalog)
    {
        string? version = null;
        bool ready = false;
        string? line;
        while ((line = Console.ReadLine()) != null)
        {
            JsonElement? id = null;
            int errorCode = -32700;
            try
            {
                using var document = JsonDocument.Parse(line);
                var request = document.RootElement;
                errorCode = -32600;
                if (request.ValueKind != JsonValueKind.Object ||
                    !request.TryGetProperty("jsonrpc", out var jsonrpc) || jsonrpc.ValueKind != JsonValueKind.String ||
                    jsonrpc.GetString() != "2.0" || !request.TryGetProperty("method", out var method) ||
                    method.ValueKind != JsonValueKind.String)
                    throw new InvalidOperationException("Invalid JSON-RPC request.");

                request.TryGetProperty("params", out var parameters);
                if (!request.TryGetProperty("id", out var requestId))
                {
                    if (version != null && method.GetString() == "notifications/initialized")
                        ready = true;
                    continue;
                }
                if (requestId.ValueKind is not (JsonValueKind.String or JsonValueKind.Number))
                    throw new InvalidOperationException("Expected a string or numeric request ID.");
                id = requestId.Clone();

                object result;
                errorCode = -32602;
                switch (method.GetString())
                {
                    case "initialize" when version == null:
                        string? requested = RequiredProperty(parameters, "protocolVersion").GetString();
                        version = requested switch
                        {
                            ProtocolVersion or "2025-06-18" or "2025-03-26" => requested,
                            _ => ProtocolVersion
                        };
                        result = new
                        {
                            protocolVersion = version,
                            capabilities = new { tools = new { listChanged = false } },
                            serverInfo = new { name = "tokenforge-catalog", version = CredentialRuntime.Version }
                        };
                        break;
                    case "ping":
                        result = new { };
                        break;
                    case "tools/list" when ready:
                        result = ToolList;
                        break;
                    case "tools/call" when ready:
                        result = Call(catalog, parameters, version != "2025-03-26");
                        break;
                    default:
                        errorCode = -32601;
                        throw new InvalidOperationException("Method unavailable.");
                }
                Write(new { jsonrpc = "2.0", id, result });
            }
            catch (Exception error) when (error is JsonException or InvalidOperationException or FormatException)
            {
                string message = error is JsonException
                    ? (errorCode == -32700 ? "Invalid JSON." : "Invalid tool argument types or properties.")
                    : error.Message;
                Write(new { jsonrpc = "2.0", id, error = new { code = errorCode, message } });
            }
        }
        return 0;
    }

    private static object Call(PublishedCatalog catalog, JsonElement parameters, bool structured)
    {
        var tool = RequiredProperty(parameters, "name").GetString();
        var arguments = parameters.TryGetProperty("arguments", out var provided)
            ? provided : JsonSerializer.SerializeToElement(new { });
        if (arguments.ValueKind != JsonValueKind.Object ||
            arguments.EnumerateObject().Any(property => property.Value.ValueKind == JsonValueKind.Null))
            throw new InvalidOperationException("Tool arguments must be an object with non-null values.");

        object result = tool switch
        {
            "search_applications" => Search(catalog, arguments.Deserialize<SearchArguments>(ToolArguments)!),
            "get_application" => Get(catalog, arguments.Deserialize<GetArguments>(ToolArguments)!),
            _ => throw new InvalidOperationException("Unknown catalog tool.")
        };
        var content = new[] { new { type = "text", text = JsonSerializer.Serialize(result) } };
        return structured ? new { content, structuredContent = result } : new { content };
    }

    private static object Search(PublishedCatalog catalog, SearchArguments args)
    {
        if (args.PageSize is < 1 or > MaxPageSize || args.Offset < 0)
            throw new InvalidOperationException($"Expected pageSize between 1 and {MaxPageSize} and a non-negative offset.");
        if (args.Name != null && !ValidFilter(args.Name))
            throw new InvalidOperationException("name must be non-blank and at most 4096 characters.");
        if (args.Scopes?.Any(scope => !ValidFilter(scope)) == true)
            throw new InvalidOperationException("Each scope must be non-blank and at most 4096 characters.");

        var result = catalog.Search(new PublishedCatalogQuery(
            args.AppId == null ? null : ParseId(args.AppId, "appId"),
            args.Name,
            args.ResourceId == null ? null : ParseId(args.ResourceId, "resourceId"),
            args.Scopes,
            args.TenancyEvidence == null ? null : NativePublishedCatalogCommand.ParseTenancy(args.TenancyEvidence),
            args.IncludeNonVerified));
        var applications = result.Applications.Skip(args.Offset).Take(args.PageSize).ToArray();
        int? nextOffset = args.Offset < result.Count - applications.Length
            ? args.Offset + applications.Length : null;
        return new
        {
            result.SchemaVersion, result.CatalogRevision, result.Count,
            Offset = args.Offset, PageSize = args.PageSize, NextOffset = nextOffset,
            Applications = applications
        };
    }

    private static PublishedCatalogResult Get(PublishedCatalog catalog, GetArguments args) =>
        catalog.GetApplication(ParseId(args.AppId, "appId"), args.IncludeNonVerified);

    private static Guid ParseId(string? value, string field) =>
        value?.Length == 36 && Guid.TryParseExact(value, "D", out var id)
            ? id : throw new InvalidOperationException($"{field} must be a full hyphenated GUID.");

    private static bool ValidFilter(string? value) =>
        !string.IsNullOrWhiteSpace(value) && value.Length <= 4096;

    private static JsonElement RequiredProperty(JsonElement element, string name) =>
        element.ValueKind == JsonValueKind.Object && element.TryGetProperty(name, out var value)
            ? value : throw new InvalidOperationException($"Missing {name}.");

    private static void Write(object message)
    {
        Console.WriteLine(JsonSerializer.Serialize(message));
        Console.Out.Flush();
    }
}
