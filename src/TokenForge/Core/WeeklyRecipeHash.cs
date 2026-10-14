using System;
using System.Globalization;
using System.IO;
using System.Security.Cryptography;
using System.Text.Encodings.Web;
using System.Text.Json;

namespace TokenForge.Core;

public static class WeeklyRecipeHash
{
    public static string Compute(string json) => Convert.ToHexString(SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(Canonical(json)))).ToLowerInvariant();
    public static string Canonical(string json)
    {
        if (System.Text.Encoding.UTF8.GetByteCount(json)>128*1024*1024) throw new InvalidOperationException("Invalid weekly recipe.");
        using var document = JsonDocument.Parse(json, new JsonDocumentOptions{MaxDepth=100});
        var root = document.RootElement;
        bool modern = root.TryGetProperty("Discovery", out var discovery) && discovery.GetProperty("SchemaVersion").GetInt32() == 2;
        using var stream = new MemoryStream();
        using (var writer = new Utf8JsonWriter(stream, new JsonWriterOptions { Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping }))
        {
            Write(writer, root, modern, ""); writer.Flush();
        }
        return System.Text.Encoding.UTF8.GetString(stream.ToArray());
    }
    private static void Write(Utf8JsonWriter writer, JsonElement value, bool modern, string path)
    {
        switch (value.ValueKind)
        {
            case JsonValueKind.Object:
                writer.WriteStartObject();
                foreach (var field in value.EnumerateObject()) { writer.WritePropertyName(field.Name); Write(writer, field.Value, modern, path + "/" + field.Name); }
                writer.WriteEndObject(); break;
            case JsonValueKind.Array:
                writer.WriteStartArray(); foreach (var item in value.EnumerateArray()) Write(writer, item, modern, path + "[]"); writer.WriteEndArray(); break;
            case JsonValueKind.String:
                string text = value.GetString()!;
                bool date = modern ? path is "/CreatedAt" or "/Discovery/FetchedAt" : System.Text.RegularExpressions.Regex.IsMatch(text, @"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,7})?(?:[Zz]|[+-][0-9]{2}(?::?[0-9]{2})?)?\z");
                if (date && (modern ? DateTimeOffset.TryParse(text, CultureInfo.InvariantCulture, DateTimeStyles.None, out var parsed) : LegacyDate(text, out parsed)))
                {
                    parsed = parsed.ToUniversalTime();
                    if (modern) text = parsed.ToString("o", CultureInfo.InvariantCulture);
                    else
                    {
                        long fraction = parsed.Ticks % TimeSpan.TicksPerSecond;
                        text = parsed.ToString("yyyy-MM-dd'T'HH:mm:ss", CultureInfo.InvariantCulture) + (fraction == 0 ? "" : "." + fraction.ToString("D7").TrimEnd('0')) + "+00:00";
                    }
                }
                writer.WriteRawValue(Quote(text), skipInputValidation: false); break;
            case JsonValueKind.Number:
                if (value.TryGetInt64(out long integer)) writer.WriteNumberValue(integer);
                else
                {
                    string number = value.GetDouble().ToString("R", CultureInfo.InvariantCulture);
                    if (!number.Contains('.') && !number.Contains('E')) number += ".0";
                    writer.WriteRawValue(number);
                }
                break;
            case JsonValueKind.True: writer.WriteBooleanValue(true); break;
            case JsonValueKind.False: writer.WriteBooleanValue(false); break;
            case JsonValueKind.Null: writer.WriteNullValue(); break;
            default: throw new InvalidOperationException();
        }
    }
    private static bool LegacyDate(string text, out DateTimeOffset parsed)
    {
        parsed=default;
        // Newtonsoft accepts hour24 rollover and arithmetical two-digit offsets
        // beyond DateTimeOffset's ±14-hour range in literal legacy metadata.
        var match=System.Text.RegularExpressions.Regex.Match(text,@"^(?<date>[0-9]{4}-[0-9]{2}-[0-9]{2})T(?<hour>[0-9]{2}):(?<minute>[0-9]{2}):(?<second>[0-9]{2})(?<fraction>\.[0-9]{1,7})?(?<zone>[Zz]|[+-][0-9]{2}(?::?[0-9]{2})?)?\z");
        if(!match.Success)return false;
        try
        {
            int hour=int.Parse(match.Groups["hour"].Value,CultureInfo.InvariantCulture);
            bool rollover=hour==24;
            if(hour>24 || rollover && (match.Groups["minute"].Value!="00" || match.Groups["second"].Value!="00" || match.Groups["fraction"].Success && match.Groups["fraction"].Value.Trim('0','.').Length!=0))return false;
            string clock=match.Groups["date"].Value+"T"+(rollover ? "00" : match.Groups["hour"].Value)+":"+match.Groups["minute"].Value+":"+match.Groups["second"].Value+match.Groups["fraction"].Value;
            var date=DateTime.ParseExact(clock,new[]{"yyyy-MM-dd'T'HH:mm:ss","yyyy-MM-dd'T'HH:mm:ss.FFFFFFF"},CultureInfo.InvariantCulture,DateTimeStyles.None);
            if(rollover)date=date.AddDays(1);
            string zone=match.Groups["zone"].Value;
            if(zone.Length==0)date=date.ToUniversalTime();
            else if(zone!="Z" && zone!="z")
            {
                string digits=zone.Substring(1).Replace(":","");
                int minutes=int.Parse(digits.Substring(0,2),CultureInfo.InvariantCulture)*60+(digits.Length==4 ? int.Parse(digits.Substring(2,2),CultureInfo.InvariantCulture) : 0);
                long adjusted=date.Ticks+(zone[0]=='+' ? -1L : 1L)*minutes*TimeSpan.TicksPerMinute;
                date=new DateTime(Math.Clamp(adjusted,DateTime.MinValue.Ticks,DateTime.MaxValue.Ticks));
            }
            parsed=new DateTimeOffset(DateTime.SpecifyKind(date,DateTimeKind.Utc));return true;
        }
        catch {return false;}
    }
    private static string Quote(string text)
    {
        // Newtonsoft's default string escaping used by ConvertTo-Json preserves
        // Unicode, including NBSP and C1 characters, except its line separators.
        var output = new System.Text.StringBuilder("\"");
        foreach (char c in text)
        {
            switch(c)
            {
                case '"': output.Append("\\\""); break;
                case '\\': output.Append("\\\\"); break;
                case '\b': output.Append("\\b"); break;
                case '\f': output.Append("\\f"); break;
                case '\n': output.Append("\\n"); break;
                case '\r': output.Append("\\r"); break;
                case '\t': output.Append("\\t"); break;
                default:
                    if(c < 32 || c is '\u0085' or '\u2028' or '\u2029')
                        output.Append("\\u").Append(((int)c).ToString("x4", CultureInfo.InvariantCulture));
                    else output.Append(c);
                    break;
            }
        }
        return output.Append('"').ToString();
    }

}
