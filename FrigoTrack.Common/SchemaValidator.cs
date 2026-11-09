using System.Collections.Concurrent;
using System.Globalization;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;

namespace FrigoTrack.Common;

/// <summary>Messaggio non valido: indica il campo sbagliato (es. "temperature_c") e il motivo.</summary>
public class SchemaValidationException : Exception
{
    /// <summary>Percorso del campo sbagliato (es. "temperature_c"), oppure null se riguarda tutto il messaggio.</summary>
    public string? Field { get; }

    public SchemaValidationException(string? field, string message) : base(message)
    {
        Field = field;
    }
}

/// <summary>
/// Validatore JSON Schema (draft 2020-12) per i vincoli usati dal progetto:
/// type, required, properties, additionalProperties, enum, const, minimum, maximum,
/// minLength, maxLength, pattern, format (date-time), items, minItems, maxItems.
/// Gli schemi stanno nella cartella schemas/, uno per ogni tipo di messaggio.
/// </summary>
public static class SchemaValidator
{
    private static readonly ConcurrentDictionary<string, JsonElement> Schemas = new();
    private static readonly ConcurrentDictionary<string, Regex> Patterns = new();

    // formato RFC 3339 rigido: 2026-11-02T08:15:30Z oppure con frazione e/o offset +01:00
    private static readonly Regex DateTimeShape = new(
        @"^[0-9]{4}-[0-9]{2}-[0-9]{2}[Tt][0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]+)?([Zz]|[+-][0-9]{2}:[0-9]{2})\z",
        RegexOptions.CultureInvariant);

    /// <summary>Cartella degli schemi (copiata accanto all'eseguibile dal progetto Common).</summary>
    public static string SchemaDirectory { get; set; } = Path.Combine(AppContext.BaseDirectory, "schemas");

    public static void Validate(string schemaName, JsonNode? instance)
        => Validate(schemaName, JsonSerializer.SerializeToElement(instance));

    public static void Validate(string schemaName, JsonElement instance)
    {
        JsonElement schema = Schemas.GetOrAdd(schemaName, name =>
        {
            string text = File.ReadAllText(Path.Combine(SchemaDirectory, name + ".json"));
            using JsonDocument doc = JsonDocument.Parse(text);
            return doc.RootElement.Clone();
        });
        Check(schema, instance, new List<string>());
    }

    // ------------------------------------------------------------------ controlli

    private static void Check(JsonElement schema, JsonElement value, List<string> path)
    {
        if (schema.ValueKind != JsonValueKind.Object) return;

        if (schema.TryGetProperty("type", out JsonElement type) && !TypeMatches(type, value))
            Fail(path, null, $"tipo errato, atteso {Describe(type)}");

        if (schema.TryGetProperty("const", out JsonElement constant) && !SameValue(constant, value))
            Fail(path, null, $"deve valere {constant.GetRawText()}");

        if (schema.TryGetProperty("enum", out JsonElement allowed)
            && !allowed.EnumerateArray().Any(a => SameValue(a, value)))
            Fail(path, null, $"valore non ammesso, ammessi: {allowed.GetRawText()}");

        switch (value.ValueKind)
        {
            case JsonValueKind.String: CheckString(schema, value.GetString()!, path); break;
            case JsonValueKind.Number: CheckNumber(schema, value.GetDouble(), path); break;
            case JsonValueKind.Object: CheckObject(schema, value, path); break;
            case JsonValueKind.Array: CheckArray(schema, value, path); break;
        }
    }

    private static void CheckString(JsonElement schema, string s, List<string> path)
    {
        int length = s.EnumerateRunes().Count();
        if (schema.TryGetProperty("minLength", out JsonElement min) && length < min.GetInt32())
            Fail(path, null, $"troppo corto (minimo {min.GetInt32()} caratteri)");
        if (schema.TryGetProperty("maxLength", out JsonElement max) && length > max.GetInt32())
            Fail(path, null, $"troppo lungo (massimo {max.GetInt32()} caratteri)");

        if (schema.TryGetProperty("pattern", out JsonElement pattern)
            && !GetRegex(pattern.GetString()!).IsMatch(s))
            Fail(path, null, $"non rispetta il pattern {pattern.GetString()}");

        if (schema.TryGetProperty("format", out JsonElement format)
            && format.GetString() == "date-time" && !IsDateTime(s))
            Fail(path, null, "non e' una data-ora valida (RFC 3339, es. 2026-11-02T08:15:30Z)");
    }

    private static void CheckNumber(JsonElement schema, double n, List<string> path)
    {
        if (schema.TryGetProperty("minimum", out JsonElement min) && n < min.GetDouble())
            Fail(path, null, $"{n.ToString(CultureInfo.InvariantCulture)} e' minore del minimo {min.GetRawText()}");
        if (schema.TryGetProperty("maximum", out JsonElement max) && n > max.GetDouble())
            Fail(path, null, $"{n.ToString(CultureInfo.InvariantCulture)} e' maggiore del massimo {max.GetRawText()}");
    }

    private static void CheckObject(JsonElement schema, JsonElement obj, List<string> path)
    {
        if (schema.TryGetProperty("required", out JsonElement required))
        {
            foreach (JsonElement name in required.EnumerateArray())
            {
                if (!obj.TryGetProperty(name.GetString()!, out _))
                    Fail(path, name.GetString(), "campo obbligatorio mancante");
            }
        }

        bool hasProperties = schema.TryGetProperty("properties", out JsonElement properties);

        if (schema.TryGetProperty("additionalProperties", out JsonElement additional))
        {
            foreach (JsonProperty p in obj.EnumerateObject())
            {
                if (hasProperties && properties.TryGetProperty(p.Name, out _)) continue;
                if (additional.ValueKind == JsonValueKind.False)
                    Fail(path, p.Name, "campo non previsto dallo schema");
                if (additional.ValueKind == JsonValueKind.Object)
                {
                    path.Add(p.Name);
                    Check(additional, p.Value, path);
                    path.RemoveAt(path.Count - 1);
                }
            }
        }

        if (hasProperties)
        {
            foreach (JsonProperty rule in properties.EnumerateObject())
            {
                if (!obj.TryGetProperty(rule.Name, out JsonElement child)) continue;
                path.Add(rule.Name);
                Check(rule.Value, child, path);
                path.RemoveAt(path.Count - 1);
            }
        }
    }

    private static void CheckArray(JsonElement schema, JsonElement array, List<string> path)
    {
        int count = array.GetArrayLength();
        if (schema.TryGetProperty("minItems", out JsonElement min) && count < min.GetInt32())
            Fail(path, null, $"servono almeno {min.GetInt32()} elementi");
        if (schema.TryGetProperty("maxItems", out JsonElement max) && count > max.GetInt32())
            Fail(path, null, $"al massimo {max.GetInt32()} elementi");

        if (schema.TryGetProperty("items", out JsonElement items))
        {
            int i = 0;
            foreach (JsonElement item in array.EnumerateArray())
            {
                path.Add(i.ToString(CultureInfo.InvariantCulture));
                Check(items, item, path);
                path.RemoveAt(path.Count - 1);
                i++;
            }
        }
    }

    // ------------------------------------------------------------------ utilita'

    private static bool TypeMatches(JsonElement type, JsonElement value)
    {
        if (type.ValueKind == JsonValueKind.Array)
            return type.EnumerateArray().Any(t => TypeMatches(t, value));

        return type.GetString() switch
        {
            "object" => value.ValueKind == JsonValueKind.Object,
            "array" => value.ValueKind == JsonValueKind.Array,
            "string" => value.ValueKind == JsonValueKind.String,
            "boolean" => value.ValueKind is JsonValueKind.True or JsonValueKind.False,
            "null" => value.ValueKind == JsonValueKind.Null,
            "number" => value.ValueKind == JsonValueKind.Number,
            // 87 e 87.0 sono interi per JSON Schema, 87.5 no
            "integer" => value.ValueKind == JsonValueKind.Number
                         && value.TryGetDouble(out double d) && double.IsFinite(d) && d == Math.Floor(d),
            _ => false,
        };
    }

    private static string Describe(JsonElement type)
        => type.ValueKind == JsonValueKind.Array
            ? string.Join(" o ", type.EnumerateArray().Select(t => t.GetString()))
            : type.GetString()!;

    private static bool SameValue(JsonElement a, JsonElement b)
    {
        if (a.ValueKind != b.ValueKind) return false;
        return a.ValueKind switch
        {
            JsonValueKind.String => a.GetString() == b.GetString(),
            JsonValueKind.Number => a.GetDouble() == b.GetDouble(),
            _ => a.GetRawText() == b.GetRawText(),
        };
    }

    private static bool IsDateTime(string s)
        => DateTimeShape.IsMatch(s)
           && DateTimeOffset.TryParse(s, CultureInfo.InvariantCulture, DateTimeStyles.None, out _);

    private static Regex GetRegex(string pattern) => Patterns.GetOrAdd(pattern, p =>
    {
        // In .NET '$' accetta anche un "\n" finale ("ABC\n" passerebbe ^[A-Z]+$).
        // In JSON Schema (ECMA-262) no: si sostituisce il '$' finale con \z.
        if (p.EndsWith('$') && !p.EndsWith("\\$")) p = p[..^1] + "\\z";
        return new Regex(p, RegexOptions.CultureInvariant, TimeSpan.FromMilliseconds(200));
    });

    private static void Fail(List<string> path, string? extra, string reason)
    {
        List<string> parts = new(path);
        if (extra != null) parts.Add(extra);
        string? field = parts.Count == 0 ? null : string.Join(".", parts);
        string where = field == null ? "messaggio" : $"campo '{field}'";
        throw new SchemaValidationException(field, $"{where} non valido: {reason}");
    }
}
