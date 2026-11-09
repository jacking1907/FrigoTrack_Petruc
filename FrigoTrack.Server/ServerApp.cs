using System.Collections.Concurrent;
using System.Globalization;
using System.Numerics;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Nodes;
using FrigoTrack.Common;

namespace FrigoTrack.Server;

/// <summary>Errore di protocollo: diventa una risposta 400/401/404 con un messaggio conforme a schemas/error.json.</summary>
public class ProtocolException : Exception
{
    public int Status { get; }
    public string Code { get; }
    public string? Field { get; }
    public Session? Session { get; }   // se presente, l'errore viaggia cifrato

    public ProtocolException(int status, string code, string message, string? field = null, Session? session = null)
        : base(message)
    {
        Status = status;
        Code = code;
        Field = field;
        Session = session;
    }
}

/// <summary>Una sessione: ogni client ha la propria chiave, ricavata con Diffie-Hellman.</summary>
public class Session
{
    public string Id { get; }
    public byte[] Key { get; }

    public Session(string id, byte[] key)
    {
        Id = id;
        Key = key;
    }
}

/// <summary>Misure salvate in un file JSON (lista di oggetti), con scrittura atomica.</summary>
public class ReadingStore
{
    private readonly string _path;
    private readonly object _lock = new();
    private readonly List<JsonObject> _items = new();

    public ReadingStore(string path)
    {
        _path = path;
        string? dir = Path.GetDirectoryName(Path.GetFullPath(path));
        if (dir != null) Directory.CreateDirectory(dir);

        if (File.Exists(path) && JsonNode.Parse(File.ReadAllText(path)) is JsonArray existing)
            _items.AddRange(existing.Select(x => (JsonObject)x!.DeepClone()));
        else
            Flush();
    }

    public int Count { get { lock (_lock) return _items.Count; } }

    public void Add(JsonObject record)
    {
        lock (_lock)
        {
            _items.Add(record);
            Flush();
        }
    }

    public List<JsonObject> Query(string? sensorId, DateTimeOffset? from, DateTimeOffset? to, int limit)
    {
        lock (_lock)
        {
            return _items
                .Where(r => sensorId == null || (string?)r["sensor_id"] == sensorId)
                .Select(r => (Item: r, Time: DateTimeOffset.Parse((string)r["timestamp"]!, CultureInfo.InvariantCulture)))
                .Where(x => (from == null || x.Time >= from) && (to == null || x.Time <= to))
                .OrderBy(x => x.Time)
                .TakeLast(limit)
                .Select(x => (JsonObject)x.Item.DeepClone())
                .ToList();
        }
    }

    private void Flush()   // chiamare con il lock preso
    {
        JsonArray all = new(_items.Select(i => i.DeepClone()).ToArray());
        File.WriteAllText(_path, all.ToJsonString(new JsonSerializerOptions { WriteIndented = true }));
    }
}

/// <summary>
/// Server di raccolta dati. Regola di sicurezza: il server prima DECIFRA (verificando il tag),
/// poi VALIDA con JSON Schema. Se la decifratura fallisce risponde 400 senza elaborare nulla.
/// </summary>
public static class ServerApp
{

    // intervalli di sicurezza (gradi C) per tipo di merce
    private static readonly Dictionary<string, (double Min, double Max)> SafeRanges = new()
    {
        ["food"] = (0, 4),
        ["pharma"] = (2, 8),
        ["frozen"] = (-25, -18),
    };

    public static WebApplication Build(string dataFile, string url, bool log = false)
    {
        WebApplicationBuilder builder = WebApplication.CreateBuilder();
        builder.WebHost.UseUrls(url);
        builder.WebHost.ConfigureKestrel(o => o.Limits.MaxRequestBodySize = 128 * 1024);
        builder.Logging.AddFilter("Microsoft.AspNetCore", LogLevel.Warning);

        ReadingStore store = new(dataFile);
        ConcurrentDictionary<string, Session> sessions = new();
        builder.Services.AddSingleton(store);      // i test li leggono da app.Services
        builder.Services.AddSingleton(sessions);
        WebApplication app = builder.Build();

        app.MapPost("/api/handshake", Endpoint(log, ctx => Handshake(ctx, sessions)));
        app.MapPost("/api/telemetry", Endpoint(log, ctx => Telemetry(ctx, sessions, store)));
        app.MapPost("/api/readings", Endpoint(log, ctx => Readings(ctx, sessions, store)));
        app.MapPost("/api/close", Endpoint(log, ctx => Close(ctx, sessions)));

        // qualunque altro percorso o metodo: 404
        app.MapFallback(Endpoint(log, _ =>
            throw new ProtocolException(404, "not_found", "endpoint inesistente")));

        return app;
    }

    // ------------------------------------------------------------------ endpoint

    private static async Task<JsonNode> Handshake(HttpContext ctx, ConcurrentDictionary<string, Session> sessions)
    {
        JsonElement data = await ReadJsonBody(ctx, "bad_request");
        try { SchemaValidator.Validate("handshake_request", data); }
        catch (SchemaValidationException e) { throw new ProtocolException(400, "invalid_message", e.Message, e.Field); }

        BigInteger p = Dh.FromHex(data.GetProperty("p").GetString()!);
        BigInteger g = Dh.FromHex(data.GetProperty("g").GetString()!);
        BigInteger a = Dh.FromHex(data.GetProperty("A").GetString()!);

        // Accettiamo solo il gruppo noto: un p scelto dal client potrebbe essere debole.
        if (p != Dh.P)
            throw new ProtocolException(400, "invalid_message", "gruppo DH non supportato (usare RFC 3526 gruppo 14)", "p");
        if (g != Dh.G)
            throw new ProtocolException(400, "invalid_message", "generatore non supportato", "g");
        if (!Dh.IsValidPublic(a))
            throw new ProtocolException(400, "invalid_message", "chiave pubblica non valida", "A");

        BigInteger b = Dh.CreatePrivateKey();
        BigInteger bigB = Dh.PublicKey(b);                              // B = g^b mod p
        byte[] key = Dh.DeriveKey(Dh.SharedSecret(a, b));               // K = A^b mod p

        string sessionId = Convert.ToHexString(RandomNumberGenerator.GetBytes(16)).ToLowerInvariant();
        sessions[sessionId] = new Session(sessionId, key);

        JsonObject body = new() { ["session_id"] = sessionId, ["B"] = Dh.ToHex(bigB) };
        SchemaValidator.Validate("handshake_response", body);
        return body;
    }

    private static async Task<JsonNode> Telemetry(HttpContext ctx, ConcurrentDictionary<string, Session> sessions, ReadingStore store)
    {
        (Session session, JsonElement message) = await ReadEnvelope(ctx, sessions);
        ValidateMessage("telemetry", message, session);   // solo DOPO la decifratura

        string cargo = message.GetProperty("cargo_type").GetString()!;
        double temperature = message.GetProperty("temperature_c").GetDouble();
        (double min, double max) = SafeRanges[cargo];

        JsonObject? alarm = null;
        if (temperature < min || temperature > max)
        {
            string sensor = message.GetProperty("sensor_id").GetString()!;
            alarm = new JsonObject
            {
                ["type"] = "temperature_out_of_range",
                ["message"] = FormattableString.Invariant($"{sensor}: {temperature} C fuori da [{min}, {max}] per '{cargo}'"),
                ["value"] = temperature,
                ["min"] = min,
                ["max"] = max,
            };
        }

        string now = Now();
        JsonObject record = (JsonObject)JsonNode.Parse(message.GetRawText())!;
        record["received_at"] = now;
        record["alarm"] = alarm != null;
        store.Add(record);

        JsonObject ack = new() { ["status"] = "ok", ["received_at"] = now };
        if (alarm != null) ack["alarm"] = alarm;
        return Reply("telemetry_ack", session, ack);
    }

    private static async Task<JsonNode> Readings(HttpContext ctx, ConcurrentDictionary<string, Session> sessions, ReadingStore store)
    {
        (Session session, JsonElement message) = await ReadEnvelope(ctx, sessions);
        ValidateMessage("readings_request", message, session);

        string? sensorId = message.TryGetProperty("sensor_id", out JsonElement s) ? s.GetString() : null;
        DateTimeOffset? from = message.TryGetProperty("from", out JsonElement f) ? ParseTime(f) : null;
        DateTimeOffset? to = message.TryGetProperty("to", out JsonElement t) ? ParseTime(t) : null;
        int limit = message.TryGetProperty("limit", out JsonElement l) ? l.GetInt32() : 100;

        if (from != null && to != null && from > to)
            throw new ProtocolException(400, "invalid_message", "'from' deve precedere 'to'", "from", session);

        List<JsonObject> items = store.Query(sensorId, from, to, limit);
        JsonObject body = new()
        {
            ["count"] = items.Count,
            ["readings"] = new JsonArray(items.Cast<JsonNode>().ToArray()),
        };
        return Reply("readings_response", session, body);
    }

    private static async Task<JsonNode> Close(HttpContext ctx, ConcurrentDictionary<string, Session> sessions)
    {
        (Session session, JsonElement message) = await ReadEnvelope(ctx, sessions);
        ValidateMessage("close_request", message, session);

        JsonNode answer = Reply("close_response", session, new JsonObject { ["status"] = "closed" });
        sessions.TryRemove(session.Id, out _);   // la chiave viene cancellata
        return answer;
    }

    // ------------------------------------------------------------------ passi comuni

    /// <summary>Busta valida, poi sessione esistente, poi DECIFRATURA con verifica del tag.</summary>
    private static async Task<(Session, JsonElement)> ReadEnvelope(HttpContext ctx, ConcurrentDictionary<string, Session> sessions)
    {
        JsonElement envelope = await ReadJsonBody(ctx, "invalid_envelope");
        try { SchemaValidator.Validate("envelope", envelope); }
        catch (SchemaValidationException e) { throw new ProtocolException(400, "invalid_envelope", "busta non valida", e.Field); }

        string sessionId = envelope.GetProperty("session_id").GetString()!;
        if (!sessions.TryGetValue(sessionId, out Session? session))
            throw new ProtocolException(401, "unknown_session", "sessione inesistente o scaduta");

        JsonElement message;
        try
        {
            message = SecureBox.Open(session.Key, envelope);   // decifra e verifica il tag
        }
        catch (DecryptException)
        {
            throw new ProtocolException(400, "decryption_failed", "decifratura o tag non validi");
        }
        catch (PayloadException e)
        {
            // il tag era valido: possiamo rispondere cifrati
            throw new ProtocolException(400, "invalid_message", e.Message, null, session);
        }

        return (session, message);
    }

    private static void ValidateMessage(string schema, JsonElement message, Session session)
    {
        try { SchemaValidator.Validate(schema, message); }
        catch (SchemaValidationException e)
        {
            throw new ProtocolException(400, "invalid_message", e.Message, e.Field, session);
        }
    }

    /// <summary>Controlla la risposta con il suo schema e la cifra.</summary>
    private static JsonNode Reply(string schema, Session session, JsonObject body)
    {
        SchemaValidator.Validate(schema, body);   // il server rispetta i suoi stessi schemi
        return SecureBox.Seal(session.Key, session.Id, body);
    }

    private static async Task<JsonElement> ReadJsonBody(HttpContext ctx, string errorCode)
    {
        try
        {
            using JsonDocument doc = await JsonDocument.ParseAsync(ctx.Request.Body);
            return doc.RootElement.Clone();
        }
        catch (JsonException)
        {
            throw new ProtocolException(400, errorCode, "corpo non JSON");
        }
        catch (BadHttpRequestException)
        {
            throw new ProtocolException(400, errorCode, "corpo troppo grande o non valido");
        }
    }

#pragma warning disable ASP0016   // falso allarme: la risposta e' scritta da Handle, non dal valore restituito
    private static RequestDelegate Endpoint(bool log, Func<HttpContext, Task<JsonNode>> endpoint)
        => ctx => Handle(ctx, log, () => endpoint(ctx));
#pragma warning restore ASP0016

    /// <summary>Esegue un endpoint e trasforma le eccezioni di protocollo in risposte HTTP.</summary>
    private static async Task Handle(HttpContext ctx, bool log, Func<Task<JsonNode>> endpoint)
    {
        int status = 200;
        JsonNode body;
        string note = "";
        try
        {
            body = await endpoint();
        }
        catch (ProtocolException e)
        {
            status = e.Status;
            JsonObject error = new()
            {
                ["status"] = e.Status,
                ["error"] = e.Code,
                ["message"] = e.Message,
                ["field"] = e.Field,
            };
            SchemaValidator.Validate("error", error);
            // se il messaggio era stato decifrato bene, anche l'errore viaggia cifrato
            body = e.Session != null ? SecureBox.Seal(e.Session.Key, e.Session.Id, error) : error;
            note = $" {e.Code}" + (e.Field != null ? $" (campo {e.Field})" : "");
        }

        if (log) Console.WriteLine($"{DateTime.Now:HH:mm:ss} {ctx.Request.Method} {ctx.Request.Path} -> {status}{note}");

        ctx.Response.StatusCode = status;
        ctx.Response.ContentType = "application/json";
        await ctx.Response.WriteAsync(body.ToJsonString());
    }

    private static DateTimeOffset ParseTime(JsonElement e)
        => DateTimeOffset.Parse(e.GetString()!, CultureInfo.InvariantCulture);

    private static string Now() => DateTimeOffset.UtcNow.ToString("yyyy-MM-dd'T'HH:mm:ss'Z'", CultureInfo.InvariantCulture);
}
