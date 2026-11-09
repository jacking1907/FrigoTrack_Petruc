using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using FrigoTrack.Common;

namespace FrigoTrack.Client;

/// <summary>Il server ha risposto con un errore (400, 401, 404...). Il corpo e' gia' decifrato, se era cifrato.</summary>
public class ServerException : Exception
{
    public int Status { get; }
    public JsonElement Body { get; }
    public string? Error => Read("error");
    public string? Field => Read("field");

    public ServerException(int status, JsonElement body)
        : base(Describe(status, body))
    {
        Status = status;
        Body = body;
    }

    private string? Read(string name)
        => Body.ValueKind == JsonValueKind.Object && Body.TryGetProperty(name, out JsonElement v)
           && v.ValueKind == JsonValueKind.String ? v.GetString() : null;

    private static string Describe(int status, JsonElement body)
    {
        if (body.ValueKind != JsonValueKind.Object) return $"{status}";
        string Get(string n) => body.TryGetProperty(n, out JsonElement v) && v.ValueKind == JsonValueKind.String ? v.GetString()! : "-";
        return $"{status}: {Get("error")} - {Get("message")} (campo: {Get("field")})";
    }
}

/// <summary>Una sessione cifrata verso il server: handshake Diffie-Hellman, poi messaggi in busta.</summary>
public class SecureClient
{
    private readonly HttpClient _http;

    public string? SessionId { get; private set; }
    public byte[]? Key { get; private set; }

    public SecureClient(HttpClient http)
    {
        _http = http;
    }

    /// <summary>Handshake: in rete vanno solo p, g, A e B. La chiave non viaggia mai.</summary>
    public async Task HandshakeAsync()
    {
        var a = Dh.CreatePrivateKey();
        var publicA = Dh.PublicKey(a);                                  // A = g^a mod p

        JsonObject request = new()
        {
            ["p"] = Dh.ToHex(Dh.P),
            ["g"] = Dh.ToHex(Dh.G),
            ["A"] = Dh.ToHex(publicA),
        };
        SchemaValidator.Validate("handshake_request", request);

        (int status, JsonElement body) = await PostAsync("/api/handshake", request);
        if (status != 200) throw new ServerException(status, body);
        SchemaValidator.Validate("handshake_response", body);

        var b = Dh.FromHex(body.GetProperty("B").GetString()!);
        if (!Dh.IsValidPublic(b)) throw new InvalidOperationException("chiave pubblica del server non valida");

        Key = Dh.DeriveKey(Dh.SharedSecret(b, a));                      // K = B^a mod p
        SessionId = body.GetProperty("session_id").GetString();
    }

    /// <summary>Valida il messaggio con lo schema, lo cifra, lo invia, decifra e valida la risposta.</summary>
    public async Task<JsonElement> CallAsync(string path, string requestSchema, string responseSchema,
                                             JsonNode message, bool localValidation = true)
    {
        if (Key == null || SessionId == null) throw new InvalidOperationException("handshake non eseguito");

        if (localValidation) SchemaValidator.Validate(requestSchema, message);      // prima si valida...
        JsonObject envelope = SecureBox.Seal(Key, SessionId, message);              // ...poi si cifra

        (int status, JsonElement body) = await PostAsync(path, envelope);
        if (body.ValueKind == JsonValueKind.Object && body.TryGetProperty("ciphertext", out _))
            body = SecureBox.Open(Key, body);                                       // risposta cifrata (ok o errore)

        if (status != 200) throw new ServerException(status, body);
        SchemaValidator.Validate(responseSchema, body);
        return body;
    }

    public Task<JsonElement> SendMeasureAsync(JsonObject measure, bool localValidation = true)
        => CallAsync("/api/telemetry", "telemetry", "telemetry_ack", measure, localValidation);

    public Task<JsonElement> ReadingsAsync(JsonObject filters)
        => CallAsync("/api/readings", "readings_request", "readings_response", filters);

    public async Task CloseAsync()
    {
        await CallAsync("/api/close", "close_request", "close_response", new JsonObject { ["action"] = "close" });
        Key = null;   // la chiave sparisce anche dal client
    }

    /// <summary>POST di basso livello (usato anche dai test per inviare buste manomesse).</summary>
    public async Task<(int Status, JsonElement Body)> PostAsync(string path, JsonNode payload)
    {
        using StringContent content = new(payload.ToJsonString(), Encoding.UTF8, "application/json");
        using HttpResponseMessage response = await _http.PostAsync(path, content);
        string text = await response.Content.ReadAsStringAsync();
        using JsonDocument doc = JsonDocument.Parse(text);
        return ((int)response.StatusCode, doc.RootElement.Clone());
    }
}
