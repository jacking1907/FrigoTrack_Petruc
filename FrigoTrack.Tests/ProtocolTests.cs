using System.Text.Json;
using System.Text.Json.Nodes;
using FrigoTrack.Client;
using FrigoTrack.Common;
using Xunit;

namespace FrigoTrack.Tests;

/// <summary>Test di protocollo: server e client veri, che si parlano in HTTP.</summary>
public class ProtocolTests : IDisposable
{
    private readonly TestServer _srv = new();

    public void Dispose() => _srv.Dispose();

    private static JsonObject Good() => new()
    {
        ["sensor_id"] = "CELLA-BG-007",
        ["timestamp"] = "2026-11-02T08:15:30Z",
        ["cargo_type"] = "pharma",
        ["temperature_c"] = 4.6,
        ["humidity"] = 55,
        ["battery"] = 87,
    };

    private static string? Str(JsonElement e, string name) => e.GetProperty(name).GetString();

    // ------------------------------------------------------------ 1. handshake riuscito

    [Fact]
    public async Task Handshake_ok_stessa_chiave_su_entrambi_i_lati()
    {
        SecureClient client = await _srv.NewSessionAsync();

        Assert.Equal(32, client.Key!.Length);
        Assert.Equal(client.Key, _srv.Sessions[client.SessionId!].Key);
    }

    [Fact]
    public async Task Handshake_sessioni_diverse_hanno_chiavi_diverse()
    {
        SecureClient a = await _srv.NewSessionAsync();
        SecureClient b = await _srv.NewSessionAsync();

        Assert.NotEqual(a.SessionId, b.SessionId);
        Assert.NotEqual(a.Key, b.Key);
    }

    [Fact]
    public async Task Handshake_rifiuta_un_gruppo_non_supportato()
    {
        SecureClient client = new(_srv.Http);
        (int status, JsonElement body) = await client.PostAsync("/api/handshake",
            new JsonObject { ["p"] = "17", ["g"] = "2", ["A"] = "5" });

        Assert.Equal(400, status);
        Assert.Equal("p", Str(body, "field"));
    }

    [Fact]
    public async Task Handshake_rifiuta_una_chiave_pubblica_banale()
    {
        SecureClient client = new(_srv.Http);
        (int status, JsonElement body) = await client.PostAsync("/api/handshake",
            new JsonObject { ["p"] = Dh.ToHex(Dh.P), ["g"] = "2", ["A"] = "1" });

        Assert.Equal(400, status);
        Assert.Equal("A", Str(body, "field"));
    }

    // ------------------------------------------------------------ 2. messaggio valido

    [Fact]
    public async Task Misura_valida_riceve_ack_e_viene_salvata()
    {
        SecureClient client = await _srv.NewSessionAsync();

        JsonElement ack = await client.SendMeasureAsync(Good());

        Assert.Equal("ok", Str(ack, "status"));
        Assert.False(ack.TryGetProperty("alarm", out _));
        Assert.Equal(1, _srv.Store.Count);
        Assert.Contains("CELLA-BG-007", File.ReadAllText(_srv.DataFile));
    }

    [Fact]
    public async Task Allarme_se_i_farmaci_escono_dall_intervallo()
    {
        SecureClient client = await _srv.NewSessionAsync();
        JsonObject hot = Good();
        hot["temperature_c"] = 12.0;

        JsonElement ack = await client.SendMeasureAsync(hot);

        JsonElement alarm = ack.GetProperty("alarm");
        Assert.Equal("temperature_out_of_range", Str(alarm, "type"));
        Assert.Equal(2.0, alarm.GetProperty("min").GetDouble());
        Assert.Equal(8.0, alarm.GetProperty("max").GetDouble());
    }

    // ------------------------------------------------------------ 3. messaggio non valido

    [Theory]
    [InlineData("temperature_c", "99")]
    [InlineData("cargo_type", "\"armi\"")]
    [InlineData("sensor_id", "\"cella-1\"")]
    [InlineData("timestamp", "\"ieri\"")]
    [InlineData("battery", "50.5")]
    [InlineData("extra", "1")]
    public async Task Misura_non_valida_viene_rifiutata_indicando_il_campo(string field, string rawJson)
    {
        SecureClient client = await _srv.NewSessionAsync();
        JsonObject bad = Good();
        bad[field] = JsonNode.Parse(rawJson);

        ServerException e = await Assert.ThrowsAsync<ServerException>(
            () => client.SendMeasureAsync(bad, localValidation: false));   // salta il controllo locale

        Assert.Equal(400, e.Status);
        Assert.Equal(field, e.Field);
        Assert.Equal(0, _srv.Store.Count);
    }

    [Fact]
    public async Task Campo_obbligatorio_mancante()
    {
        SecureClient client = await _srv.NewSessionAsync();
        JsonObject bad = Good();
        bad.Remove("cargo_type");

        ServerException e = await Assert.ThrowsAsync<ServerException>(
            () => client.SendMeasureAsync(bad, localValidation: false));

        Assert.Equal("cargo_type", e.Field);
    }

    [Fact]
    public async Task Il_client_valida_lo_schema_prima_di_cifrare()
    {
        SecureClient client = await _srv.NewSessionAsync();
        JsonObject bad = Good();
        bad["temperature_c"] = 99;

        SchemaValidationException e = await Assert.ThrowsAsync<SchemaValidationException>(
            () => client.SendMeasureAsync(bad));

        Assert.Equal("temperature_c", e.Field);
        Assert.Equal(0, _srv.Store.Count);   // non e' nemmeno partito
    }

    [Fact]
    public async Task NaN_non_supera_i_limiti_di_minimum_e_maximum()
    {
        SecureClient client = await _srv.NewSessionAsync();
        // JSON non valido (NaN), ma cifrato correttamente: il tag e' valido, il contenuto no
        string raw = Good().ToJsonString().Replace("4.6", "NaN");
        JsonObject envelope = SecureBox.SealText(client.Key!, client.SessionId!, raw);

        (int status, JsonElement body) = await client.PostAsync("/api/telemetry", envelope);

        Assert.Equal(400, status);
        JsonElement error = SecureBox.Open(client.Key!, body);   // l'errore e' cifrato
        Assert.Equal("invalid_message", Str(error, "error"));
    }

    // ------------------------------------------------------------ 4. busta manomessa

    [Fact]
    public async Task Busta_manomessa_da_400_senza_elaborare_nulla()
    {
        SecureClient client = await _srv.NewSessionAsync();
        JsonObject envelope = SecureBox.Seal(client.Key!, client.SessionId!, Good());
        byte[] cipher = Convert.FromBase64String((string)envelope["ciphertext"]!);
        cipher[0] ^= 0x01;                                        // un solo bit cambiato
        envelope["ciphertext"] = Convert.ToBase64String(cipher);

        (int status, JsonElement body) = await client.PostAsync("/api/telemetry", envelope);

        Assert.Equal(400, status);
        Assert.Equal("decryption_failed", Str(body, "error"));
        Assert.Equal(0, _srv.Store.Count);                        // nulla e' stato elaborato
    }

    [Fact]
    public async Task Tag_alterato_da_400()
    {
        SecureClient client = await _srv.NewSessionAsync();
        JsonObject envelope = SecureBox.Seal(client.Key!, client.SessionId!, Good());
        envelope["tag"] = new string('A', 22) + "==";

        (int status, JsonElement body) = await client.PostAsync("/api/telemetry", envelope);

        Assert.Equal(400, status);
        Assert.Equal("decryption_failed", Str(body, "error"));
    }

    [Fact]
    public async Task Busta_spostata_su_un_altra_sessione_viene_rifiutata()
    {
        SecureClient a = await _srv.NewSessionAsync();
        SecureClient b = await _srv.NewSessionAsync();
        JsonObject envelope = SecureBox.Seal(a.Key!, a.SessionId!, Good());
        envelope["session_id"] = b.SessionId;                     // chiave diversa e AAD diverso

        (int status, JsonElement body) = await a.PostAsync("/api/telemetry", envelope);

        Assert.Equal(400, status);
        Assert.Equal("decryption_failed", Str(body, "error"));
    }


    [Fact]
    public async Task Busta_con_campi_mancanti_da_400()
    {
        SecureClient client = await _srv.NewSessionAsync();

        (int status, JsonElement body) = await client.PostAsync("/api/telemetry",
            new JsonObject { ["session_id"] = client.SessionId });

        Assert.Equal(400, status);
        Assert.Equal("invalid_envelope", Str(body, "error"));
    }

    // ------------------------------------------------------------ 5. sessione inesistente

    [Fact]
    public async Task Sessione_inesistente_da_401()
    {
        SecureClient client = await _srv.NewSessionAsync();
        JsonObject envelope = SecureBox.Seal(client.Key!, "deadbeef", Good());

        (int status, JsonElement body) = await client.PostAsync("/api/telemetry", envelope);

        Assert.Equal(401, status);
        Assert.Equal("unknown_session", Str(body, "error"));
    }

    [Fact]
    public async Task Dopo_close_la_sessione_e_la_chiave_non_esistono_piu()
    {
        SecureClient client = await _srv.NewSessionAsync();
        string sessionId = client.SessionId!;
        byte[] key = client.Key!;

        await client.CloseAsync();

        Assert.False(_srv.Sessions.ContainsKey(sessionId));
        (int status, _) = await client.PostAsync("/api/telemetry", SecureBox.Seal(key, sessionId, Good()));
        Assert.Equal(401, status);
    }

    // ------------------------------------------------------------ 404, readings, riservatezza

    [Fact]
    public async Task Endpoint_inesistente_da_404()
    {
        SecureClient client = new(_srv.Http);

        (int status, JsonElement body) = await client.PostAsync("/api/nope", new JsonObject());
        Assert.Equal(404, status);
        Assert.Equal("not_found", Str(body, "error"));

        HttpResponseMessage get = await _srv.Http.GetAsync("/api/telemetry");   // metodo sbagliato
        Assert.Equal(404, (int)get.StatusCode);
    }

    [Fact]
    public async Task Readings_filtra_per_sensore_intervallo_e_limite()
    {
        SecureClient client = await _srv.NewSessionAsync();
        JsonObject m1 = Good(); m1["timestamp"] = "2026-11-02T08:00:00Z";
        JsonObject m2 = Good(); m2["timestamp"] = "2026-11-02T09:00:00Z"; m2["temperature_c"] = 5.0;
        JsonObject m3 = Good(); m3["sensor_id"] = "CAMION-MI-012"; m3["cargo_type"] = "food"; m3["temperature_c"] = 2.0;
        foreach (JsonObject m in new[] { m1, m2, m3 }) await client.SendMeasureAsync(m);

        JsonElement all = await client.ReadingsAsync(new JsonObject { ["sensor_id"] = "CELLA-BG-007" });
        Assert.Equal(2, all.GetProperty("count").GetInt32());

        JsonElement last = await client.ReadingsAsync(new JsonObject { ["sensor_id"] = "CELLA-BG-007", ["limit"] = 1 });
        Assert.Equal(5.0, last.GetProperty("readings")[0].GetProperty("temperature_c").GetDouble());

        JsonElement later = await client.ReadingsAsync(new JsonObject
        {
            ["sensor_id"] = "CELLA-BG-007",
            ["from"] = "2026-11-02T08:30:00Z",
        });
        Assert.Equal(1, later.GetProperty("count").GetInt32());
    }

    [Fact]
    public async Task Readings_con_richiesta_non_valida_indica_il_campo()
    {
        SecureClient client = await _srv.NewSessionAsync();

        ServerException e = await Assert.ThrowsAsync<ServerException>(() =>
            client.CallAsync("/api/readings", "readings_request", "readings_response",
                             new JsonObject { ["limit"] = 0 }, localValidation: false));

        Assert.Equal("limit", e.Field);
    }

    [Fact]
    public async Task In_rete_non_compare_nessun_dato_in_chiaro_tranne_il_session_id()
    {
        SecureClient client = await _srv.NewSessionAsync();

        JsonObject envelope = SecureBox.Seal(client.Key!, client.SessionId!, Good());
        string wire = envelope.ToJsonString();

        Assert.DoesNotContain("CELLA-BG-007", wire);
        Assert.DoesNotContain("pharma", wire);
        Assert.Equal(new[] { "session_id", "nonce", "ciphertext", "tag" }, envelope.Select(p => p.Key).ToArray());
    }
}
