using System.Numerics;
using System.Text.Json.Nodes;
using FrigoTrack.Common;
using Xunit;

namespace FrigoTrack.Tests;

/// <summary>Test dei singoli moduli: Diffie-Hellman, cifratura, validazione.</summary>
public class UnitTests
{
    private static JsonObject Good() => new()
    {
        ["sensor_id"] = "CELLA-BG-007",
        ["timestamp"] = "2026-11-02T08:15:30Z",
        ["cargo_type"] = "pharma",
        ["temperature_c"] = 4.6,
    };

    // ------------------------------------------------------------ Diffie-Hellman

    [Fact]
    public void Dh_client_e_server_ottengono_lo_stesso_segreto()
    {
        BigInteger a = Dh.CreatePrivateKey(), b = Dh.CreatePrivateKey();
        BigInteger bigA = Dh.PublicKey(a), bigB = Dh.PublicKey(b);

        Assert.Equal(Dh.SharedSecret(bigB, a), Dh.SharedSecret(bigA, b));
        Assert.Equal(2048L, Dh.P.GetBitLength());
    }

    [Fact]
    public void Dh_esadecimale_andata_e_ritorno()
    {
        BigInteger n = Dh.CreatePrivateKey();
        Assert.Equal(n, Dh.FromHex(Dh.ToHex(n)));
    }

    // ------------------------------------------------------------ cifratura

    [Fact]
    public void Cifratura_andata_e_ritorno()
    {
        byte[] key = Dh.DeriveKey(12345);
        JsonObject envelope = SecureBox.Seal(key, "abcd1234", Good());

        var opened = SecureBox.Open(key, System.Text.Json.JsonSerializer.SerializeToElement(envelope));

        Assert.Equal("CELLA-BG-007", opened.GetProperty("sensor_id").GetString());
    }

    [Fact]
    public void Chiave_sbagliata_non_decifra()
    {
        JsonObject envelope = SecureBox.Seal(Dh.DeriveKey(1), "abcd1234", Good());

        Assert.Throws<DecryptException>(() =>
            SecureBox.Open(Dh.DeriveKey(2), System.Text.Json.JsonSerializer.SerializeToElement(envelope)));
    }

    // ------------------------------------------------------------ JSON Schema

    [Fact]
    public void Schema_misura_valida()
    {
        SchemaValidator.Validate("telemetry", Good());
    }

    [Fact]
    public void Schema_pattern_non_accetta_un_newline_finale()
    {
        JsonObject bad = Good();
        bad["sensor_id"] = "CELLA-BG-007\n";

        SchemaValidationException e = Assert.Throws<SchemaValidationException>(() => SchemaValidator.Validate("telemetry", bad));

        Assert.Equal("sensor_id", e.Field);
    }

    [Theory]
    [InlineData("2026-11-02T08:15:30Z", true)]
    [InlineData("2026-11-02T08:15:30.250+01:00", true)]
    [InlineData("2026-11-02 08:15:30", false)]
    [InlineData("2026-13-45T00:00:00Z", false)]
    [InlineData("02/11/2026", false)]
    public void Schema_date_time_rigoroso(string timestamp, bool valid)
    {
        JsonObject m = Good();
        m["timestamp"] = timestamp;

        if (valid) SchemaValidator.Validate("telemetry", m);
        else Assert.Throws<SchemaValidationException>(() => SchemaValidator.Validate("telemetry", m));
    }

    [Fact]
    public void Schema_intero_con_parte_decimale_nulla_e_accettato()
    {
        JsonObject ok = Good();
        ok["battery"] = JsonNode.Parse("87.0");
        SchemaValidator.Validate("telemetry", ok);

        JsonObject bad = Good();
        bad["battery"] = JsonNode.Parse("87.5");
        Assert.Throws<SchemaValidationException>(() => SchemaValidator.Validate("telemetry", bad));
    }

    [Fact]
    public void Schema_vincoli_minimum_e_maximum()
    {
        JsonObject cold = Good();
        cold["temperature_c"] = -41;
        JsonObject hot = Good();
        hot["temperature_c"] = 40.1;

        Assert.Equal("temperature_c", Assert.Throws<SchemaValidationException>(() => SchemaValidator.Validate("telemetry", cold)).Field);
        Assert.Equal("temperature_c", Assert.Throws<SchemaValidationException>(() => SchemaValidator.Validate("telemetry", hot)).Field);
    }

    [Fact]
    public void Schema_campo_extra_e_campo_mancante()
    {
        JsonObject extra = Good();
        extra["colore"] = "blu";
        JsonObject missing = Good();
        missing.Remove("timestamp");

        Assert.Equal("colore", Assert.Throws<SchemaValidationException>(() => SchemaValidator.Validate("telemetry", extra)).Field);
        Assert.Equal("timestamp", Assert.Throws<SchemaValidationException>(() => SchemaValidator.Validate("telemetry", missing)).Field);
    }
}
