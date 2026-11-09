using System.Globalization;
using System.Text.Json;
using System.Text.Json.Nodes;
using FrigoTrack.Common;

namespace FrigoTrack.Client;

/// <summary>
/// Simula 3 sensori, ognuno con la propria sessione (handshake indipendente, chiave propria).
/// Avvio:  dotnet run --project FrigoTrack.Client -- [--url http://127.0.0.1:5000] [--interval 2] [--count 5] [--invalid]
/// </summary>
public static class Program
{
    // sensore, tipo di merce, temperatura tipica
    private record Sensor(string Id, string Cargo, double BaseTemp);

    private static readonly Sensor[] Sensors =
    {
        new("CELLA-BG-007", "pharma", 5.0),
        new("CAMION-MI-012", "food", 2.0),
        new("CELLA-BS-003", "frozen", -21.0),
    };

    public static async Task<int> Main(string[] args)
    {
        string url = "http://127.0.0.1:5000";
        double interval = 2.0;
        int count = 5;
        bool sendInvalid = false;

        for (int i = 0; i < args.Length; i++)
        {
            switch (args[i])
            {
                case "--url": url = args[++i]; break;
                case "--interval": interval = double.Parse(args[++i], CultureInfo.InvariantCulture); break;
                case "--count": count = int.Parse(args[++i]); break;
                case "--invalid": sendInvalid = true; break;   // invia anche una misura non valida (demo)
            }
        }

        using HttpClient http = new() { BaseAddress = new Uri(url), Timeout = TimeSpan.FromSeconds(10) };
        try
        {
            await Task.WhenAll(Sensors.Select(s => RunSensor(http, s, interval, count, sendInvalid)));
            Console.WriteLine("Premi un tasto per chiudere...");
            Console.ReadKey();
            return 0;
        }
        catch (HttpRequestException e)
        {
            Console.WriteLine($"Server non raggiungibile ({e.Message}). Avviare prima il server.");
            return 1;
        }
    }

    private static async Task RunSensor(HttpClient http, Sensor sensor, double interval, int count, bool sendInvalid)
    {
        void Log(string text) => Console.WriteLine($"[{sensor.Id}] {text}");

        SecureClient client = new(http);
        await client.HandshakeAsync();
        Log($"handshake ok, sessione {client.SessionId}, chiave derivata (mai trasmessa)");

        for (int i = 0; i < count; i++)
        {
            bool spike = i == count - 1 && count > 2;       // l'ultima misura esce dall'intervallo: scatta l'allarme
            JsonObject measure = MakeMeasure(sensor, spike);
            double temperature = measure["temperature_c"]!.GetValue<double>();
            try
            {
                JsonElement ack = await client.SendMeasureAsync(measure);
                string alarm = ack.TryGetProperty("alarm", out JsonElement a)
                    ? " ALLARME: " + a.GetProperty("message").GetString() : "";
                Log(FormattableString.Invariant($"misura {i + 1}/{count}: {temperature} C -> ack{alarm}"));
            }
            catch (Exception e) when (e is ServerException or SchemaValidationException)
            {
                Log("errore: " + e.Message);
            }
            await Task.Delay(TimeSpan.FromSeconds(interval));
        }

        if (sendInvalid)
        {
            JsonObject bad = MakeMeasure(sensor, false);
            bad["temperature_c"] = 99;                       // oltre il massimo dello schema
            try
            {
                await client.SendMeasureAsync(bad, localValidation: false);   // salta il controllo locale apposta
            }
            catch (ServerException e)
            {
                Log("misura NON valida rifiutata dal server -> " + e.Message);
            }
        }

        JsonElement got = await client.ReadingsAsync(new JsonObject { ["sensor_id"] = sensor.Id, ["limit"] = 3 });
        string last = string.Join(", ", got.GetProperty("readings").EnumerateArray()
            .Select(r => r.GetProperty("temperature_c").GetDouble().ToString(CultureInfo.InvariantCulture)));
        Log($"ultime misure sul server: [{last}]");

        await client.CloseAsync();
        Log("sessione chiusa, chiave cancellata");
    }

    private static JsonObject MakeMeasure(Sensor sensor, bool spike)
    {
        Random rnd = Random.Shared;
        double temperature = sensor.BaseTemp + (rnd.NextDouble() * 1.6 - 0.8);
        if (spike) temperature += rnd.Next(2) == 0 ? -6 : 6;

        return new JsonObject
        {
            ["sensor_id"] = sensor.Id,
            ["timestamp"] = DateTimeOffset.UtcNow.ToString("yyyy-MM-dd'T'HH:mm:ss'Z'", CultureInfo.InvariantCulture),
            ["cargo_type"] = sensor.Cargo,
            ["temperature_c"] = Math.Round(temperature, 1),
            ["humidity"] = Math.Round(40 + rnd.NextDouble() * 30, 1),
            ["battery"] = rnd.Next(60, 101),
        };
    }
}
