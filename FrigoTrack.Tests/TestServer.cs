using System.Collections.Concurrent;
using FrigoTrack.Client;
using FrigoTrack.Server;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;

namespace FrigoTrack.Tests;

/// <summary>Avvia un server vero (porta libera scelta dal sistema) per la durata di un test.</summary>
public sealed class TestServer : IDisposable
{
    private readonly string _dir = Path.Combine(Path.GetTempPath(), "frigotrack-test-" + Guid.NewGuid().ToString("N"));
    private readonly WebApplication _app;

    public string DataFile { get; }
    public HttpClient Http { get; }
    public ReadingStore Store => _app.Services.GetRequiredService<ReadingStore>();
    public ConcurrentDictionary<string, Session> Sessions => _app.Services.GetRequiredService<ConcurrentDictionary<string, Session>>();

    public TestServer()
    {
        DataFile = Path.Combine(_dir, "readings.json");
        _app = ServerApp.Build(DataFile, "http://127.0.0.1:0");
        _app.StartAsync().GetAwaiter().GetResult();
        Http = new HttpClient { BaseAddress = new Uri(_app.Urls.First()) };
    }

    /// <summary>Un client con handshake gia' eseguito.</summary>
    public async Task<SecureClient> NewSessionAsync()
    {
        SecureClient client = new(Http);
        await client.HandshakeAsync();
        return client;
    }

    public void Dispose()
    {
        Http.Dispose();
        _app.StopAsync().GetAwaiter().GetResult();
        _app.DisposeAsync().AsTask().GetAwaiter().GetResult();
        try { Directory.Delete(_dir, recursive: true); } catch (IOException) { }
    }
}
