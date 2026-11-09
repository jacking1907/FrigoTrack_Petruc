namespace FrigoTrack.Server;

/// <summary>
/// Avvio:  dotnet run --project FrigoTrack.Server -- [--host 127.0.0.1] [--port 5000] [--data data/readings.json]
/// </summary>
public static class Program
{
    public static void Main(string[] args)
    {
        string host = "127.0.0.1";
        int port = 5000;
        string dataFile = "data/readings.json";

        for (int i = 0; i < args.Length - 1; i++)
        {
            switch (args[i])
            {
                case "--host": host = args[++i]; break;
                case "--port": port = int.Parse(args[++i]); break;
                case "--data": dataFile = args[++i]; break;
            }
        }

        WebApplication app = ServerApp.Build(dataFile, $"http://{host}:{port}", log: true);
        app.Run();
    }
}
