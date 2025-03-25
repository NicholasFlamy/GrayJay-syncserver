using Noise;
using SyncServer.Repositories;
using System.Text.Json;
using System.Threading.Tasks;

namespace SyncServer;

class Program
{

    private const string _dbPath = "records.db";

    static async Task Main()
    {
        KeyPair keyPair;
        try
        {
            var syncKeyPair = JsonSerializer.Deserialize<SyncKeyPair>(File.ReadAllText("key.txt"));
            keyPair = new KeyPair(Convert.FromBase64String(syncKeyPair!.PrivateKey), Convert.FromBase64String(syncKeyPair!.PublicKey));
        }
        catch (Exception ex)
        {
            // Key pair non-existing, invalid or lost
            var p = KeyPair.Generate();
            var syncKeyPair = new SyncKeyPair(1, Convert.ToBase64String(p.PublicKey), Convert.ToBase64String(p.PrivateKey));
            File.WriteAllText("key.txt", JsonSerializer.Serialize(syncKeyPair));
            Logger.Error(nameof(Program), "Failed to load existing key pair", ex);
            keyPair = p;
        }

        var publicKey = Convert.ToBase64String(keyPair.PublicKey);
        Console.WriteLine("Public Key: " + publicKey);

        var connectionString = $"Data Source={_dbPath};Pooling=False;";
        using var recordRepository = new SqliteRecordRepository(connectionString);
        await recordRepository.InitializeAsync();

        using var server = new TcpSyncServer(9000, keyPair, recordRepository);
        server.Start();

        Console.WriteLine("Server running. Press ENTER to stop.");
        Console.ReadLine();
    }
}
