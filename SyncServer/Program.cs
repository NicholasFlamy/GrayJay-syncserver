using Noise;
using System.Text.Json;

namespace SyncServer;

class Program
{
    static void Main()
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

        var server = new TcpSyncServer(keyPair);
        server.Start();

        Console.WriteLine("Server running. Press ENTER to stop.");
        Console.ReadLine();

        server.Stop();
    }
}
