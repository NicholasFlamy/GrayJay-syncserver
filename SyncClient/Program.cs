using Noise;
using SyncClient;
using System.Net;
using System.Net.Sockets;
using System.Text.Json;

internal class Program
{
    static async Task Main(string[] args)
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

        bool handshakeComplete = false;
        var publicKey = Convert.ToBase64String(keyPair.PublicKey);
        Console.WriteLine("Public Key: " + publicKey);
        var socket = new TcpClient("127.0.0.1", 9000);
        var socketSession = new SyncSocketSession((socket.Client.RemoteEndPoint as IPEndPoint)!.Address.ToString(), keyPair,
            socket.GetStream(),
            socket.GetStream(),
            onClose: s => { },
            onHandshakeComplete: s =>
            {
                var remotePublicKey = s.RemotePublicKey;
                if (remotePublicKey == null)
                {
                    s.Stop();
                    return;
                }

                Logger.Info(nameof(Program), $"Handshake complete with (LocalPublicKey = {s.LocalPublicKey}, RemotePublicKey = {s.RemotePublicKey})");
                handshakeComplete = true;
            },
            onData: (s, opcode, subOpcode, data) =>
            {
                Logger.Info(nameof(Program), $"Received data (opcode: {opcode}, subOpcode: {subOpcode})");
            });

        socketSession.StartAsInitiator("c48kEsdhkvdmSuj7ZpwYem2Em6EHBzqHVRmKjDTWdlA=");

        CancellationTokenSource cts = new CancellationTokenSource();
        Console.CancelKeyPress += (_, __) => cts.Cancel();
        while (!cts.IsCancellationRequested)
        {
            if (handshakeComplete)
                await socketSession.SendAsync(SyncSocketSession.Opcode.PING, cancellationToken: cts.Token);
            await Task.Delay(TimeSpan.FromSeconds(5), cts.Token);
        }
    }
}