using Noise;
using SyncClient;
using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using System.Text.Json;

internal class Program
{
    static ConcurrentBag<string> _handshakeCompleted = new ConcurrentBag<string>();

    static async Task Main(string[] args)
    {
        KeyPair keyPair1 = LoadOrGenerateKeyPair("key1.txt");
        KeyPair keyPair2 = LoadOrGenerateKeyPair("key2.txt");

        string publicKey1 = Convert.ToBase64String(keyPair1.PublicKey);
        string publicKey2 = Convert.ToBase64String(keyPair2.PublicKey);
        Console.WriteLine("Client 1 Public Key: " + publicKey1);
        Console.WriteLine("Client 2 Public Key: " + publicKey2);

        string serverPublicKey = "12rV6GgH3zRDLuHNuCSbfIdnfs2HNm8t31zPorw13zQ=";

        var socket1 = new TcpClient("127.0.0.1", 9000);
        var socketSession1 = CreateSocketSession(socket1, keyPair1, serverPublicKey);

        var socket2 = new TcpClient("127.0.0.1", 9000);
        var socketSession2 = CreateSocketSession(socket2, keyPair2, serverPublicKey);

        socketSession1.StartAsInitiator(serverPublicKey);
        socketSession2.StartAsInitiator(serverPublicKey);

        await Task.WhenAll(
            WaitForHandshake(socketSession1),
            WaitForHandshake(socketSession2)
        );

        await socketSession1.PublishConnectionInformationAsync([socketSession2.LocalPublicKey], 1000, true, true, true, true);
        await socketSession2.PublishConnectionInformationAsync([socketSession1.LocalPublicKey], 1000, true, true, true, true);

        await socketSession1.SendRequestConnectionInfoAsync(publicKey2);

        CancellationTokenSource cts = new CancellationTokenSource();
        Console.CancelKeyPress += (_, __) => cts.Cancel();
        while (!cts.IsCancellationRequested)
        {
            await Task.Delay(TimeSpan.FromSeconds(5), cts.Token);
        }
    }

    static KeyPair LoadOrGenerateKeyPair(string fileName)
    {
        try
        {
            var syncKeyPair = JsonSerializer.Deserialize<SyncKeyPair>(File.ReadAllText(fileName));
            return new KeyPair(Convert.FromBase64String(syncKeyPair!.PrivateKey), Convert.FromBase64String(syncKeyPair!.PublicKey));
        }
        catch (Exception ex)
        {
            var p = KeyPair.Generate();
            var syncKeyPair = new SyncKeyPair(1, Convert.ToBase64String(p.PublicKey), Convert.ToBase64String(p.PrivateKey));
            File.WriteAllText(fileName, JsonSerializer.Serialize(syncKeyPair));
            Logger.Error(nameof(Program), $"Failed to load existing key pair from {fileName}", ex);
            return p;
        }
    }

    static SyncSocketSession CreateSocketSession(TcpClient socket, KeyPair keyPair, string serverPublicKey)
    {
        var publicKey = Convert.ToBase64String(keyPair.PublicKey);
        var socketSession = new SyncSocketSession(
            (socket.Client.RemoteEndPoint as IPEndPoint)!.Address.ToString(),
            keyPair,
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
                Logger.Info(nameof(Program), $"Handshake complete for {publicKey} with server {remotePublicKey}");
                _handshakeCompleted.Add(publicKey);
            },
            onData: (s, opcode, subOpcode, data) =>
            {
                if (opcode == SyncSocketSession.Opcode.RESPONSE_CONNECTION_INFO)
                {
                    if (subOpcode == 0)
                    {
                        Logger.Info(nameof(Program), $"Received connection info for requested public key.");
                    }
                    else
                    {
                        Logger.Info(nameof(Program), $"Connection info request failed with error code {subOpcode}");
                    }
                }
                else
                {
                    Logger.Info(nameof(Program), $"Received data (opcode: {opcode}, subOpcode: {subOpcode})");
                }
            }
        );
        return socketSession;
    }

    static Task WaitForHandshake(SyncSocketSession session)
    {
        return Task.Run(() =>
        {
            while (!_handshakeCompleted.Contains(session.LocalPublicKey))
            {
                Thread.Sleep(100);
            }
        });
    }
}