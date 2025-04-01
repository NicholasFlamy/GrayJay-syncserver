using Noise;
using SyncClient;
using SyncShared;
using System;
using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;

namespace ServerLoadTest
{
    internal class Program
    {
        // Server configuration
        private static readonly string ServerPublicKey = "xGbHRzDOvE6plRbQaFgSen82eijF+gxS0yeUaeEErkw=";
        private static int NumPairs = 500; // Number of client pairs; adjust to scale load
        private static readonly ConcurrentBag<string> HandshakeCompleted = new ConcurrentBag<string>();
        private static int ActiveClients = 0;

        static async Task Main(string[] args)
        {
            int numClients = NumPairs * 2;
            List<KeyPair> keyPairs = new List<KeyPair>();
            List<SyncSocketSession> sessions = new List<SyncSocketSession>();
            Dictionary<SyncSocketSession, string> sessionToPeer = new Dictionary<SyncSocketSession, string>();

            _ = Task.Run(async () =>
            {
                while (true)
                {
                    await Task.Delay(5000); // Report every 5 seconds
                    var now = DateTime.Now;

                    double avgLatency = Metrics.DataLatencies.Any() ? Metrics.DataLatencies.Average() : 0;
                    long missingPackets = Metrics.MissingPackets;
                    int disconnections = Metrics.Disconnections.Count;

                    Console.WriteLine(
                        $"[{now}] Clients: {ActiveClients}, " +
                        $"Avg Latency: {avgLatency:F2}ms, " +
                        $"Missing Packets: {missingPackets}, " +
                        $"Disconnections: {disconnections}");
                }
            });

            for (int i = 0; i < numClients; i++)
            {
                KeyPair keyPair = KeyPair.Generate(); // Generate in-memory key pair
                keyPairs.Add(keyPair);
                var socket = new TcpClient("relay.grayjay.app", 9000); // Connect to server
                var session = CreateSocketSession(socket, keyPair, ServerPublicKey, sessionToPeer);
                sessions.Add(session);
                _ = session.StartAsInitiatorAsync(ServerPublicKey); // Initiate handshake
                ActiveClients++;
                await Task.Delay(1);
            }

            for (int i = 0; i < numClients; i += 2)
            {
                string pubKey1 = Convert.ToBase64String(keyPairs[i].PublicKey);
                string pubKey2 = Convert.ToBase64String(keyPairs[i + 1].PublicKey);
                sessionToPeer[sessions[i]] = pubKey2;
                sessionToPeer[sessions[i + 1]] = pubKey1;
            }

            await Task.WhenAll(sessions.Select(s => WaitForHandshake(s)));
            Console.WriteLine($"All {numClients} handshakes completed.");

            for (int i = 0; i < numClients; i += 2)
            {
                var session1 = sessions[i];
                var publicKey2 = Convert.ToBase64String(keyPairs[i + 1].PublicKey);
                await session1.StartRelayedChannelAsync(publicKey2);
                Console.WriteLine($"Started channel from client {i} to client {i + 1}");
            }

            CancellationTokenSource cts = new CancellationTokenSource();
            Console.CancelKeyPress += (_, __) => cts.Cancel();
            Console.WriteLine($"Running with {NumPairs} pairs ({numClients} clients). Press Ctrl+C to stop.");
            await Task.Delay(-1, cts.Token);
        }

        /// <summary>
        /// Creates a socket session with handlers for handshake, data, and channel events.
        /// </summary>
        private static SyncSocketSession CreateSocketSession(
            TcpClient socket,
            KeyPair keyPair,
            string serverPublicKey,
            Dictionary<SyncSocketSession, string> sessionToPeer)
        {
            var publicKey = Convert.ToBase64String(keyPair.PublicKey);
            var socketSession = new SyncSocketSession(
                (socket.Client.RemoteEndPoint as System.Net.IPEndPoint)!.Address.ToString(),
                keyPair,
                socket.GetStream(),
                socket.GetStream(),
                onClose: s => { Metrics.Disconnections.Add(s.LocalPublicKey); }, // Track disconnections
                onHandshakeComplete: s =>
                {
                    // Measure handshake time
                    HandshakeCompleted.Add(s.LocalPublicKey);
                },
                onData: (s, opcode, subOpcode, data) => { /* Optional: Log non-channel data */ },
                onNewChannel: (s, c) =>
                {
                    // Start sending data at ~1 kb/s
                    int sequenceNumber = 0;
                    Task.Run(async () =>
                    {
                        await Task.Delay(TimeSpan.FromSeconds(5));

                        while (true)
                        {
                            long timestamp = DateTime.UtcNow.Ticks;
                            int seq = Interlocked.Increment(ref sequenceNumber);
                            byte[] dataToSend = new byte[1000];
                            BitConverter.GetBytes(timestamp).CopyTo(dataToSend, 0); // 8 bytes
                            BitConverter.GetBytes(seq).CopyTo(dataToSend, 8);       // 4 bytes
                            Array.Fill(dataToSend, (byte)0xFF, 12, 88);            // 88 bytes dummy data
                            await c.SendRelayedDataAsync(Opcode.DATA, 0, dataToSend);
                            await Task.Delay(1000);
                        }
                    });

                    // Handle received data
                    c.SetDataHandler((session, channel, opcode, subOpcode, data) =>
                    {
                        if (data.Length < 12) return; // Ensure data has timestamp and sequence
                        long sentTimestamp = BinaryPrimitives.ReadInt64LittleEndian(data);
                        int seq = BinaryPrimitives.ReadInt32LittleEndian(data.Slice(8));
                        long receivedTimestamp = DateTime.UtcNow.Ticks;
                        double latencyMs = (receivedTimestamp - sentTimestamp) / (double)TimeSpan.TicksPerMillisecond;
                        Metrics.DataLatencies.Add(latencyMs);

                        // Check for missing packets
                        string senderKey = sessionToPeer[session]; // Peer is the sender
                        string receiverKey = session.LocalPublicKey;
                        string key = $"{senderKey}->{receiverKey}";
                        int lastSeq = Metrics.LastSequenceNumbers.GetOrAdd(key, 0);
                        if (seq > lastSeq + 1)
                        {
                            int missing = seq - lastSeq - 1;
                            Interlocked.Add(ref Metrics.MissingPackets, missing);
                        }
                        Metrics.LastSequenceNumbers[key] = seq;
                    });
                }
            );
            return socketSession;
        }

        /// <summary>
        /// Waits for a client's handshake to complete.
        /// </summary>
        private static Task WaitForHandshake(SyncSocketSession session)
        {
            return Task.Run(() =>
            {
                while (!HandshakeCompleted.Contains(session.LocalPublicKey))
                {
                    Thread.Sleep(100);
                }
            });
        }
    }

    /// <summary>
    /// Static class to store and manage performance metrics.
    /// </summary>
    static class Metrics
    {
        public static ConcurrentBag<double> DataLatencies = new ConcurrentBag<double>(); // ms
        public static ConcurrentDictionary<string, int> LastSequenceNumbers = new ConcurrentDictionary<string, int>();
        public static long MissingPackets = 0;
        public static ConcurrentBag<string> Disconnections = new ConcurrentBag<string>();
    }
}