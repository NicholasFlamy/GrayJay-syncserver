using Noise;
using SyncClient;
using SyncServer;
using SyncServer.Repositories;
using SyncShared;
using System.Net.Sockets;
using static SyncClient.SyncSocketSession;

namespace SyncServerTests
{
    [TestClass]
    public class SyncServerTests
    {
        private (TcpSyncServer server, string serverPublicKey, int port) SetupServer()
        {
            var serverKeyPair = KeyPair.Generate();
            var serverPublicKey = Convert.ToBase64String(serverKeyPair.PublicKey);
            var recordRepository = new InMemoryRecordRepository();
            var server = new TcpSyncServer(0, serverKeyPair, recordRepository, 50);
            server.Start();
            var port = server.Port;
            return (server, serverPublicKey, port);
        }

        private async Task<SyncSocketSession> CreateClientAsync(
            int port,
            string serverPublicKey,
            Action<SyncSocketSession>? onHandshakeComplete = null,
            Action<SyncSocketSession, Opcode, byte, ReadOnlySpan<byte>>? onData = null,
            Action<SyncSocketSession, ChannelRelayed>? onNewChannel = null)
        {
            var keyPair = KeyPair.Generate();
            var tcpClient = new TcpClient();
            await tcpClient.ConnectAsync("127.0.0.1", port);
            var tcs = new TaskCompletionSource<bool>();
            var socketSession = new SyncSocketSession(
                "127.0.0.1",
                keyPair,
                tcpClient.GetStream(),
                tcpClient.GetStream(),
                onClose: s => { tcpClient.Close(); },
                onHandshakeComplete: s =>
                {
                    onHandshakeComplete?.Invoke(s);
                    tcs.SetResult(true);
                },
                onData: onData ?? ((s, o, so, d) => { }),
                onNewChannel: onNewChannel ?? ((s, c) => { }),
                isChannelAllowed: (s, c) => true
            )
            { IsTrusted = true };
            _ = socketSession.StartAsInitiatorAsync(serverPublicKey);
            await tcs.Task.WithTimeout(5000, "Handshake timed out");
            return socketSession;
        }

        [TestMethod]
        public async Task MultipleClientsHandshake_Success()
        {
            var (server, serverPublicKey, port) = SetupServer();
            using (server)
            {
                using var client1 = await CreateClientAsync(port, serverPublicKey);
                using var client2 = await CreateClientAsync(port, serverPublicKey);
                Assert.IsNotNull(client1.RemotePublicKey, "Client 1 handshake failed");
                Assert.IsNotNull(client2.RemotePublicKey, "Client 2 handshake failed");
                Assert.AreEqual(serverPublicKey, client1.RemotePublicKey);
                Assert.AreEqual(serverPublicKey, client2.RemotePublicKey);
            }
        }

        [TestMethod]
        public async Task HandshakeWithIncorrectPublicKey_Fails()
        {
            var (server, serverPublicKey, port) = SetupServer();
            using (server)
            {
                var incorrectPublicKey = Convert.ToBase64String(KeyPair.Generate().PublicKey);
                var keyPair = KeyPair.Generate();
                var tcpClient = new TcpClient();
                await tcpClient.ConnectAsync("127.0.0.1", port);
                var stream = tcpClient.GetStream();
                var tcs = new TaskCompletionSource<bool>();
                var socketSession = new SyncSocketSession(
                    "127.0.0.1",
                    keyPair,
                    stream,
                    stream,
                    onClose: s => tcs.TrySetResult(true),
                    onHandshakeComplete: s => tcs.TrySetResult(false),
                    onData: (s, o, so, d) => { },
                    onNewChannel: (s, c) => { }
                );
                _ = socketSession.StartAsInitiatorAsync(incorrectPublicKey);
                await tcs.Task.WithTimeout(5000, "Connection close timed out");
                Assert.IsNull(socketSession.RemotePublicKey, "Handshake should fail with incorrect public key");
                socketSession.Dispose();
            }
        }

        [TestMethod]
        public async Task PublishAndRequestConnectionInfo_Authorized_Success()
        {
            var (server, serverPublicKey, port) = SetupServer();
            using (server)
            {
                using var clientA = await CreateClientAsync(port, serverPublicKey);
                using var clientB = await CreateClientAsync(port, serverPublicKey);
                using var clientC = await CreateClientAsync(port, serverPublicKey);
                await clientA.PublishConnectionInformationAsync(new[] { clientB.LocalPublicKey }, 12345, true, true, true, true);
                await Task.Delay(100);
                var infoB = await clientB.RequestConnectionInfoAsync(clientA.LocalPublicKey);
                var infoC = await clientC.RequestConnectionInfoAsync(clientA.LocalPublicKey);
                Assert.IsNotNull(infoB, "Client B should receive connection info");
                Assert.AreEqual(12345, infoB!.Port);
                Assert.IsNull(infoC, "Client C should not receive connection info (unauthorized)");
            }
        }

        [TestMethod]
        public async Task PublishConnectionInfo_MultipleAuthorizedKeys_Success()
        {
            var (server, serverPublicKey, port) = SetupServer();
            using (server)
            {
                using var clientA = await CreateClientAsync(port, serverPublicKey);
                using var clientB = await CreateClientAsync(port, serverPublicKey);
                using var clientC = await CreateClientAsync(port, serverPublicKey);
                var authorizedKeys = new[] { clientB.LocalPublicKey, clientC.LocalPublicKey };
                await clientA.PublishConnectionInformationAsync(authorizedKeys, 12345, true, true, true, true);
                await Task.Delay(100);
                var infoB = await clientB.RequestConnectionInfoAsync(clientA.LocalPublicKey);
                var infoC = await clientC.RequestConnectionInfoAsync(clientA.LocalPublicKey);
                Assert.IsNotNull(infoB, "Client B should receive connection info");
                Assert.IsNotNull(infoC, "Client C should receive connection info");
                Assert.AreEqual(12345, infoB!.Port);
                Assert.AreEqual(12345, infoC!.Port);
            }
        }

        [TestMethod]
        public async Task RequestConnectionInfoForSelf_Unauthorized()
        {
            var (server, serverPublicKey, port) = SetupServer();
            using (server)
            {
                using var clientA = await CreateClientAsync(port, serverPublicKey);
                var info = await clientA.RequestConnectionInfoAsync(clientA.LocalPublicKey);
                Assert.IsNull(info, "Requesting own connection info should return null (unauthorized)");
            }
        }

        [TestMethod]
        public async Task PublishConnectionInfo_MalformedData_Handled()
        {
            var (server, serverPublicKey, port) = SetupServer();
            using (server)
            {
                using var clientA = await CreateClientAsync(port, serverPublicKey);
                var malformedAuthorizedKeys = new[] { "invalidBase64" };
                await Assert.ThrowsExceptionAsync<FormatException>(
                    async () => await clientA.PublishConnectionInformationAsync(malformedAuthorizedKeys, 12345, true, true, true, true),
                    "Publishing with malformed authorized keys should throw FormatException"
                );
            }
        }

        [TestMethod]
        public async Task BulkRequestConnectionInfo_MixedResults_Success()
        {
            var (server, serverPublicKey, port) = SetupServer();
            using (server)
            {
                using var clientA = await CreateClientAsync(port, serverPublicKey);
                using var clientB = await CreateClientAsync(port, serverPublicKey);
                using var clientC = await CreateClientAsync(port, serverPublicKey);
                await clientA.PublishConnectionInformationAsync(new[] { clientB.LocalPublicKey }, 1000, true, true, true, true);
                await clientC.PublishConnectionInformationAsync(new[] { clientB.LocalPublicKey }, 2000, true, true, true, true);
                var nonExistentKey = Convert.ToBase64String(new byte[32]);
                var infos = await clientB.RequestBulkConnectionInfoAsync(new[] { clientA.LocalPublicKey, clientC.LocalPublicKey, nonExistentKey });
                Assert.AreEqual(3, infos.Count);
                Assert.IsNotNull(infos[clientA.LocalPublicKey]);
                Assert.AreEqual(1000, infos[clientA.LocalPublicKey]!.Port);
                Assert.IsNotNull(infos[clientC.LocalPublicKey]);
                Assert.AreEqual(2000, infos[clientC.LocalPublicKey]!.Port);
                Assert.IsNull(infos[nonExistentKey]);
            }
        }

        [TestMethod]
        public async Task RelayedTransport_Bidirectional_Success()
        {
            var (server, serverPublicKey, port) = SetupServer();
            using (server)
            {
                var tcsA = new TaskCompletionSource<ChannelRelayed>();
                var tcsB = new TaskCompletionSource<ChannelRelayed>();
                using var clientA = await CreateClientAsync(port, serverPublicKey, onNewChannel: (s, c) => tcsA.SetResult(c));
                using var clientB = await CreateClientAsync(port, serverPublicKey, onNewChannel: (s, c) => tcsB.SetResult(c));
                var channelTask = clientA.StartRelayedChannelAsync(clientB.LocalPublicKey);
                var channelA = await tcsA.Task.WithTimeout(500000, "Channel A creation timed out");
                var channelB = await tcsB.Task.WithTimeout(500000, "Channel B creation timed out");
                await channelTask;

                var tcsDataB = new TaskCompletionSource<byte[]>();
                channelB.SetDataHandler((s, c, o, so, d) => tcsDataB.SetResult(d.ToArray()));
                await channelA.SendRelayedDataAsync(Opcode.DATA, 0, new byte[] { 1, 2, 3 });

                var tcsDataA = new TaskCompletionSource<byte[]>();
                channelA.SetDataHandler((s, c, o, so, d) => tcsDataA.SetResult(d.ToArray()));
                await channelB.SendRelayedDataAsync(Opcode.DATA, 0, new byte[] { 4, 5, 6 });

                var receivedB = await tcsDataB.Task.WithTimeout(500000, "Data to B timed out");
                var receivedA = await tcsDataA.Task.WithTimeout(500000, "Data to A timed out");
                CollectionAssert.AreEqual(new byte[] { 1, 2, 3 }, receivedB);
                CollectionAssert.AreEqual(new byte[] { 4, 5, 6 }, receivedA);
            }
        }

        [TestMethod]
        public async Task RelayedTransport_MaximumMessageSize_Success()
        {
            var (server, serverPublicKey, port) = SetupServer();
            using (server)
            {
                const int MAX_DATA_PER_PACKET = MAXIMUM_PACKET_SIZE - HEADER_SIZE - 8 - 16 - 16;
                var maxSizeData = new byte[MAX_DATA_PER_PACKET];
                new Random().NextBytes(maxSizeData);
                var tcsA = new TaskCompletionSource<ChannelRelayed>();
                var tcsB = new TaskCompletionSource<ChannelRelayed>();
                using var clientA = await CreateClientAsync(port, serverPublicKey, onNewChannel: (s, c) => tcsA.SetResult(c));
                using var clientB = await CreateClientAsync(port, serverPublicKey, onNewChannel: (s, c) => tcsB.SetResult(c));
                var channelTask = clientA.StartRelayedChannelAsync(clientB.LocalPublicKey);
                var channelA = await tcsA.Task.WithTimeout(5000, "Channel A creation timed out");
                var channelB = await tcsB.Task.WithTimeout(5000, "Channel B creation timed out");
                await channelTask;

                var tcsDataB = new TaskCompletionSource<byte[]>();
                channelB.SetDataHandler((s, c, o, so, d) => tcsDataB.SetResult(d.ToArray()));
                await channelA.SendRelayedDataAsync(Opcode.DATA, 0, maxSizeData);
                var receivedData = await tcsDataB.Task.WithTimeout(5000, "Max size data timed out");
                CollectionAssert.AreEqual(maxSizeData, receivedData);
            }
        }

        [TestMethod]
        public async Task RelayedTransport_ZeroByteMessage_Success()
        {
            var (server, serverPublicKey, port) = SetupServer();
            using (server)
            {
                var tcsA = new TaskCompletionSource<ChannelRelayed>();
                var tcsB = new TaskCompletionSource<ChannelRelayed>();
                using var clientA = await CreateClientAsync(port, serverPublicKey, onNewChannel: (s, c) => tcsA.SetResult(c));
                using var clientB = await CreateClientAsync(port, serverPublicKey, onNewChannel: (s, c) => tcsB.SetResult(c));
                var channelTask = clientA.StartRelayedChannelAsync(clientB.LocalPublicKey);
                var channelA = await tcsA.Task.WithTimeout(5000, "Channel A creation timed out");
                var channelB = await tcsB.Task.WithTimeout(5000, "Channel B creation timed out");
                await channelTask;

                var tcsDataB = new TaskCompletionSource<byte[]>();
                channelB.SetDataHandler((s, c, o, so, d) => tcsDataB.SetResult(d.ToArray()));
                await channelA.SendRelayedDataAsync(Opcode.DATA, 0, Array.Empty<byte>());
                var receivedData = await tcsDataB.Task.WithTimeout(5000, "Zero-byte data timed out");
                Assert.AreEqual(0, receivedData.Length);
            }
        }

        [TestMethod]
        public async Task MultipleRelayedChannels_SamePair_Success()
        {
            var (server, serverPublicKey, port) = SetupServer();
            using (server)
            {
                var tcsA1 = new TaskCompletionSource<ChannelRelayed>();
                var tcsB1 = new TaskCompletionSource<ChannelRelayed>();
                var tcsA2 = new TaskCompletionSource<ChannelRelayed>();
                var tcsB2 = new TaskCompletionSource<ChannelRelayed>();
                using var clientA = await CreateClientAsync(port, serverPublicKey, onNewChannel: (s, c) =>
                {
                    if (!tcsA1.Task.IsCompleted) tcsA1.SetResult(c);
                    else tcsA2.SetResult(c);
                });
                using var clientB = await CreateClientAsync(port, serverPublicKey, onNewChannel: (s, c) =>
                {
                    if (!tcsB1.Task.IsCompleted) tcsB1.SetResult(c);
                    else tcsB2.SetResult(c);
                });

                var channelTask1 = clientA.StartRelayedChannelAsync(clientB.LocalPublicKey);
                var channelA1 = await tcsA1.Task.WithTimeout(5000, "Channel A1 creation timed out");
                var channelB1 = await tcsB1.Task.WithTimeout(5000, "Channel B1 creation timed out");
                await channelTask1;

                var channelTask2 = clientA.StartRelayedChannelAsync(clientB.LocalPublicKey);
                var channelA2 = await tcsA2.Task.WithTimeout(5000, "Channel A2 creation timed out");
                var channelB2 = await tcsB2.Task.WithTimeout(5000, "Channel B2 creation timed out");
                await channelTask2;

                var tcsDataB1 = new TaskCompletionSource<byte[]>();
                channelB1.SetDataHandler((s, c, o, so, d) => tcsDataB1.SetResult(d.ToArray()));
                var tcsDataB2 = new TaskCompletionSource<byte[]>();
                channelB2.SetDataHandler((s, c, o, so, d) => tcsDataB2.SetResult(d.ToArray()));

                await channelA1.SendRelayedDataAsync(Opcode.DATA, 0, new byte[] { 1 });
                await channelA2.SendRelayedDataAsync(Opcode.DATA, 0, new byte[] { 2 });

                var receivedB1 = await tcsDataB1.Task.WithTimeout(5000, "Data on channel B1 timed out");
                var receivedB2 = await tcsDataB2.Task.WithTimeout(5000, "Data on channel B2 timed out");
                CollectionAssert.AreEqual(new byte[] { 1 }, receivedB1);
                CollectionAssert.AreEqual(new byte[] { 2 }, receivedB2);
            }
        }

        [TestMethod]
        public async Task RelayedTransport_TargetNotConnected_Fails()
        {
            var (server, serverPublicKey, port) = SetupServer();
            using (server)
            {
                using var clientA = await CreateClientAsync(port, serverPublicKey);
                var nonExistentKey = Convert.ToBase64String(new byte[32]);
                await Assert.ThrowsExceptionAsync<Exception>(
                    async () => await clientA.StartRelayedChannelAsync(nonExistentKey),
                    "Starting relayed channel to non-existent target should fail"
                );
            }
        }

        [TestMethod]
        public async Task RelayedTransport_Disconnect_CleansUp()
        {
            var (server, serverPublicKey, port) = SetupServer();
            using (server)
            {
                var tcsA = new TaskCompletionSource<ChannelRelayed>();
                var tcsB = new TaskCompletionSource<ChannelRelayed>();
                using var clientA = await CreateClientAsync(port, serverPublicKey, onNewChannel: (s, c) => tcsA.SetResult(c));
                using var clientB = await CreateClientAsync(port, serverPublicKey, onNewChannel: (s, c) => tcsB.SetResult(c));
                var channel = await clientA.StartRelayedChannelAsync(clientB.LocalPublicKey);

                clientB.Dispose();
                await Task.Delay(100);
                await Assert.ThrowsExceptionAsync<ObjectDisposedException>(
                    async () => await channel.SendRelayedDataAsync(Opcode.DATA, 0, new byte[] { 1 }),
                    "Sending data after peer disconnect should fail"
                );
            }
        }

        [TestMethod]
        public async Task PublishAndGetRecord_Success()
        {
            var (server, serverPublicKey, port) = SetupServer();
            using (server)
            {
                using var clientA = await CreateClientAsync(port, serverPublicKey);
                using var clientB = await CreateClientAsync(port, serverPublicKey);
                using var clientC = await CreateClientAsync(port, serverPublicKey);
                var data = new byte[] { 1, 2, 3 };
                bool success = await clientA.PublishRecordAsync(clientB.LocalPublicKey, "testKey", data);
                var recordB = await clientB.GetRecordAsync(clientA.LocalPublicKey, "testKey");
                var recordC = await clientC.GetRecordAsync(clientA.LocalPublicKey, "testKey");
                Assert.IsTrue(success);
                Assert.IsNotNull(recordB);
                CollectionAssert.AreEqual(data, recordB!.Value.Data);
                Assert.IsNull(recordC, "Unauthorized client should not access record");
            }
        }

        [TestMethod]
        public async Task PublishRecord_MaxKeyLength_Success()
        {
            var (server, serverPublicKey, port) = SetupServer();
            using (server)
            {
                using var clientA = await CreateClientAsync(port, serverPublicKey);
                using var clientB = await CreateClientAsync(port, serverPublicKey);
                var maxKey = new string('a', 32);
                var data = new byte[] { 1, 2, 3 };
                bool success = await clientA.PublishRecordAsync(clientB.LocalPublicKey, maxKey, data);
                var record = await clientB.GetRecordAsync(clientA.LocalPublicKey, maxKey);
                Assert.IsTrue(success);
                Assert.IsNotNull(record);
                CollectionAssert.AreEqual(data, record!.Value.Data);
            }
        }

        [TestMethod]
        public async Task PublishRecord_RateLimited()
        {
            var (server, serverPublicKey, port) = SetupServer();
            using (server)
            {
                using var clientA = await CreateClientAsync(port, serverPublicKey);
                using var clientB = await CreateClientAsync(port, serverPublicKey);
                var data = new byte[5 * 1024 * 1024];
                bool success1 = await clientA.PublishRecordAsync(clientB.LocalPublicKey, "testA", data);
                bool success2 = await clientA.PublishRecordAsync(clientB.LocalPublicKey, "testB", data);
                var record1 = await clientB.GetRecordAsync(clientA.LocalPublicKey, "testA").WithTimeout(5000, "Get record A timed out");
                var record2 = await clientB.GetRecordAsync(clientA.LocalPublicKey, "testB").WithTimeout(5000, "Get record B timed out");
                Assert.IsTrue(success1);
                Assert.IsFalse(success2);
                Assert.IsNotNull(record1);
                Assert.IsNull(record2);
            }
        }

        [TestMethod]
        public async Task PublishRecord_InvalidKey_Fails()
        {
            var (server, serverPublicKey, port) = SetupServer();
            using (server)
            {
                using var clientA = await CreateClientAsync(port, serverPublicKey);
                var invalidKey = new string('a', 33);
                await Assert.ThrowsExceptionAsync<ArgumentException>(
                    async () => await clientA.PublishRecordAsync(clientA.LocalPublicKey, invalidKey, new byte[] { 1 }),
                    "Publishing with invalid key should throw ArgumentException"
                );
            }
        }

        [TestMethod]
        public async Task GetNonExistentRecord_ReturnsNull()
        {
            var (server, serverPublicKey, port) = SetupServer();
            using (server)
            {
                using var clientA = await CreateClientAsync(port, serverPublicKey);
                using var clientB = await CreateClientAsync(port, serverPublicKey);
                var record = await clientB.GetRecordAsync(clientA.LocalPublicKey, "nonExistentKey");
                Assert.IsNull(record, "Getting non-existent record should return null");
            }
        }

        [TestMethod]
        public async Task UpdateRecord_TimestampUpdated()
        {
            var (server, serverPublicKey, port) = SetupServer();
            using (server)
            {
                using var clientA = await CreateClientAsync(port, serverPublicKey);
                using var clientB = await CreateClientAsync(port, serverPublicKey);
                var key = "updateKey";
                var data1 = new byte[] { 1 };
                var data2 = new byte[] { 2 };
                await clientA.PublishRecordAsync(clientB.LocalPublicKey, key, data1);
                var record1 = await clientB.GetRecordAsync(clientA.LocalPublicKey, key);
                await Task.Delay(1000);
                await clientA.PublishRecordAsync(clientB.LocalPublicKey, key, data2);
                var record2 = await clientB.GetRecordAsync(clientA.LocalPublicKey, key);
                Assert.IsNotNull(record1);
                Assert.IsNotNull(record2);
                Assert.IsTrue(record2!.Value.Timestamp > record1!.Value.Timestamp);
                CollectionAssert.AreEqual(data2, record2.Value.Data);
            }
        }

        [TestMethod]
        public async Task DeleteRecord_Success()
        {
            var (server, serverPublicKey, port) = SetupServer();
            using (server)
            {
                using var clientA = await CreateClientAsync(port, serverPublicKey);
                using var clientB = await CreateClientAsync(port, serverPublicKey);
                var data = new byte[] { 1, 2, 3 };
                await clientA.PublishRecordAsync(clientB.LocalPublicKey, "toDelete", data);
                bool success = await clientB.DeleteRecordAsync(clientA.LocalPublicKey, clientB.LocalPublicKey, "toDelete");
                var record = await clientB.GetRecordAsync(clientA.LocalPublicKey, "toDelete");
                Assert.IsTrue(success);
                Assert.IsNull(record);
            }
        }

        [TestMethod]
        public async Task DeleteRecord_Unauthorized_Fails()
        {
            var (server, serverPublicKey, port) = SetupServer();
            using (server)
            {
                using var clientA = await CreateClientAsync(port, serverPublicKey);
                using var clientB = await CreateClientAsync(port, serverPublicKey);
                using var clientC = await CreateClientAsync(port, serverPublicKey);
                await clientA.PublishRecordAsync(clientB.LocalPublicKey, "protected", new byte[] { 4, 5, 6 });
                bool success = await clientC.DeleteRecordAsync(clientA.LocalPublicKey, clientB.LocalPublicKey, "protected");
                var record = await clientB.GetRecordAsync(clientA.LocalPublicKey, "protected");
                Assert.IsFalse(success);
                Assert.IsNotNull(record);
                CollectionAssert.AreEqual(new byte[] { 4, 5, 6 }, record!.Value.Data);
            }
        }

        [TestMethod]
        public async Task ListRecordKeys_NoRecords_EmptyList()
        {
            var (server, serverPublicKey, port) = SetupServer();
            using (server)
            {
                using var clientA = await CreateClientAsync(port, serverPublicKey);
                using var clientB = await CreateClientAsync(port, serverPublicKey);
                var keys = await clientB.ListRecordKeysAsync(clientA.LocalPublicKey, clientB.LocalPublicKey);
                Assert.AreEqual(0, keys.Count, "Expected empty list for no records");
            }
        }

        [TestMethod]
        public async Task ListRecordKeys_Success()
        {
            var (server, serverPublicKey, port) = SetupServer();
            using (server)
            {
                using var clientA = await CreateClientAsync(port, serverPublicKey);
                using var clientB = await CreateClientAsync(port, serverPublicKey);
                var keys = new[] { "key1", "key2", "key3" };
                foreach (var key in keys)
                    await clientA.PublishRecordAsync(clientB.LocalPublicKey, key, new byte[] { 1 });
                var listedKeys = await clientB.ListRecordKeysAsync(clientA.LocalPublicKey, clientB.LocalPublicKey);
                CollectionAssert.AreEquivalent(keys, listedKeys.Select(k => k.Key).ToArray());
            }
        }

        [TestMethod]
        public async Task BulkPublishAndGetRecords_MultipleConsumers_Success()
        {
            var (server, serverPublicKey, port) = SetupServer();
            using (server)
            {
                using var clientA = await CreateClientAsync(port, serverPublicKey);
                using var clientB = await CreateClientAsync(port, serverPublicKey);
                using var clientC = await CreateClientAsync(port, serverPublicKey);
                var data = new byte[] { 1, 2, 3 };
                bool success = await clientA.PublishRecordsAsync(new[] { clientB.LocalPublicKey, clientC.LocalPublicKey }, "multiKey", data);
                var recordsB = await clientB.GetRecordsAsync(new[] { clientA.LocalPublicKey }, "multiKey");
                var recordsC = await clientC.GetRecordsAsync(new[] { clientA.LocalPublicKey }, "multiKey");
                Assert.IsTrue(success);
                Assert.IsTrue(recordsB.ContainsKey(clientA.LocalPublicKey));
                CollectionAssert.AreEqual(data, recordsB[clientA.LocalPublicKey].Data);
                Assert.IsTrue(recordsC.ContainsKey(clientA.LocalPublicKey));
                CollectionAssert.AreEqual(data, recordsC[clientA.LocalPublicKey].Data);
            }
        }

        [TestMethod]
        public async Task SingleLargeMessageViaRelayedChannel_Success()
        {
            var (server, serverPublicKey, port) = SetupServer();
            using (server)
            {
                var largeData = new byte[100000];
                new Random().NextBytes(largeData);
                var tcsA = new TaskCompletionSource<ChannelRelayed>();
                var tcsB = new TaskCompletionSource<ChannelRelayed>();
                using var clientA = await CreateClientAsync(port, serverPublicKey, onNewChannel: (s, c) => tcsA.SetResult(c));
                using var clientB = await CreateClientAsync(port, serverPublicKey, onNewChannel: (s, c) => tcsB.SetResult(c));
                var channelTask = clientA.StartRelayedChannelAsync(clientB.LocalPublicKey);
                var channelA = await tcsA.Task.WithTimeout(5000, "Channel A creation timed out");
                var channelB = await tcsB.Task.WithTimeout(5000, "Channel B creation timed out");
                await channelTask;

                var tcsDataB = new TaskCompletionSource<byte[]>();
                channelB.SetDataHandler((s, c, o, so, d) => tcsDataB.SetResult(d.ToArray()));
                await channelA.SendRelayedDataAsync(Opcode.DATA, 0, largeData);
                var receivedData = await tcsDataB.Task.WithTimeout(10000, "Receiving large data timed out");
                CollectionAssert.AreEqual(largeData, receivedData);
            }
        }


        [TestMethod]
        public async Task SingleLargeMessageViaRelayedChannel_RateLimited()
        {
            var (server, serverPublicKey, port) = SetupServer();
            using (server)
            {
                var largeData = new byte[10_000_000];
                new Random().NextBytes(largeData);
                using var clientA = await CreateClientAsync(port, serverPublicKey);
                using var clientB = await CreateClientAsync(port, serverPublicKey);
                var channelA = await clientA.StartRelayedChannelAsync(clientB.LocalPublicKey);
                await channelA.SendRelayedDataAsync(Opcode.DATA, 0, largeData);
                Assert.ThrowsException<NullReferenceException>(async () => await channelA.SendRelayedDataAsync(Opcode.DATA, 0, largeData));
            }
        }

        [TestMethod]
        public async Task MultipleLargeMessagesConcurrently_Success()
        {
            var (server, serverPublicKey, port) = SetupServer();
            using (server)
            {
                var largeData1 = new byte[50000];
                var largeData2 = new byte[50000];
                new Random().NextBytes(largeData1);
                new Random().NextBytes(largeData2);
                var tcsA = new TaskCompletionSource<ChannelRelayed>();
                var tcsB = new TaskCompletionSource<ChannelRelayed>();
                using var clientA = await CreateClientAsync(port, serverPublicKey, onNewChannel: (s, c) => tcsA.SetResult(c));
                using var clientB = await CreateClientAsync(port, serverPublicKey, onNewChannel: (s, c) => tcsB.SetResult(c));
                var channelTask = clientA.StartRelayedChannelAsync(clientB.LocalPublicKey);
                var channelA = await tcsA.Task.WithTimeout(5000, "Channel A creation timed out");
                var channelB = await tcsB.Task.WithTimeout(5000, "Channel B creation timed out");
                await channelTask;

                var tcsDataB1 = new TaskCompletionSource<byte[]>();
                var tcsDataB2 = new TaskCompletionSource<byte[]>();
                int receivedCount = 0;
                channelB.SetDataHandler((s, c, o, so, d) =>
                {
                    if (Interlocked.Increment(ref receivedCount) == 1)
                        tcsDataB1.SetResult(d.ToArray());
                    else
                        tcsDataB2.SetResult(d.ToArray());
                });

                var sendTask1 = channelA.SendRelayedDataAsync(Opcode.DATA, 0, largeData1);
                var sendTask2 = channelA.SendRelayedDataAsync(Opcode.DATA, 0, largeData2);
                await Task.WhenAll(sendTask1, sendTask2);

                var receivedData1 = await tcsDataB1.Task.WithTimeout(10000, "First large data timed out");
                var receivedData2 = await tcsDataB2.Task.WithTimeout(10000, "Second large data timed out");
                CollectionAssert.AreEqual(largeData1, receivedData1);
                CollectionAssert.AreEqual(largeData2, receivedData2);
                Assert.AreEqual(2, receivedCount);
            }
        }

        [TestMethod]
        public async Task MixedSmallAndLargeMessages_Success()
        {
            var (server, serverPublicKey, port) = SetupServer();
            using (server)
            {
                var smallData = new byte[] { 1, 2, 3 };
                var largeData = new byte[70000];
                new Random().NextBytes(largeData);
                var tcsA = new TaskCompletionSource<ChannelRelayed>();
                var tcsB = new TaskCompletionSource<ChannelRelayed>();
                using var clientA = await CreateClientAsync(port, serverPublicKey, onNewChannel: (s, c) => tcsA.SetResult(c));
                using var clientB = await CreateClientAsync(port, serverPublicKey, onNewChannel: (s, c) => tcsB.SetResult(c));
                var channelTask = clientA.StartRelayedChannelAsync(clientB.LocalPublicKey);
                var channelA = await tcsA.Task.WithTimeout(5000, "Channel A creation timed out");
                var channelB = await tcsB.Task.WithTimeout(5000, "Channel B creation timed out");
                await channelTask;

                var receivedMessages = new List<byte[]>();
                var tcsAllReceived = new TaskCompletionSource<bool>();
                channelB.SetDataHandler((s, c, o, so, d) =>
                {
                    lock (receivedMessages)
                    {
                        receivedMessages.Add(d.ToArray());
                        if (receivedMessages.Count == 3)
                            tcsAllReceived.SetResult(true);
                    }
                });

                await channelA.SendRelayedDataAsync(Opcode.DATA, 0, smallData);
                await channelA.SendRelayedDataAsync(Opcode.DATA, 0, largeData);
                await channelA.SendRelayedDataAsync(Opcode.DATA, 0, smallData);

                await tcsAllReceived.Task.WithTimeout(10000, "Receiving mixed messages timed out");
                lock (receivedMessages)
                {
                    Assert.AreEqual(3, receivedMessages.Count);
                    CollectionAssert.AreEqual(smallData, receivedMessages[0]);
                    CollectionAssert.AreEqual(largeData, receivedMessages[1]);
                    CollectionAssert.AreEqual(smallData, receivedMessages[2]);
                }
            }
        }

        [TestMethod]
        public async Task Streaming_InterleavedOpcodes_Success()
        {
            var (server, serverPublicKey, port) = SetupServer();
            using (server)
            {
                var largeData = new byte[100000];
                new Random().NextBytes(largeData);

                var tcsLargeReceived = new TaskCompletionSource<byte[]>();
                var tcsCustomPingReceived = new TaskCompletionSource<bool>();
                using var clientA = await CreateClientAsync(port, serverPublicKey);
                using var clientB = await CreateClientAsync(port, serverPublicKey, onNewChannel: (s, c) =>
                {
                    c.SetDataHandler((s, c, o, so, d) =>
                    {
                        if (o == Opcode.DATA && so == 0) tcsLargeReceived.SetResult(d.ToArray());
                        else if (o == Opcode.DATA && so == 1) tcsCustomPingReceived.SetResult(true);
                    });
                });

                var channelA = await clientA.StartRelayedChannelAsync(clientB.LocalPublicKey);
                var largeSendTask = channelA.SendRelayedDataAsync(Opcode.DATA, 0, largeData);
                await Task.Delay(50);
                await channelA.SendRelayedDataAsync(Opcode.DATA, 1, new byte[0]);
                await largeSendTask;

                var receivedLarge = await tcsLargeReceived.Task.WithTimeout(10000, "Large data timed out");
                var customPingReceived = await tcsCustomPingReceived.Task.WithTimeout(5000, "Custom PING timed out");
                CollectionAssert.AreEqual(largeData, receivedLarge);
                Assert.IsTrue(customPingReceived);
            }
        }

        [TestMethod]
        public async Task PublishAndGetLargeRecord_Success()
        {
            var (server, serverPublicKey, port) = SetupServer();
            using (server)
            {
                var largeData = new byte[1000000];
                new Random().NextBytes(largeData);
                using var clientA = await CreateClientAsync(port, serverPublicKey);
                using var clientB = await CreateClientAsync(port, serverPublicKey);
                bool success = await clientA.PublishRecordAsync(clientB.LocalPublicKey, "largeRecord", largeData);
                var record = await clientB.GetRecordAsync(clientA.LocalPublicKey, "largeRecord");
                Assert.IsTrue(success);
                Assert.IsNotNull(record);
                CollectionAssert.AreEqual(largeData, record!.Value.Data);
            }
        }

        [TestMethod]
        public async Task InvalidRequest_MalformedPacket_Handled()
        {
            var (server, serverPublicKey, port) = SetupServer();
            using (server)
            {
                using var client = await CreateClientAsync(port, serverPublicKey);
                var malformedData = new byte[] { 0xFF };
                await client.SendAsync(0xFF, 0, malformedData);
                await Task.Delay(100);
                Assert.IsNotNull(client.RemotePublicKey, "Client should remain connected after invalid request");
            }
        }

        [TestMethod]
        public async Task InvalidPublicKeyInRequest_Handled()
        {
            var (server, serverPublicKey, port) = SetupServer();
            using (server)
            {
                using var clientA = await CreateClientAsync(port, serverPublicKey);
                var invalidKey = "invalidBase64";
                await Assert.ThrowsExceptionAsync<FormatException>(
                    async () => await clientA.RequestConnectionInfoAsync(invalidKey),
                    "Requesting with invalid public key should throw FormatException"
                );
            }
        }

        [TestMethod]
        public async Task LargeNumberOfRecords_Success()
        {
            var (server, serverPublicKey, port) = SetupServer();
            using (server)
            {
                using var clientA = await CreateClientAsync(port, serverPublicKey);
                using var clientB = await CreateClientAsync(port, serverPublicKey);
                const int NUM_RECORDS = 1000;
                var keys = Enumerable.Range(0, NUM_RECORDS).Select(i => $"key{i}").ToArray();
                var tasks = keys.Select(key => clientA.PublishRecordAsync(clientB.LocalPublicKey, key, new byte[] { 1 }));
                await Task.WhenAll(tasks);
                var listedKeys = await clientB.ListRecordKeysAsync(clientA.LocalPublicKey, clientB.LocalPublicKey);
                Assert.AreEqual(NUM_RECORDS, listedKeys.Count);
                CollectionAssert.AreEquivalent(keys, listedKeys.Select(k => k.Key).ToArray());
            }
        }
    }

    public static class TaskExtensions
    {
        public static async Task<T> WithTimeout<T>(this Task<T> task, int timeoutMs, string message)
        {
            var cts = new CancellationTokenSource();
            var completedTask = await Task.WhenAny(task, Task.Delay(timeoutMs, cts.Token));
            if (completedTask == task)
            {
                cts.Cancel();
                return await task;
            }
            throw new TimeoutException(message);
        }

        public static async Task WithTimeout(this Task task, int timeoutMs, string message)
        {
            var cts = new CancellationTokenSource();
            var completedTask = await Task.WhenAny(task, Task.Delay(timeoutMs, cts.Token));
            if (completedTask == task)
            {
                cts.Cancel();
                await task;
            }
            else
                throw new TimeoutException(message);
        }
    }
}