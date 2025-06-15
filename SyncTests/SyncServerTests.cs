using Noise;
using SyncClient;
using SyncServer;
using SyncServer.Repositories;
using SyncShared;
using System.Buffers.Binary;
using System.Drawing;
using System.Net.Sockets;
using System.Reflection.Emit;
using System.Threading;
using System.Threading.Channels;

namespace SyncServerTests
{
    [TestClass]
    public class SyncServerTests
    {
        private (TcpSyncServer server, string serverPublicKey, int port) SetupServer(int maxConnections = 50)
        {
            var serverKeyPair = KeyPair.Generate();
            var serverPublicKey = Convert.ToBase64String(serverKeyPair.PublicKey);
            var recordRepository = new InMemoryRecordRepository();
            var deviceTokenRepository = new InMemoryDeviceTokenRepository();
            var server = new TcpSyncServer(0, serverKeyPair, recordRepository, deviceTokenRepository, null, maxConnections);
            server.Start();
            var port = server.Port;
            return (server, serverPublicKey, port);
        }

        private async Task<SyncSocketSession> CreateClientAsync(
            int port,
            string serverPublicKey,
            Action<SyncSocketSession>? onHandshakeComplete = null,
            Action<SyncSocketSession, Opcode, byte, ReadOnlySpan<byte>>? onData = null,
            Action<SyncSocketSession, ChannelRelayed>? onNewChannel = null,
            Func<LinkType, SyncSocketSession, string, string?, uint, bool>? isHandshakeAllowed = null,
            uint appId = 0)
        {
            var keyPair = KeyPair.Generate();
            var socket = await Utilities.OpenTcpSocketAsync("127.0.0.1", port);
            var tcs = new TaskCompletionSource<bool>();
            var socketSession = new SyncSocketSession(
                "127.0.0.1",
                keyPair,
                socket,
                onClose: s => { socket.Close(); },
                onHandshakeComplete: s =>
                {
                    onHandshakeComplete?.Invoke(s);
                    tcs.SetResult(true);
                },
                onData: onData ?? ((s, o, so, d) => { }),
                onNewChannel: onNewChannel ?? ((s, c) => { }),
                isHandshakeAllowed: (linkType, s, pk, pw, appId) => isHandshakeAllowed != null ? isHandshakeAllowed(linkType, s, pk, pw, appId) : true
            );
            socketSession.Authorizable = AlwaysAuthorized.Instance;
            socketSession.StartAsInitiator(serverPublicKey, appId);
            await tcs.Task.WithTimeout(500000, "Handshake timed out");
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
                var socket = await Utilities.OpenTcpSocketAsync("127.0.0.1", port);
                var tcs = new TaskCompletionSource<bool>();
                var socketSession = new SyncSocketSession(
                    "127.0.0.1",
                    keyPair,
                    socket,
                    onClose: s => tcs.TrySetResult(true),
                    onHandshakeComplete: s => tcs.TrySetResult(false),
                    onData: (s, o, so, d) => { },
                    onNewChannel: (s, c) => { }
                );
                socketSession.StartAsInitiator(incorrectPublicKey);
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
                Assert.AreEqual(2, infos.Count);
                Assert.IsNotNull(infos[clientA.LocalPublicKey]);
                Assert.AreEqual(1000, infos[clientA.LocalPublicKey]!.Port);
                Assert.IsNotNull(infos[clientC.LocalPublicKey]);
                Assert.AreEqual(2000, infos[clientC.LocalPublicKey]!.Port);
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
                var channelA = await tcsA.Task.WithTimeout(5000, "Channel A creation timed out");
                channelA.Authorizable = AlwaysAuthorized.Instance;
                var channelB = await tcsB.Task.WithTimeout(5000, "Channel B creation timed out");
                channelB.Authorizable = AlwaysAuthorized.Instance;
                await channelTask;

                var tcsDataB = new TaskCompletionSource<byte[]>();
                channelB.SetDataHandler((s, c, o, so, d) => tcsDataB.SetResult(d.ToArray()));
                await channelA.SendAsync(Opcode.DATA, 0, new byte[] { 1, 2, 3 });

                var tcsDataA = new TaskCompletionSource<byte[]>();
                channelA.SetDataHandler((s, c, o, so, d) => tcsDataA.SetResult(d.ToArray()));
                await channelB.SendAsync(Opcode.DATA, 0, new byte[] { 4, 5, 6 });

                var receivedB = await tcsDataB.Task.WithTimeout(5000, "Data to B timed out");
                var receivedA = await tcsDataA.Task.WithTimeout(5000, "Data to A timed out");
                CollectionAssert.AreEqual(new byte[] { 1, 2, 3 }, receivedB);
                CollectionAssert.AreEqual(new byte[] { 4, 5, 6 }, receivedA);
            }
        }

        [TestMethod]
        public async Task RelayedTransport_Bidirectional_Gzip_Success()
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
                channelA.Authorizable = AlwaysAuthorized.Instance;
                var channelB = await tcsB.Task.WithTimeout(5000, "Channel B creation timed out");
                channelB.Authorizable = AlwaysAuthorized.Instance;
                await channelTask;

                var tcsDataB = new TaskCompletionSource<byte[]>();
                channelB.SetDataHandler((s, c, o, so, d) => tcsDataB.SetResult(d.ToArray()));
                await channelA.SendAsync(Opcode.DATA, 0, new byte[] { 1, 2, 3 }, contentEncoding: ContentEncoding.Gzip);

                var tcsDataA = new TaskCompletionSource<byte[]>();
                channelA.SetDataHandler((s, c, o, so, d) => tcsDataA.SetResult(d.ToArray()));
                await channelB.SendAsync(Opcode.DATA, 0, new byte[] { 4, 5, 6 }, contentEncoding: ContentEncoding.Gzip);

                var receivedB = await tcsDataB.Task.WithTimeout(5000, "Data to B timed out");
                var receivedA = await tcsDataA.Task.WithTimeout(5000, "Data to A timed out");
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
                const int MAX_DATA_PER_PACKET = SyncSocketSession.MAXIMUM_PACKET_SIZE - SyncSocketSession.HEADER_SIZE - 8 - 16 - 16;
                var maxSizeData = new byte[MAX_DATA_PER_PACKET];
                new Random().NextBytes(maxSizeData);
                var tcsA = new TaskCompletionSource<ChannelRelayed>();
                var tcsB = new TaskCompletionSource<ChannelRelayed>();
                using var clientA = await CreateClientAsync(port, serverPublicKey, onNewChannel: (s, c) => tcsA.SetResult(c));
                using var clientB = await CreateClientAsync(port, serverPublicKey, onNewChannel: (s, c) => tcsB.SetResult(c));
                var channelTask = clientA.StartRelayedChannelAsync(clientB.LocalPublicKey);
                var channelA = await tcsA.Task.WithTimeout(5000, "Channel A creation timed out");
                channelA.Authorizable = AlwaysAuthorized.Instance;
                var channelB = await tcsB.Task.WithTimeout(5000, "Channel B creation timed out");
                channelB.Authorizable = AlwaysAuthorized.Instance;
                await channelTask;

                var tcsDataB = new TaskCompletionSource<byte[]>();
                channelB.SetDataHandler((s, c, o, so, d) => tcsDataB.SetResult(d.ToArray()));
                await channelA.SendAsync(Opcode.DATA, 0, maxSizeData);
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
                channelA.Authorizable = AlwaysAuthorized.Instance;
                var channelB = await tcsB.Task.WithTimeout(5000, "Channel B creation timed out");
                channelB.Authorizable = AlwaysAuthorized.Instance;
                await channelTask;

                var tcsDataB = new TaskCompletionSource<byte[]>();
                channelB.SetDataHandler((s, c, o, so, d) => tcsDataB.SetResult(d.ToArray()));
                await channelA.SendAsync(Opcode.DATA, 0, Array.Empty<byte>());
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
                var tcsB1 = new TaskCompletionSource<ChannelRelayed>();
                var tcsB2 = new TaskCompletionSource<ChannelRelayed>();
                using var clientA = await CreateClientAsync(port, serverPublicKey, onNewChannel: (s, c) => { });
                using var clientB = await CreateClientAsync(port, serverPublicKey, onNewChannel: (s, c) =>
                {
                    if (!tcsB1.Task.IsCompleted) tcsB1.SetResult(c);
                    else tcsB2.SetResult(c);
                });

                var channelA1 = await clientA.StartRelayedChannelAsync(clientB.LocalPublicKey).WithTimeout(5000, "Channel A1 creation timed out");
                channelA1.Authorizable = AlwaysAuthorized.Instance;
                var channelB1 = await tcsB1.Task.WithTimeout(5000, "Channel B1 creation timed out");
                channelB1.Authorizable = AlwaysAuthorized.Instance;

                var tcsDataB1 = new TaskCompletionSource<byte[]>();
                channelB1.SetDataHandler((s, c, o, so, d) => tcsDataB1.SetResult(d.ToArray()));
                await channelA1.SendAsync(Opcode.DATA, 0, new byte[] { 1 });

                var receivedB1 = await tcsDataB1.Task.WithTimeout(5000, "Data on channel B1 timed out");
                CollectionAssert.AreEqual(new byte[] { 1 }, receivedB1);

                channelA1.Dispose();
                await Task.Delay(100);

                var channelA2 = await clientA.StartRelayedChannelAsync(clientB.LocalPublicKey).WithTimeout(5000, "Channel A2 creation timed out");
                channelA2.Authorizable = AlwaysAuthorized.Instance;
                var channelB2 = await tcsB2.Task.WithTimeout(5000, "Channel B2 creation timed out");
                channelB2.Authorizable = AlwaysAuthorized.Instance;

                var tcsDataB2 = new TaskCompletionSource<byte[]>();
                channelB2.SetDataHandler((s, c, o, so, d) => tcsDataB2.SetResult(d.ToArray()));
                await channelA2.SendAsync(Opcode.DATA, 0, new byte[] { 2 });

                var receivedB2 = await tcsDataB2.Task.WithTimeout(5000, "Data on channel B2 timed out");
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
                    async () => await channel.SendAsync(Opcode.DATA, 0, new byte[] { 1 }),
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
        public async Task PublishAndGetRecord_Gzip_Success()
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
                channelA.Authorizable = AlwaysAuthorized.Instance;
                var channelB = await tcsB.Task.WithTimeout(5000, "Channel B creation timed out");
                channelB.Authorizable = AlwaysAuthorized.Instance;
                await channelTask;

                var tcsDataB = new TaskCompletionSource<byte[]>();
                channelB.SetDataHandler((s, c, o, so, d) => tcsDataB.SetResult(d.ToArray()));
                await channelA.SendAsync(Opcode.DATA, 0, largeData);
                var receivedData = await tcsDataB.Task.WithTimeout(10000, "Receiving large data timed out");
                CollectionAssert.AreEqual(largeData, receivedData);
            }
        }

        [TestMethod]
        public async Task SingleLargeMessageViaRelayedChannel_Gzip_Success()
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
                channelA.Authorizable = AlwaysAuthorized.Instance;
                var channelB = await tcsB.Task.WithTimeout(5000, "Channel B creation timed out");
                channelB.Authorizable = AlwaysAuthorized.Instance;
                await channelTask;

                var tcsDataB = new TaskCompletionSource<byte[]>();
                channelB.SetDataHandler((s, c, o, so, d) => tcsDataB.SetResult(d.ToArray()));
                await channelA.SendAsync(Opcode.DATA, 0, largeData, contentEncoding: ContentEncoding.Gzip);
                var receivedData = await tcsDataB.Task.WithTimeout(10000, "Receiving large data timed out");
                CollectionAssert.AreEqual(largeData, receivedData);
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
                channelA.Authorizable = AlwaysAuthorized.Instance;
                var channelB = await tcsB.Task.WithTimeout(5000, "Channel B creation timed out");
                channelB.Authorizable = AlwaysAuthorized.Instance;
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

                var sendTask1 = channelA.SendAsync(Opcode.DATA, 0, largeData1);
                var sendTask2 = channelA.SendAsync(Opcode.DATA, 0, largeData2);
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

                var receivedMessages = new List<byte[]>();
                var tcsAllReceived = new TaskCompletionSource<bool>();
                using var clientB = await CreateClientAsync(port, serverPublicKey, onNewChannel: (s, c) =>
                {
                    c.SetDataHandler((s, c, o, so, d) =>
                    {
                        lock (receivedMessages)
                        {
                            receivedMessages.Add(d.ToArray());
                            if (receivedMessages.Count == 3)
                                tcsAllReceived.SetResult(true);
                        }
                    });
                    c.Authorizable = AlwaysAuthorized.Instance;
                });

                var channelA = await clientA.StartRelayedChannelAsync(clientB.LocalPublicKey);
                channelA.Authorizable = AlwaysAuthorized.Instance;
                await channelA.SendAsync(Opcode.DATA, 0, smallData);
                await channelA.SendAsync(Opcode.DATA, 0, largeData);
                await channelA.SendAsync(Opcode.DATA, 0, smallData);

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

        /*[TestMethod]
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
                    c.Authorizable = AlwaysAuthorized.Instance;
                });

                var channelA = await clientA.StartRelayedChannelAsync(clientB.LocalPublicKey);
                channelA.Authorizable = AlwaysAuthorized.Instance;
                var largeSendTask = channelA.SendAsync(Opcode.DATA, 0, largeData);
                await Task.Delay(50);
                await channelA.SendAsync(Opcode.DATA, 1, new byte[0]);
                await largeSendTask;

                var receivedLarge = await tcsLargeReceived.Task.WithTimeout(10000, "Large data timed out");
                var customPingReceived = await tcsCustomPingReceived.Task.WithTimeout(5000, "Custom PING timed out");
                CollectionAssert.AreEqual(largeData, receivedLarge);
                Assert.IsTrue(customPingReceived);
            }
        }*/

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

        /*[TestMethod]
        public async Task KeypairRegistrationLimitPerIP_Enforced()
        {
            var (server, serverPublicKey, port) = SetupServer(51);
            using (server)
            {
                var clients = new List<SyncSocketSession>();
                // Register 50 clients successfully
                for (int i = 0; i < 50; i++)
                {
                    var client = await CreateClientAsync(port, serverPublicKey);
                    clients.Add(client);
                }

                // 51st client should be disconnected due to keypair limit
                var client51 = await CreateClientAsync(port, serverPublicKey).WithTimeout(5000, "Timed out creating client");

                await Task.Delay(100);

                for (int i = 0; i < clients.Count; i++)
                    await clients[i].SendAsync(Opcode.PING);
                await Assert.ThrowsExceptionAsync<ObjectDisposedException>(async () => await client51.SendAsync(Opcode.PING));

                Logger.Info<SyncServerTests>("Disposing client.Dispose()");
                foreach (var client in clients)
                    client.Dispose();
                clients.Clear();

                Logger.Info<SyncServerTests>("client51.Dispose()");
                client51.Dispose();
            }
        }

        [TestMethod]
        public async Task RelayRequestLimitPerIP_Enforced()
        {
            //This test is known broken
            var (server, serverPublicKey, port) = SetupServer(200);
            using (server)
            {
                const int maxConnectionsPerIp = 48; // Assumed per-IP limit of 100 active connections
                var targetClients = new List<SyncSocketSession>();

                // Create target clients
                for (int i = 0; i < maxConnectionsPerIp + 1; i++)
                {
                    targetClients.Add(await CreateClientAsync(port, serverPublicKey));
                }

                var initiatorClients = new List<SyncSocketSession>();

                // Create initiator clients, each connecting to a unique target
                for (int i = 0; i < maxConnectionsPerIp; i++)
                {
                    var initiator = await CreateClientAsync(port, serverPublicKey);
                    initiatorClients.Add(initiator);
                    await initiator.StartRelayedChannelAsync(targetClients[i].LocalPublicKey)
                        .WithTimeout(5000, "Relay request timed out");
                }

                // Attempt the 101st request, which should fail due to the per-IP limit
                using var extraInitiator = await CreateClientAsync(port, serverPublicKey);
                await Assert.ThrowsExceptionAsync<Exception>(
                    async () => await extraInitiator.StartRelayedChannelAsync(targetClients[maxConnectionsPerIp].LocalPublicKey),
                    "101st relay request should fail due to IP limit"
                );
            }
        }

        [TestMethod]
        public async Task RelayRequestLimitPerKey_Enforced()
        {
            //This test is known broken
            var (server, serverPublicKey, port) = SetupServer();
            using (server)
            {
                using var initiator = await CreateClientAsync(port, serverPublicKey);
                using var target = await CreateClientAsync(port, serverPublicKey);
                // Make 10 relay requests (within limit)
                for (int i = 0; i < 10; i++)
                {
                    await initiator.StartRelayedChannelAsync(target.LocalPublicKey).WithTimeout(5000, "Relay request timed out");
                }
                // 11th request should fail
                await Assert.ThrowsExceptionAsync<Exception>(
                    async () => await initiator.StartRelayedChannelAsync(target.LocalPublicKey),
                    "11th relay request per key should fail"
                );
            }
        }

        [TestMethod]
        public async Task RelayDataLimitPerIP_Enforced()
        {
            var (server, serverPublicKey, port) = SetupServer(100);
            using (server)
            {
                // Create 10 client pairs (20 clients total) to distribute load
                const int pairCount = 25;
                var clientsA = new List<SyncSocketSession>();
                var clientsB = new List<SyncSocketSession>();
                var channels = new List<ChannelRelayed>();

                for (int i = 0; i < pairCount; i++)
                {
                    var clientA = await CreateClientAsync(port, serverPublicKey);
                    var clientB = await CreateClientAsync(port, serverPublicKey);
                    var channel = await clientA.StartRelayedChannelAsync(clientB.LocalPublicKey);

                    clientsA.Add(clientA);
                    clientsB.Add(clientB);
                    channels.Add(channel);
                }

                // Each channel sends data in chunks, aiming to exceed 100MB IP limit
                var data = new byte[50_000]; // 50KB per send
                const int sendsPerChannel = 100; // 50KB * 100 = 5MB per channel
                                                 // Total: 25 pairs * 5MB = 125MB, well over 100MB IP limit

                var successfulSends = new int[pairCount];
                var sendTasks = new List<Task>();

                for (int i = 0; i < pairCount; i++)
                {
                    int channelIndex = i;
                    sendTasks.Add(Task.Run(async () =>
                    {
                        for (int j = 0; j < sendsPerChannel; j++)
                        {
                            try
                            {
                                await channels[channelIndex].SendAsync(Opcode.DATA, 0, data);
                                successfulSends[channelIndex]++;
                            }
                            catch (Exception)
                            {
                                break;
                            }
                        }
                    }));
                }

                await Task.WhenAll(sendTasks);

                long totalBytesSent = successfulSends.Sum(count => (long)count * data.Length);
                const long ipLimitBytes = 100_000_000; // 100MB

                Assert.IsTrue(totalBytesSent >= ipLimitBytes,
                    $"Expected at least {ipLimitBytes} bytes sent, but only sent {totalBytesSent}");
                Assert.IsTrue(totalBytesSent < pairCount * sendsPerChannel * data.Length,
                    "Expected failure before sending all data, but all sends succeeded");

                foreach (var client in clientsA.Concat(clientsB)) client.Dispose();
            }
        }

        [TestMethod]
        public async Task RelayDataLimitPerConnectionID_Enforced()
        {
            var (server, serverPublicKey, port) = SetupServer();
            using (server)
            {
                using var clientA = await CreateClientAsync(port, serverPublicKey);
                using var clientB = await CreateClientAsync(port, serverPublicKey);
                var channel = await clientA.StartRelayedChannelAsync(clientB.LocalPublicKey);
                var data = new byte[100_000]; // 100KB per send
                // Send 10MB (connection limit)
                for (int i = 0; i < 100; i++)
                {
                    await channel.SendAsync(Opcode.DATA, 0, data);
                }

                await Task.Delay(100);

                // Next send should fail
                await Assert.ThrowsExceptionAsync<ObjectDisposedException>(
                    async () => await channel.SendAsync(Opcode.DATA, 0, data),
                    "Sending beyond connection data limit should fail"
                );
            }
        }

        /*[TestMethod]
        public async Task PublishRequestLimitPerIP_Enforced()
        {
            var (server, serverPublicKey, port) = SetupServer();
            using (server)
            {
                using var clientA = await CreateClientAsync(port, serverPublicKey);
                using var clientB = await CreateClientAsync(port, serverPublicKey);

                // Make 1000 publish requests
                for (int i = 0; i < 2000; i++)
                {
                    if (!await clientA.PublishRecordAsync(clientB.LocalPublicKey, $"key{i}", new byte[] { 1 }))
                    {
                        Assert.IsTrue(i > 1000);
                        break;
                    }
                }

                await Task.Delay(1000);
            }
        }

        [TestMethod]
        public async Task KVStorageLimitPerPublisher_Enforced()
        {
            var (server, serverPublicKey, port) = SetupServer();
            using (server)
            {
                using var clientA = await CreateClientAsync(port, serverPublicKey);
                using var clientB = await CreateClientAsync(port, serverPublicKey);
                var largeData = new byte[1024 * 1024]; // 1MB
                // Publish 10MB (limit)
                for (int i = 0; i < 10; i++)
                {
                    await clientA.PublishRecordAsync(clientB.LocalPublicKey, $"largeKey{i}", largeData);
                }
                // Next publish should fail
                Assert.IsFalse(await clientA.PublishRecordAsync(clientB.LocalPublicKey, "largeKey10", largeData));
            }
        }

        [TestMethod]
        public async Task MaxRelayedConnectionsPerIP_Enforced()
        {
            var (server, serverPublicKey, port) = SetupServer(200);
            server.MaxKeypairsPerHour = 1000;

            using (server)
            {
                var clients = new List<SyncSocketSession>();
                using var target = await CreateClientAsync(port, serverPublicKey);
                // Create 100 active relayed connections
                for (int i = 0; i < 100; i++)
                {
                    var client = await CreateClientAsync(port, serverPublicKey);
                    await client.StartRelayedChannelAsync(target.LocalPublicKey);
                    clients.Add(client);
                }
                // 101st connection should fail
                using var extraClient = await CreateClientAsync(port, serverPublicKey);
                await Assert.ThrowsExceptionAsync<Exception>(
                    async () => await extraClient.StartRelayedChannelAsync(target.LocalPublicKey),
                    "101st relayed connection per IP should fail"
                );
            }
        }

        [TestMethod]
        public async Task MaxRelayedConnectionsPerKey_Enforced()
        {
            var (server, serverPublicKey, port) = SetupServer();
            using (server)
            {
                using var initiator = await CreateClientAsync(port, serverPublicKey);
                var targets = new List<SyncSocketSession>();
                // Create 10 active relayed connections from one key
                for (int i = 0; i < 10; i++)
                {
                    var target = await CreateClientAsync(port, serverPublicKey);
                    await initiator.StartRelayedChannelAsync(target.LocalPublicKey);
                    targets.Add(target);
                }

                await Task.Delay(100);

                // 11th connection should fail
                using var extraTarget = await CreateClientAsync(port, serverPublicKey);
                await Assert.ThrowsExceptionAsync<Exception>(
                    async () => await initiator.StartRelayedChannelAsync(extraTarget.LocalPublicKey),
                    "11th relayed connection per key should fail"
                );
            }
        }

        [TestMethod]
        public async Task MaxActiveStreams_Enforced()
        {
            var (server, serverPublicKey, port) = SetupServer();
            using (server)
            {
                using var clientA = await CreateClientAsync(port, serverPublicKey);

                var streamIdGenerator = 0;
                var startStream = async () =>
                {
                    var segmentData = new byte[10];
                    BinaryPrimitives.WriteInt32LittleEndian(segmentData.AsSpan().Slice(0, 4), Interlocked.Increment(ref streamIdGenerator));
                    BinaryPrimitives.WriteInt32LittleEndian(segmentData.AsSpan().Slice(4, 4), 100000);
                    segmentData[8] = (byte)Opcode.DATA;
                    segmentData[9] = (byte)0;
                    await clientA.SendAsync((byte)Opcode.STREAM, (byte)StreamOpcode.START, segmentData);
                };

                // Start 10 streams
                for (int i = 0; i < 10; i++)
                    await startStream();

                //Connection should still be open
                await clientA.SendAsync(Opcode.PING);

                // 11th stream should disconnect the session
                await startStream();
                await Task.Delay(100);
                await Assert.ThrowsExceptionAsync<ObjectDisposedException>(async () => await clientA.SendAsync(Opcode.PING));
            }
        }*/

        [TestMethod]
        public async Task RelayedTransport_WithValidPairingCode_Success()
        {
            var (server, serverPublicKey, port) = SetupServer();
            using (server)
            {
                const string validPairingCode = "secret123";
                var tcsA = new TaskCompletionSource<ChannelRelayed>();
                var tcsB = new TaskCompletionSource<ChannelRelayed>();

                // Client B requires a specific pairing code
                using var clientB = await CreateClientAsync(
                    port,
                    serverPublicKey,
                    onNewChannel: (s, c) => tcsB.SetResult(c),
                    isHandshakeAllowed: (linkType, s, pk, code, appId) => code == validPairingCode
                );

                using var clientA = await CreateClientAsync(
                    port,
                    serverPublicKey,
                    onNewChannel: (s, c) => tcsA.SetResult(c)
                );

                // Start relayed channel with the correct pairing code
                var channelTask = clientA.StartRelayedChannelAsync(clientB.LocalPublicKey, pairingCode: validPairingCode);
                var channelA = await tcsA.Task.WithTimeout(5000, "Channel A creation timed out");
                channelA.Authorizable = AlwaysAuthorized.Instance;
                var channelB = await tcsB.Task.WithTimeout(5000, "Channel B creation timed out");
                channelB.Authorizable = AlwaysAuthorized.Instance;
                await channelTask.WithTimeout(5000, "Channel establishment timed out");

                // Verify communication works
                var tcsDataB = new TaskCompletionSource<byte[]>();
                channelB.SetDataHandler((s, c, o, so, d) => tcsDataB.SetResult(d.ToArray()));
                await channelA.SendAsync(Opcode.DATA, 0, new byte[] { 1, 2, 3 });
                var receivedData = await tcsDataB.Task.WithTimeout(5000, "Data transmission timed out");

                CollectionAssert.AreEqual(new byte[] { 1, 2, 3 }, receivedData);
            }
        }

        [TestMethod]
        public async Task RelayedTransport_WithInvalidPairingCode_Fails()
        {
            var (server, serverPublicKey, port) = SetupServer();
            using (server)
            {
                const string validPairingCode = "secret123";
                const string invalidPairingCode = "wrongCode";
                var tcsB = new TaskCompletionSource<ChannelRelayed>();

                // Client B requires a specific pairing code
                using var clientB = await CreateClientAsync(
                    port,
                    serverPublicKey,
                    onNewChannel: (s, c) => tcsB.SetResult(c),
                    isHandshakeAllowed: (linkType, s, pk, code, appId) => code == validPairingCode
                );

                using var clientA = await CreateClientAsync(port, serverPublicKey);

                // Attempt to start relayed channel with an incorrect pairing code
                await Assert.ThrowsExceptionAsync<Exception>(
                    async () => await clientA.StartRelayedChannelAsync(clientB.LocalPublicKey, pairingCode: invalidPairingCode),
                    "Starting relayed channel with invalid pairing code should fail"
                );

                // Ensure no channel was created on client B
                var channelTask = tcsB.Task;
                var completedTask = await Task.WhenAny(channelTask, Task.Delay(1000));
                Assert.AreNotEqual(channelTask, completedTask, "No channel should be created on target with invalid pairing code");
            }
        }

        [TestMethod]
        public async Task RelayedTransport_WithoutPairingCodeWhenRequired_Fails()
        {
            var (server, serverPublicKey, port) = SetupServer();
            using (server)
            {
                const string validPairingCode = "secret123";
                var tcsB = new TaskCompletionSource<ChannelRelayed>();

                // Client B requires a pairing code
                using var clientB = await CreateClientAsync(
                    port,
                    serverPublicKey,
                    onNewChannel: (s, c) => tcsB.SetResult(c),
                    isHandshakeAllowed: (linkType, s, pk, code, appId) => code == validPairingCode
                );

                using var clientA = await CreateClientAsync(port, serverPublicKey);

                // Attempt to start relayed channel without providing a pairing code
                await Assert.ThrowsExceptionAsync<Exception>(
                    async () => await clientA.StartRelayedChannelAsync(clientB.LocalPublicKey),
                    "Starting relayed channel without pairing code when required should fail"
                );

                // Ensure no channel was created on client B
                var channelTask = tcsB.Task;
                var completedTask = await Task.WhenAny(channelTask, Task.Delay(1000));
                Assert.AreNotEqual(channelTask, completedTask, "No channel should be created on target without pairing code");
            }
        }

        [TestMethod]
        public async Task RelayedTransport_WithPairingCodeWhenNotRequired_Success()
        {
            var (server, serverPublicKey, port) = SetupServer();
            using (server)
            {
                const string pairingCode = "unnecessaryCode";
                var tcsA = new TaskCompletionSource<ChannelRelayed>();
                var tcsB = new TaskCompletionSource<ChannelRelayed>();

                // Client B allows all connections (no pairing code required)
                using var clientB = await CreateClientAsync(
                    port,
                    serverPublicKey,
                    onNewChannel: (s, c) => tcsB.SetResult(c),
                    isHandshakeAllowed: (linkType, s, pk, code, appId) => true
                );

                using var clientA = await CreateClientAsync(
                    port,
                    serverPublicKey,
                    onNewChannel: (s, c) => tcsA.SetResult(c)
                );

                // Start relayed channel with an unnecessary pairing code
                var channelTask = clientA.StartRelayedChannelAsync(clientB.LocalPublicKey, pairingCode: pairingCode);
                var channelA = await tcsA.Task.WithTimeout(5000, "Channel A creation timed out");
                channelA.Authorizable = AlwaysAuthorized.Instance;
                var channelB = await tcsB.Task.WithTimeout(5000, "Channel B creation timed out");
                channelB.Authorizable = AlwaysAuthorized.Instance;
                await channelTask.WithTimeout(5000, "Channel establishment timed out");

                // Verify communication works
                var tcsDataB = new TaskCompletionSource<byte[]>();
                channelB.SetDataHandler((s, c, o, so, d) => tcsDataB.SetResult(d.ToArray()));
                await channelA.SendAsync(Opcode.DATA, 0, new byte[] { 4, 5, 6 });
                var receivedData = await tcsDataB.Task.WithTimeout(5000, "Data transmission timed out");

                CollectionAssert.AreEqual(new byte[] { 4, 5, 6 }, receivedData);
            }
        }

        [TestMethod]
        public async Task PreventMultipleConnections_SameDirection()
        {
            var (server, serverPublicKey, port) = SetupServer();
            using (server)
            {
                using var clientA = await CreateClientAsync(port, serverPublicKey);
                using var clientB = await CreateClientAsync(port, serverPublicKey);

                // First connection should succeed
                var channel1 = await clientA.StartRelayedChannelAsync(clientB.LocalPublicKey);
                Assert.IsNotNull(channel1);

                // Second connection should fail
                try
                {
                    await clientA.StartRelayedChannelAsync(clientB.LocalPublicKey);
                    Assert.Fail("Second connection should have thrown an exception.");
                }
                catch (Exception ex)
                {
                    Assert.IsTrue(ex.Message.Contains("DuplicateConnection") || ex.Message.Contains("6"),
                        "Second connection should fail with DuplicateConnection error.");
                }
            }
        }

        [TestMethod]
        public async Task PreventMultipleConnections_OppositeDirection()
        {
            var (server, serverPublicKey, port) = SetupServer();
            using (server)
            {
                using var clientA = await CreateClientAsync(port, serverPublicKey);
                using var clientB = await CreateClientAsync(port, serverPublicKey);

                // Establish first connection A -> B
                var channel1 = await clientA.StartRelayedChannelAsync(clientB.LocalPublicKey);
                Assert.IsNotNull(channel1, "First connection should be established");

                // Attempt connection B -> A
                await Assert.ThrowsExceptionAsync<Exception>(
                    async () => await clientB.StartRelayedChannelAsync(clientA.LocalPublicKey),
                    "Connection in opposite direction should fail due to existing connection"
                );
            }
        }

        [TestMethod]
        public async Task AllowNewConnectionAfterClosing()
        {
            var (server, serverPublicKey, port) = SetupServer();
            using (server)
            {
                using var clientA = await CreateClientAsync(port, serverPublicKey);
                using var clientB = await CreateClientAsync(port, serverPublicKey);

                // Establish first connection A -> B
                var channel1 = await clientA.StartRelayedChannelAsync(clientB.LocalPublicKey);
                Assert.IsNotNull(channel1, "First connection should be established");

                // Close the connection
                channel1.Dispose();
                await Task.Delay(100); // Allow time for server cleanup

                // Attempt new connection A -> B
                var channel2 = await clientA.StartRelayedChannelAsync(clientB.LocalPublicKey);
                Assert.IsNotNull(channel2, "New connection should be allowed after closing the previous one");
            }
        }

       /*[TestMethod]
        public async Task ConcurrentConnectionAttempts()
        {
            // Set up the server and clients
            var (server, serverPublicKey, port) = SetupServer();
            using (server)
            {
                using var clientA = await CreateClientAsync(port, serverPublicKey);
                using var clientB = await CreateClientAsync(port, serverPublicKey);

                // Start two connection attempts concurrently
                var taskA = clientA.StartRelayedChannelAsync(clientB.LocalPublicKey);
                var taskB = clientB.StartRelayedChannelAsync(clientA.LocalPublicKey);

                // Wait for both tasks to complete (successfully or with failure)
                try
                {
                    await Task.WhenAll(taskA, taskB);
                }
                catch
                {
                    // Exceptions are expected; we'll check them below
                }

                // Count successes and failures
                int successCount = (taskA.IsCompletedSuccessfully ? 1 : 0) + (taskB.IsCompletedSuccessfully ? 1 : 0);
                int failureCount = (taskA.IsFaulted ? 1 : 0) + (taskB.IsFaulted ? 1 : 0);

                // Assert the expected outcome
                Assert.AreEqual(1, successCount, "Exactly one connection should succeed.");
                Assert.AreEqual(1, failureCount, "Exactly one connection should fail.");

                // Verify the failure is due to DuplicateConnection (error code 6)
                Task failedTask = taskA.IsFaulted ? taskA : taskB;
                if (failedTask.IsFaulted)
                {
                    var exception = failedTask.Exception?.InnerException;
                    Assert.IsNotNull(exception, "The failed task should have an exception.");
                    Assert.IsTrue(exception.Message.Contains("DuplicateConnection") || exception.Message.Contains("6"),
                        "The failure should be due to a duplicate connection error.");
                }
            }
        }*/

        [TestMethod]
        public async Task AllowConnectionsBetweenDifferentPairs()
        {
            var (server, serverPublicKey, port) = SetupServer();
            using (server)
            {
                using var clientA = await CreateClientAsync(port, serverPublicKey);
                using var clientB = await CreateClientAsync(port, serverPublicKey);
                using var clientC = await CreateClientAsync(port, serverPublicKey);

                // Establish A -> B
                var channelAB = await clientA.StartRelayedChannelAsync(clientB.LocalPublicKey);
                Assert.IsNotNull(channelAB, "Connection A -> B should be established");

                // Establish A -> C
                var channelAC = await clientA.StartRelayedChannelAsync(clientC.LocalPublicKey);
                Assert.IsNotNull(channelAC, "Connection A -> C should be established");

                // Establish B -> C
                var channelBC = await clientB.StartRelayedChannelAsync(clientC.LocalPublicKey);
                Assert.IsNotNull(channelBC, "Connection B -> C should be established");
            }
        }

        [TestMethod]
        public async Task SessionDisposalDuringConnectionAttempt()
        {
            var (server, serverPublicKey, port) = SetupServer();
            using (server)
            {
                using var clientA = await CreateClientAsync(port, serverPublicKey);
                using var clientB = await CreateClientAsync(port, serverPublicKey);

                // Start connection attempt A -> B
                var connectionTask = clientA.StartRelayedChannelAsync(clientB.LocalPublicKey);

                // Dispose client B immediately
                clientB.Dispose();

                // Connection attempt should fail
                await Assert.ThrowsExceptionAsync<Exception>(
                    async () => await connectionTask,
                    "Connection attempt should fail if target session is disposed"
                );
            }
        }

        [TestMethod]
        public async Task RelayedTransport_WithValidAppId_Success()
        {
            // Arrange: Set up server and clients
            var (server, serverPublicKey, port) = SetupServer();
            using (server)
            {
                const uint allowedAppId = 1234;
                var tcsB = new TaskCompletionSource<ChannelRelayed>();

                // Client B requires appId 1234
                using var clientB = await CreateClientAsync(
                    port,
                    serverPublicKey,
                    onNewChannel: (s, c) => tcsB.SetResult(c),
                    isHandshakeAllowed: (linkType, s, pk, code, appId) => appId == allowedAppId
                );

                using var clientA = await CreateClientAsync(port, serverPublicKey);

                // Act: Start relayed channel with valid appId
                var channelTask = clientA.StartRelayedChannelAsync(clientB.LocalPublicKey, appId: allowedAppId);
                var channelB = await tcsB.Task.WithTimeout(5000, "Channel B creation timed out");
                await channelTask.WithTimeout(5000, "Channel establishment timed out");

                // Assert: Channel is established
                Assert.IsNotNull(channelB, "Channel should be created on target with valid appId");
            }
        }

        [TestMethod]
        public async Task RelayedTransport_WithInvalidAppId_Fails()
        {
            // Arrange: Set up server and clients
            var (server, serverPublicKey, port) = SetupServer();
            using (server)
            {
                const uint allowedAppId = 1234;
                var tcsB = new TaskCompletionSource<ChannelRelayed>();

                // Client B requires appId 1234
                using var clientB = await CreateClientAsync(
                    port,
                    serverPublicKey,
                    onNewChannel: (s, c) => tcsB.SetResult(c),
                    isHandshakeAllowed: (linkType, s, pk, code, appId) => appId == allowedAppId
                );

                using var clientA = await CreateClientAsync(port, serverPublicKey);

                // Act & Assert: Attempt with invalid appId should fail
                await Assert.ThrowsExceptionAsync<Exception>(
                    async () => await clientA.StartRelayedChannelAsync(clientB.LocalPublicKey, appId: 5678),
                    "Starting relayed channel with invalid appId should fail"
                );

                // Ensure no channel was created on client B
                var channelTask = tcsB.Task;
                var completedTask = await Task.WhenAny(channelTask, Task.Delay(1000));
                Assert.AreNotEqual(channelTask, completedTask, "No channel should be created with invalid appId");
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