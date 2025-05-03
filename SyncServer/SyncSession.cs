using System.Buffers;
using System.Buffers.Binary;
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading.Tasks;
using Noise;
using SyncShared;
using static System.Runtime.InteropServices.JavaScript.JSType;
using static SyncServer.TcpSyncServer;
using LogLevel = SyncShared.LogLevel;

namespace SyncServer;

public class SyncSession
{
    public enum SessionPrimaryState
    {
        VersionCheck,
        Handshake,
        DataTransfer,
        Closed
    }

    public enum SessionSecondaryState
    {
        WaitingForSize,
        WaitingForData
    }

    public const int HEADER_SIZE = 6;
    public const int MAXIMUM_PACKET_SIZE = 65535 - 16;
    public const int MAXIMUM_PACKET_SIZE_ENCRYPTED = MAXIMUM_PACKET_SIZE + 16;
    private const long KV_STORAGE_LIMIT_PER_PUBLISHER = 10 * 1024 * 1024; // 10MB
    private const int MAX_ACTIVE_STREAMS = 10;

    public required Socket Socket { get; init; }
    public required HandshakeState HandshakeState { get; init; }
    public string? RemotePublicKey { get; private set; }
    public int RemoteVersion { get; private set; } = -1;
    private byte[] _sessionBuffer = new byte[8 * 1024];
    private byte[] _decryptionBuffer = new byte[8 * 1024];
    private readonly TcpSyncServer _server;
    private Transport? _transport;
    private Action<SyncSession> _onHandshakeComplete;
    private Action<SyncSession> _onClose;
    private readonly Dictionary<int, SyncStream> _syncStreams = new();
    private int _streamIdGenerator = 0;
    private readonly SemaphoreSlim _sendSemaphore = new SemaphoreSlim(1);
    private readonly bool _useRateLimits;

    public SyncSession(TcpSyncServer server, Action<SyncSession> onHandshakeComplete, Action<SyncSession> onClose, bool useRateLimits = true)
    {
        _server = server;
        _onHandshakeComplete = onHandshakeComplete;
        _onClose = onClose;
        _useRateLimits = useRateLimits;
    }

    public void Dispose()
    {
        _onClose?.Invoke(this);
        HandshakeState?.Dispose();
        Socket?.Close();
        lock (_syncStreams)
        {
            foreach (var pair in _syncStreams)
                pair.Value.Dispose();
            _syncStreams.Clear();
        }
        if (RemotePublicKey != null)
        {
            _server.RemoveRelayedConnectionsByPublicKey(RemotePublicKey);
        }
    }

    private async ValueTask ReceiveExactAsync(byte[] buffer, int offset, int size, CancellationToken cancellationToken = default)
    {
        Stopwatch? sw = null;
        if (Logger.WillLog(LogLevel.Debug))
            sw = new Stopwatch();

        int totalBytesReceived = 0;
        while (totalBytesReceived < size)
        {
            cancellationToken.ThrowIfCancellationRequested();

            sw?.Restart();
            int bytesReceived = await Socket.ReceiveAsync(new ArraySegment<byte>(buffer, offset + totalBytesReceived, size - totalBytesReceived));
            if (bytesReceived == 0)
                throw new Exception("Connection closed");
            if (Logger.WillLog(LogLevel.Debug))
                Logger.Debug<SyncSession>($"Receive duration ({bytesReceived}/{size} bytes), requested {size - totalBytesReceived} bytes: {sw?.ElapsedMilliseconds}ms");
            totalBytesReceived += bytesReceived;
        }

        if (Logger.WillLog(LogLevel.Debug))
            Logger.Debug<SyncSession>($"Received {totalBytesReceived} bytes.\n{Utilities.HexDump(buffer.AsSpan().Slice(0, totalBytesReceived))}");
    }

    public void Start()
    {
        _ = Task.Run(async () =>
        {
            try
            {
                await SendVersionAsync();
                await ReceiveExactAsync(_sessionBuffer, 0, 4);
                HandleVersionCheck(_sessionBuffer.AsSpan(0, 4));

                Interlocked.Increment(ref _server.Metrics.TotalHandshakeAttempts);

                await ReceiveExactAsync(_sessionBuffer, 0, 4);
                int handshakeSize = BinaryPrimitives.ReadInt32LittleEndian(_sessionBuffer.AsSpan(0, 4));
                if (handshakeSize > _sessionBuffer.Length)
                    throw new Exception($"Handshake size should be less than {_sessionBuffer.Length} bytes.");

                await ReceiveExactAsync(_sessionBuffer, 0, handshakeSize);
                Logger.Info<SyncSession>($"HandshakeAsResponder: Received handshake message ({handshakeSize} bytes)");

                var handshakeData = new ArraySegment<byte>(_sessionBuffer, 0, handshakeSize);

                int offset = 0;
                uint appId = BinaryPrimitives.ReadUInt32LittleEndian(handshakeData.Slice(offset, 4));
                offset += 4;
                int pairingMessageLength = BinaryPrimitives.ReadInt32LittleEndian(handshakeData.Slice(offset, 4));
                if (pairingMessageLength > 128)
                    throw new InvalidDataException($"Received pairing message length ({pairingMessageLength}) exceeds maximum allowed size (128) (app id: {appId}).");

                offset += 4;

                string? receivedPairingCode = null;
                if (pairingMessageLength > 0)
                {
                    if (handshakeData.Count < offset + pairingMessageLength)
                        throw new InvalidDataException($"Message too short for specified pairing message length (app id: {appId}).");
                    var pairingProtocol = new Protocol(HandshakePattern.N, CipherFunction.ChaChaPoly, HashFunction.Blake2b);
                    using var pairingHandshakeState = pairingProtocol.Create(false, s: _server.LocalKeyPair.PrivateKey);
                    var pairingMessage = handshakeData.Slice(offset, pairingMessageLength);
                    offset += pairingMessageLength;
                    var pairingPlaintext = new byte[512];
                    var (_, _, _) = pairingHandshakeState.ReadMessage(pairingMessage, pairingPlaintext);
                    receivedPairingCode = Encoding.UTF8.GetString(pairingPlaintext, 0, Array.IndexOf(pairingPlaintext, (byte)0, 0, Math.Min(32, pairingPlaintext.Length)));
                    Logger.Info<SyncSession>($"HandshakeAsResponder: Received pairing code '{receivedPairingCode}' from client (app id: {appId})");
                }

                if (handshakeData.Count < offset)
                    throw new InvalidDataException("Message too short for channel handshake.");
                var channelMessage = handshakeData.Slice(offset);
                var (_, _, _) = HandshakeState.ReadMessage(channelMessage, _decryptionBuffer);
                var (bytesWritten, _, transport) = HandshakeState.WriteMessage(null, _decryptionBuffer);
                Logger.Info<SyncSession>($"HandshakeAsResponder: Read channel message size {channelMessage.Count} (app id: {appId})");

                BinaryPrimitives.WriteInt32LittleEndian(_sessionBuffer, bytesWritten);
                _decryptionBuffer.AsSpan(0, bytesWritten).CopyTo(_sessionBuffer.AsSpan(4));

                try
                {
                    await _sendSemaphore.WaitAsync();
                    await SendAsync(_sessionBuffer, 0, bytesWritten + 4);
                }
                finally
                {
                    _sendSemaphore.Release();
                }

                Logger.Info<SyncSession>($"HandshakeAsResponder: Wrote response message size {bytesWritten} (app id: {appId})");

                _transport = transport;
                RemotePublicKey = Convert.ToBase64String(HandshakeState.RemoteStaticPublicKey);
                Logger.Info<SyncSession>($"HandshakeAsResponder: Remote public key {RemotePublicKey} (app id: {appId})");

                _onHandshakeComplete?.Invoke(this);
                Interlocked.Increment(ref _server.Metrics.TotalHandshakeSuccesses);

                string ipAddress = GetIpAddress();
                if (_useRateLimits && !_server.TryRegisterNewKeypair(ipAddress))
                {
                    Interlocked.Increment(ref _server.Metrics.TotalKeypairRegistrationRateLimitExceedances);
                    Logger.Error<SyncSession>($"IP {ipAddress} exceeded keypair rate limit (app id: {appId})");
                    Dispose();
                    return;
                }

                if (receivedPairingCode != null)
                    Logger.Info<SyncSession>($"Accepted pairing code '{receivedPairingCode}' from {RemotePublicKey} (app id: {appId})");

                while (true)
                {
                    await ReceiveExactAsync(_sessionBuffer, 0, 4);
                    int messageSize = BinaryPrimitives.ReadInt32LittleEndian(_sessionBuffer.AsSpan(0, 4));

                    if (messageSize <= _sessionBuffer.Length)
                    {
                        await ReceiveExactAsync(_sessionBuffer, 0, messageSize);
                        await HandlePacketAsync(new ArraySegment<byte>(_sessionBuffer, 0, messageSize));
                    }
                    else
                    {
                        var accumulatedBuffer = Utilities.RentBytes(messageSize);
                        try
                        {
                            await ReceiveExactAsync(accumulatedBuffer, 0, messageSize);
                            await HandlePacketAsync(new ArraySegment<byte>(accumulatedBuffer, 0, messageSize));
                        }
                        finally
                        {
                            Utilities.ReturnBytes(accumulatedBuffer);
                        }
                    }
                }
            }
            catch (Exception e)
            {
                Dispose();
                Logger.Error<SyncSession>($"Receive error", e);
            }
        });
    }

    private async ValueTask HandlePacketAsync(ArraySegment<byte> data)
    {
        int decryptedSize = data.Count - 16;
        var shouldRent = decryptedSize > _decryptionBuffer.Length;
        var decryptionBuffer = shouldRent ? Utilities.RentBytes(decryptedSize) : _decryptionBuffer;

        try
        {
            int plen = Decrypt(data, decryptionBuffer);
            await HandleDecryptedPacketAsync(new ArraySegment<byte>(decryptionBuffer, 0, plen));
        }
        finally
        {
            if (decryptionBuffer != _decryptionBuffer)
                Utilities.ReturnBytes(decryptionBuffer);
        }
    }

    private async ValueTask HandleStreamAsync(StreamOpcode subOpcode, ArraySegment<byte> data)
    {
        switch (subOpcode)
        {
            case StreamOpcode.START:
                {
                    ReadOnlySpan<byte> span = data;
                    int id = BinaryPrimitives.ReadInt32LittleEndian(span);
                    span = span.Slice(4);
                    int expectedSize = BinaryPrimitives.ReadInt32LittleEndian(span);
                    span = span.Slice(4);
                    byte op = span[0];
                    span = span.Slice(1);
                    byte subOp = span[0];
                    span = span.Slice(1);
                    var syncStream = new SyncStream(expectedSize, (Opcode)op, subOp);
                    if (span.Length > 0)
                        syncStream.Add(span);
                    lock (_syncStreams)
                    {
                        if (_syncStreams.Count >= MAX_ACTIVE_STREAMS)
                        {
                            Logger.Error<SyncSession>("Too many active streams, closing connection.");
                            Dispose();
                            return;
                        }
                        _syncStreams[id] = syncStream;
                    }
                    break;
                }

            case StreamOpcode.DATA:
                {
                    ReadOnlySpan<byte> span = data;
                    int id = BinaryPrimitives.ReadInt32LittleEndian(span);
                    span = span.Slice(4);
                    int expectedOffset = BinaryPrimitives.ReadInt32LittleEndian(span);
                    span = span.Slice(4);
                    SyncStream? syncStream;
                    lock (_syncStreams)
                    {
                        if (!_syncStreams.TryGetValue(id, out syncStream) || syncStream == null)
                            throw new Exception("Received data for sync stream that does not exist");
                    }
                    if (expectedOffset != syncStream.BytesReceived)
                        throw new Exception("Expected offset not matching with the amount of received bytes");
                    if (span.Length > 0)
                        syncStream.Add(span);
                    break;
                }

            case StreamOpcode.END:
                {
                    ReadOnlySpan<byte> span = data;
                    int id = BinaryPrimitives.ReadInt32LittleEndian(span);
                    span = span.Slice(4);
                    int expectedOffset = BinaryPrimitives.ReadInt32LittleEndian(span);
                    span = span.Slice(4);
                    SyncStream? syncStream;
                    lock (_syncStreams)
                    {
                        if (!_syncStreams.Remove(id, out syncStream) || syncStream == null)
                            throw new Exception("Received data for sync stream that does not exist");
                    }
                    if (expectedOffset != syncStream.BytesReceived)
                        throw new Exception("Expected offset not matching with the amount of received bytes");
                    if (span.Length > 0)
                        syncStream.Add(span);
                    if (!syncStream.IsComplete)
                        throw new Exception("After sync stream end, the stream must be complete");
                    await HandleDecryptedPacketAsync(syncStream.Opcode, syncStream.SubOpcode, syncStream.GetBytes());
                    break;
                }
        }
    }

    private async ValueTask HandleRequest(RequestOpcode subOpcode, ArraySegment<byte> data)
    {
        if (data.Count < 4)
        {
            Logger.Error<SyncSession>("Received a request without a request id, terminating connection.");
            Dispose();
            return;
        }

        int requestId = BinaryPrimitives.ReadInt32LittleEndian(data.Slice(0, 4));
        data = data.Slice(4);

        try
        {
            switch (subOpcode)
            {
                case RequestOpcode.CONNECTION_INFO:
                    await HandleRequestConnectionInfoAsync(requestId, data);
                    break;
                case RequestOpcode.TRANSPORT:
                    await HandleRequestTransportAsync(requestId, data);
                    break;
                case RequestOpcode.PUBLISH_RECORD:
                    await HandleRequestPublishRecordAsync(requestId, data);
                    break;
                case RequestOpcode.BULK_DELETE_RECORD:
                    await HandleRequestBulkDeleteRecordAsync(requestId, data);
                    break;
                case RequestOpcode.DELETE_RECORD:
                    await HandleRequestDeleteRecordAsync(requestId, data);
                    break;
                case RequestOpcode.LIST_RECORD_KEYS:
                    await HandleRequestListKeysAsync(requestId, data);
                    break;
                case RequestOpcode.GET_RECORD:
                    await HandleRequestGetRecordAsync(requestId, data);
                    break;
                case RequestOpcode.BULK_PUBLISH_RECORD:
                    Interlocked.Increment(ref _server.Metrics.TotalPublishRecordRequests);

                    if (data.Count < 10)
                    {
                        Logger.Error<SyncSession>("REQUEST_BULK_PUBLISH_RECORD packet too short");
                        await SendEmptyResponseAsync(ResponseOpcode.BULK_PUBLISH_RECORD, requestId, (int)BulkPublishRecordResponseCode.InvalidRequest);
                        return;
                    }
                    int keyLength = data[0];
                    if (keyLength > 32 || data.Count < 6 + keyLength)
                    {
                        await SendEmptyResponseAsync(ResponseOpcode.BULK_PUBLISH_RECORD, requestId, (int)BulkPublishRecordResponseCode.InvalidRequest);
                        return;
                    }
                    string key = Encoding.UTF8.GetString(data.Slice(1, keyLength));
                    byte numConsumers = data[1 + keyLength];
                    int offset = 2 + keyLength;
                    var records = new List<(byte[] publisherPublicKey, byte[] consumerPublicKey, string key, byte[] encryptedBlob)>(numConsumers);

                    byte[] publisherPublicKey = Convert.FromBase64String(RemotePublicKey!);
                    for (int i = 0; i < numConsumers; i++)
                    {
                        if (offset + 36 > data.Count)
                        {
                            await SendEmptyResponseAsync(ResponseOpcode.BULK_PUBLISH_RECORD, requestId, (int)BulkPublishRecordResponseCode.InvalidRequest);
                            return;
                        }
                        byte[] consumerPublicKey = data.Slice(offset, 32).ToArray();
                        offset += 32;
                        int blobLength = BinaryPrimitives.ReadInt32LittleEndian(data.Slice(offset, 4));
                        offset += 4;
                        if (offset + blobLength > data.Count)
                        {
                            await SendEmptyResponseAsync(ResponseOpcode.BULK_PUBLISH_RECORD, requestId, (int)BulkPublishRecordResponseCode.InvalidRequest);
                            return;
                        }
                        byte[] encryptedBlob = data.Slice(offset, blobLength).ToArray();
                        offset += blobLength;
                        records.Add((publisherPublicKey, consumerPublicKey, key, encryptedBlob));
                    }

                    var stopwatch = Stopwatch.StartNew();
                    _ = Task.Run(async () =>
                    {
                        try
                        {
                            long totalNewSize = records.Sum(r => r.encryptedBlob.Length);
                            long totalSize = await _server.RecordRepository.GetTotalSizeAsync(publisherPublicKey);
                            if (totalSize + totalNewSize > KV_STORAGE_LIMIT_PER_PUBLISHER)
                            {
                                await SendEmptyResponseAsync(ResponseOpcode.BULK_PUBLISH_RECORD, requestId, (int)BulkPublishRecordResponseCode.StorageLimitExceeded); // 2 = storage limit exceeded
                                return;
                            }
                            await _server.RecordRepository.BulkInsertOrUpdateAsync(records);

                            stopwatch.Stop();
                            Interlocked.Add(ref _server.Metrics.TotalPublishRecordTimeMs, stopwatch.ElapsedMilliseconds);
                            Interlocked.Increment(ref _server.Metrics.PublishRecordCount);
                            Interlocked.Increment(ref _server.Metrics.TotalPublishRecordSuccesses);
                            await SendEmptyResponseAsync(ResponseOpcode.BULK_PUBLISH_RECORD, requestId, (int)BulkPublishRecordResponseCode.Success); //Success
                        }
                        catch (Exception ex)
                        {
                            stopwatch.Stop();
                            Interlocked.Add(ref _server.Metrics.TotalPublishRecordTimeMs, stopwatch.ElapsedMilliseconds);
                            Interlocked.Increment(ref _server.Metrics.PublishRecordCount);
                            Interlocked.Increment(ref _server.Metrics.TotalPublishRecordFailures);
                            Logger.Error<SyncSession>("Error bulk publishing records", ex);
                            await SendEmptyResponseAsync(ResponseOpcode.BULK_PUBLISH_RECORD, requestId, (int)BulkPublishRecordResponseCode.GeneralError);
                        }
                    });
                    break;

                case RequestOpcode.BULK_GET_RECORD:
                    if (data.Count < 10) // Minimum: requestId (4) + keyLength (1) + key (0) + numPublishers (1)
                    {
                        Logger.Error<SyncSession>("REQUEST_BULK_GET_RECORD packet too short");
                        await SendEmptyResponseAsync(ResponseOpcode.BULK_GET_RECORD, requestId, (int)BulkGetRecordResponseCode.InvalidRequest);
                        return;
                    }
                    keyLength = data[0];
                    if (keyLength > 32 || data.Count < 6 + keyLength)
                    {
                        await SendEmptyResponseAsync(ResponseOpcode.BULK_GET_RECORD, requestId, (int)BulkGetRecordResponseCode.InvalidRequest);
                        return;
                    }
                    key = Encoding.UTF8.GetString(data.Slice(1, keyLength));
                    byte numPublishers = data[1 + keyLength];
                    offset = 2 + keyLength;
                    var publisherPublicKeys = new List<byte[]>(numPublishers);

                    for (int i = 0; i < numPublishers; i++)
                    {
                        if (offset + 32 > data.Count)
                        {
                            await SendEmptyResponseAsync(ResponseOpcode.BULK_GET_RECORD, requestId, (int)BulkGetRecordResponseCode.InvalidRequest);
                            return;
                        }
                        publisherPublicKeys.Add(data.Slice(offset, 32).ToArray());
                        offset += 32;
                    }

                    _ = Task.Run(async () =>
                    {
                        try
                        {
                            byte[] consumerPublicKey = Convert.FromBase64String(RemotePublicKey!);
                            var records = await _server.RecordRepository.GetByPublishersAsync(consumerPublicKey, publisherPublicKeys, key);
                            using var ms = new MemoryStream();
                            using var writer = new BinaryWriter(ms);
                            writer.Write(requestId);
                            writer.Write((int)BulkGetRecordResponseCode.Success); //status code
                            writer.Write((byte)records.Count());
                            foreach (var record in records)
                            {
                                writer.Write(record.PublisherPublicKey);
                                writer.Write(record.EncryptedBlob.Length);
                                writer.Write(record.EncryptedBlob);
                                writer.Write(record.Timestamp.ToBinary());
                            }
                            await SendAsync(Opcode.RESPONSE, (byte)ResponseOpcode.BULK_GET_RECORD, ms.ToArray());
                        }
                        catch (Exception ex)
                        {
                            Logger.Error<SyncSession>("Error bulk getting records", ex);
                            await SendEmptyResponseAsync(ResponseOpcode.BULK_GET_RECORD, requestId, (int)BulkGetRecordResponseCode.GeneralError);
                        }
                    });
                    break;
                case RequestOpcode.BULK_CONNECTION_INFO:
                    await HandleRequestBulkConnectionInfoAsync(requestId, data);
                    break;
                default:
                    Logger.Info<SyncSession>($"Invalid RequestOpcode received {subOpcode}.");
                    await SendEmptyResponseAsync((ResponseOpcode)((byte)subOpcode), requestId, 1);
                    //TODO: Dispose?
                    break;
            }
        }
        catch (Exception e)
        {
            Logger.Error<SyncSession>($"Generic error happened in request handler {subOpcode}.", e);
            await SendEmptyResponseAsync((ResponseOpcode)((byte)subOpcode), requestId, 1);
            //TODO: Dispose?
        }
    }

    private async ValueTask HandleResponse(ResponseOpcode subOpcode, ArraySegment<byte> data)
    {
        switch (subOpcode)
        {
            case ResponseOpcode.TRANSPORT:
                if (data.Count < 16)
                {
                    Logger.Error<SyncSession>("ResponseOpcode.TRANSPORT packet too short");
                    return;
                }

                int statusCode = BinaryPrimitives.ReadInt32LittleEndian(data.Slice(0, 4));
                long connectionId = BinaryPrimitives.ReadInt64LittleEndian(data.Slice(4, 8));
                int requestId = BinaryPrimitives.ReadInt32LittleEndian(data.Slice(12, 4));
                var connection = _server.GetRelayedConnection(connectionId);
                if (connection == null)
                {
                    Logger.Error<SyncSession>($"No relayed connection found for connectionId {connectionId}");
                    _server.RemoveRelayPairByConnectionId(connectionId);
                    return;
                }

                if (statusCode == 0)
                {
                    if (data.Count < 20)
                    {
                        Logger.Error<SyncSession>("ResponseOpcode.TRANSPORT packet too short for message length");
                        _server.RemoveRelayedConnection(connectionId);
                        return;
                    }
                    int messageLength = BinaryPrimitives.ReadInt32LittleEndian(data.Slice(16, 4));
                    if (data.Count != 20 + messageLength)
                    {
                        Logger.Error<SyncSession>($"Invalid ResponseOpcode.TRANSPORT packet size. Expected {20 + messageLength}, got {data.Count}");
                        return;
                    }

                    connection.Target = this;
                    connection.IsActive = true;
                    var packetSize = 24 + messageLength;
                    var packetToInitiator = Utilities.RentBytes(packetSize);
                    try
                    {
                        BinaryPrimitives.WriteInt32LittleEndian(packetToInitiator.AsSpan(0, 4), requestId);
                        BinaryPrimitives.WriteInt32LittleEndian(packetToInitiator.AsSpan(4, 4), statusCode);
                        BinaryPrimitives.WriteInt32LittleEndian(packetToInitiator.AsSpan(8, 4), RemoteVersion);
                        BinaryPrimitives.WriteInt64LittleEndian(packetToInitiator.AsSpan(12, 8), connectionId);
                        BinaryPrimitives.WriteInt32LittleEndian(packetToInitiator.AsSpan(20, 4), messageLength);
                        data.Slice(20, messageLength).CopyTo(new ArraySegment<byte>(packetToInitiator, 24, messageLength));
                        await connection.Initiator.SendAsync(Opcode.RESPONSE, (byte)ResponseOpcode.TRANSPORT_RELAYED, new ArraySegment<byte>(packetToInitiator, 0, packetSize));
                        Interlocked.Increment(ref _server.Metrics.TotalRelayedConnectionsEstablished);
                    }
                    finally
                    {
                        Utilities.ReturnBytes(packetToInitiator);
                    }
                }
                else
                {
                    byte[] packetToInitiator = Utilities.RentBytes(8);
                    try
                    {
                        BinaryPrimitives.WriteInt32LittleEndian(packetToInitiator.AsSpan().Slice(0, 4), requestId);
                        BinaryPrimitives.WriteInt32LittleEndian(packetToInitiator.AsSpan().Slice(4, 4), statusCode);
                        await connection.Initiator.SendAsync(Opcode.RESPONSE, (byte)ResponseOpcode.TRANSPORT_RELAYED, new ArraySegment<byte>(packetToInitiator, 0, 8));
                        _server.RemoveRelayedConnection(connectionId);
                        if (statusCode != (int)TransportResponseCode.DuplicateConnection)
                        {
                            string initiatorPublicKey = connection.Initiator.RemotePublicKey!;
                            string targetPublicKey = RemotePublicKey!;
                            _server.AddToBlacklist(initiatorPublicKey, targetPublicKey, TimeSpan.FromMinutes(5));
                            Logger.Info<SyncSession>($"Added relay from {initiatorPublicKey} to {targetPublicKey} to blacklist for 5 minutes due to rejection.");
                        }
                    }
                    finally
                    {
                        Utilities.ReturnBytes(packetToInitiator);
                    }
                }
                break;
        }
    }

    private async ValueTask HandleRelayAsync(RelayOpcode opcode, ArraySegment<byte> data)
    {
        switch (opcode)
        {
            case RelayOpcode.DATA:
                await ForwardRelayDataAsync(data);
                break;
            case RelayOpcode.ERROR:
                await ForwardRelayErrorAsync(data);
                break;
            case RelayOpcode.RELAY_ERROR:
                await HandleRelayErrorAsync(data);
                break;
        }
    }

    private void HandleNotify(NotifyOpcode opcode, Span<byte> data)
    {
        switch (opcode)
        {
            case NotifyOpcode.CONNECTION_INFO:
                HandlePublishConnectionInfo(data);
                break;
        }
    }

    private async ValueTask HandleDecryptedPacketAsync(Opcode opcode, byte subOpcode, ArraySegment<byte> data)
    {
        switch (opcode)
        {
            case Opcode.STREAM:
                await HandleStreamAsync((StreamOpcode)subOpcode, data);
                break;
            case Opcode.PING:
                await SendAsync(Opcode.PONG);
                break;
            case Opcode.REQUEST:
                await HandleRequest((RequestOpcode)subOpcode, data);
                break;
            case Opcode.RESPONSE:
                await HandleResponse((ResponseOpcode)subOpcode, data);
                break;
            case Opcode.NOTIFY:
                HandleNotify((NotifyOpcode)subOpcode, data);
                break;
            case Opcode.RELAY:
                await HandleRelayAsync((RelayOpcode)subOpcode, data);
                break;
            default:
                Logger.Debug<SyncSession>($"Received unhandled opcode: {opcode}");
                break;
        }
    }

    private async ValueTask HandleDecryptedPacketAsync(ArraySegment<byte> data)
    {
        int size = BinaryPrimitives.ReadInt32LittleEndian(data.Slice(0, 4));
        if (size != data.Count - 4)
            throw new Exception("Incomplete packet received");

        Opcode opcode = (Opcode)data[4];
        byte subOpcode = data[5];
        var packetData = data.Slice(6);

        if (Logger.WillLog(LogLevel.Debug))
            Logger.Debug<SyncSession>($"HandleDecryptedPacket (opcode = {opcode}, subOpcode = {subOpcode}, size = {packetData.Count})");
        await HandleDecryptedPacketAsync(opcode, subOpcode, packetData);
    }

    private async ValueTask ForwardRelayDataAsync(ArraySegment<byte> data)
    {
        if (data.Count < 8)
        {
            Logger.Error<SyncSession>("RELAY_DATA packet too short");
            return;
        }

        long connectionId = BinaryPrimitives.ReadInt64LittleEndian(data.Slice(0, 8));
        var connection = _server.GetRelayedConnection(connectionId);

        string ipAddress = GetIpAddress();
        if (_useRateLimits && !_server.IsRelayDataAllowedByIP(ipAddress, data.Count))
        {
            Interlocked.Increment(ref _server.Metrics.TotalRelayDataByIpRateLimitExceedances);
            Logger.Error<SyncSession>($"IP {ipAddress} exceeded relay data rate limit");
            await SendRelayErrorAsync(connectionId, RelayErrorCode.RateLimitExceeded);
            _server.RemoveRelayedConnection(connectionId);
            return;
        }

        if (_useRateLimits && !_server.IsRelayDataAllowedByConnectionId(connectionId, data.Count))
        {
            Interlocked.Increment(ref _server.Metrics.TotalRelayDataByConnectionIdRateLimitExceedances);
            Logger.Error<SyncSession>($"Received data to relay but exceeded ConnectionId rate limit for connectionId {connectionId}, connection terminated.");
            await SendRelayErrorAsync(connectionId, RelayErrorCode.RateLimitExceeded);
            _server.RemoveRelayedConnection(connectionId);
            return;
        }

        if (connection == null || !connection.IsActive)
        {
            Logger.Error<SyncSession>($"Received data to relay but no relayed connection for connectionId {connectionId}");
            await SendRelayErrorAsync(connectionId, RelayErrorCode.NotFound);
            _server.RemoveRelayedConnection(connectionId);
            return;
        }
        if (connection.Initiator != this && connection.Target != this)
        {
            Logger.Error<SyncSession>($"Received data to relay but unauthorized access to relayed connection {connectionId} by {this.RemotePublicKey}");
            await SendRelayErrorAsync(connectionId, RelayErrorCode.Unauthorized);
            _server.RemoveRelayedConnection(connectionId);
            return;
        }
        SyncSession? otherClient = connection.Initiator == this ? connection.Target : connection.Initiator;
        if (otherClient != null)
        {
            byte[] packet = Utilities.RentBytes(data.Count);
            try
            {
                BinaryPrimitives.WriteInt64LittleEndian(packet.AsSpan(0, 8), connectionId);
                data.Slice(8).CopyTo(packet, 8);
                await otherClient.SendAsync(Opcode.RELAY, (byte)RelayOpcode.RELAYED_DATA, new ArraySegment<byte>(packet, 0, data.Count));
                Interlocked.Add(ref _server.Metrics.TotalRelayedDataBytes, data.Count - 8);
            }
            catch (Exception e)
            {
                Logger.Warning<SyncSession>($"Failed to relay data from {RemotePublicKey} to {otherClient}. Closing connection.", e);
                otherClient.Dispose();
            }
            finally
            {
                Utilities.ReturnBytes(packet);
            }
        }
        else
            Logger.Warning<SyncSession>($"Relay data requested for null client by {this.RemotePublicKey}");
    }

    private async ValueTask ForwardRelayErrorAsync(ArraySegment<byte> data)
    {
        if (data.Count < 8)
        {
            Logger.Error<SyncSession>("ERROR relay packet too short");
            return;
        }

        long connectionId = BinaryPrimitives.ReadInt64LittleEndian(data.Slice(0, 8));
        var connection = _server.GetRelayedConnection(connectionId);
        if (connection == null || !connection.IsActive)
        {
            Logger.Error<SyncSession>($"Received error to relay but no active relayed connection for connectionId {connectionId}");
            await SendRelayErrorAsync(connectionId, RelayErrorCode.NotFound);
            _server.RemoveRelayPairByConnectionId(connectionId);
            return;
        }
        if (connection.Initiator != this && connection.Target != this)
        {
            Logger.Error<SyncSession>($"Received error to relay but unauthorized access to relayed connection {connectionId} by {this.RemotePublicKey}");
            await SendRelayErrorAsync(connectionId, RelayErrorCode.Unauthorized);
            _server.RemoveRelayPairByConnectionId(connectionId);
            return;
        }
        SyncSession? otherClient = connection.Initiator == this ? connection.Target : connection.Initiator;
        if (otherClient != null)
        {
            byte[] packet = Utilities.RentBytes(data.Count);
            try
            {
                BinaryPrimitives.WriteInt64LittleEndian(packet.AsSpan(0, 8), connectionId);
                data.Slice(8).CopyTo(packet, 8);
                await otherClient.SendAsync(Opcode.RELAY, (byte)RelayOpcode.RELAYED_ERROR, new ArraySegment<byte>(packet, 0, data.Count));
                Interlocked.Add(ref _server.Metrics.TotalRelayedErrorBytes, data.Count - 8);
            }
            catch (Exception e)
            {
                Logger.Warning<SyncSession>($"Failed to relay data from {RemotePublicKey} to {otherClient}. Closing connection.", e);
                otherClient.Dispose();
            }
            finally
            {
                Utilities.ReturnBytes(packet);
            }
        }
        else
            Logger.Warning<SyncSession>($"Relay error requested for null client by {this.RemotePublicKey}");
    }

    private async ValueTask HandleRelayErrorAsync(ArraySegment<byte> data)
    {
        if (data.Count < 12)
        {
            Logger.Error<SyncSession>("RELAY_ERROR packet too short");
            return;
        }

        long connectionId = BinaryPrimitives.ReadInt64LittleEndian(data.Slice(0, 8));
        RelayErrorCode errorCode = (RelayErrorCode)BinaryPrimitives.ReadInt32LittleEndian(data.Slice(8, 4));
        var connection = _server.GetRelayedConnection(connectionId);
        if (connection == null || !connection.IsActive)
        {
            Logger.Error<SyncSession>($"Received relay error but no active relayed connection for connectionId {connectionId}");
            await SendRelayErrorAsync(connectionId, RelayErrorCode.ConnectionClosed);
            _server.RemoveRelayPairByConnectionId(connectionId);
            return;
        }
        if (connection.Initiator != this && connection.Target != this)
        {
            Logger.Error<SyncSession>($"Received relay error but it was unauthorized access to relayed connection {connectionId} by {this.RemotePublicKey}");
            await SendRelayErrorAsync(connectionId, RelayErrorCode.Unauthorized);
            _server.RemoveRelayPairByConnectionId(connectionId);
            return;
        }

        Logger.Error<SyncSession>($"Received relay error {errorCode} from {this.RemotePublicKey} about connection {connectionId}, closing connection.");

        SyncSession? otherClient = connection.Initiator == this ? connection.Target : connection.Initiator;
        if (otherClient != null)
            await otherClient.SendRelayErrorAsync(connectionId, errorCode);

        _server.RemoveRelayedConnection(connectionId);
    }

    private async ValueTask HandleRequestBulkDeleteRecordAsync(int requestId, ArraySegment<byte> data)
    {
        if (data.Count < 65) // Minimum: publisher (32) + consumer (32) + numKeys (1)
        {
            Logger.Error<SyncSession>("REQUEST_BULK_DELETE_RECORD packet too short");
            await SendEmptyResponseAsync(ResponseOpcode.BULK_DELETE_RECORD, requestId, (int)BulkDeleteRecordResponseCode.InvalidRequest);
            return;
        }
        byte[] publisherPublicKey = data.Slice(0, 32).ToArray();
        byte[] consumerPublicKey = data.Slice(32, 32).ToArray();
        byte numKeys = data[64];
        int offset = 65;
        var keys = new List<string>(numKeys);

        for (int i = 0; i < numKeys; i++)
        {
            if (offset >= data.Count)
            {
                await SendEmptyResponseAsync(ResponseOpcode.BULK_DELETE_RECORD, requestId, (int)BulkDeleteRecordResponseCode.InvalidRequest);
                return;
            }
            byte keyLength = data[offset];
            offset += 1;
            if (offset + keyLength > data.Count || keyLength > 32)
            {
                await SendEmptyResponseAsync(ResponseOpcode.BULK_DELETE_RECORD, requestId, (int)BulkDeleteRecordResponseCode.InvalidRequest);
                return;
            }
            string key = Encoding.UTF8.GetString(data.Slice(offset, keyLength));
            keys.Add(key);
            offset += keyLength;
        }
        byte[] senderPublicKey = Convert.FromBase64String(RemotePublicKey!);

        // Authorization: Sender must be publisher or consumer
        if (!senderPublicKey.SequenceEqual(publisherPublicKey) && !senderPublicKey.SequenceEqual(consumerPublicKey))
        {
            await SendEmptyResponseAsync(ResponseOpcode.BULK_DELETE_RECORD, requestId, (int)BulkDeleteRecordResponseCode.Unauthorized); // Unauthorized
            return;
        }

        _ = Task.Run(async () =>
        {
            try
            {
                await _server.RecordRepository.BulkDeleteAsync(publisherPublicKey, consumerPublicKey, keys);
                await SendEmptyResponseAsync(ResponseOpcode.BULK_DELETE_RECORD, requestId, (int)BulkDeleteRecordResponseCode.Success); // Success
            }
            catch (Exception ex)
            {
                Logger.Error<SyncSession>("Error bulk deleting records", ex);
                await SendEmptyResponseAsync(ResponseOpcode.BULK_DELETE_RECORD, requestId, (int)BulkDeleteRecordResponseCode.GeneralError); // Error
            }
        });
    }

    private async ValueTask HandleRequestBulkConnectionInfoAsync(int requestId, ArraySegment<byte> data)
    {
        if (data.Count < 1)
        {
            Logger.Error<SyncSession>("REQUEST_BULK_CONNECTION_INFO packet too short");
            await SendEmptyResponseAsync(ResponseOpcode.BULK_CONNECTION_INFO, requestId, (int)BulkConnectionInfoResponseCode.InvalidRequest);
            return;
        }
        byte numKeys = data[0];
        if (data.Count != 1 + numKeys * 32)
        {
            Logger.Error<SyncSession>("Invalid REQUEST_BULK_CONNECTION_INFO packet size");
            await SendEmptyResponseAsync(ResponseOpcode.BULK_CONNECTION_INFO, requestId, (int)BulkConnectionInfoResponseCode.InvalidRequest);
            return;
        }
        var publicKeys = new List<string>(numKeys);
        for (int i = 0; i < numKeys; i++)
        {
            string pk = Convert.ToBase64String(data.Slice(1 + i * 32, 32));
            publicKeys.Add(pk);
        }
        string requestingPublicKey = RemotePublicKey!;

        var responseData = new MemoryStream();
        using var writer = new BinaryWriter(responseData);
        writer.Write(requestId); // 4 bytes: Request ID
        writer.Write((int)BulkConnectionInfoResponseCode.Success);
        writer.Write(numKeys); // 1 byte: Number of responses
        foreach (var pk in publicKeys)
        {
            var block = _server.RetrieveConnectionInfo(pk, requestingPublicKey);
            writer.Write(Convert.FromBase64String(pk)); //32 bytes: Public key
            if (block != null)
            {
                writer.Write((byte)0); // 1 byte: Status (success)
                writer.Write(block.Length); // 4 bytes: Length of connection info
                writer.Write(block); // Variable: Connection info data
            }
            else
            {
                writer.Write((byte)1); // 1 byte: Status (not found)
            }
        }
        await SendAsync(Opcode.RESPONSE, (byte)ResponseOpcode.BULK_CONNECTION_INFO, responseData.ToArray());
    }

    private void HandlePublishConnectionInfo(ReadOnlySpan<byte> data)
    {
        if (RemotePublicKey == null)
        {
            Logger.Error<SyncSession>("Cannot publish connection info before handshake completes.");
            return;
        }

        int offset = 0;
        byte numEntries = data[offset];
        offset += 1;

        var remoteIpBytes = ((IPEndPoint)Socket.RemoteEndPoint!).Address.GetAddressBytes();
        for (int i = 0; i < numEntries; i++)
        {
            ReadOnlySpan<byte> publicKeySpan = data.Slice(offset, 32);
            string intendedPublicKey = Convert.ToBase64String(publicKeySpan);
            offset += 32;

            ReadOnlySpan<byte> handshakeSpan = data.Slice(offset, 48);
            offset += 48;

            int ciphertextLength = BinaryPrimitives.ReadInt32LittleEndian(data.Slice(offset, 4));
            offset += 4;

            ReadOnlySpan<byte> ciphertextSpan = data.Slice(offset, ciphertextLength);
            offset += ciphertextLength;

            byte[] block = new byte[1 + remoteIpBytes.Length + 48 + ciphertextLength];
            block[0] = (byte)remoteIpBytes.Length;
            remoteIpBytes.CopyTo(block.AsSpan(1, remoteIpBytes.Length));
            handshakeSpan.CopyTo(block.AsSpan(1 + remoteIpBytes.Length, 48));
            ciphertextSpan.CopyTo(block.AsSpan(1 + remoteIpBytes.Length + 48, ciphertextLength));

            _server.StoreConnectionInfo(RemotePublicKey, intendedPublicKey, block);
        }

        Logger.Info<SyncSession>($"Published connection info for {numEntries} authorized keys by {RemotePublicKey}.");
    }

    private async ValueTask HandleRequestConnectionInfoAsync(int requestId, ArraySegment<byte> data)
    {
        if (data.Count != 32)
        {
            Logger.Error<SyncSession>("Invalid target public key length in REQUEST_CONNECTION_INFO");
            await SendEmptyResponseAsync(ResponseOpcode.CONNECTION_INFO, requestId, (int)ConnectionInfoResponseCode.InvalidRequest); 
            return;
        }

        string targetPublicKey = Convert.ToBase64String(data.Slice(0, 32)); 
        string requestingPublicKey = RemotePublicKey!;

        var block = _server.RetrieveConnectionInfo(targetPublicKey, requestingPublicKey);
        if (block == null)
        {
            await SendEmptyResponseAsync(ResponseOpcode.CONNECTION_INFO, requestId, (int)ConnectionInfoResponseCode.NotFound);
            return;
        }

        var responseData = Utilities.RentBytes(8 + block.Length);

        try
        {
            BinaryPrimitives.WriteInt32LittleEndian(responseData.AsSpan(0, 4), requestId);
            BinaryPrimitives.WriteInt32LittleEndian(responseData.AsSpan(4, 4), 0); //status code
            block.CopyTo(responseData.AsSpan(8));
            await SendAsync(Opcode.RESPONSE, (byte)ResponseOpcode.CONNECTION_INFO, responseData, 0, 8 + block.Length);
        }
        finally
        {
            Utilities.ReturnBytes(responseData);
        }
    }

    private async ValueTask HandleRequestTransportAsync(int requestId, ArraySegment<byte> data)
    {
        Interlocked.Increment(ref _server.Metrics.TotalRelayedConnectionsRequested);

        if (data.Count < 40)
        {
            Logger.Error<SyncSession>("REQUEST_TRANSPORT packet too short");
            await SendEmptyResponseAsync(ResponseOpcode.TRANSPORT_RELAYED, requestId, (int)TransportResponseCode.GeneralError);
            return;
        }

        int offset = 0;
        uint appId = BinaryPrimitives.ReadUInt32LittleEndian(data.Slice(offset, 4));
        offset += 4;

        string targetPublicKey = Convert.ToBase64String(data.Slice(offset, 32));
        offset += 32;

        int pairingMessageLength = BinaryPrimitives.ReadInt32LittleEndian(data.Slice(offset, 4));
        offset += 4;

        if (pairingMessageLength > 0)
        {
            if (data.Count < offset + pairingMessageLength + 4)
            {
                Logger.Error<SyncSession>($"REQUEST_TRANSPORT packet too short for pairing message (app id: {appId})");
                await SendEmptyResponseAsync(ResponseOpcode.TRANSPORT_RELAYED, requestId, (int)TransportResponseCode.PairingCodeDataMismatch);
                return;
            }
            offset += pairingMessageLength;
        }

        Logger.Verbose<SyncSession>($"Transport request received (from = {RemotePublicKey}, to = {targetPublicKey}) (app id: {appId}).");

        int channelMessageLength = BinaryPrimitives.ReadInt32LittleEndian(data.Slice(offset, 4));
        if (data.Count != offset + 4 + channelMessageLength)
        {
            Logger.Error<SyncSession>($"Invalid REQUEST_TRANSPORT packet size. Expected {offset + 4 + channelMessageLength}, got {data.Count} (app id: {appId})");
            await SendEmptyResponseAsync(ResponseOpcode.TRANSPORT_RELAYED, requestId, (int)TransportResponseCode.ChannelMessageDataLengthMismatch);
            return;
        }

        if (_server.IsBlacklisted(RemotePublicKey!, targetPublicKey))
        {
            Logger.Info<SyncSession>($"Relay request from {RemotePublicKey} to {targetPublicKey} rejected due to blacklist (app id: {appId}).");
            await SendEmptyResponseAsync(ResponseOpcode.TRANSPORT_RELAYED, requestId, (int)TransportResponseCode.Blacklisted);
            return;
        }

        if (_useRateLimits)
        {
            string ipAddress = GetIpAddress();
            var (allowedByIp, reasonByIp) = _server.IsRelayRequestAllowedByIP(ipAddress);
            if (!allowedByIp)
            {
                if (reasonByIp == RateLimitReason.TokenRateLimitExceeded)
                {
                    Interlocked.Increment(ref _server.Metrics.TotalRelayRequestByIpTokenRateLimitExceedances);
                }
                else if (reasonByIp == RateLimitReason.ConnectionLimitExceeded)
                {
                    Interlocked.Increment(ref _server.Metrics.TotalRelayRequestByIpConnectionLimitExceedances);
                }
                Logger.Error<SyncSession>($"IP {ipAddress} exceeded relay request limit: {reasonByIp} (app id: {appId})");
                await SendEmptyResponseAsync(ResponseOpcode.TRANSPORT_RELAYED, requestId, (int)TransportResponseCode.RateLimitExceeded);
                return;
            }

            var (allowedByKey, reasonByKey) = _server.IsRelayRequestAllowedByKey(RemotePublicKey!);
            if (!allowedByKey)
            {
                if (reasonByKey == RateLimitReason.TokenRateLimitExceeded)
                {
                    Interlocked.Increment(ref _server.Metrics.TotalRelayRequestByKeyTokenRateLimitExceedances);
                }
                else if (reasonByKey == RateLimitReason.ConnectionLimitExceeded)
                {
                    Interlocked.Increment(ref _server.Metrics.TotalRelayRequestByKeyConnectionLimitExceedances);
                }
                Logger.Error<SyncSession>($"Remote public key {RemotePublicKey!} exceeded relay request limit: {reasonByKey} (app id: {appId})");
                await SendEmptyResponseAsync(ResponseOpcode.TRANSPORT_RELAYED, requestId, (int)TransportResponseCode.RateLimitExceeded);
                return;
            }
        }

        var targetSession = _server.GetSession(targetPublicKey);
        if (targetSession == null)
        {
            Logger.Info<SyncSession>($"Target {targetPublicKey} not found for relay request (app id: {appId}).");
            await SendEmptyResponseAsync(ResponseOpcode.TRANSPORT_RELAYED, requestId, (int)TransportResponseCode.GeneralError);
            return;
        }

        long connectionId = _server.GetNextConnectionId();
        /* TODO REIMPLEMENT if (!_server.TryReserveRelayPair(RemotePublicKey!, targetPublicKey, connectionId, out var pair))
        {
            Logger.Info<SyncSession>($"Relay request from {RemotePublicKey} to {targetPublicKey} rejected due to existing connection (app id: {appId}).");
            await SendEmptyResponseAsync(ResponseOpcode.TRANSPORT_RELAYED, requestId, (int)TransportResponseCode.DuplicateConnection);
            return;
        }*/

        bool setupFailed = true;
        try
        {
            _server.SetRelayedConnection(connectionId, this);

            byte[] initiatorPublicKeyBytes = Convert.FromBase64String(RemotePublicKey!);
            byte[] pairingMessage = pairingMessageLength > 0 ? data.Slice(40, pairingMessageLength).ToArray() : Array.Empty<byte>();
            byte[] channelHandshakeMessage = data.Slice(offset + 4, channelMessageLength).ToArray();

            var packetSize = 4 + 8 + 4 + 4 + 32 + 4 + pairingMessageLength + 4 + channelMessageLength;
            var packetToTarget = Utilities.RentBytes(packetSize);

            try
            {
                int packetOffset = 0;
                BinaryPrimitives.WriteInt32LittleEndian(packetToTarget.AsSpan(packetOffset, 4), RemoteVersion);
                packetOffset += 4;
                BinaryPrimitives.WriteInt64LittleEndian(packetToTarget.AsSpan(packetOffset, 8), connectionId);
                packetOffset += 8;
                BinaryPrimitives.WriteInt32LittleEndian(packetToTarget.AsSpan(packetOffset, 4), requestId);
                packetOffset += 4;
                BinaryPrimitives.WriteUInt32LittleEndian(packetToTarget.AsSpan(packetOffset, 4), appId);
                packetOffset += 4;
                initiatorPublicKeyBytes.CopyTo(packetToTarget.AsSpan(packetOffset, 32));
                packetOffset += 32;
                BinaryPrimitives.WriteInt32LittleEndian(packetToTarget.AsSpan(packetOffset, 4), pairingMessageLength);
                packetOffset += 4;
                if (pairingMessageLength > 0)
                {
                    pairingMessage.CopyTo(packetToTarget.AsSpan(packetOffset));
                    packetOffset += pairingMessageLength;
                }
                BinaryPrimitives.WriteInt32LittleEndian(packetToTarget.AsSpan(packetOffset, 4), channelMessageLength);
                packetOffset += 4;
                channelHandshakeMessage.CopyTo(packetToTarget.AsSpan(packetOffset));

                await targetSession.SendAsync(Opcode.REQUEST, (byte)RequestOpcode.TRANSPORT_RELAYED, new ArraySegment<byte>(packetToTarget, 0, packetSize));
                setupFailed = false;
            }
            finally
            {
                Utilities.ReturnBytes(packetToTarget);
            }
        }
        catch (Exception ex)
        {
            Logger.Error<SyncSession>($"Failed to setup relay connection {connectionId}: {ex.Message} (app id: {appId})");
            throw;
        }
        finally
        {
            if (setupFailed)
                _server.RemoveRelayedConnection(connectionId);
        }
    }

    private async ValueTask HandleRequestPublishRecordAsync(int requestId, ArraySegment<byte> data)
    {
        Interlocked.Increment(ref _server.Metrics.TotalPublishRecordRequests);

        if (data.Count < 37)
        {
            Logger.Error<SyncSession>("REQUEST_PUBLISH_RECORD packet too short");
            await SendEmptyResponseAsync(ResponseOpcode.PUBLISH_RECORD, requestId, (int)PublishRecordResponseCode.InvalidRequest); 
            return;
        }
        byte[] consumerPublicKey = data.Slice(0, 32).ToArray();
        int keyLength = data[32];
        if (keyLength > 32)
        {
            await SendEmptyResponseAsync(ResponseOpcode.PUBLISH_RECORD, requestId, (int)PublishRecordResponseCode.ConsumerPublicKeyDataLengthMismatch);
            return;
        }
        string key = Encoding.UTF8.GetString(data.Slice(33, keyLength));
        int blobLengthOffset = 33 + keyLength;
        int blobLength = BinaryPrimitives.ReadInt32LittleEndian(data.Slice(blobLengthOffset, 4));
        if (data.Count < blobLengthOffset + 4 + blobLength)
        {
            await SendEmptyResponseAsync(ResponseOpcode.PUBLISH_RECORD, requestId, (int)PublishRecordResponseCode.BlobPublicKeyDataLengthMismatch);
            return;
        }
        byte[] encryptedBlob = data.Slice(blobLengthOffset + 4, blobLength).ToArray();
        byte[] publisherPublicKey = Convert.FromBase64String(RemotePublicKey!);

        string ipAddress = GetIpAddress();
        if (_useRateLimits && !_server.IsPublishRequestAllowed(ipAddress))
        {
            Interlocked.Increment(ref _server.Metrics.TotalPublishRequestRateLimitExceedances);
            Logger.Error<SyncSession>($"IP {ipAddress} exceeded publish request rate limit");
            await SendEmptyResponseAsync(ResponseOpcode.PUBLISH_RECORD, requestId, (int)PublishRecordResponseCode.RateLimitExceeded); 
            return;
        }

        var stopwatch = Stopwatch.StartNew();
        _ = Task.Run(async () =>
        {
            try
            {
                long totalSize = await _server.RecordRepository.GetTotalSizeAsync(publisherPublicKey);
                if (totalSize + encryptedBlob.Length > KV_STORAGE_LIMIT_PER_PUBLISHER)
                {
                    Logger.Error<SyncSession>($"KV_STORAGE_LIMIT_PER_PUBLISHER exceeded for key '{publisherPublicKey}'.");
                    Interlocked.Increment(ref _server.Metrics.TotalStorageLimitExceedances);
                    await SendEmptyResponseAsync(ResponseOpcode.PUBLISH_RECORD, requestId, (int)PublishRecordResponseCode.StorageLimitExceeded); 
                    return;
                }
                await _server.RecordRepository.InsertOrUpdateAsync(publisherPublicKey, consumerPublicKey, key, encryptedBlob);
                stopwatch.Stop();
                Interlocked.Add(ref _server.Metrics.TotalPublishRecordTimeMs, stopwatch.ElapsedMilliseconds);
                Interlocked.Increment(ref _server.Metrics.PublishRecordCount);
                Interlocked.Increment(ref _server.Metrics.TotalPublishRecordSuccesses);
                await SendEmptyResponseAsync(ResponseOpcode.PUBLISH_RECORD, requestId, (int)PublishRecordResponseCode.Success);
            }
            catch (Exception ex)
            {
                stopwatch.Stop();
                Interlocked.Add(ref _server.Metrics.TotalPublishRecordTimeMs, stopwatch.ElapsedMilliseconds);
                Interlocked.Increment(ref _server.Metrics.PublishRecordCount);
                Interlocked.Increment(ref _server.Metrics.TotalPublishRecordFailures);
                Logger.Error<SyncSession>("Error publishing record", ex);
                await SendEmptyResponseAsync(ResponseOpcode.PUBLISH_RECORD, requestId, (int)PublishRecordResponseCode.GeneralError);
            }
        });
    }

    private string GetIpAddress()
    {
        return ((IPEndPoint)Socket.RemoteEndPoint!).Address.ToString();
    }

    private async ValueTask HandleRequestDeleteRecordAsync(int requestId, ArraySegment<byte> data)
    {
        Interlocked.Increment(ref _server.Metrics.TotalDeleteRecordRequests);

        // Parse request: publisherPublicKey (32), consumerPublicKey (32), keyLength (1), key (variable)
        if (data.Count < 65) // Minimum size: 32 + 32 + 1 + 0
        {
            Logger.Error<SyncSession>("REQUEST_DELETE_RECORD packet too short");
            await SendEmptyResponseAsync(ResponseOpcode.DELETE_RECORD, requestId, (int)DeleteRecordResponseCode.InvalidRequest);
            return;
        }
        byte[] publisherPublicKey = data.Slice(0, 32).ToArray();
        byte[] consumerPublicKey = data.Slice(32, 32).ToArray();
        int keyLength = data[64];
        if (keyLength > 32)
        {
            await SendEmptyResponseAsync(ResponseOpcode.DELETE_RECORD, requestId, (int)DeleteRecordResponseCode.InvalidRequest);
            return;
        }
        string key = Encoding.UTF8.GetString(data.Slice(65, keyLength));
        byte[] senderPublicKey = Convert.FromBase64String(RemotePublicKey!);

        // Authorization: Sender must be publisher or consumer
        if (!senderPublicKey.SequenceEqual(publisherPublicKey) && !senderPublicKey.SequenceEqual(consumerPublicKey))
        {
            await SendEmptyResponseAsync(ResponseOpcode.DELETE_RECORD, requestId, (int)DeleteRecordResponseCode.Unauthorized);
            return;
        }

        var stopwatch = Stopwatch.StartNew();
        _ = Task.Run(async () =>
        {
            try
            {
                await _server.RecordRepository.DeleteAsync(publisherPublicKey, consumerPublicKey, key);
                stopwatch.Stop();
                await SendEmptyResponseAsync(ResponseOpcode.DELETE_RECORD, requestId, (int)DeleteRecordResponseCode.Success);

                Interlocked.Add(ref _server.Metrics.TotalDeleteRecordTimeMs, stopwatch.ElapsedMilliseconds);
                Interlocked.Increment(ref _server.Metrics.DeleteRecordCount);
                Interlocked.Increment(ref _server.Metrics.TotalDeleteRecordSuccesses);
            }
            catch (Exception ex)
            {
                stopwatch.Stop();
                Logger.Error<SyncSession>("Error deleting record", ex);
                await SendEmptyResponseAsync(ResponseOpcode.DELETE_RECORD, requestId, (int)DeleteRecordResponseCode.GeneralError);

                Interlocked.Add(ref _server.Metrics.TotalDeleteRecordTimeMs, stopwatch.ElapsedMilliseconds);
                Interlocked.Increment(ref _server.Metrics.DeleteRecordCount);
                Interlocked.Increment(ref _server.Metrics.TotalDeleteRecordFailures);
            }
        });
    }

    private async ValueTask HandleRequestListKeysAsync(int requestId, ArraySegment<byte> data)
    {
        Interlocked.Increment(ref _server.Metrics.TotalListKeysRequests);

        // Parse request: publisherPublicKey (32), consumerPublicKey (32)
        if (data.Count != 64)
        {
            Logger.Error<SyncSession>("REQUEST_LIST_KEYS packet invalid size");
            await SendEmptyResponseAsync(ResponseOpcode.LIST_RECORD_KEYS, requestId, (int)ListRecordKeysResponseCode.InvalidRequest);
            return;
        }
        byte[] publisherPublicKey = data.Slice(0, 32).ToArray();
        byte[] consumerPublicKey = data.Slice(32, 32).ToArray();
        byte[] senderPublicKey = Convert.FromBase64String(RemotePublicKey!);

        // Authorization: Sender must be publisher or consumer
        if (!senderPublicKey.SequenceEqual(publisherPublicKey) && !senderPublicKey.SequenceEqual(consumerPublicKey))
        {
            await SendEmptyResponseAsync(ResponseOpcode.LIST_RECORD_KEYS, requestId, (int)ListRecordKeysResponseCode.Unauthorized);
            return;
        }

        var stopwatch = Stopwatch.StartNew();
        _ = Task.Run(async () =>
        {
            try
            {
                var keys = await _server.RecordRepository.ListKeysAsync(publisherPublicKey, consumerPublicKey);
                stopwatch.Stop();

                using var ms = new MemoryStream();
                using var writer = new BinaryWriter(ms);
                writer.Write(requestId);
                writer.Write((int)ListRecordKeysResponseCode.Success); //Status code
                writer.Write(keys.Count());
                foreach (var (key, timestamp) in keys)
                {
                    byte[] keyBytes = Encoding.UTF8.GetBytes(key);
                    writer.Write((byte)keyBytes.Length);
                    writer.Write(keyBytes);
                    writer.Write(timestamp.ToBinary());
                }
                var responseData = ms.ToArray();
                await SendAsync(Opcode.RESPONSE, (byte)ResponseOpcode.LIST_RECORD_KEYS, responseData); // Success

                Interlocked.Add(ref _server.Metrics.TotalListKeysTimeMs, stopwatch.ElapsedMilliseconds);
                Interlocked.Increment(ref _server.Metrics.ListKeysCount);
                Interlocked.Increment(ref _server.Metrics.TotalListKeysSuccesses);
            }
            catch (Exception ex)
            {
                stopwatch.Stop();

                Logger.Error<SyncSession>("Error listing keys", ex);
                await SendEmptyResponseAsync(ResponseOpcode.LIST_RECORD_KEYS, requestId, (int)ListRecordKeysResponseCode.GeneralError);

                Interlocked.Add(ref _server.Metrics.TotalListKeysTimeMs, stopwatch.ElapsedMilliseconds);
                Interlocked.Increment(ref _server.Metrics.ListKeysCount);
                Interlocked.Increment(ref _server.Metrics.TotalListKeysFailures);
            }
        });
    }

    private async ValueTask HandleRequestGetRecordAsync(int requestId, ArraySegment<byte> data)
    {
        Interlocked.Increment(ref _server.Metrics.TotalGetRecordRequests);

        // Parse request: publisherPublicKey (32), consumerPublicKey (32), keyLength (1), key (variable)
        if (data.Count < 33) // Minimum size: 32 + 1 + 0
        {
            Logger.Error<SyncSession>("REQUEST_GET_RECORD packet too short");
            await SendEmptyResponseAsync(ResponseOpcode.GET_RECORD, requestId, (int)GetRecordResponseCode.InvalidRequest);
            return;
        }
        byte[] publisherPublicKey = data.Slice(0, 32).ToArray();
        int keyLength = data[32];
        if (keyLength > 32)
        {
            await SendEmptyResponseAsync(ResponseOpcode.GET_RECORD, requestId, (int)GetRecordResponseCode.InvalidRequest);
            return;
        }
        string key = Encoding.UTF8.GetString(data.Slice(33, keyLength));
        byte[] consumerPublicKey = Convert.FromBase64String(RemotePublicKey!);

        var stopwatch = Stopwatch.StartNew();
        _ = Task.Run(async () =>
        {
            try
            {
                var record = await _server.RecordRepository.GetAsync(publisherPublicKey, consumerPublicKey, key);
                stopwatch.Stop();
                if (record != null)
                {

                    using var ms = new MemoryStream();
                    using var writer = new BinaryWriter(ms);
                    writer.Write(requestId);
                    writer.Write((int)GetRecordResponseCode.Success);
                    writer.Write(record.EncryptedBlob.Length);
                    writer.Write(record.EncryptedBlob);
                    writer.Write(record.Timestamp.ToBinary());
                    var responseData = ms.ToArray();
                    await SendAsync(Opcode.RESPONSE, (byte)ResponseOpcode.GET_RECORD, responseData);

                    Interlocked.Add(ref _server.Metrics.TotalGetRecordTimeMs, stopwatch.ElapsedMilliseconds);
                    Interlocked.Increment(ref _server.Metrics.GetRecordCount);
                    Interlocked.Increment(ref _server.Metrics.TotalGetRecordSuccesses);
                }
                else
                {
                    await SendEmptyResponseAsync(ResponseOpcode.GET_RECORD, requestId, (int)GetRecordResponseCode.NotFound);

                    Interlocked.Add(ref _server.Metrics.TotalGetRecordTimeMs, stopwatch.ElapsedMilliseconds);
                    Interlocked.Increment(ref _server.Metrics.GetRecordCount);
                    Interlocked.Increment(ref _server.Metrics.TotalGetRecordFailures);
                }
            }
            catch (Exception ex)
            {
                Logger.Error<SyncSession>("Error getting record", ex);
                await SendEmptyResponseAsync(ResponseOpcode.GET_RECORD, requestId, (int)GetRecordResponseCode.GeneralError);
            }
        });
    }

    public void HandleVersionCheck(ReadOnlySpan<byte> data)
    {
        const int MINIMUM_VERSION = 4;

        if (data.Length != 4)
            throw new Exception("Expected exactly 4 bytes representing the version");

        RemoteVersion = BinaryPrimitives.ReadInt32LittleEndian(data);
        if (RemoteVersion < MINIMUM_VERSION)
            throw new Exception($"Version must be at least {MINIMUM_VERSION}");
    }

    private const int CURRENT_VERSION = 4;
    private static readonly byte[] VersionBytes = { CURRENT_VERSION, 0, 0, 0 };
    public async ValueTask SendVersionAsync()
    {
        try
        {
            await _sendSemaphore.WaitAsync();
            await SendAsync(VersionBytes, 0, 4);
        }
        finally
        {
            _sendSemaphore.Release();
        }
    }

    public async ValueTask SendAsync(Opcode opcode, byte subOpcode)
    {
        var decryptedSize = 4 + 1 + 1;
        var encryptedSize = decryptedSize + 4 + 16;
        byte[] decryptedPacket = Utilities.RentBytes(decryptedSize);
        byte[] encryptedPacket = Utilities.RentBytes(encryptedSize);

        try
        {
            try
            {
                BinaryPrimitives.WriteInt32LittleEndian(decryptedPacket.AsSpan(0, 4), decryptedSize - 4);
                decryptedPacket[4] = (byte)opcode;
                decryptedPacket[5] = (byte)subOpcode;

                if (Logger.WillLog(LogLevel.Debug))
                    Logger.Debug<SyncSession>($"Send (opcode = {opcode}, subOpcode = {subOpcode}, size = 0)");

                if (Logger.WillLog(LogLevel.Debug))
                    Logger.Debug<SyncSession>($"Encrypted message bytes {HEADER_SIZE}");

                var len = Encrypt(decryptedPacket.AsSpan(0, HEADER_SIZE), encryptedPacket.AsSpan().Slice(4));
                BinaryPrimitives.WriteInt32LittleEndian(encryptedPacket.AsSpan().Slice(0, 4), len);
            }
            finally
            {
                Utilities.ReturnBytes(decryptedPacket);
            }

            try
            {
                await _sendSemaphore.WaitAsync();
                await SendAsync(encryptedPacket, 0, encryptedSize);

                if (Logger.WillLog(LogLevel.Debug))
                    Logger.Debug<SyncSession>($"Wrote message bytes {encryptedSize}");
            }
            finally
            {
                _sendSemaphore.Release();
            }
        }
        finally
        {
            Utilities.ReturnBytes(encryptedPacket);
        }
    }

    public async ValueTask SendAsync(Opcode opcode, byte subOpcode, ArraySegment<byte> data)
    {
        if (Logger.WillLog(LogLevel.Debug))
            Logger.Debug<SyncSession>($"Send (opcode = {opcode}, subOpcode = {subOpcode}, size = {data.Count})");

        if (data.Count + HEADER_SIZE > MAXIMUM_PACKET_SIZE)
        {
            var segmentSize = MAXIMUM_PACKET_SIZE - HEADER_SIZE;
            var segmentData = Utilities.RentBytes(segmentSize);
            try
            {
                var id = Interlocked.Increment(ref _streamIdGenerator);

                for (var sendOffset = 0; sendOffset < data.Count;)
                {
                    var bytesRemaining = data.Count - sendOffset;
                    int bytesToSend;
                    int segmentPacketSize;

                    StreamOpcode op;
                    if (sendOffset == 0)
                    {
                        op = StreamOpcode.START;
                        bytesToSend = segmentSize - 4 - 4 - 1 - 1;
                        segmentPacketSize = bytesToSend + 4 + 4 + 1 + 1;
                    }
                    else
                    {
                        bytesToSend = Math.Min(segmentSize - 4 - 4, bytesRemaining);
                        if (bytesToSend >= bytesRemaining)
                            op = StreamOpcode.END;
                        else
                            op = StreamOpcode.DATA;

                        segmentPacketSize = bytesToSend + 4 + 4;
                    }

                    var segmentDataSegment = new ArraySegment<byte>(segmentData);
                    if (op == StreamOpcode.START)
                    {
                        //TODO: replace segmentData.AsSpan() into a local variable once C# 13
                        BinaryPrimitives.WriteInt32LittleEndian(segmentData.AsSpan().Slice(0, 4), id);
                        BinaryPrimitives.WriteInt32LittleEndian(segmentData.AsSpan().Slice(4, 4), data.Count);
                        segmentData[8] = (byte)opcode;
                        segmentData[9] = (byte)subOpcode;
                        data.Slice(sendOffset, bytesToSend).CopyTo(segmentDataSegment.Slice(10));
                    }
                    else
                    {
                        //TODO: replace segmentData.AsSpan() into a local variable once C# 13
                        BinaryPrimitives.WriteInt32LittleEndian(segmentData.AsSpan().Slice(0, 4), id);
                        BinaryPrimitives.WriteInt32LittleEndian(segmentData.AsSpan().Slice(4, 4), sendOffset);
                        data.Slice(sendOffset, bytesToSend).CopyTo(segmentDataSegment.Slice(8));
                    }

                    sendOffset += bytesToSend;
                    await SendAsync(Opcode.STREAM, (byte)op, segmentDataSegment.Slice(0, segmentPacketSize));
                }
            }
            finally
            {
                Utilities.ReturnBytes(segmentData);
            }
        }
        else
        {
            var decryptedSize = 4 + 1 + 1 + data.Count;
            var encryptedSize = decryptedSize + 4 + 16;
            byte[] decryptedPacket = Utilities.RentBytes(decryptedSize);
            byte[] encryptedPacket = Utilities.RentBytes(encryptedSize);

            try
            {
                try
                {
                    BinaryPrimitives.WriteInt32LittleEndian(decryptedPacket.AsSpan().Slice(0, 4), decryptedSize - 4);
                    decryptedPacket[4] = (byte)opcode;
                    decryptedPacket[5] = (byte)subOpcode;
                    data.CopyTo(new ArraySegment<byte>(decryptedPacket).Slice(HEADER_SIZE));
                }
                finally
                {
                    Utilities.ReturnBytes(decryptedPacket);
                }

                if (Logger.WillLog(LogLevel.Debug))
                    Logger.Debug<SyncSession>($"Encrypted message bytes {data.Count + HEADER_SIZE}");

                try
                {
                    await _sendSemaphore.WaitAsync();

                    var len = Encrypt(decryptedPacket.AsSpan().Slice(0, data.Count + HEADER_SIZE), encryptedPacket.AsSpan().Slice(4));
                    BinaryPrimitives.WriteInt32LittleEndian(encryptedPacket.AsSpan().Slice(0, 4), len);
                    await SendAsync(encryptedPacket, 0, encryptedSize);

                    if (Logger.WillLog(LogLevel.Debug))
                        Logger.Debug<SyncSession>($"Wrote message bytes {len}");
                }
                finally
                {
                    _sendSemaphore.Release();
                }
            }
            finally
            {
                Utilities.ReturnBytes(encryptedPacket);
            }
        }
    }

    public async ValueTask SendAsync(Opcode opcode, byte subOpcode = 0, byte[]? data = null, int offset = 0, int count = -1)
    {
        if (count == -1)
            count = data?.Length ?? 0;

        if (data != null)
            await SendAsync(opcode, subOpcode, new ArraySegment<byte>(data, offset, count));
        else
            await SendAsync(opcode, subOpcode);
    }

    private int Encrypt(ReadOnlySpan<byte> source, Span<byte> destination)
    {
        int encryptedLength = _transport!.WriteMessage(source, destination);
        if (Logger.WillLog(LogLevel.Debug))
            Logger.Debug<SyncSession>($"Encrypted message bytes (source size: {source.Length}, destination size: {encryptedLength})\n{Utilities.HexDump(source)}");
        return encryptedLength;
    }

    private int Decrypt(ReadOnlySpan<byte> source, Span<byte> destination)
    {
        int plen = _transport!.ReadMessage(source, destination);
        if (Logger.WillLog(LogLevel.Debug))
            Logger.Debug<SyncSession>($"Decrypted message bytes (source size: {source.Length}, destination size: {plen})\n{Utilities.HexDump(destination.Slice(0, plen))}");
        return plen;
    }

    //TODO: Reuse buffer initially set by InitializeBufferPool
    private async ValueTask SendAsync(byte[] data, int offset, int count, CancellationToken cancellationToken = default)
    {
        if (Logger.WillLog(LogLevel.Debug))
            Logger.Debug<SyncSession>($"Sending {count} bytes.\n{Utilities.HexDump(data.AsSpan().Slice(offset, count))}");

        Stopwatch? sw = null;
        if (Logger.WillLog(LogLevel.Debug))
            sw = new Stopwatch();

        int totalBytesSent = 0;
        while (totalBytesSent < count)
        {
            cancellationToken.ThrowIfCancellationRequested();

            sw?.Restart();
            if (Logger.WillLog(LogLevel.Debug))
                Logger.Debug<SyncSession>($"Sending {count - totalBytesSent} bytes.");

            int bytesSent = await Socket.SendAsync(new ArraySegment<byte>(data, offset + totalBytesSent, count - totalBytesSent));
            if (bytesSent == 0)
                throw new Exception("Failed to send.");
            if (Logger.WillLog(LogLevel.Debug))
                Logger.Debug<SyncSession>($"Send duration ({bytesSent} bytes): {sw?.ElapsedMilliseconds}ms");

            totalBytesSent += bytesSent;
        }
    }

    private async ValueTask SendEmptyResponseAsync(ResponseOpcode responseOpcode, int requestId, int statusCode)
    {
        byte[] responseData = Utilities.RentBytes(12);
        try
        {
            BinaryPrimitives.WriteInt32LittleEndian(responseData.AsSpan().Slice(0, 4), requestId);
            BinaryPrimitives.WriteInt32LittleEndian(responseData.AsSpan().Slice(4, 4), statusCode);
            await SendAsync(Opcode.RESPONSE, (byte)responseOpcode, responseData, 0, 12);
        }
        finally
        {
            Utilities.ReturnBytes(responseData);
        }
    }

    private async ValueTask SendRelayErrorAsync(long connectionId, RelayErrorCode errorCode)
    {
        byte[] errorPacket = Utilities.RentBytes(12);
        try
        {
            BinaryPrimitives.WriteInt64LittleEndian(errorPacket.AsSpan().Slice(0, 8), connectionId);
            BinaryPrimitives.WriteInt32LittleEndian(errorPacket.AsSpan().Slice(8, 4), (int)errorCode);
            await SendAsync(Opcode.RELAY, (byte)RelayOpcode.RELAY_ERROR, errorPacket);
        }
        finally
        {
            Utilities.ReturnBytes(errorPacket);
        }
    }
}
