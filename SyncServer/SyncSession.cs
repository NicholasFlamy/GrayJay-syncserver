using System.Buffers;
using System.Buffers.Binary;
using System.Diagnostics;
using System.Drawing;
using System.Net;
using System.Net.Sockets;
using System.Reflection.Emit;
using System.Text;
using System.Threading;
using Noise;
using SyncShared;
using static System.Runtime.InteropServices.JavaScript.JSType;
using static SyncServer.TcpSyncServer;

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

    public required Socket Socket { get; init; }
    public required SocketAsyncEventArgs ReadArgs { get; init; }
    public required SocketAsyncEventArgs WriteArgs { get; init; }
    public required HandshakeState HandshakeState { get; init; }
    public string? RemotePublicKey { get; private set; }
    public SessionPrimaryState PrimaryState { get; set; } = SessionPrimaryState.VersionCheck;
    public SessionSecondaryState SecondaryState { get; set; } = SessionSecondaryState.WaitingForSize;
    public int RemoteVersion { get; private set; } = -1;
    private Queue<(byte[] data, int offset, int count, bool returnToPool)> SendQueue = new Queue<(byte[], int, int, bool)>(16);
    private bool _isBusyWriting = false;
    private int _messageSize = -1;
    private byte[]? _accumulatedBuffer;
    private int _accumulatedBytes = 0;
    private byte[] _sizeBuffer = new byte[4];
    private int _sizeAccumulatedBytes = 0;
    private byte[] _sessionBuffer = new byte[1024];
    private byte[] _decryptionBuffer = new byte[1024];
    private readonly TcpSyncServer _server;
    private Transport? _transport;
    private Action<SyncSession> _onHandshakeComplete;
    private readonly Dictionary<int, SyncStream> _syncStreams = new();
    private int _streamIdGenerator = 0;
    private readonly object _sendLock = new object();

    public SyncSession(TcpSyncServer server, Action<SyncSession> onHandshakeComplete)
    {
        _server = server;
        _onHandshakeComplete = onHandshakeComplete;
    }

    public void Dispose()
    {
        HandshakeState?.Dispose();
        _isBusyWriting = false;
        Socket?.Close();
        PrimaryState = SessionPrimaryState.Closed;
        if (_accumulatedBuffer != null)
        {
            Utilities.ReturnBytes(_accumulatedBuffer);
            _accumulatedBuffer = null;
        }
        lock (_syncStreams)
        {
            foreach (var pair in _syncStreams)
                pair.Value.Dispose();
            _syncStreams.Clear();
        }
    }

    public void HandleData(int bytesReceived)
    {
        var data = ReadArgs.Buffer.AsSpan(0, bytesReceived);
        if (Logger.WillLog(LogLevel.Debug))
            Logger.Debug<SyncSession>($"Received {bytesReceived} bytes.\n{Utilities.HexDump(data)}");

        int offset = 0;
        if (PrimaryState == SessionPrimaryState.VersionCheck)
        {
            if (data.Length != 4)
                throw new Exception("Expected exactly 4 bytes for version.");

            HandleVersionCheck(data);
            PrimaryState = SessionPrimaryState.Handshake;
            offset = 4;
        }

        while (offset < bytesReceived)
        {
            if (SecondaryState == SessionSecondaryState.WaitingForSize)
            {
                int sizeBytesNeeded = 4 - _sizeAccumulatedBytes;
                int available = bytesReceived - offset;

                if (available < sizeBytesNeeded)
                {
                    data.Slice(offset, available).CopyTo(_sizeBuffer.AsSpan(_sizeAccumulatedBytes));
                    _sizeAccumulatedBytes += available;
                    offset += available;
                    return;
                }
                else
                {
                    data.Slice(offset, sizeBytesNeeded).CopyTo(_sizeBuffer.AsSpan(_sizeAccumulatedBytes));
                    _messageSize = BinaryPrimitives.ReadInt32LittleEndian(_sizeBuffer);

                    if (_messageSize <= 0 || _messageSize > MAXIMUM_PACKET_SIZE_ENCRYPTED)
                        throw new Exception($"Invalid message size: {_messageSize}");

                    offset += sizeBytesNeeded;
                    _sizeAccumulatedBytes = 0;
                    SecondaryState = SessionSecondaryState.WaitingForData;
                    _accumulatedBytes = 0;
                }
            }

            if (SecondaryState == SessionSecondaryState.WaitingForData)
            {
                int available = bytesReceived - offset;
                int needed = _messageSize - _accumulatedBytes;

                if (available >= needed)
                {
                    if (_accumulatedBuffer != null)
                    {
                        if (_accumulatedBytes == 0 && available >= _messageSize)
                        {
                            HandlePacket(data.Slice(offset, _messageSize));
                        }
                        else
                        {
                            data.Slice(offset, needed).CopyTo(_accumulatedBuffer.AsSpan(_accumulatedBytes));
                            HandlePacket(_accumulatedBuffer.AsSpan(0, _messageSize));
                        }
                    }
                    else
                    {
                        HandlePacket(data.Slice(offset, _messageSize));
                    }
                    offset += needed;

                    if (_accumulatedBuffer != null && _accumulatedBuffer != _sessionBuffer)
                        Utilities.ReturnBytes(_accumulatedBuffer);

                    _accumulatedBuffer = null;
                    SecondaryState = SessionSecondaryState.WaitingForSize;
                }
                else
                {
                    if (_messageSize <= _sessionBuffer.Length)
                        _accumulatedBuffer ??= _sessionBuffer;
                    else
                        _accumulatedBuffer ??= Utilities.RentBytes(_messageSize);

                    data.Slice(offset, available).CopyTo(_accumulatedBuffer.AsSpan(_accumulatedBytes));
                    _accumulatedBytes += available;
                    offset += available;
                    return;
                }
            }
        }
    }
    private void HandlePacket(ReadOnlySpan<byte> data)
    {
        int decryptedSize = data.Length - 16;
        var shouldRent = decryptedSize > _decryptionBuffer.Length;
        var decryptionBuffer = shouldRent ? Utilities.RentBytes(decryptedSize) : _decryptionBuffer;

        try
        {
            if (PrimaryState == SessionPrimaryState.Handshake)
            {
                var (_, _, _) = HandshakeState.ReadMessage(data, _decryptionBuffer);
                var (bytesWritten, _, transport) = HandshakeState.WriteMessage(null, _decryptionBuffer);
                Logger.Info<SyncSession>($"HandshakeAsResponder: Read message size {data.Length}");

                BinaryPrimitives.WriteInt32LittleEndian(_sessionBuffer, bytesWritten);
                _decryptionBuffer.AsSpan().Slice(0, bytesWritten).CopyTo(_sessionBuffer.AsSpan().Slice(4));

                lock (_sendLock)
                {
                    Send(_sessionBuffer, 0, bytesWritten + 4);
                }

                Logger.Info<SyncSession>($"HandshakeAsResponder: Wrote message size {bytesWritten}");

                _transport = transport;
                RemotePublicKey = Convert.ToBase64String(HandshakeState.RemoteStaticPublicKey);
                Logger.Info<SyncSession>($"HandshakeAsResponder: Remote public key {RemotePublicKey}");

                PrimaryState = SessionPrimaryState.DataTransfer;
                _onHandshakeComplete?.Invoke(this);
            }
            else
            {
                int plen = Decrypt(data, decryptionBuffer);
                HandleDecryptedPacket(decryptionBuffer.AsSpan().Slice(0, plen));
            }
        }
        finally
        {
            if (decryptionBuffer != _decryptionBuffer)
                Utilities.ReturnBytes(decryptionBuffer);
        }
    }

    private void HandleDecryptedPacket(Opcode opcode, byte subOpcode, Span<byte> data)
    {

        switch (opcode)
        {
            case Opcode.STREAM_START:
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
                        _syncStreams[id] = syncStream;
                    }
                    break;
                }

            case Opcode.STREAM_DATA:
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

            case Opcode.STREAM_END:
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
                    HandleDecryptedPacket(syncStream.Opcode, syncStream.SubOpcode, syncStream.GetBytes());
                    break;
                }
            case Opcode.PING:
                Send(Opcode.PONG);
                break;
            case Opcode.PUBLISH_CONNECTION_INFO:
                HandlePublishConnectionInfo(data);
                break;
            case Opcode.REQUEST_CONNECTION_INFO:
                HandleRequestConnectionInfo(data);
                break;
            case Opcode.REQUEST_RELAYED_TRANSPORT:
                HandleRequestRelayedTransport(data);
                break;
            case Opcode.RESPONSE_RELAYED_TRANSPORT:
                if (subOpcode == 0)
                {
                    if (data.Length < 16)
                    {
                        Logger.Error<SyncSession>("RESPONSE_RELAYED_TRANSPORT packet too short");
                        return;
                    }
                    long connectionId = BinaryPrimitives.ReadInt64LittleEndian(data.Slice(0, 8));
                    int requestId = BinaryPrimitives.ReadInt32LittleEndian(data.Slice(8, 4));
                    int messageLength = BinaryPrimitives.ReadInt32LittleEndian(data.Slice(12, 4));
                    if (data.Length != 16 + messageLength)
                    {
                        Logger.Error<SyncSession>($"Invalid RESPONSE_RELAYED_TRANSPORT packet size. Expected {16 + messageLength}, got {data.Length}");
                        return;
                    }
                    byte[] responseHandshakeMessage = data.Slice(16, messageLength).ToArray();

                    var connection = _server.GetRelayedConnection(connectionId);
                    if (connection != null)
                    {
                        connection.Target = this;
                        connection.IsActive = true;
                        var packetToInitiator = new byte[16 + messageLength];
                        BinaryPrimitives.WriteInt32LittleEndian(packetToInitiator.AsSpan(0, 4), requestId);
                        BinaryPrimitives.WriteInt64LittleEndian(packetToInitiator.AsSpan(4, 8), connectionId);
                        BinaryPrimitives.WriteInt32LittleEndian(packetToInitiator.AsSpan(12, 4), messageLength);
                        responseHandshakeMessage.CopyTo(packetToInitiator.AsSpan(16));
                        connection.Initiator.Send(Opcode.RESPONSE_RELAYED_TRANSPORT, 0, packetToInitiator);
                    }
                    else
                    {
                        Logger.Error<SyncSession>($"No relayed connection found for connectionId {connectionId}");
                        _server.RemoveRelayedConnection(connectionId);
                    }
                }
                else
                {
                    if (data.Length < 12)
                    {
                        Logger.Error<SyncSession>("RESPONSE_RELAYED_TRANSPORT error packet too short");
                        return;
                    }
                    long connectionId = BinaryPrimitives.ReadInt64LittleEndian(data.Slice(0, 8));
                    int requestId = BinaryPrimitives.ReadInt32LittleEndian(data.Slice(8, 4));
                    var connection = _server.GetRelayedConnection(connectionId);
                    if (connection != null)
                    {
                        Span<byte> packetToInitiator = stackalloc byte[4]; 
                        BinaryPrimitives.WriteInt32LittleEndian(packetToInitiator, requestId);
                        connection.Initiator.Send(Opcode.RESPONSE_RELAYED_TRANSPORT, subOpcode, packetToInitiator);
                        _server.RemoveRelayedConnection(connectionId);
                    }
                }
                break;
            case Opcode.RELAYED_DATA:
                HandleRelayedData(data);
                break;
            case Opcode.REQUEST_PUBLISH_RECORD:
                HandleRequestPublishRecord(data);
                break;
            case Opcode.REQUEST_BULK_DELETE_RECORD:
                HandleRequestBulkDeleteRecord(data);
                break;
            case Opcode.REQUEST_DELETE_RECORD:
                HandleRequestDeleteRecord(data);
                break;
            case Opcode.REQUEST_LIST_RECORD_KEYS:
                HandleRequestListKeys(data);
                break;
            case Opcode.REQUEST_GET_RECORD:
                HandleRequestGetRecord(data);
                break;
            case Opcode.REQUEST_BULK_PUBLISH_RECORD:
                if (data.Length < 10) // Minimum: requestId (4) + keyLength (1) + key (0) + numConsumers (1)
                {
                    Logger.Error<SyncSession>("REQUEST_BULK_PUBLISH_RECORD packet too short");
                    return;
                }
                int bulkPublishRequestId = BinaryPrimitives.ReadInt32LittleEndian(data.Slice(0, 4));
                int keyLength = data[4];
                if (keyLength > 32 || data.Length < 6 + keyLength)
                {
                    SendErrorResponse(Opcode.RESPONSE_BULK_PUBLISH_RECORD, bulkPublishRequestId, 1);
                    return;
                }
                string key = Encoding.UTF8.GetString(data.Slice(5, keyLength));
                byte numConsumers = data[5 + keyLength];
                int offset = 6 + keyLength;
                var records = new List<(byte[] publisherPublicKey, byte[] consumerPublicKey, string key, byte[] encryptedBlob)>(numConsumers);

                byte[] publisherPublicKey = Convert.FromBase64String(RemotePublicKey!);
                for (int i = 0; i < numConsumers; i++)
                {
                    if (offset + 36 > data.Length) // consumerPublicKey (32) + blobLength (4)
                    {
                        SendErrorResponse(Opcode.RESPONSE_BULK_PUBLISH_RECORD, bulkPublishRequestId, 1);
                        return;
                    }
                    byte[] consumerPublicKey = data.Slice(offset, 32).ToArray();
                    offset += 32;
                    int blobLength = BinaryPrimitives.ReadInt32LittleEndian(data.Slice(offset, 4));
                    offset += 4;
                    if (offset + blobLength > data.Length)
                    {
                        SendErrorResponse(Opcode.RESPONSE_BULK_PUBLISH_RECORD, bulkPublishRequestId, 1);
                        return;
                    }
                    byte[] encryptedBlob = data.Slice(offset, blobLength).ToArray();
                    offset += blobLength;
                    records.Add((publisherPublicKey, consumerPublicKey, key, encryptedBlob));
                }

                _ = Task.Run(async () =>
                {
                    try
                    {
                        await _server.RecordRepository.BulkInsertOrUpdateAsync(records);
                        SendResponse(Opcode.RESPONSE_BULK_PUBLISH_RECORD, 0, bulkPublishRequestId);
                    }
                    catch (Exception ex)
                    {
                        Logger.Error<SyncSession>("Error bulk publishing records", ex);
                        SendErrorResponse(Opcode.RESPONSE_BULK_PUBLISH_RECORD, bulkPublishRequestId, 1);
                    }
                });
                break;

            case Opcode.REQUEST_BULK_GET_RECORD:
                if (data.Length < 10) // Minimum: requestId (4) + keyLength (1) + key (0) + numPublishers (1)
                {
                    Logger.Error<SyncSession>("REQUEST_BULK_GET_RECORD packet too short");
                    return;
                }
                int bulkGetRequestId = BinaryPrimitives.ReadInt32LittleEndian(data.Slice(0, 4));
                keyLength = data[4];
                if (keyLength > 32 || data.Length < 6 + keyLength)
                {
                    SendErrorResponse(Opcode.RESPONSE_BULK_GET_RECORD, bulkGetRequestId, 1);
                    return;
                }
                key = Encoding.UTF8.GetString(data.Slice(5, keyLength));
                byte numPublishers = data[5 + keyLength];
                offset = 6 + keyLength;
                var publisherPublicKeys = new List<byte[]>(numPublishers);

                for (int i = 0; i < numPublishers; i++)
                {
                    if (offset + 32 > data.Length)
                    {
                        SendErrorResponse(Opcode.RESPONSE_BULK_GET_RECORD, bulkGetRequestId, 1);
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
                        writer.Write(bulkGetRequestId);
                        writer.Write((byte)records.Count());
                        foreach (var record in records)
                        {
                            writer.Write(record.PublisherPublicKey);
                            writer.Write(record.EncryptedBlob.Length);
                            writer.Write(record.EncryptedBlob);
                            writer.Write(record.Timestamp.ToBinary());
                        }
                        Send(Opcode.RESPONSE_BULK_GET_RECORD, 0, ms.ToArray());
                    }
                    catch (Exception ex)
                    {
                        Logger.Error<SyncSession>("Error bulk getting records", ex);
                        SendErrorResponse(Opcode.RESPONSE_BULK_GET_RECORD, bulkGetRequestId, 1);
                    }
                });
                break;
            case Opcode.REQUEST_BULK_CONNECTION_INFO:
                HandleRequestBulkConnectionInfo(data);
                break;
            default:
                Logger.Debug<SyncSession>($"Received unhandled opcode: {opcode}");
                break;
        }
    }

    private void HandleDecryptedPacket(Span<byte> data)
    {
        int size = BinaryPrimitives.ReadInt32LittleEndian(data.Slice(0, 4));
        if (size != data.Length - 4)
            throw new Exception("Incomplete packet received");

        Opcode opcode = (Opcode)data[4];
        byte subOpcode = data[5];
        var packetData = data.Slice(6);

        Logger.Info<SyncSession>($"HandleDecryptedPacket (opcode = {opcode}, subOpcode = {subOpcode}, size = {packetData.Length})");
        HandleDecryptedPacket(opcode, subOpcode, packetData);
    }

    private void HandleRelayedData(ReadOnlySpan<byte> data)
    {
        if (data.Length < 8)
        {
            Logger.Error<SyncSession>("RELAYED_DATA packet too short");
            return;
        }

        long connectionId = BinaryPrimitives.ReadInt64LittleEndian(data.Slice(0, 8));
        var connection = _server.GetRelayedConnection(connectionId);
        if (connection == null || !connection.IsActive)
        {
            Logger.Error<SyncSession>($"No active relayed connection for connectionId {connectionId}");
            byte[] errorPacket = new byte[8];
            BinaryPrimitives.WriteInt64LittleEndian(errorPacket.AsSpan(0, 8), connectionId);
            Send(Opcode.RELAYED_DATA, 1, errorPacket);
            return;
        }
        if (connection.Initiator != this && connection.Target != this)
        {
            Logger.Error<SyncSession>($"Unauthorized access to relayed connection {connectionId} by {this.RemotePublicKey}");
            byte[] errorPacket = new byte[8];
            BinaryPrimitives.WriteInt64LittleEndian(errorPacket.AsSpan(0, 8), connectionId);
            Send(Opcode.RELAYED_DATA, 1, errorPacket);
            return;
        }
        SyncSession? otherClient = connection.Initiator == this ? connection.Target : connection.Initiator;
        if (otherClient != null)
        {
            byte[] packet = Utilities.RentBytes(data.Length);
            try
            {
                BinaryPrimitives.WriteInt64LittleEndian(packet.AsSpan(0, 8), connectionId);
                data.Slice(8).CopyTo(packet.AsSpan(8));
                otherClient.Send(Opcode.RELAYED_DATA, 0, packet.AsSpan(0, data.Length));
            }
            finally
            {
                Utilities.ReturnBytes(packet);
            }
        }
    }

    private void HandleRequestBulkDeleteRecord(ReadOnlySpan<byte> data)
    {
        if (data.Length < 69) // Minimum: requestId (4) + publisher (32) + consumer (32) + numKeys (1)
        {
            Logger.Error<SyncSession>("REQUEST_BULK_DELETE_RECORD packet too short");
            return;
        }
        int requestId = BinaryPrimitives.ReadInt32LittleEndian(data.Slice(0, 4));
        byte[] publisherPublicKey = data.Slice(4, 32).ToArray();
        byte[] consumerPublicKey = data.Slice(36, 32).ToArray();
        byte numKeys = data[68];
        int offset = 69;
        var keys = new List<string>(numKeys);

        for (int i = 0; i < numKeys; i++)
        {
            if (offset >= data.Length)
            {
                SendErrorResponse(Opcode.RESPONSE_BULK_DELETE_RECORD, requestId, 1);
                return;
            }
            byte keyLength = data[offset];
            offset += 1;
            if (offset + keyLength > data.Length || keyLength > 32)
            {
                SendErrorResponse(Opcode.RESPONSE_BULK_DELETE_RECORD, requestId, 1);
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
            SendErrorResponse(Opcode.RESPONSE_BULK_DELETE_RECORD, requestId, 1); // Unauthorized
            return;
        }

        _ = Task.Run(async () =>
        {
            try
            {
                await _server.RecordRepository.BulkDeleteAsync(publisherPublicKey, consumerPublicKey, keys);
                SendResponse(Opcode.RESPONSE_BULK_DELETE_RECORD, 0, requestId); // Success
            }
            catch (Exception ex)
            {
                Logger.Error<SyncSession>("Error bulk deleting records", ex);
                SendErrorResponse(Opcode.RESPONSE_BULK_DELETE_RECORD, requestId, 1); // Error
            }
        });
    }

    private void HandleRequestBulkConnectionInfo(ReadOnlySpan<byte> data)
    {
        if (data.Length < 5)
        {
            Logger.Error<SyncSession>("REQUEST_BULK_CONNECTION_INFO packet too short");
            return;
        }
        int requestId = BinaryPrimitives.ReadInt32LittleEndian(data.Slice(0, 4));
        byte numKeys = data[4];
        if (data.Length != 5 + numKeys * 32)
        {
            Logger.Error<SyncSession>("Invalid REQUEST_BULK_CONNECTION_INFO packet size");
            return;
        }
        var publicKeys = new List<string>(numKeys);
        for (int i = 0; i < numKeys; i++)
        {
            string pk = Convert.ToBase64String(data.Slice(5 + i * 32, 32));
            publicKeys.Add(pk);
        }
        string requestingPublicKey = RemotePublicKey!;

        var responseData = new MemoryStream();
        using var writer = new BinaryWriter(responseData);
        writer.Write(requestId); // 4 bytes: Request ID
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
        Send(Opcode.RESPONSE_BULK_CONNECTION_INFO, 0, responseData.ToArray());
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

        Logger.Info<SyncSession>($"Published connection info for {numEntries} authorized keys.");
    }

    private void HandleRequestConnectionInfo(ReadOnlySpan<byte> data)
    {
        if (data.Length != 36)
        {
            Logger.Error<SyncSession>("Invalid target public key length in REQUEST_CONNECTION_INFO");
            return;
        }

        int requestId = BinaryPrimitives.ReadInt32LittleEndian(data.Slice(0, 4));
        string targetPublicKey = Convert.ToBase64String(data.Slice(4, 32)); 
        string requestingPublicKey = RemotePublicKey!;

        var block = _server.RetrieveConnectionInfo(targetPublicKey, requestingPublicKey);
        if (block != null)
        {
            var responseData = Utilities.RentBytes(4 + block.Length);

            try
            {
                BinaryPrimitives.WriteInt32LittleEndian(responseData.AsSpan(0, 4), requestId);
                block.CopyTo(responseData.AsSpan(4));
                Send(Opcode.RESPONSE_CONNECTION_INFO, 0, responseData, 0, 4 + block.Length);
            }
            finally
            {
                Utilities.ReturnBytes(responseData);
            }
        }
        else
        {
            Span<byte> responseData = stackalloc byte[4];
            BinaryPrimitives.WriteInt32LittleEndian(responseData, requestId);
            Send(Opcode.RESPONSE_CONNECTION_INFO, 1, responseData);
        }
    }

    private void HandleRequestRelayedTransport(ReadOnlySpan<byte> data)
    {
        if (data.Length < 40)
        {
            Logger.Error<SyncSession>("REQUEST_RELAYED_TRANSPORT packet too short");
            return;
        }
        int requestId = BinaryPrimitives.ReadInt32LittleEndian(data.Slice(0, 4));
        string targetPublicKey = Convert.ToBase64String(data.Slice(4, 32));
        int handshakeMessageLength = BinaryPrimitives.ReadInt32LittleEndian(data.Slice(36, 4));
        if (data.Length != 40 + handshakeMessageLength)
        {
            Logger.Error<SyncSession>($"Invalid REQUEST_RELAYED_TRANSPORT packet size. Expected {40 + handshakeMessageLength}, got {data.Length}");
            return;
        }
        byte[] handshakeMessage = data.Slice(40, handshakeMessageLength).ToArray();

        var targetSession = _server.GetSession(targetPublicKey);
        if (targetSession == null)
        {
            Send(Opcode.RESPONSE_RELAYED_TRANSPORT, 1, BitConverter.GetBytes(requestId));
            return;
        }

        long connectionId = _server.GetNextConnectionId();
        _server.SetRelayedConnection(connectionId, this);

        byte[] initiatorPublicKeyBytes = Convert.FromBase64String(RemotePublicKey!);
        var packetToTarget = new byte[48 + handshakeMessageLength];
        BinaryPrimitives.WriteInt64LittleEndian(packetToTarget.AsSpan(0, 8), connectionId);
        BinaryPrimitives.WriteInt32LittleEndian(packetToTarget.AsSpan(8, 4), requestId);
        initiatorPublicKeyBytes.CopyTo(packetToTarget.AsSpan(12, 32));
        BinaryPrimitives.WriteInt32LittleEndian(packetToTarget.AsSpan(44, 4), handshakeMessageLength);
        handshakeMessage.CopyTo(packetToTarget.AsSpan(48));

        targetSession.Send(Opcode.REQUEST_RELAYED_TRANSPORT, 0, packetToTarget);
    }

    private void HandleRequestPublishRecord(ReadOnlySpan<byte> data)
    {
        // Parse request: requestId (4), consumerPublicKey (32), keyLength (1), key (variable), blobLength (4), encryptedBlob (variable)
        if (data.Length < 41) // Minimum size: 4 + 32 + 1 + 0 + 4
        {
            Logger.Error<SyncSession>("REQUEST_PUBLISH_RECORD packet too short");
            return;
        }
        int requestId = BinaryPrimitives.ReadInt32LittleEndian(data.Slice(0, 4));
        byte[] consumerPublicKey = data.Slice(4, 32).ToArray();
        int keyLength = data[36];
        if (keyLength > 32)
        {
            SendErrorResponse(Opcode.RESPONSE_PUBLISH_RECORD, requestId, 1); // Error: invalid key length
            return;
        }
        string key = Encoding.UTF8.GetString(data.Slice(37, keyLength));
        int blobLengthOffset = 37 + keyLength;
        int blobLength = BinaryPrimitives.ReadInt32LittleEndian(data.Slice(blobLengthOffset, 4));
        if (data.Length < blobLengthOffset + 4 + blobLength)
        {
            SendErrorResponse(Opcode.RESPONSE_PUBLISH_RECORD, requestId, 1); // Error: incomplete data
            return;
        }
        byte[] encryptedBlob = data.Slice(blobLengthOffset + 4, blobLength).ToArray();
        byte[] publisherPublicKey = Convert.FromBase64String(RemotePublicKey!);

        // Authorization: Sender must be the publisher
        // Since RemotePublicKey is the sender's public key, it’s implicitly checked by using it as publisherPublicKey

        _ = Task.Run(async () =>
        {
            try
            {
                await _server.RecordRepository.InsertOrUpdateAsync(publisherPublicKey, consumerPublicKey, key, encryptedBlob);
                SendResponse(Opcode.RESPONSE_PUBLISH_RECORD, 0, requestId); // Success
            }
            catch (Exception ex)
            {
                Logger.Error<SyncSession>("Error publishing record", ex);
                SendErrorResponse(Opcode.RESPONSE_PUBLISH_RECORD, requestId, 1); // Error
            }
        });
    }

    private void HandleRequestDeleteRecord(ReadOnlySpan<byte> data)
    {
        // Parse request: requestId (4), publisherPublicKey (32), consumerPublicKey (32), keyLength (1), key (variable)
        if (data.Length < 69) // Minimum size: 4 + 32 + 32 + 1 + 0
        {
            Logger.Error<SyncSession>("REQUEST_DELETE_RECORD packet too short");
            return;
        }
        int requestId = BinaryPrimitives.ReadInt32LittleEndian(data.Slice(0, 4));
        byte[] publisherPublicKey = data.Slice(4, 32).ToArray();
        byte[] consumerPublicKey = data.Slice(36, 32).ToArray();
        int keyLength = data[68];
        if (keyLength > 32)
        {
            SendErrorResponse(Opcode.RESPONSE_DELETE_RECORD, requestId, 1); // Error: invalid key length
            return;
        }
        string key = Encoding.UTF8.GetString(data.Slice(69, keyLength));
        byte[] senderPublicKey = Convert.FromBase64String(RemotePublicKey!);

        // Authorization: Sender must be publisher or consumer
        if (!senderPublicKey.SequenceEqual(publisherPublicKey) && !senderPublicKey.SequenceEqual(consumerPublicKey))
        {
            SendErrorResponse(Opcode.RESPONSE_DELETE_RECORD, requestId, 1); // Error: unauthorized
            return;
        }

        _ = Task.Run(async () =>
        {
            try
            {
                await _server.RecordRepository.DeleteAsync(publisherPublicKey, consumerPublicKey, key);
                SendResponse(Opcode.RESPONSE_DELETE_RECORD, 0, requestId); // Success
            }
            catch (Exception ex)
            {
                Logger.Error<SyncSession>("Error deleting record", ex);
                SendErrorResponse(Opcode.RESPONSE_DELETE_RECORD, requestId, 1); // Error
            }
        });
    }

    private void HandleRequestListKeys(ReadOnlySpan<byte> data)
    {
        // Parse request: requestId (4), publisherPublicKey (32), consumerPublicKey (32)
        if (data.Length != 68)
        {
            Logger.Error<SyncSession>("REQUEST_LIST_KEYS packet invalid size");
            return;
        }
        int requestId = BinaryPrimitives.ReadInt32LittleEndian(data.Slice(0, 4));
        byte[] publisherPublicKey = data.Slice(4, 32).ToArray();
        byte[] consumerPublicKey = data.Slice(36, 32).ToArray();
        byte[] senderPublicKey = Convert.FromBase64String(RemotePublicKey!);

        // Authorization: Sender must be publisher or consumer
        if (!senderPublicKey.SequenceEqual(publisherPublicKey) && !senderPublicKey.SequenceEqual(consumerPublicKey))
        {
            SendErrorResponse(Opcode.RESPONSE_LIST_RECORD_KEYS, requestId, 1); // Error: unauthorized
            return;
        }

        _ = Task.Run(async () =>
        {
            try
            {
                var keys = await _server.RecordRepository.ListKeysAsync(publisherPublicKey, consumerPublicKey);
                using var ms = new MemoryStream();
                using var writer = new BinaryWriter(ms);
                writer.Write(requestId);
                writer.Write((byte)0);
                writer.Write(keys.Count());
                foreach (var (key, timestamp) in keys)
                {
                    byte[] keyBytes = Encoding.UTF8.GetBytes(key);
                    writer.Write((byte)keyBytes.Length);
                    writer.Write(keyBytes);
                    writer.Write(timestamp.ToBinary());
                }
                var responseData = ms.ToArray();
                Send(Opcode.RESPONSE_LIST_RECORD_KEYS, 0, responseData); // Success
            }
            catch (Exception ex)
            {
                Logger.Error<SyncSession>("Error listing keys", ex);
                SendErrorResponse(Opcode.RESPONSE_LIST_RECORD_KEYS, requestId, 1); // Error
            }
        });
    }

    private void HandleRequestGetRecord(ReadOnlySpan<byte> data)
    {
        // Parse request: requestId (4), publisherPublicKey (32), consumerPublicKey (32), keyLength (1), key (variable)
        if (data.Length < 37) // Minimum size: 4 + 32 + 1 + 0
        {
            Logger.Error<SyncSession>("REQUEST_GET_RECORD packet too short");
            return;
        }
        int requestId = BinaryPrimitives.ReadInt32LittleEndian(data.Slice(0, 4));
        byte[] publisherPublicKey = data.Slice(4, 32).ToArray();
        int keyLength = data[36];
        if (keyLength > 32)
        {
            SendErrorResponse(Opcode.RESPONSE_GET_RECORD, requestId, 1);
            return;
        }
        string key = Encoding.UTF8.GetString(data.Slice(37, keyLength));
        byte[] consumerPublicKey = Convert.FromBase64String(RemotePublicKey!);

        _ = Task.Run(async () =>
        {
            try
            {
                var record = await _server.RecordRepository.GetAsync(publisherPublicKey, consumerPublicKey, key);
                if (record != null)
                {
                    using var ms = new MemoryStream();
                    using var writer = new BinaryWriter(ms);
                    writer.Write(requestId);
                    writer.Write(record.EncryptedBlob.Length);
                    writer.Write(record.EncryptedBlob);
                    writer.Write(record.Timestamp.ToBinary());
                    var responseData = ms.ToArray();
                    Send(Opcode.RESPONSE_GET_RECORD, 0, responseData);
                }
                else
                {
                    SendErrorResponse(Opcode.RESPONSE_GET_RECORD, requestId, 2);
                }
            }
            catch (Exception ex)
            {
                Logger.Error<SyncSession>("Error getting record", ex);
                SendErrorResponse(Opcode.RESPONSE_GET_RECORD, requestId, 1); 
            }
        });
    }

    public void HandleVersionCheck(ReadOnlySpan<byte> data)
    {
        const int MINIMUM_VERSION = 2;

        if (data.Length != 4)
            throw new Exception("Expected exactly 4 bytes representing the version");

        RemoteVersion = BinaryPrimitives.ReadInt32LittleEndian(data);
        if (RemoteVersion < MINIMUM_VERSION)
            throw new Exception($"Version must be at least {MINIMUM_VERSION}");
    }

    private const int CURRENT_VERSION = 3;
    private static readonly byte[] VersionBytes = { CURRENT_VERSION, 0, 0, 0 };
    public void SendVersion()
    {
        lock (_sendLock)
        {
            Send(VersionBytes, 0, 4);
        }
    }

    public void Send(Opcode opcode, byte subOpcode)
    {
        var decryptedSize = 4 + 1 + 1;
        var encryptedSize = decryptedSize + 4 + 16;
        Span<byte> decryptedPacket = stackalloc byte[decryptedSize]; 
        byte[] encryptedPacket = Utilities.RentBytes(encryptedSize);

        BinaryPrimitives.WriteInt32LittleEndian(decryptedPacket.Slice(0, 4), decryptedSize - 4);
        decryptedPacket[4] = (byte)opcode;
        decryptedPacket[5] = (byte)subOpcode;

        if (Logger.WillLog(LogLevel.Debug))
            Logger.Debug<SyncSession>($"Encrypted message bytes {HEADER_SIZE}");

        lock (_sendLock)
        {
            var len = Encrypt(decryptedPacket.Slice(0, HEADER_SIZE), encryptedPacket.AsSpan().Slice(4));
            BinaryPrimitives.WriteInt32LittleEndian(encryptedPacket.AsSpan().Slice(0, 4), len);
            Send(encryptedPacket, 0, encryptedSize, true);

            if (Logger.WillLog(LogLevel.Debug))
                Logger.Debug<SyncSession>($"Wrote message bytes {len}");
        }
    }

    public void Send(Opcode opcode, byte subOpcode, ReadOnlySpan<byte> data)
    {
        if (data.Length + HEADER_SIZE > MAXIMUM_PACKET_SIZE)
        {
            var segmentSize = MAXIMUM_PACKET_SIZE - HEADER_SIZE;
            var segmentData = new byte[segmentSize];
            var id = Interlocked.Increment(ref _streamIdGenerator);

            for (var sendOffset = 0; sendOffset < data.Length;)
            {
                var bytesRemaining = data.Length - sendOffset;
                int bytesToSend;
                int segmentPacketSize;

                Opcode op;
                if (sendOffset == 0)
                {
                    op = Opcode.STREAM_START;
                    bytesToSend = segmentSize - 4 - 4 - 1 - 1;
                    segmentPacketSize = bytesToSend + 4 + 4 + 1 + 1;
                }
                else
                {
                    bytesToSend = Math.Min(segmentSize - 4 - 4, bytesRemaining);
                    if (bytesToSend >= bytesRemaining)
                        op = Opcode.STREAM_END;
                    else
                        op = Opcode.STREAM_DATA;

                    segmentPacketSize = bytesToSend + 4 + 4;
                }

                if (op == Opcode.STREAM_START)
                {
                    //TODO: replace segmentData.AsSpan() into a local variable once C# 13
                    BinaryPrimitives.WriteInt32LittleEndian(segmentData.AsSpan().Slice(0, 4), id);
                    BinaryPrimitives.WriteInt32LittleEndian(segmentData.AsSpan().Slice(4, 4), data.Length);
                    segmentData[8] = (byte)opcode;
                    segmentData[9] = (byte)subOpcode;
                    data.Slice(sendOffset, bytesToSend).CopyTo(segmentData.AsSpan().Slice(10));
                }
                else
                {
                    //TODO: replace segmentData.AsSpan() into a local variable once C# 13
                    BinaryPrimitives.WriteInt32LittleEndian(segmentData.AsSpan().Slice(0, 4), id);
                    BinaryPrimitives.WriteInt32LittleEndian(segmentData.AsSpan().Slice(4, 4), sendOffset);
                    data.Slice(sendOffset, bytesToSend).CopyTo(segmentData.AsSpan().Slice(8));
                }

                sendOffset += bytesToSend;
                Send(op, 0, segmentData.AsSpan().Slice(0, segmentPacketSize).ToArray());
            }
        }
        else
        {
            var decryptedSize = 4 + 1 + 1 + data.Length;
            var encryptedSize = decryptedSize + 4 + 16;
            byte[] decryptedPacket = Utilities.RentBytes(decryptedSize);
            byte[] encryptedPacket = Utilities.RentBytes(encryptedSize);


            try
            {
                BinaryPrimitives.WriteInt32LittleEndian(decryptedPacket.AsSpan().Slice(0, 4), decryptedSize - 4);
                decryptedPacket[4] = (byte)opcode;
                decryptedPacket[5] = (byte)subOpcode;
                data.CopyTo(decryptedPacket.AsSpan().Slice(HEADER_SIZE));
            }
            finally
            {
                Utilities.ReturnBytes(decryptedPacket);
            }

            if (Logger.WillLog(LogLevel.Debug))
                Logger.Debug<SyncSession>($"Encrypted message bytes {data.Length + HEADER_SIZE}");

            lock (_sendLock)
            {
                var len = Encrypt(decryptedPacket.AsSpan().Slice(0, data.Length + HEADER_SIZE), encryptedPacket.AsSpan().Slice(4));
                BinaryPrimitives.WriteInt32LittleEndian(encryptedPacket.AsSpan().Slice(0, 4), len);
                Send(encryptedPacket, 0, encryptedSize, true);

                if (Logger.WillLog(LogLevel.Debug))
                    Logger.Debug<SyncSession>($"Wrote message bytes {len}");
            }
        }
    }

    public void Send(Opcode opcode, byte subOpcode = 0, byte[]? data = null, int offset = 0, int count = -1)
    {
        if (count == -1)
            count = data?.Length ?? 0;

        if (data != null)
            Send(opcode, subOpcode, data.AsSpan(offset, count));
        else
            Send(opcode, subOpcode);
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
    private void Send(byte[] data, int offset, int count, bool returnToPool = false)
    {
        if (!_isBusyWriting)
        {
            if (Logger.WillLog(LogLevel.Debug))
                Logger.Debug<SyncSession>($"Sending {count} bytes.\n{Utilities.HexDump(data.AsSpan().Slice(offset, count))}");

            WriteArgs.SetBuffer(data, offset, count);
            ((ArgsPair)WriteArgs.UserToken!).ReturnToPool = returnToPool;
            bool pending = Socket.SendAsync(WriteArgs!);
            if (pending)
            {
                Logger.Debug<SyncSession>($"Write not synchronously completed. Set isBusyWriting to true.");
                _isBusyWriting = true;
            }
            else
            {
                if (Logger.WillLog(LogLevel.Debug))
                    Logger.Debug<SyncSession>($"Sent {count} bytes synchronously.");

                if (returnToPool)
                    Utilities.ReturnBytes(data);
            }
        }
        else
        {
            if (Logger.WillLog(LogLevel.Debug))
                Logger.Debug<SyncSession>($"Queued {count} bytes to send.");
            SendQueue.Enqueue((data, offset, count, returnToPool));
        }
    }

    private void SendResponse(Opcode opcode, byte subOpcode, int requestId)
    {
        Span<byte> responseData = stackalloc byte[4]; 
        BinaryPrimitives.WriteInt32LittleEndian(responseData, requestId);
        Send(opcode, subOpcode, responseData);
    }

    private void SendErrorResponse(Opcode opcode, int requestId, byte errorCode)
    {
        Span<byte> responseData = stackalloc byte[4];
        BinaryPrimitives.WriteInt32LittleEndian(responseData, requestId);
        Send(opcode, errorCode, responseData);
    }

    public void OnWriteCompleted()
    {
        byte[] sentBuffer = WriteArgs.Buffer!;
        var argsPair = (ArgsPair)WriteArgs.UserToken!;
        if (argsPair.ReturnToPool)
            Utilities.ReturnBytes(sentBuffer);

        lock (_sendLock)
        {
            if (SendQueue.Count > 0)
            {
                do
                {
                    var (data, offset, count, returnToPoolNext) = SendQueue.Dequeue();
                    if (Logger.WillLog(LogLevel.Debug))
                        Logger.Debug<SyncSession>($"Sending {count} bytes from queue.\n{Utilities.HexDump(data.AsSpan().Slice(offset, count))}");

                    WriteArgs.SetBuffer(data, offset, count);
                    argsPair.ReturnToPool = returnToPoolNext;
                    bool pending = Socket.SendAsync(WriteArgs!);
                    if (!pending)
                    {
                        Logger.Debug<SyncSession>($"Sent {count} bytes synchronously.");
                        if (returnToPoolNext)
                            Utilities.ReturnBytes(data);
                    }
                    else
                    {
                        Logger.Debug<SyncSession>($"Waiting on next send to complete.");
                        break;
                    }
                } while (SendQueue.Count > 0);
            }
            else
            {
                Logger.Debug<SyncSession>($"Send completed. Set isBusyWriting to false because last write was completed.");
                _isBusyWriting = false;
            }
        }
    }
}
