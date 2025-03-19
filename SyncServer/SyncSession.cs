using System.Buffers;
using System.Buffers.Binary;
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
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

    public enum Opcode : byte
    {
        PING = 0,
        PONG = 1,
        NOTIFY_AUTHORIZED = 2,
        NOTIFY_UNAUTHORIZED = 3,
        STREAM_START = 4,
        STREAM_DATA = 5,
        STREAM_END = 6,
        DATA = 7,
        PUBLISH_CONNECTION_INFO = 8,
        REQUEST_CONNECTION_INFO = 9,
        RESPONSE_CONNECTION_INFO = 10,
        REQUEST_RELAYED_TRANSPORT = 11,
        RESPONSE_RELAYED_TRANSPORT = 12,
        RELAYED_DATA = 13
    }

    public const int HEADER_SIZE = 6;
    private const int MaxPacketSizeEncrypted = 65535;

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

                    if (_messageSize <= 0 || _messageSize > MaxPacketSizeEncrypted)
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
                Send(_sessionBuffer, 0, bytesWritten + 4);
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

    private void HandleDecryptedPacket(Span<byte> data)
    {
        int size = BinaryPrimitives.ReadInt32LittleEndian(data.Slice(0, 4));
        if (size != data.Length - 4)
            throw new Exception("Incomplete packet received");

        Opcode opcode = (Opcode)data[4];
        byte subOpcode = data[5];
        var packetData = data.Slice(6);

        Logger.Info<SyncSession>($"HandleDecryptedPacket (opcode = {opcode}, subOpcode = {subOpcode}, size = {packetData.Length})");

        switch (opcode)
        {
            case Opcode.PING:
                Send(Opcode.PONG);
                break;
            case Opcode.PUBLISH_CONNECTION_INFO:
                HandlePublishConnectionInfo(packetData);
                break;
            case Opcode.REQUEST_CONNECTION_INFO:
                HandleRequestConnectionInfo(packetData);
                break;
            case Opcode.REQUEST_RELAYED_TRANSPORT:
                HandleRequestRelayedTransport(packetData);
                break;
            case Opcode.RESPONSE_RELAYED_TRANSPORT:
                if (subOpcode == 0)
                {
                    if (packetData.Length < 16)
                    {
                        Logger.Error<SyncSession>("RESPONSE_RELAYED_TRANSPORT packet too short");
                        return;
                    }
                    long connectionId = BinaryPrimitives.ReadInt64LittleEndian(packetData.Slice(0, 8));
                    int requestId = BinaryPrimitives.ReadInt32LittleEndian(packetData.Slice(8, 4));
                    int messageLength = BinaryPrimitives.ReadInt32LittleEndian(packetData.Slice(12, 4));
                    if (packetData.Length != 16 + messageLength)
                    {
                        Logger.Error<SyncSession>($"Invalid RESPONSE_RELAYED_TRANSPORT packet size. Expected {16 + messageLength}, got {packetData.Length}");
                        return;
                    }
                    byte[] responseHandshakeMessage = packetData.Slice(16, messageLength).ToArray();

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
                    if (packetData.Length < 12)
                    {
                        Logger.Error<SyncSession>("RESPONSE_RELAYED_TRANSPORT error packet too short");
                        return;
                    }
                    long connectionId = BinaryPrimitives.ReadInt64LittleEndian(packetData.Slice(0, 8));
                    int requestId = BinaryPrimitives.ReadInt32LittleEndian(packetData.Slice(8, 4));
                    var connection = _server.GetRelayedConnection(connectionId);
                    if (connection != null)
                    {
                        var packetToInitiator = new byte[4];
                        BinaryPrimitives.WriteInt32LittleEndian(packetToInitiator.AsSpan(0, 4), requestId);
                        connection.Initiator.Send(Opcode.RESPONSE_RELAYED_TRANSPORT, subOpcode, packetToInitiator);
                        _server.RemoveRelayedConnection(connectionId);
                    }
                }
                break;
            case Opcode.RELAYED_DATA:
                HandleRelayedData(packetData);
                break;
            default:
                Logger.Debug<SyncSession>($"Received unhandled opcode: {opcode}");
                break;
        }
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

    public void HandleVersionCheck(ReadOnlySpan<byte> data)
    {
        const int MINIMUM_VERSION = 2;

        if (data.Length != 4)
            throw new Exception("Expected exactly 4 bytes representing the version");

        RemoteVersion = BinaryPrimitives.ReadInt32LittleEndian(data);
        if (RemoteVersion < MINIMUM_VERSION)
            throw new Exception($"Version must be at least {MINIMUM_VERSION}");
    }

    public void Send(Opcode opcode, byte subOpcode, ReadOnlySpan<byte> data)
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

        var len = Encrypt(decryptedPacket.AsSpan().Slice(0, data.Length + HEADER_SIZE), encryptedPacket.AsSpan().Slice(4));
        BinaryPrimitives.WriteInt32LittleEndian(encryptedPacket.AsSpan().Slice(0, 4), len);
        Send(encryptedPacket, 0, encryptedSize, true);

        if (Logger.WillLog(LogLevel.Debug))
            Logger.Debug<SyncSession>($"Wrote message bytes {len}");
    }

    public void Send(Opcode opcode, byte subOpcode = 0, byte[]? data = null, int offset = 0, int count = -1)
    {
        if (count == -1)
            count = data?.Length ?? 0;

        var decryptedSize = 4 + 1 + 1 + count;
        var encryptedSize = decryptedSize + 4 + 16;
        byte[] decryptedPacket = Utilities.RentBytes(decryptedSize);
        byte[] encryptedPacket = Utilities.RentBytes(encryptedSize);

        try
        {
            BinaryPrimitives.WriteInt32LittleEndian(decryptedPacket.AsSpan().Slice(0, 4), decryptedSize - 4);
            decryptedPacket[4] = (byte)opcode;
            decryptedPacket[5] = (byte)subOpcode;
            data?.AsSpan().Slice(offset, count).CopyTo(decryptedPacket.AsSpan().Slice(HEADER_SIZE));
        }
        finally
        {
            Utilities.ReturnBytes(decryptedPacket);
        }

        if (Logger.WillLog(LogLevel.Debug))
            Logger.Debug<SyncSession>($"Encrypted message bytes {count + HEADER_SIZE}");

        var len = Encrypt(decryptedPacket.AsSpan().Slice(0, count + HEADER_SIZE), encryptedPacket.AsSpan().Slice(4));
        BinaryPrimitives.WriteInt32LittleEndian(encryptedPacket.AsSpan().Slice(0, 4), len);
        Send(encryptedPacket, 0, encryptedSize, true);

        if (Logger.WillLog(LogLevel.Debug))
            Logger.Debug<SyncSession>($"Wrote message bytes {len}");
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
    public void Send(byte[] data, bool returnToPool = false) => Send(data, 0, data.Length);
    public void Send(byte[] data, int offset, int count, bool returnToPool = false)
    {
        lock (SendQueue)
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
    }

    public void OnWriteCompleted()
    {
        byte[] sentBuffer = WriteArgs.Buffer!;
        var argsPair = (ArgsPair)WriteArgs.UserToken!;
        if (argsPair.ReturnToPool)
            Utilities.ReturnBytes(sentBuffer);

        lock (SendQueue)
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
