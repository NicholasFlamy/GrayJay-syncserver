using System.Buffers;
using System.Buffers.Binary;
using System.Net.Sockets;
using Noise;
using SyncShared;
using static SyncServer.TcpSyncRelayServer;

namespace SyncServer;

public class SyncRelaySession
{
    public enum SessionPrimaryState
    {
        VersionCheck,
        Handshake,
        WaitingForConnectionId,
        RelayWaitingForPeer,
        RelayConnected,
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
        CONNECT = 2,
        NOTIFY_CONNECT = 3
    }

    public const int HEADER_SIZE = 5;
    private const int MaxPendingByteCount = 2048;
    private const int MaxPacketSizeEncrypted = 65535;

    public required Socket Socket { get; init; }
    public required SocketAsyncEventArgs ReadArgs { get; init; }
    public required SocketAsyncEventArgs WriteArgs { get; init; }
    public required HandshakeState HandshakeState { get; init; }
    public string? RemotePublicKey { get; private set; }
    public SessionPrimaryState PrimaryState { get; private set; } = SessionPrimaryState.VersionCheck;
    public SessionSecondaryState SecondaryState { get; private set; } = SessionSecondaryState.WaitingForSize;
    public int RemoteVersion { get; private set; } = -1;
    private Queue<(byte[] data, int offset, int count, bool returnToPool)> PendingQueue = new Queue<(byte[], int, int, bool)>(16);
    private Queue<(byte[] data, int offset, int count, bool returnToPool)> SendQueue = new Queue<(byte[], int, int, bool)>(16);
    private bool _isBusyWriting = false;
    private int _messageSize = -1;
    private byte[]? _accumulatedBuffer;
    private int _accumulatedBytes = 0;
    private byte[] _sizeBuffer = new byte[4];
    private int _sizeAccumulatedBytes = 0;
    private byte[] _sessionBuffer = new byte[1024];
    private byte[] _decryptionBuffer = new byte[1024];
    private readonly TcpSyncRelayServer _server;
    private string? _connectionId;
    private Transport? _transport;
    private SyncRelaySession? _peerSession;
    private int _pendingBytes = 0;
    private readonly object _stateLock = new object();

    public SyncRelaySession(TcpSyncRelayServer server)
    {
        _server = server;
    }

    public void Dispose()
    {
        HandshakeState?.Dispose();
        _isBusyWriting = false;
        Socket?.Close();
        PrimaryState = SessionPrimaryState.Closed;
        if (_connectionId != null)
            _server.UnregisterPending(_connectionId);
        if (_accumulatedBuffer != null)
        {
            Utilities.ReturnBytes(_accumulatedBuffer);
            _accumulatedBuffer = null;
        }
    }

    public void NotifyConnected(SyncRelaySession session)
    {
        lock (_stateLock)
        {
            _peerSession = session;

            Logger.Info<SyncRelaySession>("NotifyConnected started sending pending data");

            foreach (var p in PendingQueue)
                _peerSession!.Send(p.data, p.offset, p.count, p.returnToPool);

            PrimaryState = SessionPrimaryState.RelayConnected;
            _pendingBytes = 0;

            Logger.Info<SyncRelaySession>("NotifyConnected finished sending pending data");
        }
    }

    public void HandleData(int bytesReceived)
    {
        var data = ReadArgs.Buffer.AsSpan(0, bytesReceived);
        if (Logger.WillLog(LogLevel.Debug))
            Logger.Debug<SyncRelaySession>($"Received {bytesReceived} bytes.\n{Utilities.HexDump(data)}");

        lock (_stateLock)
        {
            int offset = 0;
            if (PrimaryState == SessionPrimaryState.VersionCheck)
            {
                if (data.Length != 4)
                    throw new Exception("Expected exactly 4 bytes for version.");

                HandleVersionCheck(data);
                PrimaryState = SessionPrimaryState.Handshake;
                offset = 4;
            }
            else if (PrimaryState == SessionPrimaryState.RelayWaitingForPeer)
            {
                if (_pendingBytes + bytesReceived > MaxPendingByteCount)
                    throw new Exception($"Pending bytes cannot exceed {MaxPendingByteCount} bytes.");

                var rentedBuffer = Utilities.RentBytes(bytesReceived);
                data.CopyTo(rentedBuffer.AsSpan().Slice(0, bytesReceived));
                _pendingBytes += bytesReceived;
                PendingQueue.Enqueue((rentedBuffer, 0, bytesReceived, true));

                Logger.Debug<SyncRelaySession>($"Queued {bytesReceived} bytes as pending.");
                return;
            }
            else if (PrimaryState == SessionPrimaryState.RelayConnected)
            {
                var rentedBuffer = Utilities.RentBytes(bytesReceived);
                data.CopyTo(rentedBuffer.AsSpan().Slice(0, bytesReceived));
                _peerSession!.Send(rentedBuffer, 0, bytesReceived, true);
                Logger.Debug<SyncRelaySession>($"Relayed {bytesReceived} bytes.");
                return;
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
    }
    private void HandlePacket(ReadOnlySpan<byte> data)
    {
        if (PrimaryState == SessionPrimaryState.Handshake)
        {
            var (_, _, _) = HandshakeState.ReadMessage(data, _decryptionBuffer);
            var (bytesWritten, _, transport) = HandshakeState.WriteMessage(null, _decryptionBuffer);
            Logger.Info<SyncRelaySession>($"HandshakeAsResponder: Read message size {data.Length}");

            BinaryPrimitives.WriteInt32LittleEndian(_sessionBuffer, bytesWritten);
            _decryptionBuffer.AsSpan().Slice(0, bytesWritten).CopyTo(_sessionBuffer.AsSpan().Slice(4));
            Send(_sessionBuffer, 0, bytesWritten + 4);
            Logger.Info<SyncRelaySession>($"HandshakeAsResponder: Wrote message size {bytesWritten}");

            _transport = transport;
            RemotePublicKey = Convert.ToBase64String(HandshakeState.RemoteStaticPublicKey);
            Logger.Info<SyncRelaySession>($"HandshakeAsResponder: Remote public key {RemotePublicKey}");

            PrimaryState = SessionPrimaryState.WaitingForConnectionId;
        }
        else
        {
            int maximumDecryptedSize = data.Length - 16;
            var shouldRent = maximumDecryptedSize > _decryptionBuffer.Length;
            var decryptionBuffer = shouldRent ? Utilities.RentBytes(_decryptionBuffer.Length) : _decryptionBuffer;

            try
            {
                int plen = Decrypt(data, decryptionBuffer);
                HandleDecryptedPacket(decryptionBuffer.AsSpan().Slice(0, plen));
            }
            finally
            {
                if (shouldRent)
                    Utilities.ReturnBytes(decryptionBuffer);
            }
        }
    }

    private void HandleDecryptedPacket(ReadOnlySpan<byte> data)
    {
        int size = BinaryPrimitives.ReadInt32LittleEndian(data.Slice(0, 4));
        if (size != data.Length - 4)
            throw new Exception("Incomplete packet received");

        Opcode opcode = (Opcode)data[4];
        byte subOpcode = data[5];
        var packetData = data.Slice(6);

        Logger.Info<SyncRelaySession>($"HandleDecryptedPacket (opcode = {opcode}, subOpcode = {subOpcode}, size = {packetData.Length})");

        switch (opcode)
        {
            case Opcode.PING:
                Send(Opcode.PONG);
                break;
            case Opcode.CONNECT:
                HandleConnect(packetData);
                break;
            default:
                Logger.Debug<SyncRelaySession>($"Received unhandled opcode: {opcode}");
                break;
        }
    }

    private void HandleConnect(ReadOnlySpan<byte> data)
    {
        if (RemotePublicKey == null)
        {
            Logger.Error<SyncRelaySession>("Cannot connect before handshake completes.");
            return;
        }

        _connectionId = Convert.ToBase64String(data);
        Logger.Info<SyncRelaySession>($"HandleConnect (connection id: {_connectionId})");

        _peerSession = _server.FindPeerSession(_connectionId);
        if (_peerSession != null)
        {
            _peerSession.NotifyConnected(this);
            PrimaryState = SessionPrimaryState.RelayConnected;
        }
        else
        {
            PrimaryState = SessionPrimaryState.RelayWaitingForPeer;
            _server.RegisterPending(this, _connectionId);
        }
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

    public void Send(Opcode opcode, byte[]? data = null)
    {
        var decryptedSize = 4 + 1 + (data?.Length ?? 0);
        var encryptedSize = decryptedSize + 4 + 16;
        byte[] decryptedPacket = Utilities.RentBytes(decryptedSize);
        byte[] encryptedPacket = Utilities.RentBytes(encryptedSize);

        try
        {
            BinaryPrimitives.WriteInt32LittleEndian(decryptedPacket.AsSpan().Slice(0, 4), decryptedSize - 4);
            decryptedPacket[4] = (byte)opcode;
            data?.CopyTo(decryptedPacket.AsSpan().Slice(HEADER_SIZE));
        }
        finally
        {
            Utilities.ReturnBytes(decryptedPacket);
        }

        if (Logger.WillLog(LogLevel.Debug))
            Logger.Debug<SyncRelaySession>($"Encrypted message bytes {(data?.Length ?? 0) + HEADER_SIZE}");

        var len = Encrypt(decryptedPacket.AsSpan().Slice(0, (data?.Length ?? 0) + HEADER_SIZE), encryptedPacket.AsSpan().Slice(4));
        BinaryPrimitives.WriteInt32LittleEndian(encryptedPacket.AsSpan().Slice(0, 4), len);
        Send(encryptedPacket, 0, encryptedSize, true);

        if (Logger.WillLog(LogLevel.Debug))
            Logger.Debug<SyncRelaySession>($"Wrote message bytes {len}");
    }

    private int Encrypt(ReadOnlySpan<byte> source, Span<byte> destination)
    {
        int encryptedLength = _transport!.WriteMessage(source, destination);
        if (Logger.WillLog(LogLevel.Debug))
            Logger.Debug<SyncRelaySession>($"Encrypted message bytes (source size: {source.Length}, destination size: {encryptedLength})\n{Utilities.HexDump(source)}");
        return encryptedLength;
    }

    private int Decrypt(ReadOnlySpan<byte> source, Span<byte> destination)
    {
        int plen = _transport!.ReadMessage(source, destination);
        if (Logger.WillLog(LogLevel.Debug))
            Logger.Debug<SyncRelaySession>($"Decrypted message bytes (source size: {source.Length}, destination size: {plen})\n{Utilities.HexDump(destination.Slice(0, plen))}");
        return plen;
    }

    public void Send(byte[] data, bool returnToPool = false) => Send(data, 0, data.Length);
    public void Send(byte[] data, int offset, int count, bool returnToPool = false)
    {
        lock (SendQueue)
        {
            if (!_isBusyWriting)
            {
                if (Logger.WillLog(LogLevel.Debug))
                    Logger.Debug<SyncRelaySession>($"Sending {count} bytes.\n{Utilities.HexDump(data.AsSpan().Slice(offset, count))}");

                WriteArgs.SetBuffer(data, offset, count);
                ((ArgsPair)WriteArgs.UserToken!).ReturnToPool = returnToPool;
                bool pending = Socket.SendAsync(WriteArgs!);
                if (pending)
                {
                    Logger.Debug<SyncRelaySession>($"Write not synchronously completed. Set isBusyWriting to true.");
                    _isBusyWriting = true;
                }
                else
                {
                    Logger.Debug<SyncRelaySession>($"Sent {count} bytes synchronously.");

                    if (returnToPool)
                        Utilities.ReturnBytes(data);
                }
            }
            else
            {
                if (Logger.WillLog(LogLevel.Debug))
                    Logger.Debug<SyncRelaySession>($"Queued {count} bytes to send.");
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
                        Logger.Debug<SyncRelaySession>($"Sending {count} bytes from queue.\n{Utilities.HexDump(data.AsSpan().Slice(offset, count))}");

                    WriteArgs.SetBuffer(data, offset, count);
                    argsPair.ReturnToPool = returnToPoolNext;
                    bool pending = Socket.SendAsync(WriteArgs!);
                    if (!pending)
                    {
                        Logger.Debug<SyncRelaySession>($"Sent {count} bytes synchronously.");
                        if (returnToPoolNext)
                            Utilities.ReturnBytes(data);
                    }
                    else
                    {
                        Logger.Debug<SyncRelaySession>($"Waiting on next send to complete.");
                        break;
                    }
                } while (SendQueue.Count > 0);
            }
            else
            {
                Logger.Debug<SyncRelaySession>($"Send completed. Set isBusyWriting to false because last write was completed.");
                _isBusyWriting = false;
            }
        }
    }
}
