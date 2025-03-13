using System;
using System.Buffers;
using System.Buffers.Binary;
using System.Net.Sockets;
using System.Runtime.CompilerServices;
using Noise;
using SyncShared;
using static System.Runtime.InteropServices.JavaScript.JSType;

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
        DATA = 7
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
    private Queue<(byte[] data, int offset, int count)> SendQueue = new Queue<(byte[], int, int)>(16);
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

    public SyncSession(TcpSyncServer server)
    {
        _server = server;
    }

    public void Dispose()
    {
        HandshakeState?.Dispose();
        _isBusyWriting = false;
        Socket?.Close();
        PrimaryState = SessionPrimaryState.Closed;
        if (_accumulatedBuffer != null)
        {
            ArrayPool<byte>.Shared.Return(_accumulatedBuffer);
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
                        ArrayPool<byte>.Shared.Return(_accumulatedBuffer);

                    _accumulatedBuffer = null;
                    SecondaryState = SessionSecondaryState.WaitingForSize;
                }
                else
                {
                    if (_messageSize <= _sessionBuffer.Length)
                        _accumulatedBuffer ??= _sessionBuffer;
                    else
                        _accumulatedBuffer ??= ArrayPool<byte>.Shared.Rent(_messageSize);

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
        }
        else
        {
            int maximumDecryptedSize = data.Length - 16;
            var shouldRent = maximumDecryptedSize > _decryptionBuffer.Length;
            var decryptionBuffer = shouldRent ? ArrayPool<byte>.Shared.Rent(_decryptionBuffer.Length) : _decryptionBuffer;

            try
            {
                int plen = Decrypt(data, decryptionBuffer);
                HandleDecryptedPacket(decryptionBuffer.AsSpan().Slice(0, plen));
            }
            finally
            {
                if (shouldRent)
                    ArrayPool<byte>.Shared.Return(decryptionBuffer);
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
        byte[] packetData = new byte[size - 2];

        Logger.Info<SyncSession>($"HandleDecryptedPacket (opcode = {opcode}, subOpcode = {subOpcode}, size = {packetData.Length})");

        if (opcode == Opcode.PING)
        {
            Send(Opcode.PONG);
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

    public void Send(Opcode opcode, byte subOpcode = 0, byte[]? data = null)
    {
        var decryptedSize = 4 + 1 + 1 + (data?.Length ?? 0);
        var decryptedPacket = ArrayPool<byte>.Shared.Rent(decryptedSize);
        var encryptedPacket = new byte[decryptedSize + 4 + 16];

        try
        {
            BinaryPrimitives.WriteInt32LittleEndian(decryptedPacket.AsSpan().Slice(0, 4), decryptedSize - 4);
            decryptedPacket[4] = (byte)opcode;
            decryptedPacket[5] = (byte)subOpcode;
            data?.CopyTo(decryptedPacket.AsSpan().Slice(HEADER_SIZE));
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(decryptedPacket);
        }

        if (Logger.WillLog(LogLevel.Debug))
            Logger.Debug<SyncSession>($"Encrypted message bytes {(data?.Length ?? 0) + HEADER_SIZE}");

        var len = Encrypt(decryptedPacket.AsSpan().Slice(0, (data?.Length ?? 0) + HEADER_SIZE), encryptedPacket.AsSpan().Slice(4));
        BinaryPrimitives.WriteInt32LittleEndian(encryptedPacket.AsSpan().Slice(0, 4), len);
        Send(encryptedPacket);

        if (Logger.WillLog(LogLevel.Debug))
            Logger.Debug<SyncSession>($"Wrote message bytes {len}");
    }

    private int Encrypt(ReadOnlySpan<byte> source, Span<byte> destination)
    {
        int encryptedLength = _transport!.WriteMessage(source, destination);
        if (Logger.WillLog(LogLevel.Debug))
            Logger.Debug<SyncSession>($"Encrypted message bytes (source size: {source.Length}, destination size: {destination.Length})\n{Utilities.HexDump(source)}");
        return encryptedLength;
    }

    private int Decrypt(ReadOnlySpan<byte> source, Span<byte> destination)
    {
        int plen = _transport!.ReadMessage(source, destination);
        if (Logger.WillLog(LogLevel.Debug))
            Logger.Debug<SyncSession>($"Decrypted message bytes (source size: {source.Length}, destination size: {destination.Length})\n{Utilities.HexDump(destination.Slice(0, plen))}");
        return plen;
    }

    //TODO: Reuse buffer initially set by InitializeBufferPool
    public void Send(byte[] data) => Send(data, 0, data.Length);
    public void Send(byte[] data, int offset, int count)
    {
        lock (SendQueue)
        {
            if (!_isBusyWriting)
            {
                if (Logger.WillLog(LogLevel.Debug))
                    Logger.Debug<SyncSession>($"Sending {count} bytes.\n{Utilities.HexDump(data.AsSpan().Slice(offset, count))}");

                WriteArgs.SetBuffer(data, offset, count);
                bool pending = Socket.SendAsync(WriteArgs!);
                if (pending)
                {
                    Logger.Debug<SyncSession>($"Write not synchronously completed. Set isBusyWriting to true.");
                    _isBusyWriting = true;
                }
                else
                    Logger.Debug<SyncSession>($"Sent {count} bytes synchronously.");
            }
            else
            {
                if (Logger.WillLog(LogLevel.Debug))
                    Logger.Debug<SyncSession>($"Queued {count} bytes to send.");
                SendQueue.Enqueue((data, offset, count));
            }
        }
    }

    public void OnWriteCompleted()
    {
        lock (SendQueue)
        {
            if (SendQueue.Count > 0)
            {
                var (data, offset, count) = SendQueue.Dequeue();
                if (Logger.WillLog(LogLevel.Debug))
                    Logger.Debug<SyncSession>($"Sending {count} bytes from queue.\n{Utilities.HexDump(data.AsSpan().Slice(offset, count))}");

                WriteArgs.SetBuffer(data, offset, count);
                bool pending = Socket.SendAsync(WriteArgs!);
                if (!pending)
                {
                    Logger.Debug<SyncSession>($"Sent {count} bytes synchronously.");
                }
                else
                {
                    Logger.Debug<SyncSession>($"Waiting on next send to complete.");
                }
            }
            else
            {
                Logger.Debug<SyncSession>($"Send completed. Set isBusyWriting to false because last write was completed.");
                _isBusyWriting = false;
            }
        }
    }
}
