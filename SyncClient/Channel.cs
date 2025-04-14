using Noise;
using SyncShared;
using System.Buffers.Binary;
using System.Net.Sockets;
using System.Text;
namespace SyncClient;

public interface IChannel : IDisposable
{
    public string? RemotePublicKey { get; }
    public int? RemoteVersion { get; }
    public IAuthorizable? Authorizable { get; set; }
    public object? SyncSession { get; set; } //TODO: Replace with SyncSession once library is properly structured
    public void SetDataHandler(Action<SyncSocketSession, IChannel, Opcode, byte, ReadOnlySpan<byte>>? onData);
    public Task SendAsync(Opcode opcode, byte subOpcode, byte[]? data = null, int offset = 0, int count = -1, CancellationToken cancellationToken = default);
    public void SetCloseHandler(Action<IChannel>? onClose);
    public LinkType LinkType { get; }
}

public class ChannelSocket : IChannel
{
    public string? RemotePublicKey => _session.RemotePublicKey;
    public int? RemoteVersion => _session.RemoteVersion;
    private readonly SyncSocketSession _session;
    private Action<SyncSocketSession, IChannel, Opcode, byte, ReadOnlySpan<byte>>? _onData;
    private Action<IChannel>? _onClose;
    public LinkType LinkType => LinkType.Direct;

    public IAuthorizable? Authorizable
    {
        get => _session.Authorizable;
        set => _session.Authorizable = value;
    }
    public object? SyncSession { get; set; }

    public ChannelSocket(SyncSocketSession session)
    {
        _session = session;
    }

    public void SetDataHandler(Action<SyncSocketSession, IChannel, Opcode, byte, ReadOnlySpan<byte>>? onData)
    {
        _onData = onData;
    }

    public void SetCloseHandler(Action<IChannel>? onClose)
    {
        _onClose = onClose;
    }

    public void Dispose()
    {
        _session.Dispose();
        _onClose?.Invoke(this);
    }

    public void InvokeDataHandler(Opcode opcode, byte subOpcode, ReadOnlySpan<byte> data)
    {
        _onData?.Invoke(_session, this, opcode, subOpcode, data);
    }

    public async Task SendAsync(Opcode opcode, byte subOpcode, byte[]? data = null, int offset = 0, int count = -1, CancellationToken cancellationToken = default)
    {
        if (data != null)
            await _session.SendAsync(opcode, subOpcode, data, offset, count, cancellationToken: cancellationToken);
        else
            await _session.SendAsync(opcode, subOpcode, cancellationToken: cancellationToken);
    }
}

public class ChannelRelayed : IChannel
{
    private SemaphoreSlim _sendSemaphore { get; } = new SemaphoreSlim(1);
    private object _decryptLock = new object();
    private HandshakeState? _handshakeState;
    private Transport? _transport = null;
    public IAuthorizable? Authorizable { get; set; }
    public bool IsAuthorized => Authorizable?.IsAuthorized ?? false;
    public long ConnectionId { get; set; }
    public string? RemotePublicKey { get; private set; }
    public int? RemoteVersion { get; private set; }
    public object? SyncSession { get; set; }
    public LinkType LinkType => LinkType.Relayed;

    private readonly KeyPair _localKeyPair;
    private readonly SyncSocketSession _session;
    private Action<SyncSocketSession, IChannel, Opcode, byte, ReadOnlySpan<byte>>? _onData;
    private Action<IChannel>? _onClose;
    private bool _disposed = false;

    public ChannelRelayed(SyncSocketSession session, KeyPair localKeyPair, string publicKey, bool initiator)
    {
        _session = session;
        _localKeyPair = localKeyPair;
        _handshakeState = initiator
            ? Constants.Protocol.Create(initiator, s: _localKeyPair.PrivateKey, rs: Convert.FromBase64String(publicKey))
            : Constants.Protocol.Create(initiator, s: _localKeyPair.PrivateKey);
        RemotePublicKey = publicKey;
    }

    public void SetDataHandler(Action<SyncSocketSession, IChannel, Opcode, byte, ReadOnlySpan<byte>>? onData)
    {
        _onData = onData;
    }

    public void SetCloseHandler(Action<IChannel>? onClose)
    {
        _onClose = onClose;
    }

    public void Dispose()
    {
        _disposed = true;

        var connectionId = ConnectionId;
        if (connectionId != 0)
        {
            Task.Run(async () =>
            {
                try
                {
                    await _session.SendRelayError(connectionId, RelayErrorCode.ConnectionClosed);
                }
                catch (Exception ex)
                {
                    Logger.Error<SyncSocketSession>("Exception while sending relay error.", ex);
                }
            });
        }

        _sendSemaphore.Dispose();
        _transport?.Dispose();
        _transport = null;
        _handshakeState?.Dispose();
        _handshakeState = null;

        _onClose?.Invoke(this);
    }

    private void ThrowIfDisposed()
    {
        if (_disposed) 
            throw new ObjectDisposedException(nameof(ChannelRelayed));
    }

    public void InvokeDataHandler(Opcode opcode, byte subOpcode, ReadOnlySpan<byte> data)
    {
        _onData?.Invoke(_session, this, opcode, subOpcode, data);
    }

    private void CompleteHandshake(int remoteVersion, Transport transport)
    {
        ThrowIfDisposed();

        RemoteVersion = remoteVersion;
        RemotePublicKey = Convert.ToBase64String(_handshakeState!.RemoteStaticPublicKey);
        _handshakeState!.Dispose();
        _handshakeState = null;
        _transport = transport;
        Logger.Info<SyncSocketSession>($"Completed handshake for connectionId {ConnectionId}");
    }

    private async Task SendPacketAsync(byte[] packet, CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();

        await _sendSemaphore.WaitAsync(cancellationToken);
        try
        {
            var encryptedPayload = new byte[packet.Length + 16];
            int encryptedLength = _transport!.WriteMessage(packet, encryptedPayload);

            var relayedPacket = new byte[8 + encryptedLength];
            BinaryPrimitives.WriteInt64LittleEndian(relayedPacket.AsSpan(0, 8), ConnectionId);
            Array.Copy(encryptedPayload, 0, relayedPacket, 8, encryptedLength);

            await _session.SendAsync(Opcode.RELAY, (byte)RelayOpcode.DATA, relayedPacket, cancellationToken: cancellationToken);
        }
        finally
        {
            _sendSemaphore.Release();
        }
    }

    public async Task SendErrorAsync(RelayErrorCode errorCode, CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();

        await _sendSemaphore.WaitAsync(cancellationToken);
        try
        {
            Span<byte> packet = stackalloc byte[4];
            BinaryPrimitives.WriteInt32LittleEndian(packet, (int)errorCode);

            var encryptedPayload = new byte[4 + 16];
            int encryptedLength = _transport!.WriteMessage(packet, encryptedPayload);

            var relayedPacket = new byte[8 + encryptedLength];
            BinaryPrimitives.WriteInt64LittleEndian(relayedPacket.AsSpan(0, 8), ConnectionId);
            Array.Copy(encryptedPayload, 0, relayedPacket, 8, encryptedLength);

            await _session.SendAsync(Opcode.RELAY, (byte)RelayOpcode.ERROR, relayedPacket, cancellationToken: cancellationToken);
        }
        finally
        {
            _sendSemaphore.Release();
        }
    }

    public async Task SendAsync(Opcode opcode, byte subOpcode, byte[]? data = null, int offset = 0, int count = -1, CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();

        if (count == -1)
            count = data?.Length ?? 0;

        if (count != 0 && data == null)
            throw new Exception("Data must be set if count is not 0");

        const int ENCRYPTION_OVERHEAD = 16;
        const int CONNECTION_ID_SIZE = 8;
        const int HEADER_SIZE = 6;
        const int MAX_DATA_PER_PACKET = SyncSocketSession.MAXIMUM_PACKET_SIZE - HEADER_SIZE - CONNECTION_ID_SIZE - ENCRYPTION_OVERHEAD - 16;

        if (count > MAX_DATA_PER_PACKET && data != null)
        {
            var streamId = _session.GenerateStreamId();
            int totalSize = count;
            int sendOffset = 0;

            while (sendOffset < totalSize)
            {
                int bytesRemaining = totalSize - sendOffset;
                int bytesToSend = Math.Min(MAX_DATA_PER_PACKET - 8 - 2, bytesRemaining);

                // Prepare stream data
                byte[] streamData;
                StreamOpcode streamOpcode;
                if (sendOffset == 0)
                {
                    streamOpcode = StreamOpcode.START;
                    streamData = new byte[4 + 4 + 1 + 1 + bytesToSend];
                    BinaryPrimitives.WriteInt32LittleEndian(streamData.AsSpan(0, 4), streamId);
                    BinaryPrimitives.WriteInt32LittleEndian(streamData.AsSpan(4, 4), totalSize);
                    streamData[8] = (byte)opcode;
                    streamData[9] = subOpcode;
                    Array.Copy(data, offset + sendOffset, streamData, 10, bytesToSend);
                }
                else
                {
                    streamData = new byte[4 + 4 + bytesToSend];
                    BinaryPrimitives.WriteInt32LittleEndian(streamData.AsSpan(0, 4), streamId);
                    BinaryPrimitives.WriteInt32LittleEndian(streamData.AsSpan(4, 4), sendOffset);
                    Array.Copy(data, offset + sendOffset, streamData, 8, bytesToSend);
                    streamOpcode = (bytesToSend < bytesRemaining) ? StreamOpcode.DATA : StreamOpcode.END;
                }

                // Wrap with header
                var fullPacket = new byte[HEADER_SIZE + streamData.Length];
                BinaryPrimitives.WriteInt32LittleEndian(fullPacket.AsSpan(0, 4), streamData.Length + 2);
                fullPacket[4] = (byte)Opcode.STREAM;
                fullPacket[5] = (byte)streamOpcode;
                Array.Copy(streamData, 0, fullPacket, HEADER_SIZE, streamData.Length);

                await SendPacketAsync(fullPacket, cancellationToken);
                sendOffset += bytesToSend;
            }
        }
        else
        {
            var packet = new byte[HEADER_SIZE + count];
            BinaryPrimitives.WriteInt32LittleEndian(packet.AsSpan(0, 4), count + 2);
            packet[4] = (byte)opcode;
            packet[5] = subOpcode;
            if (count > 0 && data != null)
                Array.Copy(data, offset, packet, HEADER_SIZE, count);
            await SendPacketAsync(packet, cancellationToken);
        }
    }

    public async Task SendRequestTransportAsync(int requestId, string publicKey, string? pairingCode = null, CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();

        await _sendSemaphore.WaitAsync();
        try
        {
            var channelMessage = new byte[1024];
            var (channelBytesWritten, _, _) = _handshakeState!.WriteMessage(null, channelMessage);

            byte[] publicKeyBytes = Convert.FromBase64String(publicKey);
            if (publicKeyBytes.Length != 32)
                throw new ArgumentException("Public key must be 32 bytes.");

            int pairingMessageLength;
            byte[] pairingMessage;

            if (pairingCode != null)
            {
                var pairingProtocol = new Protocol(HandshakePattern.N, CipherFunction.ChaChaPoly, HashFunction.Blake2b);
                using var pairingHandshakeState = pairingProtocol.Create(true, rs: publicKeyBytes);
                byte[] pairingCodeBytes = Encoding.UTF8.GetBytes(pairingCode);
                if (pairingCodeBytes.Length > 32)
                    throw new ArgumentException("Pairing code must not exceed 32 bytes.");

                var pairingMessageBuffer = new byte[1024];
                var (bytesWritten, _, _) = pairingHandshakeState.WriteMessage(pairingCodeBytes, pairingMessageBuffer);
                pairingMessageLength = bytesWritten;

                pairingMessage = pairingMessageBuffer.AsSpan(0, bytesWritten).ToArray();
            }
            else
            {
                pairingMessageLength = 0;
                pairingMessage = Array.Empty<byte>();
            }

            var packetSize = 4 + 32 + 4 + pairingMessageLength + 4 + channelBytesWritten;
            var packet = new byte[packetSize];

            int offset = 0;
            BinaryPrimitives.WriteInt32LittleEndian(packet.AsSpan(offset, 4), requestId);
            offset += 4;
            publicKeyBytes.CopyTo(packet.AsSpan(offset, 32));
            offset += 32;
            BinaryPrimitives.WriteInt32LittleEndian(packet.AsSpan(offset, 4), pairingMessageLength);
            offset += 4;
            if (pairingMessageLength > 0)
            {
                pairingMessage.CopyTo(packet.AsSpan(offset));
                offset += pairingMessageLength;
            }
            BinaryPrimitives.WriteInt32LittleEndian(packet.AsSpan(offset, 4), channelBytesWritten);
            offset += 4;
            channelMessage.AsSpan(0, channelBytesWritten).CopyTo(packet.AsSpan(offset));

            await _session.SendAsync(Opcode.REQUEST, (byte)RequestOpcode.TRANSPORT, packet, cancellationToken: cancellationToken);
        }
        finally
        {
            _sendSemaphore.Release();
        }
    }

    public async Task SendResponseTransportAsync(int remoteVersion, int requestId, byte[] handshakeMessage)
    {
        ThrowIfDisposed();

        var message = new byte[1024];
        var plaintext = new byte[1024];
        _handshakeState!.ReadMessage(handshakeMessage, plaintext);
        var (bytesWritten, _, transport) = _handshakeState!.WriteMessage(null, message);

        var responsePacket = new byte[20 + bytesWritten];
        BinaryPrimitives.WriteInt32LittleEndian(responsePacket.AsSpan(0, 4), (int)0); //status code
        BinaryPrimitives.WriteInt64LittleEndian(responsePacket.AsSpan(4, 8), ConnectionId);
        BinaryPrimitives.WriteInt32LittleEndian(responsePacket.AsSpan(12, 4), requestId);
        BinaryPrimitives.WriteInt32LittleEndian(responsePacket.AsSpan(16, 4), bytesWritten);
        message.AsSpan(0, bytesWritten).CopyTo(responsePacket.AsSpan(20));

        CompleteHandshake(remoteVersion, transport!);
        await _session.SendAsync(Opcode.RESPONSE, (byte)ResponseOpcode.TRANSPORT, responsePacket);
    }

    public (byte[] decryptedPayload, int length) Decrypt(ReadOnlySpan<byte> encryptedPayload)
    {
        ThrowIfDisposed();

        lock (_decryptLock)
        {
            var decryptedPayload = new byte[encryptedPayload.Length - 16];
            int plen = _transport!.ReadMessage(encryptedPayload, decryptedPayload);
            if (plen != decryptedPayload.Length)
                throw new Exception($"Expected decrypted payload length to be {plen}");
            return (decryptedPayload, plen);
        }
    }

    public void HandleTransportRelayed(int remoteVersion, long connectionId, byte[] handshakeMessage)
    {
        ThrowIfDisposed();

        lock (_decryptLock)
        {
            ConnectionId = connectionId;
            var plaintext = new byte[1024];
            var (_, _, transport) = _handshakeState!.ReadMessage(handshakeMessage, plaintext);
            CompleteHandshake(remoteVersion, transport!);
        }
    }
}
