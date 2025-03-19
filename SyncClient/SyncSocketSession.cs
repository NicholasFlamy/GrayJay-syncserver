using System.Buffers.Binary;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Net;
using Noise;
using SyncShared;
using System.Text;
using System.Collections.Concurrent;
using System.Security.Cryptography;

namespace SyncClient;

public interface IAuthorizable
{
    bool IsAuthorized { get; }
}

public record ConnectionInfo(
    ushort Port,
    string Name,
    IPAddress RemoteIp,
    List<IPAddress> Ipv4Addresses,
    List<IPAddress> Ipv6Addresses,
    bool AllowLocal,
    bool AllowRemoteDirect,
    bool AllowRemoteHolePunched,
    bool AllowRemoteProxied
);

public class SyncSocketSession : IDisposable
{
    private static readonly Protocol _protocol = new Protocol(
        HandshakePattern.IK,
        CipherFunction.ChaChaPoly,
        HashFunction.Blake2b
    );

    public class Channel : IDisposable
    {
        public long ConnectionId { get; set; }
        public HandshakeState? HandshakeState;
        public string? RemotePublicKey { get; private set; } = null;
        public Transport? Transport { get; private set; } = null;
        private readonly KeyPair _localKeyPair;
        private readonly SyncSocketSession _session;
        private Action<SyncSocketSession, Channel, Opcode, byte, byte[]>? _onData;

        public Channel(SyncSocketSession session, KeyPair localKeyPair, string publicKey, bool initiator)
        {
            _session = session;
            _localKeyPair = localKeyPair;
            HandshakeState = initiator 
                ? _protocol.Create(initiator, s: _localKeyPair.PrivateKey, rs: Convert.FromBase64String(publicKey))
                : _protocol.Create(initiator, s: _localKeyPair.PrivateKey);
        }

        public void SetDataHandler(Action<SyncSocketSession, Channel, Opcode, byte, byte[]>? onData)
        {
            _onData = onData;
        }

        public void Dispose()
        {
            Transport?.Dispose();
            Transport = null;
            HandshakeState?.Dispose();
            HandshakeState = null;
        }

        public void InvokeDataHandler(Opcode opcode, byte subOpcode, byte[] data, Channel? sourceChannel = null)
        {
            _onData?.Invoke(_session, this, opcode, subOpcode, data);
        }

        public void CompleteHandshake(Transport transport)
        {
            RemotePublicKey = Convert.ToBase64String(HandshakeState!.RemoteStaticPublicKey);
            HandshakeState!.Dispose();
            HandshakeState = null;
            Transport = transport;
            Logger.Info<SyncSocketSession>($"Completed handshake for connectionId {ConnectionId}");
        }

        public Task SendRelayedDataAsync(Opcode opcode, byte subOpcode, byte[]? data = null, int offset = 0, int count = -1, CancellationToken cancellationToken = default)
            => _session.SendRelayedDataAsync(this, opcode, subOpcode, data, offset, count, cancellationToken);
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

    private readonly Stream _inputStream;
    private readonly Stream _outputStream;
    private readonly SemaphoreSlim _sendSemaphore = new SemaphoreSlim(1);
    private readonly byte[] _buffer = new byte[MAXIMUM_PACKET_SIZE_ENCRYPTED];
    private readonly byte[] _bufferDecrypted = new byte[MAXIMUM_PACKET_SIZE];
    private readonly byte[] _sendBuffer = new byte[MAXIMUM_PACKET_SIZE];
    private readonly byte[] _sendBufferEncrypted = new byte[MAXIMUM_PACKET_SIZE_ENCRYPTED];
    private readonly Dictionary<int, SyncStream> _syncStreams = new();
    private int _streamIdGenerator = 0;
    private readonly Action<SyncSocketSession> _onClose;
    private readonly Action<SyncSocketSession> _onHandshakeComplete;
    private readonly Action<SyncSocketSession, Channel> _onNewChannel;
    private Thread? _thread = null;
    private Transport? _transport = null;
    public string? RemotePublicKey { get; private set; } = null;
    private bool _started;
    private KeyPair _localKeyPair;
    private readonly string _localPublicKey;
    public string LocalPublicKey => _localPublicKey;
    private readonly Action<SyncSocketSession, Opcode, byte, byte[]> _onData;
    public string RemoteAddress { get; }
    public int RemoteVersion { get; private set; } = -1;
    private readonly ConcurrentDictionary<long, Channel> _channels = new();
    private readonly ConcurrentDictionary<int, (Channel Channel, TaskCompletionSource<Channel> Tcs)> _pendingChannels = new();
    private readonly ConcurrentDictionary<int, TaskCompletionSource<ConnectionInfo?>> _pendingConnectionInfoRequests = new();
    private int _requestIdGenerator = 0;

    public IAuthorizable? Authorizable { get; set; }


    public SyncSocketSession(string remoteAddress, KeyPair localKeyPair, Stream inputStream, Stream outputStream,
        Action<SyncSocketSession> onClose, Action<SyncSocketSession> onHandshakeComplete,
        Action<SyncSocketSession, Opcode, byte, byte[]> onData, Action<SyncSocketSession, Channel> onNewChannel)
    {
        _inputStream = inputStream;
        _outputStream = outputStream;
        _onClose = onClose;
        _onHandshakeComplete = onHandshakeComplete;
        _localKeyPair = localKeyPair;
        _onData = onData;
        _onNewChannel = onNewChannel;
        _localPublicKey = Convert.ToBase64String(localKeyPair.PublicKey);
        RemoteAddress = remoteAddress;
    }

    public void StartAsInitiator(string remotePublicKey)
    {
        _started = true;
        _thread = new Thread(() =>
        {
            try
            {
                HandshakeAsInitiator(remotePublicKey);
                _onHandshakeComplete(this);
                ReceiveLoop();
            }
            catch (Exception e)
            {
                Logger.Error<SyncSocketSession>($"Failed to run as initiator: {e}");
            }
            finally
            {
                Stop();
            }
        });
        _thread.Start();
    }

    public void StartAsResponder()
    {
        _started = true;
        _thread = new Thread(() =>
        {
            try
            {
                HandshakeAsResponder();
                _onHandshakeComplete(this);
                ReceiveLoop();
            }
            catch (Exception e)
            {
                Logger.Error<SyncSocketSession>($"Failed to run as responder: {e}");
            }
            finally
            {
                Stop();
            }
        });
        _thread.Start();
    }

    private void ReceiveLoop()
    {
        while (_started)
        {
            try
            {
                byte[] messageSizeBytes = new byte[4];
                Read(messageSizeBytes, 0, 4);
                int messageSize = BitConverter.ToInt32(messageSizeBytes, 0);
                if (messageSize == 0)
                    throw new Exception("Disconnected.");

                if (Logger.WillLog(LogLevel.Debug))
                    Logger.Debug<SyncSocketSession>($"Read message size {messageSize}");

                if (messageSize > MAXIMUM_PACKET_SIZE_ENCRYPTED)
                    throw new Exception($"Message size ({messageSize}) exceeds maximum allowed size ({MAXIMUM_PACKET_SIZE_ENCRYPTED})");

                int bytesRead = 0;
                while (bytesRead < messageSize)
                {
                    int read = Read(_buffer, bytesRead, messageSize - bytesRead);
                    if (read == -1)
                        throw new Exception("Stream closed");
                    bytesRead += read;
                }

                if (Logger.WillLog(LogLevel.Debug))
                    Logger.Debug<SyncSocketSession>($"Read message bytes {bytesRead}");

                int plen = Decrypt(_buffer.AsSpan().Slice(0, messageSize), _bufferDecrypted);
                if (Logger.WillLog(LogLevel.Debug))
                    Logger.Debug<SyncSocketSession>($"Decrypted message bytes {plen}");

                HandleData(_bufferDecrypted, plen);
            }
            catch (Exception e)
            {
                Logger.Error<SyncSocketSession>($"Exception while receiving data: {e}");
                break;
            }
        }
    }

    public void Stop()
    {
        _started = false;
        _onClose(this);
        _inputStream.Close();
        _outputStream.Close();
        _transport?.Dispose();
        _thread = null;
        Logger.Info<SyncSocketSession>("Session closed");
    }

    private void HandshakeAsInitiator(string remotePublicKey)
    {
        PerformVersionCheck();

        var message = new byte[Protocol.MaxMessageLength];
        var plaintext = new byte[Protocol.MaxMessageLength];
        using (var handshakeState = _protocol.Create(true, s: _localKeyPair.PrivateKey, rs: Convert.FromBase64String(remotePublicKey)))
        {
            var (bytesWritten, _, _) = handshakeState.WriteMessage(null, message);
            Send(BitConverter.GetBytes(bytesWritten));
            Send(message, 0, bytesWritten);
            Logger.Info<SyncSocketSession>($"HandshakeAsInitiator: Wrote message size {bytesWritten}");

            var bytesRead = Read(message, 0, 4);
            if (bytesRead != 4)
                throw new Exception("Expected exactly 4 bytes (message size)");

            var messageSize = BitConverter.ToInt32(message);
            Logger.Info<SyncSocketSession>($"HandshakeAsInitiator: Read message size {messageSize}");
            bytesRead = 0;
            while (bytesRead < messageSize)
            {
                var read = Read(message, bytesRead, messageSize - bytesRead);
                if (read == 0)
                    throw new Exception("Stream closed.");
                bytesRead += read;
            }

            var (_, _, transport) = handshakeState.ReadMessage(message.AsSpan().Slice(0, messageSize), plaintext);
            _transport = transport;

            RemotePublicKey = Convert.ToBase64String(handshakeState.RemoteStaticPublicKey);
        }
    }

    private void HandshakeAsResponder()
    {
        PerformVersionCheck();

        var message = new byte[Protocol.MaxMessageLength];
        var plaintext = new byte[Protocol.MaxMessageLength];
        using (var handshakeState = _protocol.Create(false, s: _localKeyPair.PrivateKey))
        {
            var bytesRead = Read(message, 0, 4);
            if (bytesRead != 4)
                throw new Exception($"Expected exactly 4 bytes (message size), read {bytesRead}");

            var messageSize = BitConverter.ToInt32(message);
            Logger.Info<SyncSocketSession>($"HandshakeAsResponder: Read message size {messageSize}");

            bytesRead = 0;
            while (bytesRead < messageSize)
            {
                var read = Read(message, bytesRead, messageSize - bytesRead);
                if (read == 0)
                    throw new Exception("Stream closed.");
                bytesRead += read;
            }

            var (_, _, _) = handshakeState.ReadMessage(message.AsSpan().Slice(0, messageSize), plaintext);

            var (bytesWritten, _, transport) = handshakeState.WriteMessage(null, message);
            Send(BitConverter.GetBytes(bytesWritten));
            Send(message, 0, bytesWritten);
            Logger.Info<SyncSocketSession>($"HandshakeAsResponder: Wrote message size {bytesWritten}");

            _transport = transport;

            RemotePublicKey = Convert.ToBase64String(handshakeState.RemoteStaticPublicKey);
        }
    }

    private void PerformVersionCheck()
    {
        const int CURRENT_VERSION = 3;
        const int MINIMUM_VERSION = 2;
        Send(BitConverter.GetBytes(CURRENT_VERSION), 0, 4);
        byte[] versionBytes = new byte[4];
        int bytesRead = Read(versionBytes, 0, 4);
        if (bytesRead != 4)
            throw new Exception($"Expected 4 bytes to be read, read {bytesRead}");
        RemoteVersion = BitConverter.ToInt32(versionBytes, 0);
        Logger.Info(nameof(SyncSocketSession), $"PerformVersionCheck {RemoteVersion}");
        if (RemoteVersion < MINIMUM_VERSION)
            throw new Exception("Invalid version");
    }

    private int Encrypt(ReadOnlySpan<byte> source, Span<byte> destination)
    {
        int encryptedLength = _transport!.WriteMessage(source, destination);
        if (Logger.WillLog(LogLevel.Debug))
            Logger.Debug<SyncSocketSession>($"Encrypted message bytes (source size: {source.Length}, destination size: {encryptedLength})\n{Utilities.HexDump(source)}");
        return encryptedLength;
    }

    private int Decrypt(ReadOnlySpan<byte> source, Span<byte> destination)
    {
        int plen = _transport!.ReadMessage(source, destination);
        if (Logger.WillLog(LogLevel.Debug))
            Logger.Debug<SyncSocketSession>($"Decrypted message bytes (source size: {source.Length}, destination size: {plen})\n{Utilities.HexDump(destination.Slice(0, plen))}");
        return plen;
    }

    private int Read(byte[] buffer, int offset, int size)
    {
        int bytesRead = _inputStream.Read(buffer, offset, size);
        if (Logger.WillLog(LogLevel.Debug))
            Logger.Debug<SyncSocketSession>($"Read {bytesRead} bytes.\n{Utilities.HexDump(buffer.AsSpan().Slice(offset, bytesRead))}");
        return bytesRead;
    }

    private async Task SendAsync(byte[] data, int offset = 0, int size = -1, CancellationToken cancellationToken = default)
    {
        if (Logger.WillLog(LogLevel.Debug))
            Logger.Debug<SyncSocketSession>($"Sending {data.Length} bytes.\n{Utilities.HexDump(data.AsSpan().Slice(offset, size))}");

        if (size == -1)
            size = data.Length;
        await _outputStream.WriteAsync(data, offset, size, cancellationToken);
    }

    private void Send(byte[] data, int offset = 0, int size = -1)
    {
        if (size == -1)
            size = data.Length;
        Send(data.AsSpan().Slice(0, size));
    }

    private void Send(ReadOnlySpan<byte> data)
    {
        if (Logger.WillLog(LogLevel.Debug))
            Logger.Debug<SyncSocketSession>($"Sending {data.Length} bytes.\n{Utilities.HexDump(data)}");
        _outputStream.Write(data);
    }

    public async Task SendAsync(Opcode opcode, byte subOpcode, byte[] data, int offset = 0, int size = -1, CancellationToken cancellationToken = default) =>
        await SendAsync((byte)opcode, subOpcode, data, offset, size, cancellationToken);
    public async Task SendAsync(byte opcode, byte subOpcode, byte[] data, int offset = 0, int size = -1, CancellationToken cancellationToken = default)
    {
        if (size == -1)
            size = data.Length;

        if (size + HEADER_SIZE > MAXIMUM_PACKET_SIZE)
        {
            var segmentSize = MAXIMUM_PACKET_SIZE - HEADER_SIZE;
            var segmentData = new byte[segmentSize];
            var id = Interlocked.Increment(ref _streamIdGenerator);

            for (var sendOffset = 0; sendOffset < size;)
            {
                var bytesRemaining = size - sendOffset;
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
                    BinaryPrimitives.WriteInt32LittleEndian(segmentData.AsSpan().Slice(4, 4), size);
                    segmentData[8] = (byte)opcode;
                    segmentData[9] = (byte)subOpcode;
                    data.AsSpan(offset, size).Slice(sendOffset, bytesToSend).CopyTo(segmentData.AsSpan().Slice(10));
                }
                else
                {
                    //TODO: replace segmentData.AsSpan() into a local variable once C# 13
                    BinaryPrimitives.WriteInt32LittleEndian(segmentData.AsSpan().Slice(0, 4), id);
                    BinaryPrimitives.WriteInt32LittleEndian(segmentData.AsSpan().Slice(4, 4), sendOffset);
                    data.AsSpan(offset, size).Slice(sendOffset, bytesToSend).CopyTo(segmentData.AsSpan().Slice(8));
                }

                sendOffset += bytesToSend;
                await SendAsync((byte)op, 0, segmentData.AsSpan().Slice(0, segmentPacketSize).ToArray(), cancellationToken: cancellationToken);
            }
        }
        else
        {
            try
            {
                await _sendSemaphore.WaitAsync();

                Array.Copy(BitConverter.GetBytes(data.Length + 2), 0, _sendBuffer, 0, 4);
                _sendBuffer[4] = (byte)opcode;
                _sendBuffer[5] = (byte)subOpcode;
                data.CopyTo(_sendBuffer.AsSpan().Slice(HEADER_SIZE));

                if (Logger.WillLog(LogLevel.Debug))
                    Logger.Debug<SyncSocketSession>($"Encrypted message bytes {data.Length + HEADER_SIZE}");

                var len = Encrypt(_sendBuffer.AsSpan().Slice(0, data.Length + HEADER_SIZE), _sendBufferEncrypted);

                Send(BitConverter.GetBytes(len), 0, 4);

                if (Logger.WillLog(LogLevel.Debug))
                    Logger.Debug<SyncSocketSession>($"Wrote message size {len}");

                Send(_sendBufferEncrypted, 0, len);

                if (Logger.WillLog(LogLevel.Debug))
                    Logger.Debug<SyncSocketSession>($"Wrote message bytes {len}");
            }
            finally
            {
                _sendSemaphore.Release();
            }
        }
    }

    public async Task SendAsync(Opcode opcode, byte subOpcode = 0, CancellationToken cancellationToken = default)
    {
        try
        {
            await _sendSemaphore.WaitAsync(cancellationToken);

            Array.Copy(BitConverter.GetBytes(2), 0, _sendBuffer, 0, 4);
            _sendBuffer[4] = (byte)opcode;
            _sendBuffer[5] = (byte)subOpcode;

            if (Logger.WillLog(LogLevel.Debug))
                Logger.Debug<SyncSocketSession>($"Encrypted message bytes {HEADER_SIZE}");

            var len = Encrypt(_sendBuffer.AsSpan().Slice(0, HEADER_SIZE), _sendBufferEncrypted);
            await SendAsync(BitConverter.GetBytes(len), 0, 4, cancellationToken);

            if (Logger.WillLog(LogLevel.Debug))
                Logger.Debug<SyncSocketSession>($"Wrote message size {len}");

            await SendAsync(_sendBufferEncrypted, 0, len, cancellationToken);

            if (Logger.WillLog(LogLevel.Debug))
                Logger.Debug<SyncSocketSession>($"Wrote message bytes {len}");
        }
        finally
        {
            _sendSemaphore.Release();
        }
    }

    private void HandleData(byte[] data, int length, Channel? sourceChannel = null)
    {
        if (length < HEADER_SIZE)
            throw new Exception("Packet must be at least 6 bytes (header size)");

        int size = BitConverter.ToInt32(data, 0);
        if (size != length - 4)
            throw new Exception("Incomplete packet received");

        byte opcode = data[4];
        byte subOpcode = data[5];
        byte[] packetData = new byte[size - 2];
        Array.Copy(data, HEADER_SIZE, packetData, 0, size - 2);

        HandlePacket((Opcode)opcode, subOpcode, packetData, sourceChannel);
    }

    public Task<ConnectionInfo> RequestConnectionInfoAsync(string publicKey, CancellationToken cancellationToken = default)
    {
        var tcs = new TaskCompletionSource<ConnectionInfo>();
        var requestId = Interlocked.Increment(ref _requestIdGenerator);
        _pendingConnectionInfoRequests[requestId] = tcs;
        cancellationToken.Register(() =>
        {
            if (_pendingConnectionInfoRequests.TryRemove(requestId, out var cancelledTcs))
            {
                cancelledTcs.TrySetCanceled();
            }
        });

        try
        {
            byte[] publicKeyBytes = Convert.FromBase64String(publicKey);
            if (publicKeyBytes.Length != 32)
                throw new ArgumentException("Public key must be 32 bytes.");

            var packet = new byte[4 + 32];
            BinaryPrimitives.WriteInt32LittleEndian(packet.AsSpan(0, 4), requestId);
            publicKeyBytes.CopyTo(packet.AsSpan(4, 32));

            _ = SendAsync(Opcode.REQUEST_CONNECTION_INFO, 0, packet, cancellationToken: cancellationToken)
                .ContinueWith(t =>
                {
                    if (t.IsFaulted && _pendingConnectionInfoRequests.TryRemove(requestId, out var failedTcs))
                    {
                        failedTcs.TrySetException(t.Exception!.InnerException!);
                    }
                });
        }
        catch (Exception ex)
        {
            if (_pendingConnectionInfoRequests.TryRemove(requestId, out var errorTcs))
            {
                errorTcs.TrySetException(ex);
            }
            throw;
        }

        return tcs.Task;
    }

    public Task<Channel> StartRelayedChannelAsync(string publicKey, CancellationToken cancellationToken = default)
    {
        var tcs = new TaskCompletionSource<Channel>();
        var requestId = Interlocked.Increment(ref _requestIdGenerator);
        var channel = new Channel(this, _localKeyPair, publicKey, true);
        _onNewChannel?.Invoke(this, channel);
        _pendingChannels[requestId] = (channel, tcs);

        cancellationToken.Register(() =>
        {
            if (_pendingChannels.TryRemove(requestId, out var pending))
            {
                pending.Channel.Dispose();
                pending.Tcs.TrySetCanceled();
            }
        });

        try
        {
            var message = new byte[1024];
            var (bytesWritten, _, _) = channel.HandshakeState!.WriteMessage(null, message);

            byte[] publicKeyBytes = Convert.FromBase64String(publicKey);
            if (publicKeyBytes.Length != 32)
                throw new ArgumentException("Public key must be 32 bytes.");

            var packetSize = 4 + 32 + 4 + bytesWritten;
            var packet = new byte[packetSize];
            BinaryPrimitives.WriteInt32LittleEndian(packet.AsSpan(0, 4), requestId);
            publicKeyBytes.CopyTo(packet.AsSpan(4, 32));
            BinaryPrimitives.WriteInt32LittleEndian(packet.AsSpan(36, 4), bytesWritten);
            message.AsSpan(0, bytesWritten).CopyTo(packet.AsSpan(40));

            _ = SendAsync(Opcode.REQUEST_RELAYED_TRANSPORT, 0, packet, cancellationToken: cancellationToken)
                .ContinueWith(t =>
                {
                    if (t.IsFaulted && _pendingChannels.TryRemove(requestId, out var pending))
                    {
                        pending.Channel.Dispose();
                        pending.Tcs.TrySetException(t.Exception!.InnerException!);
                    }
                });
        }
        catch (Exception ex)
        {
            if (_pendingChannels.TryRemove(requestId, out var pending))
            {
                pending.Channel.Dispose();
                pending.Tcs.TrySetException(ex);
            }
            throw;
        }

        return tcs.Task;
    }

    public async Task PublishConnectionInformationAsync(string[] authorizedKeys, int port, bool allowLocal, bool allowRemoteDirect, bool allowRemoteHolePunched, bool allowRemoteProxied, CancellationToken cancellationToken = default)
    {
        const int MAX_AUTHORIZED_KEYS = 255;
        if (authorizedKeys.Length > MAX_AUTHORIZED_KEYS)
            throw new ArgumentException($"Number of authorized keys exceeds the maximum limit of {MAX_AUTHORIZED_KEYS}.");

        // Collect network information
        var ipv4Addresses = new List<IPAddress>(capacity: 4);
        var ipv6Addresses = new List<IPAddress>(capacity: 4);
        foreach (var nic in NetworkInterface.GetAllNetworkInterfaces())
        {
            if (nic.OperationalStatus == OperationalStatus.Up)
            {
                foreach (var unicast in nic.GetIPProperties().UnicastAddresses)
                {
                    var ip = unicast.Address;
                    if (!IPAddress.IsLoopback(ip))
                    {
                        if (ip.AddressFamily == AddressFamily.InterNetwork)
                            ipv4Addresses.Add(ip);
                        else if (ip.AddressFamily == AddressFamily.InterNetworkV6)
                            ipv6Addresses.Add(ip);
                    }
                }
            }
        }

        // Serialize connection information
        var nameBytes = Utilities.GetLimitedUtf8Bytes(OSHelper.GetComputerName(), 255);
        int blobSize = 2 + 1 + nameBytes.Length + 1 + ipv4Addresses.Count * 4 + 1 + ipv6Addresses.Count * 16 + 1 + 1 + 1 + 1;
        byte[] data = new byte[blobSize];
        using (var stream = new MemoryStream(data))
        using (var writer = new BinaryWriter(stream))
        {
            writer.Write((ushort)port);
            writer.Write((byte)nameBytes.Length);
            writer.Write(nameBytes);
            writer.Write((byte)ipv4Addresses.Count);
            foreach (var addr in ipv4Addresses)
                writer.Write(addr.GetAddressBytes());
            writer.Write((byte)ipv6Addresses.Count);
            foreach (var addr in ipv6Addresses)
                writer.Write(addr.GetAddressBytes());
            writer.Write((byte)(allowLocal ? 1 : 0));
            writer.Write((byte)(allowRemoteDirect ? 1 : 0));
            writer.Write((byte)(allowRemoteHolePunched ? 1 : 0));
            writer.Write((byte)(allowRemoteProxied ? 1 : 0));
        }

        // Precalculate total size
        int totalSize = 1 + authorizedKeys.Length * (100 + data.Length);
        var publishBytes = new byte[totalSize];

        // Encrypt data for each authorized key
        using (var publishDataStream = new MemoryStream(publishBytes, 0, totalSize, true, true))
        using (var writer = new BinaryWriter(publishDataStream))
        {
            writer.Write((byte)authorizedKeys.Length);
            foreach (var authorizedKey in authorizedKeys)
            {
                var publicKeyBytes = Convert.FromBase64String(authorizedKey);
                if (publicKeyBytes.Length != 32)
                    throw new InvalidOperationException("Public key must be 32 bytes.");
                writer.Write(publicKeyBytes);

                var protocol = new Protocol(HandshakePattern.N, CipherFunction.ChaChaPoly, HashFunction.Blake2b);
                using var handshakeState = protocol.Create(true, rs: publicKeyBytes);

                var expectedHandshakeSize = 32 + 16;
                var handshakeMessage = new byte[expectedHandshakeSize];
                var (handshakeBytesWritten, _, transport) = handshakeState.WriteMessage(null, handshakeMessage);
                if (handshakeBytesWritten != expectedHandshakeSize)
                    throw new InvalidOperationException($"Handshake message must be {expectedHandshakeSize} bytes.");
                writer.Write(handshakeMessage, 0, expectedHandshakeSize);

                var ciphertext = new byte[data.Length + 16];
                var ciphertextBytesWritten = transport.WriteMessage(data, ciphertext);
                if (ciphertextBytesWritten != data.Length + 16)
                    throw new InvalidOperationException("Ciphertext size mismatch.");
                writer.Write(data.Length + 16);
                writer.Write(ciphertext, 0, data.Length + 16);
            }
        }

        // Send encrypted data
        await SendAsync(Opcode.PUBLISH_CONNECTION_INFO, 0, publishBytes, cancellationToken: cancellationToken);
    }

    private void HandlePacket(Opcode opcode, byte subOpcode, byte[] data, Channel? sourceChannel = null)
    {
        switch (opcode)
        {
            case Opcode.PING:
                Task.Run(async () => 
                {
                    try
                    {
                        if (sourceChannel != null)
                        {
                            await sourceChannel.SendRelayedDataAsync(Opcode.PONG, 0);
                        }
                        else
                        {
                            await SendAsync(Opcode.PONG);
                        }
                    }
                    catch (Exception e)
                    {
                        Logger.Error<SyncSocketSession>("Failed to send pong: " + e.ToString(), e);
                    }
                });
                Logger.Debug<SyncSocketSession>("Received PONG");
                return;
            case Opcode.PONG:
                Logger.Debug<SyncSocketSession>("Received PONG");
                return;
            case Opcode.NOTIFY_AUTHORIZED:
            case Opcode.NOTIFY_UNAUTHORIZED:
                //Ignore for sourceChannel != null because in order to establish the channel authorization is already completed
                if (sourceChannel == null)
                    _onData(this, opcode, subOpcode, data);
                return;
            case Opcode.RESPONSE_CONNECTION_INFO:
                {
                    if (data.Length < 4)
                    {
                        Logger.Error<SyncSocketSession>("RESPONSE_CONNECTION_INFO packet too short");
                        return;
                    }
                    int requestId = BinaryPrimitives.ReadInt32LittleEndian(data.AsSpan(0, 4));
                    if (_pendingConnectionInfoRequests.TryRemove(requestId, out var tcs))
                    {
                        if (subOpcode == 0)
                        {
                            try
                            {
                                var connectionInfo = ParseConnectionInfo(data.AsSpan(4));
                                tcs.SetResult(connectionInfo);
                            }
                            catch (Exception ex)
                            {
                                tcs.SetException(ex);
                            }
                        }
                        else
                        {
                            tcs.SetResult(null);
                        }
                    }
                    else
                    {
                        Logger.Error<SyncSocketSession>($"No pending request for requestId {requestId}");
                    }
                    return;
                }
            case Opcode.REQUEST_RELAYED_TRANSPORT:
                Logger.Info<SyncSocketSession>("Received request for a relayed transport");
                HandleRequestRelayedTransport(data);
                return;
            case Opcode.RESPONSE_RELAYED_TRANSPORT:
                if (subOpcode == 0)
                {
                    if (data.Length < 16)
                    {
                        Logger.Error<SyncSocketSession>("RESPONSE_RELAYED_TRANSPORT packet too short");
                        return;
                    }
                    int requestId = BinaryPrimitives.ReadInt32LittleEndian(data.AsSpan(0, 4));
                    long connectionId = BinaryPrimitives.ReadInt64LittleEndian(data.AsSpan(4, 8));
                    int messageLength = BinaryPrimitives.ReadInt32LittleEndian(data.AsSpan(12, 4));
                    if (data.Length != 16 + messageLength)
                    {
                        Logger.Error<SyncSocketSession>($"Invalid RESPONSE_RELAYED_TRANSPORT packet size. Expected {16 + messageLength}, got {data.Length}");
                        return;
                    }
                    byte[] handshakeMessage = data.AsSpan(16, messageLength).ToArray();
                    if (_pendingChannels.TryRemove(requestId, out var pending))
                    {
                        var (channel, tcs) = pending;
                        channel.ConnectionId = connectionId;
                        var plaintext = new byte[1024];
                        var (_, _, transport) = channel.HandshakeState!.ReadMessage(handshakeMessage, plaintext);
                        channel.CompleteHandshake(transport);
                        _channels[connectionId] = channel;
                        tcs.SetResult(channel);
                    }
                    else
                    {
                        Logger.Error<SyncSocketSession>($"No pending channel for requestId {requestId}");
                    }
                }
                else
                {
                    if (data.Length < 4)
                    {
                        Logger.Error<SyncSocketSession>("RESPONSE_RELAYED_TRANSPORT error packet too short");
                        return;
                    }
                    int requestId = BinaryPrimitives.ReadInt32LittleEndian(data.AsSpan(0, 4));
                    if (_pendingChannels.TryRemove(requestId, out var pending))
                    {
                        var (channel, tcs) = pending;
                        channel.Dispose();
                        tcs.SetException(new Exception($"Relayed transport request {requestId} failed with error code {subOpcode}"));
                    }
                }
                return;
            case Opcode.RELAYED_DATA:
                HandleRelayedData(subOpcode, data);
                return;
        }

        var isAuthorized = Authorizable?.IsAuthorized != true || sourceChannel != null;
        if (!isAuthorized)
        {
            Logger.Warning<SyncSocketSession>($"Ignored message due to lack of authorization (opcode: {opcode}, subOpcode: {subOpcode}) because ");
            return;
        }

        switch (opcode)
        {
            case Opcode.STREAM_START:
                {
                    using var stream = new MemoryStream(data);
                    using var reader = new BinaryReader(stream);
                    var id = reader.ReadInt32();
                    var expectedSize = reader.ReadInt32();
                    var op = (Opcode)reader.ReadByte();
                    var subOp = reader.ReadByte();
                    var syncStream = new SyncStream(expectedSize, op, subOp);
                    if (stream.Position < stream.Length)
                        syncStream.Add(data.AsSpan().Slice((int)stream.Position));

                    lock (_syncStreams)
                    {
                        _syncStreams[id] = syncStream;
                    }
                    break;
                }
            case Opcode.STREAM_DATA:
                {
                    using var stream = new MemoryStream(data);
                    using var reader = new BinaryReader(stream);
                    var id = reader.ReadInt32();
                    var expectedOffset = reader.ReadInt32();

                    SyncStream? syncStream;
                    lock (_syncStreams)
                    {
                        if (!_syncStreams.TryGetValue(id, out syncStream) || syncStream == null)
                            throw new Exception("Received data for sync stream that does not exist");
                    }

                    if (expectedOffset != syncStream.BytesReceived)
                        throw new Exception("Expected offset not matching with the amount of received bytes");

                    if (stream.Position < stream.Length)
                        syncStream.Add(data.AsSpan().Slice((int)stream.Position));

                    break;
                }
            case Opcode.STREAM_END:
                {
                    using var stream = new MemoryStream(data);
                    using var reader = new BinaryReader(stream);
                    var id = reader.ReadInt32();
                    var expectedOffset = reader.ReadInt32();

                    SyncStream? syncStream;
                    lock (_syncStreams)
                    {
                        if (!_syncStreams.Remove(id, out syncStream) || syncStream == null)
                            throw new Exception("Received data for sync stream that does not exist");
                    }

                    if (expectedOffset != syncStream.BytesReceived)
                        throw new Exception("Expected offset not matching with the amount of received bytes");

                    if (stream.Position < stream.Length)
                        syncStream.Add(data.AsSpan().Slice((int)stream.Position));

                    if (!syncStream.IsComplete)
                        throw new Exception("After sync stream end, the stream must be complete");

                    HandlePacket(syncStream.Opcode, syncStream.SubOpcode, syncStream.GetBytes(), sourceChannel);
                    break;
                }
            case Opcode.DATA:
                {
                    if (sourceChannel != null)
                        sourceChannel.InvokeDataHandler(opcode, subOpcode, data);
                    else
                        _onData.Invoke(this, opcode, subOpcode, data);
                    break;
                }
            default:
                Logger.Warning<SyncSocketSession>($"Unknown opcode received (opcode = {opcode}, subOpcode = {subOpcode})");
                break;
        }
    }

    private void HandleRelayedData(byte subOpcode, byte[] data)
    {
        if (data.Length < 8)
        {
            Logger.Error<SyncSocketSession>("RELAYED_DATA packet too short");
            return;
        }
        long connectionId = BinaryPrimitives.ReadInt64LittleEndian(data.AsSpan(0, 8));
        if (!_channels.TryGetValue(connectionId, out var channel))
        {
            Logger.Error<SyncSocketSession>($"No channel found for connectionId {connectionId}");
            return;
        }
        if (data.Length == 8)
        {
            _channels.TryRemove(connectionId, out _);
            channel.Dispose();
            Logger.Info<SyncSocketSession>($"Relayed connection {connectionId} closed by peer");
            return;
        }

        var encryptedPayload = data.AsSpan(8);
        var decryptedPayload = new byte[encryptedPayload.Length - 16];
        int plen = channel.Transport!.ReadMessage(encryptedPayload, decryptedPayload);
        if (plen != decryptedPayload.Length)
        {
            Logger.Error<SyncSocketSession>("Failed to decrypt relayed data");
            return;
        }

        HandleData(decryptedPayload, plen, channel);
    }

    public Task SendRelayedDataAsync(long connectionId, Opcode opcode, byte subOpcode, byte[]? data = null, int offset = 0, int count = -1, CancellationToken cancellationToken = default)
    {
        if (!_channels.TryGetValue(connectionId, out var channel))
            throw new Exception($"No channel found for connectionId {connectionId}");
        return SendRelayedDataAsync(channel, opcode, subOpcode, data, offset, count, cancellationToken);
    }

    public async Task SendRelayedDataAsync(Channel channel, Opcode opcode, byte subOpcode, byte[]? data = null, int offset = 0, int count = -1, CancellationToken cancellationToken = default)
    {
        if (count == -1)
            count = data?.Length ?? 0;

        if (count != 0 && data == null)
            throw new Exception("Data must be set if count is not 0");

        const int ENCRYPTION_OVERHEAD = 16;
        const int CONNECTION_ID_SIZE = 8;
        const int HEADER_SIZE = 6;
        const int MAX_DATA_PER_PACKET = MAXIMUM_PACKET_SIZE - HEADER_SIZE - CONNECTION_ID_SIZE - ENCRYPTION_OVERHEAD - 16;

        if (count > MAX_DATA_PER_PACKET && data != null)
        {
            var streamId = Interlocked.Increment(ref _streamIdGenerator);
            int totalSize = count;
            int sendOffset = 0;

            while (sendOffset < totalSize)
            {
                int bytesRemaining = totalSize - sendOffset;
                int bytesToSend = Math.Min(MAX_DATA_PER_PACKET - 8 - 2, bytesRemaining);

                // Prepare stream data
                byte[] streamData;
                Opcode streamOpcode;
                if (sendOffset == 0)
                {
                    streamOpcode = Opcode.STREAM_START;
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
                    streamOpcode = (bytesToSend < bytesRemaining) ? Opcode.STREAM_DATA : Opcode.STREAM_END;
                }

                // Wrap with header
                var fullPacket = new byte[HEADER_SIZE + streamData.Length];
                BinaryPrimitives.WriteInt32LittleEndian(fullPacket.AsSpan(0, 4), streamData.Length + 2);
                fullPacket[4] = (byte)streamOpcode;
                fullPacket[5] = 0;
                Array.Copy(streamData, 0, fullPacket, HEADER_SIZE, streamData.Length);

                await SendRelayedPacketAsync(channel, fullPacket, cancellationToken);
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
            await SendRelayedPacketAsync(channel, packet, cancellationToken);
        }
    }

    private async Task SendRelayedPacketAsync(Channel channel, byte[] packet, CancellationToken cancellationToken)
    {
        var encryptedPayload = new byte[packet.Length + 16];
        int encryptedLength = channel.Transport!.WriteMessage(packet, encryptedPayload);

        var relayedPacket = new byte[8 + encryptedLength];
        BinaryPrimitives.WriteInt64LittleEndian(relayedPacket.AsSpan(0, 8), channel.ConnectionId);
        Array.Copy(encryptedPayload, 0, relayedPacket, 8, encryptedLength);

        await SendAsync(Opcode.RELAYED_DATA, 0, relayedPacket, cancellationToken: cancellationToken);
    }

    private void HandleRequestRelayedTransport(byte[] data)
    {
        if (data.Length < 48)
        {
            Logger.Error<SyncSocketSession>("HandleRequestRelayedTransport: Packet too short");
            return;
        }
        long connectionId = BinaryPrimitives.ReadInt64LittleEndian(data.AsSpan(0, 8));
        int requestId = BinaryPrimitives.ReadInt32LittleEndian(data.AsSpan(8, 4));
        var publicKeyBytes = data.AsSpan(12, 32).ToArray();
        int messageLength = BinaryPrimitives.ReadInt32LittleEndian(data.AsSpan(44, 4));
        if (data.Length != 48 + messageLength)
        {
            Logger.Error<SyncSocketSession>($"HandleRequestRelayedTransport: Invalid packet size. Expected {48 + messageLength}, got {data.Length}");
            return;
        }
        byte[] handshakeMessage = data.AsSpan(48, messageLength).ToArray();
        string publicKey = Convert.ToBase64String(publicKeyBytes);

        // TODO: Placeholder authorization check
        var isAllowedToConnect = publicKey != _localPublicKey;
        if (!isAllowedToConnect)
        {
            var rp = new byte[12];
            BinaryPrimitives.WriteInt64LittleEndian(rp.AsSpan(0, 8), connectionId);
            BinaryPrimitives.WriteInt32LittleEndian(rp.AsSpan(8, 4), requestId);
            _ = Task.Run(async () =>
            {
                try
                {
                    await SendAsync(Opcode.RESPONSE_RELAYED_TRANSPORT, 2, rp);
                }
                catch (Exception e)
                {
                    Logger.Info<SyncSocketSession>("Failed to send relayed transport response", e);
                }
            });
            return;
        }

        var channel = new Channel(this, _localKeyPair, publicKey, false);
        _onNewChannel?.Invoke(this, channel);

        channel.ConnectionId = connectionId;
        _channels[connectionId] = channel;

        var message = new byte[1024];
        var plaintext = new byte[1024];
        channel.HandshakeState!.ReadMessage(handshakeMessage, plaintext);
        var (bytesWritten, _, transport) = channel.HandshakeState!.WriteMessage(null, message);

        var responsePacket = new byte[16 + bytesWritten];
        BinaryPrimitives.WriteInt64LittleEndian(responsePacket.AsSpan(0, 8), connectionId);
        BinaryPrimitives.WriteInt32LittleEndian(responsePacket.AsSpan(8, 4), requestId);
        BinaryPrimitives.WriteInt32LittleEndian(responsePacket.AsSpan(12, 4), bytesWritten);
        message.AsSpan(0, bytesWritten).CopyTo(responsePacket.AsSpan(16));

        _ = Task.Run(async () =>
        {
            try
            {
                await SendAsync(Opcode.RESPONSE_RELAYED_TRANSPORT, 0, responsePacket);
            }
            catch (Exception e)
            {
                Logger.Info<SyncSocketSession>("Failed to send relayed transport response", e);
            }
        });

        channel.CompleteHandshake(transport);
    }

    private ConnectionInfo ParseConnectionInfo(ReadOnlySpan<byte> data)
    {
        using var stream = new MemoryStream(data.ToArray());
        using var reader = new BinaryReader(stream);

        var expectedHandshakeSize = 32 + 16;
        var ipSize = reader.ReadByte();
        var remoteIpBytes = reader.ReadBytes(ipSize);
        var remoteIp = new IPAddress(remoteIpBytes);
        byte[] handshakeMessage = reader.ReadBytes(expectedHandshakeSize);
        byte[] ciphertext = reader.ReadBytes(data.Length - expectedHandshakeSize - ipSize - 1);
        var protocol = new Protocol(HandshakePattern.N, CipherFunction.ChaChaPoly, HashFunction.Blake2b);

        using var handshakeState = protocol.Create(false, s: _localKeyPair.PrivateKey);
        var plaintextBuffer = new byte[0];
        var (_, _, transport) = handshakeState.ReadMessage(handshakeMessage, plaintextBuffer);

        var decryptedData = new byte[ciphertext.Length - 16];
        var decryptedLength = transport.ReadMessage(ciphertext, decryptedData);
        if (decryptedLength != decryptedData.Length)
        {
            throw new Exception("Decryption failed: incomplete data");
        }

        using var infoStream = new MemoryStream(decryptedData);
        using var infoReader = new BinaryReader(infoStream);
        ushort port = infoReader.ReadUInt16();

        byte nameLength = infoReader.ReadByte();
        byte[] nameBytes = infoReader.ReadBytes(nameLength);
        string name = Encoding.UTF8.GetString(nameBytes);

        byte ipv4Count = infoReader.ReadByte();
        List<IPAddress> ipv4Addresses = new List<IPAddress>();
        for (int i = 0; i < ipv4Count; i++)
        {
            byte[] addrBytes = infoReader.ReadBytes(4);
            ipv4Addresses.Add(new IPAddress(addrBytes));
        }

        byte ipv6Count = infoReader.ReadByte();
        List<IPAddress> ipv6Addresses = new List<IPAddress>();
        for (int i = 0; i < ipv6Count; i++)
        {
            byte[] addrBytes = infoReader.ReadBytes(16);
            ipv6Addresses.Add(new IPAddress(addrBytes));
        }

        bool allowLocal = infoReader.ReadByte() != 0;
        bool allowRemoteDirect = infoReader.ReadByte() != 0;
        bool allowRemoteHolePunched = infoReader.ReadByte() != 0;
        bool allowRemoteProxied = infoReader.ReadByte() != 0;

        Logger.Info<SyncSocketSession>(
            $"Received connection info: port={port}, name={name}, " +
            $"remoteIp={remoteIp}, ipv4={string.Join(", ", ipv4Addresses)}, ipv6={string.Join(", ", ipv6Addresses)}, " +
            $"allowLocal={allowLocal}, allowRemoteDirect={allowRemoteDirect}, allowRemoteHolePunched={allowRemoteHolePunched}, allowRemoteProxied={allowRemoteProxied}"
        );

        return new ConnectionInfo(
            port,
            name,
            remoteIp,
            ipv4Addresses,
            ipv6Addresses,
            allowLocal,
            allowRemoteDirect,
            allowRemoteHolePunched,
            allowRemoteProxied
        );
    }

    public void Dispose()
    {
        lock (_syncStreams)
        {
            _syncStreams.Clear();
        }

        foreach (var channel in _channels.Values)
            channel.Dispose();
        _channels.Clear();

        foreach (var pair in _pendingChannels.Values)
            pair.Channel.Dispose();
        _pendingChannels.Clear();

        Stop();
    }

    public const int MAXIMUM_PACKET_SIZE = 65535 - 16;
    public const int MAXIMUM_PACKET_SIZE_ENCRYPTED = MAXIMUM_PACKET_SIZE + 16;
    public const int HEADER_SIZE = 6;
}