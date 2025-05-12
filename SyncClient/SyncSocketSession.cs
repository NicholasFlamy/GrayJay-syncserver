using System.Buffers.Binary;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Net;
using Noise;
using SyncShared;
using System.Text;
using System.Collections.Concurrent;
using System.Buffers;
using System.Diagnostics;
using System.IO.Compression;
using System.Drawing;
using System.Threading;
using System.Buffers.Text;

namespace SyncClient;

public record ConnectionInfo(
    ushort Port,
    string Name,
    IPAddress RemoteIp,
    List<IPAddress> Ipv4Addresses,
    List<IPAddress> Ipv6Addresses,
    bool AllowLocalDirect,
    bool AllowRemoteDirect,
    bool AllowRemoteHolePunched,
    bool AllowRemoteRelayed
);

//TODO: Cancellation token source and cancel on dispose
public class SyncSocketSession : IDisposable
{
    private readonly Socket _socket;
    private readonly SemaphoreSlim _sendSemaphore = new SemaphoreSlim(1);
    private readonly byte[] _buffer = new byte[MAXIMUM_PACKET_SIZE_ENCRYPTED];
    private readonly byte[] _bufferDecrypted = new byte[MAXIMUM_PACKET_SIZE];
    private readonly byte[] _sendBuffer = new byte[MAXIMUM_PACKET_SIZE];
    private readonly byte[] _sendBufferEncrypted = new byte[MAXIMUM_PACKET_SIZE_ENCRYPTED + 4]; //+4 to leave room for size prefix
    private readonly Dictionary<int, SyncStream> _syncStreams = new();
    private readonly Action<SyncSocketSession>? _onClose;
    private readonly Action<SyncSocketSession>? _onHandshakeComplete;
    private readonly Action<SyncSocketSession, ChannelRelayed>? _onNewChannel;
    private readonly Action<SyncSocketSession, ChannelRelayed, bool>? _onChannelEstablished;
    private readonly Func<LinkType, SyncSocketSession, string, string?, uint, bool>? _isHandshakeAllowed;

    private int _streamIdGenerator = 0;
    private Transport? _transport = null;
    public string? RemotePublicKey { get; private set; } = null;
    private bool _started;
    private KeyPair _localKeyPair;
    private readonly string _localPublicKey;
    public string LocalPublicKey => _localPublicKey;
    private readonly Action<SyncSocketSession, Opcode, byte, ReadOnlySpan<byte>>? _onData;
    public string RemoteAddress { get; }
    public int RemoteVersion { get; private set; } = -1;
    private readonly ConcurrentDictionary<long, ChannelRelayed> _channels = new();
    private readonly ConcurrentDictionary<int, (ChannelRelayed Channel, TaskCompletionSource<ChannelRelayed> Tcs)> _pendingChannels = new();
    private readonly ConcurrentDictionary<int, TaskCompletionSource<ConnectionInfo?>> _pendingConnectionInfoRequests = new();
    private readonly ConcurrentDictionary<int, TaskCompletionSource<bool>> _pendingPublishRequests = new();
    private readonly ConcurrentDictionary<int, TaskCompletionSource<bool>> _pendingDeleteRequests = new();
    private readonly ConcurrentDictionary<int, TaskCompletionSource<List<(string Key, DateTime Timestamp)>>> _pendingListKeysRequests = new();
    private readonly ConcurrentDictionary<int, TaskCompletionSource<(byte[] EncryptedBlob, DateTime Timestamp)?>> _pendingGetRecordRequests = new();
    private readonly ConcurrentDictionary<int, TaskCompletionSource<Dictionary<string, (byte[] Data, DateTime Timestamp)>>> _pendingBulkGetRecordRequests = new();
    private readonly ConcurrentDictionary<int, TaskCompletionSource<Dictionary<string, ConnectionInfo>>> _pendingBulkConnectionInfoRequests = new();
    private int _requestIdGenerator = 0;
    public IAuthorizable? Authorizable { get; set; }
    public bool IsAuthorized => Authorizable?.IsAuthorized ?? false;

    public SyncSocketSession(string remoteAddress, KeyPair localKeyPair, Socket socket,
        Action<SyncSocketSession>? onClose = null, Action<SyncSocketSession>? onHandshakeComplete = null,
        Action<SyncSocketSession, Opcode, byte, ReadOnlySpan<byte>>? onData = null, Action<SyncSocketSession, ChannelRelayed>? onNewChannel = null, Func<LinkType, SyncSocketSession, string, string?, uint, bool>? isHandshakeAllowed = null, Action<SyncSocketSession, ChannelRelayed, bool>? onChannelEstablished = null)
    {
        _socket = socket;
        _socket.ReceiveBufferSize = MAXIMUM_PACKET_SIZE_ENCRYPTED;
        _socket.SendBufferSize = MAXIMUM_PACKET_SIZE_ENCRYPTED;

        _onClose = onClose;
        _onHandshakeComplete = onHandshakeComplete;
        _onChannelEstablished = onChannelEstablished;
        _localKeyPair = localKeyPair;
        _onData = onData;
        _onNewChannel = onNewChannel;
        _localPublicKey = Convert.ToBase64String(localKeyPair.PublicKey);
        _isHandshakeAllowed = isHandshakeAllowed;
        RemoteAddress = remoteAddress;
    }

    public async Task StartAsInitiatorAsync(string remotePublicKey, uint appId = 0, string? pairingCode = null, CancellationToken cancellationToken = default)
    {
        _started = true;
        try
        {
            await HandshakeAsInitiatorAsync(remotePublicKey, appId, pairingCode, cancellationToken);
            _onHandshakeComplete?.Invoke(this);
            await ReceiveLoopAsync(cancellationToken);
        }
        catch (Exception e)
        {
            Logger.Error<SyncSocketSession>($"Failed to run as initiator: {e}");
        }
        finally
        {
            Dispose();
        }
    }

    public async Task StartAsResponderAsync(CancellationToken cancellationToken = default)
    {
        _started = true;
        try
        {
            if (await HandshakeAsResponderAsync(cancellationToken))
            {
                _onHandshakeComplete?.Invoke(this);
                await ReceiveLoopAsync(cancellationToken);
            }
        }
        catch (Exception e)
        {
            Logger.Error<SyncSocketSession>($"Failed to run as responder: {e}");
        }
        finally
        {
            Dispose();
        }
    }

    private async Task ReceiveLoopAsync(CancellationToken cancellationToken = default)
    {
        byte[] messageSizeBytes = new byte[4];
        while (_started)
        {
            try
            {
                await ReceiveExactAsync(messageSizeBytes, 0, 4, cancellationToken);
                int messageSize = BinaryPrimitives.ReadInt32LittleEndian(messageSizeBytes.AsSpan(0, 4));
                if (messageSize == 0)
                    throw new Exception("Disconnected.");

                if (Logger.WillLog(LogLevel.Debug))
                    Logger.Debug<SyncSocketSession>($"Read message size {messageSize}");

                if (messageSize > MAXIMUM_PACKET_SIZE_ENCRYPTED)
                    throw new Exception($"Message size ({messageSize}) exceeds maximum allowed size ({MAXIMUM_PACKET_SIZE_ENCRYPTED})");

                await ReceiveExactAsync(_buffer, 0, messageSize, cancellationToken);

                if (Logger.WillLog(LogLevel.Debug))
                    Logger.Debug<SyncSocketSession>($"Read message bytes {messageSize}");

                int plen = Decrypt(_buffer.AsSpan().Slice(0, messageSize), _bufferDecrypted);
                if (Logger.WillLog(LogLevel.Debug))
                    Logger.Debug<SyncSocketSession>($"Decrypted message bytes {plen}");

                HandleData(_bufferDecrypted, plen);
            }
            catch (Exception e)
            {
                Logger.Error<SyncSocketSession>($"Exception while receiving data: {e}");
                Dispose();
                break;
            }
        }
    }

    private async ValueTask HandshakeAsInitiatorAsync(string remotePublicKey, uint appId = 0, string? pairingCode = null, CancellationToken cancellationToken = default)
    {
        await PerformVersionCheckAsync();

        var message = new byte[512];
        var plaintext = new byte[512];
        using (var handshakeState = Constants.Protocol.Create(true, s: _localKeyPair.PrivateKey, rs: remotePublicKey.DecodeBase64()))
        {
            byte[] pairingMessage = Array.Empty<byte>();
            int pairingMessageLength = 0;
            if (pairingCode != null)
            {
                var pairingProtocol = new Protocol(HandshakePattern.N, CipherFunction.ChaChaPoly, HashFunction.Blake2b);
                using var pairingHandshakeState = pairingProtocol.Create(true, rs: remotePublicKey.DecodeBase64());
                byte[] pairingCodeBytes = Encoding.UTF8.GetBytes(pairingCode);
                if (pairingCodeBytes.Length > 32)
                    throw new ArgumentException("Pairing code must not exceed 32 bytes.");

                var pairingMessageBuffer = new byte[512];
                (pairingMessageLength, _, _) = pairingHandshakeState.WriteMessage(pairingCodeBytes, pairingMessageBuffer);
                pairingMessage = pairingMessageBuffer.AsSpan(0, pairingMessageLength).ToArray();
            }

            int offset = 4;
            BinaryPrimitives.WriteUInt32LittleEndian(message.AsSpan(offset, 4), appId);
            offset += 4;
            BinaryPrimitives.WriteInt32LittleEndian(message.AsSpan(offset, 4), pairingMessageLength);
            offset += 4;
            if (pairingMessageLength > 0)
            {
                pairingMessage.CopyTo(message.AsSpan(offset, pairingMessageLength));
                offset += pairingMessageLength;
            }
            var (channelBytesWritten, _, _) = handshakeState.WriteMessage(null, message.AsSpan(offset));
            int totalMessageSize = 4 + 4 + pairingMessageLength + channelBytesWritten;
            BinaryPrimitives.WriteInt32LittleEndian(message.AsSpan(0, 4), totalMessageSize);

            await SendAsync(message, 0, totalMessageSize + 4, cancellationToken: cancellationToken);
            Logger.Info<SyncSocketSession>($"HandshakeAsInitiator: Wrote message size {totalMessageSize} (pairing: {pairingMessageLength}, channel: {channelBytesWritten}, app id: {appId}");

            await ReceiveExactAsync(message, 0, 4);
            var messageSize = BitConverter.ToInt32(message);
            Logger.Info<SyncSocketSession>($"HandshakeAsInitiator: Read message size {messageSize} (app id: {appId})");
            await ReceiveExactAsync(message, 0, messageSize);

            var (_, _, transport) = handshakeState.ReadMessage(message.AsSpan().Slice(0, messageSize), plaintext);
            _transport = transport;
            RemotePublicKey = Convert.ToBase64String(handshakeState.RemoteStaticPublicKey);
        }
    }

    private async ValueTask<bool> HandshakeAsResponderAsync(CancellationToken cancellationToken = default)
    {
        await PerformVersionCheckAsync();

        var message = new byte[512];
        var plaintext = new byte[512];
        using (var handshakeState = Constants.Protocol.Create(false, s: _localKeyPair.PrivateKey))
        {
            await ReceiveExactAsync(message, 0, 4);
            var messageSize = BinaryPrimitives.ReadInt32LittleEndian(message.AsSpan(0, 4));
            Logger.Info<SyncSocketSession>($"HandshakeAsResponder: Read message size {messageSize}");
            await ReceiveExactAsync(message, 0, messageSize);

            int offset = 0;
            uint appId = BinaryPrimitives.ReadUInt32LittleEndian(message.AsSpan(offset, 4));
            offset += 4;

            int pairingMessageLength = BinaryPrimitives.ReadInt32LittleEndian(message.AsSpan(offset, 4));
            if (pairingMessageLength > 128)
                throw new InvalidDataException($"Received (pairing message length: {pairingMessageLength}, app id: {appId}) exceeds maximum allowed size (128).");

            offset += 4;
            string? receivedPairingCode = null;
            if (pairingMessageLength > 0)
            {
                var pairingProtocol = new Protocol(HandshakePattern.N, CipherFunction.ChaChaPoly, HashFunction.Blake2b);
                using var pairingHandshakeState = pairingProtocol.Create(false, s: _localKeyPair.PrivateKey);
                var pairingMessage = message.AsSpan(offset, pairingMessageLength);
                offset += pairingMessageLength;
                var pairingPlaintext = new byte[512];
                var (_, _, _) = pairingHandshakeState.ReadMessage(pairingMessage, pairingPlaintext);
                receivedPairingCode = Encoding.UTF8.GetString(pairingPlaintext, 0, Array.IndexOf(pairingPlaintext, (byte)0, 0, Math.Min(32, pairingPlaintext.Length)));
                Logger.Info<SyncSocketSession>($"HandshakeAsResponder: Received pairing code '{receivedPairingCode}' (app id: {appId})");
            }

            var channelMessage = message.AsSpan(offset, messageSize - offset);
            var (_, _, _) = handshakeState.ReadMessage(channelMessage, plaintext);
            var remotePublicKey = Convert.ToBase64String(handshakeState.RemoteStaticPublicKey);

            var isAllowedToConnect = remotePublicKey != _localPublicKey && (_isHandshakeAllowed?.Invoke(LinkType.Direct, this, remotePublicKey, receivedPairingCode, appId) ?? true);
            if (!isAllowedToConnect)
            {
                Logger.Info<SyncSocketSession>($"HandshakeAsResponder: Handshake is not allowed (app id: {appId}). Closing connection.");
                Dispose();
                return false;
            }

            var (bytesWritten, _, transport) = handshakeState.WriteMessage(null, message.AsSpan(4));
            BinaryPrimitives.WriteInt32LittleEndian(message.AsSpan(0, 4), bytesWritten);
            await SendAsync(message, 0, bytesWritten + 4, cancellationToken: cancellationToken);
            Logger.Info<SyncSocketSession>($"HandshakeAsResponder: Wrote message size {bytesWritten} (app id: {appId})");

            _transport = transport;

            RemotePublicKey = remotePublicKey;
            return true;
        }
    }

    private const int CURRENT_VERSION = 4;
    private static readonly byte[] VERSION_BYTES = BitConverter.GetBytes(CURRENT_VERSION);
    private async ValueTask PerformVersionCheckAsync(CancellationToken cancellationToken = default)
    {
        const int MINIMUM_VERSION = 4;
        await SendAsync(VERSION_BYTES, 0, 4, cancellationToken: cancellationToken);
        byte[] versionBytes = new byte[4];
        await ReceiveExactAsync(versionBytes, 0, 4);
        RemoteVersion = BinaryPrimitives.ReadInt32LittleEndian(versionBytes.AsSpan(0, 4));
        Logger.Info(nameof(SyncSocketSession), $"PerformVersionCheck {RemoteVersion}");
        if (RemoteVersion < MINIMUM_VERSION)
            throw new Exception("Invalid version");
    }

    private int Encrypt(ReadOnlySpan<byte> source, Span<byte> destination)
    {
        int encryptedLength = _transport!.WriteMessage(source, destination);
        if (Logger.WillLog(LogLevel.Debug))
            Logger.Debug<SyncSocketSession>($"Encrypted message bytes (source size: {source.Length}, destination size: {encryptedLength})");
        return encryptedLength;
    }

    private int Decrypt(ReadOnlySpan<byte> source, Span<byte> destination)
    {
        int plen = _transport!.ReadMessage(source, destination);
        if (Logger.WillLog(LogLevel.Debug))
            Logger.Debug<SyncSocketSession>($"Decrypted message bytes (source size: {source.Length}, destination size: {plen})");
        return plen;
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
            int bytesReceived = await _socket.ReceiveAsync(new ArraySegment<byte>(buffer, offset + totalBytesReceived, size - totalBytesReceived), cancellationToken);
            if (bytesReceived == 0)
                throw new Exception("Connection closed");
            if (Logger.WillLog(LogLevel.Debug))
                Logger.Debug<SyncSocketSession>($"Receive duration ({bytesReceived}/{size} bytes): {sw?.ElapsedMilliseconds}ms");
            totalBytesReceived += bytesReceived;
        }

        if (Logger.WillLog(LogLevel.Debug))
            Logger.Debug<SyncSocketSession>($"Received {totalBytesReceived} bytes.");
    }

    private async ValueTask SendAsync(byte[] data, int offset = 0, int count = -1, CancellationToken cancellationToken = default)
    {
        if (count == -1)
            count = data.Length;

        if (Logger.WillLog(LogLevel.Debug))
            Logger.Debug<SyncSocketSession>($"Sending {count} bytes.");

        Stopwatch? sw = null;
        if (Logger.WillLog(LogLevel.Debug))
            sw = new Stopwatch();

        int totalBytesSent = 0;
        while (totalBytesSent < count)
        {
            cancellationToken.ThrowIfCancellationRequested();

            sw?.Restart();
            if (Logger.WillLog(LogLevel.Debug))
                Logger.Debug<SyncSocketSession>($"Sending {count - totalBytesSent} bytes.");

            int bytesSent = await _socket.SendAsync(new ArraySegment<byte>(data, offset + totalBytesSent, count - totalBytesSent));
            if (bytesSent == 0)
                throw new Exception("Failed to send.");
            if (Logger.WillLog(LogLevel.Debug))
                Logger.Debug<SyncSocketSession>($"Send duration ({bytesSent} bytes): {sw?.ElapsedMilliseconds}ms");

            totalBytesSent += bytesSent;
        }
    }

    public int GenerateStreamId() => Interlocked.Increment(ref _streamIdGenerator);
    public async Task SendAsync(Opcode opcode, byte subOpcode, byte[] data, int offset = 0, int size = -1, ContentEncoding contentEncoding = ContentEncoding.Raw, CancellationToken cancellationToken = default) =>
        await SendAsync((byte)opcode, subOpcode, data, offset, size, contentEncoding, cancellationToken);
    public async Task SendAsync(byte opcode, byte subOpcode, byte[] data, int offset = 0, int size = -1, ContentEncoding contentEncoding = ContentEncoding.Raw, CancellationToken cancellationToken = default)
    {
        if (size == -1)
            size = data.Length;

        if (Logger.WillLog(LogLevel.Debug))
            Logger.Debug<SyncSocketSession>($"SendAsync (opcode = {opcode}, subOpcode = {subOpcode}, contentEncoding = {contentEncoding}, size = {size})");

        byte[] processedData = data;
        int processedSize = size;

        if (contentEncoding == ContentEncoding.Gzip)
        {
            var isGzipSupported = opcode == (byte)Opcode.DATA;
            if (isGzipSupported)
            {
                using (var compressedStream = new MemoryStream())
                {
                    using (var gzipStream = new GZipStream(compressedStream, CompressionMode.Compress))
                    {
                        await gzipStream.WriteAsync(data.AsMemory(offset, size), cancellationToken);
                    }
                    processedData = compressedStream.ToArray();
                    processedSize = processedData.Length;
                }
            }
            else
            {
                Logger.Warning<SyncSocketSession>($"Gzip requested but not supported on this (opcode = {opcode}, subOpcode = {subOpcode}), falling back.");
                contentEncoding = ContentEncoding.Raw;
            }
        }

        if (processedSize + HEADER_SIZE > MAXIMUM_PACKET_SIZE)
        {
            var segmentSize = MAXIMUM_PACKET_SIZE - HEADER_SIZE;
            var id = GenerateStreamId();
            var segmentData = Utilities.RentBytes(segmentSize);

            try
            {
                for (var sendOffset = 0; sendOffset < processedSize;)
                {
                    var bytesRemaining = processedSize - sendOffset;
                    int bytesToSend;
                    int segmentPacketSize;

                    StreamOpcode op;
                    if (sendOffset == 0)
                    {
                        op = StreamOpcode.START;
                        bytesToSend = segmentSize - 4 - HEADER_SIZE;
                        segmentPacketSize = bytesToSend + 4 + HEADER_SIZE;
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

                    if (op == StreamOpcode.START)
                    {
                        BinaryPrimitives.WriteInt32LittleEndian(segmentData.AsSpan().Slice(0, 4), id);
                        BinaryPrimitives.WriteInt32LittleEndian(segmentData.AsSpan().Slice(4, 4), processedSize);
                        segmentData[8] = (byte)opcode;
                        segmentData[9] = (byte)subOpcode;
                        segmentData[10] = (byte)contentEncoding;
                        processedData.AsSpan(offset, processedSize).Slice(sendOffset, bytesToSend).CopyTo(segmentData.AsSpan().Slice(4 + HEADER_SIZE));
                    }
                    else
                    {
                        BinaryPrimitives.WriteInt32LittleEndian(segmentData.AsSpan().Slice(0, 4), id);
                        BinaryPrimitives.WriteInt32LittleEndian(segmentData.AsSpan().Slice(4, 4), sendOffset);
                        processedData.AsSpan(offset, processedSize).Slice(sendOffset, bytesToSend).CopyTo(segmentData.AsSpan().Slice(8));
                    }

                    sendOffset += bytesToSend;
                    await SendAsync((byte)Opcode.STREAM, (byte)op, segmentData.AsSpan().Slice(0, segmentPacketSize).ToArray(), contentEncoding: ContentEncoding.Raw, cancellationToken: cancellationToken);
                }
            }
            finally
            {
                Utilities.ReturnBytes(segmentData);
            }
        }
        else
        {
            try
            {
                await _sendSemaphore.WaitAsync();

                BinaryPrimitives.WriteInt32LittleEndian(_sendBuffer.AsSpan(0, 4), processedSize + HEADER_SIZE - 4);
                _sendBuffer[4] = (byte)opcode;
                _sendBuffer[5] = (byte)subOpcode;
                _sendBuffer[6] = (byte)contentEncoding;
                processedData.CopyTo(_sendBuffer.AsSpan().Slice(HEADER_SIZE));

                if (Logger.WillLog(LogLevel.Debug))
                    Logger.Debug<SyncSocketSession>($"Encrypted message bytes {processedSize + HEADER_SIZE}");

                var len = Encrypt(_sendBuffer.AsSpan().Slice(0, processedSize + HEADER_SIZE), _sendBufferEncrypted.AsSpan(4));

                BinaryPrimitives.WriteInt32LittleEndian(_sendBufferEncrypted.AsSpan(0, 4), len);
                await SendAsync(_sendBufferEncrypted, 0, len + 4, cancellationToken: cancellationToken);
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
        if (Logger.WillLog(LogLevel.Debug))
            Logger.Debug<SyncSocketSession>($"SendAsync (opcode = {opcode}, subOpcode = {subOpcode}, size = 0)");

        try
        {
            await _sendSemaphore.WaitAsync(cancellationToken);

            BinaryPrimitives.WriteInt32LittleEndian(_sendBuffer.AsSpan(0, 4), HEADER_SIZE - 4);
            _sendBuffer[4] = (byte)opcode;
            _sendBuffer[5] = (byte)subOpcode;
            _sendBuffer[6] = (byte)ContentEncoding.Raw;

            if (Logger.WillLog(LogLevel.Debug))
                Logger.Debug<SyncSocketSession>($"Encrypted message bytes {HEADER_SIZE}");

            var len = Encrypt(_sendBuffer.AsSpan().Slice(0, HEADER_SIZE), _sendBufferEncrypted.AsSpan(4));
            BinaryPrimitives.WriteInt32LittleEndian(_sendBufferEncrypted.AsSpan(0, 4), len);
            await SendAsync(_sendBufferEncrypted, 0, len + 4, cancellationToken: cancellationToken);

            if (Logger.WillLog(LogLevel.Debug))
                Logger.Debug<SyncSocketSession>($"Wrote message bytes {len}");
        }
        finally
        {
            _sendSemaphore.Release();
        }
    }

    private void HandleData(byte[] data, int length, ChannelRelayed? sourceChannel = null)
    {
        if (length < HEADER_SIZE)
            throw new Exception($"Packet must be at least {HEADER_SIZE} bytes (header size)");

        int size = BitConverter.ToInt32(data, 0);
        if (size != length - 4)
            throw new Exception("Incomplete packet received");

        byte opcode = data[4];
        byte subOpcode = data[5];
        ContentEncoding contentEncoding = (ContentEncoding)data[6];
        ReadOnlySpan<byte> packetData = data.AsSpan(HEADER_SIZE, size - HEADER_SIZE + 4);

        HandlePacket((Opcode)opcode, subOpcode, packetData, contentEncoding, sourceChannel);
    }

    private int GenerateRequestId() => Interlocked.Increment(ref _requestIdGenerator);
    public Task<ConnectionInfo?> RequestConnectionInfoAsync(string publicKey, CancellationToken cancellationToken = default)
    {
        var tcs = new TaskCompletionSource<ConnectionInfo?>();
        var requestId = GenerateRequestId();
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
            byte[] publicKeyBytes = publicKey.DecodeBase64();
            if (publicKeyBytes.Length != 32)
                throw new ArgumentException("Public key must be 32 bytes.");

            var packet = new byte[4 + 32];
            BinaryPrimitives.WriteInt32LittleEndian(packet.AsSpan(0, 4), requestId);
            publicKeyBytes.CopyTo(packet.AsSpan(4, 32));

            _ = SendAsync(Opcode.REQUEST, (byte)RequestOpcode.CONNECTION_INFO, packet, cancellationToken: cancellationToken)
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

    public async Task<Dictionary<string, ConnectionInfo>> RequestBulkConnectionInfoAsync(IEnumerable<string> publicKeys, CancellationToken cancellationToken = default)
    {
        var tcs = new TaskCompletionSource<Dictionary<string, ConnectionInfo>>();
        var requestId = GenerateRequestId();
        _pendingBulkConnectionInfoRequests[requestId] = tcs;

        cancellationToken.Register(() =>
        {
            if (_pendingBulkConnectionInfoRequests.TryRemove(requestId, out var cancelledTcs))
            {
                cancelledTcs.TrySetCanceled();
            }
        });

        try
        {
            var publicKeyList = publicKeys.ToList();
            var numKeys = publicKeyList.Count;
            using var ms = new MemoryStream();
            using var writer = new BinaryWriter(ms);
            writer.Write(requestId); // 4 bytes: Request ID
            writer.Write((byte)numKeys); // 1 byte: Number of public keys
            foreach (var pk in publicKeyList)
            {
                byte[] pkBytes = pk.DecodeBase64();
                if (pkBytes.Length != 32)
                    throw new ArgumentException($"Invalid public key length for {pk}; must be 32 bytes.");
                writer.Write(pkBytes); // 32 bytes per public key
            }
            var packet = ms.ToArray();
            await SendAsync(Opcode.REQUEST, (byte)RequestOpcode.BULK_CONNECTION_INFO, packet, cancellationToken: cancellationToken);
        }
        catch (Exception ex)
        {
            if (_pendingBulkConnectionInfoRequests.TryRemove(requestId, out var errorTcs))
            {
                errorTcs.TrySetException(ex);
            }
            throw;
        }

        return await tcs.Task;
    }

    public Task<ChannelRelayed> StartRelayedChannelAsync(string publicKey, uint appId = 0, string? pairingCode = null, CancellationToken cancellationToken = default)
    {
        var tcs = new TaskCompletionSource<ChannelRelayed>();
        var requestId = GenerateRequestId();
        var channel = new ChannelRelayed(this, _localKeyPair, publicKey, true);
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
            _ = channel.SendRequestTransportAsync(requestId, publicKey, appId, pairingCode, cancellationToken).ContinueWith(t =>
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

    public async Task PublishConnectionInformationAsync(string[] authorizedKeys, int port, bool allowLocalDirect, bool allowRemoteDirect, bool allowRemoteHolePunched, bool allowRemoteRelayed, CancellationToken cancellationToken = default)
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
                        else if (ip.AddressFamily == AddressFamily.InterNetworkV6 && !ip.IsIPv6LinkLocal)
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
            writer.Write((byte)(allowLocalDirect ? 1 : 0));
            writer.Write((byte)(allowRemoteDirect ? 1 : 0));
            writer.Write((byte)(allowRemoteHolePunched ? 1 : 0));
            writer.Write((byte)(allowRemoteRelayed ? 1 : 0));
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
                var publicKeyBytes = authorizedKey.DecodeBase64();
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
                var ciphertextBytesWritten = transport!.WriteMessage(data, ciphertext);
                if (ciphertextBytesWritten != data.Length + 16)
                    throw new InvalidOperationException("Ciphertext size mismatch.");
                writer.Write(data.Length + 16);
                writer.Write(ciphertext, 0, data.Length + 16);
            }
        }

        // Send encrypted data
        await SendAsync(Opcode.NOTIFY, (byte)NotifyOpcode.CONNECTION_INFO, publishBytes, cancellationToken: cancellationToken);
    }

    private void HandleNotify(NotifyOpcode opcode, ReadOnlySpan<byte> data, ChannelRelayed? sourceChannel = null)
    {
        switch (opcode)
        {
            case NotifyOpcode.AUTHORIZED:
            case NotifyOpcode.UNAUTHORIZED:
                if (sourceChannel != null)
                    sourceChannel.InvokeDataHandler(Opcode.NOTIFY, (byte)opcode, data);
                else
                    _onData?.Invoke(this, Opcode.NOTIFY, (byte)opcode, data);
                break;
            case NotifyOpcode.CONNECTION_INFO:
                break;
        }
    }

    private void HandleResponse(ResponseOpcode opcode, ReadOnlySpan<byte> data, ChannelRelayed? sourceChannel = null)
    {
        if (data.Length < 8)
        {
            Logger.Error<SyncSocketSession>("Response packet too short");
            return;
        }

        int requestId = BinaryPrimitives.ReadInt32LittleEndian(data.Slice(0, 4));
        int statusCode = BinaryPrimitives.ReadInt32LittleEndian(data.Slice(4, 4));
        data = data.Slice(8);

        switch (opcode)
        {
            case ResponseOpcode.CONNECTION_INFO:
                {
                    if (_pendingConnectionInfoRequests.TryRemove(requestId, out var tcs))
                    {
                        if (statusCode == 0)
                        {
                            try
                            {
                                var connectionInfo = ParseConnectionInfo(data);
                                tcs.SetResult(connectionInfo);
                            }
                            catch (Exception ex)
                            {
                                tcs.SetException(ex);
                            }
                        }
                        else
                            tcs.SetResult(null);
                    }
                    else
                        Logger.Error<SyncSocketSession>($"No pending request for requestId {requestId}");
                    return;
                }
            case ResponseOpcode.TRANSPORT_RELAYED:
                if (statusCode == 0)
                {
                    if (data.Length < 16)
                    {
                        Logger.Error<SyncSocketSession>("RESPONSE_RELAYED_TRANSPORT packet too short");
                        return;
                    }
                    
                    int remoteVersion = BinaryPrimitives.ReadInt32LittleEndian(data.Slice(0, 4));
                    long connectionId = BinaryPrimitives.ReadInt64LittleEndian(data.Slice(4, 8));
                    int messageLength = BinaryPrimitives.ReadInt32LittleEndian(data.Slice(12, 4));
                    if (data.Length != 16 + messageLength)
                    {
                        Logger.Error<SyncSocketSession>($"Invalid RESPONSE_RELAYED_TRANSPORT packet size. Expected {16 + messageLength}, got {data.Length}");
                        return;
                    }
                    byte[] handshakeMessage = data.Slice(16, messageLength).ToArray();
                    if (_pendingChannels.TryRemove(requestId, out var pending))
                    {
                        var (channel, tcs) = pending;
                        channel.HandleTransportRelayed(remoteVersion, connectionId, handshakeMessage);
                        _channels[connectionId] = channel;
                        tcs.SetResult(channel);
                        _onChannelEstablished?.Invoke(this, channel, false);
                    }
                    else
                        Logger.Error<SyncSocketSession>($"No pending channel for requestId {requestId}");
                }
                else
                {
                    if (_pendingChannels.TryRemove(requestId, out var pending))
                    {
                        var (channel, tcs) = pending;
                        channel.Dispose();
                        tcs.SetException(new Exception($"Relayed transport request {requestId} failed with error code {(TransportResponseCode)statusCode}"));
                    }
                }
                return;
            case ResponseOpcode.PUBLISH_RECORD:
                {
                    Logger.Info<SyncSocketSession>($"Received publishing record response requestId = {requestId}.");

                    if (_pendingPublishRequests.TryRemove(requestId, out var tcs))
                    {
                        if (statusCode == 0)
                            tcs.SetResult(true);
                        else
                            tcs.SetResult(false);
                    }
                    else
                    {
                        Logger.Error<SyncSocketSession>($"No pending publish request for requestId {requestId}");
                    }
                    return;
                }

            case ResponseOpcode.DELETE_RECORD:
                {
                    if (_pendingDeleteRequests.TryRemove(requestId, out var tcs))
                    {
                        if (statusCode == 0)
                            tcs.SetResult(true);
                        else
                            tcs.SetResult(false);
                    }
                    else
                    {
                        Logger.Error<SyncSocketSession>($"No pending delete request for requestId {requestId}");
                    }
                    return;
                }
            case ResponseOpcode.BULK_DELETE_RECORD:
                {
                    if (_pendingDeleteRequests.TryRemove(requestId, out var tcs))
                    {
                        if (statusCode == 0)
                            tcs.SetResult(true);
                        else
                            tcs.SetResult(false);
                    }
                    else
                    {
                        Logger.Error<SyncSocketSession>($"No pending bulk delete request for requestId {requestId}");
                    }
                    return;
                }
            case ResponseOpcode.LIST_RECORD_KEYS:
                {
                    if (_pendingListKeysRequests.TryRemove(requestId, out var tcs))
                    {
                        if (statusCode == 0)
                        {
                            try
                            {
                                var keys = new List<(string Key, DateTime Timestamp)>();
                                if (data.Length < 4)
                                    throw new Exception("Packet too short for key count");
                                int keyCount = BinaryPrimitives.ReadInt32LittleEndian(data.Slice(0, 4));
                                data = data.Slice(4);
                                for (int i = 0; i < keyCount; i++)
                                {
                                    if (data.Length < 1)
                                    {
                                        throw new Exception("Packet too short for key length");
                                    }
                                    byte keyLength = data[0];
                                    data = data.Slice(1);
                                    if (data.Length < keyLength)
                                    {
                                        throw new Exception("Packet too short for key data");
                                    }
                                    string key = Encoding.UTF8.GetString(data.Slice(0, keyLength));
                                    data = data.Slice(keyLength);
                                    if (data.Length < 8)
                                    {
                                        throw new Exception("Packet too short for timestamp");
                                    }
                                    long timestampBinary = BinaryPrimitives.ReadInt64LittleEndian(data.Slice(0, 8));
                                    data = data.Slice(8);
                                    DateTime timestamp = DateTime.FromBinary(timestampBinary);
                                    keys.Add((key, timestamp));
                                }
                                tcs.SetResult(keys);
                            }
                            catch (Exception ex)
                            {
                                tcs.SetException(ex);
                            }
                        }
                        else
                        {
                            tcs.SetException(new Exception($"Error listing keys: status code {statusCode}"));
                        }
                    }
                    else
                    {
                        Logger.Error<SyncSocketSession>($"No pending list keys request for requestId {requestId}");
                    }
                    return;
                }
            case ResponseOpcode.BULK_GET_RECORD:
                {
                    if (_pendingBulkGetRecordRequests.TryRemove(requestId, out var getTcs))
                    {
                        if (statusCode == 0)
                        {
                            try
                            {
                                int offset = 0;
                                byte recordCount = data[offset];
                                offset += 1;
                                var records = new Dictionary<string, (byte[], DateTime)>(recordCount);
                                for (int i = 0; i < recordCount; i++)
                                {
                                    byte[] publisherBytes = data.Slice(offset, 32).ToArray();
                                    string publisher = Convert.ToBase64String(publisherBytes);
                                    offset += 32;

                                    int blobLength = BinaryPrimitives.ReadInt32LittleEndian(data.Slice(offset, 4));
                                    offset += 4;
                                    byte[] encryptedBlob = data.Slice(offset, blobLength).ToArray();
                                    offset += blobLength;

                                    long timestampBinary = BinaryPrimitives.ReadInt64LittleEndian(data.Slice(offset, 8));
                                    DateTime timestamp = DateTime.FromBinary(timestampBinary);
                                    offset += 8;

                                    // Decrypt the blob
                                    var protocol = new Protocol(HandshakePattern.N, CipherFunction.ChaChaPoly, HashFunction.Blake2b);
                                    using var handshakeState = protocol.Create(false, s: _localKeyPair.PrivateKey);
                                    var handshakeMessage = new byte[48];
                                    encryptedBlob.AsSpan(0, 48).CopyTo(handshakeMessage);
                                    var (_, _, transport) = handshakeState.ReadMessage(handshakeMessage, new byte[0]);

                                    // First pass: Calculate total decrypted size
                                    int blobOffset = 48;
                                    int totalDecryptedSize = 0;
                                    int chunkCount = 0;
                                    while (blobOffset + 4 <= encryptedBlob.Length)
                                    {
                                        int chunkLength = BinaryPrimitives.ReadInt32LittleEndian(encryptedBlob.AsSpan(blobOffset, 4));
                                        if (chunkLength <= 16 || blobOffset + 4 + chunkLength > encryptedBlob.Length)
                                        {
                                            throw new InvalidDataException("Invalid encrypted chunk length");
                                        }
                                        totalDecryptedSize += chunkLength - 16; // Subtract 16-byte tag
                                        blobOffset += 4 + chunkLength;
                                        chunkCount++;
                                    }

                                    if (chunkCount == 0)
                                    {
                                        throw new Exception("No valid chunks decrypted");
                                    }

                                    // Allocate a single buffer for decrypted data
                                    var dataResult = new byte[totalDecryptedSize];
                                    int dataOffset = 0;
                                    blobOffset = 48;

                                    // Second pass: Decrypt directly into the buffer
                                    for (int j = 0; j < chunkCount; j++)
                                    {
                                        int chunkLength = BinaryPrimitives.ReadInt32LittleEndian(encryptedBlob.AsSpan(blobOffset, 4));
                                        blobOffset += 4;
                                        var encryptedChunk = encryptedBlob.AsSpan(blobOffset, chunkLength);
                                        var decryptedSpan = dataResult.AsSpan(dataOffset, chunkLength - 16);
                                        int decryptedLength = transport!.ReadMessage(encryptedChunk, decryptedSpan);
                                        dataOffset += decryptedLength;
                                        blobOffset += chunkLength;
                                    }

                                    records[publisher] = (dataResult, timestamp);
                                }
                                getTcs.SetResult(records);
                            }
                            catch (Exception ex)
                            {
                                Logger.Error<SyncSocketSession>("Error processing RESPONSE_BULK_GET_RECORD: {Exception}", ex);
                                getTcs.SetException(ex);
                            }
                        }
                        else
                        {
                            getTcs.SetException(new Exception($"Error getting bulk records: statusCode {statusCode}"));
                        }
                    }
                    return;
                }
            case ResponseOpcode.GET_RECORD:
                {
                    if (_pendingGetRecordRequests.TryRemove(requestId, out var tcs))
                    {
                        if (statusCode == 0)
                        {
                            try
                            {
                                int offset = 0;
                                int blobLength = BinaryPrimitives.ReadInt32LittleEndian(data.Slice(offset, 4));
                                offset += 4;
                                var encryptedBlob = data.Slice(offset, blobLength);
                                offset += blobLength;
                                long timestampBinary = BinaryPrimitives.ReadInt64LittleEndian(data.Slice(offset, 8));
                                DateTime timestamp = DateTime.FromBinary(timestampBinary);

                                // Initialize Noise protocol for decryption
                                var protocol = new Protocol(HandshakePattern.N, CipherFunction.ChaChaPoly, HashFunction.Blake2b);
                                using var handshakeState = protocol.Create(false, s: _localKeyPair.PrivateKey);
                                var handshakeMessage = new byte[48];
                                encryptedBlob.Slice(0, 48).CopyTo(handshakeMessage);
                                var (_, _, transport) = handshakeState.ReadMessage(handshakeMessage, new byte[0]);

                                // First pass: Calculate total decrypted size
                                int blobOffset = 48;
                                int totalDecryptedSize = 0;
                                int chunkCount = 0;
                                while (blobOffset + 4 <= encryptedBlob.Length)
                                {
                                    int chunkLength = BinaryPrimitives.ReadInt32LittleEndian(encryptedBlob.Slice(blobOffset, 4));
                                    if (chunkLength <= 16 || blobOffset + 4 + chunkLength > encryptedBlob.Length)
                                    {
                                        throw new InvalidDataException("Invalid encrypted chunk length");
                                    }
                                    totalDecryptedSize += chunkLength - 16; // Subtract 16-byte tag
                                    blobOffset += 4 + chunkLength;
                                    chunkCount++;
                                }

                                if (chunkCount == 0)
                                {
                                    throw new Exception("No valid chunks decrypted");
                                }

                                // Allocate a single buffer for all decrypted data
                                var dataResult = new byte[totalDecryptedSize];
                                int dataOffset = 0;
                                blobOffset = 48;

                                // Second pass: Decrypt directly into the buffer
                                for (int i = 0; i < chunkCount; i++)
                                {
                                    int chunkLength = BinaryPrimitives.ReadInt32LittleEndian(encryptedBlob.Slice(blobOffset, 4));
                                    blobOffset += 4;
                                    var encryptedChunk = encryptedBlob.Slice(blobOffset, chunkLength);
                                    var decryptedSpan = dataResult.AsSpan(dataOffset, chunkLength - 16);
                                    int decryptedLength = transport!.ReadMessage(encryptedChunk, decryptedSpan);
                                    dataOffset += decryptedLength;
                                    blobOffset += chunkLength;
                                }

                                tcs.SetResult((dataResult, timestamp));
                            }
                            catch (Exception ex)
                            {
                                Logger.Error<SyncSocketSession>("Error processing RESPONSE_GET_RECORD: {Exception}", ex);
                                tcs.SetException(ex);
                            }
                        }
                        else if (statusCode == 2)
                        {
                            tcs.SetResult(null); // Record not found
                        }
                        else
                        {
                            tcs.SetException(new Exception($"Error getting record: statusCode {statusCode}"));
                        }
                    }
                    return;
                }
            case ResponseOpcode.BULK_PUBLISH_RECORD:
                {
                    if (_pendingPublishRequests.TryRemove(requestId, out var publishTcs))
                    {
                        publishTcs.SetResult(statusCode == 0);
                    }
                    else
                    {
                        Logger.Error<SyncSocketSession>($"No pending bulk publish request for requestId {requestId}");
                    }
                    return;
                }
            case ResponseOpcode.BULK_CONNECTION_INFO:
                {
                    if (_pendingBulkConnectionInfoRequests.TryRemove(requestId, out var tcs))
                    {
                        try
                        {
                            var result = new Dictionary<string, ConnectionInfo>();
                            int offset = 0;
                            byte numResponses = data[offset];
                            offset += 1;
                            for (int i = 0; i < numResponses; i++)
                            {
                                if (offset + 32 + 1 > data.Length)
                                {
                                    throw new Exception("Invalid RESPONSE_BULK_CONNECTION_INFO packet: insufficient data");
                                }
                                string publicKey = Convert.ToBase64String(data.Slice(offset, 32));
                                offset += 32;
                                byte status = data[offset];
                                offset += 1;
                                if (status == 0) // Success
                                {
                                    if (offset + 4 > data.Length)
                                    {
                                        throw new Exception("Invalid RESPONSE_BULK_CONNECTION_INFO packet: missing length");
                                    }
                                    int infoSize = BinaryPrimitives.ReadInt32LittleEndian(data.Slice(offset, 4));
                                    offset += 4;
                                    if (offset + infoSize > data.Length)
                                    {
                                        throw new Exception("Invalid RESPONSE_BULK_CONNECTION_INFO packet: data truncated");
                                    }
                                    var connectionInfo = ParseConnectionInfo(data.Slice(offset, infoSize));
                                    result[publicKey] = connectionInfo;
                                    offset += infoSize;
                                }
                            }
                            tcs.SetResult(result);
                        }
                        catch (Exception ex)
                        {
                            tcs.SetException(ex);
                        }
                    }
                    else
                    {
                        Logger.Error<SyncSocketSession>($"No pending bulk request for requestId {requestId}");
                    }
                    return;
                }
        }
    }

    private void HandleRequest(RequestOpcode opcode, ReadOnlySpan<byte> data, ChannelRelayed? sourceChannel = null)
    {
        switch (opcode)
        {
            case RequestOpcode.TRANSPORT_RELAYED:
                Logger.Info<SyncSocketSession>("Received request for a relayed transport");
                HandleRequestTransportRelayed(data);
                break;
        }
    }

    private void HandleStream(StreamOpcode opcode, ReadOnlySpan<byte> data, ChannelRelayed? sourceChannel = null)
    {
        switch (opcode)
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
                    ContentEncoding contentEncoding = (ContentEncoding)span[0];
                    span = span.Slice(1);
                    var syncStream = new SyncStream(expectedSize, (Opcode)op, subOp, contentEncoding);
                    if (span.Length > 0)
                        syncStream.Add(span);
                    lock (_syncStreams)
                    {
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

                    SyncStream? syncStream = null;
                    try
                    {
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

                        HandlePacket(syncStream.Opcode, syncStream.SubOpcode, syncStream.GetBytes(), syncStream.ContentEncoding, sourceChannel);
                    }
                    finally
                    {
                        syncStream?.Dispose();
                    }
                    break;
                }
        }
    }

    private void HandleRelay(RelayOpcode opcode, ReadOnlySpan<byte> data, ChannelRelayed? sourceChannel = null)
    {
        switch (opcode)
        {
            case RelayOpcode.RELAYED_DATA:
                HandleRelayedData(data);
                break;
            case RelayOpcode.RELAYED_ERROR:
                HandleRelayedError(data);
                break;
            case RelayOpcode.RELAY_ERROR:
                HandleRelayError(data);
                break;
        }
    }

    private void HandlePacket(Opcode opcode, byte subOpcode, ReadOnlySpan<byte> data, ContentEncoding contentEncoding, ChannelRelayed? sourceChannel = null)
    {
        if (Logger.WillLog(LogLevel.Debug))
            Logger.Debug<SyncSocketSession>($"HandlePacket (opcode = {opcode}, subOpcode = {subOpcode}, data.length = {data.Length}, contentEncoding = {contentEncoding}, sourceChannel.ConnectionId = {sourceChannel?.ConnectionId})");

        if (contentEncoding == ContentEncoding.Gzip)
        {
            var isGzipSupported = opcode == Opcode.DATA;
            if (!isGzipSupported)
                throw new Exception($"Failed to handle packet, gzip is not supported for this opcode (opcode = {opcode}, subOpcode = {subOpcode}, data.length = {data.Length}).");

            using (var compressedStream = new MemoryStream(data.ToArray()))
            using (var decompressedStream = new MemoryStream())
            {
                using (var gzipStream = new GZipStream(compressedStream, CompressionMode.Decompress))
                {
                    gzipStream.CopyTo(decompressedStream);
                }
                data = decompressedStream.ToArray();
            }
        }

        switch (opcode)
        {
            case Opcode.PING:
                Task.Run(async () =>
                {
                    try
                    {
                        if (sourceChannel != null)
                        {
                            await sourceChannel.SendAsync(Opcode.PONG, 0);
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
            case Opcode.RESPONSE:
                HandleResponse((ResponseOpcode)subOpcode, data, sourceChannel);
                return;
            case Opcode.REQUEST:
                HandleRequest((RequestOpcode)subOpcode, data, sourceChannel);
                return;
            case Opcode.NOTIFY:
                HandleNotify((NotifyOpcode)subOpcode, data, sourceChannel);
                return;
            case Opcode.RELAY:
                HandleRelay((RelayOpcode)subOpcode, data, sourceChannel);
                return;
        }

        var isAuthorized = sourceChannel != null ? sourceChannel.IsAuthorized : IsAuthorized;
        if (!isAuthorized)
        {
            Logger.Warning<SyncSocketSession>($"Ignored message due to lack of authorization (opcode: {opcode}, subOpcode: {subOpcode}) because ");
            return;
        }

        switch (opcode)
        {
            case Opcode.STREAM:
                HandleStream((StreamOpcode)subOpcode, data, sourceChannel);
                break;
            case Opcode.DATA:
                {
                    if (sourceChannel != null)
                        sourceChannel.InvokeDataHandler(opcode, subOpcode, data);
                    else
                        _onData?.Invoke(this, opcode, subOpcode, data);
                    break;
                }
            default:
                Logger.Warning<SyncSocketSession>($"Unknown opcode received (opcode = {opcode}, subOpcode = {subOpcode})");
                break;
        }
    }

    private void HandleRelayedData(ReadOnlySpan<byte> data)
    {
        if (data.Length < 8)
        {
            Logger.Error<SyncSocketSession>("RELAYED_DATA packet too short.");
            return;
        }
        long connectionId = BinaryPrimitives.ReadInt64LittleEndian(data.Slice(0, 8));
        if (!_channels.TryGetValue(connectionId, out var channel))
        {
            Logger.Error<SyncSocketSession>($"No channel found for connectionId {connectionId}.");
            //TODO: Maybe have a generic error to notify the other side the connection id doesn't exist?
            return;
        }

        var encryptedPayload = data.Slice(8);
        var (decryptedPayload, length) = channel.Decrypt(encryptedPayload);
        try
        {
            HandleData(decryptedPayload, length, channel);
        }
        catch (Exception e)
        {
            Logger.Error<SyncSocketSession>("Exception while handling relayed data.", e);

            if (channel != null)
            {
                Task.Run(async () =>
                {
                    try
                    {
                        await channel.SendErrorAsync(RelayErrorCode.ConnectionClosed);
                    }
                    catch (Exception ex)
                    {
                        Logger.Error<SyncSocketSession>("Exception while sending relayed error.", ex);
                    }
                    finally
                    {
                        channel.Dispose();
                    }
                });
            }
            _channels.TryRemove(connectionId, out _);
        }
    }

    private void HandleRelayedError(ReadOnlySpan<byte> data)
    {
        if (data.Length < 8)
        {
            Logger.Error<SyncSocketSession>("RELAYED_ERROR packet too short.");
            return;
        }

        long connectionId = BinaryPrimitives.ReadInt64LittleEndian(data.Slice(0, 8));
        if (!_channels.TryGetValue(connectionId, out var channel) || channel == null)
        {
            Logger.Error<SyncSocketSession>($"No channel found for connectionId {connectionId}.");
            Task.Run(async () =>
            {
                try
                {
                    await SendRelayError(connectionId, RelayErrorCode.NotFound);
                }
                catch (Exception ex)
                {
                    Logger.Error<SyncSocketSession>("Exception while sending relay error.", ex);
                }
            });
            return;
        }

        var encryptedPayload = data.Slice(8);
        try
        {
            var (decryptedPayload, length) = channel.Decrypt(encryptedPayload);
            var errorCode = (RelayErrorCode)BinaryPrimitives.ReadInt32LittleEndian(decryptedPayload.AsSpan(0, length));
            Logger.Error<SyncSocketSession>($"Received relayed error (errorCode = {errorCode}) on connection id {connectionId}, closing connection.");
        }
        catch (Exception e)
        {
            Logger.Error<SyncSocketSession>("Exception while handling relayed error.", e);
        }
        finally
        {
            channel.Dispose();
            _channels.TryRemove(connectionId, out _);
        }
    }

    public async Task SendRelayError(long connectionId, RelayErrorCode errorCode, CancellationToken cancellationToken = default)
    {
        Span<byte> errorPacket = stackalloc byte[12];
        BinaryPrimitives.WriteInt64LittleEndian(errorPacket.Slice(0, 8), connectionId);
        BinaryPrimitives.WriteInt32LittleEndian(errorPacket.Slice(8, 4), (int)errorCode);
        await SendAsync(Opcode.RELAY, (byte)RelayOpcode.RELAY_ERROR, errorPacket.ToArray(), cancellationToken: cancellationToken);
    }

    private void HandleRelayError(ReadOnlySpan<byte> data)
    {
        if (data.Length < 12)
        {
            Logger.Error<SyncSocketSession>("RELAY_ERROR packet too short.");
            return;
        }

        long connectionId = BinaryPrimitives.ReadInt64LittleEndian(data.Slice(0, 8));
        RelayErrorCode errorCode = (RelayErrorCode)BinaryPrimitives.ReadInt32LittleEndian(data.Slice(8, 4));
        if (!_channels.TryGetValue(connectionId, out var channel) || channel == null)
        {
            Logger.Error<SyncSocketSession>($"Received error code {errorCode} for non existant channel with connectionId {connectionId}.");
            return;
        }

        Logger.Info<SyncSocketSession>($"Received relay error (errorCode = {errorCode}) on connection id {connectionId}, closing connection.");
        channel.Dispose();
        _channels.TryRemove(connectionId, out _);

        var requestId = -1;
        foreach (var pendingChannelPair in _pendingChannels)
        {
            if (pendingChannelPair.Value.Channel == channel)
            {
                requestId = pendingChannelPair.Key;
                break;
            }
        }
        if (_pendingChannels.TryRemove(requestId, out var task))
            task.Tcs.TrySetCanceled();
    }

    private void HandleRequestTransportRelayed(ReadOnlySpan<byte> data)
    {
        if (data.Length < 52)
        {
            Logger.Error<SyncSocketSession>("HandleRequestRelayedTransport: Packet too short");
            return;
        }

        int offset = 0;
        int remoteVersion = BinaryPrimitives.ReadInt32LittleEndian(data.Slice(offset, 4));
        offset += 4;
        long connectionId = BinaryPrimitives.ReadInt64LittleEndian(data.Slice(offset, 8));
        offset += 8;
        int requestId = BinaryPrimitives.ReadInt32LittleEndian(data.Slice(offset, 4));
        offset += 4;
        uint appId = BinaryPrimitives.ReadUInt32LittleEndian(data.Slice(offset, 4));
        offset += 4;
        var publicKeyBytes = data.Slice(offset, 32).ToArray();
        offset += 32;
        int pairingMessageLength = BinaryPrimitives.ReadInt32LittleEndian(data.Slice(offset, 4));
        offset += 4;
        if (pairingMessageLength > 128)
            throw new InvalidDataException($"Received (pairing message length: {pairingMessageLength}, app id: {appId}) exceeds maximum allowed size (128).");

        byte[] pairingMessage = Array.Empty<byte>();
        if (pairingMessageLength > 0)
        {
            if (data.Length < offset + pairingMessageLength + 4)
            {
                Logger.Error<SyncSocketSession>($"HandleRequestRelayedTransport: Packet too short for pairing message (app id: {appId})");
                return;
            }
            pairingMessage = data.Slice(offset, pairingMessageLength).ToArray();
            offset += pairingMessageLength;
        }

        int channelMessageLength = BinaryPrimitives.ReadInt32LittleEndian(data.Slice(offset, 4));
        if (data.Length != offset + 4 + channelMessageLength)
        {
            Logger.Error<SyncSocketSession>($"HandleRequestRelayedTransport: Invalid packet size. Expected {offset + 4 + channelMessageLength}, got {data.Length}");
            return;
        }
        byte[] channelHandshakeMessage = data.Slice(offset + 4, channelMessageLength).ToArray();
        string publicKey = Convert.ToBase64String(publicKeyBytes);

        string? pairingCode = null;
        if (pairingMessageLength > 0)
        {
            var pairingProtocol = new Protocol(HandshakePattern.N, CipherFunction.ChaChaPoly, HashFunction.Blake2b);
            using var pairingHandshakeState = pairingProtocol.Create(false, s: _localKeyPair.PrivateKey);
            var plaintextBuffer = new byte[1024];
            var (_, _, _) = pairingHandshakeState.ReadMessage(pairingMessage, plaintextBuffer);
            pairingCode = Encoding.UTF8.GetString(plaintextBuffer, 0, Array.IndexOf(plaintextBuffer, (byte)0, 0, Math.Min(32, plaintextBuffer.Length)));
        }

        var isAllowedToConnect = publicKey != _localPublicKey && (_isHandshakeAllowed?.Invoke(LinkType.Relayed, this, publicKey, pairingCode, appId) ?? true);
        if (!isAllowedToConnect)
        {
            var rp = new byte[16];
            BinaryPrimitives.WriteInt32LittleEndian(rp.AsSpan(0, 4), (int)2);
            BinaryPrimitives.WriteInt64LittleEndian(rp.AsSpan(4, 8), connectionId);
            BinaryPrimitives.WriteInt32LittleEndian(rp.AsSpan(12, 4), requestId);
            _ = Task.Run(async () =>
            {
                try
                {
                    await SendAsync(Opcode.RESPONSE, (byte)ResponseOpcode.TRANSPORT, rp);
                }
                catch (Exception e)
                {
                    Logger.Error<SyncSocketSession>("Failed to send relayed transport response", e);
                }
            });
            return;
        }

        var channel = new ChannelRelayed(this, _localKeyPair, publicKey, false);
        channel.ConnectionId = connectionId;
        _onNewChannel?.Invoke(this, channel);
        _channels[connectionId] = channel;

        _ = Task.Run(async () =>
        {
            try
            {
                await channel.SendResponseTransportAsync(remoteVersion, requestId, channelHandshakeMessage);
                _onChannelEstablished?.Invoke(this, channel, true);
            }
            catch (Exception e)
            {
                Logger.Error<SyncSocketSession>("Failed to send relayed transport response", e);
            }
        });
    }

    private ConnectionInfo ParseConnectionInfo(ReadOnlySpan<byte> data)
    {
        byte ipSize = data[0];
        ReadOnlySpan<byte> remoteIpBytes = data.Slice(1, ipSize);
        IPAddress remoteIp = new IPAddress(remoteIpBytes);

        int handshakeStart = 1 + ipSize;
        ReadOnlySpan<byte> handshakeMessageSpan = data.Slice(handshakeStart, 48);
        byte[] handshakeMessage = handshakeMessageSpan.ToArray();

        int ciphertextStart = handshakeStart + 48;
        ReadOnlySpan<byte> ciphertextSpan = data.Slice(ciphertextStart);
        byte[] ciphertext = ciphertextSpan.ToArray();

        var protocol = new Protocol(HandshakePattern.N, CipherFunction.ChaChaPoly, HashFunction.Blake2b);
        using var handshakeState = protocol.Create(false, s: _localKeyPair.PrivateKey);
        var plaintextBuffer = new byte[0];
        var (_, _, transport) = handshakeState.ReadMessage(handshakeMessage, plaintextBuffer);

        var decryptedData = new byte[ciphertext.Length - 16];
        var decryptedLength = transport!.ReadMessage(ciphertext, decryptedData);
        if (decryptedLength != decryptedData.Length)
        {
            throw new Exception("Decryption failed: incomplete data");
        }

        ReadOnlySpan<byte> infoSpan = decryptedData;

        ushort port = BinaryPrimitives.ReadUInt16LittleEndian(infoSpan);
        infoSpan = infoSpan.Slice(2);

        byte nameLength = infoSpan[0];
        infoSpan = infoSpan.Slice(1);

        ReadOnlySpan<byte> nameBytes = infoSpan.Slice(0, nameLength);
        string name = Encoding.UTF8.GetString(nameBytes);
        infoSpan = infoSpan.Slice(nameLength);

        byte ipv4Count = infoSpan[0];
        infoSpan = infoSpan.Slice(1);

        List<IPAddress> ipv4Addresses = new List<IPAddress>();
        for (int i = 0; i < ipv4Count; i++)
        {
            ReadOnlySpan<byte> addrBytes = infoSpan.Slice(0, 4);
            ipv4Addresses.Add(new IPAddress(addrBytes));
            infoSpan = infoSpan.Slice(4);
        }

        byte ipv6Count = infoSpan[0];
        infoSpan = infoSpan.Slice(1);

        List<IPAddress> ipv6Addresses = new List<IPAddress>();
        for (int i = 0; i < ipv6Count; i++)
        {
            ReadOnlySpan<byte> addrBytes = infoSpan.Slice(0, 16);
            ipv6Addresses.Add(new IPAddress(addrBytes));
            infoSpan = infoSpan.Slice(16);
        }

        bool allowLocalDirect = infoSpan[0] != 0;
        infoSpan = infoSpan.Slice(1);
        bool allowRemoteDirect = infoSpan[0] != 0;
        infoSpan = infoSpan.Slice(1);
        bool allowRemoteHolePunched = infoSpan[0] != 0;
        infoSpan = infoSpan.Slice(1);
        bool allowRemoteRelayed = infoSpan[0] != 0;

        return new ConnectionInfo(
            port,
            name,
            remoteIp,
            ipv4Addresses,
            ipv6Addresses,
            allowLocalDirect,
            allowRemoteDirect,
            allowRemoteHolePunched,
            allowRemoteRelayed
        );
    }

    //TODO: Not return bool?
    public async Task<bool> PublishRecordsAsync(IEnumerable<string> consumerPublicKeys, string key, byte[] data, ContentEncoding contentEncoding = ContentEncoding.Raw, CancellationToken cancellationToken = default)
    {
        var keyBytes = Encoding.UTF8.GetBytes(key);
        if (string.IsNullOrEmpty(key) || keyBytes.Length > 32)
            throw new ArgumentException("Key must be non-empty and at most 32 bytes.", nameof(key));

        var consumerList = consumerPublicKeys.ToList();
        if (consumerList.Count == 0)
            throw new ArgumentException("At least one consumer is required.");

        var requestId = GenerateRequestId();
        var tcs = new TaskCompletionSource<bool>();
        _pendingPublishRequests[requestId] = tcs;

        cancellationToken.Register(() =>
        {
            if (_pendingPublishRequests.TryRemove(requestId, out var cancelledTcs))
                cancelledTcs.TrySetCanceled();
        });

        const int MaxPlaintextSize = 65535;
        const int HandshakeSize = 48;
        const int LengthSize = 4;
        const int TagSize = 16;

        try
        {
            // Precalculate blob size (same for all consumers)
            int chunkCount = (data.Length + MaxPlaintextSize - 1) / MaxPlaintextSize;
            int blobSize = HandshakeSize;
            for (int i = 0; i < chunkCount; i++)
            {
                int chunkSize = Math.Min(MaxPlaintextSize, data.Length - i * MaxPlaintextSize);
                blobSize += LengthSize + (chunkSize + TagSize);
            }

            // Calculate total packet size
            int totalPacketSize = 4 + 1 + keyBytes.Length + 1 + consumerList.Count * (32 + 4 + blobSize);
            var packet = new byte[totalPacketSize];
            int offset = 0;

            // Write packet header
            BinaryPrimitives.WriteInt32LittleEndian(packet.AsSpan(offset, 4), requestId);
            offset += 4;
            packet[offset] = (byte)keyBytes.Length;
            offset += 1;
            keyBytes.CopyTo(packet.AsSpan(offset, keyBytes.Length));
            offset += keyBytes.Length;
            packet[offset] = (byte)consumerList.Count;
            offset += 1;

            // Buffer for encrypted chunks (reused across consumers)
            var encryptedChunkBuffer = ArrayPool<byte>.Shared.Rent(MaxPlaintextSize + TagSize);

            foreach (var consumerPublicKey in consumerList)
            {
                byte[] consumerPublicKeyBytes = consumerPublicKey.DecodeBase64();
                if (consumerPublicKeyBytes.Length != 32)
                    throw new ArgumentException($"Consumer public key must be 32 bytes: {consumerPublicKey}");

                var protocol = new Protocol(HandshakePattern.N, CipherFunction.ChaChaPoly, HashFunction.Blake2b);
                using var handshakeState = protocol.Create(true, rs: consumerPublicKeyBytes);
                var handshakeMessage = new byte[HandshakeSize];
                var (handshakeBytesWritten, _, transport) = handshakeState.WriteMessage(null, handshakeMessage);

                // Write consumer public key
                consumerPublicKeyBytes.CopyTo(packet.AsSpan(offset, 32));
                offset += 32;
                BinaryPrimitives.WriteInt32LittleEndian(packet.AsSpan(offset, 4), blobSize);
                offset += 4;

                // Write handshake
                handshakeMessage.CopyTo(packet.AsSpan(offset, HandshakeSize));
                offset += HandshakeSize;

                // Encrypt and write chunks
                int dataOffset = 0;
                for (int i = 0; i < chunkCount; i++)
                {
                    int chunkSize = Math.Min(MaxPlaintextSize, data.Length - dataOffset);
                    var plaintextSpan = data.AsSpan(dataOffset, chunkSize);
                    transport!.WriteMessage(plaintextSpan, encryptedChunkBuffer.AsSpan(0, chunkSize + TagSize));
                    BinaryPrimitives.WriteInt32LittleEndian(packet.AsSpan(offset, 4), chunkSize + TagSize);
                    offset += 4;
                    encryptedChunkBuffer.AsSpan(0, chunkSize + TagSize).CopyTo(packet.AsSpan(offset));
                    offset += chunkSize + TagSize;
                    dataOffset += chunkSize;
                }
            }

            ArrayPool<byte>.Shared.Return(encryptedChunkBuffer);
            await SendAsync(Opcode.REQUEST, (byte)RequestOpcode.BULK_PUBLISH_RECORD, packet, contentEncoding: contentEncoding, cancellationToken: cancellationToken);
        }
        catch (Exception ex)
        {
            if (_pendingPublishRequests.TryRemove(requestId, out var errorTcs))
                errorTcs.TrySetException(ex);
            throw;
        }

        return await tcs.Task;
    }

    public async Task<bool> PublishRecordAsync(string consumerPublicKey, string key, byte[] data, ContentEncoding contentEncoding = ContentEncoding.Raw, CancellationToken cancellationToken = default)
    {
        var keyBytes = Encoding.UTF8.GetBytes(key);
        if (string.IsNullOrEmpty(key) || keyBytes.Length > 32)
            throw new ArgumentException("Key must be non-empty and at most 32 bytes.", nameof(key));

        var requestId = GenerateRequestId();
        var tcs = new TaskCompletionSource<bool>();
        _pendingPublishRequests[requestId] = tcs;

        cancellationToken.Register(() =>
        {
            if (_pendingPublishRequests.TryRemove(requestId, out var cancelledTcs))
                cancelledTcs.TrySetCanceled();
        });

        const int HandshakeSize = 48;
        const int LengthSize = 4;
        const int TagSize = 16;
        const int MaxPlaintextSize = 65535 - TagSize;

        try
        {
            byte[] consumerPublicKeyBytes = consumerPublicKey.DecodeBase64();
            if (consumerPublicKeyBytes.Length != 32)
                throw new ArgumentException("Consumer public key must be 32 bytes.", nameof(consumerPublicKey));

            // Calculate blob size
            int chunkCount = (data.Length + MaxPlaintextSize - 1) / MaxPlaintextSize;
            int blobSize = HandshakeSize;
            for (int i = 0; i < chunkCount; i++)
            {
                int chunkSize = Math.Min(MaxPlaintextSize, data.Length - i * MaxPlaintextSize);
                blobSize += LengthSize + (chunkSize + TagSize);
            }

            // Construct packet
            int packetSize = 4 + 32 + 1 + keyBytes.Length + 4 + blobSize;
            var packet = new byte[packetSize];
            int offset = 0;

            BinaryPrimitives.WriteInt32LittleEndian(packet.AsSpan(offset, 4), requestId);
            offset += 4;
            consumerPublicKeyBytes.CopyTo(packet.AsSpan(offset, 32));
            offset += 32;
            packet[offset] = (byte)keyBytes.Length;
            offset += 1;
            keyBytes.CopyTo(packet.AsSpan(offset, keyBytes.Length));
            offset += keyBytes.Length;
            BinaryPrimitives.WriteInt32LittleEndian(packet.AsSpan(offset, 4), blobSize);
            offset += 4;

            // Encrypt data
            var protocol = new Protocol(HandshakePattern.N, CipherFunction.ChaChaPoly, HashFunction.Blake2b);
            using var handshakeState = protocol.Create(true, rs: consumerPublicKeyBytes);
            var handshakeMessage = new byte[HandshakeSize];
            var (handshakeBytesWritten, _, transport) = handshakeState.WriteMessage(null, handshakeMessage);
            handshakeMessage.CopyTo(packet.AsSpan(offset, HandshakeSize));
            offset += HandshakeSize;

            var encryptedChunkBuffer = ArrayPool<byte>.Shared.Rent(MaxPlaintextSize + TagSize);
            int dataOffset = 0;
            for (int i = 0; i < chunkCount; i++)
            {
                int chunkSize = Math.Min(MaxPlaintextSize, data.Length - dataOffset);
                var plaintextSpan = data.AsSpan(dataOffset, chunkSize);
                transport!.WriteMessage(plaintextSpan, encryptedChunkBuffer.AsSpan(0, chunkSize + TagSize));
                BinaryPrimitives.WriteInt32LittleEndian(packet.AsSpan(offset, 4), chunkSize + TagSize);
                offset += 4;
                encryptedChunkBuffer.AsSpan(0, chunkSize + TagSize).CopyTo(packet.AsSpan(offset));
                offset += chunkSize + TagSize;
                dataOffset += chunkSize;
            }

            ArrayPool<byte>.Shared.Return(encryptedChunkBuffer);
            Logger.Verbose<SyncSocketSession>($"Sent publish request with requestId {requestId}");
            await SendAsync(Opcode.REQUEST, (byte)RequestOpcode.PUBLISH_RECORD, packet, contentEncoding: contentEncoding, cancellationToken: cancellationToken);
        }
        catch (Exception ex)
        {
            if (_pendingPublishRequests.TryRemove(requestId, out var errorTcs))
                errorTcs.TrySetException(ex);
            throw;
        }

        return await tcs.Task;
    }

    public async Task<(byte[] Data, DateTime Timestamp)?> GetRecordAsync(string publisherPublicKey, string key, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrEmpty(key) || key.Length > 32)
            throw new ArgumentException("Key must be non-empty and at most 32 bytes.", nameof(key));

        var tcs = new TaskCompletionSource<(byte[] Data, DateTime Timestamp)?>();
        var requestId = GenerateRequestId();
        _pendingGetRecordRequests[requestId] = tcs;

        cancellationToken.Register(() =>
        {
            if (_pendingGetRecordRequests.TryRemove(requestId, out var cancelledTcs))
                cancelledTcs.TrySetCanceled();
        });

        try
        {
            byte[] publisherPublicKeyBytes = publisherPublicKey.DecodeBase64();
            if (publisherPublicKeyBytes.Length != 32)
                throw new ArgumentException("Publisher public key must be 32 bytes.", nameof(publisherPublicKey));

            byte[] keyBytes = Encoding.UTF8.GetBytes(key);
            int packetSize = 4 + 32 + 1 + keyBytes.Length;
            var packet = new byte[packetSize];
            int offset = 0;
            BinaryPrimitives.WriteInt32LittleEndian(packet.AsSpan(offset, 4), requestId);
            offset += 4;
            publisherPublicKeyBytes.CopyTo(packet.AsSpan(offset, 32));
            offset += 32;
            packet[offset] = (byte)keyBytes.Length;
            offset += 1;
            keyBytes.CopyTo(packet.AsSpan(offset, keyBytes.Length));

            await SendAsync(Opcode.REQUEST, (byte)RequestOpcode.GET_RECORD, packet, cancellationToken: cancellationToken);
        }
        catch (Exception ex)
        {
            if (_pendingGetRecordRequests.TryRemove(requestId, out var errorTcs))
                errorTcs.TrySetException(ex);
            throw;
        }

        return await tcs.Task;
    }

    public async Task<Dictionary<string, (byte[] Data, DateTime Timestamp)>> GetRecordsAsync(IEnumerable<string> publisherPublicKeys, string key, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrEmpty(key) || key.Length > 32)
            throw new ArgumentException("Key must be non-empty and at most 32 bytes.", nameof(key));

        var publishers = publisherPublicKeys.ToList();
        if (publishers.Count == 0)
            return new Dictionary<string, (byte[], DateTime)>();

        var requestId = GenerateRequestId();
        var tcs = new TaskCompletionSource<Dictionary<string, (byte[], DateTime)>>();
        _pendingBulkGetRecordRequests[requestId] = tcs;

        cancellationToken.Register(() =>
        {
            if (_pendingBulkGetRecordRequests.TryRemove(requestId, out var cancelledTcs))
                cancelledTcs.TrySetCanceled();
        });

        try
        {
            byte[] keyBytes = Encoding.UTF8.GetBytes(key);
            int packetSize = 4 + 1 + keyBytes.Length + 1 + publishers.Count * 32;
            var packet = new byte[packetSize];
            int offset = 0;
            BinaryPrimitives.WriteInt32LittleEndian(packet.AsSpan(offset, 4), requestId);
            offset += 4;
            packet[offset] = (byte)keyBytes.Length;
            offset += 1;
            keyBytes.CopyTo(packet.AsSpan(offset, keyBytes.Length));
            offset += keyBytes.Length;
            packet[offset] = (byte)publishers.Count;
            offset += 1;
            foreach (var publisher in publishers)
            {
                byte[] publisherPublicKeyBytes = publisher.DecodeBase64();
                if (publisherPublicKeyBytes.Length != 32)
                    throw new ArgumentException($"Publisher public key must be 32 bytes: {publisher}");
                publisherPublicKeyBytes.CopyTo(packet.AsSpan(offset, 32));
                offset += 32;
            }

            await SendAsync(Opcode.REQUEST, (byte)RequestOpcode.BULK_GET_RECORD, packet, cancellationToken: cancellationToken);
        }
        catch (Exception ex)
        {
            if (_pendingBulkGetRecordRequests.TryRemove(requestId, out var errorTcs))
                errorTcs.TrySetException(ex);
            throw;
        }

        return await tcs.Task;
    }

    public async Task<bool> DeleteRecordsAsync(string publisherPublicKey, string consumerPublicKey, IEnumerable<string> keys, CancellationToken cancellationToken = default)
    {
        var keyList = keys.ToList();
        if (keyList.Any(k => Encoding.UTF8.GetByteCount(k) > 32))
            throw new ArgumentException("Keys must be at most 32 bytes.", nameof(keys));

        var tcs = new TaskCompletionSource<bool>();
        var requestId = GenerateRequestId();
        _pendingDeleteRequests[requestId] = tcs;

        cancellationToken.Register(() =>
        {
            if (_pendingDeleteRequests.TryRemove(requestId, out var cancelledTcs))
                cancelledTcs.TrySetCanceled();
        });

        try
        {
            byte[] publisherPublicKeyBytes = publisherPublicKey.DecodeBase64();
            if (publisherPublicKeyBytes.Length != 32)
                throw new ArgumentException("Publisher public key must be 32 bytes.", nameof(publisherPublicKey));

            byte[] consumerPublicKeyBytes = consumerPublicKey.DecodeBase64();
            if (consumerPublicKeyBytes.Length != 32)
                throw new ArgumentException("Consumer public key must be 32 bytes.", nameof(consumerPublicKey));

            using var ms = new MemoryStream();
            using var writer = new BinaryWriter(ms);
            writer.Write(requestId); // 4 bytes: Request ID
            writer.Write(publisherPublicKeyBytes); // 32 bytes: Publisher public key
            writer.Write(consumerPublicKeyBytes); // 32 bytes: Consumer public key
            writer.Write((byte)keyList.Count); // 1 byte: Number of keys (max 255)
            foreach (var key in keyList)
            {
                byte[] keyBytes = Encoding.UTF8.GetBytes(key);
                writer.Write((byte)keyBytes.Length); // 1 byte: Key length
                writer.Write(keyBytes); // Variable: Key bytes
            }
            var packet = ms.ToArray();
            await SendAsync(Opcode.REQUEST, (byte)RequestOpcode.BULK_DELETE_RECORD, packet, cancellationToken: cancellationToken);
        }
        catch (Exception ex)
        {
            if (_pendingDeleteRequests.TryRemove(requestId, out var errorTcs))
                errorTcs.TrySetException(ex);
            throw;
        }

        return await tcs.Task;
    }

    public Task<bool> DeleteRecordAsync(string publisherPublicKey, string consumerPublicKey, string key, CancellationToken cancellationToken = default)
    {
        if (key.Length > 32)
            throw new ArgumentException("Key must be at most 32 bytes.", nameof(key));

        var tcs = new TaskCompletionSource<bool>();
        var requestId = GenerateRequestId();
        _pendingDeleteRequests[requestId] = tcs;

        cancellationToken.Register(() =>
        {
            if (_pendingDeleteRequests.TryRemove(requestId, out var cancelledTcs))
            {
                cancelledTcs.TrySetCanceled();
            }
        });

        try
        {
            byte[] publisherPublicKeyBytes = publisherPublicKey.DecodeBase64();
            if (publisherPublicKeyBytes.Length != 32)
                throw new ArgumentException("Publisher public key must be 32 bytes.", nameof(publisherPublicKey));

            byte[] consumerPublicKeyBytes = consumerPublicKey.DecodeBase64();
            if (consumerPublicKeyBytes.Length != 32)
                throw new ArgumentException("Consumer public key must be 32 bytes.", nameof(consumerPublicKey));

            byte[] keyBytes = Encoding.UTF8.GetBytes(key);
            if (keyBytes.Length > 32)
                throw new ArgumentException("Key must be at most 32 bytes.", nameof(key));

            var packet = new byte[4 + 32 + 32 + 1 + keyBytes.Length];
            int offset = 0;
            BinaryPrimitives.WriteInt32LittleEndian(packet.AsSpan(offset, 4), requestId);
            offset += 4;
            publisherPublicKeyBytes.CopyTo(packet.AsSpan(offset, 32));
            offset += 32;
            consumerPublicKeyBytes.CopyTo(packet.AsSpan(offset, 32));
            offset += 32;
            packet[offset] = (byte)keyBytes.Length;
            offset += 1;
            keyBytes.CopyTo(packet.AsSpan(offset, keyBytes.Length));

            _ = SendAsync(Opcode.REQUEST, (byte)RequestOpcode.DELETE_RECORD, packet, cancellationToken: cancellationToken)
                .ContinueWith(t =>
                {
                    if (t.IsFaulted && _pendingDeleteRequests.TryRemove(requestId, out var failedTcs))
                    {
                        failedTcs.TrySetException(t.Exception!.InnerException!);
                    }
                });
        }
        catch (Exception ex)
        {
            if (_pendingDeleteRequests.TryRemove(requestId, out var errorTcs))
            {
                errorTcs.TrySetException(ex);
            }
            throw;
        }

        return tcs.Task;
    }

    public Task<List<(string Key, DateTime Timestamp)>> ListRecordKeysAsync(string publisherPublicKey, string consumerPublicKey, CancellationToken cancellationToken = default)
    {
        var tcs = new TaskCompletionSource<List<(string Key, DateTime Timestamp)>>();
        var requestId = GenerateRequestId();
        _pendingListKeysRequests[requestId] = tcs;

        cancellationToken.Register(() =>
        {
            if (_pendingListKeysRequests.TryRemove(requestId, out var cancelledTcs))
            {
                cancelledTcs.TrySetCanceled();
            }
        });

        try
        {
            byte[] publisherPublicKeyBytes = publisherPublicKey.DecodeBase64();
            if (publisherPublicKeyBytes.Length != 32)
                throw new ArgumentException("Publisher public key must be 32 bytes.", nameof(publisherPublicKey));

            byte[] consumerPublicKeyBytes = consumerPublicKey.DecodeBase64();
            if (consumerPublicKeyBytes.Length != 32)
                throw new ArgumentException("Consumer public key must be 32 bytes.", nameof(consumerPublicKey));

            var packet = new byte[4 + 32 + 32];
            BinaryPrimitives.WriteInt32LittleEndian(packet.AsSpan(0, 4), requestId);
            publisherPublicKeyBytes.CopyTo(packet.AsSpan(4, 32));
            consumerPublicKeyBytes.CopyTo(packet.AsSpan(36, 32));

            _ = SendAsync(Opcode.REQUEST, (byte)RequestOpcode.LIST_RECORD_KEYS, packet, cancellationToken: cancellationToken)
                .ContinueWith(t =>
                {
                    if (t.IsFaulted && _pendingListKeysRequests.TryRemove(requestId, out var failedTcs))
                    {
                        failedTcs.TrySetException(t.Exception!.InnerException!);
                    }
                });
        }
        catch (Exception ex)
        {
            if (_pendingListKeysRequests.TryRemove(requestId, out var errorTcs))
            {
                errorTcs.TrySetException(ex);
            }
            throw;
        }

        return tcs.Task;
    }

    public void Dispose()
    {
        foreach (var kvp in _pendingConnectionInfoRequests)
            kvp.Value.TrySetCanceled();
        _pendingConnectionInfoRequests.Clear();

        foreach (var kvp in _pendingPublishRequests)
            kvp.Value.TrySetCanceled();
        _pendingPublishRequests.Clear();

        foreach (var kvp in _pendingDeleteRequests)
            kvp.Value.TrySetCanceled();
        _pendingDeleteRequests.Clear();

        foreach (var kvp in _pendingListKeysRequests)
            kvp.Value.TrySetCanceled();
        _pendingListKeysRequests.Clear();

        foreach (var kvp in _pendingGetRecordRequests)
            kvp.Value.TrySetCanceled();
        _pendingGetRecordRequests.Clear();

        foreach (var kvp in _pendingBulkGetRecordRequests)
            kvp.Value.TrySetCanceled();
        _pendingBulkGetRecordRequests.Clear();

        foreach (var kvp in _pendingBulkConnectionInfoRequests)
            kvp.Value.TrySetCanceled();
        _pendingBulkConnectionInfoRequests.Clear();

        foreach (var kvp in _pendingChannels)
        {
            kvp.Value.Tcs.TrySetCanceled();
            kvp.Value.Channel.Dispose();
        }
        _pendingChannels.Clear();

        lock (_syncStreams)
        {
            foreach (var pair in _syncStreams)
                pair.Value.Dispose();
            _syncStreams.Clear();
        }

        foreach (var channel in _channels.Values)
            channel.Dispose();
        _channels.Clear();

        _started = false;
        _onClose?.Invoke(this);
        _socket.Close();
        _transport?.Dispose();
        Logger.Info<SyncSocketSession>("Session closed");
    }

    public const int MAXIMUM_PACKET_SIZE = 65535 - 16;
    public const int MAXIMUM_PACKET_SIZE_ENCRYPTED = MAXIMUM_PACKET_SIZE + 16;
    public const int HEADER_SIZE = 7;
}