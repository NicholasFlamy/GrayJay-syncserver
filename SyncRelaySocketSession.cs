using System.Buffers.Binary;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Net;
using Noise;
using SyncShared;
using System.Text;

namespace SyncClient;

public class SyncRelaySocketSession : IDisposable
{
    private static readonly Protocol _protocol = new Protocol(
        HandshakePattern.IK,
        CipherFunction.ChaChaPoly,
        HashFunction.Blake2b
    );

    public enum Opcode : byte
    {
        PING = 0,
        PONG = 1,
        CONNECT = 2,
        NOTIFY_CONNECT = 3
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
    private readonly Action<SyncRelaySocketSession> _onClose;
    private readonly Action<SyncRelaySocketSession> _onHandshakeComplete;
    private Thread? _thread = null;
    private Transport? _transport = null;
    private string _relayPublicKey;
    private string _targetPublicKey;
    private byte[] _connectionId;
    public string? RemotePublicKey { get; private set; } = null;
    private bool _started;
    private KeyPair _localKeyPair;
    private readonly string _localPublicKey;
    public string LocalPublicKey => _localPublicKey;
    private readonly Action<SyncRelaySocketSession, Opcode, byte, byte[]> _onData;
    public int RemoteVersion { get; private set; } = -1;

    public SyncRelaySocketSession(string relayPublicKey, string targetPublicKey, byte[] connectionId, KeyPair localKeyPair, Stream inputStream, Stream outputStream,
        Action<SyncRelaySocketSession> onClose, Action<SyncRelaySocketSession> onHandshakeComplete,
        Action<SyncRelaySocketSession, Opcode, byte, byte[]> onData)
    {
        _inputStream = inputStream;
        _outputStream = outputStream;
        _onClose = onClose;
        _onHandshakeComplete = onHandshakeComplete;
        _localKeyPair = localKeyPair;
        _onData = onData;
        _localPublicKey = Convert.ToBase64String(localKeyPair.PublicKey);
        _relayPublicKey = relayPublicKey;
        _targetPublicKey = targetPublicKey;
        _connectionId = connectionId;
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

    public async Task SendAsync(Opcode opcode, byte[] data, int offset = 0, int size = -1, CancellationToken cancellationToken = default) =>
        await SendAsync((byte)opcode, data, offset, size, cancellationToken);
    public async Task SendAsync(byte opcode, byte[] data, int offset = 0, int size = -1, CancellationToken cancellationToken = default)
    {
        if (size == -1)
            size = data.Length;

        try
        {
            await _sendSemaphore.WaitAsync();

            Array.Copy(BitConverter.GetBytes(data.Length + 1), 0, _sendBuffer, 0, 4);
            _sendBuffer[4] = (byte)opcode;
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

    public async Task SendAsync(Opcode opcode, byte subOpcode = 0, CancellationToken cancellationToken = default)
    {
        try
        {
            await _sendSemaphore.WaitAsync(cancellationToken);

            Array.Copy(BitConverter.GetBytes(2), 0, _sendBuffer, 0, 4);
            _sendBuffer[4] = (byte)opcode;

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

    private void HandleData(byte[] data, int length)
    {
        if (length < HEADER_SIZE)
            throw new Exception("Packet must be at least 6 bytes (header size)");

        int size = BitConverter.ToInt32(data, 0);
        if (size != length - 4)
            throw new Exception("Incomplete packet received");

        byte opcode = data[4];
        byte[] packetData = new byte[size - 1];
        Array.Copy(data, HEADER_SIZE, packetData, 0, size - 1);

        HandlePacket((Opcode)opcode, packetData);
    }

    public async Task Connect(string targetPublicKey, string connectionId, CancellationToken cancellationToken = default)
    {
        byte[] publicKeyBytes;
        try
        {
            publicKeyBytes = Convert.FromBase64String(publicKey);
            if (publicKeyBytes.Length != 32)
                throw new ArgumentException("Public key must be 32 bytes.");
        }
        catch (FormatException ex)
        {
            throw new ArgumentException("Invalid base64 encoding for public key.", ex);
        }

        await SendAsync(Opcode.REQUEST_CONNECTION_INFO, 0, publicKeyBytes, cancellationToken: cancellationToken);
    }

    private void HandlePacket(Opcode opcode, byte[] data)
    {
        switch (opcode)
        {
            case Opcode.PING:
                Task.Run(async () => 
                {
                    try
                    {
                        await SendAsync(Opcode.PONG);
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
            case Opcode.NOTIFY_CONNECT:
                {
                    Logger.Info<SyncRelaySocketSession>("Connect notify received.");
                    return;
                }
        }
    }

    private void ProcessConnectionInfo(byte[] data)
    {
        using var stream = new MemoryStream(data);
        using var reader = new BinaryReader(stream);

        var expectedHandshakeSize = 32 + 16;
        var ipSize = reader.ReadByte();
        var remoteIpBytes = reader.ReadBytes(ipSize);
        var remoteIp = new IPAddress(remoteIpBytes);
        byte[] handshakeMessage = reader.ReadBytes(expectedHandshakeSize);
        byte[] ciphertext = reader.ReadBytes(data.Length - expectedHandshakeSize);
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
    }

    public void Dispose()
    {
        lock (_syncStreams)
        {
            _syncStreams.Clear();
        }

        Stop();
    }

    public const int MAXIMUM_PACKET_SIZE = 65535 - 16;
    public const int MAXIMUM_PACKET_SIZE_ENCRYPTED = MAXIMUM_PACKET_SIZE + 16;
    public const int HEADER_SIZE = 5;
}