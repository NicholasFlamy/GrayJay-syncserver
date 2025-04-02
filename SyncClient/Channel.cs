using Noise;
using SyncShared;
namespace SyncClient;

public interface IChannel : IDisposable
{
    public string? RemotePublicKey { get; }
    public int? RemoteVersion { get; }
    public void SetDataHandler(Action<SyncSocketSession, IChannel, Opcode, byte, ReadOnlySpan<byte>>? onData);
    public Task SendRelayedDataAsync(Opcode opcode, byte subOpcode, byte[]? data = null, int offset = 0, int count = -1, CancellationToken cancellationToken = default);
}

public class ChannelSocket : IChannel
{
    public string? RemotePublicKey => _session.RemotePublicKey;
    public int? RemoteVersion => _session.RemoteVersion;
    private readonly SyncSocketSession _session;
    private Action<SyncSocketSession, IChannel, Opcode, byte, ReadOnlySpan<byte>>? _onData;

    public ChannelSocket(SyncSocketSession session)
    {
        _session = session;
    }

    public void SetDataHandler(Action<SyncSocketSession, IChannel, Opcode, byte, ReadOnlySpan<byte>>? onData)
    {
        _onData = onData;
    }

    public void Dispose()
    {
        _session.Dispose();
    }

    public void InvokeDataHandler(Opcode opcode, byte subOpcode, ReadOnlySpan<byte> data)
    {
        _onData?.Invoke(_session, this, opcode, subOpcode, data);
    }

    public async Task SendRelayedDataAsync(Opcode opcode, byte subOpcode, byte[]? data = null, int offset = 0, int count = -1, CancellationToken cancellationToken = default)
    {
        if (data != null)
            await _session.SendAsync(opcode, subOpcode, data, offset, count, cancellationToken: cancellationToken);
        else
            await _session.SendAsync(opcode, subOpcode, cancellationToken: cancellationToken);
    }
}

public class ChannelRelayed : IChannel
{
    public long ConnectionId { get; set; }
    public HandshakeState? HandshakeState;
    public Transport? Transport { get; private set; } = null;

    public string? RemotePublicKey { get; private set; }
    public int? RemoteVersion { get; private set; }

    private readonly KeyPair _localKeyPair;
    private readonly SyncSocketSession _session;
    private Action<SyncSocketSession, IChannel, Opcode, byte, ReadOnlySpan<byte>>? _onData;

    public ChannelRelayed(SyncSocketSession session, KeyPair localKeyPair, string publicKey, bool initiator)
    {
        _session = session;
        _localKeyPair = localKeyPair;
        HandshakeState = initiator
            ? Constants.Protocol.Create(initiator, s: _localKeyPair.PrivateKey, rs: Convert.FromBase64String(publicKey))
            : Constants.Protocol.Create(initiator, s: _localKeyPair.PrivateKey);
    }

    public void SetDataHandler(Action<SyncSocketSession, IChannel, Opcode, byte, ReadOnlySpan<byte>>? onData)
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

    public void InvokeDataHandler(Opcode opcode, byte subOpcode, ReadOnlySpan<byte> data)
    {
        _onData?.Invoke(_session, this, opcode, subOpcode, data);
    }

    public void CompleteHandshake(int remoteVersion, Transport transport)
    {
        RemoteVersion = remoteVersion;
        RemotePublicKey = Convert.ToBase64String(HandshakeState!.RemoteStaticPublicKey);
        HandshakeState!.Dispose();
        HandshakeState = null;
        Transport = transport;
        Logger.Info<SyncSocketSession>($"Completed handshake for connectionId {ConnectionId}");
    }

    public Task SendRelayedDataAsync(Opcode opcode, byte subOpcode, byte[]? data = null, int offset = 0, int count = -1, CancellationToken cancellationToken = default)
        => _session.SendRelayedDataAsync(this, opcode, subOpcode, data, offset, count, cancellationToken);
}
