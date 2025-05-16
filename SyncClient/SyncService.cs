using FUTO.MDNS;
using Noise;
using SyncShared;
using System.Net.Sockets;
using System.Net;
using Logger = SyncShared.Logger;
using System.Security.Cryptography;
using System.Collections.Concurrent;
using System.Runtime.CompilerServices;

namespace SyncClient;

public record class SyncServiceSettings
{
    public int ListenerPort = 12315;
    public bool MdnsBroadcast { get; init; } = true;
    public bool MdnsConnectDiscovered { get; init; } = true;
    public bool BindListener { get; init; } = true;
    public bool ConnectLastKnown { get; init; } = true;
    public bool RelayHandshakeAllowed { get; init; } = true;
    public bool RelayPairAllowed { get; init; } = true;
    public bool RelayEnabled { get; init; } = true;
    public bool RelayConnectDirect { get; init; } = true;
    public bool RelayConnectRelayed { get; init; } = true;
}

public class SyncService : IDisposable
{
    private readonly ISyncDatabaseProvider _database;
    private readonly SyncServiceSettings _settings;
    private CancellationTokenSource? _cancellationTokenSource;
    private readonly ServiceDiscoverer _serviceDiscoverer;
    private KeyPair? _keyPair;
    public string? PublicKey { get; private set; }
    private TcpListener? _serverSocket;
    private readonly Dictionary<string, long> _lastMdnsConnectTimes = new Dictionary<string, long>();
    private readonly Dictionary<string, SyncSession> _sessions = new Dictionary<string, SyncSession>();
    private readonly ConcurrentDictionary<string, Action<bool?, string>> _remotePendingStatusUpdate = new();
    public bool ServerSocketFailedToStart { get; private set; } = false;
    public string PairingCode { get; } = GenerateReadablePassword(8);
    public readonly uint AppId;
    public Action<SyncSession, bool, bool>? OnAuthorized;
    public Action<SyncSession>? OnUnauthorized;
    public Action<SyncSession, bool>? OnConnectedChanged;
    public Action<SyncSession>? OnClose;
    public Action<SyncSession, Opcode, byte, ReadOnlySpan<byte>>? OnData;
    public Action<string, Action<bool>>? AuthorizePrompt;
    private SyncSocketSession? _relaySession;
    private readonly string _relayServer;
    private readonly string _serviceName;
    private readonly string _relayPublicKey;

    public SyncService(string serviceName, string relayServer, string relayPublicKey, uint appId, ISyncDatabaseProvider database, SyncServiceSettings? settings = null)
    {
        _serviceName = serviceName;
        _relayServer = relayServer;
        _relayPublicKey = relayPublicKey;
        AppId = appId;
        _database = database;
        _settings = settings ?? new SyncServiceSettings();

        _serviceDiscoverer = new ServiceDiscoverer([serviceName]);
        _serviceDiscoverer.OnServicesUpdated += HandleServiceUpdated;
    }

    public async Task StartAsync()
    {
        if (_cancellationTokenSource != null)
        {
            Logger.Warning<SyncService>("Already started.");
            return;
        }

        _cancellationTokenSource = new CancellationTokenSource();

        try
        {
            var syncKeyPair = _database.GetSyncKeyPair();
            if (syncKeyPair == null)
                throw new Exception("No sync keypair available.");

            _keyPair = new KeyPair(syncKeyPair!.PrivateKey.DecodeBase64(), syncKeyPair!.PublicKey.DecodeBase64());
        }
        catch (Exception ex)
        {
            // Key pair non-existing, invalid or lost
            var p = KeyPair.Generate();

            var publicKey = p.PublicKey;
            var privateKey = p.PrivateKey;

            var syncKeyPair = new SyncKeyPair(1, publicKey.EncodeBase64(), privateKey.EncodeBase64());
            _database.SetSyncKeyPair(syncKeyPair);

            Logger.Error<SyncService>("Failed to load existing key pair", ex);
            _keyPair = p;
        }

        PublicKey = _keyPair.PublicKey.EncodeBase64();

        if (_settings.MdnsBroadcast || _settings.MdnsConnectDiscovered)
            _ = _serviceDiscoverer.RunAsync();


        if (_settings.MdnsBroadcast)
        {
            // Start broadcasting service
            await _serviceDiscoverer.BroadcastServiceAsync(Environment.MachineName, _serviceName, (ushort)_settings.ListenerPort, texts: new List<string> { $"pk={PublicKey.Replace('+', '-').Replace('/', '_').Replace("=", "")}" });
        }


        Logger.Info<SyncService>($"Sync key pair initialized (public key = {PublicKey})");

        if (_settings.BindListener)
            StartListener();

        if (_settings.RelayEnabled)
            StartRelayLoop();

        if (_settings.ConnectLastKnown)
            StartConnectLastLoop();
    }

    private void StartListener()
    {
        ServerSocketFailedToStart = false;
        _ = Task.Run(async () =>
        {
            try
            {
                _serverSocket = new TcpListener(IPAddress.Any, _settings.ListenerPort);
                _serverSocket.Start();
                Logger.Info<SyncService>($"Running on port {_settings.ListenerPort} (TCP)");

                while (!_cancellationTokenSource!.IsCancellationRequested)
                {
                    var clientSocket = await _serverSocket.AcceptSocketAsync();
                    var session = CreateSocketSession(clientSocket, true);
                    await session.StartAsResponderAsync();
                }
            }
            catch (Exception e)
            {
                Logger.Error<SyncService>("Server socket had an unexpected error.", e);
                ServerSocketFailedToStart = true;
            }
        });
    }

    private void StartConnectLastLoop()
    {
        _ = Task.Run(async () =>
        {
            try
            {
                Logger.Info<SyncService>("Running auto reconnector");

                while (!_cancellationTokenSource!.IsCancellationRequested)
                {
                    var authorizedDevices = _database.GetAllAuthorizedDevices() ?? Array.Empty<string>();
                    var pairs = authorizedDevices
                        .Select(pk => (PublicKey: pk, Address: _database.GetLastAddress(pk)))
                        .Where(t => !IsConnected(t.PublicKey) && t.Address != null)
                        .Select(t => new { t.PublicKey, LastAddress = t.Address! })
                        .ToList();

                    foreach (var pair in pairs)
                    {
                        try
                        {
                            await ConnectAsync([pair.LastAddress], _settings.ListenerPort, pair.PublicKey, null);
                        }
                        catch (Exception e)
                        {
                            Logger.Info<SyncService>("Failed to connect to " + pair.PublicKey, e);
                        }
                    }

                    if (_cancellationTokenSource.Token.WaitHandle.WaitOne(5000))
                        break;
                }
            }
            catch (Exception e)
            {
                Logger.Error<SyncService>("StateSync connect thread had an unexpected error.", e);
            }
        });
    }

    public void RemoveAuthorizedDevice(string publicKey) => _database.RemoveAuthorizedDevice(publicKey);
    public int GetAuthorizedDeviceCount() => _database.GetAuthorizedDeviceCount();
    public string[]? GetAllAuthorizedDevices() => _database.GetAllAuthorizedDevices();

    private void StartRelayLoop()
    {
        _ = Task.Run(async () =>
        {
            int[] backoffs = [1000, 5000, 10000, 20000];
            int backoffIndex = 0;

            while (!_cancellationTokenSource!.IsCancellationRequested)
            {
                try
                {
                    Logger.Info<SyncService>("Starting relay session...");

                    var socket = OpenTcpSocket(_relayServer, 9000);
                    _relaySession = new SyncSocketSession((socket.RemoteEndPoint as IPEndPoint)!.Address.ToString(), _keyPair!,
                        socket,
                        isHandshakeAllowed: IsHandshakeAllowed,
                        onNewChannel: (s, c) =>
                        {
                            var remotePublicKey = c.RemotePublicKey;
                            if (remotePublicKey == null)
                            {
                                Logger.Error<SyncService>("Remote public key should never be null in onNewChannel.");
                                return;
                            }

                            Logger.Info<SyncService>($"New channel established from relay (pk: '{c.RemotePublicKey}').");

                            SyncSession? session;
                            lock (_sessions)
                            {
                                if (!_sessions.TryGetValue(remotePublicKey, out session) || session == null)
                                {
                                    var remoteDeviceName = _database.GetDeviceName(remotePublicKey);
                                    session = CreateNewSyncSession(remotePublicKey, remoteDeviceName);
                                    _sessions[remotePublicKey] = session;
                                }

                                session.AddChannel(c);
                            }

                            c.SetDataHandler((_, channel, opcode, subOpcode, data) => session.HandlePacket(opcode, subOpcode, data));
                            c.SetCloseHandler((channel) =>
                            {
                                session.RemoveChannel(channel);
                                var remotePublicKey = channel.RemotePublicKey;
                                if (remotePublicKey != null && _remotePendingStatusUpdate.TryRemove(remotePublicKey, out var c))
                                    c?.Invoke(false, "Channel closed");
                            });
                        },
                        onChannelEstablished: async (_, channel, isResponder) =>
                        {
                            await HandleAuthorizationAsync(channel, isResponder, _cancellationTokenSource.Token);
                        },
                        onHandshakeComplete: async (relaySession) =>
                        {
                            backoffIndex = 0;

                            try
                            {
                                while (!_cancellationTokenSource.IsCancellationRequested)
                                {
                                    string[]? unconnectedAuthorizedDevices = _database.GetAllAuthorizedDevices()?.Where(pk => !IsConnected(pk))?.ToArray();
                                    if (unconnectedAuthorizedDevices != null)
                                    {
                                        await relaySession.PublishConnectionInformationAsync(unconnectedAuthorizedDevices, _settings.ListenerPort, _settings.RelayConnectDirect, false, false, _settings.RelayConnectRelayed, _cancellationTokenSource.Token);
                                        var connectionInfos = await relaySession.RequestBulkConnectionInfoAsync(unconnectedAuthorizedDevices, _cancellationTokenSource.Token);
                                        foreach (var connectionInfoPair in connectionInfos)
                                        {
                                            var targetKey = connectionInfoPair.Key;
                                            var connectionInfo = connectionInfoPair.Value;
                                            var potentialLocalAddresses = connectionInfo.Ipv4Addresses.Concat(connectionInfo.Ipv6Addresses).Where(l => l != connectionInfo.RemoteIp).ToList();
                                            if (connectionInfo.AllowLocalDirect && _settings.RelayConnectDirect)
                                            {
                                                _ = Task.Run(async () =>
                                                {
                                                    try
                                                    {
                                                        Logger.Verbose<SyncService>($"Attempting to connect directly, locally to '{targetKey}'.");
                                                        await ConnectAsync(potentialLocalAddresses.Select(l => l.ToString()).ToArray(), _settings.ListenerPort, targetKey, cancellationToken: _cancellationTokenSource.Token);
                                                    }
                                                    catch (Exception e)
                                                    {
                                                        Logger.Error<SyncService>($"Failed to start direct connection using connection info with {targetKey}.", e);
                                                    }
                                                });
                                            }

                                            var remoteAddress = connectionInfo.RemoteIp;
                                            if (connectionInfo.AllowRemoteDirect)
                                            {
                                                //TODO: Try connecting directly, remotely, set allow to true when implemented, only useful for port forwarded scenarios?
                                            }

                                            if (connectionInfo.AllowRemoteHolePunched)
                                            {
                                                //TODO: Implement hole punching, set allow to true when implemented
                                            }

                                            if (connectionInfo.AllowRemoteRelayed && _settings.RelayConnectRelayed)
                                            {
                                                try
                                                {
                                                    Logger.Verbose<SyncService>($"Attempting relayed connection with '{targetKey}'.");
                                                    await relaySession.StartRelayedChannelAsync(targetKey, AppId, null, _cancellationTokenSource.Token);
                                                }
                                                catch (Exception e)
                                                {
                                                    Logger.Error<SyncService>($"Failed to start relayed channel with {targetKey}.", e);
                                                }
                                            }
                                        }
                                    }

                                    await Task.Delay(TimeSpan.FromSeconds(15), _cancellationTokenSource.Token);
                                }
                            }
                            catch (Exception e)
                            {
                                Logger.Error<SyncService>("Unhandled exception in relay session.", e);
                                relaySession.Dispose();
                            }
                        });

                    _relaySession.Authorizable = AlwaysAuthorized.Instance;
                    await _relaySession.StartAsInitiatorAsync(_relayPublicKey, AppId, null, _cancellationTokenSource.Token);

                    Logger.Info<SyncService>("Relay session finished.");
                }
                catch (Exception e)
                {
                    Logger.Error<SyncService>("Relay session failed.", e);
                }
                finally
                {
                    _relaySession?.Dispose();
                    _relaySession = null;
                    var cancellationTokenSource = _cancellationTokenSource;
                    if (cancellationTokenSource != null)
                        await Task.Delay(backoffs[Math.Min(backoffs.Length - 1, backoffIndex++)], cancellationTokenSource.Token);
                }
            }
        });
    }

    public static string GenerateReadablePassword(int length)
    {
        const string validChars = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz23456789";
        byte[] randomBytes = new byte[length];
        RandomNumberGenerator.Fill(randomBytes);
        char[] result = new char[length];

        for (int i = 0; i < length; i++)
            result[i] = validChars[randomBytes[i] % validChars.Length];

        return new string(result);
    }

    private SyncSocketSession CreateSocketSession(Socket socket, bool isResponder, Action<SyncSocketSession>? onClose = null)
    {
        SyncSession? session = null;
        ChannelSocket? channelSocket = null;
        return new SyncSocketSession((socket.RemoteEndPoint as IPEndPoint)!.Address.ToString(), _keyPair!,
            socket,
            onClose: s =>
            {
                if (session != null && channelSocket != null)
                    session.RemoveChannel(channelSocket);
                onClose?.Invoke(s);
            },
            isHandshakeAllowed: IsHandshakeAllowed,
            onHandshakeComplete: async s =>
            {
                var remotePublicKey = s.RemotePublicKey;
                if (remotePublicKey == null)
                {
                    s.Dispose();
                    return;
                }

                Logger.Info<SyncService>($"Handshake complete with (LocalPublicKey = {s.LocalPublicKey}, RemotePublicKey = {s.RemotePublicKey})");

                lock (_sessions)
                {
                    if (!_sessions.TryGetValue(remotePublicKey, out session))
                    {
                        Logger.Info<SyncService>($"{s.RemotePublicKey} authorized");
                        _database.SetLastAddress(remotePublicKey, s.RemoteAddress);

                        var remoteDeviceName = _database.GetDeviceName(remotePublicKey);
                        session = CreateNewSyncSession(remotePublicKey, remoteDeviceName);
                        _sessions[remotePublicKey] = session;
                    }

                    channelSocket = new ChannelSocket(s);
                    session.AddChannel(channelSocket);
                }

                await HandleAuthorizationAsync(channelSocket, isResponder);
            },
            onData: (s, opcode, subOpcode, data) => session?.HandlePacket(opcode, subOpcode, data));
    }

    private async Task HandleAuthorizationAsync(IChannel channel, bool isResponder, CancellationToken cancellationToken = default)
    {
        SyncSession syncSession = ((SyncSession?)channel.SyncSession)!;
        var remotePublicKey = channel.RemotePublicKey!;
        if (isResponder)
        {
            var isAuthorized = IsAuthorized(remotePublicKey);
            if (!isAuthorized)
            {
                var authorizePrompt = AuthorizePrompt;
                if (authorizePrompt == null)
                {
                    try
                    {
                        Logger.Info<SyncService>($"{remotePublicKey} unauthorized because AuthorizePrompt is null");
                        await syncSession.UnauthorizeAsync(cancellationToken);
                    }
                    catch (Exception e)
                    {
                        Logger.Error<SyncService>("Failed to send authorize result.", e);
                    }

                    return;
                }

                authorizePrompt(remotePublicKey, async (allowed) =>
                {
                    try
                    {
                        if (allowed)
                        {
                            Logger.Info<SyncService>($"{remotePublicKey} manually authorized");
                            await syncSession.AuthorizeAsync(cancellationToken);
                        }
                        else
                        {
                            Logger.Info<SyncService>($"{remotePublicKey} manually unauthorized");
                            await syncSession.UnauthorizeAsync(cancellationToken);
                        }
                    }
                    catch (Exception e)
                    {
                        Logger.Error<SyncService>("Failed to send authorize result.", e);
                    }
                });
            }
            else
            {
                await syncSession.AuthorizeAsync(cancellationToken);
                Logger.Info<SyncService>($"Connection authorized for {remotePublicKey} because already authorized");
            }
        }
        else
        {
            await syncSession.AuthorizeAsync(cancellationToken);
            Logger.Info<SyncService>($"Connection authorized for {remotePublicKey} because initiator");
        }
    }


    public bool IsConnected(string publicKey)
    {
        lock (_sessions)
        {
            return _sessions.TryGetValue(publicKey, out var v) && v != null && v.Connected;
        }
    }

    public bool IsAuthorized(string publicKey)
    {
        return _database.IsAuthorized(publicKey);
    }

    public SyncSession? GetSession(string publicKey)
    {
        lock (_sessions)
        {
            if (_sessions.TryGetValue(publicKey, out var s))
                return s;
            return null;
        }
    }
    public List<SyncSession> GetSessions()
    {
        lock (_sessions)
        {
            return _sessions.Values.ToList();
        }
    }

    public void RemoveSession(string publicKey)
    {
        lock (_sessions)
        {
            _sessions.Remove(publicKey);
        }
    }

    private void HandleServiceUpdated(List<DnsService> services)
    {
        if (!_settings.MdnsConnectDiscovered)
            return;

        foreach (var s in services)
        {
            var addresses = s.Addresses.Select(v => v.ToString()).ToArray();
            var port = s.Port;

            if (s.Name.EndsWith(_serviceName))
            {
                var name = s.Name.Substring(0, s.Name.Length - _serviceName.Length);
                var urlSafePkey = s.Texts.Find(t => t.StartsWith("pk="))?.Substring("pk=".Length);

                if (string.IsNullOrEmpty(urlSafePkey)) continue;

                var pkey = urlSafePkey.DecodeBase64Url().EncodeBase64();
                var authorized = IsAuthorized(pkey);
                if (authorized && !IsConnected(pkey))
                {
                    var now = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();

                    lock (_lastMdnsConnectTimes)
                    {
                        if (_lastMdnsConnectTimes.TryGetValue(pkey, out var lastConnectTime) && now - lastConnectTime < 30000)
                            continue;

                        _lastMdnsConnectTimes[pkey] = now;
                    }
                    Logger.Info<SyncService>($"Found authorized device '{name}' with pkey={pkey}, attempting to connect");

                    _ = Task.Run(async () =>
                    {
                        try
                        {
                            await ConnectAsync(addresses, port, pkey);
                            Logger.Info<SyncService>($"Connected to found authorized device '{name}' with pkey={pkey}.");
                        }
                        catch (Exception ex)
                        {
                            Logger.Info<SyncService>($"Failed to connect to {pkey}", ex);
                        }
                    });
                }
            }
        }
    }

    public string? GetCachedName(string publicKey)
    {
        return _database.GetDeviceName(publicKey);
    }

    public async Task ConnectAsync(SyncDeviceInfo deviceInfo, Action<bool?, string>? onStatusUpdate = null, CancellationToken cancellationToken = default)
    {
        bool relayRequestStarted = false;
        try
        {
            await ConnectAsync(deviceInfo.Addresses, deviceInfo.Port, deviceInfo.PublicKey, deviceInfo.PairingCode, async (completed, message) =>
            {
                try
                {
                    if (completed.HasValue)
                    {
                        var relaySession = _relaySession;
                        if (completed.Value)
                            onStatusUpdate?.Invoke(completed, message);
                        else if (!relayRequestStarted && relaySession != null && _settings.RelayPairAllowed)
                        {
                            relayRequestStarted = true;
                            onStatusUpdate?.Invoke(null, "Connecting via relay...");
                            if (onStatusUpdate != null)
                                _remotePendingStatusUpdate[deviceInfo.PublicKey.DecodeBase64().EncodeBase64()] = onStatusUpdate;
                            await relaySession.StartRelayedChannelAsync(deviceInfo.PublicKey, AppId, deviceInfo.PairingCode, cancellationToken);
                        }
                    }
                    else
                        onStatusUpdate?.Invoke(completed, message);
                }
                catch (Exception e)
                {
                    Logger.Error<SyncService>("Failed to connect.", e);
                    onStatusUpdate?.Invoke(false, e.Message);
                }
            }, cancellationToken);
        }
        catch (Exception e)
        {
            Logger.Error<SyncService>("Failed to connect directly.", e);
            var relaySession = _relaySession;
            if (!relayRequestStarted && relaySession != null && _settings.RelayPairAllowed)
            {
                relayRequestStarted = true;
                onStatusUpdate?.Invoke(null, "Connecting via relay...");
                if (onStatusUpdate != null)
                    _remotePendingStatusUpdate[deviceInfo.PublicKey.DecodeBase64().EncodeBase64()] = onStatusUpdate;
                await relaySession.StartRelayedChannelAsync(deviceInfo.PublicKey, AppId, deviceInfo.PairingCode, cancellationToken);
            }
            else
            {
                throw;
            }
        }
    }

    private async Task<SyncSocketSession> ConnectAsync(string[] addresses, int port, string remotePublicKey, string? pairingCode = null, Action<bool?, string>? onStatusUpdate = null, CancellationToken cancellationToken = default)
    {
        onStatusUpdate?.Invoke(null, "Connecting directly...");

        var socket = OpenTcpSocket(addresses[0], port);
        var session = CreateSocketSession(socket, false, (s) =>
        {
            onStatusUpdate?.Invoke(false, "Disconnected.");
        });

        if (onStatusUpdate != null)
            _remotePendingStatusUpdate[remotePublicKey.DecodeBase64().EncodeBase64()] = onStatusUpdate;
        onStatusUpdate?.Invoke(null, "Handshaking...");
        await session.StartAsInitiatorAsync(remotePublicKey, AppId, pairingCode, cancellationToken);
        return session;
    }

    private bool IsHandshakeAllowed(LinkType linkType, SyncSocketSession syncSocketSession, string publicKey, string? pairingCode, uint appId)
    {
        Logger.Verbose<SyncService>($"Check if handshake allowed from '{publicKey}'.");

        if (_database.IsAuthorized(publicKey))
        {
            if (linkType == LinkType.Relayed && !_settings.RelayHandshakeAllowed)
                return false;
            return true;
        }

        Logger.Verbose<SyncService>($"Check if handshake allowed with pairing code '{pairingCode}' with active pairing code '{PairingCode}'.");
        if (PairingCode == null || pairingCode == null || pairingCode.Length == 0)
            return false;

        if (linkType == LinkType.Relayed && !_settings.RelayPairAllowed)
            return false;

        return PairingCode == pairingCode;
    }

    private SyncSession CreateNewSyncSession(string remotePublicKey, string? remoteDeviceName)
    {
        return new SyncSession(remotePublicKey, onAuthorized: (sess, isNewlyAuthorized, isNewSession) =>
        {
            if (_remotePendingStatusUpdate.TryRemove(remotePublicKey, out var m) && m != null)
                m?.Invoke(true, "Authorized");

            if (isNewSession)
            {
                var rdn = sess.RemoteDeviceName;
                if (rdn != null)
                    _database.SetDeviceName(remotePublicKey, rdn);

                _database.AddAuthorizedDevice(remotePublicKey);
            }

            OnAuthorized?.Invoke(sess, isNewlyAuthorized, isNewlyAuthorized);
        }, onUnauthorized: sess => {
            if (_remotePendingStatusUpdate.TryRemove(remotePublicKey, out var m) && m != null)
                m?.Invoke(false, "Unauthorized");

            OnUnauthorized?.Invoke(sess);
        }, onConnectedChanged: (sess, connected) =>
        {
            Logger.Info<SyncService>($"{sess.RemotePublicKey} connected: {connected}");
            OnConnectedChanged?.Invoke(sess, connected);
        }, onClose: sess =>
        {
            Logger.Info<SyncService>($"{sess.RemotePublicKey} closed");

            RemoveSession(remotePublicKey);

            if (_remotePendingStatusUpdate.TryRemove(remotePublicKey, out var m) && m != null)
                m?.Invoke(false, "Connection closed");

            OnClose?.Invoke(sess);
        }, dataHandler: (sess, opcode, subOpcode, data) =>
        {
            OnData?.Invoke(sess, opcode, subOpcode, data);
        }, remoteDeviceName);
    }

    private Socket OpenTcpSocket(string host, int port)
    {
        IPHostEntry hostEntry = Dns.GetHostEntry(host);
        var addresses = hostEntry.AddressList.OrderBy(a => a.AddressFamily == AddressFamily.InterNetwork ? 0 : 1).ToArray();

        foreach (IPAddress address in addresses)
        {
            try
            {
                Socket socket = new Socket(
                    address.AddressFamily,
                    SocketType.Stream,
                    ProtocolType.Tcp
                );

                socket.Connect(new IPEndPoint(address, port));
                Console.WriteLine($"Connected to {host}:{port} using {address.AddressFamily}");
                return socket;
            }
            catch
            {
                //Ignored
            }
        }

        throw new Exception($"Could not connect to {host}:{port}");
    }

    public void Dispose()
    {
        _cancellationTokenSource?.Cancel();
        _cancellationTokenSource = null;
        _serviceDiscoverer.Dispose();

        _relaySession?.Dispose();
        _relaySession = null;
        _serverSocket?.Stop();
        _serverSocket = null;

        lock (_sessions)
        {
            foreach (var session in _sessions)
                session.Value.Dispose();
            _sessions.Clear();
        }
    }
}
