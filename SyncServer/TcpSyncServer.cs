using FirebaseAdmin;
using FirebaseAdmin.Messaging;
using Noise;
using SyncServer.Repositories;
using SyncShared;
using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace SyncServer;

public class TcpSyncServerMetrics
{
    [JsonIgnore]
    private readonly TcpSyncServer _server;

    public TcpSyncServerMetrics(TcpSyncServer server)
    {
        _server = server;
    }

    public long StartTime => DateTimeOffset.UtcNow.ToUnixTimeSeconds();
    public long ActiveConnections;
    public long TotalConnectionsAccepted;
    public long TotalConnectionsClosed;
    public long TotalHandshakeAttempts;
    public long TotalHandshakeSuccesses;

    public long TotalRelayedConnectionsRequested;
    public long TotalRelayedConnectionsEstablished;
    public long TotalRelayedConnectionsFailed;
    public long TotalRelayedDataBytes;
    public long TotalRelayedErrorBytes;

    public long TotalKeypairRegistrationRateLimitExceedances;
    public long TotalRelayRequestByIpTokenRateLimitExceedances;
    public long TotalRelayRequestByIpConnectionLimitExceedances;
    public long TotalRelayRequestByKeyTokenRateLimitExceedances;
    public long TotalRelayRequestByKeyConnectionLimitExceedances;
    public long TotalRelayDataByIpRateLimitExceedances;
    public long TotalRelayDataByConnectionIdRateLimitExceedances;
    public long TotalPublishRequestRateLimitExceedances;

    public long TotalPublishRecordRequests;
    public long TotalDeleteRecordRequests;
    public long TotalListKeysRequests;
    public long TotalGetRecordRequests;
    public long TotalPublishRecordSuccesses;
    public long TotalDeleteRecordSuccesses;
    public long TotalListKeysSuccesses;
    public long TotalGetRecordSuccesses;
    public long TotalPublishRecordFailures;
    public long TotalDeleteRecordFailures;
    public long TotalListKeysFailures;
    public long TotalGetRecordFailures;

    public long TotalStorageLimitExceedances;

    public long TotalPublishRecordTimeMs;
    public long PublishRecordCount;
    public long TotalDeleteRecordTimeMs;
    public long DeleteRecordCount;
    public long TotalListKeysTimeMs;
    public long ListKeysCount;
    public long TotalGetRecordTimeMs;
    public long GetRecordCount;

    public long MaxConnectionsCount => _server.MaxConnections.CurrentCount;

    public int ConnectionInfoCount => _server.ConnectionInfoStore.Count;
    public long TotalPublishConnectionInfoSuccesses;
    public long TotalPublishConnectionInfoCount;
    public long TotalPublishConnectionInfoFailures;
    public long TotalPublishConnectionInfoTimeMs;
    public long TotalRequestConnectionInfoSuccesses;
    public long TotalRequestConnectionInfoFailures;
    public long TotalRequestConnectionInfoTimeMs;
    public long TotalRequestBulkConnectionInfoSuccesses;
    public long TotalRequestBulkConnectionInfoFailures;
    public long TotalRequestBulkConnectionInfoTimeMs;

    public long TotalRented => Utilities.TotalRented;
    public long TotalReturned => Utilities.TotalReturned;

    public long MemoryUsage => GC.GetTotalMemory(false);
    public int ActiveRelayedConnections => _server.RelayedConnections.Values.Count(conn => conn.IsActive);
    public int ClientCount => _server.ClientCount;
    public int SessionCount => _server.SessionCount;

    public int[] GCCounts
    {
        get
        {
            int maxGen = GC.MaxGeneration;
            int[] counts = new int[maxGen + 1];
            for (int i = 0; i <= maxGen; i++)
            {
                counts[i] = GC.CollectionCount(i);
            }
            return counts;
        }
    }
}

[JsonSourceGenerationOptions(WriteIndented = true, IncludeFields = true)]
[JsonSerializable(typeof(TcpSyncServerMetrics))]
public partial class TcpSyncServerMetricsContext : JsonSerializerContext
{
}

public class TcpSyncServer : IDisposable
{
    public class ArgsPair
    {
        public SyncSession? Session;
        public bool ReturnToPool;
    }

    public class RelayedConnection
    {
        public required SyncSession Initiator;
        public SyncSession? Target;
        public bool IsActive;
    }

    private static readonly Protocol NoiseProtocol = new Protocol(
        HandshakePattern.IK,
        CipherFunction.ChaChaPoly,
        HashFunction.Blake2b
    );

    private const int MAX_CONNECTIONS = 100000;

    private Socket? _listenSocket4;
    private Socket? _listenSocket6;
    public readonly SemaphoreSlim MaxConnections;
    private readonly ConcurrentDictionary<Socket, SyncSession> _clients = new();
    public int ClientCount => _clients.Count;
    private readonly ConcurrentDictionary<string, SyncSession> _sessions = new();
    public int SessionCount => _sessions.Count;
    private readonly KeyPair _keyPair;
    public KeyPair LocalKeyPair => _keyPair;
    public readonly ConcurrentDictionary<(string, string), byte[]> ConnectionInfoStore = new();
    public readonly ConcurrentDictionary<long, RelayedConnection> RelayedConnections = new();
    private readonly ConcurrentDictionary<(string, string), DateTime> RelayBlacklist = new ConcurrentDictionary<(string, string), DateTime>();

    private readonly ConcurrentDictionary<string, TokenBucket> _ipTokenBuckets = new();
    private readonly ConcurrentDictionary<string, TokenBucket> _keyTokenBuckets = new();
    private readonly ConcurrentDictionary<long, TokenBucket> _connectionTokenBuckets = new();
    private readonly ConcurrentDictionary<(string, string), long> _activeRelayPairs = new();
    public int MaxRelayedConnectionsPerIp = 100;
    public int MaxRelayedConnectionsPerKey = 10;
    public int MaxKeypairsPerHour = 50;

    private readonly object _pendingLock = new object();
    private readonly LinkedList<SyncSession> _pendingHandshakes = new LinkedList<SyncSession>();
    private const int MAX_PENDING_HANDSHAKES = 1000;
    private readonly TimeSpan _acceptDelay = TimeSpan.FromMilliseconds(10);

    private readonly ConcurrentDictionary<string, TokenBucket> _handshakeBuckets = new();
    private readonly ConcurrentDictionary<string, DateTime> _ipHandshakeBlacklist = new();
    private Dictionary<string, HashSet<string>> _notificationAllowList = new();
    private static readonly TimeSpan HandshakeWindow = TimeSpan.FromMinutes(1);
    private const int MaxHandshakesPerWindow = 20;
    private static readonly TimeSpan HandshakeBlacklistDuration = TimeSpan.FromMinutes(1);

    private readonly IDictionary<string, FirebaseApp>? _firebaseApps;
    private readonly int _port;
    public int Port => _port;
    private int _nextConnectionId = 0;
    public IRecordRepository RecordRepository { get; }
    public IDeviceTokenRepository DeviceTokenRepository { get; }

    public readonly TcpSyncServerMetrics Metrics;

    public bool _useRateLimits;

    public TcpSyncServer(int port, KeyPair keyPair, IRecordRepository recordRepository, IDeviceTokenRepository deviceTokenRepository, IDictionary<string, FirebaseApp>? firebaseApps = null, int maxConnections = MAX_CONNECTIONS, bool useRateLimits = false)
    {
        Metrics = new TcpSyncServerMetrics(this);
        _port = port;
        MaxConnections = new SemaphoreSlim(maxConnections, maxConnections);
        _keyPair = keyPair;
        _firebaseApps = firebaseApps;
        RecordRepository = recordRepository;
        DeviceTokenRepository = deviceTokenRepository;
        _useRateLimits = useRateLimits;
    }

    public int GetNextConnectionId() => Interlocked.Increment(ref _nextConnectionId);
    public void SetRelayedConnection(long connectionId, SyncSession initiator, SyncSession? target = null, bool isActive = false)
    {
        RelayedConnections[connectionId] = new RelayedConnection
        {
            Initiator = initiator,
            Target = target,
            IsActive = isActive
        };
    }

    public RelayedConnection? GetRelayedConnection(long connectionId)
    {
        RelayedConnections.TryGetValue(connectionId, out var connection);
        return connection;
    }

    public int GetActiveRelayedConnectionsCount(string publicKey)
    {
        return RelayedConnections.Values.Count(conn => conn.IsActive && conn.Initiator.RemotePublicKey == publicKey);
    }

    public void OnSessionClosed(SyncSession session)
    {
        var socket = session.Socket;
        if (socket != null)
            _clients.TryRemove(session.Socket, out _);

        var remotePublicKey = session?.RemotePublicKey;
        if (remotePublicKey != null)
        {
            _sessions.TryRemove(remotePublicKey, out _);
            var keysToRemove = ConnectionInfoStore.Keys.Where(k => k.Item1 == remotePublicKey).ToList();
            foreach (var key in keysToRemove)
                ConnectionInfoStore.TryRemove(key, out _);
        }

        Interlocked.Increment(ref Metrics.TotalConnectionsClosed);
        Interlocked.Decrement(ref Metrics.ActiveConnections);

        try
        {
            MaxConnections.Release();
        }
        catch (Exception e)
        {
            Logger.Warning<TcpSyncServer>("Failed to release max connections", e);
        }

        var notification = new byte[12];
        foreach (var kvp in RelayedConnections.ToArray())
        {
            var connection = kvp.Value;
            if (connection.Initiator == session || connection.Target == session)
            {
                RelayedConnections.TryRemove(kvp.Key, out _);
                RemoveRelayPairByConnectionId(kvp.Key);
                _connectionTokenBuckets.TryRemove(kvp.Key, out _);

                var otherSession = connection.Initiator == session ? connection.Target : connection.Initiator;
                if (otherSession != null)
                {
                    BinaryPrimitives.WriteInt64LittleEndian(notification.AsSpan(0, 8), kvp.Key);
                    BinaryPrimitives.WriteInt32LittleEndian(notification.AsSpan(8, 4), 2);

                    _ = Task.Run(async () =>
                    {
                        try
                        {
                            await otherSession.SendAsync(Opcode.RELAY, (byte)RelayOpcode.RELAY_ERROR, notification);
                        }
                        catch (Exception e)
                        {
                            otherSession.Dispose();
                            Logger.Info<TcpSyncServer>("Failed to send relay error", e);
                        }
                    });
                }
            }
        }

        Logger.Info<TcpSyncServer>($"Client disconnected");
    }

    public void RemoveSession(SyncSession session)
    {
        var remotePublicKey = session.RemotePublicKey;
        if (remotePublicKey != null && _sessions.TryRemove(remotePublicKey, out _))
        {
            foreach (var kvp in RelayedConnections.ToArray())
            {
                if (kvp.Value.Initiator == session || kvp.Value.Target == session)
                {
                    RelayedConnections.TryRemove(kvp.Key, out _);
                }
            }
        }
    }

    public void StoreConnectionInfo(string publicKey, string intendedPublicKey, byte[] encryptedBlob)
    {
        ConnectionInfoStore[(publicKey, intendedPublicKey)] = encryptedBlob;
    }

    public byte[]? RetrieveConnectionInfo(string targetPublicKey, string requestingPublicKey)
    {
        if (ConnectionInfoStore.TryGetValue((targetPublicKey, requestingPublicKey), out byte[]? block))
            return block;
        return null;
    }

    public SyncSession? GetSession(string publicKey)
    {
        if (_sessions.TryGetValue(publicKey, out var session))
            return session;
        return null;
    }

    public void Start()
    {
        _listenSocket4 = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
        _listenSocket4.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, true);
        _listenSocket4.Bind(new IPEndPoint(IPAddress.Any, _port));
        _listenSocket4.Listen(1000);

        _listenSocket6 = new Socket(AddressFamily.InterNetworkV6, SocketType.Stream, ProtocolType.Tcp);
        _listenSocket6.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, true);
        _listenSocket6.SetSocketOption(SocketOptionLevel.IPv6, SocketOptionName.IPv6Only, true);
        _listenSocket6.Bind(new IPEndPoint(IPAddress.IPv6Any, _port));
        _listenSocket6.Listen(1000);

        Logger.Info<TcpSyncServer>($"Server started. Listening on port {_port} for IPv4 & IPv6 (dual-socket).");

        _ = AcceptLoopAsync(_listenSocket4);
        _ = AcceptLoopAsync(_listenSocket6);
    }

    private async Task AcceptLoopAsync(Socket listenSocket)
    {
        try
        {
            while (true)
            {
                await Task.Delay(_acceptDelay);

                MaxConnections.Wait();
                var clientSocket = await listenSocket.AcceptAsync();
                if (clientSocket == null)
                {
                    Logger.Info<TcpSyncServer>("Accepted socket is null.");
                    MaxConnections.Release();
                    return;
                }

                string ip = ((IPEndPoint)clientSocket.RemoteEndPoint!).Address.ToString();
                if (_ipHandshakeBlacklist.TryGetValue(ip, out var blockedUntil) && blockedUntil > DateTime.UtcNow)
                {
                    clientSocket.Close();
                    MaxConnections.Release();
                    continue;
                }

                var bucket = _handshakeBuckets.GetOrAdd(ip, _ => new TokenBucket(MaxHandshakesPerWindow, MaxHandshakesPerWindow / HandshakeWindow.TotalSeconds));
                if (!bucket.TryConsume(1))
                {
                    Logger.Warning<TcpSyncServer>($"Blacklisted IP {ip} for exceeding rate limit.");
                    _ipHandshakeBlacklist[ip] = DateTime.UtcNow + HandshakeBlacklistDuration;
                    clientSocket.Close();
                    MaxConnections.Release();
                    continue;
                }

                SyncSession? session = null;
                try
                {
                    session = new SyncSession(this, (s) =>
                    {
                        lock (_pendingLock)
                            _pendingHandshakes.Remove(s);

                        _sessions[s.RemotePublicKey!] = s;
                    }, OnSessionClosed, _useRateLimits)
                    {
                        Socket = clientSocket,
                        HandshakeState = NoiseProtocol.Create(false, s: _keyPair.PrivateKey)
                    };
                    _clients.TryAdd(clientSocket, session);
                    Interlocked.Increment(ref Metrics.TotalConnectionsAccepted);
                    Interlocked.Increment(ref Metrics.ActiveConnections);

                    Logger.Info<TcpSyncServer>($"Client connected: {clientSocket.RemoteEndPoint}");
                    session.Start();
                }
                catch (Exception ex)
                {
                    Logger.Error<TcpSyncServer>($"Accept processing error", ex);
                    MaxConnections.Release();
                }

                if (session != null)
                {
                    lock (_pendingLock)
                    {
                        // Evict oldest if we're at capacity
                        if (_pendingHandshakes.Count >= MAX_PENDING_HANDSHAKES)
                        {
                            var oldest = _pendingHandshakes.First!;
                            _pendingHandshakes.RemoveFirst();
                            oldest.Value.Dispose();

                            Logger.Warning<TcpSyncServer>($"Evicted {ip} for not completing handshake in time when server is under load.");
                        }

                        _pendingHandshakes.AddLast(session);
                    }
                }
            }
        }
        catch (Exception e)
        {
            Logger.Error<TcpSyncServer>($"Unhandled exception in listening socket", e);
            Dispose();
        }
    }

    public bool IsBlacklisted(string initiator, string target)
    {
        if (RelayBlacklist.TryGetValue((initiator, target), out DateTime expiration))
        {
            if (DateTime.UtcNow < expiration)
            {
                return true; // Still blacklisted
            }
            else
            {
                // Expired, remove from blacklist
                RelayBlacklist.TryRemove((initiator, target), out _);
                return false;
            }
        }
        return false; // Not blacklisted
    }

    public void AddToBlacklist(string initiator, string target, TimeSpan duration)
    {
        DateTime expiration = DateTime.UtcNow + duration;
        RelayBlacklist[(initiator, target)] = expiration;
    }

    public void Dispose()
    {
        try
        {
            _listenSocket4?.Close();
            _listenSocket6?.Close();
            foreach (var client in _clients.Values)
                client.Dispose();
        }
        catch (Exception ex)
        {
            Logger.Error<TcpSyncServer>($"Shutdown error", ex);
        }
        finally
        {
            _listenSocket4?.Dispose();
            _listenSocket4 = null;
            _listenSocket6?.Dispose();
            _listenSocket6 = null;
        }

        MaxConnections.Dispose();
    }
    public bool TryRegisterNewKeypair(string ipAddress)
    {
        var bucket = _ipTokenBuckets.GetOrAdd(
            $"{ipAddress}:keypairs",
            _ => new TokenBucket(MaxKeypairsPerHour, MaxKeypairsPerHour / 3600.0)
        );
        return bucket.TryConsume(1);
    }

    public enum RateLimitReason
    {
        Allowed,
        TokenRateLimitExceeded,
        ConnectionLimitExceeded
    }

    public (bool allowed, RateLimitReason reason) IsRelayRequestAllowedByIP(string ipAddress)
    {
        var bucket = _ipTokenBuckets.GetOrAdd(
            $"{ipAddress}:relays",
            _ => new TokenBucket(100, 10)
        );
        if (!bucket.TryConsume(1))
        {
            return (false, RateLimitReason.TokenRateLimitExceeded);
        }
        if (GetRelayedConnectionCountByIP(ipAddress) >= MaxRelayedConnectionsPerIp)
        {
            return (false, RateLimitReason.ConnectionLimitExceeded);
        }
        return (true, RateLimitReason.Allowed);
    }

    public (bool allowed, RateLimitReason reason) IsRelayRequestAllowedByKey(string remotePublicKey)
    {
        var bucket = _keyTokenBuckets.GetOrAdd(
            $"{remotePublicKey}:relays",
            _ => new TokenBucket(10, 1)
        );
        if (!bucket.TryConsume(1))
        {
            return (false, RateLimitReason.TokenRateLimitExceeded);
        }
        if (GetRelayedConnectionCountByKey(remotePublicKey) >= MaxRelayedConnectionsPerKey)
        {
            return (false, RateLimitReason.ConnectionLimitExceeded);
        }
        return (true, RateLimitReason.Allowed);
    }

    public bool IsRelayDataAllowedByIP(string ipAddress, int dataSize)
    {
        var bucket = _ipTokenBuckets.GetOrAdd(
            $"{ipAddress}:relay_data",
            _ => new TokenBucket(200_000_000, 200_000)
        );
        return bucket.TryConsume(dataSize);
    }

    public bool IsRelayDataAllowedByConnectionId(long connectionId, int dataSize)
    {
        var bucket = _connectionTokenBuckets.GetOrAdd(
            connectionId,
            _ => new TokenBucket(20_000_000, 20_000)
        );
        return bucket.TryConsume(dataSize);
    }

    public bool IsPublishRequestAllowed(string ipAddress)
    {
        var bucket = _ipTokenBuckets.GetOrAdd(
            $"{ipAddress}:publishes",
            _ => new TokenBucket(1000, 10)
        );
        return bucket.TryConsume(1);
    }

    private int GetRelayedConnectionCountByIP(string ipAddress)
    {
        return RelayedConnections.Values.Count(conn =>
            GetIpAddress(conn.Initiator) == ipAddress ||
            (conn.Target != null && GetIpAddress(conn.Target) == ipAddress));
    }

    private int GetRelayedConnectionCountByKey(string remotePublicKey)
    {
        return RelayedConnections.Values.Count(conn =>
            conn.Initiator.RemotePublicKey == remotePublicKey ||
            (conn.Target != null && conn.Target.RemotePublicKey == remotePublicKey));
    }

    private string GetIpAddress(SyncSession session)
    {
        return ((IPEndPoint)session.Socket.RemoteEndPoint!).Address.ToString();
    }

    private static (string, string) GetOrderedKeyPair(string key1, string key2)
    {
        return string.CompareOrdinal(key1, key2) <= 0 ? (key1, key2) : (key2, key1);
    }

    internal bool TryReserveRelayPair(string initiatorPublicKey, string targetPublicKey, long connectionId, out (string, string) pair)
    {
        pair = GetOrderedKeyPair(initiatorPublicKey, targetPublicKey);
        return _activeRelayPairs.TryAdd(pair, connectionId);
    }

    internal void RemoveRelayPairByConnectionId(long connectionId)
    {
        var pairToRemove = default(KeyValuePair<(string, string), long>);
        foreach (var pair in _activeRelayPairs)
        {
            if (pair.Value == connectionId)
            {
                pairToRemove = pair;
                break;
            }
        }
        if (pairToRemove.Key != default)
        {
            _activeRelayPairs.TryRemove(pairToRemove.Key, out _);
        }
    }

    internal void RemoveRelayedConnection(long connectionId)
    {
        if (RelayedConnections.TryRemove(connectionId, out var connection))
            RemoveRelayPairByConnectionId(connectionId);
    }

    internal void RemoveRelayedConnectionsByPublicKey(string publicKey)
    {
        if (string.IsNullOrEmpty(publicKey))
            return;

        var connectionIds = RelayedConnections.Keys.ToList();
        foreach (var connId in connectionIds)
        {
            if (RelayedConnections.TryGetValue(connId, out var conn) &&
                conn != null &&
                ((conn.Initiator?.RemotePublicKey == publicKey) ||
                 (conn.Target?.RemotePublicKey == publicKey)))
            {
                RemoveRelayedConnection(connId);
            }
        }
    }

    private bool IsNotificationAllowed(string sourceKey, string targetKey)
    {
        if (sourceKey == targetKey)
            return true;

        HashSet<string>? current;
        lock (_notificationAllowList)
        {
            if (!_notificationAllowList.TryGetValue(targetKey, out current) || current == null)
                return false;
        }

        lock (current)
        {
            return current.Contains(sourceKey);
        }
    }

    public void SetNotificationAllowList(string sourceKey, HashSet<string> allowed, HashSet<string> disallowed)
    {
        HashSet<string>? current;
        lock (_notificationAllowList)
        {
            if (!_notificationAllowList.TryGetValue(sourceKey, out current) || current == null)
            {
                current = new HashSet<string>(StringComparer.Ordinal);
                _notificationAllowList[sourceKey] = current;
            }
        }

        lock (current)
        {
            foreach (var key in allowed)
                current.Add(key);

            foreach (var key in disallowed)
                current.Remove(key);
        }
    }

    public async Task SendPushNotificationAsync(string sourceKey, List<string> targetKeys, bool highPriority, int timeToLive_s, string data, Dictionary<string, string>? platformData = null)
    {
        var allowed = await DeviceTokenRepository.GetAllAsync(targetKeys.Where(target => IsNotificationAllowed(sourceKey, target)).ToList());

        var byApp = allowed.GroupBy(d => d.AppName);
        var tasks = new List<Task>();

        foreach (var appGroup in byApp)
        {
            var appName = appGroup.Key;
            var byPlatform = appGroup.GroupBy(d => d.Platform?.ToLowerInvariant());

            foreach (var platformGroup in byPlatform)
            {
                var tokens = platformGroup
                    .Select(d => d.Token)
                    .Where(t => !string.IsNullOrWhiteSpace(t))
                    .ToList();

                if (tokens.Count == 0)
                    continue;

                switch (platformGroup.Key)
                {
                    case "android":
                        tasks.Add(SendAndroidPushNotificationAsync(sourceKey, appName, tokens, highPriority, timeToLive_s, data, platformData));
                        break;
                }
            }
        }

        await Task.WhenAll(tasks);
    }

    private async Task SendAndroidPushNotificationAsync(string sourceKey, string appName, List<string> tokens, bool highPriority, int timeToLive_s, string data, Dictionary<string, string>? platformData = null)
    {
        if (_firebaseApps == null || !_firebaseApps.TryGetValue(appName, out var firebaseApp))
            return;

        if (Logger.WillLog(SyncShared.LogLevel.Info))
            Logger.Info<TcpSyncServer>($"Sent push notification (data: {data}).");

        platformData ??= new Dictionary<string, string>(StringComparer.Ordinal);
        var response = await FirebaseMessaging.GetMessaging(firebaseApp).SendEachAsync(tokens.Select(token => new Message()
        {
            Token = token,
            Android = new AndroidConfig
            {
                Priority = highPriority ? Priority.High : Priority.Normal,
                TimeToLive = TimeSpan.FromSeconds(timeToLive_s)
            },
            Data = new Dictionary<string, string>()
            {
                { "data", data }
            }
        }).ToList());

        if (Logger.WillLog(SyncShared.LogLevel.Error) && response.FailureCount > 0)
        {
            foreach (var resp in response.Responses)
            {
                if (resp.IsSuccess)
                    continue;

                Logger.Error<TcpSyncServer>("Failed to send push notification.", resp.Exception);
            }
        }
    }
}