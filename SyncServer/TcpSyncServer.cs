using Noise;
using SyncServer.Repositories;
using SyncShared;
using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using System.Text.Json.Serialization;
using static SyncServer.SyncSession;
using static SyncServer.TcpSyncServer;
using LogLevel = SyncShared.LogLevel;

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

    private Socket? _listenSocket;
    public readonly SemaphoreSlim MaxConnections;
    private readonly ConcurrentDictionary<Socket, SyncSession> _clients = new();
    public int ClientCount => _clients.Count;
    private readonly ConcurrentDictionary<string, SyncSession> _sessions = new();
    public int SessionCount => _sessions.Count;
    private readonly KeyPair _keyPair;
    public KeyPair LocalKeyPair => _keyPair;
    private readonly ConcurrentDictionary<(string, string), byte[]> _connectionInfoStore = new();
    public readonly ConcurrentDictionary<long, RelayedConnection> RelayedConnections = new();
    private ConcurrentDictionary<(string, string), DateTime> _relayBlacklist = new ConcurrentDictionary<(string, string), DateTime>();

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
    private static readonly TimeSpan HandshakeWindow = TimeSpan.FromMinutes(1);
    private const int MaxHandshakesPerWindow = 20;
    private static readonly TimeSpan HandshakeBlacklistDuration = TimeSpan.FromMinutes(1);

    private readonly int _port;
    public int Port => (_listenSocket?.LocalEndPoint as IPEndPoint)?.Port ?? _port;
    private int _nextConnectionId = 0;
    public IRecordRepository RecordRepository { get; }

    public readonly TcpSyncServerMetrics Metrics;

    public bool _useRateLimits;

    public TcpSyncServer(int port, KeyPair keyPair, IRecordRepository recordRepository, int maxConnections = MAX_CONNECTIONS, bool useRateLimits = true)
    {
        Metrics = new TcpSyncServerMetrics(this);
        _port = port;
        MaxConnections = new SemaphoreSlim(maxConnections, maxConnections);
        _keyPair = keyPair;
        RecordRepository = recordRepository;
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
            var keysToRemove = _connectionInfoStore.Keys.Where(k => k.Item1 == remotePublicKey).ToList();
            foreach (var key in keysToRemove)
                _connectionInfoStore.TryRemove(key, out _);
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
        _connectionInfoStore[(publicKey, intendedPublicKey)] = encryptedBlob;
    }

    public byte[]? RetrieveConnectionInfo(string targetPublicKey, string requestingPublicKey)
    {
        if (_connectionInfoStore.TryGetValue((targetPublicKey, requestingPublicKey), out byte[]? block))
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
        _listenSocket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
        _listenSocket.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, true);
        _listenSocket.NoDelay = true;
        _listenSocket.ReceiveBufferSize = MAXIMUM_PACKET_SIZE_ENCRYPTED;
        _listenSocket.SendBufferSize = MAXIMUM_PACKET_SIZE_ENCRYPTED;
        _listenSocket.Bind(new IPEndPoint(IPAddress.Any, _port));
        _listenSocket.Listen(1000);

        Logger.Info<TcpSyncServer>("Server started. Listening on port 9000...");

        _ = Task.Run(async () =>
        {
            try
            {
                while (true)
                {
                    await Task.Delay(_acceptDelay);

                    MaxConnections.Wait();
                    var clientSocket = await _listenSocket.AcceptAsync();
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
                        //Small buffer for handshake
                        clientSocket.ReceiveBufferSize = 1024;
                        clientSocket.SendBufferSize = 1024;
                        clientSocket.NoDelay = true;

                        session = new SyncSession(this, (s) =>
                        {
                            s.Socket.ReceiveBufferSize = MAXIMUM_PACKET_SIZE_ENCRYPTED;
                            s.Socket.SendBufferSize = MAXIMUM_PACKET_SIZE_ENCRYPTED;

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
        });
    }

    public bool IsBlacklisted(string initiator, string target)
    {
        if (_relayBlacklist.TryGetValue((initiator, target), out DateTime expiration))
        {
            if (DateTime.UtcNow < expiration)
            {
                return true; // Still blacklisted
            }
            else
            {
                // Expired, remove from blacklist
                _relayBlacklist.TryRemove((initiator, target), out _);
                return false;
            }
        }
        return false; // Not blacklisted
    }

    public void AddToBlacklist(string initiator, string target, TimeSpan duration)
    {
        DateTime expiration = DateTime.UtcNow + duration;
        _relayBlacklist[(initiator, target)] = expiration;
    }

    public void Dispose()
    {
        try
        {
            _listenSocket?.Close();
            foreach (var client in _clients.Values)
                client.Dispose();
        }
        catch (Exception ex)
        {
            Logger.Error<TcpSyncServer>($"Shutdown error", ex);
        }
        finally
        {
            _listenSocket?.Dispose();
            _listenSocket = null;
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
}