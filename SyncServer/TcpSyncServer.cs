using Noise;
using SyncServer.Repositories;
using SyncShared;
using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;
using static SyncServer.SyncSession;

namespace SyncServer;

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

    private const int MaxConnections = 1000;
    private const int BufferSize = 1024;

    private Socket? _listenSocket;
    private readonly SemaphoreSlim _maxConnections;
    private readonly int _maxConnectionCount;
    private readonly SocketAsyncEventArgsPool _readWritePool;
    private readonly ConcurrentDictionary<Socket, SyncSession> _clients = new();
    private readonly ConcurrentDictionary<string, SyncSession> _sessions = new();
    private readonly KeyPair _keyPair;
    private readonly ConcurrentDictionary<(string, string), byte[]> _connectionInfoStore = new();
    private readonly ConcurrentDictionary<long, RelayedConnection> _relayedConnections = new();
    private readonly int _port;
    public int Port => (_listenSocket?.LocalEndPoint as IPEndPoint)?.Port ?? _port;
    private int _nextConnectionId = 0;
    public IRecordRepository RecordRepository { get; }

    public TcpSyncServer(int port, KeyPair keyPair, IRecordRepository recordRepository, int maxConnections = MaxConnections)
    {
        _port = port;
        _maxConnectionCount = maxConnections;
        _maxConnections = new SemaphoreSlim(maxConnections, maxConnections);
        _readWritePool = new SocketAsyncEventArgsPool(2 * maxConnections);
        _keyPair = keyPair;
        RecordRepository = recordRepository;
        InitializeBufferPool();
    }

    public int GetNextConnectionId() => Interlocked.Increment(ref _nextConnectionId);
    public void SetRelayedConnection(long connectionId, SyncSession initiator, SyncSession? target = null, bool isActive = false)
    {
        _relayedConnections[connectionId] = new RelayedConnection
        {
            Initiator = initiator,
            Target = target,
            IsActive = isActive
        };
    }
    public void RemoveRelayedConnection(long connectionId)
    {
        _relayedConnections.TryRemove(connectionId, out _);
    }

    public RelayedConnection? GetRelayedConnection(long connectionId)
    {
        _relayedConnections.TryGetValue(connectionId, out var connection);
        return connection;
    }

    public void OnSessionClosed(SyncSession session)
    {
        foreach (var kvp in _relayedConnections.ToArray())
        {
            var connection = kvp.Value;
            if (connection.Initiator == session || connection.Target == session)
            {
                _relayedConnections.TryRemove(kvp.Key, out _);
                var otherSession = connection.Initiator == session ? connection.Target : connection.Initiator;
                if (otherSession != null)
                {
                    var notification = new byte[8];
                    BinaryPrimitives.WriteInt64LittleEndian(notification, kvp.Key);
                    otherSession.Send(Opcode.RELAYED_DATA, 1, notification);
                }
            }
        }
    }

    public void RemoveSession(SyncSession session)
    {
        var remotePublicKey = session.RemotePublicKey;
        if (remotePublicKey != null && _sessions.TryRemove(remotePublicKey, out _))
        {
            foreach (var kvp in _relayedConnections.ToArray())
            {
                if (kvp.Value.Initiator == session || kvp.Value.Target == session)
                {
                    _relayedConnections.TryRemove(kvp.Key, out _);
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

    private void InitializeBufferPool()
    {
        for (int i = 0; i < 2 * _maxConnectionCount; i++)
        {
            var args = new SocketAsyncEventArgs();
            args.SetBuffer(new byte[BufferSize], 0, BufferSize);
            args.Completed += IO_Completed;
            args.UserToken = new ArgsPair();
            _readWritePool.Push(args);
        }
    }

    public void Start()
    {
        _listenSocket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
        _listenSocket.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, true);
        _listenSocket.NoDelay = true;
        _listenSocket.ReceiveBufferSize = BufferSize;
        _listenSocket.SendBufferSize = BufferSize;
        _listenSocket.Bind(new IPEndPoint(IPAddress.Any, _port));
        _listenSocket.Listen(1000);

        Logger.Info<TcpSyncServer>("Server started. Listening on port 9000...");
        StartAccept();
    }

    private void StartAccept()
    {
        var acceptEventArg = new SocketAsyncEventArgs();
        acceptEventArg.Completed += Accept_Completed;

        bool pending = _listenSocket!.AcceptAsync(acceptEventArg);
        if (!pending)
            ProcessAccept(acceptEventArg);
    }

    private void Accept_Completed(object? sender, SocketAsyncEventArgs e)
    {
        ProcessAccept(e);
    }

    private void ProcessAccept(SocketAsyncEventArgs e)
    {
        if (e.SocketError != SocketError.Success)
        {
            Logger.Error<TcpSyncServer>($"Accept error, stopped accepting sockets: {e.SocketError}");
            return;
        }

        try
        {
            _maxConnections.Wait();
            var clientSocket = e.AcceptSocket;
            if (clientSocket == null)
            {
                Logger.Info<TcpSyncServer>("Accepted socket is null.");
                _maxConnections.Release();
                return;
            }

            if (_readWritePool.IsEmpty)
                throw new Exception("Read write pool should never be empty because maxConnections should block");

            var readArgs = _readWritePool.Pop();
            var writeArgs = _readWritePool.Pop();
            var session = new SyncSession(this, (s) => _sessions[s.RemotePublicKey!] = s)
            {
                Socket = clientSocket,
                ReadArgs = readArgs,
                WriteArgs = writeArgs,
                HandshakeState = NoiseProtocol.Create(false, s: _keyPair.PrivateKey)
            };
            ((ArgsPair)readArgs.UserToken!).Session = session;
            ((ArgsPair)writeArgs.UserToken!).Session = session;
            _clients.TryAdd(clientSocket, session);

            Logger.Info<TcpSyncServer>($"Client connected: {clientSocket.RemoteEndPoint}");

            session.SendVersion();

            readArgs.SetBuffer(new byte[1024], 0, 1024);
            bool pending = clientSocket.ReceiveAsync(readArgs);
            if (!pending)
                ThreadPool.QueueUserWorkItem((_) => OnReceiveCompleted(session, readArgs.BytesTransferred));
        }
        catch (Exception ex)
        {
            Logger.Error<TcpSyncServer>($"Accept processing error: {ex.Message}");
            _maxConnections.Release();
        }
        finally
        {
            e.AcceptSocket = null;
            bool acceptPending = _listenSocket!.AcceptAsync(e);
            if (!acceptPending)
                ProcessAccept(e);
        }
    }

    private void OnReceiveCompleted(SyncSession session, int bytesReceived)
    {
        try
        {
            if (Logger.WillLog(LogLevel.Debug))
                Logger.Debug<TcpSyncServer>($"Received {bytesReceived} bytes.");

            if (bytesReceived == 0)
            {
                Logger.Info<TcpSyncServer>($"OnReceiveCompleted (bytesReceived = {bytesReceived}) soft disconnect.");
                CloseConnection(session);
                return;
            }

            session.HandleData(bytesReceived);

            bool pending = session.Socket!.ReceiveAsync(session.ReadArgs!);
            if (!pending)
                OnReceiveCompleted(session, session.ReadArgs!.BytesTransferred);
        }
        catch (Exception e)
        {
            Logger.Error<TcpSyncServer>($"OnReceiveCompleted (bytesReceived = {bytesReceived}) unhandled exception.", e);
            CloseConnection(session);
        }
    }

    private void OnSendCompleted(SyncSession session, int bytesSent)
    {
        try
        {
            if (Logger.WillLog(LogLevel.Debug))
                Logger.Debug<TcpSyncServer>($"Sent {bytesSent} bytes.");

            if (bytesSent == 0)
            {
                Logger.Info<TcpSyncServer>($"OnSendCompleted (bytesSent = {bytesSent}) soft disconnect.");
                CloseConnection(session);
                return;
            }

            session.OnWriteCompleted();
        }
        catch (Exception e)
        {
            Logger.Error<TcpSyncServer>($"OnSendCompleted (bytesSent = {bytesSent}) unhandled exception.", e);
            CloseConnection(session);
        }
    }

    private void IO_Completed(object? sender, SocketAsyncEventArgs e)
    {
        var argsPair = (ArgsPair)e.UserToken!;
        var session = argsPair.Session;
        if (session == null || session.Socket == null)
        {
            Logger.Info<TcpSyncServer>("Session or socket is null in IO_Completed.");
            return;
        }

        ThreadPool.QueueUserWorkItem((_) =>
        {
            try
            {
                if (e.SocketError != SocketError.Success)
                {
                    CloseConnection(session);
                    return;
                }

                switch (e.LastOperation)
                {
                    case SocketAsyncOperation.Receive:
                        if (e.BytesTransferred == 0)
                        {
                            Logger.Error<TcpSyncServer>($"Soft disconnect");
                            CloseConnection(session);
                        }
                        else
                        {
                            OnReceiveCompleted(session, e.BytesTransferred);
                        }
                        break;
                    case SocketAsyncOperation.Send:
                        if (e.BytesTransferred == 0)
                        {
                            Logger.Error<TcpSyncServer>($"Soft disconnect");
                            CloseConnection(session);
                        }
                        else
                        {
                            OnSendCompleted(session, e.BytesTransferred);
                        }                        
                        break;
                    default:
                        throw new InvalidOperationException("Unexpected operation");
                }
            }
            catch (Exception ex)
            {
                Logger.Error<TcpSyncServer>($"IO_Completed error: {ex.Message}");
                CloseConnection(session);
            }
        });
    }

    private void CloseConnection(SyncSession? session)
    {
        if (session == null || session.Socket == null)
        {
            Logger.Info<TcpSyncServer>("Session or socket is null in CloseConnection.");
            return;
        }

        bool removed = _clients.TryRemove(session.Socket, out _);
        session.Socket.Dispose();
        var remotePublicKey = session?.RemotePublicKey;
        if (remotePublicKey != null)
        {
            _sessions.TryRemove(remotePublicKey, out _);
            var keysToRemove = _connectionInfoStore.Keys.Where(k => k.Item1 == remotePublicKey).ToList();
            foreach (var key in keysToRemove)
                _connectionInfoStore.TryRemove(key, out _);
        }

        foreach (var kvp in _relayedConnections.ToArray())
        {
            var connection = kvp.Value;
            if (connection.Initiator == session || connection.Target == session)
            {
                if (_relayedConnections.TryRemove(kvp.Key, out _))
                {
                    var otherSession = connection.Initiator == session ? connection.Target : connection.Initiator;
                    if (otherSession != null && otherSession.PrimaryState != SessionPrimaryState.Closed)
                    {
                        var notification = new byte[8];
                        BinaryPrimitives.WriteInt64LittleEndian(notification, kvp.Key);
                        otherSession.Send(Opcode.RELAYED_DATA, 1, notification);
                    }
                }
            }
        }

        if (session?.ReadArgs != null)
            _readWritePool.Push(session.ReadArgs);
        if (session?.WriteArgs != null)
            _readWritePool.Push(session.WriteArgs);
        session?.Dispose();

        try
        {
            if (removed)
                _maxConnections.Release();
        }
        catch (Exception e)
        {
            Logger.Warning<TcpSyncServer>("Failed to release max connections", e);
        }

        Logger.Info<TcpSyncServer>($"Client disconnected");
    }

    public void Dispose()
    {
        try
        {
            _listenSocket?.Close();
            foreach (var client in _clients.Values)
            {
                CloseConnection(client);
            }
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

        _maxConnections.Dispose();
    }
}