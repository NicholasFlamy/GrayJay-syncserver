using Noise;
using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;

namespace SyncServer;

public class TcpSyncServer
{
    private static readonly Protocol NoiseProtocol = new Protocol(
        HandshakePattern.IK,
        CipherFunction.ChaChaPoly,
        HashFunction.Blake2b
    );

    private const int MaxConnections = 1000;
    private const int BufferSize = 1024;
    private const int MaxPacketSizeEncrypted = 65535;
    private const int CURRENT_VERSION = 3;

    private Socket? _listenSocket;
    private readonly SemaphoreSlim _maxConnections;
    private readonly SocketAsyncEventArgsPool _readWritePool;
    private readonly ConcurrentDictionary<Socket, SyncSession> _clients = new();
    private readonly KeyPair _keyPair;
    private readonly ConcurrentDictionary<(string, string), byte[]> _connectionInfoStore = new();

    public TcpSyncServer(KeyPair keyPair)
    {
        _maxConnections = new SemaphoreSlim(MaxConnections, MaxConnections);
        _readWritePool = new SocketAsyncEventArgsPool(MaxConnections);
        _keyPair = keyPair;
        InitializeBufferPool();
    }

    public void StoreConnectionInfo(string publicKey, string intendedPublicKey, byte[] encryptedBlob)
    {
        _connectionInfoStore[(publicKey, intendedPublicKey)] = encryptedBlob;
    }

    public byte[]? RetrieveConnectionInfo(string publicKey, string intendedPublicKey)
    {
        if (_connectionInfoStore.TryGetValue((publicKey, intendedPublicKey), out byte[]? block))
            return block;
        return null;
    }

    private void InitializeBufferPool()
    {
        for (int i = 0; i < MaxConnections; i++)
        {
            var args = new SocketAsyncEventArgs();
            args.SetBuffer(new byte[BufferSize], 0, BufferSize);
            args.Completed += IO_Completed;
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
        _listenSocket.Bind(new IPEndPoint(IPAddress.Any, 9000));
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
            Logger.Error<TcpSyncServer>($"Accept error: {e.SocketError}");
            e.AcceptSocket = null;
            StartAccept();
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

            var readArgs = _readWritePool.Pop();
            var writeArgs = _readWritePool.Pop();
            var session = new SyncSession(this)
            {
                Socket = clientSocket,
                ReadArgs = readArgs,
                WriteArgs = writeArgs,
                HandshakeState = NoiseProtocol.Create(false, s: _keyPair.PrivateKey)
            };
            readArgs.UserToken = session;
            writeArgs.UserToken = session;
            _clients.TryAdd(clientSocket, session);

            Logger.Info<TcpSyncServer>($"Client connected: {clientSocket.RemoteEndPoint}");

            session.Send([CURRENT_VERSION, 0, 0, 0]);

            readArgs.SetBuffer(new byte[1024], 0, 1024);
            bool pending = clientSocket.ReceiveAsync(readArgs);
            if (!pending)
                OnReceiveCompleted(session, readArgs.BytesTransferred);
        }
        catch (Exception ex)
        {
            Logger.Error<TcpSyncServer>($"Accept processing error: {ex.Message}");
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
        session.HandleData(bytesReceived);

        bool pending = session.Socket!.ReceiveAsync(session.ReadArgs!);
        if (!pending)
            OnReceiveCompleted(session, session.ReadArgs!.BytesTransferred);
    }

    private void OnSendCompleted(SyncSession session, int bytesSent)
    {
        if (Logger.WillLog(LogLevel.Debug))
            Logger.Debug<TcpSyncServer>($"Sent {bytesSent} bytes.");

        session.OnWriteCompleted();
    }

    private void IO_Completed(object? sender, SocketAsyncEventArgs e)
    {
        var session = e.UserToken as SyncSession;
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
                        OnReceiveCompleted(session, e.BytesTransferred);
                        break;
                    case SocketAsyncOperation.Send:
                        OnSendCompleted(session, e.BytesTransferred);
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
        Socket socket = session.Socket;
        try
        {
            socket.Shutdown(SocketShutdown.Both);
        }
        catch { }
        socket.Close();

        _clients.TryRemove(socket, out _);
        if (session.ReadArgs != null)
            _readWritePool.Push(session.ReadArgs);
        if (session.WriteArgs != null)
            _readWritePool.Push(session.WriteArgs);
        session.Dispose();
        _maxConnections.Release();

        Logger.Info<TcpSyncServer>($"Client disconnected: {socket.RemoteEndPoint}");
    }

    public void Stop()
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
    }
}