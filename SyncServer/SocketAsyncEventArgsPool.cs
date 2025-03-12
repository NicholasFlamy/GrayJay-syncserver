using System.Collections.Concurrent;
using System.Net.Sockets;

namespace SyncServer;

public class SocketAsyncEventArgsPool
{
    private readonly ConcurrentStack<SocketAsyncEventArgs> _pool;

    public SocketAsyncEventArgsPool(int capacity)
    {
        _pool = new ConcurrentStack<SocketAsyncEventArgs>();
    }

    public void Push(SocketAsyncEventArgs item)
    {
        if (item == null) 
            throw new ArgumentNullException(nameof(item));

        _pool.Push(item);
    }

    public SocketAsyncEventArgs Pop()
    {
        if (_pool.TryPop(out var args))
            return args;
        throw new InvalidOperationException("Pool is empty");
    }
}