using System.Buffers;
using System.Collections.Concurrent;
using System.Net.Sockets;
using System.Net;
using System.Text;

namespace SyncShared;

public static class Utilities
{
    public static long TotalRented = 0;
    public static long TotalReturned = 0;
/*
#if DEBUG
    private static ConcurrentDictionary<byte[], Guid> OutstandingBorrows = new ConcurrentDictionary<byte[], Guid>();
#endif*/

    public static string HexDump(this ReadOnlySpan<byte> data)
    {
        var lines = (int)Math.Ceiling((double)data.Length / 16);
        var builder = new StringBuilder(lines * (16 * 3 + 2 + 16 + 2));
        for (var l = 0; l < lines; l++)
        {
            var start = l * 16;
            var endExclusive = Math.Min(data.Length, (l + 1) * 16);
            for (var i = start; i < endExclusive; i++)
                builder.AppendFormat("{0:X2} ", data[i]);
            var remainder = 16 - (endExclusive - start);
            for (var i = 0; i < remainder; i++)
                builder.Append("   ");
            builder.AppendFormat("; ");
            for (var i = start; i < endExclusive; i++)
            {
                var b = data[i];
                if (b >= 0x20 && b <= 0x7E)
                    builder.Append(Encoding.ASCII.GetString([b]));
                else
                    builder.Append(".");
            }
            if (l < lines - 1)
                builder.AppendLine();
        }
        return builder.ToString();
    }

    public static byte[] GetLimitedUtf8Bytes(string? str, int maxByteLength)
    {
        if (str == null)
            return Array.Empty<byte>();
    
        if (str == null) throw new ArgumentNullException(nameof(str));
        if (maxByteLength < 0) throw new ArgumentOutOfRangeException(nameof(maxByteLength));

        byte[] bytes = Encoding.UTF8.GetBytes(str);
        if (bytes.Length <= maxByteLength)
            return bytes;

        int truncateAt = maxByteLength;
        while (truncateAt > 0 && (bytes[truncateAt] & 0xC0) == 0x80) // Continuation byte: 10xxxxxx
            truncateAt--;

        byte[] truncatedBytes = new byte[truncateAt];
        Array.Copy(bytes, truncatedBytes, truncateAt);
        return truncatedBytes;
    }

    public static byte[] RentBytes(int minimumSize)
    {
        var rentedBytes = ArrayPool<byte>.Shared.Rent(minimumSize);
        Interlocked.Add(ref TotalRented, rentedBytes.Length);

        if (Logger.WillLog(LogLevel.Debug))
        {
/*#if DEBUG
            var id = Guid.NewGuid();
            OutstandingBorrows[rentedBytes] = id;
            Logger.Debug(nameof(Utilities), $"Rented {rentedBytes.Length} bytes (requested: {minimumSize}, total rented: {TotalRented}, total returned: {TotalReturned}, delta: {TotalRented - TotalReturned}) with id {id}:\n{Environment.StackTrace}");
#else*/
            Logger.Debug(nameof(Utilities), $"Rented {rentedBytes.Length} bytes (requested: {minimumSize}, total rented: {TotalRented}, total returned: {TotalReturned}, delta: {TotalRented - TotalReturned})");
//#endif
        }

        return rentedBytes;
    }

    public static void ReturnBytes(byte[] rentedBytes, bool clearArray = false)
    {
        Interlocked.Add(ref TotalReturned, rentedBytes.Length);
        ArrayPool<byte>.Shared.Return(rentedBytes, clearArray);

        if (Logger.WillLog(LogLevel.Debug))
        {
/*#if DEBUG
            OutstandingBorrows.TryRemove(rentedBytes, out var id);
            Logger.Debug(nameof(Utilities), $"Returned {rentedBytes.Length} bytes (total rented: {TotalRented}, total returned: {TotalReturned}, delta: {TotalRented - TotalReturned}) with id {id}");
            foreach (var outstandingBorrow in OutstandingBorrows)
                Logger.Debug(nameof(Utilities), $"Outstanding borrow ({outstandingBorrow.Value}).");
#else*/
            Logger.Debug(nameof(Utilities), $"Returned {rentedBytes.Length} bytes (total rented: {TotalRented}, total returned: {TotalReturned}, delta: {TotalRented - TotalReturned})");
//#endif
        }
    }

    public static Socket OpenTcpSocket(string host, int port)
    {
        if (string.IsNullOrWhiteSpace(host))
            throw new ArgumentException("Host cannot be null, empty, or whitespace.", nameof(host));

        if (port < IPEndPoint.MinPort || port > IPEndPoint.MaxPort)
            throw new ArgumentOutOfRangeException(nameof(port), $"Port must be between {IPEndPoint.MinPort} and {IPEndPoint.MaxPort}.");

        IPAddress[] addresses;
        try
        {
            if (IPAddress.TryParse(host, out IPAddress? ipLiteral) && ipLiteral != null)
                addresses = new[] { ipLiteral };
            else
            {
                addresses = Dns.GetHostAddresses(host);
                if (addresses == null || addresses.Length == 0)
                    throw new SocketException((int)SocketError.HostNotFound);
            }
        }
        catch (Exception ex)
        {
            throw new Exception($"Could not resolve host '{host}'.", ex);
        }

        addresses = addresses
            .OrderBy(a => a.AddressFamily == AddressFamily.InterNetwork ? 0 : 1)
            .ToArray();

        var connectionExceptions = new List<Exception>();
        foreach (IPAddress address in addresses)
        {
            string endpoint = $"{address}:{port}";
            try
            {
                var socket = new Socket(address.AddressFamily, SocketType.Stream, ProtocolType.Tcp)
                {
                    SendTimeout = 5000,
                    ReceiveTimeout = 5000
                };

                socket.Connect(new IPEndPoint(address, port));
                if (socket.Connected)
                    return socket;
            }
            catch (Exception connectEx)
            {
                connectionExceptions.Add(connectEx);
            }
        }

        string triedList = string.Join(", ", addresses.Select(a => $"{a}:{port}"));
        var finalEx = new Exception($"Could not connect to any resolved address for '{host}' on port {port}. Tried: {triedList}");
        throw new AggregateException(connectionExceptions);
    }
}
