using System.Buffers;
using System.Collections.Concurrent;
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
}
