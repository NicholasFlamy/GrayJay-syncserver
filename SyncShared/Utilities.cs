using System.Buffers;
using System.Text;

namespace SyncShared;

public static class Utilities
{
    private static long _totalRented = 0;
    public static long _totalReturned = 0;

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

    public static byte[] GetLimitedUtf8Bytes(string str, int maxByteLength)
    {
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
        if (Logger.WillLog(LogLevel.Debug))
        {
            _totalRented += rentedBytes.Length;
            Logger.Debug(nameof(Utilities), $"Rented {rentedBytes.Length} bytes (requested: {minimumSize}, total rented: {_totalRented}, total returned: {_totalReturned})");
        }
        return rentedBytes;
    }

    public static void ReturnBytes(byte[] rentedBytes, bool clearArray = false)
    {
        if (Logger.WillLog(LogLevel.Debug))
        {
            _totalReturned += rentedBytes.Length;
            Logger.Debug(nameof(Utilities), $"Returned {rentedBytes.Length} bytes (total rented: {_totalRented}, total returned: {_totalReturned})");
        }
        ArrayPool<byte>.Shared.Return(rentedBytes, clearArray);
    }
}
