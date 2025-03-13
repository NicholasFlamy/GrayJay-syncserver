using System.Text;

namespace SyncShared;

public static class Utilities
{
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
}
