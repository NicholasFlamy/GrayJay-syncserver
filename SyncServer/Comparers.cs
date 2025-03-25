namespace SyncServer;

internal class ByteArrayComparer : IEqualityComparer<byte[]>
{
    public bool Equals(byte[]? x, byte[]? y)
    {
        if (x == null && y == null) return true;
        if (x == null || y == null) return false;
        return x.SequenceEqual(y);
    }

    public int GetHashCode(byte[]? obj)
    {
        if (obj == null) return 0;
        return obj.Aggregate(17, (current, b) => current * 23 + b);
    }
}
