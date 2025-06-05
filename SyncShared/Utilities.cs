using System.Buffers;
using System.Collections.Concurrent;
using System.Net.Sockets;
using System.Net;
using System.Text;
using System.Net.NetworkInformation;

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

    public static async Task<Socket> OpenTcpSocketAsync(string host, int port, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(host))
            throw new ArgumentException("Host cannot be null or whitespace.", nameof(host));

        if (port < IPEndPoint.MinPort || port > IPEndPoint.MaxPort)
            throw new ArgumentOutOfRangeException(nameof(port), $"Port must be between {IPEndPoint.MinPort} and {IPEndPoint.MaxPort}.");

        IPAddress[] addresses;
        try
        {
            addresses = IPAddress.TryParse(host, out var ip)
                ? new[] { ip }
                : await Dns.GetHostAddressesAsync(host, cancellationToken);

            if (addresses.Length == 0)
                throw new SocketException((int)SocketError.HostNotFound);
        }
        catch (Exception ex)
        {
            throw new Exception($"Could not resolve host '{host}'.", ex);
        }

        addresses = addresses.OrderBy(ip => ip.AddressFamily == AddressFamily.InterNetwork ? 0 : 1).ToArray();

        var cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        var connectTasks = addresses.Select(addr => ConnectToAddressAsync(addr, port, cts.Token)).ToList();
        var exceptions = new List<Exception>();

        while (connectTasks.Count > 0)
        {
            var completed = await Task.WhenAny(connectTasks);
            connectTasks.Remove(completed);

            if (completed.Status == TaskStatus.RanToCompletion)
            {
                var socket = completed.Result;
                cts.Cancel();
                await Task.WhenAll(connectTasks); // Let others finish before accessing their results

                foreach (var t in connectTasks)
                {
                    if (t.Status == TaskStatus.RanToCompletion)
                        t.Result.Dispose();
                }

                return socket;
            }

            if (completed.Exception != null)
                exceptions.AddRange(completed.Exception.InnerExceptions);
        }

        string tried = string.Join(", ", addresses.Select(a => $"{a}:{port}"));
        throw new AggregateException(
            $"Could not connect to any resolved address for '{host}' on port {port}. Tried: {tried}",
            exceptions
        );
    }

    private static async Task<Socket> ConnectToAddressAsync(IPAddress address, int port, CancellationToken token)
    {
        var socket = new Socket(address.AddressFamily, SocketType.Stream, ProtocolType.Tcp)
        {
            SendTimeout = 10000,
            ReceiveTimeout = 10000
        };

        using var reg = token.Register(() => { try { socket.Dispose(); } catch { } });

        try
        {
            await socket.ConnectAsync(new IPEndPoint(address, port), token);
            return socket;
        }
        catch
        {
            socket.Dispose();
            throw;
        }
    }

    public static List<IPAddress> FindCandidateAddresses()
    {
        var candidates = NetworkInterface.GetAllNetworkInterfaces()
            .Where(IsUsableInterface)
            .SelectMany(nic =>
                nic.GetIPProperties().UnicastAddresses
                    .Where(ua => IsUsableAddress(ua.Address))
                    .Select(ua => (nic, ua)))
            .ToList();

        return candidates
            .OrderBy(t => AddressScore(t.ua.Address))
            .ThenBy(t => InterfaceScore(t.nic))
            .ThenByDescending(t => t.ua.PrefixLength)
            .ThenByDescending(t => GetInterfaceMtuSafe(t.nic))
            .Select(t => t.ua.Address)
            .ToList();
    }

    private static bool IsUsableInterface(NetworkInterface nic)
    {
        var name = nic.Name.ToLowerInvariant();

        if (nic.OperationalStatus != OperationalStatus.Up)
            return false;

        if (nic.NetworkInterfaceType == NetworkInterfaceType.Loopback ||
            nic.NetworkInterfaceType == NetworkInterfaceType.Tunnel)
            return false;

        if (string.IsNullOrWhiteSpace(nic.GetPhysicalAddress()?.ToString()))
            return false;

        return !(
            name.StartsWith("docker") ||
            name.StartsWith("veth") ||
            name.StartsWith("br-") ||
            name.StartsWith("virbr") ||
            name.StartsWith("vmnet") ||
            name.StartsWith("tun") ||
            name.StartsWith("tap"));
    }

    private static bool IsUsableAddress(IPAddress addr)
    {
        return !(IPAddress.IsLoopback(addr)
            || addr.IsIPv6LinkLocal
            || addr.IsIPv6Multicast
            || addr.Equals(IPAddress.Any)
            || addr.Equals(IPAddress.IPv6Any));
    }

    private static int InterfaceScore(NetworkInterface nic)
    {
        var name = nic.Name.ToLowerInvariant();

        if (System.Text.RegularExpressions.Regex.IsMatch(name, "^(eth|enp|eno|ens|em)\\d+") ||
            name.StartsWith("eth") ||
            name.Contains("ethernet"))
            return 0;

        if (System.Text.RegularExpressions.Regex.IsMatch(name, "^(wlan|wlp)\\d+") ||
            name.Contains("wi-fi") || name.Contains("wifi"))
            return 1;

        return 2;
    }

    private static int AddressScore(IPAddress addr)
    {
        if (addr.AddressFamily == AddressFamily.InterNetwork)
        {
            var bytes = addr.GetAddressBytes();
            if (bytes[0] == 10 ||
                (bytes[0] == 192 && bytes[1] == 168) ||
                (bytes[0] == 172 && bytes[1] >= 16 && bytes[1] <= 31))
                return 0; // Private IPv4
            return 1; // Public IPv4
        }

        if (addr.AddressFamily == AddressFamily.InterNetworkV6)
        {
            byte b0 = addr.GetAddressBytes()[0];
            if ((b0 & 0xFE) == 0xFC) return 2; // ULA (fc00::/7)
            if ((b0 & 0xE0) == 0x20) return 3; // Global
            return 4;
        }

        return int.MaxValue;
    }

    private static int GetInterfaceMtuSafe(NetworkInterface nic)
    {
        try
        {
            return nic.GetIPProperties()?.GetIPv4Properties()?.Mtu ?? 0;
        }
        catch
        {
            return 0;
        }
    }
}
