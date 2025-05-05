using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SyncShared;

public static class Extensions
{
    public static byte[] DecodeBase64(this string base64)
    {
        if (base64.Length == 0)
            return new byte[0];
        int padding = 4 - (base64.Length % 4);
        if (padding < 4)
            base64 += new string('=', padding);
        return Convert.FromBase64String(base64);
    }

    public static byte[] DecodeBase64Url(this string base64)
    {
        if (base64.Length == 0)
            return new byte[0];
        base64 = base64.Replace('-', '+').Replace('_', '/');
        int padding = 4 - (base64.Length % 4);
        if (padding < 4)
            base64 += new string('=', padding);
        return Convert.FromBase64String(base64);
    }

    public static string EncodeBase64(this byte[] bytes)
    {
        if (bytes == null)
            throw new ArgumentNullException(nameof(bytes));
        return Convert.ToBase64String(bytes);
    }

    public static string EncodeBase64Url(this byte[] bytes)
    {
        if (bytes == null)
            throw new ArgumentNullException(nameof(bytes));
        string base64 = Convert.ToBase64String(bytes);
        base64 = base64.Replace('+', '-').Replace('/', '_');
        return base64.TrimEnd('=');
    }
}
