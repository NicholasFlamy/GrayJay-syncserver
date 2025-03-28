namespace SyncServer;

public class RateInfo
{
    private readonly long _maxBytesPerSecond; // The allowed rate (e.g., 1MB/s)
    private long _tokens;                     // Current number of tokens
    private DateTime _lastUpdate;             // Time of the last update
    private readonly object _lock = new object();

    public RateInfo(long maxBytesPerSecond)
    {
        _maxBytesPerSecond = maxBytesPerSecond;
        _tokens = maxBytesPerSecond;
        _lastUpdate = DateTime.UtcNow;
    }

    public bool Update(long bytes, DateTime now)
    {
        lock (_lock)
        {
            // Refill tokens based on time elapsed
            TimeSpan elapsed = now - _lastUpdate;
            long refill = (long)(elapsed.TotalSeconds * _maxBytesPerSecond);
            _tokens = Math.Min(_maxBytesPerSecond, _tokens + refill);
            if (Logger.WillLog(LogLevel.Debug))
                Logger.Debug<RateInfo>($"Tokens after refill: {_tokens}");
            _lastUpdate = now;

            // Check if we have enough tokens to allow this transmission
            if (_tokens >= bytes)
            {
                if (Logger.WillLog(LogLevel.Debug))
                    Logger.Debug<RateInfo>($"Tokens after consumption: {_tokens}");
                _tokens -= bytes;
                return false; // Not over the limit
            }
            else
            {
                if (Logger.WillLog(LogLevel.Warning))
                    Logger.Warning<RateInfo>($"Tokens depleted: {_tokens}");
                return true; // Over the limit
            }
        }
    }
}