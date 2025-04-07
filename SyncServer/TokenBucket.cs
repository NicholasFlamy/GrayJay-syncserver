namespace SyncServer;

public class TokenBucket
{
    private readonly double _capacity;
    private readonly double _tokensPerSecond;
    private double _tokens;
    private long _lastRefillTicks;

    public TokenBucket(double capacity, double tokensPerSecond)
    {
        _capacity = capacity;
        _tokensPerSecond = tokensPerSecond;
        _tokens = capacity;
        _lastRefillTicks = DateTime.UtcNow.Ticks;
    }

    public bool TryConsume(double tokens)
    {
        long nowTicks = DateTime.UtcNow.Ticks;
        long elapsedTicks;
        
        unchecked
        {
            elapsedTicks = nowTicks - Interlocked.Read(ref _lastRefillTicks);
            if (elapsedTicks > 0)
            {
                double elapsedSeconds = elapsedTicks / (double)TimeSpan.TicksPerSecond;
                double newTokens = elapsedSeconds * _tokensPerSecond;
                double currentTokens = Interlocked.CompareExchange(ref _tokens, 0, 0);
                double updatedTokens = Math.Min(_capacity, currentTokens + newTokens);
                Interlocked.CompareExchange(ref _tokens, updatedTokens, currentTokens);
                Interlocked.CompareExchange(ref _lastRefillTicks, nowTicks, nowTicks - elapsedTicks);
            }
        }

        double availableTokens = Interlocked.CompareExchange(ref _tokens, 0, 0);
        if (availableTokens >= tokens)
        {
            double newTokens = availableTokens - tokens;
            return Interlocked.CompareExchange(ref _tokens, newTokens, availableTokens) == availableTokens;
        }
        return false;
    }
}