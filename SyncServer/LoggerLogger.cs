namespace SyncServer;

public class LoggerLogger : ILogger
{
    private readonly string _category;

    public LoggerLogger(string category)
    {
        _category = category;
    }

    public void Log<TState>(Microsoft.Extensions.Logging.LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter)
    {
        if (!IsEnabled(logLevel))
            return;

        string message = formatter(state, exception);
        switch (logLevel)
        {
            case Microsoft.Extensions.Logging.LogLevel.Trace:
                Logger.Debug(_category, message, exception); // Trace -> Debug
                break;
            case Microsoft.Extensions.Logging.LogLevel.Debug:
                Logger.Debug(_category, message, exception); // Debug -> Debug
                break;
            case Microsoft.Extensions.Logging.LogLevel.Information:
                Logger.Verbose(_category, message, exception); // Information -> Verbose
                break;
            case Microsoft.Extensions.Logging.LogLevel.Warning:
                Logger.Warning(_category, message, exception); // Warning -> Warning
                break;
            case Microsoft.Extensions.Logging.LogLevel.Error:
                Logger.Error(_category, message, exception); // Error -> Error
                break;
            case Microsoft.Extensions.Logging.LogLevel.Critical:
                Logger.Error(_category, message, exception); // Critical -> Error
                break;
            default:
                Logger.Verbose(_category, message, exception); // Fallback to Info
                break;
        }
    }

    public bool IsEnabled(Microsoft.Extensions.Logging.LogLevel logLevel)
    {
        int settingsLogLevel = (int)Logger.DefaultLogLevel;
        int logLevelValue = (int)logLevel;

        switch (settingsLogLevel)
        {
            case 0: // None
                return false;
            case 1: // Error
                return logLevelValue >= (int)Microsoft.Extensions.Logging.LogLevel.Error; // Error (4), Critical (5)
            case 2: // Warning
                return logLevelValue >= (int)Microsoft.Extensions.Logging.LogLevel.Warning; // Warning (3), Error (4), Critical (5)
            case 3: // Information
                return logLevelValue >= (int)Microsoft.Extensions.Logging.LogLevel.Information; // Information (2), Warning (3), Error (4), Critical (5)
            case 4: // Verbose
                return logLevelValue >= (int)Microsoft.Extensions.Logging.LogLevel.Debug; // Debug (1), Information (2), Warning (3), Error (4), Critical (5)
            case 5: // Debug
                return logLevelValue >= (int)Microsoft.Extensions.Logging.LogLevel.Trace; // Trace (0), Debug (1), Information (2), Warning (3), Error (4), Critical (5)
            default:
                return false; // Unknown setting, disable logging
        }
    }

    public IDisposable? BeginScope<TState>(TState state) where TState : notnull => NullScope.Instance;
}

public class NullScope : IDisposable
{
    public static NullScope Instance = new NullScope();
    public void Dispose() { }
}

public class LoggerLoggerProvider : ILoggerProvider
{
    public ILogger CreateLogger(string categoryName)
    {
        return new LoggerLogger(categoryName);
    }

    public void Dispose()
    {

    }
}