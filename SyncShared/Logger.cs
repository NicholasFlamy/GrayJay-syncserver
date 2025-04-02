
namespace SyncShared;

public enum LogLevel : int
{
    None,
    Error,
    Warning,
    Info,
    Verbose,
    Debug
}

public static class Logger
{
    public static Action<LogLevel, string, string, Exception?> LogCallback = (level, tag, message, ex) =>
    {
        if (!WillLog!(level))
            return;

        string timestamp = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss.fff");
        string levelStr = level.ToString().ToUpper();
        string logMessage = $"[{timestamp}] [{levelStr}] [{tag}] {message}";
        if (ex != null)
            logMessage += $"\nException: {ex.Message}\nStack Trace: {ex.StackTrace}";
        Console.WriteLine(logMessage);
    };

    public const LogLevel DefaultLogLevel = LogLevel.Verbose;
    public static Func<LogLevel, bool> WillLog = (level) => (int)level <= (int)DefaultLogLevel;
    //public static Func<LogLevel, bool> WillLog = (level) => false;

    public static void Debug<T>(string message, Exception? ex = null) => LogCallback.Invoke(LogLevel.Debug, typeof(T).Name, message, ex);
    public static void Verbose<T>(string message, Exception? ex = null) => LogCallback.Invoke(LogLevel.Verbose, typeof(T).Name, message, ex);
    public static void Info<T>(string message, Exception? ex = null) => LogCallback.Invoke(LogLevel.Info, typeof(T).Name, message, ex);
    public static void Warning<T>(string message, Exception? ex = null) => LogCallback.Invoke(LogLevel.Warning, typeof(T).Name, message, ex);
    public static void Error<T>(string message, Exception? ex = null) => LogCallback.Invoke(LogLevel.Error, typeof(T).Name, message, ex);
    public static void Debug(string tag, string message, Exception? ex = null) => LogCallback.Invoke(LogLevel.Debug, tag, message, ex);
    public static void Verbose(string tag, string message, Exception? ex = null) => LogCallback.Invoke(LogLevel.Verbose, tag, message, ex);
    public static void Info(string tag, string message, Exception? ex = null) => LogCallback.Invoke(LogLevel.Info, tag, message, ex);
    public static void Warning(string tag, string message, Exception? ex = null) => LogCallback.Invoke(LogLevel.Warning, tag, message, ex);
    public static void Error(string tag, string message, Exception? ex = null) => LogCallback.Invoke(LogLevel.Error, tag, message, ex);
}
