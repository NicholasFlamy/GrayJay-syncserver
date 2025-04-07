namespace SyncClient;

public interface IAuthorizable
{
    bool IsAuthorized { get; }
}

public class AlwaysAuthorized : IAuthorizable
{
    public static readonly AlwaysAuthorized Instance = new AlwaysAuthorized();
    public bool IsAuthorized => true;
}