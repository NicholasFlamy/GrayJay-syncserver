namespace SyncClient;

public class SyncDiscoverer
{
    private readonly ISyncDatabaseProvider _database;

    public SyncDiscoverer(ISyncDatabaseProvider database)
    {
        _database = database;
    }
}
