namespace SyncServer.Repositories;

public class DeviceToken
{
    public required string Id { get; set; }
    public required string AppName { get; set; }
    public required string Token { get; set; }
    public required string Platform { get; set; }
    public DateTime LastUpdated { get; set; }
}
