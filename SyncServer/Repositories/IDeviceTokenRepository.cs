namespace SyncServer.Repositories;

public interface IDeviceTokenRepository : IDisposable
{
    Task InsertOrUpdateAsync(string id, string platform, string appName, string token);
    Task<(string Platform, string AppName, string Token)> GetAsync(string id);
    Task<List<(string Id, string Platform, string AppName, string Token)>> GetAllAsync(List<string> ids);
    Task DeleteAsync(string id, string appName, string platform);
}