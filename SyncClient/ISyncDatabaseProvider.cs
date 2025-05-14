namespace SyncClient;

public interface ISyncDatabaseProvider
{
    // Authorized devices
    Task<bool> IsAuthorizedAsync(string publicKey);
    Task AddAuthorizedDeviceAsync(string publicKey);
    Task RemoveAuthorizedDeviceAsync(string publicKey);
    Task<string[]> GetAllAuthorizedDevicesAsync();

    // Sync key pair
    Task<string> GetSyncKeyPairAsync();
    Task SetSyncKeyPairAsync(string value);

    // Last address storage
    Task<string> GetLastAddressAsync(string publicKey);
    Task SetLastAddressAsync(string publicKey, string address);

    // Name storage
    Task<string> GetDeviceNameAsync(string publicKey);
    Task SetDeviceNameAsync(string publicKey, string name);
}