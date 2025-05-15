using SyncShared;

namespace SyncClient;

public interface ISyncDatabaseProvider
{
    // Authorized devices
    bool IsAuthorized(string publicKey);
    void AddAuthorizedDevice(string publicKey);
    void RemoveAuthorizedDevice(string publicKey);
    string[]? GetAllAuthorizedDevices();
    int GetAuthorizedDeviceCount();

    // Sync key pair
    SyncKeyPair? GetSyncKeyPair();
    void SetSyncKeyPair(SyncKeyPair value);

    // Last address storage
    string? GetLastAddress(string publicKey);
    void SetLastAddress(string publicKey, string address);

    // Name storage
    string? GetDeviceName(string publicKey);
    void SetDeviceName(string publicKey, string name);
}