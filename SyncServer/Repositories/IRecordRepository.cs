namespace SyncServer.Repositories;

public interface IRecordRepository : IDisposable
{
    Task InsertOrUpdateAsync(byte[] publisherPublicKey, byte[] consumerPublicKey, string key, byte[] encryptedBlob);
    Task BulkInsertOrUpdateAsync(IEnumerable<(byte[] publisherPublicKey, byte[] consumerPublicKey, string key, byte[] encryptedBlob)> records);
    Task<Record?> GetAsync(byte[] publisherPublicKey, byte[] consumerPublicKey, string key);
    Task<IEnumerable<(string Key, DateTime Timestamp)>> ListKeysAsync(byte[] publisherPublicKey, byte[] consumerPublicKey);
    Task DeleteAsync(byte[] publisherPublicKey, byte[] consumerPublicKey, string key);
    Task<IEnumerable<Record>> GetByPublishersAsync(byte[] consumerPublicKey, IEnumerable<byte[]> publisherPublicKeys, string key);
    Task BulkDeleteAsync(byte[] publisherPublicKey, byte[] consumerPublicKey, IEnumerable<string> keys);
}