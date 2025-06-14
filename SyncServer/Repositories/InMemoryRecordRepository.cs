using System.Collections.Concurrent;

namespace SyncServer.Repositories;

public class InMemoryRecordRepository : IRecordRepository
{
    private readonly ConcurrentDictionary<RecordKey, RecordValue> _store = new();
    private readonly ConcurrentDictionary<byte[], long> _totalSizes = new(new ByteArrayComparer());

    public class RecordKey : IEquatable<RecordKey>
    {
        public byte[] PublisherPublicKey { get; }
        public byte[] ConsumerPublicKey { get; }
        public string Key { get; }

        public RecordKey(byte[] publisherPublicKey, byte[] consumerPublicKey, string key)
        {
            PublisherPublicKey = publisherPublicKey ?? throw new ArgumentNullException(nameof(publisherPublicKey));
            ConsumerPublicKey = consumerPublicKey ?? throw new ArgumentNullException(nameof(consumerPublicKey));
            Key = key ?? throw new ArgumentNullException(nameof(key));
        }

        public bool Equals(RecordKey? other)
        {
            if (other == null) return false;
            return PublisherPublicKey.SequenceEqual(other.PublisherPublicKey) &&
                   ConsumerPublicKey.SequenceEqual(other.ConsumerPublicKey) &&
                   Key == other.Key;
        }

        public override bool Equals(object? obj) => Equals(obj as RecordKey);

        public override int GetHashCode()
        {
            unchecked
            {
                int hash = 17;
                hash = hash * 23 + PublisherPublicKey.Aggregate(0, (h, b) => h * 31 + b);
                hash = hash * 23 + ConsumerPublicKey.Aggregate(0, (h, b) => h * 31 + b);
                hash = hash * 23 + (Key?.GetHashCode() ?? 0);
                return hash;
            }
        }
    }

    public class RecordValue
    {
        public required byte[] EncryptedBlob { get; init; }
        public DateTime Timestamp { get; init; }
    }

    public Task<long> GetTotalSizeAsync(byte[] publisherPublicKey)
    {
        _totalSizes.TryGetValue(publisherPublicKey, out long totalSize);
        return Task.FromResult(totalSize);
    }

    public void InsertOrUpdate(byte[] publisherPublicKey, byte[] consumerPublicKey, string key, byte[] encryptedBlob)
    {
        var recordKey = new RecordKey(publisherPublicKey, consumerPublicKey, key);
        var newRecordValue = new RecordValue { EncryptedBlob = encryptedBlob, Timestamp = DateTime.UtcNow };

        if (_store.TryGetValue(recordKey, out var existingRecord))
        {
            long sizeDifference = encryptedBlob.Length - existingRecord.EncryptedBlob.Length;
            _totalSizes.AddOrUpdate(publisherPublicKey, sizeDifference, (_, current) => current + sizeDifference);
        }
        else
        {
            _totalSizes.AddOrUpdate(publisherPublicKey, encryptedBlob.Length, (_, current) => current + encryptedBlob.Length);
        }

        _store[recordKey] = newRecordValue;
    }

    public void BulkInsertOrUpdate(IEnumerable<(byte[] publisherPublicKey, byte[] consumerPublicKey, string key, byte[] encryptedBlob)> records)
    {
        foreach (var (publisherPublicKey, consumerPublicKey, key, encryptedBlob) in records)
        {
            InsertOrUpdate(publisherPublicKey, consumerPublicKey, key, encryptedBlob);
        }
    }

    public void Delete(byte[] publisherPublicKey, byte[] consumerPublicKey, string key)
    {
        var recordKey = new RecordKey(publisherPublicKey, consumerPublicKey, key);
        if (_store.TryRemove(recordKey, out var removedRecord))
        {
            _totalSizes.AddOrUpdate(publisherPublicKey, -removedRecord.EncryptedBlob.Length, (_, current) => current - removedRecord.EncryptedBlob.Length);
        }
    }

    public Record? Get(byte[] publisherPublicKey, byte[] consumerPublicKey, string key)
    {
        var recordKey = new RecordKey(publisherPublicKey, consumerPublicKey, key);
        if (_store.TryGetValue(recordKey, out var recordValue))
        {
            return new Record
            {
                PublisherPublicKey = publisherPublicKey,
                ConsumerPublicKey = consumerPublicKey,
                Key = key,
                EncryptedBlob = recordValue.EncryptedBlob,
                Timestamp = recordValue.Timestamp
            };
        }
        return null;
    }

    public IEnumerable<(string Key, DateTime Timestamp, int Size)> ListKeys(byte[] publisherPublicKey, byte[] consumerPublicKey)
    {
        return _store.Keys
            .Where(k => k.PublisherPublicKey.SequenceEqual(publisherPublicKey) && k.ConsumerPublicKey.SequenceEqual(consumerPublicKey))
            .Select(k => {
                var blob = _store[k];
                return (k.Key, blob.Timestamp, blob.EncryptedBlob.Length);
            });
    }

    public Task InsertOrUpdateAsync(byte[] publisherPublicKey, byte[] consumerPublicKey, string key, byte[] encryptedBlob)
    {
        InsertOrUpdate(publisherPublicKey, consumerPublicKey, key, encryptedBlob);
        return Task.CompletedTask;
    }

    public Task BulkInsertOrUpdateAsync(IEnumerable<(byte[] publisherPublicKey, byte[] consumerPublicKey, string key, byte[] encryptedBlob)> records)
    {
        BulkInsertOrUpdate(records);
        return Task.CompletedTask;
    }

    public Task DeleteAsync(byte[] publisherPublicKey, byte[] consumerPublicKey, string key)
    {
        Delete(publisherPublicKey, consumerPublicKey, key);
        return Task.CompletedTask;
    }

    public Task<Record?> GetAsync(byte[] publisherPublicKey, byte[] consumerPublicKey, string key)
    {
        return Task.FromResult(Get(publisherPublicKey, consumerPublicKey, key));
    }

    public Task<IEnumerable<(string Key, DateTime Timestamp, int Size)>> ListKeysAsync(byte[] publisherPublicKey, byte[] consumerPublicKey)
    {
        return Task.FromResult(ListKeys(publisherPublicKey, consumerPublicKey));
    }

    public Task<IEnumerable<Record>> GetByPublishersAsync(byte[] consumerPublicKey, IEnumerable<byte[]> publisherPublicKeys, string key)
    {
        var records = new List<Record>();
        foreach (var publisherPublicKey in publisherPublicKeys)
        {
            var recordKey = new RecordKey(publisherPublicKey, consumerPublicKey, key);
            if (_store.TryGetValue(recordKey, out var recordValue))
            {
                records.Add(new Record
                {
                    PublisherPublicKey = publisherPublicKey,
                    ConsumerPublicKey = consumerPublicKey,
                    Key = key,
                    EncryptedBlob = recordValue.EncryptedBlob,
                    Timestamp = recordValue.Timestamp
                });
            }
        }
        return Task.FromResult<IEnumerable<Record>>(records);
    }

    public async Task BulkDeleteAsync(byte[] publisherPublicKey, byte[] consumerPublicKey, IEnumerable<string> keys)
    {
        foreach (var key in keys)
            Delete(publisherPublicKey, consumerPublicKey, key);
        await Task.CompletedTask;
    }

    public void Dispose() { }
}