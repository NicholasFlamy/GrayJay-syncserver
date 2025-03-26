using Microsoft.Data.Sqlite;
using System.Collections.Concurrent;
using System.Text;
using Microsoft.Extensions.Caching.Memory;

namespace SyncServer.Repositories;

public class SqliteRecordRepository : IRecordRepository
{
    internal class RecordKey
    {
        public long PublisherId { get; }
        public long ConsumerId { get; }
        public string Key { get; }

        public RecordKey(long publisherId, long consumerId, string key)
        {
            PublisherId = publisherId;
            ConsumerId = consumerId;
            Key = key;
        }

        public override bool Equals(object? obj) =>
            obj is RecordKey other &&
            PublisherId == other.PublisherId &&
            ConsumerId == other.ConsumerId &&
            Key == other.Key;

        public override int GetHashCode() =>
            HashCode.Combine(PublisherId, ConsumerId, Key);
    }

    internal class RecordValue
    {
        public required byte[] EncryptedBlob { get; init; }
        public required DateTime Timestamp { get; init; }
    }

    private readonly string _connectionString;
    private readonly MemoryCache _recordCache;
    private readonly ConcurrentQueue<SqliteConnection> _connectionPool;
    private readonly SemaphoreSlim _connectionSemaphore;
    private readonly int _poolSize;
    private readonly MemoryCache _userIdCache;

    public SqliteRecordRepository(
        string connectionString,
        int maxCacheSize = 50000,
        int userIdCacheSize = 100000,
        int poolSize = 20,
        int maxConnections = 50)
    {
        _connectionString = connectionString ?? throw new ArgumentNullException(nameof(connectionString));
        _poolSize = poolSize;
        _connectionPool = new ConcurrentQueue<SqliteConnection>();
        _connectionSemaphore = new SemaphoreSlim(poolSize, maxConnections);
        var userIdCacheOptions = new MemoryCacheOptions { SizeLimit = userIdCacheSize };
        _userIdCache = new MemoryCache(userIdCacheOptions); 
        var recordCacheOptions = new MemoryCacheOptions { SizeLimit = maxCacheSize };
        _recordCache = new MemoryCache(recordCacheOptions);
    }

    public async Task InitializeAsync()
    {
        await InitializeDatabaseAsync();
        await InitializeConnectionPoolAsync();
    }

    private async Task InitializeDatabaseAsync()
    {
        using var connection = new SqliteConnection(_connectionString);
        await connection.OpenAsync();
        using var command = connection.CreateCommand();
        command.CommandText = @"
            CREATE TABLE IF NOT EXISTS users (
                user_id INTEGER PRIMARY KEY,
                public_key BLOB UNIQUE
            );
            CREATE TABLE IF NOT EXISTS records (
                publisher_id INTEGER NOT NULL,
                consumer_id INTEGER NOT NULL,
                key TEXT NOT NULL,
                encrypted_blob BLOB NOT NULL,
                timestamp DATETIME NOT NULL,
                PRIMARY KEY (publisher_id, consumer_id, key),
                FOREIGN KEY (publisher_id) REFERENCES users(user_id),
                FOREIGN KEY (consumer_id) REFERENCES users(user_id)
            );
            CREATE INDEX IF NOT EXISTS idx_records_publisher_id ON records (publisher_id);
            CREATE INDEX IF NOT EXISTS idx_records_consumer_id ON records (consumer_id);
            PRAGMA journal_mode=WAL;";
        await command.ExecuteNonQueryAsync();
    }

    private async Task InitializeConnectionPoolAsync()
    {
        for (int i = 0; i < _poolSize; i++)
        {
            var connection = new SqliteConnection(_connectionString);
            await connection.OpenAsync();
            _connectionPool.Enqueue(connection);
        }
    }

    private async Task<SqliteConnection> GetConnectionAsync()
    {
        await _connectionSemaphore.WaitAsync();
        if (_connectionPool.TryDequeue(out var connection))
        {
            return connection;
        }
        connection = new SqliteConnection(_connectionString);
        await connection.OpenAsync();
        return connection;
    }

    private void ReleaseConnection(SqliteConnection connection)
    {
        if (_connectionPool.Count < _poolSize)
        {
            _connectionPool.Enqueue(connection);
        }
        else
        {
            connection.Close();
            connection.Dispose();
        }
        _connectionSemaphore.Release();
    }

    public async Task<long> GetTotalSizeAsync(byte[] publisherPublicKey)
    {
        var connection = await GetConnectionAsync();
        try
        {
            var publisherId = await GetOrCreateUserIdAsync(publisherPublicKey, connection);
            using var command = connection.CreateCommand();
            command.CommandText = @"
                SELECT SUM(LENGTH(encrypted_blob)) 
                FROM records 
                WHERE publisher_id = @publisherId";
            command.Parameters.AddWithValue("@publisherId", publisherId);
            var result = await command.ExecuteScalarAsync();
            return result is long totalSize ? totalSize : 0;
        }
        finally
        {
            ReleaseConnection(connection);
        }
    }

    private async Task<long> GetOrCreateUserIdAsync(byte[] publicKey, SqliteConnection connection)
    {
        if (_userIdCache.TryGetValue(publicKey, out long userId))
        {
            return userId;
        }

        using var command = connection.CreateCommand();
        command.CommandText = "SELECT user_id FROM users WHERE public_key = @publicKey";
        command.Parameters.AddWithValue("@publicKey", publicKey);
        var result = await command.ExecuteScalarAsync();

        if (result != null)
        {
            userId = (long)result;
        }
        else
        {
            command.CommandText = "INSERT INTO users (public_key) VALUES (@publicKey); SELECT last_insert_rowid();";
            var insertResult = await command.ExecuteScalarAsync();
            if (insertResult == null)
                throw new InvalidOperationException("Failed to insert user and retrieve user ID.");
            userId = (long)insertResult;
        }
        var cacheEntryOptions = new MemoryCacheEntryOptions().SetSize(1);
        _userIdCache.Set(publicKey, userId, cacheEntryOptions);
        return userId;
    }

    public async Task InsertOrUpdateAsync(byte[] publisherPublicKey, byte[] consumerPublicKey, string key, byte[] encryptedBlob)
    {
        var connection = await GetConnectionAsync();
        try
        {
            var publisherId = await GetOrCreateUserIdAsync(publisherPublicKey, connection);
            var consumerId = await GetOrCreateUserIdAsync(consumerPublicKey, connection);
            var recordKey = new RecordKey(publisherId, consumerId, key);
            var recordValue = new RecordValue { EncryptedBlob = encryptedBlob, Timestamp = DateTime.UtcNow };

            using var command = connection.CreateCommand();
            command.CommandText = @"
                    INSERT OR REPLACE INTO records (publisher_id, consumer_id, key, encrypted_blob, timestamp)
                    VALUES (@publisherId, @consumerId, @key, @encryptedBlob, @timestamp)";
            command.Parameters.AddWithValue("@publisherId", publisherId);
            command.Parameters.AddWithValue("@consumerId", consumerId);
            command.Parameters.AddWithValue("@key", key);
            command.Parameters.AddWithValue("@encryptedBlob", encryptedBlob);
            command.Parameters.AddWithValue("@timestamp", recordValue.Timestamp);
            await command.ExecuteNonQueryAsync();

            // Update cache
            var cacheEntryOptions = new MemoryCacheEntryOptions()
                .SetSize(1)
                .SetSlidingExpiration(TimeSpan.FromMinutes(10));
            _recordCache.Set(recordKey, recordValue, cacheEntryOptions);

            // TODO: In a distributed system make a shared cache or invalidation mechanism to maintain consistency across instances.
        }
        catch (SqliteException ex) when (ex.SqliteErrorCode == SQLitePCL.raw.SQLITE_BUSY)
        {
            Logger.Warning<SqliteRecordRepository>("Database busy during insert/update, consider retrying", ex);
            throw;
        }
        catch (Exception ex)
        {
            Logger.Error<SqliteRecordRepository>("Error inserting or updating record", ex);
            throw;
        }
        finally
        {
            ReleaseConnection(connection);
        }
    }

    public async Task BulkInsertOrUpdateAsync(IEnumerable<(byte[] publisherPublicKey, byte[] consumerPublicKey, string key, byte[] encryptedBlob)> records)
    {
        var connection = await GetConnectionAsync();
        try
        {
            using var transaction = await connection.BeginTransactionAsync();
            var sqlBuilder = new StringBuilder("INSERT OR REPLACE INTO records (publisher_id, consumer_id, key, encrypted_blob, timestamp) VALUES ");
            var parameters = new List<SqliteParameter>();
            int paramIndex = 0;

            foreach (var (publisherPublicKey, consumerPublicKey, key, encryptedBlob) in records)
            {
                var publisherId = await GetOrCreateUserIdAsync(publisherPublicKey, connection);
                var consumerId = await GetOrCreateUserIdAsync(consumerPublicKey, connection);
                var timestamp = DateTime.UtcNow;

                sqlBuilder.Append($"(@p{paramIndex}, @c{paramIndex}, @k{paramIndex}, @b{paramIndex}, @t{paramIndex}),");
                parameters.Add(new SqliteParameter($"@p{paramIndex}", publisherId));
                parameters.Add(new SqliteParameter($"@c{paramIndex}", consumerId));
                parameters.Add(new SqliteParameter($"@k{paramIndex}", key));
                parameters.Add(new SqliteParameter($"@b{paramIndex}", encryptedBlob));
                parameters.Add(new SqliteParameter($"@t{paramIndex}", timestamp));
                paramIndex++;
            }

            if (paramIndex > 0)
            {
                sqlBuilder.Length--; // Remove trailing comma
                var command = connection.CreateCommand();
                command.CommandText = sqlBuilder.ToString();
                command.Parameters.AddRange(parameters.ToArray());
                await command.ExecuteNonQueryAsync();
            }

            await transaction.CommitAsync();
        }
        catch (SqliteException ex) when (ex.SqliteErrorCode == SQLitePCL.raw.SQLITE_BUSY)
        {
            Logger.Warning<SqliteRecordRepository>("Database busy during bulk insert/update, consider retrying", ex);
            throw;
        }
        catch (Exception ex)
        {
            Logger.Error<SqliteRecordRepository>("Error during bulk insert or update", ex);
            throw;
        }
        finally
        {
            ReleaseConnection(connection);
        }
    }

    public async Task<Record?> GetAsync(byte[] publisherPublicKey, byte[] consumerPublicKey, string key)
    {
        var connection = await GetConnectionAsync();
        try
        {
            var publisherId = await GetOrCreateUserIdAsync(publisherPublicKey, connection);
            var consumerId = await GetOrCreateUserIdAsync(consumerPublicKey, connection);
            var recordKey = new RecordKey(publisherId, consumerId, key);

            // Check cache first
            if (_recordCache.TryGetValue(recordKey, out RecordValue? cachedValue) && cachedValue != null)
            {
                return new Record
                {
                    PublisherPublicKey = publisherPublicKey,
                    ConsumerPublicKey = consumerPublicKey,
                    Key = key,
                    EncryptedBlob = cachedValue.EncryptedBlob,
                    Timestamp = cachedValue.Timestamp
                };
            }

            // Fetch from database
            using var command = connection.CreateCommand();
            command.CommandText = "SELECT encrypted_blob, timestamp FROM records WHERE publisher_id = @publisherId AND consumer_id = @consumerId AND key = @key";
            command.Parameters.AddWithValue("@publisherId", publisherId);
            command.Parameters.AddWithValue("@consumerId", consumerId);
            command.Parameters.AddWithValue("@key", key);
            using var reader = await command.ExecuteReaderAsync();
            if (await reader.ReadAsync())
            {
                var recordValue = new RecordValue
                {
                    EncryptedBlob = (byte[])reader["encrypted_blob"],
                    Timestamp = reader.GetDateTime(reader.GetOrdinal("timestamp"))
                };

                // Add to cache
                var cacheEntryOptions = new MemoryCacheEntryOptions()
                    .SetSize(1)
                    .SetSlidingExpiration(TimeSpan.FromMinutes(10));
                _recordCache.Set(recordKey, recordValue, cacheEntryOptions);

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
        catch (SqliteException ex) when (ex.SqliteErrorCode == SQLitePCL.raw.SQLITE_BUSY)
        {
            Logger.Warning<SqliteRecordRepository>("Database busy during get, consider retrying", ex);
            throw;
        }
        catch (Exception ex)
        {
            Logger.Error<SqliteRecordRepository>("Error retrieving record", ex);
            throw;
        }
        finally
        {
            ReleaseConnection(connection);
        }
    }

    public async Task<IEnumerable<(string Key, DateTime Timestamp)>> ListKeysAsync(byte[] publisherPublicKey, byte[] consumerPublicKey)
    {
        var connection = await GetConnectionAsync();
        try
        {
            var publisherId = await GetOrCreateUserIdAsync(publisherPublicKey, connection);
            var consumerId = await GetOrCreateUserIdAsync(consumerPublicKey, connection);

            using var command = connection.CreateCommand();
            command.CommandText = "SELECT key, timestamp FROM records WHERE publisher_id = @publisherId AND consumer_id = @consumerId";
            command.Parameters.AddWithValue("@publisherId", publisherId);
            command.Parameters.AddWithValue("@consumerId", consumerId);
            using var reader = await command.ExecuteReaderAsync();
            var list = new List<(string, DateTime)>();
            while (await reader.ReadAsync())
            {
                list.Add((
                    reader.GetString(reader.GetOrdinal("key")),
                    reader.GetDateTime(reader.GetOrdinal("timestamp"))
                ));
            }
            return list;
        }
        catch (SqliteException ex) when (ex.SqliteErrorCode == SQLitePCL.raw.SQLITE_BUSY)
        {
            Logger.Warning<SqliteRecordRepository>("Database busy during list keys, consider retrying", ex);
            throw;
        }
        catch (Exception ex)
        {
            Logger.Error<SqliteRecordRepository>("Error listing keys", ex);
            throw;
        }
        finally
        {
            ReleaseConnection(connection);
        }
    }

    public async Task DeleteAsync(byte[] publisherPublicKey, byte[] consumerPublicKey, string key)
    {
        var connection = await GetConnectionAsync();
        try
        {
            var publisherId = await GetOrCreateUserIdAsync(publisherPublicKey, connection);
            var consumerId = await GetOrCreateUserIdAsync(consumerPublicKey, connection);
            using var command = connection.CreateCommand();
            command.CommandText = "DELETE FROM records WHERE publisher_id = @publisherId AND consumer_id = @consumerId AND key = @key";
            command.Parameters.AddWithValue("@publisherId", publisherId);
            command.Parameters.AddWithValue("@consumerId", consumerId);
            command.Parameters.AddWithValue("@key", key);
            await command.ExecuteNonQueryAsync();

            // Remove from cache if exists
            var recordKey = new RecordKey(publisherId, consumerId, key);
            _recordCache.Remove(recordKey);
        }
        finally
        {
            ReleaseConnection(connection);
        }
    }

    public async Task<IEnumerable<Record>> GetByPublishersAsync(byte[] consumerPublicKey, IEnumerable<byte[]> publisherPublicKeys, string key)
    {
        const int PublisherChunkSize = 100;

        var connection = await GetConnectionAsync();
        try
        {
            var consumerId = await GetOrCreateUserIdAsync(consumerPublicKey, connection);
            var publisherIds = new List<long>();
            foreach (var pubKey in publisherPublicKeys)
            {
                var pubId = await GetOrCreateUserIdAsync(pubKey, connection);
                publisherIds.Add(pubId);
            }

            var records = new List<Record>();
            for (int i = 0; i < publisherIds.Count; i += PublisherChunkSize)
            {
                var chunk = publisherIds.Skip(i).Take(PublisherChunkSize).ToList();
                using var command = connection.CreateCommand();
                command.CommandText = @"
                    SELECT u.public_key, r.encrypted_blob, r.timestamp
                    FROM records r
                    JOIN users u ON r.publisher_id = u.user_id
                    WHERE r.consumer_id = @consumerId 
                      AND r.publisher_id IN (" + string.Join(",", chunk.Select((_, j) => $"@pubId{j}")) + @") 
                      AND r.key = @key";
                command.Parameters.AddWithValue("@consumerId", consumerId);
                command.Parameters.AddWithValue("@key", key);
                for (int j = 0; j < chunk.Count; j++)
                    command.Parameters.AddWithValue($"@pubId{j}", chunk[j]);

                using var reader = await command.ExecuteReaderAsync();
                while (await reader.ReadAsync())
                {
                    records.Add(new Record
                    {
                        PublisherPublicKey = (byte[])reader["public_key"],
                        ConsumerPublicKey = consumerPublicKey,
                        Key = key,
                        EncryptedBlob = (byte[])reader["encrypted_blob"],
                        Timestamp = reader.GetDateTime(reader.GetOrdinal("timestamp"))
                    });
                }
            }
            return records;
        }
        catch (SqliteException ex) when (ex.SqliteErrorCode == SQLitePCL.raw.SQLITE_BUSY)
        {
            Logger.Warning<SqliteRecordRepository>("Database busy during bulk get, consider retrying", ex);
            throw;
        }
        catch (Exception ex)
        {
            Logger.Error<SqliteRecordRepository>("Error retrieving bulk records", ex);
            throw;
        }
        finally
        {
            ReleaseConnection(connection);
        }
    }

    public async Task BulkDeleteAsync(byte[] publisherPublicKey, byte[] consumerPublicKey, IEnumerable<string> keys)
    {
        var connection = await GetConnectionAsync();
        try
        {
            var publisherId = await GetOrCreateUserIdAsync(publisherPublicKey, connection);
            var consumerId = await GetOrCreateUserIdAsync(consumerPublicKey, connection);
            var keyList = keys.ToList();
            if (keyList.Count == 0)
                return;

            using var transaction = await connection.BeginTransactionAsync();
            using var command = connection.CreateCommand();
            command.CommandText = @"
                DELETE FROM records 
                WHERE publisher_id = @publisherId 
                  AND consumer_id = @consumerId 
                  AND key IN (" + string.Join(",", keyList.Select((_, i) => $"@key{i}")) + ")";
            command.Parameters.AddWithValue("@publisherId", publisherId);
            command.Parameters.AddWithValue("@consumerId", consumerId);
            for (int i = 0; i < keyList.Count; i++)
            {
                command.Parameters.AddWithValue($"@key{i}", keyList[i]);
            }
            await command.ExecuteNonQueryAsync();
            await transaction.CommitAsync();

            // Invalidate cache for deleted records
            foreach (var key in keyList)
            {
                var recordKey = new RecordKey(publisherId, consumerId, key);
                _recordCache.Remove(recordKey);
            }
        }
        catch (SqliteException ex) when (ex.SqliteErrorCode == SQLitePCL.raw.SQLITE_BUSY)
        {
            Logger.Warning<SqliteRecordRepository>("Database busy during bulk delete, consider retrying", ex);
            throw;
        }
        catch (Exception ex)
        {
            Logger.Error<SqliteRecordRepository>("Error during bulk delete", ex);
            throw;
        }
        finally
        {
            ReleaseConnection(connection);
        }
    }

    public void Dispose()
    {
        while (_connectionPool.TryDequeue(out var conn))
        {
            conn.Close();
            conn.Dispose();
        }

        _recordCache.Dispose();
    }
}