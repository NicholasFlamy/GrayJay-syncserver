using System.Collections.Concurrent;
using System.Data;
using Microsoft.Data.Sqlite;
using Microsoft.Extensions.Caching.Memory;

namespace SyncServer.Repositories
{
    public class SqliteDeviceTokenRepository : IDeviceTokenRepository
    {
        private readonly string _connectionString;
        private readonly ConcurrentQueue<SqliteConnection> _connectionPool;
        private readonly SemaphoreSlim _connectionSemaphore;
        private readonly int _poolSize;
        private readonly MemoryCache _tokenCache;

        private readonly struct DeviceKey : IEquatable<DeviceKey>
        {
            public readonly string Id, Platform, AppName;
            public DeviceKey(string id, string platform, string appName)
            {
                Id = id ?? throw new ArgumentNullException(nameof(id));
                Platform = platform ?? throw new ArgumentNullException(nameof(platform));
                AppName = appName ?? throw new ArgumentNullException(nameof(appName));
            }
            public bool Equals(DeviceKey other)
                => Id == other.Id
                && Platform == other.Platform
                && AppName == other.AppName;
            public override bool Equals(object? obj)
                => obj is DeviceKey dk && Equals(dk);
            public override int GetHashCode()
                => HashCode.Combine(Id, Platform, AppName);
        }

        public SqliteDeviceTokenRepository(
            string connectionString,
            int poolSize = 20,
            int maxConnections = 50,
            int cacheSize = 10000)
        {
            _connectionString = connectionString ?? throw new ArgumentNullException(nameof(connectionString));
            _poolSize = poolSize;
            _connectionPool = new ConcurrentQueue<SqliteConnection>();
            _connectionSemaphore = new SemaphoreSlim(poolSize, maxConnections);
            _tokenCache = new MemoryCache(new MemoryCacheOptions { SizeLimit = cacheSize });
        }

        public async Task InitializeAsync()
        {
            await InitializeDatabaseAsync().ConfigureAwait(false);
            await InitializeConnectionPoolAsync().ConfigureAwait(false);
        }

        private async Task InitializeDatabaseAsync()
        {
            using var conn = new SqliteConnection(_connectionString);
            await conn.OpenAsync().ConfigureAwait(false);
            using var cmd = conn.CreateCommand();
            cmd.CommandText = @"
                CREATE TABLE IF NOT EXISTS device_tokens (
                    id           TEXT NOT NULL,
                    platform     TEXT NOT NULL,
                    app_name     TEXT NOT NULL,
                    token        TEXT NOT NULL,
                    last_updated DATETIME NOT NULL,
                    PRIMARY KEY(id, platform, app_name)
                );
                PRAGMA journal_mode = WAL;

                -- index to speed up lookups by id
                CREATE INDEX IF NOT EXISTS idx_device_tokens_id
                    ON device_tokens(id);

                -- covering index for selecting the most-recent by id
                CREATE INDEX IF NOT EXISTS idx_device_tokens_id_last_updated
                    ON device_tokens(id, last_updated DESC);
            ";
            await cmd.ExecuteNonQueryAsync().ConfigureAwait(false);
        }

        private async Task InitializeConnectionPoolAsync()
        {
            for (int i = 0; i < _poolSize; i++)
            {
                var conn = new SqliteConnection(_connectionString);
                await conn.OpenAsync().ConfigureAwait(false);
                _connectionPool.Enqueue(conn);
            }
        }

        private async Task<SqliteConnection> GetConnectionAsync()
        {
            await _connectionSemaphore.WaitAsync().ConfigureAwait(false);
            if (_connectionPool.TryDequeue(out var conn))
                return conn;

            conn = new SqliteConnection(_connectionString);
            await conn.OpenAsync().ConfigureAwait(false);
            return conn;
        }

        private void ReleaseConnection(SqliteConnection conn)
        {
            if (_connectionPool.Count < _poolSize)
                _connectionPool.Enqueue(conn);
            else
            {
                conn.Close();
                conn.Dispose();
            }
            _connectionSemaphore.Release();
        }

        public async Task InsertOrUpdateAsync(string id, string platform, string appName, string token)
        {
            var key = new DeviceKey(id, platform, appName);
            var now = DateTime.UtcNow;

            var conn = await GetConnectionAsync().ConfigureAwait(false);
            try
            {
                using var cmd = conn.CreateCommand();
                cmd.CommandText = @"
                    INSERT INTO device_tokens (id, platform, app_name, token, last_updated)
                    VALUES (@id, @platform, @appName, @token, @now)
                    ON CONFLICT(id, platform, app_name) DO UPDATE
                      SET token = excluded.token,
                          last_updated = excluded.last_updated;";
                cmd.Parameters.AddWithValue("@id", id);
                cmd.Parameters.AddWithValue("@platform", platform);
                cmd.Parameters.AddWithValue("@appName", appName);
                cmd.Parameters.AddWithValue("@token", token);
                cmd.Parameters.AddWithValue("@now", now);

                await cmd.ExecuteNonQueryAsync().ConfigureAwait(false);

                var cacheOptions = new MemoryCacheEntryOptions()
                    .SetSize(1)
                    .SetSlidingExpiration(TimeSpan.FromMinutes(10));
                _tokenCache.Set(key, token, cacheOptions);
            }
            finally
            {
                ReleaseConnection(conn);
            }
        }

        public async Task<(string Platform, string AppName, string Token)> GetAsync(string id)
        {
            var conn = await GetConnectionAsync().ConfigureAwait(false);
            try
            {
                using var cmd = conn.CreateCommand();
                cmd.CommandText = @"
                    SELECT platform, app_name, token
                      FROM device_tokens
                     WHERE id = @id
                     ORDER BY last_updated DESC
                     LIMIT 1;";
                cmd.Parameters.AddWithValue("@id", id);

                using var rdr = await cmd.ExecuteReaderAsync(CommandBehavior.SingleRow)
                                      .ConfigureAwait(false);

                if (!await rdr.ReadAsync().ConfigureAwait(false))
                    return default;

                var platform = rdr.GetString(0);
                var appName = rdr.GetString(1);
                var token = rdr.GetString(2);

                var key = new DeviceKey(id, platform, appName);
                var cacheOptions = new MemoryCacheEntryOptions()
                    .SetSize(1)
                    .SetSlidingExpiration(TimeSpan.FromMinutes(10));
                _tokenCache.Set(key, token, cacheOptions);

                return (platform, appName, token);
            }
            finally
            {
                ReleaseConnection(conn);
            }
        }

        public async Task<List<(string Id, string Platform, string AppName, string Token)>> GetAllAsync(List<string> ids)
        {
            if (ids == null || ids.Count == 0)
                return new List<(string, string, string, string)>();

            var paramNames = ids.Select((_, i) => $"@id{i}").ToArray();
            var inClause = string.Join(",", paramNames);

            var conn = await GetConnectionAsync().ConfigureAwait(false);
            try
            {
                using var cmd = conn.CreateCommand();
                cmd.CommandText = $@"
                    SELECT id, platform, app_name, token
                      FROM device_tokens
                     WHERE id IN ({inClause});";

                for (int i = 0; i < ids.Count; i++)
                    cmd.Parameters.AddWithValue(paramNames[i], ids[i]);

                using var rdr = await cmd.ExecuteReaderAsync()
                                      .ConfigureAwait(false);

                var results = new List<(string, string, string, string)>();
                while (await rdr.ReadAsync().ConfigureAwait(false))
                {
                    results.Add((
                        rdr.GetString(0),
                        rdr.GetString(1),
                        rdr.GetString(2),
                        rdr.GetString(3)
                    ));
                }
                return results;
            }
            finally
            {
                ReleaseConnection(conn);
            }
        }

        public async Task DeleteAsync(string id, string appName, string platform)
        {
            var key = new DeviceKey(id, platform, appName);
            var conn = await GetConnectionAsync().ConfigureAwait(false);
            try
            {
                using var cmd = conn.CreateCommand();
                cmd.CommandText = @"
                    DELETE FROM device_tokens
                     WHERE id = @id
                       AND platform = @platform
                       AND app_name = @appName;";
                cmd.Parameters.AddWithValue("@id", id);
                cmd.Parameters.AddWithValue("@platform", platform);
                cmd.Parameters.AddWithValue("@appName", appName);

                await cmd.ExecuteNonQueryAsync().ConfigureAwait(false);

                _tokenCache.Remove(key);
            }
            finally
            {
                ReleaseConnection(conn);
            }
        }

        public void Dispose()
        {
            while (_connectionPool.TryDequeue(out var conn))
            {
                conn.Close();
                conn.Dispose();
            }
            _tokenCache.Dispose();
        }
    }
}
