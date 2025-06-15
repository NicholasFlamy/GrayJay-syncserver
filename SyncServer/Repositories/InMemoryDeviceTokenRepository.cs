using System.Collections.Concurrent;

namespace SyncServer.Repositories
{
    public class InMemoryDeviceTokenRepository : IDeviceTokenRepository
    {
        private readonly ConcurrentDictionary<DeviceKey, DeviceToken> _store = new();

        private readonly struct DeviceKey : IEquatable<DeviceKey>
        {
            public string Id { get; }
            public string Platform { get; }
            public string AppName { get; }

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
                => obj is DeviceKey other && Equals(other);

            public override int GetHashCode()
                => HashCode.Combine(Id, Platform, AppName);
        }

        private class DeviceToken
        {
            public string Id { get; set; } = default!;
            public string Platform { get; set; } = default!;
            public string AppName { get; set; } = default!;
            public string Token { get; set; } = default!;
            public DateTime LastUpdated { get; set; }
        }

        public Task InsertOrUpdateAsync(string id, string platform, string appName, string token)
        {
            var key = new DeviceKey(id, platform, appName);
            var entry = new DeviceToken
            {
                Id = id,
                Platform = platform,
                AppName = appName,
                Token = token,
                LastUpdated = DateTime.UtcNow
            };
            _store.AddOrUpdate(key, entry, (_, __) => entry);
            return Task.CompletedTask;
        }

        public Task<(string Platform, string AppName, string Token)> GetAsync(string id)
        {
            var entry = _store
                .Values
                .Where(e => e.Id == id)
                .OrderByDescending(e => e.LastUpdated)
                .FirstOrDefault();

            if (entry is null)
            {
                return Task.FromResult(default((string, string, string)));
            }

            return Task.FromResult((entry.Platform, entry.AppName, entry.Token));
        }

        public Task<List<(string Id, string Platform, string AppName, string Token)>> GetAllAsync(List<string> ids)
        {
            var results = _store
                .Values
                .Where(e => ids.Contains(e.Id))
                .Select(e => (e.Id, e.Platform, e.AppName, e.Token))
                .ToList();

            return Task.FromResult(results);
        }

        public Task DeleteAsync(string id, string appName, string platform)
        {
            var key = new DeviceKey(id, platform, appName);
            _store.TryRemove(key, out _);
            return Task.CompletedTask;
        }

        public void Dispose()
        {

        }
    }
}
