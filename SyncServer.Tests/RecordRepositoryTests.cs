using SyncServer.Repositories;

namespace SyncServer.Tests
{
    public abstract class RecordRepositoryTests
    {
        protected abstract Task<IRecordRepository> CreateRepositoryAsync();

        [TestMethod]
        public async Task InsertOrUpdateAsync_InsertsNewRecord()
        {
            // Arrange
            using var repo = await CreateRepositoryAsync();
            var publisherKey = new byte[] { 1, 2, 3 };
            var consumerKey = new byte[] { 4, 5, 6 };
            var key = "testKey";
            var blob = new byte[] { 7, 8, 9 };

            // Act
            await repo.InsertOrUpdateAsync(publisherKey, consumerKey, key, blob);

            // Assert
            var record = await repo.GetAsync(publisherKey, consumerKey, key);
            Assert.IsNotNull(record);
            Assert.IsTrue(record.EncryptedBlob.SequenceEqual(blob));
        }

        [TestMethod]
        public async Task InsertOrUpdateAsync_UpdatesExistingRecord()
        {
            // Arrange
            using var repo = await CreateRepositoryAsync();
            var publisherKey = new byte[] { 1, 2, 3 };
            var consumerKey = new byte[] { 4, 5, 6 };
            var key = "testKey";
            var blob1 = new byte[] { 7, 8, 9 };
            var blob2 = new byte[] { 10, 11, 12 };

            // Act
            await repo.InsertOrUpdateAsync(publisherKey, consumerKey, key, blob1);
            await repo.InsertOrUpdateAsync(publisherKey, consumerKey, key, blob2);

            // Assert
            var record = await repo.GetAsync(publisherKey, consumerKey, key);
            Assert.IsNotNull(record);
            Assert.IsTrue(record.EncryptedBlob.SequenceEqual(blob2));
        }

        [TestMethod]
        public async Task BulkInsertOrUpdateAsync_InsertsMultipleRecords()
        {
            // Arrange
            using var repo = await CreateRepositoryAsync();
            var records = new[]
            {
                (new byte[] { 1, 2, 3 }, new byte[] { 4, 5, 6 }, "key1", new byte[] { 7, 8, 9 }),
                (new byte[] { 1, 2, 3 }, new byte[] { 4, 5, 6 }, "key2", new byte[] { 10, 11, 12 })
            };

            // Act
            await repo.BulkInsertOrUpdateAsync(records);

            // Assert
            var record1 = await repo.GetAsync(records[0].Item1, records[0].Item2, records[0].Item3);
            var record2 = await repo.GetAsync(records[1].Item1, records[1].Item2, records[1].Item3);
            Assert.IsNotNull(record1);
            Assert.IsNotNull(record2);
            Assert.IsTrue(record1.EncryptedBlob.SequenceEqual(records[0].Item4));
            Assert.IsTrue(record2.EncryptedBlob.SequenceEqual(records[1].Item4));
        }

        [TestMethod]
        public async Task GetAsync_ReturnsNullForNonExistentRecord()
        {
            // Arrange
            using var repo = await CreateRepositoryAsync();
            var publisherKey = new byte[] { 1, 2, 3 };
            var consumerKey = new byte[] { 4, 5, 6 };
            var key = "nonExistentKey";

            // Act
            var record = await repo.GetAsync(publisherKey, consumerKey, key);

            // Assert
            Assert.IsNull(record);
        }

        [TestMethod]
        public async Task ListKeysAsync_ReturnsCorrectKeys()
        {
            // Arrange
            using var repo = await CreateRepositoryAsync();
            var publisherKey = new byte[] { 1, 2, 3 };
            var consumerKey = new byte[] { 4, 5, 6 };
            var records = new[]
            {
                (publisherKey, consumerKey, "key1", new byte[] { 7, 8, 9 }),
                (publisherKey, consumerKey, "key2", new byte[] { 10, 11, 12 })
            };
            await repo.BulkInsertOrUpdateAsync(records);

            // Act
            var keys = await repo.ListKeysAsync(publisherKey, consumerKey);

            // Assert
            var keyList = keys.Select(k => k.Key).ToList();
            Assert.AreEqual(2, keyList.Count);
            Assert.IsTrue(keyList.Contains("key1"));
            Assert.IsTrue(keyList.Contains("key2"));
        }
    }

    [TestClass]
    public class InMemoryRecordRepositoryTests : RecordRepositoryTests
    {
        protected override Task<IRecordRepository> CreateRepositoryAsync()
        {
            return Task.FromResult((IRecordRepository)new InMemoryRecordRepository());
        }
    }

    [TestClass]
    public class SqliteRecordRepositoryTests : RecordRepositoryTests
    {
        private string? _dbPath;

        [TestInitialize]
        public void Initialize()
        {
            _dbPath = $"test_{Guid.NewGuid()}.db";
            if (File.Exists(_dbPath))
                File.Delete(_dbPath);
        }

        [TestCleanup]
        public void Cleanup()
        {
            if (File.Exists(_dbPath))
                File.Delete(_dbPath);
        }

        protected override async Task<IRecordRepository> CreateRepositoryAsync()
        {
            var connectionString = $"Data Source={_dbPath!};Pooling=False;";
            var sqliteRepository = new SqliteRecordRepository(connectionString);
            await sqliteRepository.InitializeAsync();
            return sqliteRepository;
        }
    }
}
