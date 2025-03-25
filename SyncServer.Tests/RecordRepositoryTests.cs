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

        [TestMethod]
        public async Task DeleteAsync_RemovesExistingRecord()
        {
            // Arrange
            using var repo = await CreateRepositoryAsync();
            var publisherKey = new byte[] { 1, 2, 3 };
            var consumerKey = new byte[] { 4, 5, 6 };
            var key = "testKey";
            var blob = new byte[] { 7, 8, 9 };
            await repo.InsertOrUpdateAsync(publisherKey, consumerKey, key, blob);
            var recordBefore = await repo.GetAsync(publisherKey, consumerKey, key);
            Assert.IsNotNull(recordBefore, "Record should exist before deletion.");

            // Act
            await repo.DeleteAsync(publisherKey, consumerKey, key);

            // Assert
            var recordAfter = await repo.GetAsync(publisherKey, consumerKey, key);
            Assert.IsNull(recordAfter, "Record should be null after deletion.");
        }

        [TestMethod]
        public async Task DeleteAsync_NonExistentRecord_DoesNothing()
        {
            // Arrange
            using var repo = await CreateRepositoryAsync();
            var publisherKey = new byte[] { 1, 2, 3 };
            var consumerKey = new byte[] { 4, 5, 6 };
            var key = "nonExistentKey";

            // Act
            await repo.DeleteAsync(publisherKey, consumerKey, key);

            // Assert
            var anotherKey = "anotherKey";
            var blob = new byte[] { 7, 8, 9 };
            await repo.InsertOrUpdateAsync(publisherKey, consumerKey, anotherKey, blob);
            var record = await repo.GetAsync(publisherKey, consumerKey, anotherKey);
            Assert.IsNotNull(record, "Other records should remain unaffected.");
        }

        [TestMethod]
        public async Task GetByPublishersAsync_ReturnsCorrectRecords()
        {
            // Arrange
            using var repo = await CreateRepositoryAsync();
            var consumerKey = new byte[] { 4, 5, 6 };
            var publisherKey1 = new byte[] { 1, 2, 3 };
            var publisherKey2 = new byte[] { 7, 8, 9 };
            var key = "testKey";
            var blob1 = new byte[] { 10, 11, 12 };
            var blob2 = new byte[] { 13, 14, 15 };
            await repo.InsertOrUpdateAsync(publisherKey1, consumerKey, key, blob1);
            await repo.InsertOrUpdateAsync(publisherKey2, consumerKey, key, blob2);

            // Act
            var records = await repo.GetByPublishersAsync(consumerKey, new[] { publisherKey1, publisherKey2 }, key);

            // Assert
            var recordList = records.ToList();
            Assert.AreEqual(2, recordList.Count, "Should return exactly 2 records.");
            var record1 = recordList.FirstOrDefault(r => r.PublisherPublicKey.SequenceEqual(publisherKey1));
            var record2 = recordList.FirstOrDefault(r => r.PublisherPublicKey.SequenceEqual(publisherKey2));
            Assert.IsNotNull(record1, "Record for publisherKey1 should exist.");
            Assert.IsNotNull(record2, "Record for publisherKey2 should exist.");
            Assert.IsTrue(record1.EncryptedBlob.SequenceEqual(blob1), "Blob for publisherKey1 should match.");
            Assert.IsTrue(record2.EncryptedBlob.SequenceEqual(blob2), "Blob for publisherKey2 should match.");
        }

        [TestMethod]
        public async Task GetByPublishersAsync_NoRecords_ReturnsEmpty()
        {
            // Arrange
            using var repo = await CreateRepositoryAsync();
            var consumerKey = new byte[] { 4, 5, 6 };
            var publisherKeys = new[] { new byte[] { 1, 2, 3 }, new byte[] { 7, 8, 9 } };
            var key = "testKey";

            // Act
            var records = await repo.GetByPublishersAsync(consumerKey, publisherKeys, key);

            // Assert
            Assert.AreEqual(0, records.Count(), "Should return an empty collection when no records exist.");
        }

        [TestMethod]
        public async Task BulkDeleteAsync_DeletesSpecifiedRecords()
        {
            // Arrange
            using var repo = await CreateRepositoryAsync();
            var publisherKey = new byte[] { 1, 2, 3 };
            var consumerKey = new byte[] { 4, 5, 6 };
            var keys = new[] { "key1", "key2", "key3" };
            var blobs = new[] { new byte[] { 7, 8, 9 }, new byte[] { 10, 11, 12 }, new byte[] { 13, 14, 15 } };
            for (int i = 0; i < keys.Length; i++)
            {
                await repo.InsertOrUpdateAsync(publisherKey, consumerKey, keys[i], blobs[i]);
            }

            // Act
            await repo.BulkDeleteAsync(publisherKey, consumerKey, new[] { "key1", "key3" });

            // Assert
            var record1 = await repo.GetAsync(publisherKey, consumerKey, "key1");
            var record2 = await repo.GetAsync(publisherKey, consumerKey, "key2");
            var record3 = await repo.GetAsync(publisherKey, consumerKey, "key3");
            Assert.IsNull(record1, "key1 should be deleted.");
            Assert.IsNotNull(record2, "key2 should remain.");
            Assert.IsNull(record3, "key3 should be deleted.");
        }

        [TestMethod]
        public async Task BulkDeleteAsync_NonExistentKeys_DoesNothing()
        {
            // Arrange
            using var repo = await CreateRepositoryAsync();
            var publisherKey = new byte[] { 1, 2, 3 };
            var consumerKey = new byte[] { 4, 5, 6 };
            var existingKey = "existingKey";
            var blob = new byte[] { 7, 8, 9 };
            await repo.InsertOrUpdateAsync(publisherKey, consumerKey, existingKey, blob);

            // Act
            await repo.BulkDeleteAsync(publisherKey, consumerKey, new[] { "nonExistentKey1", "nonExistentKey2" });

            // Assert
            var record = await repo.GetAsync(publisherKey, consumerKey, existingKey);
            Assert.IsNotNull(record, "Existing record should remain unaffected.");
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
