using FirebaseAdmin;
using Google.Apis.Auth.OAuth2;
using Noise;
using SyncServer.Repositories;
using SyncShared;
using System.Text.Json;

namespace SyncServer;

class Program
{

    private const string _dbPath = "records.db";
    private const string _dbDevicetokensPath = "deviceTokens.db";

    static async Task Main()
    {
        var firebaseApps = new Dictionary<string, FirebaseApp>();
        if (Directory.Exists("ServiceAccounts"))
        {
            foreach (var path in Directory.GetFiles("ServiceAccounts"))
            {
                var appName = Path.GetFileNameWithoutExtension(path);
                firebaseApps[appName] = FirebaseApp.Create(new AppOptions()
                {
                    Credential = GoogleCredential.FromFile(path)
                }, appName);
            }
        }

        KeyPair keyPair;
        try
        {
            var syncKeyPair = JsonSerializer.Deserialize(File.ReadAllText("key.txt"), SyncKeyPairContext.Default.SyncKeyPair);
            keyPair = new KeyPair(Convert.FromBase64String(syncKeyPair!.PrivateKey), Convert.FromBase64String(syncKeyPair!.PublicKey));
        }
        catch (Exception ex)
        {
            // Key pair non-existing, invalid or lost
            var p = KeyPair.Generate();
            var syncKeyPair = new SyncKeyPair(1, Convert.ToBase64String(p.PublicKey), Convert.ToBase64String(p.PrivateKey));
            File.WriteAllText("key.txt", JsonSerializer.Serialize(syncKeyPair, SyncKeyPairContext.Default.SyncKeyPair));
            Logger.Error(nameof(Program), "Failed to load existing key pair", ex);
            keyPair = p;
        }

        var publicKey = Convert.ToBase64String(keyPair.PublicKey);
        Console.WriteLine("Public Key: " + publicKey);

        using var recordRepository = new SqliteRecordRepository($"Data Source={_dbPath};Pooling=False;");
        await recordRepository.InitializeAsync();
        using var deviceTokenRepository = new SqliteDeviceTokenRepository($"Data Source={_dbDevicetokensPath};Pooling=False;");
        await deviceTokenRepository.InitializeAsync();

        using var server = new TcpSyncServer(9000, keyPair, recordRepository, deviceTokenRepository, firebaseApps);
        server.Start();

        var builder = WebApplication.CreateBuilder();
        builder.Services.AddSingleton<IDictionary<string, FirebaseApp>>(firebaseApps);
        builder.Services.AddLogging((logBuilder) =>
        {
            logBuilder.ClearProviders();
            logBuilder.AddProvider(new LoggerLoggerProvider());
        });
        using var app = builder.Build();
        app.MapGet("/", () => Results.Text(JsonSerializer.Serialize(server.Metrics, TcpSyncServerMetricsContext.Default.TcpSyncServerMetrics), "text/json"));
        app.MapGet("/prometheus", () =>
        {
            var metrics = server.Metrics;
            var sb = new System.Text.StringBuilder();

            void AppendMetric(string name, string help, string type, long value)
            {
                sb.AppendLine($"# HELP {name} {help}");
                sb.AppendLine($"# TYPE {name} {type}");
                sb.AppendLine($"{name} {value}");
            }

            // Connection metrics
            AppendMetric("tcpsyncserver_active_connections", "Number of currently active connections", "gauge", metrics.ActiveConnections);
            AppendMetric("tcpsyncserver_total_connections_accepted", "Total number of connections accepted", "counter", metrics.TotalConnectionsAccepted);
            AppendMetric("tcpsyncserver_total_connections_closed", "Total number of connections closed", "counter", metrics.TotalConnectionsClosed);
            AppendMetric("tcpsyncserver_total_handshake_attempts", "Total number of handshake attempts", "counter", metrics.TotalHandshakeAttempts);
            AppendMetric("tcpsyncserver_total_handshake_successes", "Total number of successful handshakes", "counter", metrics.TotalHandshakeSuccesses);

            // Relayed connection metrics
            AppendMetric("tcpsyncserver_total_relayed_connections_requested", "Total number of relayed connections requested", "counter", metrics.TotalRelayedConnectionsRequested);
            AppendMetric("tcpsyncserver_total_relayed_connections_established", "Total number of relayed connections established", "counter", metrics.TotalRelayedConnectionsEstablished);
            AppendMetric("tcpsyncserver_total_relayed_connections_failed", "Total number of relayed connections failed", "counter", metrics.TotalRelayedConnectionsFailed);
            AppendMetric("tcpsyncserver_total_relayed_data_bytes", "Total number of relayed data bytes", "counter", metrics.TotalRelayedDataBytes);
            AppendMetric("tcpsyncserver_total_relayed_error_bytes", "Total number of relayed error bytes", "counter", metrics.TotalRelayedErrorBytes);

            // Record operation metrics
            AppendMetric("tcpsyncserver_total_publish_record_requests", "Total number of publish record requests", "counter", metrics.TotalPublishRecordRequests);
            AppendMetric("tcpsyncserver_total_delete_record_requests", "Total number of delete record requests", "counter", metrics.TotalDeleteRecordRequests);
            AppendMetric("tcpsyncserver_total_list_keys_requests", "Total number of list keys requests", "counter", metrics.TotalListKeysRequests);
            AppendMetric("tcpsyncserver_total_get_record_requests", "Total number of get record requests", "counter", metrics.TotalGetRecordRequests);
            AppendMetric("tcpsyncserver_total_publish_record_successes", "Total number of successful publish record operations", "counter", metrics.TotalPublishRecordSuccesses);
            AppendMetric("tcpsyncserver_total_delete_record_successes", "Total number of successful delete record operations", "counter", metrics.TotalDeleteRecordSuccesses);
            AppendMetric("tcpsyncserver_total_list_keys_successes", "Total number of successful list keys operations", "counter", metrics.TotalListKeysSuccesses);
            AppendMetric("tcpsyncserver_total_get_record_successes", "Total number of successful get record operations", "counter", metrics.TotalGetRecordSuccesses);
            AppendMetric("tcpsyncserver_total_publish_record_failures", "Total number of failed publish record operations", "counter", metrics.TotalPublishRecordFailures);
            AppendMetric("tcpsyncserver_total_delete_record_failures", "Total number of failed delete record operations", "counter", metrics.TotalDeleteRecordFailures);
            AppendMetric("tcpsyncserver_total_list_keys_failures", "Total number of failed list keys operations", "counter", metrics.TotalListKeysFailures);
            AppendMetric("tcpsyncserver_total_get_record_failures", "Total number of failed get record operations", "counter", metrics.TotalGetRecordFailures);

            // Storage limit metrics
            AppendMetric("tcpsyncserver_total_storage_limit_exceedances", "Total number of storage limit exceedances", "counter", metrics.TotalStorageLimitExceedances);

            // Operation time metrics
            AppendMetric("tcpsyncserver_total_publish_record_time_ms", "Total time spent on publish record operations in milliseconds", "counter", metrics.TotalPublishRecordTimeMs);
            AppendMetric("tcpsyncserver_publish_record_count", "Total number of publish record operations", "counter", metrics.PublishRecordCount);
            AppendMetric("tcpsyncserver_total_delete_record_time_ms", "Total time spent on delete record operations in milliseconds", "counter", metrics.TotalDeleteRecordTimeMs);
            AppendMetric("tcpsyncserver_delete_record_count", "Total number of delete record operations", "counter", metrics.DeleteRecordCount);
            AppendMetric("tcpsyncserver_total_list_keys_time_ms", "Total time spent on list keys operations in milliseconds", "counter", metrics.TotalListKeysTimeMs);
            AppendMetric("tcpsyncserver_list_keys_count", "Total number of list keys operations", "counter", metrics.ListKeysCount);
            AppendMetric("tcpsyncserver_total_get_record_time_ms", "Total time spent on get record operations in milliseconds", "counter", metrics.TotalGetRecordTimeMs);
            AppendMetric("tcpsyncserver_get_record_count", "Total number of get record operations", "counter", metrics.GetRecordCount);

            // Memory and buffer metrics
            AppendMetric("tcpsyncserver_total_rented", "Total number of rented resources", "counter", metrics.TotalRented);
            AppendMetric("tcpsyncserver_total_returned", "Total number of returned resources", "counter", metrics.TotalReturned);
            AppendMetric("tcpsyncserver_memory_usage_bytes", "Current memory usage in bytes", "gauge", metrics.MemoryUsage);
            AppendMetric("tcpsyncserver_active_relayed_connections", "Number of currently active relayed connections", "gauge", metrics.ActiveRelayedConnections);

            // GC counts per generation
            sb.AppendLine("# HELP tcpsyncserver_gc_counts Number of garbage collections per generation");
            sb.AppendLine("# TYPE tcpsyncserver_gc_counts gauge");
            var gcCounts = metrics.GCCounts;
            for (int i = 0; i < gcCounts.Length; i++)
            {
                sb.AppendLine($"tcpsyncserver_gc_counts{{generation=\"{i}\"}} {gcCounts[i]}");
            }

            // Server start time
            AppendMetric("tcpsyncserver_start_time_seconds", "Start time of the server in seconds since epoch", "gauge", metrics.StartTime);

            // Rate limit exceedances
            AppendMetric("tcpsyncserver_total_keypair_registration_rate_limit_exceedances", "Total number of keypair registration rate limit exceedances", "counter", metrics.TotalKeypairRegistrationRateLimitExceedances);
            AppendMetric("tcpsyncserver_total_relay_request_by_ip_token_rate_limit_exceedances", "Total number of relay request by IP token rate limit exceedances", "counter", metrics.TotalRelayRequestByIpTokenRateLimitExceedances);
            AppendMetric("tcpsyncserver_total_relay_request_by_ip_connection_limit_exceedances", "Total number of relay request by IP connection limit exceedances", "counter", metrics.TotalRelayRequestByIpConnectionLimitExceedances);
            AppendMetric("tcpsyncserver_total_relay_request_by_key_token_rate_limit_exceedances", "Total number of relay request by key token rate limit exceedances", "counter", metrics.TotalRelayRequestByKeyTokenRateLimitExceedances);
            AppendMetric("tcpsyncserver_total_relay_request_by_key_connection_limit_exceedances", "Total number of relay request by key connection limit exceedances", "counter", metrics.TotalRelayRequestByKeyConnectionLimitExceedances);
            AppendMetric("tcpsyncserver_total_relay_data_by_ip_rate_limit_exceedances", "Total number of relay data by IP rate limit exceedances", "counter", metrics.TotalRelayDataByIpRateLimitExceedances);
            AppendMetric("tcpsyncserver_total_relay_data_by_connection_id_rate_limit_exceedances", "Total number of relay data by connection ID rate limit exceedances", "counter", metrics.TotalRelayDataByConnectionIdRateLimitExceedances);
            AppendMetric("tcpsyncserver_total_publish_request_rate_limit_exceedances", "Total number of publish request rate limit exceedances", "counter", metrics.TotalPublishRequestRateLimitExceedances);

            // Connection info metrics
            AppendMetric("tcpsyncserver_total_publish_connection_info_successes", "Total number of successful publish connection info operations", "counter", metrics.TotalPublishConnectionInfoSuccesses);
            AppendMetric("tcpsyncserver_total_publish_connection_info_count", "Total number of publish connection info operations", "counter", metrics.TotalPublishConnectionInfoCount);
            AppendMetric("tcpsyncserver_total_publish_connection_info_failures", "Total number of failed publish connection info operations", "counter", metrics.TotalPublishConnectionInfoFailures);
            AppendMetric("tcpsyncserver_total_publish_connection_info_time_ms", "Total time spent on publish connection info operations in milliseconds", "counter", metrics.TotalPublishConnectionInfoTimeMs);
            AppendMetric("tcpsyncserver_total_request_connection_info_successes", "Total number of successful request connection info operations", "counter", metrics.TotalRequestConnectionInfoSuccesses);
            AppendMetric("tcpsyncserver_total_request_connection_info_failures", "Total number of failed request connection info operations", "counter", metrics.TotalRequestConnectionInfoFailures);
            AppendMetric("tcpsyncserver_total_request_connection_info_time_ms", "Total time spent on request connection info operations in milliseconds", "counter", metrics.TotalRequestConnectionInfoTimeMs);
            AppendMetric("tcpsyncserver_total_request_bulk_connection_info_successes", "Total number of successful bulk request connection info operations", "counter", metrics.TotalRequestBulkConnectionInfoSuccesses);
            AppendMetric("tcpsyncserver_total_request_bulk_connection_info_failures", "Total number of failed bulk request connection info operations", "counter", metrics.TotalRequestBulkConnectionInfoFailures);
            AppendMetric("tcpsyncserver_total_request_bulk_connection_info_time_ms", "Total time spent on bulk request connection info operations in milliseconds", "counter", metrics.TotalRequestBulkConnectionInfoTimeMs);

            // Current state metrics
            AppendMetric("tcpsyncserver_available_connection_slots", "Available connection slots", "gauge", metrics.MaxConnectionsCount);
            AppendMetric("tcpsyncserver_connection_info_count", "Number of connection info entries", "gauge", metrics.ConnectionInfoCount);
            AppendMetric("tcpsyncserver_client_count", "Number of clients", "gauge", metrics.ClientCount);
            AppendMetric("tcpsyncserver_session_count", "Number of sessions", "gauge", metrics.SessionCount);

            return Results.Text(sb.ToString(), "text/plain; version=0.0.4");
        });
        app.Run("http://0.0.0.0:3131");

        Console.CancelKeyPress += (_, __) =>
        {
            _ = app.DisposeAsync();
            server.Dispose();
        };
    }
}
