namespace SyncShared;

public enum RelayErrorCode
{
    Success = 0,              // Operation completed successfully
    GeneralError = 1,         // Generic error
    NotFound = 2,             // Resource not found
    Unauthorized = 3,         // Unauthorized access attempt
    RateLimitExceeded = 4,    // Rate limit exceeded
    StorageLimitExceeded = 5, // Storage limit exceeded
    InvalidData = 6,          // Invalid data format or size
    ConnectionClosed = 7      // Connection was closed
}

public enum ConnectionInfoResponseCode
{
    Success = 0,         // Connection info retrieved successfully
    InvalidRequest = 1,  // Invalid data length or format (e.g., public key not 32 bytes)
    NotFound = 2         // Target connection info not found
}

public enum TransportResponseCode
{
    Success = 0,           // Transport setup successful
    GeneralError = 1,      // Generic error (e.g., invalid packet size, blacklist)
    RateLimitExceeded = 2, // Rate limit exceeded by IP or key
    PairingCodeDataMismatch = 3,
    ChannelMessageDataLengthMismatch = 4,
    Blacklisted = 5,
    DuplicateConnection = 6,
    Rejected = 7
}

public enum PublishRecordResponseCode
{
    Success = 0,             // Record published successfully
    GeneralError = 1,        // Generic error (e.g., exception in task)
    InvalidRequest = 2,      // Invalid packet size or key length
    RateLimitExceeded = 3,   // Publish request rate limit exceeded
    StorageLimitExceeded = 4, // Storage limit exceeded
    ConsumerPublicKeyDataLengthMismatch = 5,
    BlobPublicKeyDataLengthMismatch = 6
}

public enum BulkPublishRecordResponseCode
{
    Success = 0,             // Records published successfully
    GeneralError = 1,        // Generic error
    InvalidRequest = 2,      // Invalid packet size or format
    StorageLimitExceeded = 3 // Storage limit exceeded
}

public enum DeleteRecordResponseCode
{
    Success = 0,        // Record deleted successfully
    GeneralError = 1,   // Generic error
    Unauthorized = 2,   // Sender not authorized
    InvalidRequest = 3  // Invalid packet size or key length
}

public enum BulkDeleteRecordResponseCode
{
    Success = 0,        // Records deleted successfully
    GeneralError = 1,   // Generic error
    Unauthorized = 2,   // Sender not authorized
    InvalidRequest = 3  // Invalid packet size or format
}

public enum ListRecordKeysResponseCode
{
    Success = 0,        // Keys listed successfully
    GeneralError = 1,   // Generic error
    Unauthorized = 2,   // Sender not authorized
    InvalidRequest = 3  // Invalid packet size
}

public enum GetRecordResponseCode
{
    Success = 0,        // Record retrieved successfully
    GeneralError = 1,   // Generic error
    NotFound = 2,       // Record not found
    InvalidRequest = 3  // Invalid packet size or key length
}

public enum BulkGetRecordResponseCode
{
    Success = 0,        // Records retrieved successfully
    GeneralError = 1,   // Generic error
    InvalidRequest = 2  // Invalid packet size or format
}

public enum BulkConnectionInfoResponseCode
{
    Success = 0,        // Connection info retrieved successfully
    InvalidRequest = 1  // Invalid packet size or format
}