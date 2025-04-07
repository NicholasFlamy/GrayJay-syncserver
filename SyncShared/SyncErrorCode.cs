using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SyncShared;

public enum SyncErrorCode
{
    Success = 0,                   // Operation completed successfully
    GeneralError = 1,              // Generic error (used in multiple places when something fails unexpectedly)
    NotFound = 2,                  // Resource (e.g., connection, record) not found
    Unauthorized = 3,              // Unauthorized access attempt
    RateLimitExceeded = 4,         // Rate limit exceeded (e.g., relay data or publish requests)
    StorageLimitExceeded = 5,      // Storage limit exceeded (e.g., KV storage limit per publisher)
    InvalidData = 6,               // Invalid data format or size
    ConnectionClosed = 7           // Connection was closed or stream ended unexpectedly
}