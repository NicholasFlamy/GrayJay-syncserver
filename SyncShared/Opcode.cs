namespace SyncShared;

public enum Opcode : byte
{
    PING = 0,
    PONG = 1,
    NOTIFY = 2,
    STREAM = 3,
    DATA = 4,
    REQUEST = 5,
    RESPONSE = 6,
    RELAY = 7
}

public enum NotifyOpcode : byte
{
    AUTHORIZED = 0,
    UNAUTHORIZED = 1,
    CONNECTION_INFO = 2
}

public enum StreamOpcode : byte
{
    START = 0,
    DATA = 1,
    END = 2
}

public enum RequestOpcode : byte
{
    CONNECTION_INFO = 0,
    TRANSPORT = 1,
    TRANSPORT_RELAYED = 2,
    PUBLISH_RECORD = 3,
    DELETE_RECORD = 4,
    LIST_RECORD_KEYS = 5,
    GET_RECORD = 6,
    BULK_PUBLISH_RECORD = 7,
    BULK_GET_RECORD = 8,
    BULK_CONNECTION_INFO = 9,
    BULK_DELETE_RECORD = 10
}

public enum ResponseOpcode : byte
{
    CONNECTION_INFO = 0,
    TRANSPORT = 1,
    TRANSPORT_RELAYED = 2, //TODO: Server errors also included in this one, disentangle?
    PUBLISH_RECORD = 3,
    DELETE_RECORD = 4,
    LIST_RECORD_KEYS = 5,
    GET_RECORD = 6,
    BULK_PUBLISH_RECORD = 7,
    BULK_GET_RECORD = 8,
    BULK_CONNECTION_INFO = 9,
    BULK_DELETE_RECORD = 10
}

public enum RelayOpcode : byte
{
    DATA = 0,
    RELAYED_DATA = 1,
    ERROR = 2,
    RELAYED_ERROR = 3 //TODO: Server errors also included in this one, disentangle?
}