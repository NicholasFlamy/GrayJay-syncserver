namespace SyncServer.Repositories;

//Actual data structure
public class Record
{
    //32 bytes
    public required byte[] PublisherPublicKey { get; init; }
    //32 bytes
    public required byte[] ConsumerPublicKey { get; init; }
    //Maximum 32 characters
    public required string Key { get; init; }
    public required byte[] EncryptedBlob { get; init; }
    public DateTime Timestamp { get; init; }
}