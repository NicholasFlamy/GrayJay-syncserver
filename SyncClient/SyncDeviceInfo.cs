using System.Text.Json.Serialization;

namespace SyncClient;

public class SyncDeviceInfo
{
    [JsonPropertyName("publicKey")]
    public string PublicKey { get; set; }

    [JsonPropertyName("addresses")]
    public string[] Addresses { get; set; }

    [JsonPropertyName("port")]
    public int Port { get; set; }

    [JsonPropertyName("pairingCode")]
    public string? PairingCode { get; set; }

    public SyncDeviceInfo(string publicKey, string[] addresses, int port, string? pairingCode)
    {
        PublicKey = publicKey;
        Addresses = addresses;
        Port = port;
        PairingCode = pairingCode;
    }
}
