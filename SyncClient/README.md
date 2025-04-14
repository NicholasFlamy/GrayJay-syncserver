## 1. Top-Level Communication and Encryption

The SyncServer and SyncClient communicate over a TCP connection, secured using the Noise protocol with the IK handshake pattern, ChaChaPoly cipher, and Blake2b hash function. This handshake ensures mutual authentication and key exchange, establishing a secure transport layer.

### Handshake Process

- **Initiator (Client):**
  - Sends a 4-byte protocol version (little-endian integer).
  - Initiates the Noise IK handshake by sending the first handshake message.
  - Receives and processes the server's response to complete the handshake.

- **Responder (Server):**
  - Receives and verifies the protocol version (minimum version: 2).
  - Processes the client's handshake message and responds with its own handshake message.
  - Completes the handshake upon receiving the client's final message.

Upon completion, both parties derive a shared secret and establish a secure transport channel. The client's public key is verified by the server, and the server's public key is used by the client to initiate the handshake.

### Packet Structure

All packets are prefixed with a 4-byte little-endian integer indicating the packet size (excluding the prefix itself).

- **Handshake Packets:**
  - **Format:** `[Size (4 bytes)] [Noise Handshake Message (variable)]`
  - Sent unencrypted during the handshake phase.

- **Data Packets:**
  - **Format:** `[Size (4 bytes)] [Encrypted Payload (variable)]`
  - Encrypted using the Noise transport established post-handshake.
  - Maximum encrypted size: 65535 bytes.

---

## 2. The Flow of Writing Data

After the handshake, data is transmitted over the secure channel using a structured packet format.

### Data Packet Structure

- **Decrypted Format:** `[Size (4 bytes)] [Opcode (1 byte)] [SubOpcode (1 byte)] [Payload (variable)]`
  - **Size:** Little-endian integer, length of `[Opcode] [SubOpcode] [Payload]`.
  - **Opcode:** Operation type (e.g., `0x00` for PING, `0x07` for DATA).
  - **SubOpcode:** Additional operation context.
  - **Payload:** Operation-specific data.

- **Encrypted Format:** `[Size (4 bytes)] [Encrypted Data (variable)]`
  - **Size:** Length of the encrypted `[Size] [Opcode] [SubOpcode] [Payload]`.
  - **Encrypted Data:** ChaChaPoly-encrypted with a 16-byte authentication tag appended.

### Sending Data

- **Sender (Client or Server):**
  - Constructs the decrypted packet: `[Size] [Opcode] [SubOpcode] [Payload]`.
  - Encrypts it using the Noise transport, appending the 16-byte tag.
  - Prefixes the encrypted data with a 4-byte size field.
  - Sends the packet over TCP.

- **Receiver:**
  - Reads the 4-byte size prefix.
  - Reads the specified number of bytes into a buffer.
  - Decrypts the packet using the Noise transport.
  - Verifies the size field in the decrypted data matches the payload length.
  - Processes the packet based on the opcode and subOpcode.

### Handling Large Data

For payloads exceeding the maximum packet size (65519 bytes decrypted), data is split across multiple packets:
- **STREAM_START:** `[Size (4 bytes)] [0x04 (1 byte)] [0x00 (1 byte)] [StreamID (4 bytes)] [TotalSize (4 bytes)] [Opcode (1 byte)] [SubOpcode (1 byte)] [Data (variable)]`
- **STREAM_DATA:** `[Size (4 bytes)] [0x05 (1 byte)] [0x00 (1 byte)] [StreamID (4 bytes)] [Offset (4 bytes)] [Data (variable)]`
- **STREAM_END:** `[Size (4 bytes)] [0x06 (1 byte)] [0x00 (1 byte)] [StreamID (4 bytes)] [Offset (4 bytes)] [Data (variable)]`
- The receiver reassembles the data using the StreamID and Offset, processing it once STREAM_END is received.

---

## 3. The Flow of Publishing/Requesting Connection Info and Relevant Encryption

Clients publish connection information to the server, which other authorized clients can request. The data is encrypted for specific recipients.

### Publishing Connection Info

- **Client:**
  - Collects connection details (port, IP addresses, etc.).
  - Serializes into a byte array: `[Port (2 bytes)] [NameLength (1 byte)] [Name (variable)] [IPv4Count (1 byte)] [IPv4Addresses (4 bytes each)] [IPv6Count (1 byte)] [IPv6Addresses (16 bytes each)] [AllowLocal (1 byte)] [AllowRemoteDirect (1 byte)] [AllowRemoteHolePunched (1 byte)] [AllowRemoteRelayed (1 byte)]`.
  - For each authorized public key:
    - Performs a Noise N handshake (one-way authentication) using the authorized key as the remote static key.
    - Encrypts the serialized data with the derived transport.
    - Constructs an entry: `[PublicKey (32 bytes)] [HandshakeMessage (48 bytes)] [CiphertextLength (4 bytes)] [Ciphertext (variable)]`.
  - Sends a PUBLISH_CONNECTION_INFO packet: `[Size (4 bytes)] [0x08 (1 byte)] [0x00 (1 byte)] [NumEntries (1 byte)] [Entries (variable)]`.

- **Server:**
  - Receives the packet and stores each entry, indexed by the client's public key and the intended recipient's public key.

### Requesting Connection Info

- **Client:**
  - Sends a REQUEST_CONNECTION_INFO packet: `[Size (4 bytes)] [0x09 (1 byte)] [0x00 (1 byte)] [RequestID (4 bytes)] [TargetPublicKey (32 bytes)]`.
  - Awaits a RESPONSE_CONNECTION_INFO packet.

- **Server:**
  - Retrieves the stored entry for the requesting client and target public key.
  - Sends a RESPONSE_CONNECTION_INFO packet:
    - Success: `[Size (4 bytes)] [0x0A (1 byte)] [0x00 (1 byte)] [RequestID (4 bytes)] [IPSize (1 byte)] [RemoteIP (variable)] [HandshakeMessage (48 bytes)] [Ciphertext (variable)]`.
    - Failure: `[Size (4 bytes)] [0x0A (1 byte)] [0x01 (1 byte)] [RequestID (4 bytes)]`.

- **Client:**
  - Receives the response.
  - If successful, completes the Noise N handshake with its private key, decrypts the ciphertext, and parses the connection info.

---

## 4. The Flow of Establishing a Sub-Channel and Relevant Encryption

Sub-channels enable multiplexed, end-to-end encrypted communication between clients, relayed through the server.

### Flow for Establishing a Sub-Channel

- **Initiator (Client A):**
  - Creates a Channel object with a local key pair and the target public key.
  - Initiates a Noise IK handshake, generating the first message.
  - Sends a REQUEST_RELAYED_TRANSPORT packet: `[Size (4 bytes)] [0x0B (1 byte)] [0x00 (1 byte)] [RequestID (4 bytes)] [TargetPublicKey (32 bytes)] [MessageLength (4 bytes)] [HandshakeMessage (variable)]`.

- **Server:**
  - Assigns a ConnectionID (8 bytes).
  - Forwards to the target (Client B): `[Size (4 bytes)] [0x0B (1 byte)] [0x00 (1 byte)] [ConnectionID (8 bytes)] [RequestID (4 bytes)] [InitiatorPublicKey (32 bytes)] [MessageLength (4 bytes)] [HandshakeMessage (variable)]`.

- **Target (Client B):**
  - Creates a Channel object and processes the handshake message.
  - Generates the response handshake message.
  - Sends a RESPONSE_RELAYED_TRANSPORT packet: `[Size (4 bytes)] [0x0C (1 byte)] [0x00 (1 byte)] [ConnectionID (8 bytes)] [RequestID (4 bytes)] [MessageLength (4 bytes)] [HandshakeMessage (variable)]`.

- **Server:**
  - Forwards to the initiator: `[Size (4 bytes)] [0x0C (1 byte)] [0x00 (1 byte)] [RequestID (4 bytes)] [ConnectionID (8 bytes)] [MessageLength (4 bytes)] [HandshakeMessage (variable)]`.

- **Initiator (Client A):**
  - Processes the response, completes the handshake, and establishes the transport.

### Encryption for Sub-Channels

- Each sub-channel uses a separate Noise IK handshake.
- Handshake messages are relayed through the server but remain opaque, ensuring end-to-end encryption between clients.

---

## 5. Sending Data Over a Sub-Channel

Data is transmitted over sub-channels using the RELAYED_DATA opcode, encrypted end-to-end.

### Data Packet Structure for Sub-Channels

- **Outer Packet (Server-Relayed):** `[Size (4 bytes)] [0x0D (1 byte)] [SubOpcode (1 byte)] [ConnectionID (8 bytes)] [EncryptedPayload (variable)]`
- **Inner Packet (Decrypted by Client):** `[Size (4 bytes)] [Opcode (1 byte)] [SubOpcode (1 byte)] [Data (variable)]`
  - Encrypted with the sub-channel’s Noise transport, appending a 16-byte tag.

### Sending Data

- **Sender (Client A or B):**
  - Constructs the inner packet.
  - Encrypts it with the sub-channel’s transport.
  - Wraps it in a RELAYED_DATA packet with the ConnectionID.
  - Sends it to the server.

- **Server:**
  - Forwards the packet to the other client based on the ConnectionID.

- **Receiver (Client B or A):**
  - Decrypts the payload using the sub-channel’s transport.
  - Processes the inner packet.

### Handling Large Data

For data exceeding the maximum size:
- **STREAM_START:** `[Size (4 bytes)] [0x04 (1 byte)] [0x00 (1 byte)] [StreamID (4 bytes)] [TotalSize (4 bytes)] [Opcode (1 byte)] [SubOpcode (1 byte)] [Data (variable)]`
- **STREAM_DATA:** `[Size (4 bytes)] [0x05 (1 byte)] [0x00 (1 byte)] [StreamID (4 bytes)] [Offset (4 bytes)] [Data (variable)]`
- **STREAM_END:** `[Size (4 bytes)] [0x06 (1 byte)] [0x00 (1 byte)] [StreamID (4 bytes)] [Offset (4 bytes)] [Data (variable)]`
- Each segment is encrypted and sent as a RELAYED_DATA packet, reassembled by the receiver.

--- 

This document provides a concise, byte-level reference for the SyncServer and SyncClient protocol, tailored for engineering implementation and maintenance.