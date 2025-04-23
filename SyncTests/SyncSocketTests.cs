using Noise;
using SyncClient;
using SyncServerTests;
using SyncShared;
using System.IO.Pipes;

namespace SyncTests;

[TestClass]
public class SyncSocketTests
{
    /// <summary>
    /// Creates pipe streams to simulate communication between initiator and responder.
    /// </summary>
    private (Stream initiatorInput, Stream initiatorOutput, Stream responderInput, Stream responderOutput) CreatePipeStreams()
    {
        var initiatorPipeOut = new AnonymousPipeServerStream(PipeDirection.Out);
        var responderPipeIn = new AnonymousPipeClientStream(PipeDirection.In, initiatorPipeOut.ClientSafePipeHandle);

        var responderPipeOut = new AnonymousPipeServerStream(PipeDirection.Out);
        var initiatorPipeIn = new AnonymousPipeClientStream(PipeDirection.In, responderPipeOut.ClientSafePipeHandle);

        return (initiatorPipeIn, initiatorPipeOut, responderPipeIn, responderPipeOut);
    }

    /// <summary>
    /// Creates SyncSocketSession instances for initiator and responder with the given streams and parameters.
    /// </summary>
    private (SyncSocketSession initiator, SyncSocketSession responder) CreateSessions(
        Stream initiatorInput, Stream initiatorOutput, Stream responderInput, Stream responderOutput,
        KeyPair initiatorKeyPair, KeyPair responderKeyPair,
        Action<SyncSocketSession> onInitiatorHandshakeComplete,
        Action<SyncSocketSession> onResponderHandshakeComplete,
        Action<SyncSocketSession>? onClose = null,
        Func<LinkType, SyncSocketSession, string, string?, uint, bool>? isHandshakeAllowed = null,
        Action<SyncSocketSession, Opcode, byte, ReadOnlySpan<byte>>? onDataA = null,
        Action<SyncSocketSession, Opcode, byte, ReadOnlySpan<byte>>? onDataB = null)
    {
        var initiatorSession = new SyncSocketSession(
            "", initiatorKeyPair, initiatorInput, initiatorOutput,
            onClose: (session) => onClose?.Invoke(session),
            onHandshakeComplete: onInitiatorHandshakeComplete,
            onData: onDataA,
            isHandshakeAllowed: isHandshakeAllowed);

        var responderSession = new SyncSocketSession(
            "", responderKeyPair, responderInput, responderOutput,
            onClose: (session) => onClose?.Invoke(session),
            onHandshakeComplete: onResponderHandshakeComplete,
            onData: onDataB,
            isHandshakeAllowed: isHandshakeAllowed);

        return (initiatorSession, responderSession);
    }

    #region Pairing Code Tests

    [TestMethod]
    public void Handshake_WithValidPairingCode_Succeeds()
    {
        var (initiatorInput, initiatorOutput, responderInput, responderOutput) = CreatePipeStreams();
        var initiatorKeyPair = KeyPair.Generate();
        var responderKeyPair = KeyPair.Generate();
        const string validPairingCode = "secret";

        var handshakeInitiatorCompleted = new ManualResetEventSlim(false);
        var handshakeResponderCompleted = new ManualResetEventSlim(false);

        var (initiatorSession, responderSession) = CreateSessions(
            initiatorInput, initiatorOutput, responderInput, responderOutput,
            initiatorKeyPair, responderKeyPair,
            (session) => handshakeInitiatorCompleted.Set(),
            (session) => handshakeResponderCompleted.Set(),
            isHandshakeAllowed: (linkType, session, publicKey, pairingCode, appId) => pairingCode == validPairingCode);

        _ = initiatorSession.StartAsInitiatorAsync(responderSession.LocalPublicKey, pairingCode: validPairingCode);
        _ = responderSession.StartAsResponderAsync();

        Assert.IsTrue(handshakeInitiatorCompleted.Wait(10000), "Initiator handshake did not complete within 10 seconds.");
        Assert.IsTrue(handshakeResponderCompleted.Wait(10000), "Responder handshake did not complete within 10 seconds.");
    }

    [TestMethod]
    public async Task Handshake_WithInvalidPairingCode_Fails()
    {
        var (initiatorInput, initiatorOutput, responderInput, responderOutput) = CreatePipeStreams();
        var initiatorKeyPair = KeyPair.Generate();
        var responderKeyPair = KeyPair.Generate();
        const string validPairingCode = "secret";
        const string invalidPairingCode = "wrong";

        var handshakeInitiatorCompleted = new ManualResetEventSlim(false);
        var handshakeResponderCompleted = new ManualResetEventSlim(false);

        var (initiatorSession, responderSession) = CreateSessions(
            initiatorInput, initiatorOutput, responderInput, responderOutput,
            initiatorKeyPair, responderKeyPair,
            (session) => handshakeInitiatorCompleted.Set(),
            (session) => handshakeResponderCompleted.Set(),
            isHandshakeAllowed: (linkType, session, publicKey, pairingCode, appId) => pairingCode == validPairingCode);

        _ = initiatorSession.StartAsInitiatorAsync(responderSession.LocalPublicKey, pairingCode: invalidPairingCode);
        _ = responderSession.StartAsResponderAsync();

        await Task.Delay(1000); // Allow time for handshake to fail

        Assert.IsFalse(handshakeInitiatorCompleted.IsSet, "Initiator handshake should not complete with invalid pairing code.");
        Assert.IsFalse(handshakeResponderCompleted.IsSet, "Responder handshake should not complete with invalid pairing code.");
    }

    [TestMethod]
    public async Task Handshake_WithoutPairingCodeWhenRequired_Fails()
    {
        var (initiatorInput, initiatorOutput, responderInput, responderOutput) = CreatePipeStreams();
        var initiatorKeyPair = KeyPair.Generate();
        var responderKeyPair = KeyPair.Generate();
        const string validPairingCode = "secret";

        var handshakeInitiatorCompleted = new ManualResetEventSlim(false);
        var handshakeResponderCompleted = new ManualResetEventSlim(false);

        var (initiatorSession, responderSession) = CreateSessions(
            initiatorInput, initiatorOutput, responderInput, responderOutput,
            initiatorKeyPair, responderKeyPair,
            (session) => handshakeInitiatorCompleted.Set(),
            (session) => handshakeResponderCompleted.Set(),
            isHandshakeAllowed: (linkType, session, publicKey, pairingCode, appId) => pairingCode == validPairingCode);

        _ = initiatorSession.StartAsInitiatorAsync(responderSession.LocalPublicKey); // No pairing code
        _ = responderSession.StartAsResponderAsync();

        await Task.Delay(1000); // Allow time for handshake to fail

        Assert.IsFalse(handshakeInitiatorCompleted.IsSet, "Initiator handshake should not complete without pairing code.");
        Assert.IsFalse(handshakeResponderCompleted.IsSet, "Responder handshake should not complete without pairing code.");
    }

    [TestMethod]
    public void Handshake_WithPairingCodeWhenNotRequired_Succeeds()
    {
        var (initiatorInput, initiatorOutput, responderInput, responderOutput) = CreatePipeStreams();
        var initiatorKeyPair = KeyPair.Generate();
        var responderKeyPair = KeyPair.Generate();
        const string pairingCode = "unnecessary";

        var handshakeInitiatorCompleted = new ManualResetEventSlim(false);
        var handshakeResponderCompleted = new ManualResetEventSlim(false);

        var (initiatorSession, responderSession) = CreateSessions(
            initiatorInput, initiatorOutput, responderInput, responderOutput,
            initiatorKeyPair, responderKeyPair,
            (session) => handshakeInitiatorCompleted.Set(),
            (session) => handshakeResponderCompleted.Set(),
            isHandshakeAllowed: (linkType, session, publicKey, pairingCode, appId) => true); // Always allow

        _ = initiatorSession.StartAsInitiatorAsync(responderSession.LocalPublicKey, pairingCode: pairingCode);
        _ = responderSession.StartAsResponderAsync();

        Assert.IsTrue(handshakeInitiatorCompleted.Wait(10000), "Initiator handshake did not complete within 10 seconds.");
        Assert.IsTrue(handshakeResponderCompleted.Wait(10000), "Responder handshake did not complete within 10 seconds.");
    }

    #endregion

    #region Data Packet Tests

    [TestMethod]
    public async Task SendAndReceive_SmallDataPacket_Succeeds()
    {
        var (initiatorInput, initiatorOutput, responderInput, responderOutput) = CreatePipeStreams();
        var initiatorKeyPair = KeyPair.Generate();
        var responderKeyPair = KeyPair.Generate();

        var handshakeInitiatorCompleted = new ManualResetEventSlim(false);
        var handshakeResponderCompleted = new ManualResetEventSlim(false);
        var dataReceived = new ManualResetEventSlim(false);
        byte[]? receivedData = null;

        var (initiatorSession, responderSession) = CreateSessions(
            initiatorInput, initiatorOutput, responderInput, responderOutput,
            initiatorKeyPair, responderKeyPair,
            (session) => handshakeInitiatorCompleted.Set(),
            (session) => handshakeResponderCompleted.Set(),
            onDataB: (session, opcode, subOpcode, data) =>
            {
                receivedData = data.ToArray();
                dataReceived.Set();
            });

        _ = initiatorSession.StartAsInitiatorAsync(responderSession.LocalPublicKey);
        _ = responderSession.StartAsResponderAsync();

        Assert.IsTrue(handshakeInitiatorCompleted.Wait(10000), "Initiator handshake did not complete within 10 seconds.");
        Assert.IsTrue(handshakeResponderCompleted.Wait(10000), "Responder handshake did not complete within 10 seconds.");

        // Ensure both sessions are authorized to send and receive data
        initiatorSession.Authorizable = new Authorized();
        responderSession.Authorizable = new Authorized();

        var smallData = new byte[] { 1, 2, 3 };
        await initiatorSession.SendAsync(Opcode.DATA, 0, smallData);

        Assert.IsTrue(dataReceived.Wait(10000), "Data was not received within 10 seconds.");
        CollectionAssert.AreEqual(smallData, receivedData, "Received data does not match sent data.");
    }

    [TestMethod]
    public async Task SendAndReceive_ExactlyMaximumPacketSize_Succeeds()
    {
        var (initiatorInput, initiatorOutput, responderInput, responderOutput) = CreatePipeStreams();
        var initiatorKeyPair = KeyPair.Generate();
        var responderKeyPair = KeyPair.Generate();

        var handshakeInitiatorCompleted = new ManualResetEventSlim(false);
        var handshakeResponderCompleted = new ManualResetEventSlim(false);
        var dataReceived = new ManualResetEventSlim(false);
        byte[]? receivedData = null;

        var (initiatorSession, responderSession) = CreateSessions(
            initiatorInput, initiatorOutput, responderInput, responderOutput,
            initiatorKeyPair, responderKeyPair,
            (session) => handshakeInitiatorCompleted.Set(),
            (session) => handshakeResponderCompleted.Set(),
            onDataB: (session, opcode, subOpcode, data) =>
            {
                receivedData = data.ToArray();
                dataReceived.Set();
            });

        _ = initiatorSession.StartAsInitiatorAsync(responderSession.LocalPublicKey);
        _ = responderSession.StartAsResponderAsync();

        Assert.IsTrue(handshakeInitiatorCompleted.Wait(10000), "Initiator handshake did not complete within 10 seconds.");
        Assert.IsTrue(handshakeResponderCompleted.Wait(10000), "Responder handshake did not complete within 10 seconds.");

        // Ensure both sessions are authorized
        initiatorSession.Authorizable = new Authorized();
        responderSession.Authorizable = new Authorized();

        var maxData = new byte[SyncSocketSession.MAXIMUM_PACKET_SIZE - SyncSocketSession.HEADER_SIZE];
        new Random().NextBytes(maxData);
        await initiatorSession.SendAsync(Opcode.DATA, 0, maxData);

        Assert.IsTrue(dataReceived.Wait(10000), "Data was not received within 10 seconds.");
        CollectionAssert.AreEqual(maxData, receivedData, "Received data does not match sent data.");
    }

    #endregion

    #region Streaming Tests

    [TestMethod]
    public async Task Stream_LargeData_Succeeds()
    {
        var (initiatorInput, initiatorOutput, responderInput, responderOutput) = CreatePipeStreams();
        var initiatorKeyPair = KeyPair.Generate();
        var responderKeyPair = KeyPair.Generate();

        var handshakeInitiatorCompleted = new ManualResetEventSlim(false);
        var handshakeResponderCompleted = new ManualResetEventSlim(false);
        var dataReceived = new ManualResetEventSlim(false);
        byte[]? receivedData = null;

        var (initiatorSession, responderSession) = CreateSessions(
            initiatorInput, initiatorOutput, responderInput, responderOutput,
            initiatorKeyPair, responderKeyPair,
            (session) => handshakeInitiatorCompleted.Set(),
            (session) => handshakeResponderCompleted.Set(),
            onDataB: (session, opcode, subOpcode, data) =>
            {
                receivedData = data.ToArray();
                dataReceived.Set();
            });

        _ = initiatorSession.StartAsInitiatorAsync(responderSession.LocalPublicKey);
        _ = responderSession.StartAsResponderAsync();

        Assert.IsTrue(handshakeInitiatorCompleted.Wait(10000), "Initiator handshake did not complete within 10 seconds.");
        Assert.IsTrue(handshakeResponderCompleted.Wait(10000), "Responder handshake did not complete within 10 seconds.");

        // Ensure both sessions are authorized
        initiatorSession.Authorizable = new Authorized();
        responderSession.Authorizable = new Authorized();

        var largeData = new byte[2 * (SyncSocketSession.MAXIMUM_PACKET_SIZE - SyncSocketSession.HEADER_SIZE)];
        new Random().NextBytes(largeData);
        await initiatorSession.SendAsync(Opcode.DATA, 0, largeData);

        Assert.IsTrue(dataReceived.Wait(10000), "Large data was not received within 10 seconds.");
        CollectionAssert.AreEqual(largeData, receivedData, "Received large data does not match sent data.");
    }

    #endregion

    #region Authorization Tests

    [TestMethod]
    public async Task AuthorizedSession_CanSendData()
    {
        var (initiatorInput, initiatorOutput, responderInput, responderOutput) = CreatePipeStreams();
        var initiatorKeyPair = KeyPair.Generate();
        var responderKeyPair = KeyPair.Generate();

        var handshakeInitiatorCompleted = new ManualResetEventSlim(false);
        var handshakeResponderCompleted = new ManualResetEventSlim(false);
        var dataReceived = new ManualResetEventSlim(false);
        byte[]? receivedData = null;

        var (initiatorSession, responderSession) = CreateSessions(
            initiatorInput, initiatorOutput, responderInput, responderOutput,
            initiatorKeyPair, responderKeyPair,
            (session) => handshakeInitiatorCompleted.Set(),
            (session) => handshakeResponderCompleted.Set(),
            onDataB: (session, opcode, subOpcode, data) =>
            {
                receivedData = data.ToArray();
                dataReceived.Set();
            });

        _ = initiatorSession.StartAsInitiatorAsync(responderSession.LocalPublicKey);
        _ = responderSession.StartAsResponderAsync();

        Assert.IsTrue(handshakeInitiatorCompleted.Wait(10000), "Initiator handshake did not complete within 10 seconds.");
        Assert.IsTrue(handshakeResponderCompleted.Wait(10000), "Responder handshake did not complete within 10 seconds.");

        // Ensure both sessions are authorized
        initiatorSession.Authorizable = new Authorized();
        responderSession.Authorizable = new Authorized();

        var data = new byte[] { 1, 2, 3 };
        await initiatorSession.SendAsync(Opcode.DATA, 0, data);

        Assert.IsTrue(dataReceived.Wait(10000), "Data was not received within 10 seconds.");
        CollectionAssert.AreEqual(data, receivedData, "Received data does not match sent data.");
    }

    [TestMethod]
    public async Task UnauthorizedSession_CannotSendData()
    {
        var (initiatorInput, initiatorOutput, responderInput, responderOutput) = CreatePipeStreams();
        var initiatorKeyPair = KeyPair.Generate();
        var responderKeyPair = KeyPair.Generate();

        var handshakeInitiatorCompleted = new ManualResetEventSlim(false);
        var handshakeResponderCompleted = new ManualResetEventSlim(false);
        var dataReceived = new ManualResetEventSlim(false);

        var (initiatorSession, responderSession) = CreateSessions(
            initiatorInput, initiatorOutput, responderInput, responderOutput,
            initiatorKeyPair, responderKeyPair,
            (session) => handshakeInitiatorCompleted.Set(),
            (session) => handshakeResponderCompleted.Set(),
            onDataB: (session, opcode, subOpcode, data) =>
            {
                dataReceived.Set();
            });

        _ = initiatorSession.StartAsInitiatorAsync(responderSession.LocalPublicKey);
        _ = responderSession.StartAsResponderAsync();

        Assert.IsTrue(handshakeInitiatorCompleted.Wait(10000), "Initiator handshake did not complete within 10 seconds.");
        Assert.IsTrue(handshakeResponderCompleted.Wait(10000), "Responder handshake did not complete within 10 seconds.");

        // Authorize initiator but not responder
        initiatorSession.Authorizable = new Authorized();
        responderSession.Authorizable = new Unauthorized();

        var data = new byte[] { 1, 2, 3 };
        await initiatorSession.SendAsync(Opcode.DATA, 0, data);

        await Task.Delay(1000); // Allow time for processing

        Assert.IsFalse(dataReceived.IsSet, "Data should not be received when responder is unauthorized.");
    }

    [TestMethod]
    public async Task DirectHandshake_WithValidAppId_Succeeds()
    {
        // Arrange: Set up pipe streams and key pairs
        var (initiatorInput, initiatorOutput, responderInput, responderOutput) = CreatePipeStreams();
        var initiatorKeyPair = KeyPair.Generate();
        var responderKeyPair = KeyPair.Generate();
        const uint allowedAppId = 1234;

        var handshakeInitiatorCompleted = new TaskCompletionSource<bool>();
        var handshakeResponderCompleted = new TaskCompletionSource<bool>();

        // Responder requires a specific appId
        var responderIsHandshakeAllowed = (LinkType linkType, SyncSocketSession session, string publicKey, string? pairingCode, uint appId) =>
            linkType == LinkType.Direct && appId == allowedAppId;

        var (initiatorSession, responderSession) = CreateSessions(
            initiatorInput, initiatorOutput, responderInput, responderOutput,
            initiatorKeyPair, responderKeyPair,
            (session) => handshakeInitiatorCompleted.SetResult(true),
            (session) => handshakeResponderCompleted.SetResult(true),
            isHandshakeAllowed: responderIsHandshakeAllowed);

        // Act: Start handshake with valid appId
        _ = initiatorSession.StartAsInitiatorAsync(responderSession.LocalPublicKey, appId: allowedAppId);
        _ = responderSession.StartAsResponderAsync();

        // Assert: Handshake completes successfully
        await Task.WhenAll(handshakeInitiatorCompleted.Task, handshakeResponderCompleted.Task)
            .WithTimeout(5000, "Handshake timed out");

        Assert.IsNotNull(initiatorSession.RemotePublicKey, "Initiator should have completed handshake");
        Assert.IsNotNull(responderSession.RemotePublicKey, "Responder should have completed handshake");

        // Clean up
        initiatorSession.Dispose();
        responderSession.Dispose();
    }

    [TestMethod]
    public async Task DirectHandshake_WithInvalidAppId_Fails()
    {
        // Arrange: Set up pipe streams and key pairs
        var (initiatorInput, initiatorOutput, responderInput, responderOutput) = CreatePipeStreams();
        var initiatorKeyPair = KeyPair.Generate();
        var responderKeyPair = KeyPair.Generate();
        const uint allowedAppId = 1234;
        const uint invalidAppId = 5678;

        var handshakeInitiatorCompleted = new TaskCompletionSource<bool>();
        var handshakeResponderCompleted = new TaskCompletionSource<bool>();
        var initiatorClosed = new TaskCompletionSource<bool>();
        var responderClosed = new TaskCompletionSource<bool>();

        // Responder requires a specific appId
        var responderIsHandshakeAllowed = (LinkType linkType, SyncSocketSession session, string publicKey, string? pairingCode, uint appId) =>
            linkType == LinkType.Direct && appId == allowedAppId;

        SyncSocketSession? initiatorSession = null;
        SyncSocketSession? responderSession = null;
        (initiatorSession, responderSession) = CreateSessions(
            initiatorInput, initiatorOutput, responderInput, responderOutput,
            initiatorKeyPair, responderKeyPair,
            (session) => handshakeInitiatorCompleted.SetResult(true),
            (session) => handshakeResponderCompleted.SetResult(true),
            isHandshakeAllowed: responderIsHandshakeAllowed,
            onClose: (session) =>
            {
                if (session == initiatorSession) initiatorClosed.TrySetResult(true);
                else if (session == responderSession) responderClosed.TrySetResult(true);
            });

        // Act: Start handshake with invalid appId
        _ = initiatorSession.StartAsInitiatorAsync(responderSession.LocalPublicKey, appId: invalidAppId);
        _ = responderSession.StartAsResponderAsync();

        // Assert: Sessions close due to handshake failure
        await Task.WhenAll(initiatorClosed.Task, responderClosed.Task)
            .WithTimeout(5000, "Session close timed out");

        Assert.IsFalse(handshakeInitiatorCompleted.Task.IsCompleted, "Initiator handshake should not complete with invalid appId");
        Assert.IsFalse(handshakeResponderCompleted.Task.IsCompleted, "Responder handshake should not complete with invalid appId");

        // Clean up (sessions should already be disposed, but ensure resources are released)
        initiatorSession.Dispose();
        responderSession.Dispose();
    }

    #endregion

    #region Helper Classes

    private class Authorized : IAuthorizable
    {
        public bool IsAuthorized => true;
    }

    private class Unauthorized : IAuthorizable
    {
        public bool IsAuthorized => false;
    }

    #endregion
}